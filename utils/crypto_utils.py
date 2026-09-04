"""
Primitive crittografiche di utilità condivise tra le entità del sistema.

Tutte le operazioni asimmetriche usano:
  - RSA-OAEP (SHA-256) per cifratura/decifratura
  - RSA-PSS(SHA-256) per firma/verifica

Poiché i payload da cifrare (es. Cert_voter, encrypted_ballot ‖ voter_id)
possono superare il limite di un singolo blocco RSA-OAEP, si usa cifratura
ibrida:  RSA-OAEP per incapsulare la chiave AES-256, AES-GCM per il corpo.

Formato del crittogramma ibrido (bytes):
  [4 byte big-endian: lunghezza RSA ciphertext]
  [RSA ciphertext (chiave AES cifrata)]
  [12 byte: nonce AES-GCM]
  [AES-GCM ciphertext + 16-byte tag]
"""

import os
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------------------------------------------------------
# RSA-OAEP helpers (usati solo per payload piccoli, es. la chiave AES)
# ---------------------------------------------------------------------------

_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)

_PSS = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH,
)


def rsa_encrypt(plaintext: bytes, public_key: RSAPublicKey) -> bytes:
    """RSA-OAEP di un blocco (plaintext deve stare nel limite della chiave)."""
    return public_key.encrypt(plaintext, _OAEP)


def rsa_decrypt(ciphertext: bytes, private_key: RSAPrivateKey) -> bytes:
    """RSA-OAEP decrypt di un singolo blocco."""
    return private_key.decrypt(ciphertext, _OAEP)


# ---------------------------------------------------------------------------
# Cifratura ibrida (RSA-OAEP + AES-256-GCM) per payload arbitrariamente grandi
# ---------------------------------------------------------------------------

def hybrid_encrypt(plaintext: bytes, public_key: RSAPublicKey) -> bytes:
    """
    Cifra *plaintext* con la chiave pubblica RSA usando cifratura ibrida.

    1. Genera una chiave AES-256 casuale.
    2. Cifra la chiave AES con RSA-OAEP (pkRicevente).
    3. Cifra il plaintext con AES-256-GCM.
    4. Restituisce il bundle concatenato.
    """
    aes_key = os.urandom(32)                          # AES-256
    nonce   = os.urandom(12)                          # GCM nonce (96 bit)

    # Incapsula la chiave AES con RSA-OAEP
    enc_key = rsa_encrypt(aes_key, public_key)        # len = key_size // 8

    # Cifra il payload con AES-GCM (include tag di autenticità a 128 bit)
    ct = AESGCM(aes_key).encrypt(nonce, plaintext, None)

    # Formato: [4B lunghezza enc_key] | [enc_key] | [12B nonce] | [ct]
    header = struct.pack(">I", len(enc_key))
    return header + enc_key + nonce + ct


def hybrid_decrypt(bundle: bytes, private_key: RSAPrivateKey) -> bytes:
    """
    Decifra un bundle prodotto da *hybrid_encrypt*.
    """
    key_len = struct.unpack(">I", bundle[:4])[0]
    enc_key = bundle[4 : 4 + key_len]
    nonce   = bundle[4 + key_len : 4 + key_len + 12]
    ct      = bundle[4 + key_len + 12 :]

    aes_key = rsa_decrypt(enc_key, private_key)
    return AESGCM(aes_key).decrypt(nonce, ct, None)


# ---------------------------------------------------------------------------
# Firma / Verifica  (RSA-PSS, SHA-256)
# ---------------------------------------------------------------------------

def sign_pss(data: bytes, private_key: RSAPrivateKey) -> bytes:
    """Firma *data* con RSA-PSS (SHA-256). Restituisce la firma."""
    return private_key.sign(data, _PSS, hashes.SHA256())


def verify_pss(signature: bytes, data: bytes, public_key: RSAPublicKey) -> bool:
    """
    Verifica la firma RSA-PSS. Restituisce True se valida, False altrimenti.
    Non solleva eccezioni: gestisce internamente i fallimenti crittografici.
    """
    try:
        public_key.verify(signature, data, _PSS, hashes.SHA256())
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Hash SHA-256
# ---------------------------------------------------------------------------

def sha256(data: bytes) -> bytes:
    """Calcola SHA-256 di *data* e restituisce il digest (32 byte)."""
    h = hashes.Hash(hashes.SHA256())
    h.update(data)
    return h.finalize()
