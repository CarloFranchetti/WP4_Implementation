"""
Elettore (Voter).

Responsabile di:
  1. Generare la propria coppia di chiavi e richiedere un certificato alla MunicipalityCA.
  2. Verificare i certificati delle autorità (AE, AS) tramite il PublicDirectory.
  3. Richiedere una scheda vuota all'AE (inviando il proprio certificato cifrato).
  4. Verificare la firma AE sulla scheda vuota.
  5. Compilare e inviare la scheda cifrata (Enc(pkAS, ...) poi Enc(pkAE, ...)) firmandola.
  6. Conservare e verificare la ricevuta di avvenuta votazione.
"""

from __future__ import annotations

import base64
import json
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.x509.oid import NameOID

from entities.Ballot import Ballot
from utils.crypto_utils import (
    hybrid_encrypt,
    rsa_encrypt,
    sign_pss,
    verify_pss,
    sha256,
)

class Voter:
    def __init__(self, name: str, key_bits: int = 2048):
        self.name = name
        self.certificate: Optional[x509.Certificate] = None

        # Coppia di chiavi RSA dell'elettore
        self.private_key: RSAPrivateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_bits,
        )
        self.public_key: RSAPublicKey = self.private_key.public_key()

        # Scheda cifrata dell'ultimo invio (conservata per la verifica della ricevuta)
        self._last_encrypted_ballot: Optional[bytes] = None

    # ------------------------------------------------------------------
    # Accessori
    # ------------------------------------------------------------------

    def get_public_key(self) -> RSAPublicKey:
        return self.public_key

    # ------------------------------------------------------------------
    # Gestione certificato
    # ------------------------------------------------------------------

    def generate_certificate_request(self) -> x509.CertificateSigningRequest:
        """Genera un CSR da inviare alla MunicipalityCA."""
        return (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.name)]))
            .sign(self.private_key, hashes.SHA256())
        )

    def set_certificate(self, cert: x509.Certificate):
        """Salva il certificato X.509 rilasciato dalla MunicipalityCA."""
        self.certificate = cert

    # ------------------------------------------------------------------
    # Verifica certificati delle autorità (fase precedente)
    # ------------------------------------------------------------------

    def verify_authority_certificate(self, authority_name: str, public_directory) -> bool:
        """Recupera il certificato di un'autorità (AE o AS) dal PublicDirectory
        e ne verifica l'autenticità crittografica (firma StateCA).

        Returns:
            True se il certificato è presente e la firma è valida, False altrimenti.
        """
        authority_cert = public_directory.get_authority(authority_name)
        if authority_cert is None:
            return False
        return public_directory.verify_certificate(authority_cert)

    # ------------------------------------------------------------------
    # Passo 1 — Richiesta scheda vuota
    # ------------------------------------------------------------------

    def request_ballot(self, pk_ae: RSAPublicKey) -> bytes:
        """Costruisce e restituisce Enc(pkAE, ballot_request ‖ Cert_elettore).

        Il certificato dell'elettore è incluso nel payload cifrato in modo che AE
        possa estrarne la chiave pubblica (pkEletore) per le successive verifiche.

        Returns:
            Bundle ibrido cifrato con pkAE.

        Raises:
            ValueError: se l'elettore non ha ancora un certificato.
        """
        if self.certificate is None:
            raise ValueError(
                "L'elettore non possiede un certificato. "
                "Richiederne uno alla MunicipalityCA prima di procedere."
            )

        cert_der = self.certificate.public_bytes(serialization.Encoding.DER)
        payload = json.dumps({
            "request": "ballot_request",
            "cert": base64.b64encode(cert_der).decode(),
        }).encode()

        # Enc(pkAE, payload)  — cifratura ibrida perché il certificato è > 446 byte
        return hybrid_encrypt(payload, pk_ae)

    # ------------------------------------------------------------------
    # Passo 3 — Ricezione e verifica della scheda vuota
    # ------------------------------------------------------------------

    def receive_blank_ballot(
            self,
            blank_ballot_bytes: bytes,
            ae_signature: bytes,
            pk_ae: RSAPublicKey,
    ) -> Ballot:
        """Verifica σ_AE sulla scheda vuota e la restituisce deserializzata.

        Protegge contro schede vuote forgiate da avversari che si spacciano per AE.

        Returns:
            Oggetto Ballot (vuoto).

        Raises:
            ValueError: se la firma AE non è valida.
        """
        if not verify_pss(ae_signature, blank_ballot_bytes, pk_ae):
            raise ValueError(
                "Firma AE sulla scheda vuota non valida. "
                "La scheda potrebbe essere stata alterata o provenire da un'entità non autorizzata."
            )
        return Ballot.from_bytes(blank_ballot_bytes)

    # ------------------------------------------------------------------
    # Passo 4 — Compilazione e invio della scheda cifrata
    # ------------------------------------------------------------------

    def submit_ballot(
            self,
            choice: str,
            pk_ae: RSAPublicKey,
            pk_as: RSAPublicKey,
    ) -> dict:
        """Costruisce il payload di invio della scheda compilata.

        Flusso crittografico:
          1. Cifra la scheda compilata con pkAS (solo AS potrà decifrarla).
             schedacifrata = Enc(pkAS, ballot_bytes)   [RSA-OAEP, output fisso = pkAS.key_size//8]
          2. Costruisce il payload interno:
             { "encrypted_ballot": base64(schedacifrata), "voter_id": voter_id }
          3. Cifra il payload interno con pkAE (cifratura ibrida).
             schedacifratacifrata = Enc(pkAE, inner_payload)
          4. Firma la busta esterna con skEletore.
             σ = Sign(skEletore, schedacifratacifrata)

        Returns:
            dict { voter_id, encrypted_payload (base64), signature (base64) }

        Raises:
            ValueError: se l'elettore non ha certificato o la scelta non è valida.
        """
        if self.certificate is None:
            raise ValueError("L'elettore non possiede un certificato.")

        if choice not in {"SI", "NO", "ASTENUTO"}:
            raise ValueError(f"Scelta non valida '{choice}': deve essere 'SI', 'NO' o 'ASTENUTO'.")

        voter_id = str(self.certificate.serial_number)

        # 1. Enc(pkAS, ballot_bytes)  — RSA-OAEP diretto (ballot è piccolo: ~40 byte)
        filled_ballot_bytes = Ballot(choice=choice).to_bytes()
        encrypted_ballot = rsa_encrypt(filled_ballot_bytes, pk_as)
        # encrypted_ballot ha dimensione fissa = pkAS.key_size // 8  (es. 512 byte per 4096 bit)

        # Salva per la successiva verifica della ricevuta
        self._last_encrypted_ballot = encrypted_ballot

        # 2. Payload interno
        inner_payload = json.dumps({
            "encrypted_ballot": base64.b64encode(encrypted_ballot).decode(),
            "voter_id":         voter_id,
        }).encode()

        # 3. Enc(pkAE, inner_payload)  — cifratura ibrida (inner_payload > 446 byte)
        outer_encrypted = hybrid_encrypt(inner_payload, pk_ae)

        # 4. σ = Sign(skEletore, outer_encrypted)
        voter_signature = sign_pss(outer_encrypted, self.private_key)

        return {
            "voter_id":          voter_id,
            "encrypted_payload": base64.b64encode(outer_encrypted).decode(),
            "signature":         base64.b64encode(voter_signature).decode(),
        }

    # ------------------------------------------------------------------
    # Passo 7 — Verifica della ricevuta
    # ------------------------------------------------------------------

    def verify_receipt(self, receipt: bytes, pk_ae: RSAPublicKey) -> bool:
        """Verifica che la ricevuta sia Sign(skAE, Hash(encrypted_ballot)).

        Permette all'elettore di accertare che la propria scheda sia stata
        registrata correttamente, senza rivelare la preferenza espressa.

        Returns:
            True se la ricevuta è autentica, False altrimenti.

        Raises:
            ValueError: se non è stato ancora effettuato un invio.
        """
        if self._last_encrypted_ballot is None:
            raise ValueError(
                "Nessun invio di scheda trovato. "
                "Chiamare submit_ballot() prima di verificare la ricevuta."
            )

        ballot_hash = sha256(self._last_encrypted_ballot)
        return verify_pss(receipt, ballot_hash, pk_ae)