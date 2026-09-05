"""
Autorità Elettorale (AE) — Electoral Authority.

Responsabile di:
  1. Autenticare gli elettori verificando la catena di certificati.
  2. Distribuire schede vuote firmate con skAE.
  3. Ricevere e validare le schede cifrate inviate dagli elettori.
  4. Pubblicare le schede sulla Bulletin Board pubblica e rilasciare ricevute.
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.x509.oid import NameOID

from pki.StateCA import StateCA
from entities.Ballot import Ballot
from utils.crypto_utils import hybrid_decrypt, sign_pss, verify_pss, sha256


# ---------------------------------------------------------------------------
# Eccezioni di dominio
# ---------------------------------------------------------------------------

class InvalidBallotRequest(Exception):
    """Sollevata quando la richiesta di scheda non può essere soddisfatta."""


class InvalidBallotSubmission(Exception):
    """Sollevata quando l'invio della scheda compilata viene rifiutato."""


# ---------------------------------------------------------------------------
# Classe principale
# ---------------------------------------------------------------------------

class ElectoralAuthority:
    """Autorità Elettorale (AE).

    Gestisce l'autenticazione degli elettori e il ciclo di vita della scheda:
      - Riceve richieste di scheda cifrate con pkAE.
      - Verifica la catena di certificati Voter → MunicipalityCA → StateCA.
      - Emette schede vuote firmate con skAE.
      - Registra le schede cifrate (per AS) sulla Bulletin Board pubblica.
      - Rilascia ricevute di avvenuta votazione.
    """

    def __init__(self, common_name: str, state_ca: StateCA):
        self.common_name = common_name

        # Genera coppia di chiavi RSA-4096
        self._private_key: RSAPrivateKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )

        # CSR → certificato firmato da StateCA (end-entity, ca=False)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.common_name)]))
            .sign(self._private_key, hashes.SHA256())
        )
        self.certificate: x509.Certificate = state_ca.sign_authority_csr(csr)

        # Insieme degli ID elettore già utilizzati (prevenzione double-voting)
        self._consumed_ids: set[str] = set()

        # Bulletin Board pubblica B:  lista di { "encrypted_ballot": bytes, "ae_signature": bytes }
        # Ogni entry corrisponde a:  AE → Bulletin Board : Sign(skAE, Hash(schedacifrata))
        self.bulletin_board: list[dict] = []

    # ------------------------------------------------------------------
    # Accessori
    # ------------------------------------------------------------------

    def get_public_key(self) -> RSAPublicKey:
        """Restituisce la chiave pubblica dell'AE."""
        return self._private_key.public_key()

    # ------------------------------------------------------------------
    # Passo 1 → 3 del protocollo
    # ------------------------------------------------------------------

    def receive_ballot_request(
            self,
            encrypted_request: bytes,
            public_directory,
    ) -> tuple[bytes, bytes]:
        """Riceve Enc(pkAE, ballot_request ‖ Cert_elettore) e risponde con una scheda firmata.

        Flusso interno:
          1. Decifra la richiesta con skAE (cifratura ibrida).
          2. Estrae e verifica la catena del certificato dell'elettore.
          3. Costruisce la scheda vuota e la firma con skAE.

        Args:
            encrypted_request: Bundle ibrido cifrato con pkAE.
            public_directory:  PublicDirectory con i certificati pubblicati.

        Returns:
            Coppia (blank_ballot_bytes, ae_signature).

        Raises:
            InvalidBallotRequest: se la decifratura o la verifica della catena falliscono.
        """
        # 1. Decifratura ibrida
        try:
            plaintext = hybrid_decrypt(encrypted_request, self._private_key)
        except Exception as exc:
            raise InvalidBallotRequest(f"Decifratura della richiesta fallita: {exc}") from exc

        # 2. Deserializzazione: {"request": "ballot_request", "cert": <base64 DER>}
        try:
            data = json.loads(plaintext.decode())
            voter_cert_der = base64.b64decode(data["cert"])
            voter_cert = x509.load_der_x509_certificate(voter_cert_der)
        except Exception as exc:
            raise InvalidBallotRequest(f"Payload malformato: {exc}") from exc

        # 3. Verifica catena del certificato dell'elettore
        if not self._verify_voter_certificate_chain(voter_cert, public_directory):
            raise InvalidBallotRequest(
                "Verifica della catena di certificati dell'elettore fallita "
                "(certificato non valido, scaduto o non emesso da una MunicipalityCA riconosciuta)"
            )

        # 4. Costruisce e firma la scheda vuota
        #    schedavuota, σ_AE = Sign(skAE, schedavuota)
        blank_ballot_bytes = Ballot().to_bytes()
        ae_signature = sign_pss(blank_ballot_bytes, self._private_key)

        return blank_ballot_bytes, ae_signature

    # ------------------------------------------------------------------
    # Passo 4 → 7 del protocollo
    # ------------------------------------------------------------------

    def receive_encrypted_ballot(
            self,
            payload: dict,
            voter_public_key: RSAPublicKey,
            pk_as: RSAPublicKey,
    ) -> bytes:
        """Riceve, valida e registra la scheda cifrata dell'elettore.

        Payload atteso::

            {
              "voter_id":          str   (serial del certificato elettore),
              "encrypted_payload": str   (base64 di Enc(pkAE, encrypted_ballot ‖ voter_id)),
              "signature":         str   (base64 di Sign(skEletore, encrypted_payload))
            }

        Controlli eseguiti (nell'ordine della specifica):
          1. Autenticità della firma dell'elettore → Vrfy(pkEletore, σ) = 1
          2. ID elettore non ancora consumato (anti double-voting)
          3. Coerenza interna voter_id (header == payload cifrato)
          4. Dimensione del crittogramma per AS = pkAS.key_size // 8 (RSA-OAEP)

        Se tutti i controlli passano:
          - Segna voter_id come consumato.
          - Pubblica sulla Bulletin Board: Sign(skAE, Hash(encrypted_ballot)).
          - Restituisce la ricevuta: Sign(skAE, Hash(encrypted_ballot)).

        Raises:
            InvalidBallotSubmission: alla prima verifica fallita.
        """
        voter_id         = payload["voter_id"]
        encrypted_payload = base64.b64decode(payload["encrypted_payload"])
        voter_signature   = base64.b64decode(payload["signature"])

        # 1. Verifica firma dell'elettore sulla busta esterna
        #    Vrfy(pkEletore, encrypted_payload, σ_elettore) = 1
        if not verify_pss(voter_signature, encrypted_payload, voter_public_key):
            raise InvalidBallotSubmission(
                "Firma dell'elettore non valida: la scheda potrebbe essere stata manomessa"
            )

        # 2. Controllo ID già consumato (anti double-voting)
        if voter_id in self._consumed_ids:
            raise InvalidBallotSubmission(
                f"ID elettore '{voter_id}' già presente nella lista dei voti consumati "
                "(tentativo di voto multiplo rilevato)"
            )

        # 3. Decifratura della busta esterna e verifica coerenza voter_id
        try:
            inner_plaintext = hybrid_decrypt(encrypted_payload, self._private_key)
            inner_data = json.loads(inner_plaintext.decode())
            encrypted_ballot = base64.b64decode(inner_data["encrypted_ballot"])
            inner_voter_id   = inner_data["voter_id"]
        except Exception as exc:
            raise InvalidBallotSubmission(f"Impossibile decifrare la busta: {exc}") from exc

        if inner_voter_id != voter_id:
            raise InvalidBallotSubmission(
                "Mismatch voter_id: l'intestazione e il payload cifrato non concordano"
            )

        # 4. Dimensione attesa del crittogramma RSA-OAEP per pkAS
        #    Enc(pkAS, ballot_bytes) deve avere esattamente key_size // 8 byte
        expected_size = pk_as.key_size // 8
        if len(encrypted_ballot) != expected_size:
            raise InvalidBallotSubmission(
                f"Dimensione crittogramma AS anomala: attesi {expected_size} byte, "
                f"ricevuti {len(encrypted_ballot)} byte (scheda manomessa)"
            )

        # --- Tutti i controlli superati ---

        # Segna l'ID come consumato
        self._consumed_ids.add(voter_id)

        # Calcola la ricevuta: Sign(skAE, Hash(encrypted_ballot))
        ballot_hash = sha256(encrypted_ballot)
        receipt = sign_pss(ballot_hash, self._private_key)

        # Pubblica sulla Bulletin Board pubblica B
        #   AE → Bulletin Board : Sign(skAE, Hash(schedacifrata))
        self.bulletin_board.append({
            "encrypted_ballot": encrypted_ballot,
            "ae_signature":     receipt,
        })

        return receipt

    # ------------------------------------------------------------------
    # Metodi privati di supporto
    # ------------------------------------------------------------------

    def _verify_voter_certificate_chain(
            self,
            voter_cert: x509.Certificate,
            public_directory,
    ) -> bool:
        """Verifica la catena del certificato dell'elettore.

        Passi:
          a. Validità temporale del certificato.
          b. Recupero del certificato della MunicipalityCA emittente.
          c. Verifica crittografica della catena: Voter → MunicipalityCA → StateCA.

        Returns:
            True se la catena è valida, False altrimenti.
        """
        # a. Validità temporale
        now        = datetime.now(timezone.utc)
        not_before = voter_cert.not_valid_before_utc
        not_after  = voter_cert.not_valid_after_utc

        if not (not_before <= now <= not_after):
            return False

        # b. Recupero MunicipalityCA emittente dal PublicDirectory
        issuer_name = voter_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        municipality_cert = public_directory.get_municipality(issuer_name)
        if municipality_cert is None:
            return False

        # c. Verifica crittografica catena completa
        return public_directory.verify_certificate_chain(voter_cert, municipality_cert)
