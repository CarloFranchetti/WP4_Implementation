from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives import hashes


class PublicDirectory:
    """Public certificate registry.
    Maintains the certificates of the Municipalities and Authorities (Electoral, Scrutiny),
    all signed by the StateCA and freely accessible/verifiable."""

    def __init__(self):
        self.root_ca_cert = None  # Root certificate of the StateCA
        self.municipality_certs = {}  # Municipality Name -> Certificate
        self.authority_certs = {}  # Authority Name -> Certificate

    # --- Root CA ---

    def set_root_ca(self, cert: x509.Certificate):
        """Sets the root certificate of the StateCA (trust anchor for verifications)"""
        self.root_ca_cert = cert

    # --- Municipalities ---

    def add_municipality(self, cert: x509.Certificate):
        """Publishes the certificate of a Municipality"""
        name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        self.municipality_certs[name] = cert

    def get_municipality(self, issuer_name: str):
        """Retrieves the certificate of a Municipality by name"""
        return self.municipality_certs.get(issuer_name)

    # --- Authorities (Electoral, Scrutiny) ---

    def add_authority(self, cert: x509.Certificate):
        """Publishes the certificate of an authority (Electoral or Scrutiny)"""
        name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        self.authority_certs[name] = cert

    def get_authority(self, name: str):
        """Retrieves the certificate of an authority by name"""
        return self.authority_certs.get(name)

    def get_authority_public_key(self, name: str):
        """Retrieves the RSA public key from an authority certificate.

        Convenience wrapper around get_authority() that directly returns
        the public key, avoiding repeated .public_key() calls in client code.

        Raises:
            KeyError: if the authority is not registered in the directory.
        """
        cert = self.get_authority(name)
        if cert is None:
            raise KeyError(f"Autorità '{name}' non trovata nel PublicDirectory")
        return cert.public_key()

    # --- Cryptographic Verification ---

    def verify_certificate(self, cert: x509.Certificate) -> bool:
        """Cryptographic verification that the certificate is signed by the root CA (StateCA).
        Checks that the digital signature on the certificate is authentic,
        using the public key of the StateCA."""
        if self.root_ca_cert is None:
            raise ValueError("Root CA certificate not set in the PublicDirectory")

        try:
            # Verify that the signature on the certificate is from the StateCA
            root_public_key = self.root_ca_cert.public_key()
            root_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                PKCS1v15(),
                cert.signature_hash_algorithm
            )
            return True
        except Exception:
            return False

    def verify_certificate_chain(self, voter_cert, comune_cert) -> bool:
        """Verifies the entire certificate chain (Voter → MunicipalityCA → StateCA)"""

        # Step 1: be sure the municipality certificate is signed by the StateCA
        if not self.verify_certificate(comune_cert):
            return False

        # Step 2: be sure the voter certificate is signed by the MunicipalityCA
        try:
            comune_public_key = comune_cert.public_key()
            comune_public_key.verify(
                voter_cert.signature,
                voter_cert.tbs_certificate_bytes,
                PKCS1v15(),
                voter_cert.signature_hash_algorithm
            )
            return True
        except Exception:
            return False