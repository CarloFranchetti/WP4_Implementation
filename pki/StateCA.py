from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives import hashes

from .Authority import Authority


class StateCA(Authority):
    def __init__(self, common_name):
        super().__init__(common_name)

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.common_name),
        ])

        self.certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.get_public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        ).sign(self._private_key, hashes.SHA256())

    def sign_municipality_csr(self, csr: x509.CertificateSigningRequest) -> x509.Certificate:
        cert = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            self.certificate.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=1825)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True  # ca=True since municipality must be able to sign certificates of voters
        ).sign(self._private_key, hashes.SHA256())

        return cert

    def sign_authority_csr(self, csr: x509.CertificateSigningRequest) -> x509.Certificate:
        """Signs the CSR of an end-entity authority (Electoral Authority or Scrutiny Authority).
        Unlike sign_municipality_csr, it produces certificates with ca=False
        since Electoral and Scrutiny Authorities do not issue certificates to others."""
        cert = x509.CertificateBuilder().subject_name(
            csr.subject
        ).issuer_name(
            self.certificate.subject
        ).public_key(
            csr.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        ).sign(self._private_key, hashes.SHA256())

        return cert