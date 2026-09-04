from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives import hashes

from .Authority import Authority
from .StateCA import StateCA


class MunicipalityCA(Authority):
    def __init__(self, common_name: str, state_ca: StateCA):
        super().__init__(common_name)

        # 1. Create the request (CSR) for the State
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.common_name),
        ])).sign(self._private_key, hashes.SHA256())

        # 2. Obtains the certificate signed by the State
        self.certificate = state_ca.sign_municipality_csr(csr)

    def sign_voter_csr(self, csr: x509.CertificateSigningRequest):
        """Method used by the Municipality to authorize a Voter"""
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
            datetime.utcnow() + timedelta(days=1)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        ).sign(self._private_key, hashes.SHA256())

        return cert