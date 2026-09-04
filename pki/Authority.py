import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Base authority class to be inherited by State authority and the lower ones
class Authority:
    def __init__(self, name: str):
        self.common_name = name
        self._private_key = rsa.generate_private_key(
            public_exponent = 65537,
            key_size = 4096
        )
        self.certificate = None

    def get_public_key(self):
        return self._private_key.public_key()