import json
import base64
from typing import Dict, Any

from ed25519.ed25519 import SigningKey, VerifyingKey


# Alias for base64 encoding/decoding
b64e = base64.b64encode
b64d = base64.b64decode

# Certificate and CA 
# This module defines a simple Certificate and CertificateAuthority class that use Ed25519 for signing certificates.
# The Certificate class represents a minimal certificate structure with a subject name, public key, issuer name, and signature.
# The CertificateAuthority class is a minimal CA that can issue and verify certificates using Ed25519 keys.
# The CA can sign certificates for clients, and clients can verify certificates using the CA's public key.
# The CA's public key can be distributed to clients for verification.
class Certificate:
    """
    A minimal certificate structure.

    Attributes:
        subject_name (str): Name of the subject (e.g. user ID, domain).
        subject_key (bytes): The subject's public key (Ed25519) converted to bytes.
        issuer_name (str): Name of the issuer (the CA).
        signature (bytes): The CA's signature over (subject_name || subject_key).
    """
    def __init__(self, subject_name: str, subject_key: bytes, issuer_name: str, signature: bytes):
        self.subject_name = subject_name
        self.subject_key = subject_key
        self.issuer_name = issuer_name
        self.signature = signature

    def to_dict(self) -> Dict[str, str]:
        """
        Encode the certificate fields into a dict for JSON serialization.
        """
        return {
            "subject_name": self.subject_name,
            "subject_key_b64": b64e(self.subject_key).decode("utf-8"),
            "issuer_name": self.issuer_name,
            "signature_b64": b64e(self.signature).decode("utf-8"),
        }

    def to_bytes(self) -> bytes:
        """
        Returns a canonical binary representation of the certificate.
        (By JSON serializing the dict with sorted keys.)
        """
        return json.dumps(self.to_dict(), sort_keys=True).encode("utf-8")

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'Certificate':
        """
        Decode a certificate from a dictionary (the inverse of to_dict()).
        """
        return Certificate(
            subject_name=data["subject_name"],
            subject_key=b64d(data["subject_key_b64"]),
            issuer_name=data["issuer_name"],
            signature=b64d(data["signature_b64"])
        )
        



class CertificateAuthority:
    """
    A minimal Certificate Authority that uses Ed25519 to sign certificates.
    """

    def __init__(self, ca_name: str):
        """
        Generate a new Ed25519 key pair for the CA.
        
        Args:
            ca_name (str): The name of this CA (used as issuer_name).
        """
        self.ca_name = ca_name
        self._private_key = SigningKey.generate()  # Generate CA signing key
        self._public_key = VerifyingKey.from_signing_key(self._private_key)  # Corresponding public key

    def issue_certificate(self, subject_name: str, subject_public_key: VerifyingKey) -> Certificate:
        """
        Issue a certificate by signing (subject_name || subject_public_key).

        Args:
            subject_name (str): The subject's name.
            subject_public_key (VerifyingKey): The subject's Ed25519 public key.

        Returns:
            Certificate: A new certificate signed by this CA.
        """
        subject_key_bytes = subject_public_key.to_bytes()  # Convert public key to bytes
        message = subject_name.encode('utf-8') + subject_key_bytes
        signature = self._private_key.sign(message)

        return Certificate(
            subject_name=subject_name,
            subject_key=subject_key_bytes,
            issuer_name=self.ca_name,
            signature=signature
        )

    def verify_certificate(self, certificate: Certificate) -> bool:
        """
        Verify a certificate that this CA issued. Checks the signature on
        (subject_name || subject_public_key).

        Args:
            certificate (Certificate): The certificate to verify.

        Returns:
            bool: True if valid, False otherwise.
        """
        if certificate.issuer_name != self.ca_name:
            return False  # Incorrect issuer

        message = certificate.subject_name.encode('utf-8') + certificate.subject_key
        try:
            self._public_key.verify(message, certificate.signature)  # Verify using CA's public key
            return True
        except Exception:
            return False

    @property
    def public_key(self) -> VerifyingKey:
        """
        Returns the CA's public key for distribution to clients.
        """
        return self._public_key

