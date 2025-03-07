import os
import json
import base64
from typing import Optional

from cryptography.hazmat.primitives import hashes, hmac
from x25519.x25519 import X25519PrivateKey, X25519PublicKey
from ed25519.ed25519 import SigningKey, VerifyingKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from hmac import compare_digest

from sigma.certificates import CertificateAuthority, Certificate

# Alias for base64 encoding/decoding
b64e = base64.b64encode
b64d = base64.b64decode

# SIGMA Protocol
# Implemented according to Slide 161 of the lecture notes, with some minor modifications.
# This is the same as  5.1 Basic SIGMA Protocol in "SIGMA: The 'SIGn-and-MAc' Approach to Authenticated Diffie-Hellman and Its Use in the IKE Protocols" by Hugo Krawczyk: https://dx.doi.org/10.1007/978-3-540-45146-4_24

# As a brief overview:
# We use SigmaParty to represent Alice and Bob, and SigmaHandshake to encapsulate the handshake steps.
# The SigmaKeys class derives session and MAC keys from the shared secret using HKDF.
# The SecureChannel class provides a secure messaging channel using AES-GCM for encryption and HMAC-SHA256 for authentication.


# The following methods are used to compute HMAC-SHA256 and compare HMAC tags in constant time.
# They are used in various places in the code, and I used one implementation to ensure consistency.
def compute_hmac(key: bytes, data: bytes) -> bytes:
    """
    Compute HMAC-SHA256 over data using key.

    Args:
        key (bytes): The HMAC key.
        data (bytes): The message to authenticate.

    Returns:
        bytes: The raw HMAC tag.
    """
    h = hmac.HMAC(key, hashes.SHA256()) 
    h.update(data)
    return h.finalize()


def hmac_compare(tag1: bytes, tag2: bytes) -> bool:
    """
    Constant-time comparison of two HMAC tags.

    Args:
        tag1 (bytes): First HMAC tag.
        tag2 (bytes): Second HMAC tag.

    Returns:
        bool: True if tags match, False otherwise.
    """
    return compare_digest(tag1, tag2)

# This method is commented out because even though in *theory* it is constant time, 
# in practice it is not. See: https://securitypitfalls.wordpress.com/2018/08/03/constant-time-compare-in-python/
# Hence I used the hmac.compare_digest method instead as recommended by the post.
# The goal isn’t to make the entire implenmentation constant time, but for easy to implement parts like this, I might as well use the constant time method.
# The method is kept here for reference:
# def hmac_compare(tag1: bytes, tag2: bytes) -> bool:
#     """
#     Constant-time comparison of two HMAC tags to mitigate timing attacks.

#     Args:
#         tag1 (bytes): First HMAC tag.
#         tag2 (bytes): Second HMAC tag.

#     Returns:
#         bool: True if tags match, False otherwise.
#     """
#     if len(tag1) != len(tag2):
#         return False
#     diff = 0
#     for x, y in zip(tag1, tag2):
#         diff |= x ^ y
#     return diff == 0



class SigmaParty:
    """
    Represents a party (Alice or Bob) in the SIGMA protocol. Each party has:
    - A long-term Ed25519 key pair (for signing)
    - A certificate from the CA
    - The CA's public key to verify the other party's certificate
    - Ephemeral X25519 keys for DH key exchange
    - A session key after the handshake
    """

    def __init__(self, name: str, ca_public_key: VerifyingKey):
        """
        Initialize the party with a new Ed25519 key pair. The certificate
        is to be obtained from the CA (issue_certificate).

        Args:
            name (str): The party's identity (e.g., "Alice", "Bob").
            ca_public_key (VerifyingKey): The CA's public key.
        """
        self.name = name
        self._ed25519_private = SigningKey.generate()
        self.ed25519_public = VerifyingKey.from_signing_key(self._ed25519_private)
        self.certificate : Optional[Certificate] = None  # To be set after CA issues the cert
        self.ca_public_key = ca_public_key

        # Ephemeral X25519 keys (will be generated per session)
        self._x25519_private: Optional[X25519PrivateKey] = None
        self.x25519_public: Optional[X25519PublicKey] = None

        # Session key established after SIGMA completes
        self.session_key: Optional[bytes] = None
        self.mac_key: Optional[bytes] = None
        self.identity_key: Optional[bytes] = None

    def set_certificate(self, cert: Certificate):
        """
        Set the party's certificate (obtained from the CA).
        """
        self.certificate = cert

    def create_ephemeral_keypair(self):
        """
        Generate a fresh ephemeral X25519 key pair for a new SIGMA session.
        """
        self._x25519_private = X25519PrivateKey.generate()
        self.x25519_public = X25519PublicKey.from_private_key(self._x25519_private)

    def sign_data(self, data: bytes) -> bytes:
        """
        Sign data with this party's Ed25519 private key.

        Args:
            data (bytes): The data to sign.

        Returns:
            bytes: The raw signature.
        """
        return self._ed25519_private.sign(data)

    def compute_shared_secret(self, peer_public_key: X25519PublicKey) -> bytes:
        """
        Compute the X25519 shared secret with a peer's ephemeral public key.

        Args:
            peer_public_key (X25519PublicKey): The peer's X25519 public key.

        Returns:
            bytes: The 32-byte shared secret.
        """
        assert self._x25519_private is not None
        return self._x25519_private.exchange(peer_public_key)

class SigmaHandshake:
    """
    Encapsulates the SIGMA handshake steps in a single class.

    This class manages:
    - The handshake initiation and response
    - Certificate validation
    - Ephemeral key exchange (X25519)
    - Signature verification (Ed25519)
    - Key derivation (kS for encryption, kM for authentication)
    - Optionally, identity protection, which adds a third key kE, used to encrypt identities and signatures.
    """

    def __init__(self, initiator: SigmaParty, responder: SigmaParty, identity_protection: bool = False):
        """
        Initialize a SigmaHandshake between two parties.

        Args:
            initiator (SigmaParty): The party initiating the handshake.
            responder (SigmaParty): The party responding to the handshake.
        """
        self.initiator = initiator
        self.responder = responder
        self.identity_protection = identity_protection

        # Store ephemeral public keys
        self._initiator_ephemeral_pub: Optional[X25519PublicKey] = None
        self._responder_ephemeral_pub: Optional[X25519PublicKey] = None

    def create_initiation_message(self) -> bytes:
        """
        Step 1 (Initiator -> Responder): 
        The initiator sends only:
        - Their ephemeral X25519 public key (g^x)

        Returns:
            bytes: A JSON-encoded message.
        """
        # Generate ephemeral X25519 keys
        self.initiator.create_ephemeral_keypair()

        # Get ephemeral public key (g^x)
        assert self.initiator.x25519_public is not None
        ephemeral_pub_bytes = self.initiator.x25519_public.to_bytes()

        # Store for later use
        self._initiator_ephemeral_pub = self.initiator.x25519_public

        # Build JSON message with just g^x
        msg = {
            "type": "SIGMA_INIT",
            "ephemeral_pub_b64": b64e(ephemeral_pub_bytes).decode("utf-8"),
        }

        return json.dumps(msg).encode('utf-8')
    
    
    def handle_initiation_message(self, message: bytes) -> bytes:
        """
        Step 2 (Responder -> Initiator):
        The responder:
        - Generates their ephemeral keypair
        - Computes the shared secret
        - Derives keys (kS for encryption, kM for authentication)
        - Signs (g^x, g^y)
        - Responds with:
        - Their ephemeral public key (g^y)
        - Their certificate (cB)
        - Signature (σB)
        - MAC over certificate (μB)

        Returns:
            bytes: A JSON-encoded response message (SIGMA_RESP).
        """
        data = json.loads(message.decode('utf-8'))
        if data.get("type") != "SIGMA_INIT":
            raise ValueError("Invalid message type")

        # Get initiator's ephemeral key g^x
        ephemeral_pub_initiator_bytes = b64d(data["ephemeral_pub_b64"])
        ephemeral_pub_initiator = X25519PublicKey.from_bytes(ephemeral_pub_initiator_bytes)

        # Generate ephemeral keypair for responder (g^y)
        self.responder.create_ephemeral_keypair()
        assert self.responder.x25519_public is not None
        self._responder_ephemeral_pub = self.responder.x25519_public
        ephemeral_pub_responder_bytes = self.responder.x25519_public.to_bytes()

        # Compute shared secret and derive keys
        assert self.responder._x25519_private is not None
        sigma_keys = SigmaKeys.derive_from_dh(self.responder._x25519_private, ephemeral_pub_initiator, self.identity_protection)
        self.responder.session_key = sigma_keys.get_session_key()
        mac_key = sigma_keys.get_mac_key()
        self.responder.mac_key = mac_key # Needed so we don’t have to recompute it later, but only for responder

        # Sign (g^x || g^y)
        combined_ephemeral_keys = ephemeral_pub_initiator_bytes + ephemeral_pub_responder_bytes
        signature_responder = self.responder.sign_data(combined_ephemeral_keys)

        # Compute MAC(kM, cB)
        assert self.responder.certificate is not None
        mac_tag = compute_hmac(mac_key, self.responder.certificate.to_bytes())

    # Encrypt {cB, sigB, μB} using Ke only if identity protection is enabled
        if self.identity_protection:
            plaintext = json.dumps({
                "certificate": self.responder.certificate.to_dict(),
                "signature_b64": b64e(signature_responder).decode("utf-8"),
                "hmac_b64": b64e(mac_tag).decode("utf-8")
            }).encode("utf-8")

            encryption_key = sigma_keys.get_identity_key()
            self.responder.identity_key = encryption_key
            nonce = os.urandom(12)
            cipher = Cipher(algorithms.AES(encryption_key), modes.GCM(nonce))
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()

            return json.dumps({
                "type": "SIGMA_RESP",
                "ephemeral_pub_b64": b64e(ephemeral_pub_responder_bytes).decode("utf-8"),
                "nonce_b64": b64e(nonce).decode("utf-8"),
                "ciphertext_b64": b64e(ciphertext).decode("utf-8"),
                "tag_b64": b64e(encryptor.tag).decode("utf-8")
            }).encode("utf-8")
        else:
            return json.dumps({
                "type": "SIGMA_RESP",
                "ephemeral_pub_b64": b64e(ephemeral_pub_responder_bytes).decode("utf-8"),
                "certificate": self.responder.certificate.to_dict(),
                "signature_b64": b64e(signature_responder).decode("utf-8"),
                "hmac_b64": b64e(mac_tag).decode("utf-8")
            }).encode("utf-8")

    def process_response_message(self, message: bytes) -> bytes:
        """
        Step 3 (Initiator verifies responder's message):
        - Compute kS, kM
        - Verify MAC(kM, cB) ?= μB
        - Verify σB on (g^x || g^y)
        - Sign (g^x || g^y) -> σA
        - Compute MAC(kM, cA) -> μA
        - Send {cA, σA, μA}
        - Optionally, if identity protection is enabled, we also compute kE and decrypt the responder's identity, signature, and MAC.
        - We then also encrypt our identity, signature, and MAC before sending it.
        """
        data = json.loads(message.decode('utf-8'))
        if data.get("type") != "SIGMA_RESP":
            raise ValueError("Invalid message type")

        # Get responder's ephemeral key g^y
        ephemeral_pub_responder_bytes = b64d(data["ephemeral_pub_b64"])
        ephemeral_pub_responder = X25519PublicKey.from_bytes(ephemeral_pub_responder_bytes)
        self._responder_ephemeral_pub = ephemeral_pub_responder
        
        # Compute shared secret and derive kS, kM
        assert self.initiator._x25519_private is not None
        sigma_keys = SigmaKeys.derive_from_dh(self.initiator._x25519_private, ephemeral_pub_responder, self.identity_protection)
        self.initiator.session_key = sigma_keys.get_session_key()
        mac_key = sigma_keys.get_mac_key()
        # We don’t need to store the mac key for the responder, only the initiator

        # Extract responder's cert, signature, and MAC
        if self.identity_protection:
            try:
                # Decrypt responder's identity
                nonce = b64d(data["nonce_b64"])
                ciphertext = b64d(data["ciphertext_b64"])
                tag = b64d(data["tag_b64"])

                encryption_key = sigma_keys.get_identity_key()
                # We also don’t need to store the identity key for the responder as it isn’t used again
                # Decrypt the ciphertext
                cipher = Cipher(algorithms.AES(encryption_key), modes.GCM(nonce, tag))
                decryptor = cipher.decryptor()
                decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
                decrypted_json = json.loads(decrypted_data)

                responder_cert = Certificate.from_dict(decrypted_json["certificate"])
                signature_responder = b64d(decrypted_json["signature_b64"])
                mac_tag = b64d(decrypted_json["hmac_b64"])
            except Exception:
                raise ValueError("Decryption failed: Encrypted identity or signature verification failed.")
        else:
            responder_cert = Certificate.from_dict(data["certificate"])
            signature_responder = b64d(data["signature_b64"])
            mac_tag = b64d(data["hmac_b64"])


        # Verify MAC(kM, cB)
        if not hmac_compare(mac_tag, compute_hmac(mac_key, responder_cert.to_bytes())):
            raise ValueError("MAC verification failed")

        # Verify σB
        responder_verifier = VerifyingKey.from_bytes(responder_cert.subject_key)
        assert self._initiator_ephemeral_pub is not None
        combined_ephemeral_keys = self._initiator_ephemeral_pub.to_bytes() + ephemeral_pub_responder_bytes
        if not responder_verifier.verify(combined_ephemeral_keys, signature_responder):
            raise ValueError("Signature verification failed")

        # Sign (g^x || g^y)
        signature_initiator = self.initiator.sign_data(combined_ephemeral_keys)

        # Compute MAC(kM, cA)
        assert self.initiator.certificate is not None
        mac_tag_final = compute_hmac(mac_key, self.initiator.certificate.to_bytes())

        if self.identity_protection:
            # Encrypt the final message under Ke
            nonce_final = os.urandom(12)  # Generate a fresh nonce
            cipher_final = Cipher(algorithms.AES(encryption_key), modes.GCM(nonce_final))
            encryptor_final = cipher_final.encryptor()
            
            final_message = json.dumps({
            "certificate": self.initiator.certificate.to_dict(),
            "signature_b64": b64e(signature_initiator).decode("utf-8"),
            "hmac_b64": b64e(mac_tag_final).decode("utf-8")
                }).encode("utf-8")
            
            ciphertext_final = encryptor_final.update(final_message) + encryptor_final.finalize()

            # Return the encrypted final message
            return json.dumps({
                "type": "SIGMA_FINAL",
                "ciphertext_b64": b64e(ciphertext_final).decode("utf-8"),
                "nonce_b64": b64e(nonce_final).decode("utf-8"),
                "tag_b64": b64e(encryptor_final.tag).decode("utf-8")
            }).encode("utf-8")
        else:
            # If identity protection is disabled, return in plaintext
            return json.dumps({
                "type": "SIGMA_FINAL",
                "certificate": self.initiator.certificate.to_dict(),
                "signature_b64": b64e(signature_initiator).decode("utf-8"),
                "hmac_b64": b64e(mac_tag_final).decode("utf-8")
            }).encode("utf-8")

    def finalize_handshake(self, message: bytes) -> bytes:
        """
        Step 4 (Responder final check):
        - Verify MAC(kM, cA) ?= μA
        - Verify σA on (g^x || g^y)
        - Return kS if all checks pass
        """
        data = json.loads(message.decode('utf-8'))
        
        if self.identity_protection:
            # Extract encrypted fields
            encrypted_data = b64d(data["ciphertext_b64"])
            nonce = b64d(data["nonce_b64"])
            tag = b64d(data["tag_b64"])

            assert self.responder.identity_key is not None
            cipher = Cipher(algorithms.AES(self.responder.identity_key), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()
            try:
                decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
                decrypted_json = json.loads(decrypted_data)
            except Exception:
                raise ValueError("Decryption failed: Could not verify initiator's identity.")

            signature_initiator = b64d(decrypted_json["signature_b64"])
            mac_tag = b64d(decrypted_json["hmac_b64"])
            initiator_cert = Certificate.from_dict(decrypted_json["certificate"])
        else:
            signature_initiator = b64d(data["signature_b64"])
            mac_tag = b64d(data["hmac_b64"])
            initiator_cert = Certificate.from_dict(data["certificate"])

        # Verify MAC(kM, cA)
        assert self.responder.mac_key is not None
        if not hmac_compare(mac_tag, compute_hmac(self.responder.mac_key, initiator_cert.to_bytes())):
            raise ValueError("MAC verification failed")

        assert self._initiator_ephemeral_pub is not None
        assert self._responder_ephemeral_pub is not None
        combined_ephemeral_keys = self._initiator_ephemeral_pub.to_bytes() + self._responder_ephemeral_pub.to_bytes()
        # Verify σA
        initiator_verifier = VerifyingKey.from_bytes(initiator_cert.subject_key)
        if not initiator_verifier.verify(combined_ephemeral_keys, signature_initiator):
            raise ValueError("Signature verification failed")

        assert self.responder.session_key is not None
        return self.responder.session_key

# This deviates from lecture notes as I chose to use a HKDF instead of just hashing the shared secret with 
# domain separation strings. I also use slightly longer domain separation strings.
class SigmaKeys:
    """
    Represents the keys derived from the SIGMA protocol's Diffie-Hellman key exchange.

    This class ensures that:
    - kS (session key for encryption)
    - kM (MAC key for authentication)
    - Optionally kE (key for identity protection)

    Are properly derived using HKDF from the shared secret.
    """

    def __init__(self, shared_secret: bytes, salt: bytes = b"", identity_protection: bool = False):
        """
        Derives two distinct 32-byte keys:
        - kS: The session key (for encryption)
        - kM: The MAC key (for authentication)
        - Optionally, kE: The key for identity protection

        Args:
            shared_secret (bytes): The raw X25519 shared secret (32 bytes).
            salt (bytes): Optional salt for HKDF (defaults to empty).
            identity_protection (bool): Whether to derive an identity key (kE).
        """
        self.kS = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 32-byte key
            salt=salt,
            info=b"SIGMA-session-key"
        ).derive(shared_secret)

        self.kM = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 32-byte HMAC key
            salt=salt,
            info=b"SIGMA-MAC-key"
        ).derive(shared_secret)
        
        # Ensure kE is initialized only when identity protection is enabled
        self.kE = None
        if identity_protection:
            self.kE = HKDF(
                algorithm=hashes.SHA256(),
                length=32,  # 32-byte key
                salt=salt,
                info=b"SIGMA-identity-key"
            ).derive(shared_secret)

    def get_session_key(self) -> bytes:
        """Returns kS (session key for encryption)."""
        return self.kS

    def get_mac_key(self) -> bytes:
        """Returns kM (MAC key for authentication)."""
        return self.kM
    
    def get_identity_key(self) -> bytes:
        """Returns kE (key for identity protection)."""
        if self.kE is None:
            raise ValueError("Identity protection is not enabled, but get_identity_key() was called.")
        return self.kE

    @staticmethod
    def derive_from_dh(alice_private: "X25519PrivateKey", bob_public: "X25519PublicKey", identity_protection: bool = False) -> "SigmaKeys":
        """
        Given an X25519 private key and a peer's public key, perform the key exchange
        and derive both the session key (kS) and MAC key (kM).

        Args:
            alice_private (X25519PrivateKey): Private key of one party.
            bob_public (X25519PublicKey): Public key of the other party.

        Returns:
            SigmaKeys: An instance containing the derived session & MAC keys.
        """
        shared_secret = alice_private.exchange(bob_public)  # Get raw DH output
        return SigmaKeys(shared_secret, identity_protection=identity_protection)


class SecureChannel:
    """
    A secure messaging channel using AES-256-GCM for encryption and HMAC-SHA256 for authentication.
    This class requires pre-established keys (obtained via the SIGMA handshake).
    
    Attributes:
        session_key (bytes): The symmetric encryption key (kS) for AES-GCM.
        mac_key (bytes): The MAC key (kM) for HMAC authentication.
    """

    def __init__(self, session_key: bytes):
        """
        Initialize the secure channel with pre-established keys.

        Args:
            session_key (bytes): 32-byte AES-256 key for encryption.
        """
        if len(session_key) != 32:
            raise ValueError("session_key must be 32 bytes long.")

        self.session_key = session_key
        
        # Derive a new MAC key (kM') from the session key
        self.mac_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 32-byte MAC key for secure messaging
            salt=None,
            info=b"SecureChannel-MAC-Key"
        ).derive(session_key)

    def _encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypts plaintext using AES-256-GCM.

        Args:
            plaintext (bytes): The message to encrypt.

        Returns:
            bytes: Nonce + GCM tag + ciphertext.
        """
        nonce = os.urandom(12)  # Standard GCM nonce size
        cipher = Cipher(algorithms.AES(self.session_key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return nonce + encryptor.tag + ciphertext

    def _decrypt(self, data: bytes) -> bytes:
        """
        Decrypts a message using AES-256-GCM.

        Args:
            data (bytes): The encrypted data (nonce + tag + ciphertext).

        Returns:
            bytes: The decrypted plaintext.
        """
        nonce = data[:12]
        tag = data[12:28]
        ciphertext = data[28:]
        cipher = Cipher(algorithms.AES(self.session_key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def _compute_hmac(self, data: bytes) -> bytes:
        """
        Computes an HMAC-SHA256 over the given data.

        Args:
            data (bytes): Data to authenticate.

        Returns:
            bytes: The 32-byte HMAC tag.
        """
        return compute_hmac(self.mac_key, data)

    def send_message(self, plaintext: bytes) -> bytes:
        """
        Encrypts and authenticates a message.

        Args:
            plaintext (bytes): The plaintext message.

        Returns:
            bytes: A JSON-encoded (ciphertext + mac_tag) message ready for transmission.
        """
        ciphertext = self._encrypt(plaintext)
        mac_tag = self._compute_hmac(ciphertext)
        
        message = {
            "ciphertext_b64": b64e(ciphertext).decode("utf-8"),
            "hmac_b64": b64e(mac_tag).decode("utf-8")
        }
        return json.dumps(message).encode('utf-8')

    def receive_message(self, message: bytes) -> bytes:
        """
        Verifies and decrypts a received message.

        Args:
            message (bytes): The JSON-encoded secure message.

        Returns:
            bytes: The decrypted plaintext.

        Raises:
            ValueError: If HMAC verification fails.
        """
        data = json.loads(message.decode('utf-8'))
        ciphertext = b64d(data["ciphertext_b64"])
        received_mac = b64d(data["hmac_b64"])

        expected_mac = self._compute_hmac(ciphertext)
        if not self._constant_time_compare(received_mac, expected_mac):
            raise ValueError("HMAC verification failed: message may have been tampered with.")

        return self._decrypt(ciphertext)

    @staticmethod
    def _constant_time_compare(a: bytes, b: bytes) -> bool:
        """
        Compares two byte strings in constant time to prevent timing attacks.

        Args:
            a (bytes): First byte string.
            b (bytes): Second byte string.

        Returns:
            bool: True if the strings are equal, False otherwise.
        """
        return hmac_compare(a, b)


def main(identity_protection: bool = False):
    print("\n=== Running SIGMA Handshake (Identity Protection: {}) ===".format(identity_protection))

    # Step 1: Setup CA and create parties
    ca = CertificateAuthority("TestCA")
    ca_public_key = ca.public_key

    # Create parties: Alice and Bob
    alice = SigmaParty("Alice", ca_public_key)
    bob = SigmaParty("Bob", ca_public_key)

    # CA issues certificates for both
    alice_cert = ca.issue_certificate("Alice", alice.ed25519_public)
    bob_cert = ca.issue_certificate("Bob", bob.ed25519_public)

    # Each party sets its certificate
    alice.set_certificate(alice_cert)
    bob.set_certificate(bob_cert)

    # Step 2: Perform the SIGMA handshake between Alice (initiator) and Bob (responder)
    handshake = SigmaHandshake(alice, bob, identity_protection=identity_protection)

    # --- Handshake Step 1: Initiator sends SIGMA_INIT
    sigma_init_msg = handshake.create_initiation_message()
    print("SIGMA_INIT message from Alice (plaintext):")
    print(sigma_init_msg.decode())

    # --- Handshake Step 2: Responder processes SIGMA_INIT and sends SIGMA_RESP
    sigma_resp_msg = handshake.handle_initiation_message(sigma_init_msg)
    print("SIGMA_RESP message from Bob:")
    if identity_protection:
        print("(Encrypted)")
    print(sigma_resp_msg.decode())

    # --- Handshake Step 3: Initiator processes SIGMA_RESP and sends SIGMA_FINAL
    sigma_final_msg = handshake.process_response_message(sigma_resp_msg)
    print("SIGMA_FINAL message from Alice:")
    if identity_protection:
        print("(Encrypted)")
    print(sigma_final_msg.decode())

    # --- Handshake Step 4: Responder finalizes the handshake
    session_key = handshake.finalize_handshake(sigma_final_msg)
    print("\nHandshake complete.")
    assert alice.session_key is not None
    assert bob.session_key is not None
    print("Bob's session key:", session_key.hex())
    print("Alice's session key:", alice.session_key.hex())

    # Step 3: Secure Messaging using SecureChannel
    secure_channel_alice = SecureChannel(alice.session_key)
    secure_channel_bob = SecureChannel(bob.session_key)

    # Alice sends a secure message to Bob.
    plaintext = b"Hello Bob, this is a secret message from Alice!"
    encrypted_message = secure_channel_alice.send_message(plaintext)
    print("\nEncrypted message from Alice to Bob:")
    print(encrypted_message.decode())

    # Bob receives and decrypts the message.
    decrypted_message = secure_channel_bob.receive_message(encrypted_message)
    print("\nDecrypted message at Bob:")
    print(decrypted_message.decode())


if __name__ == "__main__":
    # Run both standard SIGMA and SIGMA-I (Identity Protection)
    print("\n=====================================")
    print("RUNNING SIGMA HANDSHAKE WITHOUT IDENTITY PROTECTION")
    print("=====================================")
    main(identity_protection=False)

    print("\n=====================================")
    print("RUNNING SIGMA-I (IDENTITY PROTECTION ENABLED)")
    print("=====================================")
    main(identity_protection=True)
