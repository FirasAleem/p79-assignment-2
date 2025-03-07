import os
import hashlib
import json
import base64
from typing import Tuple, Optional
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from ed25519.utils import (
    edwards_point_add_extended,
    edwards_scalar_mult,
    encode_edwards_point,
    decode_edwards_point,
    edwards_point_negate,
    affine_to_extended,
    is_valid_edwards_point,
    
)
import hmac as built_in_hmac
import argon2 

# The prime modulus (same as for Curve25519)
P = 2**255 - 19

# Order of the base-point subgroup (a prime number)
L = 2**252 + 27742317777372353535851937790883648493

# Base point for Ed25519 (affine coordinates, as specified in RFC 8032)
B = (
    15112221349535400772501151409588531511454012693041857206046113283949847762202,
    46316835694926478169428394003475163141307993866256225615783033603165251855960,
)
HKDF_HASH = hashes.SHA256()

# Fixed M and N from RFC9382 (in compressed encoding)
M = decode_edwards_point(bytes.fromhex("d048032c6ea0b6d697ddc2e86bda85a33adac920f1bf18e1b0c6d166a5cecdaf"))
N = decode_edwards_point(bytes.fromhex("d3bfb518f44f3430f29d0c92af503865a1ed3281dc69b35dd868ba85f886c4ab"))

def hash_password(password: bytes) -> int:
    """
    Computes w = Argon2(password) mod L, returning an integer in the range [0, L-1].
    For a PAKE use-case (no need to 'verify' later), you can use a fixed or
    derived salt rather than a random one you must store.
    """
    # fixed salt:
    salt = b"Argon2PWHashSaltValue"

    # Produce a raw 64-byte Argon2 digest
    argon_digest = argon2.low_level.hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=2,
        memory_cost=2**17,
        parallelism=1,
        hash_len=32,
        type=argon2.low_level.Type.I
    )

    # Convert to integer mod L
    return int.from_bytes(argon_digest, "big") % L


# Originally, this was my hash function, but when double chekcing with the RFC, it recommends a "Memory-Hard" function
# after some research, I found that Argon2 is a good choice for this.
# def hash_password(password: bytes) -> int:
#     """Computes w = H(password) mod L."""
#     digest = hashlib.sha512(password).digest()
#     return int.from_bytes(digest, "big") % L

def encode_with_length(value: bytes) -> bytes:
    """Encodes a byte string with an 8-byte little-endian length prefix."""
    return len(value).to_bytes(8, 'little') + value

def b64e(data: bytes) -> bytes:
    return base64.b64encode(data)

def b64d(data: bytes) -> bytes:
    return base64.b64decode(data)

# This is the SPAKE2 implementation for Assignment 2.
# It includes the SPAKE2 protocol, the handshake, and a secure channel for messaging.
# The SecureChannel class is pretty much identical to the one in SIGMA.
# --- SPAKE2 Implementation ---
class SPAKE2Party:
    """
    Represents one party in the SPAKE2 protocol.
    Each party is provisioned with a name, password, and a role:
        - Role A uses M.
        - Role B uses N.
    """
    def __init__(self, name: str, password: bytes, use_m: bool):
        self.name = name
        self.password = password
        self.w = hash_password(password)
        
        # Generate ephemeral scalar for the session:
        self.x = int.from_bytes(os.urandom(32), "little") % L
        
        # Use the standard Ed25519 base as the generator:
        self.B = affine_to_extended(B)
        
        # Compute ephemeral public key: X = x * B
        self.X = encode_edwards_point(edwards_scalar_mult(self.x, self.B))
        self.base = M if use_m else N
        # Compute public message: p = X + w * base
        self.pi = self.compute_public_message()
        
        # Define "A" if we're using M, "B" if we're using N.
        self.role = "A" if use_m else "B"
        
        # Store peer values (to be set during handshake)
        self.peer_pi: Optional[bytes] = None  # Peer’s public message
        self.peer_name: Optional[str] = None  # Peer’s name
        self.shared_secret: Optional[bytes] = None  # Shared key
        self.peer_confirmation: Optional[bytes] = None  # Confirmation MAC


    def compute_public_message(self) -> bytes:
        """
        Computes the SPAKE2 public message:
            p = X + w*base
        where X is the static public key and base is M or N.
        Returns the encoded group element.
        """
        # Decode the ephemeral public key from bytes to a (extended) point.
        X_point = decode_edwards_point(self.X) 
        
        # M^w or N^w, which is a scalar multiplication.
        adjustment = edwards_scalar_mult(self.w, self.base)
        
        # Compute the public message: p = X + w*base (g^x + M^w or N^w)
        pi = edwards_point_add_extended(X_point, adjustment)
        return encode_edwards_point(pi)

    def compute_shared_secret(self) -> bytes:
        """
        Computes the shared secret K.
        For party A: K = 8 * x * (pB - w*N)
        For party B: K = 8 * y * (pA - w*M)
        Here, x (or y) is the ephemeral scalar generated in __init__.
        The result is hashed (via SHA-256).
        """
        if self.peer_pi is None:
            raise ValueError("Peer public message not received yet!")

        scalar = self.x  # Use the ephemeral scalar generated at initialization.
        peer_point = decode_edwards_point(self.peer_pi)
        if not is_valid_edwards_point(peer_point):
            raise ValueError("Received point is not in the correct subgroup")
        
        # Use the opposite fixed element: if self.base is M then use N; if self.base is N then use M.
        opposite_base = N if self.base == M else M
        
        # Compute the adjustment: w * opposite_base / N^w or M^w
        adjustment = edwards_scalar_mult(self.w, opposite_base)
        
        # Adjust the peer's point: pB + (-w)*N or pA + (-w)*M
        adjusted_peer = edwards_point_add_extended(peer_point, edwards_point_negate(adjustment))
        
        # Multiply by 8 to clear the cofactor. 
        # Same as raising to hx, where h = 8
        K_point = edwards_scalar_mult(8 * scalar, adjusted_peer)
        self.shared_secret = hashlib.sha256(encode_edwards_point(K_point)).digest()
        return self.shared_secret

    def compute_transcript(self) -> bytes:
        """
        Computes the protocol transcript TT using the stored values.

        RFC 9382 defines the order as:
            TT = len(A) || A || len(B) || B || len(pA) || pA || len(pB) || pB || len(K) || K || len(w) || w
        """
        if self.peer_name is None or self.peer_pi is None or self.shared_secret is None:
            raise ValueError("Cannot compute transcript before receiving peer's message and computing shared secret.")

        # Ensure A is always first and B second
        if self.role == "A":
            name_A, pi_A = self.name, self.pi
            name_B, pi_B = self.peer_name, self.peer_pi
        else:
            name_A, pi_A = self.peer_name, self.peer_pi
            name_B, pi_B = self.name, self.pi

        return (
            encode_with_length(name_A.encode()) +
            encode_with_length(name_B.encode()) +
            encode_with_length(pi_A) +
            encode_with_length(pi_B) +
            encode_with_length(self.shared_secret) +
            encode_with_length(self.w.to_bytes(32, "big"))
        )

    def key_schedule(self) -> Tuple[bytes, bytes, bytes, bytes]:
        """
        Derives the key material from the transcript.
        Let Hash(TT) = Ke || Ka, where each is 16 bytes (for a 32-byte hash).
        Then derive confirmation keys via HKDF from Ka.
        Returns (Ke, Ka, KcA, KcB).
        """
        transcript = self.compute_transcript()
        hash_tt = hashlib.sha256(transcript).digest()
        Ke = hash_tt[:16]
        Ka = hash_tt[16:32]
        kdf = HKDF(algorithm=HKDF_HASH, length=32, salt=None, info=b"ConfirmationKeys")
        derived = kdf.derive(Ka)
        KcA, KcB = derived[:16], derived[16:]
        return Ke, Ka, KcA, KcB
    
    def store_peer_confirmation(self, peer_conf: bytes):
        """
        Stores the confirmation message received from the peer.
        """
        self.peer_confirmation = peer_conf
    
    def receive_peer_message(self, peer_pi: bytes, peer_name: str):
        """
        Stores the received public message and peer's name.
        This should be called when the other party's public message is received.
        """
        self.peer_pi = peer_pi
        self.peer_name = peer_name

    def generate_confirmation(self, Kc: bytes) -> bytes:
        """
        Generates a confirmation MAC over the transcript using HMAC-SHA256.
        """
        transcript = self.compute_transcript()
        return built_in_hmac.new(Kc, transcript, hashlib.sha256).digest()

    def verify_peer_confirmation(self, Kc: bytes) -> bool:
        """
        Verifies the confirmation MAC received from the peer.
        """
        if self.peer_confirmation is None:
            raise ValueError("No peer confirmation received!")

        transcript = self.compute_transcript()
        expected = built_in_hmac.new(Kc, transcript, hashlib.sha256).digest()
        return built_in_hmac.compare_digest(self.peer_confirmation, expected)

class SPAKE2Handshake:
    """
    Orchestrates the SPAKE2 handshake between two parties.

    The flow is:
        1. Exchange public messages (pA and pB).
        2. Each computes the shared secret K.
        3. Both parties compute the transcript TT.
        4. A key schedule is performed to derive Ke, Ka, KcA, KcB.
        5. Parties exchange confirmation MACs.
    """

    def __init__(self, initiator: SPAKE2Party, responder: SPAKE2Party):
        self.initiator = initiator
        self.responder = responder

    def run_handshake(self) -> Tuple[bytes, bytes]:
        """
        Executes the full handshake.

        Returns:
            - Ke: The shared secret key for the protocol.
            - transcript: The protocol transcript.
        """
        # Step 1: Exchange public messages
        pA, pB = self.initiator.pi, self.responder.pi

        # Store peer's info in both parties
        self.initiator.receive_peer_message(pB, self.responder.name)
        self.responder.receive_peer_message(pA, self.initiator.name)

        # Step 2: Compute shared secret
        K_A = self.initiator.compute_shared_secret()
        K_B = self.responder.compute_shared_secret()

        if K_A != K_B:
            raise ValueError("Shared secret mismatch!")
        
        # Step 3: Compute transcript (each party does it individually)
        transcript_A = self.initiator.compute_transcript()
        transcript_B = self.responder.compute_transcript()

        if transcript_A != transcript_B:
            raise ValueError("Transcript mismatch!")

        transcript = transcript_A  # Either one works, since they are equal

        # Step 4: Derive keys from the transcript
        Ke_A, Ka_A, KcA_A, KcB_A = self.initiator.key_schedule()
        Ke_B, Ka_B, KcA_B, KcB_B = self.responder.key_schedule()

        if Ke_A != Ke_B:
            raise ValueError("Ke mismatch!")

        # Step 5: Exchange confirmation messages
        conf_A = self.initiator.generate_confirmation(KcA_A)
        conf_B = self.responder.generate_confirmation(KcB_B)

        # Store peer's confirmation messages
        self.initiator.store_peer_confirmation(conf_B)
        self.responder.store_peer_confirmation(conf_A)

        # Verify confirmations
        if not self.responder.verify_peer_confirmation(KcA_A):
            raise ValueError("Initiator confirmation failed!")
        if not self.initiator.verify_peer_confirmation(KcB_B):
            raise ValueError("Responder confirmation failed!")

        return Ke_A, transcript

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
        h = hmac.HMAC(self.mac_key, hashes.SHA256())
        h.update(data)
        return h.finalize()

    def send_message(self, plaintext: bytes) -> bytes:
        """
        Encrypts and authenticates a message.

        Args:
            plaintext (bytes): The plaintext message.

        Returns:
            bytes: A JSON-encoded message ready for transmission.
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
            ValueError: If HMAC verification fails or if message is tampered with.
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
        return built_in_hmac.compare_digest(a, b)

def SPAKE2_demo():
    password = b"securepassword"
    
    # Create SPAKE2 parties
    alice = SPAKE2Party("Alice", password, use_m=True)
    bob = SPAKE2Party("Bob", password, use_m=False)
    
    # Perform the handshake
    handshake = SPAKE2Handshake(alice, bob)
    shared_secret, transcript = handshake.run_handshake()
    
    print("SPAKE2 Handshake Completed!")
    print("Shared secret Ke:", shared_secret.hex())
    
    # Derive keys for secure channel from shared_secret using HKDF.
    kdf = HKDF(algorithm=HKDF_HASH, length=32, salt=None, info=b"SecureChannel")
    session_key = kdf.derive(shared_secret)
    
    secure_channel_alice = SecureChannel(session_key)
    secure_channel_bob = SecureChannel(session_key)
    
    plaintext = b"Hello Bob, this is a secret message from Alice via SPAKE2!"
    encrypted_msg = secure_channel_alice.send_message(plaintext)
    decrypted_msg = secure_channel_bob.receive_message(encrypted_msg)
    
    assert decrypted_msg == plaintext, "Decryption failed!"
    print("Secure messaging successful!")
    print("Decrypted message:", decrypted_msg.decode())

if __name__ == "__main__":
    SPAKE2_demo()
