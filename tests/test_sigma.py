import base64
import pytest
import unittest
import os
import json
from cryptography.hazmat.primitives import hashes
from x25519.x25519 import X25519PrivateKey, X25519PublicKey
from ed25519.ed25519 import SigningKey, VerifyingKey
from sigma.sigma import (
    SigmaParty, SigmaHandshake, SecureChannel, compute_hmac, hmac_compare
)
from sigma.certificates import CertificateAuthority, Certificate


class TestSigmaProtocol(unittest.TestCase):
    ### TEST CERTIFICATE AUTHORITY (CA) ###
    def test_certificate_authority(self):
        ca = CertificateAuthority("TestCA")
        subject_key = VerifyingKey.from_signing_key(SigningKey.generate())
        cert = ca.issue_certificate("Alice", subject_key)

        assert cert.subject_name == "Alice"
        assert cert.issuer_name == "TestCA"
        assert ca.verify_certificate(cert) is True

    def test_certificate_verification_failure(self):
        ca1 = CertificateAuthority("CA1")
        ca2 = CertificateAuthority("CA2")
        
        subject_key = VerifyingKey.from_signing_key(SigningKey.generate())
        cert = ca1.issue_certificate("Alice", subject_key)
        
        assert ca2.verify_certificate(cert) is False  # Should fail as different CA signed it

    ### TEST ED25519 SIGNING & VERIFICATION ###
    def test_ed25519_signing(self):
        signing_key = SigningKey.generate()
        verifying_key = VerifyingKey.from_signing_key(signing_key)
        message = b"Hello, Ed25519!"

        signature = signing_key.sign(message)
        self.assertTrue(verifying_key.verify(message, signature))

    def test_ed25519_invalid_signature(self):
        sk1 = SigningKey.generate()
        sk2 = SigningKey.generate()
        vk2 = VerifyingKey.from_signing_key(sk2)
        
        message = b"Hello, world!"
        signature = sk1.sign(message)
        
        assert vk2.verify(signature, message) is False  # Should fail with different key

    ### TEST X25519 KEY EXCHANGE ###
    def test_x25519_key_exchange(self):
        priv1 = X25519PrivateKey.generate()
        priv2 = X25519PrivateKey.generate()
        
        pub1 = X25519PublicKey.from_private_key(priv1)
        pub2 = X25519PublicKey.from_private_key(priv2)
        
        shared1 = priv1.exchange(pub2)
        shared2 = priv2.exchange(pub1)
        
        assert shared1 == shared2  # Shared secrets should match

    ### TEST SIGMA HANDSHAKE ###
    def test_sigma_handshake(self):
        ca = CertificateAuthority("TestCA")
        alice = SigmaParty("Alice", ca.public_key)
        bob = SigmaParty("Bob", ca.public_key)

        alice.set_certificate(ca.issue_certificate("Alice", alice.ed25519_public))
        bob.set_certificate(ca.issue_certificate("Bob", bob.ed25519_public))

        handshake = SigmaHandshake(alice, bob)

        # Step 1: Alice initiates handshake
        sigma_init_msg = handshake.create_initiation_message()

        # Step 2: Bob responds
        sigma_resp_msg = handshake.handle_initiation_message(sigma_init_msg)

        # Step 3: Alice processes response
        sigma_final_msg = handshake.process_response_message(sigma_resp_msg)

        # Step 4: Bob finalizes handshake
        session_key = handshake.finalize_handshake(sigma_final_msg)

        assert session_key is not None
        assert alice.session_key == bob.session_key  # Keys must match

    ### TEST SECURE CHANNEL ###
    def test_secure_channel(self):
        key = os.urandom(32)
        mac_key = os.urandom(32)
        
        secure_channel = SecureChannel(key)
        
        message = b"Confidential message"
        encrypted_message = secure_channel.send_message(message)
        
        decrypted_message = secure_channel.receive_message(encrypted_message)
        
        assert decrypted_message == message

    def test_secure_channel_tampering(self):
        key = os.urandom(32)
        mac_key = os.urandom(32)
        
        secure_channel = SecureChannel(key)
        
        message = b"Confidential message"
        encrypted_message = secure_channel.send_message(message)
        
        # Decode the JSON message
        data = json.loads(encrypted_message.decode("utf-8"))
        
        # Corrupt the HMAC (change just one character)
        corrupted_hmac = data["hmac_b64"][:-2] + "AB"  # Change last two characters
        data["hmac_b64"] = corrupted_hmac
        
        # Re-encode the corrupted message
        tampered_message = json.dumps(data).encode("utf-8")

        # Now expect the ValueError for HMAC verification failure
        with pytest.raises(ValueError, match="HMAC verification failed"):
            secure_channel.receive_message(tampered_message)

    ### TEST HMAC FUNCTIONS ###
    def test_hmac(self):
        key = os.urandom(32)
        message = b"Integrity check"

        tag1 = compute_hmac(key, message)
        tag2 = compute_hmac(key, message)

        assert hmac_compare(tag1, tag2) is True

    def test_hmac_mismatch(self):
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        message = b"Integrity check"

        tag1 = compute_hmac(key1, message)
        tag2 = compute_hmac(key2, message)

        assert hmac_compare(tag1, tag2) is False  # Different keys should fail

    ### TEST EDGE CASES ###
    def test_invalid_certificate(self):
        cert_data = {
            "subject_name": "Alice",
            "subject_key_b64": "invalid_base64",
            "issuer_name": "TestCA",
            "signature_b64": "invalid_base64"
        }

        with pytest.raises(Exception):
            Certificate.from_dict(cert_data)

    def test_invalid_signature(self):
        sk = SigningKey.generate()
        vk = VerifyingKey.from_signing_key(sk)

        message = b"Hello, world!"
        invalid_signature = os.urandom(64)  # Random bytes instead of a valid signature

        assert vk.verify(invalid_signature, message) is False

    def test_sigma_handshake_invalid_mac(self):
        ca = CertificateAuthority("TestCA")
        alice = SigmaParty("Alice", ca.public_key)
        bob = SigmaParty("Bob", ca.public_key)

        alice.set_certificate(ca.issue_certificate("Alice", alice.ed25519_public))
        bob.set_certificate(ca.issue_certificate("Bob", bob.ed25519_public))

        handshake = SigmaHandshake(alice, bob)

        sigma_init_msg = handshake.create_initiation_message()
        sigma_resp_msg = handshake.handle_initiation_message(sigma_init_msg)

        # Decode the JSON response
        data = json.loads(sigma_resp_msg.decode("utf-8"))

        # Modify the HMAC while keeping it valid Base64
        original_hmac = data["hmac_b64"]
        corrupted_hmac = original_hmac[:-2] + "AB"  # Modify last two characters
        data["hmac_b64"] = corrupted_hmac

        # Re-encode the modified response
        corrupted_resp_msg = json.dumps(data).encode("utf-8")

        # Expect MAC verification failure, not Base64 error
        with pytest.raises(ValueError, match="MAC verification failed"):
            handshake.process_response_message(corrupted_resp_msg)

    def test_full_sigma_protocol(self):
        """
        Full integration test:
        - Setup CA
        - Issue certificates
        - Perform SIGMA handshake
        - Establish a secure communication channel
        - Encrypt & decrypt messages
        - Verify integrity & confidentiality
        """

        # Step 1: Setup Certificate Authority (CA)
        ca = CertificateAuthority("TestCA")
        ca_public_key = ca.public_key

        # Step 2: Create Alice and Bob as SIGMA parties
        alice = SigmaParty("Alice", ca_public_key)
        bob = SigmaParty("Bob", ca_public_key)

        # Step 3: CA issues certificates
        alice_cert = ca.issue_certificate("Alice", alice.ed25519_public)
        bob_cert = ca.issue_certificate("Bob", bob.ed25519_public)

        alice.set_certificate(alice_cert)
        bob.set_certificate(bob_cert)

        # Step 4: Perform the SIGMA handshake
        handshake = SigmaHandshake(alice, bob)

        # Alice initiates handshake
        sigma_init_msg = handshake.create_initiation_message()
        
        # Bob processes the initiation and responds
        sigma_resp_msg = handshake.handle_initiation_message(sigma_init_msg)
        
        # Alice processes response and sends final message
        sigma_final_msg = handshake.process_response_message(sigma_resp_msg)
        
        # Bob finalizes the handshake
        session_key = handshake.finalize_handshake(sigma_final_msg)

        # Ensure that Alice and Bob now share the same session key
        assert alice.session_key == bob.session_key
        assert session_key == alice.session_key

        # Step 5: Establish secure communication
        secure_channel_alice = SecureChannel(alice.session_key)
        secure_channel_bob = SecureChannel(bob.session_key)

        # Alice sends a secure message to Bob
        original_message = b"Hello Bob, this is Alice!"
        encrypted_message = secure_channel_alice.send_message(original_message)

        # Bob receives and decrypts the message
        decrypted_message = secure_channel_bob.receive_message(encrypted_message)

        # Ensure integrity and confidentiality
        assert decrypted_message == original_message

        # Bob sends a secure message back to Alice
        reply_message = b"Hey Alice, message received!"
        encrypted_reply = secure_channel_bob.send_message(reply_message)

        # Alice decrypts the reply
        decrypted_reply = secure_channel_alice.receive_message(encrypted_reply)

        # Ensure successful bidirectional communication
        assert decrypted_reply == reply_message

        print("\nFull SIGMA protocol setup & secure messaging test passed")

    # SIGMA-I Tests
    def test_sigma_handshake_identity_protection(self):
        ca = CertificateAuthority("TestCA")
        alice = SigmaParty("Alice", ca.public_key)
        bob = SigmaParty("Bob", ca.public_key)

        alice.set_certificate(ca.issue_certificate("Alice", alice.ed25519_public))
        bob.set_certificate(ca.issue_certificate("Bob", bob.ed25519_public))

        handshake = SigmaHandshake(alice, bob, identity_protection=True)

        sigma_init_msg = handshake.create_initiation_message()
        sigma_resp_msg = handshake.handle_initiation_message(sigma_init_msg)
        sigma_final_msg = handshake.process_response_message(sigma_resp_msg)
        session_key = handshake.finalize_handshake(sigma_final_msg)

        assert session_key is not None
        assert alice.session_key == bob.session_key  # Keys must match

    def test_sigma_identity_encryption(self):
        ca = CertificateAuthority("TestCA")
        alice = SigmaParty("Alice", ca.public_key)
        bob = SigmaParty("Bob", ca.public_key)

        alice.set_certificate(ca.issue_certificate("Alice", alice.ed25519_public))
        bob.set_certificate(ca.issue_certificate("Bob", bob.ed25519_public))

        handshake = SigmaHandshake(alice, bob, identity_protection=True)

        sigma_init_msg = handshake.create_initiation_message()
        sigma_resp_msg = handshake.handle_initiation_message(sigma_init_msg)

        data = json.loads(sigma_resp_msg.decode("utf-8"))

        # If identity protection is enabled, the certificate should NOT be visible in plaintext
        assert "certificate" not in data
        assert "ciphertext_b64" in data
        assert "nonce_b64" in data
        assert "tag_b64" in data

    def test_sigma_identity_decryption_failure(self):
        ca = CertificateAuthority("TestCA")
        alice = SigmaParty("Alice", ca.public_key)
        bob = SigmaParty("Bob", ca.public_key)

        alice.set_certificate(ca.issue_certificate("Alice", alice.ed25519_public))
        bob.set_certificate(ca.issue_certificate("Bob", bob.ed25519_public))

        handshake = SigmaHandshake(alice, bob, identity_protection=True)

        sigma_init_msg = handshake.create_initiation_message()
        sigma_resp_msg = handshake.handle_initiation_message(sigma_init_msg)

        # Manually modify the response message to simulate incorrect kE usage
        corrupted_data = json.loads(sigma_resp_msg.decode("utf-8"))
        corrupted_data["nonce_b64"] = base64.b64encode(os.urandom(12)).decode("utf-8")  # Corrupt nonce
        corrupted_message = json.dumps(corrupted_data).encode("utf-8")

        with pytest.raises(ValueError, match="Decryption failed"):
            handshake.process_response_message(corrupted_message)

    def test_secure_channel_identity_protection(self):
        ca = CertificateAuthority("TestCA")
        alice = SigmaParty("Alice", ca.public_key)
        bob = SigmaParty("Bob", ca.public_key)

        alice.set_certificate(ca.issue_certificate("Alice", alice.ed25519_public))
        bob.set_certificate(ca.issue_certificate("Bob", bob.ed25519_public))

        handshake = SigmaHandshake(alice, bob, identity_protection=True)

        sigma_init_msg = handshake.create_initiation_message()
        sigma_resp_msg = handshake.handle_initiation_message(sigma_init_msg)
        sigma_final_msg = handshake.process_response_message(sigma_resp_msg)
        session_key = handshake.finalize_handshake(sigma_final_msg)

        assert session_key == alice.session_key == bob.session_key

        # Secure messaging
        secure_channel_alice = SecureChannel(alice.session_key)
        secure_channel_bob = SecureChannel(bob.session_key)

        # Alice sends a message
        plaintext = b"Identity protected message!"
        encrypted_message = secure_channel_alice.send_message(plaintext)

        # Bob decrypts the message
        decrypted_message = secure_channel_bob.receive_message(encrypted_message)

        assert decrypted_message == plaintext
    
    def test_sigma_identity_ciphertext_tampering(self):
        ca = CertificateAuthority("TestCA")
        alice = SigmaParty("Alice", ca.public_key)
        bob = SigmaParty("Bob", ca.public_key)

        alice.set_certificate(ca.issue_certificate("Alice", alice.ed25519_public))
        bob.set_certificate(ca.issue_certificate("Bob", bob.ed25519_public))

        handshake = SigmaHandshake(alice, bob, identity_protection=True)

        sigma_init_msg = handshake.create_initiation_message()
        sigma_resp_msg = handshake.handle_initiation_message(sigma_init_msg)

        # Tamper with the encrypted identity ciphertext
        data = json.loads(sigma_resp_msg.decode("utf-8"))
        tampered_ciphertext = bytearray(base64.b64decode(data["ciphertext_b64"]))
        tampered_ciphertext[5] ^= 0xFF  # Flip one bit in the ciphertext
        data["ciphertext_b64"] = base64.b64encode(tampered_ciphertext).decode("utf-8")

        tampered_message = json.dumps(data).encode("utf-8")

        with pytest.raises(ValueError, match="Decryption failed"):
            handshake.process_response_message(tampered_message)
            
