import unittest
from x25519.x25519 import X25519


class TestX25519ECDH(unittest.TestCase):
    def setUp(self):
        """Set up the X25519 instance."""
        self.x25519 = X25519()

    def test_ecdh_shared_secret(self):
        """Test ECDH shared secret generation using RFC 7748 test vectors."""
        # Alice's private key
        alice_private_key = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        # Alice's expected public key
        alice_public_key = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        
        # Bob's private key
        bob_private_key = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        # Bob's expected public key
        bob_public_key = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        
        # Expected shared secret
        expected_shared_secret = bytes.fromhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

        # Verify that Alice's and Bob's public keys are correctly generated
        generated_alice_public_key = self.x25519.generate_public_key(alice_private_key)
        generated_bob_public_key = self.x25519.generate_public_key(bob_private_key)
        
        self.assertEqual(generated_alice_public_key, alice_public_key, "Mismatch in Alice's public key")
        self.assertEqual(generated_bob_public_key, bob_public_key, "Mismatch in Bob's public key")
        
        # Alice computes the shared secret using Bob's public key
        alice_shared_secret = self.x25519.scalar_multiply(alice_private_key, bob_public_key)
        # Bob computes the shared secret using Alice's public key
        bob_shared_secret = self.x25519.scalar_multiply(bob_private_key, alice_public_key)
        
        # Verify that both shared secrets are equal
        self.assertEqual(alice_shared_secret, bob_shared_secret, "Mismatch in shared secret between Alice and Bob")
        
        # Verify that the shared secret matches the expected value
        self.assertEqual(alice_shared_secret, expected_shared_secret, "Mismatch with expected shared secret")

        # Check that the shared secret is not all zeros
        self.assertNotEqual(alice_shared_secret, b'\x00' * 32, "Shared secret is all zeros, invalid result")


if __name__ == "__main__":
    unittest.main()
