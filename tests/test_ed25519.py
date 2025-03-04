import unittest
import os
import time
from ed25519.utils import (
    edwards_scalar_mult,
    encode_edwards_point,
    decode_edwards_point,
    normalize_extended
)
from ed25519.ed25519 import Ed25519

# The prime modulus (same as for Curve25519)
P = 2**255 - 19

# Order of the base-point subgroup (a prime number)
L = 2**252 + 27742317777372353535851937790883648493

# Base point for Ed25519 (affine coordinates, as specified in RFC 8032)
B = (
    15112221349535400772501151409588531511454012693041857206046113283949847762202,
    46316835694926478169428394003475163141307993866256225615783033603165251855960,
)

class TestEd25519(unittest.TestCase):
    def setUp(self):
        """Set up the Ed25519 instance for testing."""
        self.ed25519 = Ed25519()

    def test_generate_private_key(self):
        """Test if the generated private key is 32 bytes long."""
        private_key = self.ed25519.generate_private_key()
        self.assertEqual(len(private_key), 32)

    def test_generate_public_key_length(self):
        """Test if the generated public key is 32 bytes long."""
        private_key = self.ed25519.generate_private_key()
        public_key = self.ed25519.generate_public_key(private_key)
        self.assertEqual(len(public_key), 32)

    def test_sign_and_verify(self):
        """Test if a message can be signed and verified successfully."""
        private_key = self.ed25519.generate_private_key()
        public_key = self.ed25519.generate_public_key(private_key)
        message = b"Hello, Ed25519!"

        signature = self.ed25519.sign(private_key, message)
        self.assertTrue(self.ed25519.verify(public_key, message, signature))

    def test_invalid_signature(self):
        """Test if an invalid signature fails verification."""
        private_key = self.ed25519.generate_private_key()
        public_key = self.ed25519.generate_public_key(private_key)
        message = b"Hello, Ed25519!"
        fake_signature = os.urandom(64)

        self.assertFalse(self.ed25519.verify(public_key, message, fake_signature))

    def test_point_encoding_and_decoding(self):
        """Test if a point can be encoded and decoded correctly."""
        point = edwards_scalar_mult(12345, (0, 1, 1, 0))
        encoded_point = encode_edwards_point(point)
        decoded_point = decode_edwards_point(encoded_point)
        self.assertEqual(normalize_extended(point), normalize_extended(decoded_point))

    def run_vector(self, name, private_key_hex, public_key_hex, message_hex, signature_hex):
        private_key = bytes.fromhex(private_key_hex)
        public_key = bytes.fromhex(public_key_hex)
        message = bytes.fromhex(message_hex)
        expected_signature = bytes.fromhex(signature_hex)
        
        # Check public key generation.
        generated_public_key = self.ed25519.generate_public_key(private_key)
        self.assertEqual(
            generated_public_key, public_key,
            f"Public key mismatch for {name}"
        )
        
        # Sign and compare against expected signature.
        signature = self.ed25519.sign(private_key, message)
        self.assertEqual(
            signature, expected_signature,
            f"Signature mismatch for {name}"
        )
        
        # Verify the signature.
        self.assertTrue(
            self.ed25519.verify(public_key, message, signature),
            f"Signature verification failed for {name}"
        )


    def test_rfc_8032_vectors(self):
        test_vectors = [
            {
                "name": "Vector 1",
                "private_key": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "public_key": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "message": "",
                "signature": "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            },
            {
                "name": "Vector 2",
                "private_key": "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "public_key": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "message": "72",
                "signature": "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            },
            {
                "name": "Vector 3",
                "private_key": "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "public_key": "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "message": "af82",
                "signature": "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            },
            {
                "name": "Vector 1024",
                "private_key": "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
                "public_key": "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
                "message": "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0",
                "signature": "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03",
            },
            {
                "name": "Vector SHA(abc)",
                "private_key": "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
                "public_key": "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
                "message": "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                "signature": "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
            },
        ]

        for vector in test_vectors:
            self.run_vector(
                vector["name"],
                vector["private_key"],
                vector["public_key"],
                vector["message"],
                vector["signature"]
            )

    def test_tampered_message(self):
        private_key = self.ed25519.generate_private_key()
        public_key = self.ed25519.generate_public_key(private_key)
        message = b"Important message"
        signature = self.ed25519.sign(private_key, message)

        # Modify one byte in the message.
        tampered_message = bytearray(message)
        tampered_message[0] ^= 0xFF
        self.assertFalse(self.ed25519.verify(public_key, bytes(tampered_message), signature))

    def test_tampered_public_key(self):
        private_key = self.ed25519.generate_private_key()
        public_key = bytearray(self.ed25519.generate_public_key(private_key))
        message = b"Another message"
        signature = self.ed25519.sign(private_key, message)

        # Modify one byte in the message.
        public_key[0] ^= 0xFF
        self.assertFalse(self.ed25519.verify(bytes(public_key), message, signature))
        
    def test_long_message(self):
        private_key = self.ed25519.generate_private_key()
        public_key = self.ed25519.generate_public_key(private_key)
        message = os.urandom(16777216)  # 16 MB of random data
        signature = self.ed25519.sign(private_key, message)
        self.assertTrue(self.ed25519.verify(public_key, message, signature))
        
    def test_normalization(self):
        # Create a point
        point = edwards_scalar_mult(12345, (0, 1, 1, 0))
        normalized = normalize_extended(point)

        self.assertEqual(normalized[2], 1) # Z-coordinate should be 1
        
    def test_invalid_input_lengths(self):
        private_key = self.ed25519.generate_private_key()
        public_key = self.ed25519.generate_public_key(private_key)
        message = b"Test message"
        invalid_signature = os.urandom(10)  # too short
        self.assertFalse(self.ed25519.verify(public_key, message, invalid_signature))

        # Also, test with an invalid public key length.
        invalid_public_key = os.urandom(10)
        signature = self.ed25519.sign(private_key, message)
        with self.assertRaises(Exception):
            decode_edwards_point(invalid_public_key)
            
    def test_noncanonical_S_rejected(self):
        # Generate a valid key pair and signature.
        private_key = self.ed25519.generate_private_key()
        public_key = self.ed25519.generate_public_key(private_key)
        message = b"Test message for noncanonical s"
        signature = self.ed25519.sign(private_key, message)
        
        # Split signature into R and s.
        R_enc = signature[:32]
        s_enc = signature[32:]
        
        # Convert s to an integer and add the subgroup order L.
        s_int = int.from_bytes(s_enc, "little")
        noncanonical_s = s_int + L  # L is the order of the subgroup.
        
        # Re-encode non-canonical s.
        noncanonical_s_enc = noncanonical_s.to_bytes(32, "little")
        # Construct the tampered signature.
        tampered_signature = R_enc + noncanonical_s_enc

        # Verify that the non-canonical signature is rejected.
        self.assertFalse(self.ed25519.verify(public_key, message, tampered_signature))

    def test_noncanonical_R_rejected(self):
        private_key = self.ed25519.generate_private_key()
        public_key = self.ed25519.generate_public_key(private_key)
        message = b"Test message for noncanonical R"
        signature = self.ed25519.sign(private_key, message)
        
        # Tamper with R's encoding: change its last byte's sign bit arbitrarily.
        R_enc = bytearray(signature[:32])
        R_enc[-1] ^= 0x80  # Flip the sign bit
        tampered_signature = bytes(R_enc) + signature[32:]
        
        # Expect the verifier to reject the signature.
        self.assertFalse(self.ed25519.verify(public_key, message, tampered_signature))

    def test_noncanonical_public_key_rejected(self):
        private_key = self.ed25519.generate_private_key()
        public_key = bytearray(self.ed25519.generate_public_key(private_key))
        message = b"Test message for noncanonical public key"
        signature = self.ed25519.sign(private_key, message)
        
        # Tamper with the public key encoding.
        public_key[-1] ^= 0x40  # Flip a bit to force a non-canonical encoding.
        
        # The verification should reject a non-canonical public key.
        self.assertFalse(self.ed25519.verify(bytes(public_key), message, signature))

    def test_batch_verification(self):
        batch = []
        for _ in range(100):
            private_key = self.ed25519.generate_private_key()
            public_key = self.ed25519.generate_public_key(private_key)
            message = os.urandom(32)
            signature = self.ed25519.sign(private_key, message)
            batch.append((public_key, message, signature))
        self.assertTrue(self.ed25519.verify_batch(batch))
        
        # Tamper with one signature.
        pk, m, sig = batch[0]
        tampered_sig = bytearray(sig)
        tampered_sig[0] ^= 0xFF  # modify a byte
        batch[0] = (pk, m, bytes(tampered_sig))
        self.assertFalse(self.ed25519.verify_batch(batch))

    def test_verification_performance(self):
        batch = []
        number_of_signatures = 1000
        for _ in range(number_of_signatures):
            private_key = self.ed25519.generate_private_key()
            public_key = self.ed25519.generate_public_key(private_key)
            message = os.urandom(32)
            signature = self.ed25519.sign(private_key, message)
            batch.append((public_key, message, signature))
        
        # Measure performance of individual verifications.
        start_individual = time.perf_counter()
        for public_key, message, signature in batch:
            self.assertTrue(self.ed25519.verify(public_key, message, signature))
        individual_time = time.perf_counter() - start_individual

        # Measure performance of batch verification.
        start_batch = time.perf_counter()
        self.assertTrue(self.ed25519.verify_batch(batch))
        batch_time = time.perf_counter() - start_batch

        print(f"Individual verification time for {number_of_signatures} signatures: {individual_time:.6f} seconds")
        print(f"Batch verification time for {number_of_signatures} signatures: {batch_time:.6f} seconds")

    def test_signing_verification_performance_comparison(self):
        """
        Compare performance of our Ed25519 signing and verifying with PyNaCl's implementation.
        The test runs multiple iterations, prints the average times, and reports the speedup factors.
        """
        import time
        from nacl.signing import SigningKey as PyNaClSigningKey
        
        iterations = 1000
        message = b"Performance test message for signing and verifying" * 10

        # Set up our implementation keys.
        private_key = self.ed25519.generate_private_key()
        public_key = self.ed25519.generate_public_key(private_key)
        our_total_sign_time = 0.0
        our_total_verify_time = 0.0

        # Set up PyNaCl keys.
        seed = os.urandom(32)
        pynacl_signing_key = PyNaClSigningKey(seed)
        pynacl_verify_key = pynacl_signing_key.verify_key
        pynacl_total_sign_time = 0.0
        pynacl_total_verify_time = 0.0

        for _ in range(iterations):
            # Time our signing.
            start = time.perf_counter()
            our_signature = self.ed25519.sign(private_key, message)
            our_total_sign_time += time.perf_counter() - start

            # Time PyNaCl signing.
            start = time.perf_counter()
            pynacl_signature = pynacl_signing_key.sign(message).signature
            pynacl_total_sign_time += time.perf_counter() - start

            # Time our verification.
            start = time.perf_counter()
            valid_our = self.ed25519.verify(public_key, message, our_signature)
            our_total_verify_time += time.perf_counter() - start
            self.assertTrue(valid_our)

            # Time PyNaCl verification.
            start = time.perf_counter()
            try:
                pynacl_verify_key.verify(message, pynacl_signature)
                valid_pynacl = True
            except Exception:
                valid_pynacl = False
            pynacl_total_verify_time += time.perf_counter() - start
            self.assertTrue(valid_pynacl)

        avg_our_sign_time = our_total_sign_time / iterations
        avg_pynacl_sign_time = pynacl_total_sign_time / iterations
        avg_our_verify_time = our_total_verify_time / iterations
        avg_pynacl_verify_time = pynacl_total_verify_time / iterations

        print(f"Our signing average: {avg_our_sign_time:.6f} s")
        print(f"PyNaCl signing average: {avg_pynacl_sign_time:.6f} s")
        print(f"Our verification average: {avg_our_verify_time:.6f} s")
        print(f"PyNaCl verification average: {avg_pynacl_verify_time:.6f} s")

        # Compute and print speedup factors for signing.
        if avg_our_sign_time < avg_pynacl_sign_time:
            sign_speedup = avg_pynacl_sign_time / avg_our_sign_time
            print(f"Our signing implementation is {sign_speedup:.2f} times faster than PyNaCl's.")
        else:
            sign_speedup = avg_our_sign_time / avg_pynacl_sign_time
            print(f"PyNaCl's signing implementation is {sign_speedup:.2f} times faster than ours.")

        # Compute and print speedup factors for verifying.
        if avg_our_verify_time < avg_pynacl_verify_time:
            verify_speedup = avg_pynacl_verify_time / avg_our_verify_time
            print(f"Our verification implementation is {verify_speedup:.2f} times faster than PyNaCl's.")
        else:
            verify_speedup = avg_our_verify_time / avg_pynacl_verify_time
            print(f"PyNaCl's verification implementation is {verify_speedup:.2f} times faster than ours.")

if __name__ == "__main__":
    unittest.main()
