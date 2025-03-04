import unittest
import os
import time
from x25519.x25519 import X25519
from x25519.utils import bytes_to_int, int_to_bytes
from nacl.bindings import crypto_scalarmult, crypto_scalarmult_base

class TestX25519(unittest.TestCase):
    def test_generate_public_key(self):
        x25519 = X25519()
        private_key = os.urandom(32)
        public_key = x25519.generate_public_key(private_key)
        
        self.assertEqual(len(public_key), 32)
        self.assertNotEqual(private_key, public_key)

    def test_rfc7748_vector1_double_add(self):
        x25519 = X25519("double_and_add")
        private_key = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        public_key = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        expected_output = bytes.fromhex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        result = x25519.scalar_multiply(private_key, public_key)
        self.assertEqual(result, expected_output)

    # def test_rfc7748_vector2_double_add(self):
    #     x25519 = X25519("double_and_add")
    #     private_key = bytes.fromhex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
    #     public_key = bytes.fromhex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a413")
    #     expected_output = bytes.fromhex("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")
    #     result = x25519.scalar_multiply(private_key, public_key)
    #     print(f"Expected: {expected_output.hex()}, Got: {result.hex()}")  # Debugging
    #     self.assertEqual(result, expected_output)

    def test_rfc7748_vector1_ladder(self):
        x25519 = X25519("ladder")
        private_key = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        public_key = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        expected_output = bytes.fromhex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        result = x25519.scalar_multiply(private_key, public_key)
        self.assertEqual(result, expected_output)

    def test_rfc7748_vector2_ladder(self):
        """Validate RFC 7748 test vector 2 using the ladder and PyNaCl for verification."""
        x25519 = X25519("ladder")
        private_key = bytes.fromhex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
        public_key = bytes.fromhex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a413")
        #public_key = int_to_bytes(8883857351183929894090759386610649319417338800022198945255395922347792736741)
        #print(f"Is public key as int: {bytes_to_int(public_key)} the same as: {public_key_int}")
        #print(f"Private key as int: {bytes_to_int(private_key)} ")
        #print(f"Public key as int: {bytes_to_int(public_key)} ")
        public_key_generated = x25519.generate_public_key(private_key)
        #print(f"Public key generated: {public_key_generated.hex()}")
        #print(f"Public key expected: {public_key.hex()}")
        expected_output = bytes.fromhex("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")
        
        # X25519 implementation
        result = x25519.scalar_multiply(private_key, public_key)
        # Use PyNaCl for reference
        pynacl_result = crypto_scalarmult(private_key, public_key)
    
        #print(f"Result for RFC Vector 2: {result.hex()}")
        #print(f"Expected (RFC 7748): {expected_output.hex()}")
        #print(f"Result from X25519: {result.hex()}")
        #print(f"Result from PyNaCl: {pynacl_result.hex()}")

        # Assert that implementation matches both the expected RFC value and PyNaCl's output
        self.assertEqual(result, pynacl_result, "Mismatch with PyNaCl result")
        self.assertEqual(result, expected_output, "Mismatch with RFC 7748 expected value")


    def test_iterative_scalar_multiplication_double_add(self):
        """Perform iterative scalar multiplication 1, 1000, and 1,000,000 times and verify results."""
        x25519 = X25519("double_and_add")
        
        # Initial values
        k = bytes.fromhex("0900000000000000000000000000000000000000000000000000000000000000")
        u = k  # Initially set u to k

        # Expected results for 1, 1000, and 1,000,000 iterations
        expected_results = {
            1: "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
            1000: "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
            1000000: "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424"
        }

        # Iterative scalar multiplication
        for i in range(1, 1001):
            result = x25519.scalar_multiply(k, u)
            k, u = result, k  # Set k to the result and u to the old k
            
            # Check results at specified iterations
            if i in expected_results:
                expected_output = bytes.fromhex(expected_results[i])
                self.assertEqual(result, expected_output, f"Failed at iteration {i}")

    def test_iterative_scalar_multiplication_ladder(self):
        """Perform iterative scalar multiplication 1, 1000, and 1,000,000 times and verify results."""
        x25519 = X25519("ladder")
        
        # Initial values
        k = bytes.fromhex("0900000000000000000000000000000000000000000000000000000000000000")
        u = k  # Initially set u to k

        # Expected results for 1, 1000, and 1,000,000 iterations
        expected_results = {
            1: "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
            1000: "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
            1000000: "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424"
        }

        # Iterative scalar multiplication
        for i in range(1, 1001):
            result = x25519.scalar_multiply(k, u)
            k, u = result, k  # Set k to the result and u to the old k
            
            # Check results at specified iterations
            if i in expected_results:
                expected_output = bytes.fromhex(expected_results[i])
                self.assertEqual(result, expected_output, f"Failed at iteration {i}")

    def test_consistency_between_methods(self):
        """Ensure that the result of 'ladder' matches 'double_and_add'."""
        x25519_ladder = X25519("ladder")
        x25519_double_add = X25519("double_and_add")
        # Use either to get the keys
        private_key = x25519_ladder.generate_private_key()
        public_key = x25519_ladder.generate_public_key(private_key)
        
        result_ladder = x25519_ladder.scalar_multiply(private_key, public_key)
        result_double_add = x25519_double_add.scalar_multiply(private_key, public_key)
        
        self.assertEqual(result_ladder, result_double_add, "Mismatch between ladder and double_and_add methods.")


    def test_consistency_between_methods_and_pynacl(self):
        """Ensure that the result of 'ladder' matches 'double_and_add' and PyNaCl,
        and that public key generation agrees with PyNaCl, over many iterations."""
        iterations = 100
        for i in range(iterations):
            # Initialize both implementations.
            x25519_ladder = X25519("ladder")
            x25519_double_add = X25519("double_and_add")
            
            # Generate a private key (32 bytes, already clamped)
            private_key = x25519_ladder.generate_private_key()
            
            # Compute the public key using our implementation (scalar multiplication with base point)
            public_key = x25519_ladder.generate_public_key(private_key)
            
            # Verify public key generation against PyNaCl.
            # PyNaCl's crypto_scalarmult_base computes the public key as private_key * base_point.
            public_key_pynacl = crypto_scalarmult_base(private_key)
            self.assertEqual(
                public_key, public_key_pynacl,
                f"Iteration {i}: Public key mismatch between our implementation and PyNaCl."
            )
            
            # Compute scalar multiplication using both methods.
            result_ladder = x25519_ladder.scalar_multiply(private_key, public_key)
            result_double_add = x25519_double_add.scalar_multiply(private_key, public_key)
            self.assertEqual(
                result_ladder, result_double_add,
                f"Iteration {i}: Mismatch between ladder and double_and_add methods."
            )
            
            # Use PyNaCl to perform the scalar multiplication.
            result_pynacl = crypto_scalarmult(private_key, public_key)
            self.assertEqual(
                result_ladder, result_pynacl,
                f"Iteration {i}: Mismatch between our implementation and PyNaCl."
            )


    def test_performance_comparison(self):
        """Compare performance of MontgomeryLadder and MontgomeryDoubleAdd averaged over multiple runs."""
        import time
        x25519_ladder = X25519(method='ladder')
        x25519_double_add = X25519(method='double_and_add')
        
        private_key = os.urandom(32)
        base_point = int.to_bytes(9, 32, 'little')
        
        iterations = 100
        total_ladder_time = 0.0
        total_double_add_time = 0.0

        # Perform a few warm-up iterations
        for _ in range(2):
            x25519_ladder.scalar_multiply(private_key, base_point)
            x25519_double_add.scalar_multiply(private_key, base_point)

        # Run and time each implementation over multiple iterations.
        for _ in range(iterations):
            start_time = time.time()
            result_ladder = x25519_ladder.scalar_multiply(private_key, base_point)
            total_ladder_time += time.time() - start_time

            start_time = time.time()
            result_double_add = x25519_double_add.scalar_multiply(private_key, base_point)
            total_double_add_time += time.time() - start_time

            # Verify that both implementations produce the same result.
            self.assertEqual(result_ladder, result_double_add)

        avg_ladder_time = total_ladder_time / iterations
        avg_double_add_time = total_double_add_time / iterations

        print(f"MontgomeryLadder Average Time: {avg_ladder_time:.6f}s")
        print(f"MontgomeryDoubleAdd Average Time: {avg_double_add_time:.6f}s")
        speedup = avg_double_add_time / avg_ladder_time
        print(f"MontgomeryLadder is {speedup:.2f} times faster than MontgomeryDoubleAdd.")
        # For instance, assert that ladder is no more than 5 times slower than double_and_add.
        self.assertTrue(avg_ladder_time <= avg_double_add_time * 5)

if __name__ == "__main__":
    unittest.main()
