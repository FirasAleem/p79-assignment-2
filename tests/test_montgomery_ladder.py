import unittest
import random
import time
from x25519.x25519 import X25519
from nacl.bindings import crypto_scalarmult


class TestX25519(unittest.TestCase):
    def setUp(self):
        """Set up the X25519 class with both 'ladder' and 'double_and_add' methods."""
        self.x25519_ladder = X25519(method='ladder')
        self.x25519_double_add = X25519(method='double_and_add')

    def test_scalar_multiply_maximum(self):
        """Test scalar multiplication with the maximum possible scalar and validate against PyNaCl."""
        max_scalar = (1 << 255) - 1
        max_scalar_bytes = max_scalar.to_bytes(32, 'little')
        public_key = b'\x09' + b'\x00' * 31  # Base point

        # X25519 implementation
        result_x = self.x25519_ladder.scalar_multiply(max_scalar_bytes, public_key)
        
        # Use PyNaCl for reference
        expected_output = crypto_scalarmult(max_scalar_bytes, public_key)
        
        # Assert that the results match
        self.assertEqual(result_x, expected_output, "Mismatch between X25519 and PyNaCl for max scalar")

    def test_scalar_multiply_large_scalars(self):
        """Test scalar multiplication with large scalar values and validate with PyNaCl."""
        large_scalar = (1 << 253) - 230703
        large_scalar_bytes = large_scalar.to_bytes(32, 'little')
        base_point = b'\x09' + b'\x00' * 31  # u-coordinate of the base point
        
        # X25519 implementation
        result_x = self.x25519_ladder.scalar_multiply(large_scalar_bytes, base_point)
        
        # Use PyNaCl for reference
        expected_output = crypto_scalarmult(large_scalar_bytes, base_point)
        
        # Assert that the result matches PyNaCl's output
        self.assertEqual(result_x, expected_output, "Mismatch with PyNaCl result for large scalar")

    def test_performance_comparison(self):
        """
        Compare the performance of our MontgomeryLadder scalar multiplication
        with PyNaCl's implementation, using the same mid-range scalar and base point.
        The test runs 10 iterations for each and prints the average time.
        """
        import time
        from nacl.bindings import crypto_scalarmult

        # Create a mid-range scalar.
        scalar = (1 << 200) + 230703
        scalar_bytes = scalar.to_bytes(32, 'little')
        
        # Standard base point for X25519.
        base_point = b'\x09' + b'\x00' * 31

        iterations = 1000
        total_time_ours = 0.0
        total_time_pynacl = 0.0

        # We'll store the last computed result for final verification.
        result_ours = None
        result_pynacl = None

        for _ in range(iterations):
            # Time our MontgomeryLadder implementation.
            start_time = time.time()
            result_ours = self.x25519_ladder.scalar_multiply(scalar_bytes, base_point)
            duration_ours = time.time() - start_time
            total_time_ours += duration_ours

            # Time PyNaCl's implementation.
            start_time = time.time()
            result_pynacl = crypto_scalarmult(scalar_bytes, base_point)
            duration_pynacl = time.time() - start_time
            total_time_pynacl += duration_pynacl

        avg_time_ours = total_time_ours / iterations
        avg_time_pynacl = total_time_pynacl / iterations

        print(f"Our implementation average scalar multiplication took {avg_time_ours:.6f} seconds.")
        print(f"PyNaCl scalar multiplication average took {avg_time_pynacl:.6f} seconds.")

        speedup = avg_time_ours/avg_time_pynacl
        print(f"Speedup factor: {speedup:.2f}")
        # Verify that both implementations produce a result of type bytes.
        self.assertTrue(isinstance(result_ours, bytes))
        self.assertTrue(isinstance(result_pynacl, bytes))
        
        # Optionally, check that the results match.
        self.assertEqual(result_ours, result_pynacl)


if __name__ == "__main__":
    unittest.main()
