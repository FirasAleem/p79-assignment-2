import unittest
from x25519.utils import clamp_scalar, bytes_to_int, int_to_bytes, calculate_y_coordinate

class TestUtils(unittest.TestCase):
    def test_clamp_scalar(self):
        scalar = b'\xFF' * 32  # All bits set
        clamped = clamp_scalar(scalar)
        self.assertEqual(clamped & 7, 0)  # Check 3 least significant bits are cleared
        self.assertTrue((clamped >> 254) & 1)  # Check second-most significant bit is set
        self.assertFalse((clamped >> 255) & 1)  # Check most significant bit is cleared

    def test_bytes_to_int_and_int_to_bytes(self):
        value = 123456789
        length = 32
        converted = int_to_bytes(value, length)
        self.assertEqual(bytes_to_int(converted), value)
        self.assertEqual(len(converted), length)

    def test_calculate_y_coordinate(self):
        x = 9
        A = 486662
        P = 2**255 - 19
        y = calculate_y_coordinate(x, A, P)
        self.assertEqual((y * y) % P, (x**3 + A * x**2 + x) % P)

if __name__ == "__main__":
    unittest.main()
