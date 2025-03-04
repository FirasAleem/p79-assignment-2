# This file doesn’t use the API and instead tests the MontgomeryDoubleAdd class directly
# This is done to ensure that the functions in the class are working as expected
import unittest
from x25519.montgomery_double_add import MontgomeryDoubleAdd
from x25519.utils import calculate_y_coordinate

A = 486662
P = 2**255 - 19

class TestMontgomeryDoubleAdd(unittest.TestCase):
    def setUp(self):
        """Set up the curve parameters and create an instance of MontgomeryDoubleAdd."""
        self.curve = MontgomeryDoubleAdd(A=A, p=P)
        self.A = A
        self.P = P

    def is_point_on_curve(self, point):
        """Check if a point lies on the curve y^2 = x^3 + A*x^2 + x (mod p)."""
        if point is None:
            return True
        x, y = point
        lhs = (y * y) % self.P
        rhs = (x**3 + self.A * x**2 + x) % self.P
        if lhs != rhs:
            print(f"Point ({x}, {y}) is not on the curve: y^2 = {lhs}, x^3 + Ax^2 + x = {rhs}")
        return lhs == rhs

    def generate_point(self, x):
        """Generate a valid point on the curve given x."""
        y = calculate_y_coordinate(x, self.A, self.P)
        return (x, y)

    def test_add_basic(self):
        """Test adding two distinct points on the curve."""
        point1 = self.generate_point(9)
        point2 = self.generate_point(123456)
        
        result = self.curve.add(point1, point2)
        self.assertTrue(self.is_point_on_curve(result))

    def test_add_point_to_itself(self):
        """Test adding a point to itself (should be the same as doubling)."""
        point = self.generate_point(9)
        
        add_result = self.curve.add(point, point)
        double_result = self.curve.double(point)
        
        self.assertEqual(add_result, double_result)

    def test_add_identity(self):
        """Test adding the identity element (None) to a point."""
        point = self.generate_point(9)
        
        result = self.curve.add(point, None)
        self.assertEqual(result, point)

    def test_add_inverses(self):
        """Test adding a point and its inverse (should return None)."""
        point = self.generate_point(9)
        inverse_point = (point[0], (-point[1]) % self.P)
        
        result = self.curve.add(point, inverse_point)
        self.assertIsNone(result)

    def test_double_basic(self):
        """Test doubling a point on the curve."""
        point = self.generate_point(9)
        
        result = self.curve.double(point)
        self.assertTrue(self.is_point_on_curve(result))

    def test_double_vertical_tangent(self):
        """Test doubling a point where y = 0 (should return None)."""
        point = (12345, 0)
        result = self.curve.double(point)
        self.assertIsNone(result)

    def test_scalar_multiply(self):
        """Test scalar multiplication on the curve."""
        scalar = 67890
        point = self.generate_point(9)
        result = self.curve.scalar_multiply(scalar, point)
        
        self.assertTrue(self.is_point_on_curve(result))

if __name__ == "__main__":
    unittest.main()
