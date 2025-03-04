import os
from x25519.utils import clamp_scalar, bytes_to_int, int_to_bytes, calculate_y_coordinate
from x25519.montgomery_ladder import MontgomeryLadder
from x25519.montgomery_double_add import MontgomeryDoubleAdd
from typing import Literal

P = 2**255 - 19  # Prime modulus for Curve25519


class X25519:
    """
    A X25519 wrapper that supports scalar multiplication using either:
        - 'ladder': Montgomery ladder (constant-time scalar multiplication)
        - 'double_and_add': MontgomeryDoubleAdd using affine coordinates.
    
    This class handles clamping, byte conversion, and selecting the desired method.
    By default, the 'ladder' method is used.
    """

    def __init__(self, method: Literal['ladder', 'double_and_add'] = 'ladder') -> None:
        if method not in ['ladder', 'double_and_add']:
            raise ValueError("Method must be 'ladder' or 'double_and_add'.")
        self.method = method

    def scalar_multiply(self, private_key: bytes, public_key: bytes) -> bytes:
        """
        Perform X25519 scalar multiplication with the specified method.
        
        Args:
            private_key: 32-byte private key (little-endian).
            public_key: 32-byte little-endian representation of the input point's x-coordinate.
        
        Returns:
            32-byte little-endian representation of the resulting x-coordinate.
        """
        scalar = clamp_scalar(private_key)
        u = bytes_to_int(public_key)
        
        if self.method == 'ladder':
            ladder = MontgomeryLadder(p=P)
            result_x, _ = ladder.scalar_multiply(scalar, (u, None))
        else:  # method == 'double_and_add'
            double_add = MontgomeryDoubleAdd(A=486662, p=P)
            y_coordinate = calculate_y_coordinate(u, 486662, P)
            if y_coordinate is None:
                raise ValueError("Failed to calculate y-coordinate.")
            result_x, _ = double_add.scalar_multiply(scalar, (u, y_coordinate))

        return int_to_bytes(result_x)


    @staticmethod
    def generate_private_key() -> bytes:
        """
        Generate a random 32-byte private key suitable for X25519.
        
        Returns:
            32-byte private key.
        """
        return os.urandom(32)


    def generate_public_key(self, private_key: bytes) -> bytes:
        """
        Generate a public key from a private key using the X25519 algorithm.
        
        Args:
            private_key: 32-byte private key.
        
        Returns:
            32-byte public key.
        """
        BASE_X = b'\x09' + b'\x00' * 31 # x-coordinate of the base point for Curve25519
        return self.scalar_multiply(private_key, BASE_X)

