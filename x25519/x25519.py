import os
from x25519.utils import clamp_scalar, bytes_to_int, int_to_bytes, calculate_y_coordinate
from x25519.montgomery_ladder import MontgomeryLadder
from x25519.montgomery_double_add import MontgomeryDoubleAdd
from typing import Literal

P = 2**255 - 19  # Prime modulus for Curve25519
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

    def scalar_multiply(self, private_key: "X25519PrivateKey", public_key: "X25519PublicKey") -> bytes:
        """
        Perform X25519 scalar multiplication with the specified method.
        
        Args:
            private_key: 32-byte private key object.
            public_key: 32-byte public key object.
        
        Returns:
            32-byte little-endian representation of the resulting x-coordinate.
        """
        scalar = bytes_to_int(private_key)
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


class X25519PublicKey:
    """A wrapper for X25519 public keys, ensuring type safety and clarity."""
    
    def __init__(self, key_bytes: bytes):
        if len(key_bytes) != 32:
            raise ValueError("Public key must be 32 bytes long.")
        self._key_bytes = key_bytes  # Store as bytes internally

    @staticmethod
    def from_private_key(private_key: "X25519PrivateKey") -> "X25519PublicKey":
        """Generates the public key corresponding to a given private key."""
        BASE_X = b'\x09' + b'\x00' * 31  # Base point
        x25519 = X25519()
        return x25519.scalar_multiply(private_key, BASE_X)


class X25519PrivateKey:
    """A wrapper for X25519 private keys with safety mechanisms."""
    
    def __init__(self, key_bytes: bytes):
        if len(key_bytes) != 32:
            raise ValueError("Private key must be 32 bytes long.")
        self._key_bytes = key_bytes  # Assume already clamped

    @staticmethod
    def generate() -> "X25519PrivateKey":
        """Generates a new random private key and clamps it."""
        random_bytes = os.urandom(32)
        clamped_scalar = clamp_scalar(random_bytes)  # Properly clamp before storing
        return X25519PrivateKey(int_to_bytes(clamped_scalar))  # Store as bytes