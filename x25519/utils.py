# This file contains the utility functions used in the X25519 implementation
from typing import Tuple

def mult_inverse(a: int, p: int) -> int:
    """Compute the multiplicative inverse using Fermat's Little Theorem of a mod p."""
    return pow(a, p - 2, p)


def field_add(a: int, b: int, p: int) -> int:
    """Addition in the finite field F_p."""
    return (a + b) % p


def field_mul(a: int, b: int, p: int) -> int:
    """Multiplication in the finite field F_p."""
    return (a * b) % p

def sqrt_mod(a: int, p: int = 2**255 - 19) -> int:
    """
    Compute a square root of a modulo p, for p = 2^255 - 19.
    
    The algorithm is:
        r = a^((p+3)//8) mod p
        if r^2 ≡ a (mod p), return r.
        else if r^2 ≡ -a (mod p), return r * I mod p, where I = 2^((p-1)//4) mod p.
        Otherwise, raise an error.
    Args:
        a (int): The number to compute the square root of.
        p (int): The prime modulus (default is 2^255 - 19).
    
    Returns:
        int: A square root of a modulo p.
    
    Raises:
        ValueError: If a is not a quadratic residue modulo p.
    """
    r = pow(a, (p + 3) // 8, p)
    if (r * r) % p == a % p:
        return r
    elif (r * r) % p == (-a) % p:
        # Compute sqrt(-1) modulo p.
        I = pow(2, (p - 1) // 4, p)
        return (r * I) % p
    else:
        raise ValueError("No square root exists for a modulo p")


def calculate_y_coordinate(x: int, A: int = 486662, p: int = 2**255 - 19) -> int:
    """
    Computes the y-coordinate for a given x on a Montgomery-form elliptic curve using the square root method.
    
    The curve is defined by the equation:
        y^2 = x^3 + A*x^2 + x (mod p)

    Args:
        x (int): The x-coordinate on the curve.
        A (int): The curve parameter A in the equation.
        p (int): The prime modulus.

    Returns:
        int: The corresponding y-coordinate.

    Note:
        Returns the positive root by default. If the computed y does not satisfy 
        y^2 ≡ (x^3 + A*x^2 + x) (mod p), it returns p - y.
    """

    a = (x**3 + A * x**2 + x) % p
    y = sqrt_mod(a, p)
    # Return the smaller root between y and p - y (as mentioned in RFC 7748)
    if y > p // 2:
        y = p - y
    
    if (y * y) % p != a:
        raise ValueError("Square root computation failed")
    
    return y


def clamp_scalar(scalar_bytes: bytes) -> int:
    """
    Clamp the scalar according to the X25519 requirements.
    
    Args:
        scalar_bytes: A 32-byte private key.
    
    Returns:
        The clamped scalar as an integer.
    """
    if len(scalar_bytes) != 32:
        raise ValueError("Scalar must be exactly 32 bytes.")
        
    scalar_list = list(scalar_bytes)
    scalar_list[0] &= 248   # Clear the 3 least significant bits
    scalar_list[31] &= 127  # Clear the most significant bit
    scalar_list[31] |= 64   # Set the second-most significant bit
    return int.from_bytes(bytes(scalar_list), "little")


def bytes_to_int(data: bytes) -> int:
    """
    Convert a byte sequence to a little-endian integer.
    
    Args:
        data: A byte sequence.
    
    Returns:
        The integer representation of the byte sequence.
    """
    return int.from_bytes(data, "little")

def int_to_bytes(value: int, length: int = 32) -> bytes:
    """
    Convert an integer to a little-endian byte sequence.
    
    Args:
        value: The integer to convert.
        length: The length of the resulting byte sequence (default: 32 bytes).
    
    Returns:
        A little-endian byte sequence of the given length.
    """
    return value.to_bytes(length, "little")

def constant_swap(swap: int, x2: int, x3: int) -> Tuple[int, int]:
    mask = -swap
    dummy = mask & (x2 ^ x3)
    x2 ^= dummy
    x3 ^= dummy
    return x2, x3
