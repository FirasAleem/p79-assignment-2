from x25519.utils import mult_inverse, field_add, field_mul, sqrt_mod
import hashlib

# Prime modulus (same as Curve25519)
prime_mod = 2**255 - 19

# d = -121665/121666 mod P
d = (-121665 * mult_inverse(121666, prime_mod)) % prime_mod

# Order of the base-point subgroup
L = 2**252 + 27742317777372353535851937790883648493

# Base point in affine coordinates (as defined in RFC 8032)
B_AFFINE = (
    15112221349535400772501151409588531511454012693041857206046113283949847762202,
    46316835694926478169428394003475163141307993866256225615783033603165251855960,
)

def sha512(data: bytes) -> bytes:
    """Compute the SHA-512 hash of the input data."""
    return hashlib.sha512(data).digest()

def secret_expand(secret: bytes) -> tuple[int, bytes]:
    """
    Expand the 32-byte Ed25519 private key:
    
        1. Hash with SHA-512.
        2. Clamp the first 32 bytes to derive scalar `a`.
        3. Return `(a, prefix)`, where:
            - `a` is the clamped scalar.
            - `prefix` is used for nonce generation in signing.
    """
    if len(secret) != 32:
        raise ValueError("Invalid private key length")
    
    h = sha512(secret)
    
    key = bytearray(h[:32])
    key[0] &= 248     # Clear the lowest 3 bits of the first byte
    key[31] &= 127    # Clear the highest bit of the last byte
    key[31] |= 64     # Set the second-highest bit of the last byte
    
    a = int.from_bytes(key, "little")  # Clamped private scalar
    return a, h[32:]  # (private scalar, prefix)

def compute_public_key(private_key: bytes) -> bytes:
    """
    Compute the public key from a private key.
    
    This expands the secret key, clamps it, computes `A = a * B`, and returns 
    the compressed encoding of A.
    """
    a, _ = secret_expand(private_key)  # Expand and clamp the private key
    A_point = edwards_scalar_mult(a, affine_to_extended(B_AFFINE))  # Compute A = a * B
    return encode_edwards_point(A_point)  # Encode A to compressed form
    
# Conversions Between Affine and Extended Coordinates

def affine_to_extended(P_aff: tuple[int, int]) -> tuple[int, int, int, int]:
    """
    Convert an affine point (x, y) into extended homogeneous coordinates (X, Y, Z, T).
    I chose Z = 1 and T = x*y mod P.
    """
    x, y = P_aff
    return (x, y, 1, (x * y) % prime_mod)

def extended_to_affine(P_ext: tuple[int, int, int, int]) -> tuple[int, int]:
    """
    Convert an extended point (X, Y, Z, T) to affine coordinates (x, y)
    by computing x = X/Z and y = Y/Z.
    """
    X, Y, Z, _ = P_ext
    invZ = mult_inverse(Z, prime_mod)
    x = field_mul(X, invZ, prime_mod)
    y = field_mul(Y, invZ, prime_mod)
    return (x, y)

# Point Encoding and Decoding (Compressed Form)

def encode_edwards_point(P_ext: tuple[int, int, int, int]) -> bytes:
    """
    Compress an extended Edwards point into 32 bytes.
    
    The encoding uses the affine y-coordinate (in little-endian order) with the
    most significant bit set to the least significant bit of the x-coordinate.
    """
    x, y = extended_to_affine(P_ext)
    y_bytes = y.to_bytes(32, "little")
    if x & 1:
        y_bytes = bytearray(y_bytes)
        y_bytes[-1] |= 0x80
        y_bytes = bytes(y_bytes)
    return y_bytes

def decode_edwards_point(s: bytes) -> tuple[int, int, int, int]:
    """
    Decompress a 32 byte string into an extended Edwards point.
    
    The 32 byte string holds the affine y-coordinate (little endian) and the top bit
    holds the sign of x. Recover x from the curve equation:
            x^2 = (y^2 - 1) / (d*y^2 + 1)  mod P.
    Then convert the recovered (x, y) to extended coordinates.
    """
    if len(s) != 32:
        raise ValueError("Invalid point encoding length")
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1

    y2 = field_mul(y, y, prime_mod)
    num = field_add(y2, -1, prime_mod)              # y^2 - 1
    denom = field_add(field_mul(d, y2, prime_mod), 1, prime_mod)  # d*y^2 + 1
    inv_denom = mult_inverse(denom, prime_mod)
    x2 = field_mul(num, inv_denom, prime_mod)
    x = sqrt_mod(x2, prime_mod)
    if (x & 1) != sign:
        x = prime_mod - x
    return affine_to_extended((x, y))

# Extended Edwards Point Operations (Using RFC 8032 § 5.1.4 formulas)

def edwards_point_add_extended(
    P: tuple[int, int, int, int], Q: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    """
    Add two Edwards points (in extended coordinates) using the complete formulas.
    
    Let P = (X1,Y1,Z1,T1) and Q = (X2,Y2,Z2,T2). Then:
    
        A = (Y1 - X1)*(Y2 - X2)
        B = (Y1 + X1)*(Y2 + X2)
        C = T1 * 2*d * T2
        D = Z1 * 2 * Z2
        E = B - A
        F = D - C
        G = D + C
        H = B + A
        X3 = E * F
        Y3 = G * H
        T3 = E * H
        Z3 = F * G
    """
    X1, Y1, Z1, T1 = P
    X2, Y2, Z2, T2 = Q
    A = field_mul((Y1 - X1) % prime_mod, (Y2 - X2) % prime_mod, prime_mod)
    B = field_mul((Y1 + X1) % prime_mod, (Y2 + X2) % prime_mod, prime_mod)
    C = field_mul(T1, field_mul(2 * d, T2, prime_mod), prime_mod)
    D = field_mul(2 * Z1, Z2, prime_mod)
    E = field_add(B, -A, prime_mod)
    F = field_add(D, -C, prime_mod)
    G = field_add(D, C, prime_mod)
    H = field_add(B, A, prime_mod)
    X3 = field_mul(E, F, prime_mod)
    Y3 = field_mul(G, H, prime_mod)
    T3 = field_mul(E, H, prime_mod)
    Z3 = field_mul(F, G, prime_mod)
    return (X3 % prime_mod, Y3 % prime_mod, Z3 % prime_mod, T3 % prime_mod)

def edwards_point_double_extended(
    P: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    """
    Double an Edwards point (in extended coordinates) using the formulas:
    
        A = X1^2
        B = Y1^2
        C = 2*Z1^2
        H = A + B
        E = H - (X1 + Y1)^2
        G = A - B
        F = C + G
        X3 = E * F
        Y3 = G * H
        T3 = E * H
        Z3 = F * G
    """
    X1, Y1, Z1, _ = P
    A = field_mul(X1, X1, prime_mod)
    B = field_mul(Y1, Y1, prime_mod)
    C = field_mul(2, field_mul(Z1, Z1, prime_mod), prime_mod)
    H_val = field_add(A, B, prime_mod)
    sumXY = (X1 + Y1) % prime_mod
    sumXY_sq = field_mul(sumXY, sumXY, prime_mod)
    E = field_add(H_val, -sumXY_sq, prime_mod)
    G_val = field_add(A, -B, prime_mod)
    F = field_add(C, G_val, prime_mod)
    X3 = field_mul(E, F, prime_mod)
    Y3 = field_mul(G_val, H_val, prime_mod)
    T3 = field_mul(E, H_val, prime_mod)
    Z3 = field_mul(F, G_val, prime_mod)
    return (X3 % prime_mod, Y3 % prime_mod, Z3 % prime_mod, T3 % prime_mod)

# Double and Add

def edwards_scalar_mult(
    scalar: int, P_ext: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    """
    Perform scalar multiplication [scalar] * P on the Edwards curve using
    a simple double-and-add algorithm in extended coordinates.
    
    The identity element is represented as (0, 1, 1, 0).
    Note: This implementation is not constant-time.
    """
    # Identity element in extended coordinates: (0,1,1,0) represents the affine (0,1).
    result = (0, 1, 1, 0)
    accum = P_ext

    while scalar:
        if scalar & 1:
            result = edwards_point_add_extended(result, accum)
        accum = edwards_point_double_extended(accum)
        scalar //= 2

    return result

def normalize_extended(P: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    """Normalize an extended Edwards point so that Z = 1."""
    X, Y, Z, T = P
    if Z == 0:
        raise ValueError("Cannot normalize a point at infinity (Z=0)")
    inv_Z = mult_inverse(Z, prime_mod)
    X_norm = (X * inv_Z) % prime_mod
    Y_norm = (Y * inv_Z) % prime_mod
    T_norm = (T * inv_Z) % prime_mod  
    return (X_norm, Y_norm, 1, T_norm)


def edwards_point_negate(P: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    X, Y, Z, T = P
    return (-X % prime_mod, Y, Z, -T % prime_mod)

def is_identity(P: tuple[int, int, int, int]) -> bool:
    # Assuming normalize_extended returns the normalized extended point (with Z == 1)
    # and the identity (neutral element) is (0, 1, 1, 0)
    norm = normalize_extended(P)
    return norm == (0, 1, 1, 0)
