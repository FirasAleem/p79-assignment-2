import os
from x25519.utils import mult_inverse
from ed25519.utils import ( 
    sha512,
    secret_expand,
    compute_public_key,
    edwards_point_add_extended, 
    edwards_scalar_mult, 
    encode_edwards_point, 
    decode_edwards_point, 
    affine_to_extended, 
    normalize_extended, 
    edwards_point_negate, 
    is_identity,
    )

# The prime modulus (same as for Curve25519)
P = 2**255 - 19

# Compute d = -121665/121666 mod P
d = (-121665 * mult_inverse(121666, P)) % P

# Order of the base-point subgroup (a prime number)
L = 2**252 + 27742317777372353535851937790883648493

# Base point for Ed25519 (affine coordinates, as specified in RFC 8032)
B = (
    15112221349535400772501151409588531511454012693041857206046113283949847762202,
    46316835694926478169428394003475163141307993866256225615783033603165251855960,
)

class SigningKey:
    """A wrapper for Ed25519 signing keys (private keys)."""

    def __init__(self, key_bytes: bytes):
        if len(key_bytes) != 32:
            raise ValueError("Signing key must be 32 bytes long.")
        self._key_bytes = key_bytes
        self._ed25519 = Ed25519()  # Instance of Ed25519

    def to_bytes(self) -> bytes:
        """Returns the signing key as 32 bytes."""
        return self._key_bytes

    # This method was removed in order to have a more consistent API with the X25519 Key Classes
    # Instead, Verifying Key has a method "from_signing_key" to generate the verifying key
    # I left it commented out for reference
    # def generate_verifying_key(self) -> "VerifyingKey":
    #     """Generates the corresponding Ed25519 verifying key."""
    #     verifying_key_bytes = compute_public_key(self._key_bytes)
    #     return VerifyingKey(verifying_key_bytes)

    def sign(self, message: bytes) -> bytes:
        """Sign a message using this signing key."""
        return self._ed25519.sign(self, message)  # Use Ed25519 to sign

    @staticmethod
    def generate() -> "SigningKey":
        """Generates a new random Ed25519 signing key."""
        return SigningKey(os.urandom(32))

    @staticmethod
    def from_bytes(data: bytes) -> "SigningKey":
        """Creates a signing key from a 32-byte representation."""
        if len(data) != 32:
            raise ValueError("Signing key must be exactly 32 bytes long.")
        return SigningKey(data)


class VerifyingKey:
    """A wrapper for Ed25519 verifying keys (public keys)."""

    def __init__(self, key_bytes: bytes):
        if len(key_bytes) != 32:
            raise ValueError("Verifying key must be 32 bytes long.")
        self._key_bytes = key_bytes
        self._ed25519 = Ed25519()  # Instance of Ed25519

    def to_bytes(self) -> bytes:
        """Returns the verifying key as 32 bytes."""
        return self._key_bytes

    @staticmethod
    def from_signing_key(signing_key: SigningKey) -> "VerifyingKey":
        """Creates a verifying key from a signing key."""
        verifying_key_bytes = compute_public_key(signing_key.to_bytes())
        return VerifyingKey(verifying_key_bytes) 
        
    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify a message signature using this verifying key."""
        return self._ed25519.verify(self, message, signature)  # Use Ed25519 to verify

    @staticmethod
    def from_bytes(data: bytes) -> "VerifyingKey":
        """Creates a verifying key from a 32-byte representation."""
        if len(data) != 32:
            raise ValueError("Verifying key must be exactly 32 bytes long.")
        return VerifyingKey(data)


class Ed25519:
    """
    An implementation of Ed25519 for key generation, signing, and verification
    """

    def __init__(self):
        self.P = P
        self.d = d
        self.L = L
        self.B = affine_to_extended(B) 


    def sign(self, signing_key: SigningKey, message: bytes) -> bytes:
        """
        Sign a message using Ed25519:
        
            1. Compute H = SHA-512(private_key), split into lower 32 bytes and prefix.
            2. Clamp the lower half to obtain the scalar 'a'.
            3. Compute A = a * B.
            4. Compute r = SHA-512(prefix || message) mod L.
            5. Compute R = r * B.
            6. Compute k = SHA-512(encode(R) || encode(A) || message) mod L.
            7. Compute S = (r + k * a) mod L.
            8. Return the 64-byte signature: encode(R) || S.
            
        """
        # Step 1 - 3 are handled by secret_expand and compute_public_key
        a, prefix = secret_expand(signing_key.to_bytes())
        A_enc = VerifyingKey.from_signing_key(signing_key).to_bytes()
        
        # Step 4
        r = int.from_bytes(sha512(prefix + message), "little") % self.L
        
        # Step 5
        R_point = edwards_scalar_mult(r, self.B)
    
        R_enc = encode_edwards_point(R_point)
        
        # Step 6
        k = int.from_bytes(sha512(R_enc + A_enc + message), "little") % self.L
        
        # Step 7
        S = (r + k * a) % self.L
        S_enc = S.to_bytes(32, "little")
        
        return R_enc + S_enc

    def verify(self, verifying_key: VerifyingKey, message: bytes, signature: bytes) -> bool:
        """
        Verify an Ed25519 signature:
        
        1. Split the 64-byte signature into R (first 32 bytes) and S (last 32 bytes).
        2. Decode R and the public key A.
        3. Compute k = SHA-512(encode(R) || public_key || message) mod L.
        4. ~Verify that S * B == R + k * A, 4.~ Verify that [8][S]B = [8]R + [8][k]A.
        """
        if len(signature) != 64:
            return False
        # Step 1
        R_enc = signature[:32]
        S_enc = signature[32:]
                
        s_int = int.from_bytes(S_enc, "little")
        # Reject if s is not canonical
        if s_int >= self.L:
            return False

        try:
            # Step 2
            R_point = decode_edwards_point(R_enc)
            A_point = decode_edwards_point(verifying_key.to_bytes())
        except Exception:
            return False

        # Step 3
        k = int.from_bytes(sha512(R_enc + verifying_key.to_bytes() + message), "little") % self.L
        
        # Compute sB and kA.
        sB = edwards_scalar_mult(s_int, self.B)
        kA = edwards_scalar_mult(k, A_point)
        
        # Compute P = sB - kA.
        point = edwards_point_add_extended(sB, edwards_point_negate(kA))
        
        # Multiply both sides by 8.
        eight_R = edwards_scalar_mult(8, R_point)
        eight_P = edwards_scalar_mult(8, point)
        
        return normalize_extended(eight_R) == normalize_extended(eight_P)

        # This is the code for other verification equation 
        # # Step 4
        # S = s_int % self.L
        # SB_point = edwards_scalar_mult(S, self.B)
        
        # kA_point = edwards_scalar_mult(k, A_point)
        # R_calc = edwards_point_add_extended(R_point, kA_point)
        
        # print(f"SB_point: {normalize_extended(SB_point)}")
        # print(f"R_calc: {normalize_extended(R_calc)}")
        
        # return normalize_extended(SB_point) == normalize_extended(R_calc)


    def verify_batch(self, batch: list[tuple[VerifyingKey, bytes, bytes]]) -> bool:
        """
        Batch verification.
        Each tuple in 'batch' is (public_key, message, signature).
        Instead of computing full point operations per signature, we accumulate:
        - s_sum: the weighted sum of the s scalars.
        - r_sum: the weighted sum of the R points.
        - a_sum: the weighted sum of the public key points scaled by the challenge.
        At the end, we verify that:
        8*(r_sum + a_sum - s_sum*B) == identity
        """
        # For a single signature, fall back to individual verification
        if len(batch) == 1:
            public_key, message, signature = batch[0]
            return self.verify(public_key, message, signature)
        
        # Initialize the accumulated terms
        s_sum = 0
        r_sum = (0, 1, 1, 0)
        a_sum = (0, 1, 1, 0)
        
        for (public_key, message, signature) in batch:
            # Check signature length.
            if len(signature) != 64:
                return False

            R_enc, S_enc = signature[:32], signature[32:]
            
            # Parse S without reducing modulo L
            s_int = int.from_bytes(S_enc, "little")
            if s_int >= self.L:
                return False  # Non-canonical s
            
            # Decode R and A.
            try:
                R_point = decode_edwards_point(R_enc)
                A_point = decode_edwards_point(public_key.to_bytes())
            except Exception:
                return False
            
            # Compute challenge: k = H(R || public_key || message) mod L.
            k = int.from_bytes(sha512(R_enc + public_key.to_bytes() + message), "little") % self.L
            
            # Choose a random scalar z for this signature (nonzero modulo L).
            z = int.from_bytes(os.urandom(32), "little") % self.L
            if z == 0:
                z = 1
            # Accumulate the weighted terms
            s_sum = (s_sum + z * s_int) % self.L
            r_sum = edwards_point_add_extended(r_sum, edwards_scalar_mult(z, R_point))
            a_sum = edwards_point_add_extended(a_sum, edwards_scalar_mult(z * k, A_point))
            
        # Compute -s_sum mod L and multiply the base point.
        neg_s_sum = (self.L - s_sum) % self.L
        neg_s_sum_base = edwards_scalar_mult(neg_s_sum, self.B)

        # Combine the accumulators.
        combined = edwards_point_add_extended(r_sum, a_sum)
        combined = edwards_point_add_extended(combined, neg_s_sum_base)

        # Multiply by 8 and check against the identity.
        combined_8 = edwards_scalar_mult(8, combined)
        return is_identity(combined_8)
