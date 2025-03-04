from x25519.utils import mult_inverse, field_add, field_mul, constant_swap
from typing import Optional, Tuple

# A point on the Montgomery curve is represented as (x, y), but y is always None for X25519
# This is done to keep the interface consistent with the double-and-add implementation
Point = Optional[Tuple[int, Optional[int]]]

# Constants for Curve25519
P = 2**255 - 19  # Prime modulus
A24 = 121665  # (486662 - 2) // 4


class MontgomeryLadder:
    """
    Implements scalar multiplication on Curve25519 using the Montgomery ladder.

    This implementation works entirely in projective coordinates (X:Z) and returns the
    resulting affine x-coordinate as an integer. It assumes:
        - The scalar is already clamped and provided as an integer.
        - The input point is given by its affine x-coordinate (also an integer).
    
    The caller is responsible for clamping, byte conversion, and assembling a full X25519 routine.
    This will be done seperately so that the method for scalar multiplication can be chosen (double-and-add or Montgomery ladder).
    """
    
    def __init__(self, p: int = P, a24: int = A24) -> None:
        self.p = p
        self.a24 = a24

    def scalar_multiply(self, scalar: int, P: Point) -> Point:
        """
        Multiply the point P with affine x-coordinate u by the scalar using the Montgomery ladder.
        
        Args:
            scalar: The secret scalar (as an integer, already clamped).
            P: The input point (x, None) where x is the affine x-coordinate.
            
        Returns:
            A Point (x, None) where x is the resulting affine x-coordinate.
        """
        if scalar == 0:
            return P

        p = self.p
        a24 = self.a24
        x1, _ = P  # We only use the x-coordinate
        x1 = x1 % (1 << 255) # MASK TO ENSURE 255 BITS

        # Initialize projective coordinates:
        # (x2 : z2) = (1 : 0) represents the point at infinity,
        # (x3 : z3) = (x1 : 1) represents the input point
        x2, z2 = 1, 0
        x3, z3 = x1, 1
        swap = 0

        # Process bits 254 down to 0 (255 iterations total)
        # Swaps are constant time as this is a SHOULD in the RFC
        for t in range(254, -1, -1):
            k_t = (scalar >> t) & 1
            swap ^= k_t
            x2, x3 = constant_swap(swap, x2, x3)
            z2, z3 = constant_swap(swap, z2, z3)
            swap = k_t
            x2, z2, x3, z3 = self._ladder_step(x2, z2, x3, z3, x1)

        # Final swap
        x2, x3 = constant_swap(swap, x2, x3)
        z2, z3 = constant_swap(swap, z2, z3)

        # Convert the projective coordinate (x2:z2) to the affine x-coordinate.
        x_final = field_mul(x2, mult_inverse(z2, p), p)
        #print(f"Multiplying scalar: {scalar} with point: {P} using Montgomery ladder gives x: {x_final}")
        return (x_final, None)

    def _ladder_step(self, x2: int, z2: int, x3: int, z3: int, x1: int) -> Tuple[int, int, int, int]:
        """
        Perform one step of the Montgomery ladder using projective coordinates.
        
        Args:
            x2, z2: Projective coordinates of the first point.
            x3, z3: Projective coordinates of the second point.
            x1: The affine x-coordinate of the input point.
        
        Returns:
            Updated projective coordinates (x2_new, z2_new, x3_new, z3_new).
        """
        p = self.p
        a24 = self.a24

        # Compute intermediate values for the ladder step
        A_val = field_add(x2, z2, p)
        B_val = field_add(x2, -z2, p)
        AA = field_mul(A_val, A_val, p)
        BB = field_mul(B_val, B_val, p)
        E = field_add(AA, -BB, p)

        C_val = field_add(x3, z3, p)
        D_val = field_add(x3, -z3, p)
        DA = field_mul(D_val, A_val, p)
        CB = field_mul(C_val, B_val, p)

        # Update x3 and z3
        sum_DA_CB = field_add(DA, CB, p)
        diff_DA_CB = field_add(DA, -CB, p)
        x3_new = field_mul(sum_DA_CB, sum_DA_CB, p)
        z3_new = field_mul(x1, field_mul(diff_DA_CB, diff_DA_CB, p), p)

        # Update x2 and z2
        AA_plus_E = field_add(AA, field_mul(a24, E, p), p)
        x2_new = field_mul(AA, BB, p)
        z2_new = field_mul(E, AA_plus_E, p)

        return x2_new, z2_new, x3_new, z3_new
