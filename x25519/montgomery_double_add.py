from x25519.utils import mult_inverse
from typing import Optional, Tuple

# A point on the curve is represented as (x, y) 
# I'm using None to denote the point at infinity.
Point = Optional[Tuple[int, int]]


class MontgomeryDoubleAdd:
    """
    A class representing a Montgomery curve of the form:
        y^2 = x^3 + A*x^2 + x   (mod p)
    """

    def __init__(self, A: int, p: int) -> None:
        """
        Initialize the Montgomery curve with parameter A and prime modulus p.
        
        Args:
            A: The curve parameter (for Curve25519, A=486662).
            p: The prime modulus (for Curve25519, p=2^255 - 19).
        """
        self.A: int = A
        self.p: int = p

    def add(self, P: Point, Q: Point) -> Point:
        """
        Add two points P and Q on the Montgomery curve using the affine formulas.
        
        Args:
            P: A point on the curve as a tuple (x, y) or None (identity).
            Q: Another point on the curve.
        
        Returns:
            The sum P+Q as a point (x, y) or None if the result is the identity.
        
            - If P is None, returns Q.
            - If Q is None, returns P.
            - If P and Q are inverses (i.e. x coordinates equal and y1 = -y2 mod p),
                then returns None (the identity).
            - If P == Q, we delegate to the doubling function.
        """
        if P is None:
            return Q
        if Q is None:
            return P

        x1, y1 = P
        x2, y2 = Q

        if x1 == x2:
            # Check for P == -Q: then y1 + y2 == 0 mod p
            if (y1 + y2) % self.p == 0:
                return None
            else:
                # P == Q, so use doubling.
                return self.double(P)

        # Compute an intermediate lambda = (y2 - y1)/(x2 - x1) in F_p
        lam = (y2 - y1) * mult_inverse((x2 - x1), self.p) % self.p
        
        # For a Montgomery curve the addition formula becomes:
        #   x3 = lambda^2 - A - x1 - x2  (mod p)
        #   y3 = lambda*(x1 - x3) - y1   (mod p)
        
        x3 = (lam * lam - self.A - x1 - x2) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p
        #print(f"Add: P = {P}, Q = {Q}, Result = ({x3}, {y3})")
        return (x3, y3)


    def double(self, P: Point) -> Point:
        """
        Double a point P on the Montgomery curve.
        
        Args:
            P: A point on the curve as a tuple (x, y) or None.
        
        Returns:
            The point 2P as a tuple (x, y) or None if P is the identity or y=0.
        
        The doubling formulas for a Montgomery curve in this form are:
            lambda = (3*x1^2 + 2*A*x1 + 1) / (2*y1)    (mod p)
            x3 = lambda^2 - A - 2*x1                   (mod p)
            y3 = lambda*(x1 - x3) - y1                 (mod p)
        """
        if P is None:
            return None

        x1, y1 = P
        if y1 == 0:
            # The tangent is vertical ∴ the result is the identity
            return None

        # Intermediate lambda again
        lam = (3 * x1 * x1 + 2 * self.A * x1 + 1) * mult_inverse(2 * y1, self.p) % self.p
        x3 = (lam * lam - self.A - 2 * x1) % self.p
        y3 = (lam * (x1 - x3) - y1) % self.p
        return (x3, y3)


    def scalar_multiply(self, k: int, P: Point) -> Point:
        """
        Compute k * P using the double-and-add algorithm.
        
        Args:
            k: The scalar multiplier (a non-negative integer).
            P: The point on the curve to multiply.
        
        Returns:
            The resulting point k*P.
        """
        result: Point = None  # The identity element
        accum: Point = P
        
        while k > 0:
            if k & 1: # If LSB of k is 1 (i.e. k is odd)
                result = self.add(result, accum) # Add the current point to the result
            accum = self.double(accum) # Otherwise, double the current point
            k //= 2 # Shift k to the right by 1 bit (i.e. divide by 2)

        return result