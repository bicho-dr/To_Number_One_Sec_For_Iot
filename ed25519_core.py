"""
ed25519_core.py
----------------
Pure-Python implementation of the Ed25519 elliptic curve group operations.
No external cryptography library is used: every operation (point addition,
scalar multiplication, hashing to a scalar) is built from the mathematical
definition of the twisted Edwards curve, so the team can explain every line
during the oral defense.

Curve: -x^2 + y^2 = 1 + d*x^2*y^2  (mod p)
This is the standard curve used by Ed25519 / Ed25519 ring signatures.
"""

import hashlib
import secrets

# ---------------------------------------------------------------------------
# 1. Field and curve constants (standard Ed25519 parameters, RFC 8032)
# ---------------------------------------------------------------------------
p = 2 ** 255 - 19                                    # prime field modulus
L = 2 ** 252 + 27742317777372353535851937790883648493  # order of the base point G

_d = (-121665 * pow(121666, p - 2, p)) % p           # curve parameter d

# Base point G (generator), fixed constants from RFC 8032
Gx = 15112221349535400772501151409588531511454012693041857206046113283949847762202
Gy = 46316835694926478169428394003475163141307993866256225615783033603165251855960
G = (Gx, Gy)

IDENTITY = (0, 1)  # neutral element of the group ("point at infinity" in affine form)


# ---------------------------------------------------------------------------
# 2. Point arithmetic (affine coordinates)
# ---------------------------------------------------------------------------
def point_add(P, Q):
    """
    Unified addition formula for twisted Edwards curves.
    Because d is a non-square mod p, this SAME formula works for P+Q and
    for doubling (P+P) -- no special case needed.
    """
    x1, y1 = P
    x2, y2 = Q
    x1y2 = (x1 * y2) % p
    y1x2 = (y1 * x2) % p
    y1y2 = (y1 * y2) % p
    x1x2 = (x1 * x2) % p
    dxxyy = (_d * x1x2 * y1y2) % p

    x3 = (x1y2 + y1x2) * pow((1 + dxxyy) % p, p - 2, p) % p
    y3 = (y1y2 + x1x2) * pow((1 - dxxyy) % p, p - 2, p) % p
    return (x3, y3)


def scalar_mult(s, P):
    """Double-and-add scalar multiplication: computes s * P."""
    s = s % L
    result = IDENTITY
    addend = P
    while s:
        if s & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        s >>= 1
    return result


def point_compress(P):
    """Standard Ed25519 point compression -> 32 bytes (used for hashing)."""
    x, y = P
    y_bytes = y & ((1 << 255) - 1)
    if x & 1:
        y_bytes |= 1 << 255
    return y_bytes.to_bytes(32, "little")


# ---------------------------------------------------------------------------
# 3. Scalar helpers
# ---------------------------------------------------------------------------
def random_scalar():
    """Cryptographically secure random scalar in [1, L-1]."""
    return secrets.randbelow(L - 1) + 1


def hash_to_scalar(*chunks: bytes) -> int:
    """Hash arbitrary byte strings together into a scalar mod L (SHA-512)."""
    h = hashlib.sha512(b"".join(chunks)).digest()
    return int.from_bytes(h, "little") % L


# ---------------------------------------------------------------------------
# 4. Basic KeyGen (used by every variant built on top of this file)
# ---------------------------------------------------------------------------
def keygen():
    """Returns (private_scalar, public_point)."""
    sk = random_scalar()
    pk = scalar_mult(sk, G)
    return sk, pk
