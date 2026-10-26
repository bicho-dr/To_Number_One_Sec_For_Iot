"""
ring_signature.py
------------------
AOS-style Ring Signature (Abe-Ohkubo-Suzuki, 1-out-of-n) built on top of the
Ed25519 group defined in ed25519_core.py.

Scenario (IoT): a set of n sensors belongs to a trusted ring (e.g. the n
registered cameras of a smart-city operator). One sensor signs a message
(a reading) so that the gateway can verify "this came from SOME member of
the ring" without learning WHICH member signed.

Public API
----------
keygen()                                    -> (sk, pk)
ring_sign(message, ring_pks, idx, sk)       -> Signature
ring_verify(message, ring_pks, signature)   -> bool
"""

from dataclasses import dataclass
from typing import List, Tuple

from ed25519_core import (
    G, L, IDENTITY,
    point_add, scalar_mult, point_compress,
    random_scalar, hash_to_scalar, keygen,
)

Point = Tuple[int, int]


@dataclass
class Signature:
    c0: int            # the "anchor" challenge the ring must loop back to
    s: List[int]        # one response scalar per ring member


def _ring_digest(message: bytes, ring_pks: List[Point]) -> bytes:
    """Binds the signature to BOTH the message and the exact set of ring members,
    so an attacker cannot reuse a signature with a different ring."""
    return message + b"".join(point_compress(P) for P in ring_pks)


def ring_sign(message: bytes, ring_pks: List[Point], signer_index: int, signer_sk: int) -> Signature:
    """
    Produces a ring signature proving that *one* of ring_pks signed `message`,
    without revealing signer_index.
    """
    n = len(ring_pks)
    assert 0 <= signer_index < n, "signer_index out of range"

    digest_prefix = _ring_digest(message, ring_pks)

    c = [0] * n
    s = [0] * n

    # 1. Start the ring at a random nonce k, placed "after" the real signer.
    k = random_scalar()
    R = scalar_mult(k, G)
    c[(signer_index + 1) % n] = hash_to_scalar(digest_prefix, point_compress(R))

    # 2. Walk the ring forward, picking RANDOM s_i for every member except the
    #    real signer -- this is what makes the other members "fake" but still
    #    verifiable.
    i = (signer_index + 1) % n
    while i != signer_index:
        s[i] = random_scalar()
        R_i = point_add(scalar_mult(s[i], G), scalar_mult(c[i], ring_pks[i]))
        nxt = (i + 1) % n
        c[nxt] = hash_to_scalar(digest_prefix, point_compress(R_i))
        i = nxt

    # 3. Close the ring: only the real signer can compute this, because it
    #    requires the private key signer_sk.
    s[signer_index] = (k - c[signer_index] * signer_sk) % L

    return Signature(c0=c[0], s=s)


def ring_verify(message: bytes, ring_pks: List[Point], sig: Signature) -> bool:
    """
    Recomputes the ring starting from c0 and checks it loops back to c0.
    Returns True iff the signature is valid for this exact message + ring.
    """
    n = len(ring_pks)
    if len(sig.s) != n:
        return False

    digest_prefix = _ring_digest(message, ring_pks)

    c = sig.c0 % L
    for i in range(n):
        R_i = point_add(scalar_mult(sig.s[i] % L, G), scalar_mult(c, ring_pks[i]))
        c = hash_to_scalar(digest_prefix, point_compress(R_i))

    return c == sig.c0


# ---------------------------------------------------------------------------
# Convenience: build a full ring of fresh keys (handy for tests/benchmarks)
# ---------------------------------------------------------------------------
def make_ring(n: int):
    """Returns (list_of_sk, list_of_pk) for n freshly generated ring members."""
    sks, pks = [], []
    for _ in range(n):
        sk, pk = keygen()
        sks.append(sk)
        pks.append(pk)
    return sks, pks


if __name__ == "__main__":
    # Tiny smoke test when running this file directly.
    sks, pks = make_ring(5)
    msg = b"temperature=21.4C;sensor_batch=7"
    sig = ring_sign(msg, pks, signer_index=2, signer_sk=sks[2])
    print("Valid signature verifies :", ring_verify(msg, pks, sig))
    print("Tampered message fails   :", ring_verify(b"temperature=99.9C", pks, sig))