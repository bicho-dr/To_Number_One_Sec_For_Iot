import pytest

from ed25519_core import keygen
from ring_signature import ring_sign, ring_verify, make_ring


# ---------------------------------------------------------------------------
# A fresh ring of 5 members is rebuilt for every test (pytest fixture),
# so tests never interfere with each other.
# ---------------------------------------------------------------------------
@pytest.fixture
def ring5():
    sks, pks = make_ring(5)
    return sks, pks


def test_valid_signature_verifies(ring5):
    sks, pks = ring5
    msg = b"temperature=21.4C;sensor_batch=7"
    sig = ring_sign(msg, pks, signer_index=2, signer_sk=sks[2])
    assert ring_verify(msg, pks, sig) is True


def test_every_member_can_sign(ring5):
    """Each of the n members must be able to produce a valid signature
    (not just member 0), otherwise the construction is broken."""
    sks, pks = ring5
    msg = b"humidity=55%"
    for idx in range(len(pks)):
        sig = ring_sign(msg, pks, signer_index=idx, signer_sk=sks[idx])
        assert ring_verify(msg, pks, sig) is True


def test_tampered_message_fails(ring5):
    sks, pks = ring5
    msg = b"temperature=21.4C"
    sig = ring_sign(msg, pks, signer_index=0, signer_sk=sks[0])
    tampered = b"temperature=99.9C"
    assert ring_verify(tampered, pks, sig) is False


def test_wrong_ring_fails(ring5):
    """A signature made for one ring must NOT verify against a different ring,
    even if the attacker reuses the same message/signature values."""
    sks, pks = ring5
    other_sks, other_pks = make_ring(5)

    msg = b"temperature=21.4C"
    sig = ring_sign(msg, pks, signer_index=0, signer_sk=sks[0])
    assert ring_verify(msg, other_pks, sig) is False


def test_signer_not_in_ring_cannot_forge(ring5):
    """An outsider (private key not matching ANY public key in the ring)
    must not be able to produce a valid signature -- this is the
    unforgeability property."""
    sks, pks = ring5
    outsider_sk, outsider_pk = keygen()  # not part of the ring at all

    msg = b"temperature=21.4C"
    # The outsider tries to sign by *pretending* to be ring member 0,
    # but using their own private key instead of member 0's.
    forged_sig = ring_sign(msg, pks, signer_index=0, signer_sk=outsider_sk)
    assert ring_verify(msg, pks, forged_sig) is False


def test_signature_size_is_independent_of_which_member_signed(ring5):
    """Sanity check: the signature always has exactly n response scalars,
    regardless of which member actually signed (anonymity prerequisite)."""
    sks, pks = ring5
    msg = b"pressure=1013hPa"
    sig_a = ring_sign(msg, pks, signer_index=0, signer_sk=sks[0])
    sig_b = ring_sign(msg, pks, signer_index=4, signer_sk=sks[4])
    assert len(sig_a.s) == len(sig_b.s) == len(pks)
