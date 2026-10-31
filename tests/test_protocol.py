import pytest
from cryptography.exceptions import InvalidTag

from gpio_server import protocol

KEY = bytes(range(32))


def test_seal_round_trip():
    envelope = protocol.seal(KEY, protocol.REQUEST_AAD, {"op": "state"})
    assert protocol.unseal(KEY, protocol.REQUEST_AAD, envelope) == {"op": "state"}


def test_every_seal_uses_a_fresh_nonce():
    a = protocol.seal(KEY, protocol.REQUEST_AAD, {})
    b = protocol.seal(KEY, protocol.REQUEST_AAD, {})
    assert a[: protocol.NONCE_SIZE] != b[: protocol.NONCE_SIZE]


@pytest.mark.parametrize("position", [0, 12, -1])
def test_tampered_byte_is_rejected(position):
    envelope = bytearray(protocol.seal(KEY, protocol.REQUEST_AAD, {"op": "state"}))
    envelope[position] ^= 1
    with pytest.raises(InvalidTag):
        protocol.unseal(KEY, protocol.REQUEST_AAD, bytes(envelope))


def test_wrong_key_is_rejected():
    envelope = protocol.seal(KEY, protocol.REQUEST_AAD, {})
    with pytest.raises(InvalidTag):
        protocol.unseal(bytes(32), protocol.REQUEST_AAD, envelope)


def test_wrong_aad_is_rejected():
    envelope = protocol.seal(KEY, protocol.REQUEST_AAD, {})
    with pytest.raises(InvalidTag):
        protocol.unseal(KEY, protocol.RESPONSE_AAD, envelope)


@pytest.mark.parametrize("envelope", [b"", b"x" * 27])
def test_short_envelope_is_rejected(envelope):
    with pytest.raises(InvalidTag):
        protocol.unseal(KEY, protocol.REQUEST_AAD, envelope)


def test_parse_key():
    assert protocol.parse_key(KEY.hex().upper() + "\n") == KEY
    with pytest.raises(ValueError):
        protocol.parse_key("abcd")


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_challenge_is_single_use():
    challenges = protocol.Challenges()
    c = challenges.issue()
    assert len(c) == protocol.CHALLENGE_SIZE
    assert challenges.redeem(c)
    assert not challenges.redeem(c)


def test_unknown_challenge_is_rejected():
    assert not protocol.Challenges().redeem(bytes(16))


def test_challenge_expires():
    clock = FakeClock()
    challenges = protocol.Challenges(ttl=10, clock=clock)
    c = challenges.issue()
    clock.now += 10
    assert not challenges.redeem(c)


def test_expired_challenges_are_pruned():
    clock = FakeClock()
    challenges = protocol.Challenges(ttl=10, clock=clock)
    old = [challenges.issue() for _ in range(5)]
    clock.now += 11
    fresh = challenges.issue()
    assert list(challenges._pending) == [fresh]
    assert not any(challenges.redeem(c) for c in old)


def test_check_line_config():
    assert protocol.check_line_config({"mode": "input", "op": "configure"}) == {"mode": "input"}
    for bad in ({"mode": "x"}, {"bias": "up"}, {"label": "x" * 25}, {"label": 3}, {"active_low": 1}):
        with pytest.raises(ValueError):
            protocol.check_line_config(bad)


def test_framing():
    framed = protocol.frame(b"hello")
    assert framed == b"\x00\x05hello"
    assert protocol.unframe(framed) == b"hello"
    assert protocol.unframe(framed[:4]) is None
    assert protocol.unframe(b"\x00") is None
