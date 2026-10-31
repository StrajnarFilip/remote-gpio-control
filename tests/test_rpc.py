import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from gpio_server import protocol
from gpio_server.rpc import Rpc

KEY = bytes(range(32))


class FakeGpio:
    def __init__(self):
        self.calls = []

    def state(self):
        return [{"name": "GPIO17", "mode": "output", "value": 0}]

    def set(self, line, value):
        self.calls.append(("set", line, value))

    def pulse(self, line, ms):
        self.calls.append(("pulse", line, ms))

    def configure(self, line, changes):
        if line != "GPIO17":
            raise ValueError(f"unknown line {line!r}")
        self.calls.append(("configure", line, changes))


@pytest.fixture
def rpc():
    return Rpc(KEY, FakeGpio())


def request(rpc, key=KEY, **fields):
    """Build a sealed request the way a client does."""
    challenge = rpc.challenges.issue()
    return protocol.seal(key, protocol.REQUEST_AAD, {"challenge": challenge.hex(), **fields})


def reply_to(envelope, reply):
    return protocol.unseal(KEY, protocol.response_aad(envelope), reply)


def test_valid_request(rpc):
    envelope = request(rpc, op="set", line="GPIO17", value=1)
    reply = reply_to(envelope, rpc.handle(envelope))
    assert reply == {"ok": True, "lines": FakeGpio().state()}
    assert rpc._gpio.calls == [("set", "GPIO17", 1)]


def test_replayed_request_is_rejected(rpc):
    envelope = request(rpc, op="pulse", line="GPIO17", ms=500)
    assert rpc.handle(envelope) is not None
    assert rpc.handle(envelope) is None
    assert rpc._gpio.calls == [("pulse", "GPIO17", 500)]


def test_expired_challenge_is_rejected(rpc):
    clock = [0.0]
    rpc.challenges = protocol.Challenges(ttl=10, clock=lambda: clock[0])
    envelope = request(rpc, op="state")
    clock[0] = 10.0
    assert rpc.handle(envelope) is None


def test_request_without_issued_challenge_is_rejected(rpc):
    for challenge in (bytes(16).hex(), "zz", None):
        envelope = protocol.seal(KEY, protocol.REQUEST_AAD, {"challenge": challenge, "op": "state"})
        assert rpc.handle(envelope) is None


def test_wrong_key_is_rejected(rpc):
    assert rpc.handle(request(rpc, key=bytes(32), op="state")) is None


def test_garbage_is_rejected(rpc):
    assert rpc.handle(b"") is None
    assert rpc.handle(b"x" * 100) is None


def test_reply_resent_as_request_is_rejected(rpc):
    envelope = request(rpc, op="state")
    assert rpc.handle(rpc.handle(envelope)) is None


def test_reply_is_bound_to_its_request(rpc):
    """A recorded reply can't be passed off as the answer to another request."""
    first = request(rpc, op="state")
    old_reply = rpc.handle(first)
    second = request(rpc, op="state")
    rpc.handle(second)
    with pytest.raises(InvalidTag):
        reply_to(second, old_reply)


def test_authentic_non_json_is_rejected(rpc):
    nonce = bytes(12)
    envelope = nonce + AESGCM(KEY).encrypt(nonce, b"\xff not json", protocol.REQUEST_AAD)
    assert rpc.handle(envelope) is None


@pytest.mark.parametrize("fields, error", [
    ({"op": "explode"}, "unknown op"),
    ({"op": "set", "value": 1}, "line must be a string"),
    ({"op": "set", "line": "GPIO17", "value": 2}, "value must be 0 or 1"),
    ({"op": "set", "line": "GPIO17", "value": True}, "value must be 0 or 1"),
    ({"op": "pulse", "line": "GPIO17", "ms": 0}, "ms must be"),
    ({"op": "pulse", "line": "GPIO17", "ms": 10_001}, "ms must be"),
    ({"op": "configure", "line": "GPIO17", "mode": "sideways"}, "mode must be"),
    ({"op": "configure", "line": "GPIO99", "mode": "input"}, "unknown line"),
])
def test_invalid_requests_get_an_error_reply(rpc, fields, error):
    envelope = request(rpc, **fields)
    reply = reply_to(envelope, rpc.handle(envelope))
    assert reply["ok"] is False
    assert error in reply["error"]
    assert reply["lines"] == FakeGpio().state()
    assert rpc._gpio.calls == []


def test_configure_passes_only_known_fields(rpc):
    envelope = request(rpc, op="configure", line="GPIO17", mode="input", bias="pull-up", junk=1)
    assert reply_to(envelope, rpc.handle(envelope))["ok"]
    assert rpc._gpio.calls == [("configure", "GPIO17", {"mode": "input", "bias": "pull-up"})]
