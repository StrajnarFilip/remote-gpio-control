import pytest
from dbus_fast import DBusError

from gpio_server import protocol
from gpio_server.ble import BleTransport
from gpio_server.rpc import Rpc
from tests.test_rpc import KEY, FakeGpio

DEVICE = "/org/bluez/hci0/dev_AA"


def read_reply(transport, device=DEVICE, mtu=23):
    """Read the reply frame like a BLE stack would: pieces, each via long reads."""
    frame = b""
    while protocol.unframe(frame) is None:
        piece, offset = b"", 0
        while True:
            chunk = transport.read_rpc(device, offset)[: mtu - 1]
            piece += chunk
            offset += len(chunk)
            if len(chunk) < mtu - 1:
                break
        assert piece, "reply ended early"
        frame += piece
    return protocol.unframe(frame)


def exchange(transport, rpc, write_size=None, **fields):
    challenge = transport.read_challenge(DEVICE, 0)
    envelope = protocol.seal(KEY, protocol.REQUEST_AAD, {"challenge": challenge.hex(), **fields})
    frame = protocol.frame(envelope)
    size = write_size or len(frame)
    for offset in range(0, len(frame), size):
        transport.write_rpc(DEVICE, offset, frame[offset : offset + size])
    return protocol.unseal(KEY, protocol.response_aad(envelope), read_reply(transport))


class BigGpio(FakeGpio):
    def state(self):
        return [{"name": f"GPIO{i}", "mode": "off", "value": None, "label": "x" * 24} for i in range(40)]


def test_single_write_and_large_reply():
    rpc = Rpc(KEY, BigGpio())
    reply = exchange(BleTransport(rpc), rpc, op="state")
    assert reply["ok"] and len(reply["lines"]) == 40


def test_long_write_in_pieces():
    rpc = Rpc(KEY, FakeGpio())
    reply = exchange(BleTransport(rpc), rpc, write_size=18, op="set", line="GPIO17", value=1)
    assert reply["ok"]
    assert rpc._gpio.calls == [("set", "GPIO17", 1)]


def test_replayed_write_is_not_authorized():
    rpc = Rpc(KEY, FakeGpio())
    transport = BleTransport(rpc)
    challenge = transport.read_challenge(DEVICE, 0)
    frame = protocol.frame(protocol.seal(KEY, protocol.REQUEST_AAD, {"challenge": challenge.hex(), "op": "state"}))
    transport.write_rpc(DEVICE, 0, frame)
    with pytest.raises(DBusError):
        transport.write_rpc(DEVICE, 0, frame)
    assert transport.read_rpc(DEVICE, 0) == b""


def test_replies_are_per_device():
    rpc = Rpc(KEY, FakeGpio())
    transport = BleTransport(rpc)
    assert exchange(transport, rpc, op="state")["ok"]
    assert transport.read_rpc("/org/bluez/hci0/dev_BB", 0) == b""


def test_offset_beyond_received_data_is_rejected():
    transport = BleTransport(Rpc(KEY, FakeGpio()))
    with pytest.raises(DBusError):
        transport.write_rpc(DEVICE, 10, b"x")
