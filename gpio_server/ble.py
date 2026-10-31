"""BLE transport: a BlueZ GATT service carrying the same envelopes as HTTPS.

No pairing is needed; security comes from the envelopes, which are checked
by Rpc. See PROTOCOL.md for the characteristics and framing.
"""

import asyncio
import logging

from dbus_fast import BusType, DBusError, Message, Variant
from dbus_fast.aio import MessageBus
from dbus_fast.service import PropertyAccess, ServiceInterface, dbus_property, method

from . import protocol

log = logging.getLogger(__name__)

BLUEZ = "org.bluez"
APP_PATH = "/gpio_server/app"
SERVICE_PATH = APP_PATH + "/service0"
ADVERT_PATH = "/gpio_server/advert"


class BleTransport:
    """Per-device message assembly for the rpc characteristic."""

    def __init__(self, rpc):
        self._rpc = rpc
        self._incoming = {}  # device -> request frame received so far
        self._outgoing = {}  # device -> reply frame not yet read
        self._piece = {}  # device -> piece currently being read

    def read_challenge(self, device: str, offset: int) -> bytes:
        # 16 bytes always fit in one ATT read, so offset is always 0.
        return self._rpc.challenges.issue()

    def write_rpc(self, device: str, offset: int, data: bytes):
        """Collect a request frame; long writes arrive in pieces at increasing offsets."""
        received = self._incoming.get(device, b"") if offset else b""
        if offset > len(received):
            raise DBusError("org.bluez.Error.InvalidOffset", "offset beyond received data")
        frame = received[:offset] + data
        if len(frame) > 2 + protocol.MAX_ENVELOPE:
            raise DBusError("org.bluez.Error.InvalidValueLength", "request too large")
        envelope = protocol.unframe(frame)
        if envelope is None:
            self._incoming[device] = frame  # wait for the rest
            return
        self._incoming.pop(device, None)
        self._outgoing.pop(device, None)
        self._piece.pop(device, None)
        reply = self._rpc.handle(envelope)
        if reply is None:
            raise DBusError("org.bluez.Error.NotAuthorized", "denied")
        self._outgoing[device] = protocol.frame(reply)

    def read_rpc(self, device: str, offset: int) -> bytes:
        """Each read at offset 0 returns the next piece of the reply frame.

        Reads at a non-zero offset are the stack's long reads of that same
        piece, which happen when a piece is larger than the MTU.
        """
        if offset == 0:
            remaining = self._outgoing.get(device, b"")
            self._piece[device] = remaining[: protocol.BLE_PIECE_SIZE]
            self._outgoing[device] = remaining[protocol.BLE_PIECE_SIZE :]
        return self._piece.get(device, b"")[offset:]


class Service(ServiceInterface):
    def __init__(self):
        super().__init__("org.bluez.GattService1")

    @dbus_property(access=PropertyAccess.READ)
    def UUID(self) -> "s":
        return protocol.SERVICE_UUID

    @dbus_property(access=PropertyAccess.READ)
    def Primary(self) -> "b":
        return True


class Characteristic(ServiceInterface):
    def __init__(self, uuid: str, read, write=None):
        super().__init__("org.bluez.GattCharacteristic1")
        self._uuid = uuid
        self._read = read
        self._write = write

    @dbus_property(access=PropertyAccess.READ)
    def UUID(self) -> "s":
        return self._uuid

    @dbus_property(access=PropertyAccess.READ)
    def Service(self) -> "o":
        return SERVICE_PATH

    @dbus_property(access=PropertyAccess.READ)
    def Flags(self) -> "as":
        return ["read", "write"] if self._write else ["read"]

    @method()
    def ReadValue(self, options: "a{sv}") -> "ay":
        return self._read(*_device_and_offset(options))

    @method()
    def WriteValue(self, value: "ay", options: "a{sv}"):
        if not self._write:
            raise DBusError("org.bluez.Error.NotSupported", "read only")
        self._write(*_device_and_offset(options), bytes(value))


class Advertisement(ServiceInterface):
    def __init__(self, name: str):
        super().__init__("org.bluez.LEAdvertisement1")
        self._name = name

    @dbus_property(access=PropertyAccess.READ)
    def Type(self) -> "s":
        return "peripheral"

    @dbus_property(access=PropertyAccess.READ)
    def ServiceUUIDs(self) -> "as":
        return [protocol.SERVICE_UUID]

    @dbus_property(access=PropertyAccess.READ)
    def LocalName(self) -> "s":
        return self._name

    @method()
    def Release(self):
        log.info("advertisement released by BlueZ")


def _device_and_offset(options: dict):
    device = options["device"].value if "device" in options else ""
    offset = options["offset"].value if "offset" in options else 0
    return device, offset


async def serve(rpc, adapter: str, name: str):
    """Publish the GATT service and keep it registered while BlueZ comes and goes."""
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    transport = BleTransport(rpc)
    bus.export(SERVICE_PATH, Service())
    bus.export(SERVICE_PATH + "/challenge", Characteristic(protocol.CHALLENGE_UUID, transport.read_challenge))
    bus.export(SERVICE_PATH + "/rpc", Characteristic(protocol.RPC_UUID, transport.read_rpc, transport.write_rpc))
    bus.export(ADVERT_PATH, Advertisement(name))

    async def register():
        adapter_path = f"/org/bluez/{adapter}"
        for _ in range(10):  # the adapter can appear a little after bluetoothd
            try:
                proxy = bus.get_proxy_object(BLUEZ, adapter_path, await bus.introspect(BLUEZ, adapter_path))
                properties = proxy.get_interface("org.freedesktop.DBus.Properties")
                await properties.call_set("org.bluez.Adapter1", "Powered", Variant("b", True))
                await proxy.get_interface("org.bluez.GattManager1").call_register_application(APP_PATH, {})
                await proxy.get_interface("org.bluez.LEAdvertisingManager1").call_register_advertisement(ADVERT_PATH, {})
                log.info("BLE: advertising as %r on %s", name, adapter)
                return
            except Exception as e:
                log.warning("BLE: registration on %s failed: %s", adapter, e)
                await asyncio.sleep(3)
        log.error("BLE: giving up on %s until bluetoothd restarts", adapter)

    # BlueZ forgets our registration when bluetoothd restarts: register again
    # whenever org.bluez gets a new owner.
    tasks = set()

    def on_message(message: Message):
        if message.member == "NameOwnerChanged" and message.body[0] == BLUEZ and message.body[2]:
            task = asyncio.create_task(register())
            tasks.add(task)
            task.add_done_callback(tasks.discard)

    bus.add_message_handler(on_message)
    await bus.call(Message(
        destination="org.freedesktop.DBus",
        path="/org/freedesktop/DBus",
        interface="org.freedesktop.DBus",
        member="AddMatch",
        signature="s",
        body=[f"type='signal',member='NameOwnerChanged',arg0='{BLUEZ}'"],
    ))
    await register()
    await bus.wait_for_disconnect()
