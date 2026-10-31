#!/usr/bin/env python3
"""gpioctl: command-line client for gpio-server over HTTPS or Bluetooth LE.

  gpioctl.py state
  gpioctl.py set GPIO17 1
  gpioctl.py pulse GPIO17 500
  gpioctl.py configure GPIO17 --mode output --label "Garage door"
  gpioctl.py --ble state                 # no network needed

The key comes from $GPIO_KEY or --key-file.
"""

import argparse
import asyncio
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

from gpio_server import protocol

REQUEST_FIELDS = ("line", "value", "ms", "mode", "label", "bias", "active_low")


def http_exchange(url: str, make_envelope):
    # Certificate checks are off on purpose: the server's certificate is
    # self-signed, and the envelopes (not TLS) provide all of the security.
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(f"{url}/challenge", context=context, timeout=10) as response:
            envelope = make_envelope(response.read())
        request = urllib.request.Request(f"{url}/rpc", data=envelope, method="POST")
        with urllib.request.urlopen(request, context=context, timeout=10) as response:
            return envelope, response.read()
    except urllib.error.HTTPError as e:
        sys.exit("rejected by the server (wrong key?)" if e.code == 403 else f"HTTP {e.code}")
    except urllib.error.URLError as e:
        sys.exit(f"cannot reach {url}: {e.reason}")


async def ble_exchange(address: str, make_envelope):
    from bleak import BleakClient, BleakScanner
    from bleak.exc import BleakError

    if not address:
        device = await BleakScanner.find_device_by_filter(
            lambda _, adv: protocol.SERVICE_UUID in adv.service_uuids, timeout=10
        )
        if device is None:
            sys.exit("no gpio-server found over Bluetooth")
        address = device
    async with BleakClient(address) as client:
        envelope = make_envelope(bytes(await client.read_gatt_char(protocol.CHALLENGE_UUID)))
        try:
            await client.write_gatt_char(protocol.RPC_UUID, protocol.frame(envelope), response=True)
        except BleakError as e:
            sys.exit(f"rejected by the server (wrong key?): {e}")
        # The reply arrives in pieces; read until the whole frame is here.
        frame = b""
        while (reply := protocol.unframe(frame)) is None:
            piece = bytes(await client.read_gatt_char(protocol.RPC_UUID))
            if not piece:
                sys.exit("incomplete reply")
            frame += piece
        return envelope, reply


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default=os.environ.get("GPIO_URL", "https://localhost:8443"),
                        help="server URL (default $GPIO_URL or %(default)s)")
    parser.add_argument("--ble", nargs="?", const="", metavar="ADDRESS",
                        help="use Bluetooth LE: scan for the server, or connect to ADDRESS")
    parser.add_argument("--key-file", default="~/.config/gpio-server.key",
                        help="file with the 64-hex-character key (default %(default)s)")
    parser.add_argument("--json", action="store_true", help="print the raw reply")
    parser.add_argument("--dump-request", metavar="FILE",
                        help="also save the sealed request, e.g. to check that a replay is rejected")
    commands = parser.add_subparsers(dest="op", required=True)
    commands.add_parser("state", help="show all lines")
    command = commands.add_parser("set", help="set an output")
    command.add_argument("line")
    command.add_argument("value", type=int, choices=(0, 1))
    command = commands.add_parser("pulse", help="make an output active for some milliseconds")
    command.add_argument("line")
    command.add_argument("ms", type=int)
    command = commands.add_parser("configure", help="change a line's settings")
    command.add_argument("line")
    command.add_argument("--mode", choices=protocol.MODES)
    command.add_argument("--label")
    command.add_argument("--bias", choices=protocol.BIASES)
    command.add_argument("--active-low", action=argparse.BooleanOptionalAction)
    args = parser.parse_args()

    if "GPIO_KEY" in os.environ:
        key = protocol.parse_key(os.environ["GPIO_KEY"])
    else:
        key = protocol.read_key(Path(args.key_file).expanduser())
    fields = {k: v for k, v in vars(args).items() if k in REQUEST_FIELDS and v is not None}

    def make_envelope(challenge: bytes) -> bytes:
        envelope = protocol.seal(key, protocol.REQUEST_AAD, {"challenge": challenge.hex(), "op": args.op, **fields})
        if args.dump_request:
            Path(args.dump_request).write_bytes(envelope)
        return envelope

    if args.ble is not None:
        envelope, reply_envelope = asyncio.run(ble_exchange(args.ble, make_envelope))
    else:
        envelope, reply_envelope = http_exchange(args.url.rstrip("/"), make_envelope)
    reply = protocol.unseal(key, protocol.response_aad(envelope), reply_envelope)

    if args.json:
        print(json.dumps(reply, indent=2))
    else:
        for line in reply["lines"]:
            value = "-" if line["value"] is None else line["value"]
            note = f"in use by {line['busy']}" if line["busy"] else line["label"]
            print(f"{line['name']:<8} {line['mode']:<7} {value:<2} {note}")
    if not reply["ok"]:
        sys.exit(f"error: {reply['error']}")


if __name__ == "__main__":
    main()
