"""gpio-server: control GPIO lines over HTTPS and Bluetooth LE."""

import argparse
import asyncio
import logging
import os
import secrets
import socket
import subprocess
import threading
from pathlib import Path

from . import protocol
from .gpio import Gpio
from .rpc import Rpc

log = logging.getLogger("gpio_server")


def main():
    parser = argparse.ArgumentParser(prog="gpio-server", description=__doc__)
    parser.add_argument("--data-dir", default="/var/lib/gpio-server",
                        help="holds the key, TLS certificate and pin settings (default %(default)s)")
    parser.add_argument("--listen", default="0.0.0.0:8443", help="HTTPS address (default %(default)s)")
    parser.add_argument("--lines", default=r"GPIO\d+",
                        help="regex of the line names that may be managed (default %(default)s)")
    parser.add_argument("--ble-adapter", default="hci0", help="default %(default)s")
    parser.add_argument("--ble-name", default="gpio", help="advertised name (default %(default)s)")
    parser.add_argument("--no-http", action="store_true", help="disable HTTPS")
    parser.add_argument("--no-ble", action="store_true", help="disable Bluetooth LE")
    parser.add_argument("-v", "--verbose", action="store_true", help="log every request")
    args = parser.parse_args()
    if args.no_http and args.no_ble:
        parser.error("nothing to do with both --no-http and --no-ble")
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s")

    os.umask(0o077)  # everything we write (key, certificate, settings) is private
    data = Path(args.data_dir)
    data.mkdir(parents=True, exist_ok=True)
    rpc = Rpc(load_or_create_key(data / "key"), Gpio(str(data / "pins.json"), args.lines))

    http_thread = None
    if not args.no_http:
        from .web import Server

        host, port = args.listen.rsplit(":", 1)
        server = Server((host, int(port)), rpc, *ensure_certificate(data))
        http_thread = threading.Thread(target=server.serve_forever, daemon=True)
        http_thread.start()
        log.info("HTTPS: listening on %s", args.listen)

    if not args.no_ble:
        try:
            from . import ble

            asyncio.run(ble.serve(rpc, args.ble_adapter, args.ble_name))
        except Exception as e:
            log.error("BLE: stopped: %s", e)

    if http_thread:
        http_thread.join()


def load_or_create_key(path: Path) -> bytes:
    if not path.exists():
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
            f.write(secrets.token_hex(protocol.KEY_SIZE) + "\n")
        log.warning("generated a new key, show it with: sudo cat %s", path)
    return protocol.read_key(path)


def ensure_certificate(data: Path):
    """Self-signed certificate; browsers need HTTPS before they allow WebCrypto."""
    cert, key = data / "tls.crt", data / "tls.key"
    if not cert.exists():
        host = socket.gethostname()
        result = subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
             "-nodes", "-days", "3650", "-subj", f"/CN={host}",
             "-addext", f"subjectAltName=DNS:{host},DNS:{host}.local,DNS:localhost",
             "-keyout", str(key), "-out", str(cert)],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise SystemExit(f"openssl failed to create a certificate:\n{result.stderr}")
        log.info("generated a self-signed TLS certificate for %s", host)
    return str(cert), str(key)


if __name__ == "__main__":
    main()
