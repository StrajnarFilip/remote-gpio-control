# gpio-server

Control a Raspberry Pi's GPIO pins (or any Linux board's) from a browser or the
command line, over the network (HTTPS) or directly over Bluetooth LE without
any network at all.

- **One pre-shared AES-256 key** protects everything. Share it by copying 64
  hex characters, or by scanning a QR code in the web UI.
- **Replay-proof:** every command must answer a fresh, single-use server
  challenge (details in [PROTOCOL.md](PROTOCOL.md)).
- **No setup for pins:** lines are discovered through libgpiod by their
  device-tree names (`GPIO2`…`GPIO27` on a Pi 5). Configure them as input or
  output from the UI.
- **Small:** about 600 lines of Python and 300 of JavaScript, with no frameworks.

```
gpio_server/
  protocol.py   envelopes (AES-256-GCM), challenges, BLE framing   <- start reviewing here
  rpc.py        authenticate, check freshness, dispatch
  gpio.py       libgpiod: discovery, inputs/outputs, pulse, saved settings
  web.py        HTTPS transport + web UI files
  ble.py        Bluetooth LE transport (BlueZ GATT over D-Bus)
  __main__.py   options, key and certificate creation, startup
  static/       web UI (qrcode.js is vendored, see below)
gpioctl.py      command-line client (HTTPS or BLE)
```

## Install on a Raspberry Pi

These steps are for Raspberry Pi OS Trixie (Debian 13).

```sh
sudo apt install python3-libgpiod python3-cryptography python3-dbus-fast
sudo git clone <this repository> /opt/gpio-server
sudo useradd --system --no-create-home --shell /usr/sbin/nologin gpio-server
sudo cp /opt/gpio-server/deploy/gpio-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now gpio-server
journalctl -u gpio-server            # shows the lines found and "advertising as 'gpio'"
```

If the apt packages are missing or too old (libgpiod's Python bindings must be
v2), use a virtualenv instead: `python3 -m venv /opt/gpio-server/.venv &&
/opt/gpio-server/.venv/bin/pip install gpiod cryptography dbus-fast`. Then
point `ExecStart` at `/opt/gpio-server/.venv/bin/python`.

On first start the server creates its key, a self-signed TLS certificate and
an empty settings file in `/var/lib/gpio-server/`.

## Get the key onto your devices

1. Show the key on the Pi: `sudo cat /var/lib/gpio-server/key`
2. Open `https://<pi-address>:8443`, accept the certificate warning once, and paste the key.
3. To add a phone, click **Share key** and scan the QR code with its camera.
   The QR code holds `https://<pi-address>:8443/#key=…`. The part after `#` is
   never sent to any server; the page stores the key and removes it from the
   address bar.

The server never sends the key anywhere; browsers keep their own copy in local storage.

To rotate the key: `sudo rm /var/lib/gpio-server/key && sudo systemctl restart gpio-server`, then share the new key.

## Command line

```sh
export GPIO_KEY=<64 hex chars>          # or put the key in ~/.config/gpio-server.key
export GPIO_URL=https://raspberrypi.local:8443
./gpioctl.py state
./gpioctl.py configure GPIO17 --mode output --label "Garage door"
./gpioctl.py pulse GPIO17 500
./gpioctl.py configure GPIO27 --mode input --bias pull-up
./gpioctl.py --ble state                # over Bluetooth, no network (needs: pip install bleak)
```

## Server options

| Option | Default | |
|---|---|---|
| `--data-dir` | `/var/lib/gpio-server` | key, certificate, `pins.json` |
| `--listen` | `0.0.0.0:8443` | HTTPS address |
| `--lines` | `GPIO\d+` | regex of the line names that may be managed; check names with `gpioinfo` |
| `--ble-name` | `gpio` | advertised Bluetooth name (keep it short: advertisements hold 31 bytes) |
| `--ble-adapter` | `hci0` | |
| `--no-http`, `--no-ble` | | turn off a transport |
| `-v` | | log every request |

The default `--lines` deliberately hides the Pi's internal lines (`FAN_TACH`,
`PCIE_RP1_WAKE`, `ID_SDA`, …), which should never be switched remotely.
Lines used by enabled interfaces such as I²C or SPI are shown as busy.

## Security

**Protected against anyone without the key**, whether on the LAN, within
Bluetooth range, or on the internet if you forward the port:

- they can't read state, run commands, or forge replies;
- recorded messages can't be replayed;
- quantum attacks don't help, because only AES-256 is used.

**Not covered:**

- **A leaked key** gives full control. There is one key for everything, and no
  forward secrecy: a leaked key also decrypts recorded traffic. Rotate the key
  if a device is lost.
- **Delayed delivery:** a request blocked in transit can still be delivered
  once within 10 seconds. A `pulse` can therefore run twice if the client also
  retries.
- **Denial of service:** flooding the network or jamming the radio.
- **Physical access** to the Pi.
- **The web UI's JavaScript** is only as trustworthy as the connection that
  delivered it. If you click through a certificate warning while someone is
  intercepting your traffic, they could serve a page that steals the key. Check
  the certificate fingerprint against `openssl x509 -noout -fingerprint -sha256
  -in /var/lib/gpio-server/tls.crt`, or use `gpioctl.py`, which doesn't have
  this problem.

## Development

```sh
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/pytest
sudo tests/gpio-sim.sh                  # simulated chip with lines GPIO0..GPIO27
.venv/bin/python -m gpio_server --data-dir ./dev-data --no-ble
```

`gpio_server/static/qrcode.js` is
[qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) 1.4.4 by
Kazuhiko Arase (MIT), unmodified. Its SHA-256 is
`18ae399f81182bc9de916e9c77b195df20cc58d6f2d55a62b085a299f1bf1780`.
