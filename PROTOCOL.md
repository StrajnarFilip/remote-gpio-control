# gpio-server protocol v1

Everything a client needs to talk to gpio-server over HTTPS or Bluetooth LE.
The reference implementations are `gpio_server/protocol.py` (Python) and
`gpio_server/static/app.js` (browser).

## Key

32 random bytes (AES-256), written and shared as 64 hex characters. Every
client holds the same key; holding the key means full control.

## Envelope

Every request and every reply is one envelope:

```
envelope = nonce (12 random bytes) || AES-256-GCM(key, nonce, plaintext, aad)   # includes a 16-byte tag
plaintext = UTF-8 JSON object
```

| Direction | AAD |
|---|---|
| request | `"gpio-server/v1 request"` |
| reply | `"gpio-server/v1 response"` followed by the 12-byte nonce of the request being answered |

The two labels stop a reply from being sent back to the server as a request.
Including the request nonce binds each reply to exactly one request: a
recorded reply fails authentication against any other request.

Only AES-256-GCM is used, and there is no public-key cryptography anywhere, so
the protocol is quantum-resistant. Grover's algorithm leaves AES-256 at about
128-bit strength.

## Replay protection

1. The client fetches a **challenge**: 16 random bytes from the server.
2. The client sends a request carrying `"challenge": "<32 hex chars>"` inside the sealed JSON.
3. The server accepts the request only if all of these hold, checked in this order:
   1. the GCM tag is valid;
   2. the challenge was issued by this server process;
   3. it was issued less than **10 seconds** ago (monotonic clock);
   4. it has not been used before. Redeeming a challenge removes it.

Challenges live only in memory, so a server restart invalidates every message
recorded before it. No clocks need to agree and nothing is persisted.

The one window left: an attacker who blocks a request in transit can deliver it
once, within those 10 seconds. `set` and `configure` are idempotent; `pulse` is
not, so a client that retries a failed `pulse` may cause two pulses.

## Requests

```json
{"challenge": "…", "op": "state"}
{"challenge": "…", "op": "set", "line": "GPIO17", "value": 1}
{"challenge": "…", "op": "pulse", "line": "GPIO17", "ms": 500}
{"challenge": "…", "op": "configure", "line": "GPIO17", "mode": "output", "label": "Garage", "bias": "none", "active_low": false}
```

| op | fields |
|---|---|
| `state` | none |
| `set` | `line`; `value`: `0` or `1` (logical: active-low is applied by the kernel). Output lines only. |
| `pulse` | `line`; `ms`: 1–10000. The line goes active, then inactive after `ms`. Output lines only. |
| `configure` | `line`, plus any of: `mode` (`off`, `input`, `output`), `label` (≤ 24 characters), `bias` (`none`, `pull-up`, `pull-down`; inputs only), `active_low` (boolean). Changing only the label does not touch the hardware. Outputs start inactive. |

## Replies

```json
{"ok": true, "lines": [ … ]}
{"ok": false, "error": "GPIO18 is not an output", "lines": [ … ]}
```

Every reply carries the full state of every manageable line:

```json
{"name": "GPIO17", "mode": "output", "value": 1, "label": "Garage", "bias": "none", "active_low": false, "busy": null}
```

- `value` is `null` for lines that are `off`.
- `busy` names the consumer (e.g. a kernel driver) when someone else holds the line; such lines can't be configured.

The server discovers lines by name through libgpiod. By default it manages lines named `GPIO<n>`; on a Raspberry Pi 5 that is the header's GPIO2–GPIO27.

A request that fails authentication or freshness gets **no sealed reply**: HTTP 403, or a BLE `NotAuthorized` write error.

## HTTPS transport

| Request | Body | Response |
|---|---|---|
| `GET /challenge` | none | 16 raw bytes |
| `POST /rpc` | request envelope (≤ 4096 bytes) | `200` with the reply envelope, `403` if rejected, `413` if too large |
| `GET /` | none | web UI |

The server uses a self-signed certificate. TLS exists only because browsers
require HTTPS for WebCrypto and Web Bluetooth; clients may skip certificate
verification, because the envelope carries all of the security. With OpenSSL
3.5 or later, TLS still negotiates the hybrid post-quantum X25519MLKEM768 key
exchange.

## Bluetooth LE transport

There is one primary GATT service, and no pairing is needed.

| | UUID | Properties |
|---|---|---|
| Service | `79fc9371-0370-434e-b6a2-c245e12d7514` | advertised |
| `challenge` | `7c5b0353-76f0-417c-b3b8-4d872b3134a9` | read: a fresh 16-byte challenge on every read |
| `rpc` | `4bdc484e-1469-47fc-8f3f-caaa38c618e8` | write request, read reply |

ATT values are limited to 512 bytes, and a full reply is larger, so the `rpc`
characteristic carries **frames**:

```
frame = length (2 bytes, big-endian) || envelope
```

1. **Write** the request frame with a write-with-response. If it is bigger than
   the MTU, the BLE stack splits it into a long write automatically. The write
   fails with `NotAuthorized` if the request is rejected.
2. **Read** the `rpc` characteristic repeatedly. Each read returns the next
   piece of the reply frame, at most 512 bytes. Stop once you have
   `2 + length` bytes. Replies are kept per connected device.
