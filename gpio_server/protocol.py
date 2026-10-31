"""Wire protocol shared by the server and clients. PROTOCOL.md is the spec."""

import json
import os
import threading
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE = 32  # AES-256
NONCE_SIZE = 12
TAG_SIZE = 16
CHALLENGE_SIZE = 16
CHALLENGE_TTL = 10.0  # seconds

REQUEST_AAD = b"gpio-server/v1 request"
RESPONSE_AAD = b"gpio-server/v1 response"

# BLE GATT identifiers, fixed for protocol v1.
SERVICE_UUID = "79fc9371-0370-434e-b6a2-c245e12d7514"
CHALLENGE_UUID = "7c5b0353-76f0-417c-b3b8-4d872b3134a9"
RPC_UUID = "4bdc484e-1469-47fc-8f3f-caaa38c618e8"
BLE_PIECE_SIZE = 512  # the largest value one ATT read can return

MAX_ENVELOPE = 4096

# Vocabulary of line configuration.
MODES = ("off", "input", "output")
BIASES = ("none", "pull-up", "pull-down")
MAX_LABEL = 24
MAX_PULSE_MS = 10_000


def parse_key(text: str) -> bytes:
    key = bytes.fromhex(text.strip())
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be {KEY_SIZE * 2} hex characters")
    return key


def read_key(path) -> bytes:
    with open(path) as f:
        return parse_key(f.read())


def seal(key: bytes, aad: bytes, message: dict) -> bytes:
    """Encrypt and authenticate a JSON message as nonce || ciphertext || tag."""
    # A random 96-bit nonce is safe for ~2^32 messages per key.
    nonce = os.urandom(NONCE_SIZE)
    plaintext = json.dumps(message, separators=(",", ":")).encode()
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def unseal(key: bytes, aad: bytes, envelope: bytes):
    """Inverse of seal(). Raises InvalidTag unless the envelope is authentic."""
    if len(envelope) < NONCE_SIZE + TAG_SIZE:
        raise InvalidTag()
    nonce, ciphertext = envelope[:NONCE_SIZE], envelope[NONCE_SIZE:]
    return json.loads(AESGCM(key).decrypt(nonce, ciphertext, aad))


def response_aad(request_envelope: bytes) -> bytes:
    """A reply is bound to the request it answers through that request's nonce.

    The nonce is chosen at random by the client, so a recorded reply can never
    be passed off as the answer to a new request.
    """
    return RESPONSE_AAD + request_envelope[:NONCE_SIZE]


class Challenges:
    """Single-use, short-lived server challenges: the replay protection.

    A request is accepted only if it carries a challenge this process issued
    less than `ttl` seconds ago and that has not been redeemed yet. State
    lives in memory only, so a restart invalidates everything recorded before
    it. Memory is bounded by issue rate x ttl.
    """

    def __init__(self, ttl=CHALLENGE_TTL, clock=time.monotonic):
        self._ttl = ttl
        self._clock = clock
        self._pending = {}  # challenge -> expiry, oldest first
        self._lock = threading.Lock()

    def issue(self) -> bytes:
        challenge = os.urandom(CHALLENGE_SIZE)
        with self._lock:
            now = self._clock()
            # Insertion order is expiry order (constant ttl, monotonic clock),
            # so expired entries are always at the front.
            while self._pending:
                oldest = next(iter(self._pending))
                if self._pending[oldest] > now:
                    break
                del self._pending[oldest]
            self._pending[challenge] = now + self._ttl
        return challenge

    def redeem(self, challenge: bytes) -> bool:
        with self._lock:
            expiry = self._pending.pop(challenge, None)
            return expiry is not None and self._clock() < expiry


def check_line_config(fields: dict) -> dict:
    """Validate a (partial) line configuration and return its known fields."""
    if "mode" in fields and fields["mode"] not in MODES:
        raise ValueError(f"mode must be one of {', '.join(MODES)}")
    if "bias" in fields and fields["bias"] not in BIASES:
        raise ValueError(f"bias must be one of {', '.join(BIASES)}")
    if "label" in fields and not (
        isinstance(fields["label"], str) and len(fields["label"]) <= MAX_LABEL
    ):
        raise ValueError(f"label must be a string of at most {MAX_LABEL} characters")
    if "active_low" in fields and not isinstance(fields["active_low"], bool):
        raise ValueError("active_low must be true or false")
    return {k: fields[k] for k in ("mode", "label", "bias", "active_low") if k in fields}


def frame(payload: bytes) -> bytes:
    """BLE framing: a 2-byte big-endian length, then the payload."""
    return len(payload).to_bytes(2, "big") + payload


def unframe(buffer: bytes):
    """Return the payload of a complete frame, or None if more bytes are needed."""
    if len(buffer) < 2:
        return None
    length = int.from_bytes(buffer[:2], "big")
    if len(buffer) < 2 + length:
        return None
    return buffer[2 : 2 + length]
