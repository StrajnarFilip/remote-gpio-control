"""Authenticated command handling, shared by every transport."""

import logging

from cryptography.exceptions import InvalidTag

from . import protocol

log = logging.getLogger(__name__)


class Rpc:
    def __init__(self, key: bytes, gpio):
        self._key = key
        self._gpio = gpio
        self.challenges = protocol.Challenges()

    def handle(self, envelope: bytes):
        """Return the sealed reply, or None if the request is not authentic and fresh."""
        try:
            request = protocol.unseal(self._key, protocol.REQUEST_AAD, envelope)
        except (InvalidTag, ValueError):
            log.warning("rejected request: not authentic")
            return None
        if not self.challenges.redeem(_challenge(request)):
            log.warning("rejected request: unknown, expired or reused challenge")
            return None

        try:
            self._dispatch(request)
            reply = {"ok": True}
        except (ValueError, OSError) as e:
            reply = {"ok": False, "error": str(e)}
        reply["lines"] = self._gpio.state()
        return protocol.seal(self._key, protocol.response_aad(envelope), reply)

    def _dispatch(self, request: dict):
        op = request.get("op")
        if op not in ("state", "set", "pulse", "configure"):
            raise ValueError(f"unknown op {op!r}")
        if op == "state":
            return
        line = request.get("line")
        if not isinstance(line, str):
            raise ValueError("line must be a string")
        if op == "set":
            value = request.get("value")
            if not _is_int(value) or value not in (0, 1):
                raise ValueError("value must be 0 or 1")
            self._gpio.set(line, value)
        elif op == "pulse":
            ms = request.get("ms")
            if not _is_int(ms) or not 1 <= ms <= protocol.MAX_PULSE_MS:
                raise ValueError(f"ms must be an integer from 1 to {protocol.MAX_PULSE_MS}")
            self._gpio.pulse(line, ms)
        else:  # configure
            self._gpio.configure(line, protocol.check_line_config(request))


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _challenge(request) -> bytes:
    """The challenge a request claims to answer, or b"" if it has none."""
    if not isinstance(request, dict) or not isinstance(request.get("challenge"), str):
        return b""
    try:
        return bytes.fromhex(request["challenge"])
    except ValueError:
        return b""
