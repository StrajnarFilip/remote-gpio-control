"""GPIO lines discovered through libgpiod and managed at runtime."""

import glob
import json
import logging
import os
import re
import threading

import gpiod
from gpiod.line import Bias, Direction, Value

from . import protocol

log = logging.getLogger(__name__)

CONSUMER = "gpio-server"
DEFAULTS = {"mode": "off", "label": "", "bias": "none", "active_low": False}
_BIAS = {"none": Bias.DISABLED, "pull-up": Bias.PULL_UP, "pull-down": Bias.PULL_DOWN}


def discover(pattern: str) -> dict:
    """Map line name -> (chip path, offset) for every line whose name matches.

    Names come from the device tree (on a Raspberry Pi 5 the header pins are
    GPIO2..GPIO27), so nobody has to look up chip numbers or offsets.
    """
    lines = {}
    # realpath: the Pi 5 has a gpiochip4 -> gpiochip0 compatibility symlink.
    for path in sorted({os.path.realpath(p) for p in glob.glob("/dev/gpiochip*")}):
        if not gpiod.is_gpiochip_device(path):
            continue
        with gpiod.Chip(path) as chip:
            for offset in range(chip.get_info().num_lines):
                name = chip.get_line_info(offset).name
                if not name or not re.fullmatch(pattern, name):
                    continue
                if name in lines:
                    log.warning("ignoring duplicate line name %s on %s", name, path)
                    continue
                lines[name] = (path, offset)
    return lines


class Gpio:
    def __init__(self, state_file: str, pattern: str):
        self._state_file = state_file
        self._lock = threading.Lock()
        self._lines = discover(pattern)
        self._chips = {path: gpiod.Chip(path) for path, _ in self._lines.values()}
        self._config = {name: dict(DEFAULTS) for name in self._lines}
        self._requests = {}  # name -> gpiod.LineRequest, for lines not "off"
        self._timers = {}  # name -> threading.Timer ending a pulse
        if self._lines:
            log.info("found %d lines: %s", len(self._lines), " ".join(self._lines))
        else:
            log.warning("no GPIO lines named like %r (check `gpioinfo` and --lines)", pattern)

        # Saved entries for lines that are missing or busy now stay in the
        # file, so they apply again once the line is available.
        self._saved = self._load()
        for name, saved in self._saved.items():
            if name not in self._lines:
                log.warning("saved line %s not found, leaving it unconfigured", name)
                continue
            try:
                self._apply(name, {**DEFAULTS, **protocol.check_line_config(saved)})
            except ValueError as e:
                log.warning("%s left off: %s", name, e)

    def state(self) -> list:
        with self._lock:
            return [self._line_state(name) for name in self._lines]

    def set(self, name: str, value: int):
        with self._lock:
            request, offset = self._output(name)
            self._cancel_pulse(name)
            request.set_value(offset, Value.ACTIVE if value else Value.INACTIVE)

    def pulse(self, name: str, ms: int):
        """Make an output active, then inactive again after `ms` milliseconds."""
        with self._lock:
            request, offset = self._output(name)
            self._cancel_pulse(name)
            request.set_value(offset, Value.ACTIVE)
            timer = threading.Timer(ms / 1000, lambda: self._end_pulse(name, timer))
            timer.daemon = True
            self._timers[name] = timer
            timer.start()

    def configure(self, name: str, changes: dict):
        with self._lock:
            self._check(name)
            old = self._config[name]
            new = {**old, **changes}
            # A label change alone must not glitch the hardware.
            if any(new[k] != old[k] for k in ("mode", "bias", "active_low")):
                self._apply(name, new)
            self._config[name] = new
            self._saved[name] = new
            self._save()

    def _line_state(self, name: str) -> dict:
        path, offset = self._lines[name]
        request = self._requests.get(name)
        if request:
            value, busy = int(request.get_value(offset) == Value.ACTIVE), None
        else:
            info = self._chips[path].get_line_info(offset)
            value, busy = None, (info.consumer or "kernel") if info.used else None
        return {"name": name, **self._config[name], "value": value, "busy": busy}

    def _apply(self, name: str, config: dict):
        """Make the hardware match `config`. Raises ValueError if that fails."""
        self._cancel_pulse(name)
        old = self._requests.pop(name, None)
        if old:
            old.release()
        self._config[name] = {**config, "mode": "off"}
        if config["mode"] == "off":
            return
        path, offset = self._lines[name]
        is_input = config["mode"] == "input"
        settings = gpiod.LineSettings(
            direction=Direction.INPUT if is_input else Direction.OUTPUT,
            bias=_BIAS[config["bias"]] if is_input else Bias.AS_IS,
            active_low=config["active_low"],
            output_value=Value.INACTIVE,  # outputs always start inactive
        )
        try:
            request = self._chips[path].request_lines({offset: settings}, consumer=CONSUMER)
        except OSError as e:
            raise ValueError(f"cannot use {name}: {e.strerror}") from e
        self._requests[name] = request
        self._config[name] = config

    def _check(self, name: str):
        if name not in self._lines:
            raise ValueError(f"unknown line {name!r}")

    def _output(self, name: str):
        self._check(name)
        if self._config[name]["mode"] != "output":
            raise ValueError(f"{name} is not an output")
        return self._requests[name], self._lines[name][1]

    def _cancel_pulse(self, name: str):
        timer = self._timers.pop(name, None)
        if timer:
            timer.cancel()

    def _end_pulse(self, name: str, timer: threading.Timer):
        with self._lock:
            if self._timers.get(name) is not timer:
                return  # superseded by a later set, pulse or configure
            del self._timers[name]
            self._requests[name].set_value(self._lines[name][1], Value.INACTIVE)

    def _load(self) -> dict:
        try:
            with open(self._state_file) as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def _save(self):
        tmp = self._state_file + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self._saved, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._state_file)
