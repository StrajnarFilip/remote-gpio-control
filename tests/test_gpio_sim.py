"""gpio.py against real libgpiod, on a simulated chip: sudo tests/gpio-sim.sh

Skipped unless every discovered GPIO<n> line belongs to a gpio-sim chip, so
these tests never touch real hardware.
"""

import json
import time

import pytest

gpiod = pytest.importorskip("gpiod")

from gpio_server.gpio import CONSUMER, Gpio, discover  # noqa: E402


def _is_sim(path):
    with gpiod.Chip(path) as chip:
        return chip.get_info().label.startswith("gpio-sim")


LINES = discover(r"GPIO\d+")
pytestmark = pytest.mark.skipif(
    not LINES or not all(_is_sim(path) for path, _ in LINES.values()),
    reason="needs a gpio-sim chip and no real GPIO lines: sudo tests/gpio-sim.sh",
)


@pytest.fixture
def gpio(tmp_path):
    g = Gpio(str(tmp_path / "pins.json"), r"GPIO\d+")
    yield g
    for line in g.state():
        if line["mode"] != "off":
            g.configure(line["name"], {"mode": "off"})


def state(g, name):
    return next(line for line in g.state() if line["name"] == name)


def test_discovers_header_names():
    assert set(LINES) == {f"GPIO{i}" for i in range(28)}


def test_output_set_and_state(gpio):
    gpio.configure("GPIO17", {"mode": "output"})
    assert state(gpio, "GPIO17")["value"] == 0
    gpio.set("GPIO17", 1)
    assert state(gpio, "GPIO17")["value"] == 1
    path, offset = LINES["GPIO17"]
    with gpiod.Chip(path) as chip:
        info = chip.get_line_info(offset)
    assert info.used and info.consumer == CONSUMER


def test_set_requires_output(gpio):
    with pytest.raises(ValueError, match="not an output"):
        gpio.set("GPIO17", 1)
    with pytest.raises(ValueError, match="unknown line"):
        gpio.set("GPIO99", 1)


def test_pulse_ends_inactive(gpio):
    gpio.configure("GPIO17", {"mode": "output"})
    gpio.pulse("GPIO17", 50)
    assert state(gpio, "GPIO17")["value"] == 1
    time.sleep(0.2)
    assert state(gpio, "GPIO17")["value"] == 0


def test_set_cancels_pulse(gpio):
    gpio.configure("GPIO17", {"mode": "output"})
    gpio.pulse("GPIO17", 100)
    gpio.set("GPIO17", 1)
    time.sleep(0.3)
    assert state(gpio, "GPIO17")["value"] == 1


def test_input_follows_bias(gpio):
    # gpio-sim reports a floating input as its pull, so bias is observable.
    gpio.configure("GPIO27", {"mode": "input", "bias": "pull-up"})
    assert state(gpio, "GPIO27")["value"] == 1
    gpio.configure("GPIO27", {"bias": "pull-down"})
    assert state(gpio, "GPIO27")["value"] == 0


def test_active_low_inverts_logical_value(gpio):
    gpio.configure("GPIO27", {"mode": "input", "bias": "pull-up", "active_low": True})
    assert state(gpio, "GPIO27")["value"] == 0


def test_label_change_keeps_hardware_untouched(gpio):
    gpio.configure("GPIO17", {"mode": "output"})
    gpio.set("GPIO17", 1)
    request = gpio._requests["GPIO17"]
    gpio.configure("GPIO17", {"label": "Lamp"})
    assert gpio._requests["GPIO17"] is request
    assert state(gpio, "GPIO17")["value"] == 1


def test_off_releases_the_line(gpio):
    gpio.configure("GPIO17", {"mode": "output"})
    gpio.configure("GPIO17", {"mode": "off"})
    path, offset = LINES["GPIO17"]
    with gpiod.Chip(path) as chip:
        assert not chip.get_line_info(offset).used
    assert state(gpio, "GPIO17")["value"] is None


def test_line_held_elsewhere_is_busy(gpio):
    path, offset = LINES["GPIO5"]
    with gpiod.request_lines(path, consumer="someone-else", config={offset: None}):
        assert state(gpio, "GPIO5")["busy"] == "someone-else"
        with pytest.raises(ValueError, match="cannot use GPIO5"):
            gpio.configure("GPIO5", {"mode": "output"})
    assert state(gpio, "GPIO5")["mode"] == "off"


def test_settings_are_saved_and_restored(tmp_path):
    state_file = tmp_path / "pins.json"
    state_file.write_text(json.dumps({
        "GPIO17": {"mode": "output", "label": "Lamp"},
        "GPIO99": {"mode": "input"},  # missing line: kept, not applied
    }))
    g = Gpio(str(state_file), r"GPIO\d+")
    try:
        restored = state(g, "GPIO17")
        assert (restored["mode"], restored["label"], restored["value"]) == ("output", "Lamp", 0)
        g.configure("GPIO4", {"mode": "input"})
        saved = json.loads(state_file.read_text())
        assert saved["GPIO4"]["mode"] == "input"
        assert "GPIO99" in saved
    finally:
        for name in ("GPIO17", "GPIO4"):
            g.configure(name, {"mode": "off"})
