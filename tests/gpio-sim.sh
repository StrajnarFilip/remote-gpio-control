#!/bin/sh
# Create a simulated GPIO chip whose lines are named GPIO0..GPIO27, like a
# Raspberry Pi header, so gpio-server can run on any Linux machine.
#
#   sudo tests/gpio-sim.sh          create the chip (owned by the invoking user)
#   sudo tests/gpio-sim.sh remove   remove it again
set -eu

CFG=/sys/kernel/config/gpio-sim/gpio-server-test
BANK=$CFG/gpio-bank0

if [ "${1:-}" = remove ]; then
    echo 0 > "$CFG/live"
    for line in "$BANK"/line*; do rmdir "$line"; done
    rmdir "$BANK" "$CFG"
    exit 0
fi

modprobe gpio-sim
mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config
mkdir "$CFG" "$BANK"
echo 28 > "$BANK/num_lines"
for i in $(seq 0 27); do
    mkdir "$BANK/line$i"
    echo "GPIO$i" > "$BANK/line$i/name"
done
echo 1 > "$CFG/live"

CHIP=$(cat "$BANK/chip_name")
chown "${SUDO_USER:-root}" "/dev/$CHIP"
echo "created /dev/$CHIP with lines GPIO0..GPIO27"
echo "simulate an input changing with:"
echo "  echo pull-up | sudo tee /sys/devices/platform/$(cat "$CFG/dev_name")/$CHIP/sim_gpio27/pull"
