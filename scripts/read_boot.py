#!/usr/bin/env python3
"""Reset a board via RTS and dump its boot log over serial.

For debugging when idf_monitor isn't usable (e.g. no TTY in a sandboxed
shell). Toggles RTS to hard-reset the board (same line ESP-IDF's own
auto-reset uses), then reads raw bytes for a fixed duration.

Usage: python3 scripts/read_boot.py /dev/cu.usbmodemXXXX [seconds] > boot.log
Requires pyserial — use the ESP-IDF venv, e.g.:
  $IDF_PYTHON_ENV_PATH/bin/python scripts/read_boot.py /dev/cu.usbmodemXXXX
"""
import sys
import time

import serial

def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} <port> [seconds]", file=sys.stderr)
        return 1

    port = sys.argv[1]
    duration = float(sys.argv[2]) if len(sys.argv) > 2 else 10.0

    ser = serial.Serial(port, 115200, timeout=0.5)
    ser.dtr = False
    ser.rts = False
    time.sleep(0.2)
    ser.rts = True
    time.sleep(0.3)
    ser.rts = False

    end = time.time() + duration
    data = b""
    while time.time() < end:
        chunk = ser.read(4096)
        if chunk:
            data += chunk
    ser.close()
    sys.stdout.buffer.write(data)
    return 0

if __name__ == "__main__":
    sys.exit(main())
