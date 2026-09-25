#!/usr/bin/env python3
"""Print the UDID of the newest available iOS simulator whose name matches a regex.

Usage: pick-simulator.py '<name-regex>'

Candidates are ranked by iOS runtime version first, then by the device name using
natural ordering, so "iPhone 18 Pro" beats "iPhone 17 Pro" on the same runtime.
The chosen device is echoed to stderr for the job log.
"""

import json
import re
import subprocess
import sys


def runtime_version(runtime_identifier):
    match = re.search(r"SimRuntime\.iOS-(\d+)-(\d+)", runtime_identifier)
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2))


def natural_key(name):
    return [int(token) if token.isdigit() else token for token in re.split(r"(\d+)", name)]


def main():
    if len(sys.argv) != 2:
        print("usage: pick-simulator.py '<name-regex>'", file=sys.stderr)
        return 2

    pattern = re.compile(sys.argv[1])
    output = subprocess.check_output(
        ["xcrun", "simctl", "list", "devices", "available", "-j"], text=True
    )
    candidates = []
    for runtime, devices in json.loads(output).get("devices", {}).items():
        version = runtime_version(runtime)
        if version is None:
            continue
        for device in devices:
            name = device.get("name", "")
            if device.get("isAvailable", False) and pattern.search(name):
                candidates.append((version, natural_key(name), name, device["udid"]))

    if not candidates:
        print(f"No available iOS simulator matches /{pattern.pattern}/", file=sys.stderr)
        return 1

    candidates.sort(reverse=True)
    version, _, name, udid = candidates[0]
    print(f"Picked '{name}' on iOS {version[0]}.{version[1]} ({udid})", file=sys.stderr)
    print(udid)
    return 0


if __name__ == "__main__":
    sys.exit(main())
