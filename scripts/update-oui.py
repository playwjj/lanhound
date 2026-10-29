#!/usr/bin/env python3
"""Regenerate internal/oui/oui_data.txt from the official IEEE registries.

Usage:
    curl -O https://standards-oui.ieee.org/oui/oui.txt        # MA-L (24-bit)
    curl -O https://standards-oui.ieee.org/oui28/mam.txt      # MA-M (28-bit)
    curl -O https://standards-oui.ieee.org/oui36/oui36.txt    # MA-S (36-bit)
    python3 scripts/update-oui.py oui.txt mam.txt oui36.txt

Small vendors get MA-M/MA-S blocks carved out of a MA-L block that is
itself registered to "IEEE Registration Authority"; without the two
extra files those devices would show that instead of their maker.

Output lines: "<6, 7 or 9 hex digits><TAB>Vendor Name", sorted. The
lookup tries the longest prefix first.
"""
import re
import sys

HEX = re.compile(r"^([0-9A-F]{2})-([0-9A-F]{2})-([0-9A-F]{2})\s+\(hex\)\s+(.*?)\s*$")
BASE16 = re.compile(r"^([0-9A-F]{6})(?:-([0-9A-F]{6}))?\s+\(base 16\)\s+(.*?)\s*$")


def parse(path: str, seen: dict[str, str]) -> None:
    oui = None
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = HEX.match(line)
            if m:
                oui = m.group(1) + m.group(2) + m.group(3)
                continue
            m = BASE16.match(line)
            if not m or oui is None:
                continue
            start, end, vendor = m.group(1), m.group(2), m.group(3).strip()
            if not vendor:
                continue
            if end is None:  # MA-L: "AABBCC (base 16)"
                prefix = start
            elif end.endswith("FFFFF"):  # MA-M: one hex digit more
                prefix = oui + start[0]
            else:  # MA-S: three hex digits more
                prefix = oui + start[:3]
            seen.setdefault(prefix, vendor)
            oui = None


def main() -> None:
    srcs = sys.argv[1:] or ["oui.txt"]
    seen: dict[str, str] = {}
    for src in srcs:
        parse(src, seen)
    out = "internal/oui/oui_data.txt"
    with open(out, "w", encoding="utf-8") as f:
        for prefix in sorted(seen):
            f.write(f"{prefix}\t{seen[prefix]}\n")
    print(f"wrote {out}: {len(seen)} entries")


if __name__ == "__main__":
    main()
