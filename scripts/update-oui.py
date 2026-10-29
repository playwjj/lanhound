#!/usr/bin/env python3
"""Regenerate internal/oui/oui_data.txt from the official IEEE OUI registry.

Usage:
    curl -O https://standards-oui.ieee.org/oui/oui.txt
    python3 scripts/update-oui.py oui.txt

Output lines: "AABBCC<TAB>Vendor Name", sorted, deduplicated.
"""
import re
import sys

def main() -> None:
    src = sys.argv[1] if len(sys.argv) > 1 else "oui.txt"
    seen: dict[str, str] = {}
    with open(src, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = re.match(r"^([0-9A-F]{2})-([0-9A-F]{2})-([0-9A-F]{2})\s+\(hex\)\s+(.+?)\s*$", line)
            if m:
                prefix = m.group(1) + m.group(2) + m.group(3)
                vendor = m.group(4).strip()
                if prefix not in seen and vendor:
                    seen[prefix] = vendor
    out = "internal/oui/oui_data.txt"
    with open(out, "w", encoding="utf-8") as f:
        for prefix in sorted(seen):
            f.write(f"{prefix}\t{seen[prefix]}\n")
    print(f"wrote {out}: {len(seen)} entries")

if __name__ == "__main__":
    main()
