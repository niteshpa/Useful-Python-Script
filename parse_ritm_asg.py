#!/usr/bin/env python3
# Usage: python3 parse_ritm_asg.py <input_file> [output_file]

import re, sys, json, ipaddress
from pathlib import Path

IP  = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

RANGE_DASH = re.compile(rf'\b({IP})\s*[-–—]\s*({IP})\b')
RANGE_WORD = re.compile(rf'\b({IP})\s+(?:to|through)\s+({IP})\b', re.IGNORECASE)
CIDR       = re.compile(rf'\b({IP}/\d{{1,2}})\b')
SINGLE_IP  = re.compile(rf'\b({IP})\b')


def clean(text):
    text = re.sub(r'\b[\w.%+\-]+@[\w.\-]+\.[a-zA-Z]{{2,}}\b', '', text)          # emails
    text = re.sub(r'https?://([^\s/:]+)[^\s]*', r'\1', text)                       # URLs
    text = re.sub(r'\b\d{{2,4}}[.\-/]\d{{2}}[.\-/]\d{{2,4}}\b', '', text)         # dates
    text = re.sub(r'\b(version|release|patch|build|agent|ver|tag|rev|rhel|centos|ubuntu)[:\s]+[\d.]+\b', '', text, flags=re.IGNORECASE)
    text = re.sub(r'\bv\d+(\.\d+)+\b', '', text, flags=re.IGNORECASE)             # v1.2.3
    text = re.sub(rf'({IP}):\d+', r'\1', text)                                    # ip:port
    text = re.sub(r'\b(KB|RITM|INC|CHG|TASK|REQ|PRB)\d+\b', '', text, flags=re.IGNORECASE)
    return text


def valid_ip(s):
    try: ipaddress.IPv4Address(s); return True
    except ValueError: return False

def valid_cidr(s):
    try: ipaddress.IPv4Network(s, strict=False); return True
    except ValueError: return False


def get_ranges(text):
    results, seen = [], []
    for pat in (RANGE_DASH, RANGE_WORD):
        for m in pat.finditer(text):
            if any(s <= m.start() < e for s, e in seen): continue
            if valid_ip(m.group(1)) and valid_ip(m.group(2)):
                s, e = ipaddress.IPv4Address(m.group(1)), ipaddress.IPv4Address(m.group(2))
                if int(s) <= int(e):
                    results.append((s, e, m.start(), m.end()))
                    seen.append((m.start(), m.end()))
    return results


def get_cidrs(text):
    return [(str(ipaddress.IPv4Network(m.group(1), strict=False)), m.start(), m.end())
            for m in CIDR.finditer(text) if valid_cidr(m.group(1))]


def get_ips(text, consumed):
    return {ipaddress.IPv4Address(m.group(1))
            for m in SINGLE_IP.finditer(text)
            if not any(s <= m.start() < e for s, e in consumed) and valid_ip(m.group(1))}


def consolidate(ips):
    if not ips: return []
    sips = sorted(ips, key=int)
    groups, s, e = [], sips[0], sips[0]
    for ip in sips[1:]:
        if int(ip) == int(e) + 1: e = ip
        else: groups.append((s, e)); s = e = ip
    return groups + [(s, e)]


def asg_rule(dest):
    return {"protocol": "<tcp/udp/all>", "destination": dest, "ports": "<PORT>", "description": "<DESCRIPTION>"}


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 parse_ritm_asg.py <input_file> [output_file]")
        sys.exit(1)

    src = Path(sys.argv[1])
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("asg_additions.json")

    text    = clean(src.read_text(encoding="utf-8", errors="ignore"))
    ranges  = get_ranges(text)
    cidrs   = get_cidrs(text)
    consumed = [(s, e) for *_, s, e in ranges] + [(s, e) for _, s, e in cidrs]
    ips     = {ip for ip in get_ips(text, consumed)
               if not any(int(s) <= int(ip) <= int(e) for s, e, *_ in ranges)
               and not any(ip in ipaddress.IPv4Network(c) for c, *_ in cidrs)}

    rules = (
        [asg_rule(f"{s}-{e}") for s, e, *_ in sorted(ranges, key=lambda x: int(x[0]))] +
        [asg_rule(c)          for c, *_ in sorted(cidrs)] +
        [asg_rule(str(s) if s == e else f"{s}-{e}") for s, e in consolidate(ips)]
    )

    output = json.dumps(rules, indent=2)
    print(output)
    out.write_text(output, encoding="utf-8")
    print(f"\n[OK] {len(rules)} rule(s) → {out}", file=sys.stderr)


if __name__ == "__main__":
    main()
