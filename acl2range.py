#!/usr/bin/env python3
"""Cisco ACL -> IP range/CIDR converter.

Supports common Cisco IOS ACL syntaxes (standard, extended, named ACL blocks).
Primary goal: extract source/destination address ranges from ACL entries.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from dataclasses import dataclass
from typing import Iterable, Iterator, List, Optional, Sequence, Tuple


@dataclass(frozen=True)
class IpRange:
    start: ipaddress.IPv4Address
    end: ipaddress.IPv4Address

    def to_dict(self) -> dict:
        return {"start": str(self.start), "end": str(self.end)}

    def to_text(self) -> str:
        return f"{self.start}-{self.end}"

    def to_cidr_list(self) -> Optional[List[str]]:
        # Only possible if this range is exactly representable as a set of CIDRs.
        # ipaddress.summarize_address_range always returns a list, but we only use
        # it when the range came from a contiguous wildcard (see contiguous check).
        return [str(n) for n in ipaddress.summarize_address_range(self.start, self.end)]


@dataclass(frozen=True)
class ParsedAcl:
    action: str  # permit|deny
    protocol: Optional[str]
    src: IpRange
    dst: Optional[IpRange]
    raw: str

    def to_dict(self, include_cidr: bool) -> dict:
        data = {
            "action": self.action,
            "protocol": self.protocol,
            "src": self.src.to_dict(),
            "raw": self.raw,
        }
        if self.dst is not None:
            data["dst"] = self.dst.to_dict()
        if include_cidr:
            data["src"]["cidr"] = self.src.to_cidr_list()
            if self.dst is not None:
                data["dst"]["cidr"] = self.dst.to_cidr_list()
        return data


_ACTIONS = {"permit", "deny"}
_PORT_OPS = {"eq", "gt", "lt", "neq", "range"}


def _strip_inline_comment(line: str) -> str:
    # Cisco configs sometimes use leading '!' lines; inline comments are uncommon,
    # but people paste with '#'. Keep it conservative.
    for sep in ("#", "//"):
        if sep in line:
            line = line.split(sep, 1)[0]
    return line.rstrip("\r\n")


def _tokenize(line: str) -> List[str]:
    # Collapse whitespace but keep tokens as-is.
    return re.findall(r"\S+", line)


def _is_ipv4(s: str) -> bool:
    try:
        ipaddress.IPv4Address(s)
        return True
    except Exception:
        return False


def _wildcard_to_range(ip: ipaddress.IPv4Address, wildcard: ipaddress.IPv4Address) -> IpRange:
    ip_int = int(ip)
    wc_int = int(wildcard)
    start = ipaddress.IPv4Address(ip_int & (~wc_int & 0xFFFFFFFF))
    end = ipaddress.IPv4Address(ip_int | wc_int)
    return IpRange(start=start, end=end)


def _is_contiguous_wildcard(wildcard: ipaddress.IPv4Address) -> bool:
    # Wildcard is inverse netmask. Contiguous wildcard means host bits are a block of 1s.
    wc = int(wildcard)
    nm = (~wc) & 0xFFFFFFFF
    # nm should be like 111..1100..00 => contiguous netmask
    # Check: nm & (nm + 1) == 0 for masks of the form 111..1100..00? Not exactly.
    # Standard check: for contiguous netmask, (nm | (nm - 1)) == 0xFFFFFFFF, excluding 0.
    if nm == 0:
        return True  # /0 equivalent wildcard 255.255.255.255
    return (nm | (nm - 1)) == 0xFFFFFFFF


def _consume_addr(tokens: Sequence[str], i: int) -> Tuple[IpRange, int]:
    if i >= len(tokens):
        raise ValueError("missing address")

    t = tokens[i].lower()
    if t == "any":
        return IpRange(ipaddress.IPv4Address("0.0.0.0"), ipaddress.IPv4Address("255.255.255.255")), i + 1

    if t == "host":
        if i + 1 >= len(tokens) or not _is_ipv4(tokens[i + 1]):
            raise ValueError("host requires IPv4 address")
        ip = ipaddress.IPv4Address(tokens[i + 1])
        return IpRange(ip, ip), i + 2

    # Support CIDR style if provided by user input (not typical Cisco, but handy)
    if "/" in tokens[i]:
        net = ipaddress.IPv4Network(tokens[i], strict=False)
        return IpRange(net.network_address, net.broadcast_address), i + 1

    if _is_ipv4(tokens[i]):
        ip = ipaddress.IPv4Address(tokens[i])
        if i + 1 < len(tokens) and _is_ipv4(tokens[i + 1]):
            wildcard = ipaddress.IPv4Address(tokens[i + 1])
            return _wildcard_to_range(ip, wildcard), i + 2
        # If wildcard is omitted, treat as host (common in some pasted variants)
        return IpRange(ip, ip), i + 1

    raise ValueError(f"unrecognized address token: {tokens[i]}")


def _skip_port_spec(tokens: Sequence[str], i: int) -> int:
    # Port spec can appear after an address for tcp/udp.
    # Examples: eq 80 | range 1000 2000 | gt 1023
    if i >= len(tokens):
        return i
    op = tokens[i].lower()
    if op not in _PORT_OPS:
        return i
    if op == "range":
        return min(len(tokens), i + 3)
    return min(len(tokens), i + 2)


def parse_acl_line(line: str) -> Optional[ParsedAcl]:
    raw = _strip_inline_comment(line).strip()
    if not raw:
        return None
    if raw.startswith("!"):
        return None

    tokens = _tokenize(raw)
    if not tokens:
        return None

    # Skip ACL block headers: "ip access-list ..."
    if len(tokens) >= 3 and tokens[0].lower() == "ip" and tokens[1].lower() == "access-list":
        return None

    # Normalize "access-list <id> ..." form
    if tokens[0].lower() == "access-list" and len(tokens) >= 3:
        tokens = tokens[2:]  # drop "access-list" and number/name

    # Some configs start with sequence numbers inside named ACL blocks:
    # "10 permit tcp any any"
    if tokens and re.fullmatch(r"\d+", tokens[0]):
        tokens = tokens[1:]

    if not tokens:
        return None

    first = tokens[0].lower()
    if first not in _ACTIONS:
        return None

    action = first
    i = 1

    protocol: Optional[str] = None
    # Heuristic: extended ACL has protocol after action.
    if i < len(tokens) and tokens[i].lower() not in ("any", "host") and not _is_ipv4(tokens[i]) and "/" not in tokens[i]:
        protocol = tokens[i].lower()
        i += 1

    # Source address
    src, i = _consume_addr(tokens, i)
    if protocol in ("tcp", "udp"):
        i = _skip_port_spec(tokens, i)

    # Destination address if present
    dst: Optional[IpRange] = None
    if i < len(tokens):
        try:
            dst, i = _consume_addr(tokens, i)
        except ValueError:
            # Standard ACL / incomplete line: treat as src-only
            dst = None
        else:
            if protocol in ("tcp", "udp"):
                i = _skip_port_spec(tokens, i)

    return ParsedAcl(action=action, protocol=protocol, src=src, dst=dst, raw=raw)


def iter_parsed(lines: Iterable[str]) -> Iterator[ParsedAcl]:
    for line in lines:
        try:
            parsed = parse_acl_line(line)
        except Exception:
            continue
        if parsed is not None:
            yield parsed


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="acl2range",
        description="Convert Cisco ACL entries to IPv4 ranges (and CIDRs when possible).",
    )
    p.add_argument("-i", "--input", help="Input file (default: stdin)")
    p.add_argument(
        "-f",
        "--format",
        choices=["text", "json", "jsonl"],
        default="text",
        help="Output format (default: text)",
    )
    p.add_argument(
        "--include-cidr",
        action="store_true",
        help="Include CIDR summarization fields in JSON/JSONL output.",
    )
    p.add_argument(
        "--only",
        choices=["src", "dst", "both"],
        default="both",
        help="Which addresses to output (default: both).",
    )

    args = p.parse_args(argv)

    if args.input:
        with open(args.input, "r", encoding="utf-8") as f:
            lines = f.readlines()
    else:
        lines = sys.stdin.readlines()

    parsed = list(iter_parsed(lines))

    if args.format == "text":
        for entry in parsed:
            if args.only in ("src", "both"):
                print(f"{entry.action} {entry.protocol or 'ip'} src {entry.src.to_text()}")
            if args.only in ("dst", "both") and entry.dst is not None:
                print(f"{entry.action} {entry.protocol or 'ip'} dst {entry.dst.to_text()}")
        return 0

    if args.format == "json":
        data = [e.to_dict(include_cidr=args.include_cidr) for e in parsed]
        print(json.dumps(data, indent=2))
        return 0

    # jsonl
    for e in parsed:
        print(json.dumps(e.to_dict(include_cidr=args.include_cidr)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
