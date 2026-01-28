# Cisco ACL to IP Range

Small CLI that extracts IPv4 ranges from Cisco IOS ACL entries.

## Requirements

- Python 3.10+ (works with standard library only)

## Usage

From a file:

```bash
python acl2range.py -i acl.txt
```

From stdin:

```bash
type acl.txt | python acl2range.py
```

JSON output:

```bash
python acl2range.py -i acl.txt --format json
```

## Examples

Input:

```text
access-list 10 permit 192.168.1.0 0.0.0.255
access-list 101 permit tcp 10.0.0.0 0.0.0.255 any eq 443
ip access-list extended WEB
  10 permit tcp any host 1.2.3.4 eq 22
```

Output (text):

```text
permit ip src 192.168.1.0-192.168.1.255
permit tcp src 10.0.0.0-10.0.0.255
permit tcp dst 0.0.0.0-255.255.255.255
permit tcp src 0.0.0.0-255.255.255.255
permit tcp dst 1.2.3.4-1.2.3.4
```

Notes:
- `any` becomes `0.0.0.0-255.255.255.255`
- `host X` becomes `X-X`
- wildcard masks are converted to an inclusive range using: `start = ip & ~wildcard`, `end = ip | wildcard`
