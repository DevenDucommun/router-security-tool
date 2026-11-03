"""
Batch target parsing.

Accepts a free-form list of targets separated by commas, whitespace, or
newlines (e.g. the contents of an uploaded hosts file):

    192.168.1.1
    10.0.0.0/30            (CIDR: usable host addresses)
    192.168.1.10-20        (last-octet range)
    router.lan             (hostname)
    # comments and blank lines are ignored

Expansion is capped so a typo like /16 cannot launch 65k SSH sessions.
"""

import ipaddress
import re
from typing import Dict, List

MAX_BATCH_TARGETS = 256

_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)
_OCTET_RANGE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$")


class TargetParseError(ValueError):
    pass


def _expand_token(token: str) -> List[str]:
    if "/" in token:
        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError:
            raise TargetParseError(f"invalid CIDR: {token}")
        if network.version != 4:
            raise TargetParseError(f"only IPv4 CIDR ranges are supported: {token}")
        if network.num_addresses > MAX_BATCH_TARGETS + 2:
            raise TargetParseError(
                f"{token} expands to {network.num_addresses} addresses (max {MAX_BATCH_TARGETS})"
            )
        hosts = [str(h) for h in network.hosts()]
        return hosts or [str(network.network_address)]

    match = _OCTET_RANGE.match(token)
    if match:
        prefix, start, end = match.group(1), int(match.group(2)), int(match.group(3))
        if start > end or end > 255:
            raise TargetParseError(f"invalid range: {token}")
        addresses = [f"{prefix}{n}" for n in range(start, end + 1)]
        ipaddress.ip_address(addresses[0])  # validates the prefix octets
        return addresses

    try:
        return [str(ipaddress.ip_address(token))]
    except ValueError:
        pass

    if _HOSTNAME.match(token) and not token.replace(".", "").isdigit():
        return [token.rstrip(".").lower()]

    raise TargetParseError(f"not an IP address, CIDR range, or hostname: {token}")


def parse_targets(text: str) -> Dict[str, List[str]]:
    """
    Parse a batch target list.

    Returns {"targets": [...unique hosts in input order], "errors": [...]}.
    Raises TargetParseError if the expanded list exceeds MAX_BATCH_TARGETS.
    """
    targets: List[str] = []
    seen = set()
    errors: List[str] = []

    for raw_line in (text or "").splitlines():
        line = raw_line.split("#", 1)[0]
        for token in re.split(r"[,\s]+", line.strip()):
            if not token:
                continue
            try:
                expanded = _expand_token(token)
            except (TargetParseError, ValueError) as e:
                errors.append(str(e) if isinstance(e, TargetParseError) else f"invalid target: {token}")
                continue
            for host in expanded:
                if host not in seen:
                    seen.add(host)
                    targets.append(host)
                    if len(targets) > MAX_BATCH_TARGETS:
                        raise TargetParseError(
                            f"too many targets: more than {MAX_BATCH_TARGETS} after expansion"
                        )

    return {"targets": targets, "errors": errors}
