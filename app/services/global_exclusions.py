"""RedPulse - Global Exclusion Layer (Enhanced).

Hard-coded denylist of protected TLDs, IP ranges, and patterns that are
ALWAYS blocked regardless of authorization method or scope rules.
This layer runs FIRST in every validation path and CANNOT be overridden.

Phase 13 Safety Gate: Extended coverage for government, military, education,
international government orgs, and known-safe localhost/internal ranges.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Optional


# ==================== TLD Denylist ====================
# These TLDs are ALWAYS blocked - no exceptions, no overrides
PROTECTED_TLDS = frozenset({
    # US Government/Military
    ".gov", ".mil", ".edu",
    # International Government
    ".gov.uk", ".gov.au", ".gov.ca", ".gov.in", ".gov.br",
    ".gob", ".gouv", ".go.jp", ".go.kr", ".go.id", ".go.th",
    # Military (NATO)
    ".nato",
    # Additional protected categories
    # Note: .onion (Tor) is NOT blocked - valid pentest targets
})

# Regex patterns for domain matching (compiled once)
_PROTECTED_TLD_PATTERNS = [
    re.compile(r"\.gov\.[a-z]{2}$", re.IGNORECASE),
    re.compile(r"\.mil\.[a-z]{2}$", re.IGNORECASE),
    re.compile(r"\.gob\.[a-z]{2}$", re.IGNORECASE),
    re.compile(r"\.gouv\.[a-z]{2}$", re.IGNORECASE),
    re.compile(r"\.go\.[a-z]{2}$", re.IGNORECASE),
]


# ==================== IP Range Denylist ====================
# RFC 1918 private ranges, loopback, link-local, documentation
_BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("10.0.0.0/8"),         # RFC 1918
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local
    ipaddress.ip_network("198.18.0.0/15"),      # Benchmarking
    ipaddress.ip_network("192.0.0.0/24"),       # IETF protocol
    ipaddress.ip_network("192.0.2.0/24"),       # Documentation (TEST-NET-1)
    ipaddress.ip_network("198.51.100.0/24"),    # Documentation (TEST-NET-2)
    ipaddress.ip_network("203.0.113.0/24"),     # Documentation (TEST-NET-3)
    ipaddress.ip_network("::1/128"),            # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),           # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),          # IPv6 link-local
]


# ==================== Protected Domain Patterns ====================
# Regex for sensitive domains that should never be scanned
_SENSITIVE_DOMAIN_PATTERNS = [
    re.compile(r"^dns\..*"),           # DNS infrastructure
    re.compile(r"^ns\d*\..*"),         # Nameservers
    re.compile(r"^smtp\..*"),          # Mail servers (often protected)
    re.compile(r"^mail\..*"),
]


def is_excluded(target_domain: str) -> bool:
    """Check if a target domain is in the global exclusion list.

    Checks in order (short-circuit):
    1. TLD denylist (.gov, .mil, .edu, international variants)
    2. IP address denylist (private, loopback, documentation ranges)
    3. Protected domain patterns

    Returns True if the target should ALWAYS be blocked.
    """
    if not target_domain:
        return False

    target = target_domain.lower().strip()

    # Remove scheme if URL was passed
    if "://" in target:
        target = target.split("://", 1)[1].split("/")[0].split(":")[0]

    # 1. TLD denylist
    for tld in PROTECTED_TLDS:
        if target.endswith(tld):
            return True

    # Regex patterns for international government TLDs
    for pattern in _PROTECTED_TLD_PATTERNS:
        if pattern.search(target):
            return True

    # 2. IP address denylist
    if _is_blocked_ip(target):
        return True

    # 3. Protected domain patterns
    for pattern in _SENSITIVE_DOMAIN_PATTERNS:
        if pattern.match(target):
            return True

    return False


def _is_blocked_ip(host: str) -> bool:
    """Check if a host is an IP address in a blocked range."""
    try:
        ip = ipaddress.ip_address(host)
        for network in _BLOCKED_IP_NETWORKS:
            if ip in network:
                return True
    except ValueError:
        # Not an IP address, that's fine
        pass
    return False


def get_exclusion_reason(target_domain: str) -> Optional[str]:
    """Get the human-readable reason why a target is excluded.

    Returns None if the target is NOT excluded.
    """
    if not target_domain:
        return None

    target = target_domain.lower().strip()
    if "://" in target:
        target = target.split("://", 1)[1].split("/")[0].split(":")[0]

    # TLD check
    for tld in PROTECTED_TLDS:
        if target.endswith(tld):
            return f"Protected TLD '{tld}' - government/military/education domains are always blocked"

    for pattern in _PROTECTED_TLD_PATTERNS:
        if pattern.search(target):
            return "International government domain pattern detected"

    # IP check
    try:
        ip = ipaddress.ip_address(target)
        for network in _BLOCKED_IP_NETWORKS:
            if ip in network:
                return f"IP address {target} is in blocked range {network}"
    except ValueError:
        pass

    # Pattern check
    for pattern in _SENSITIVE_DOMAIN_PATTERNS:
        if pattern.match(target):
            return "Protected infrastructure domain pattern detected"

    return None
