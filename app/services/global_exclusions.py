"""RedPulse - Global Exclusion Layer.

Hard-coded denylist of protected TLDs and IP ranges checked on every target
regardless of authorization method or scope rules. Exclusion always wins over
include rules - a target in the denylist is always rejected.
"""

# TLDs that are always blocked for scanning
PROTECTED_TLDS = {".gov", ".mil", ".edu"}

# Best-effort government/military IP ranges (populated from public sources if available)
# These are flagged as "best effort" - not exhaustive, but provides additional protection
GOVERNMENT_IP_RANGES = []  # To be populated from public IANA/RIR allocations if desired


def is_excluded(target_domain: str) -> bool:
    """
    Check if a target domain is in the global exclusion list.

    This check happens BEFORE any scope-rule matching, and it cannot be
    overridden by an `include` rule - exclusion always wins.

    Args:
        target_domain: The domain to check (e.g., "example.com")

    Returns:
        True if the target is excluded, False otherwise.
    """
    # Check TLD-based exclusions
    for protected_tld in PROTECTED_TLDS:
        if target_domain.lower().endswith(protected_tld):
            return True

    # TODO: Add IP range checking when we have a reliable source
    # for government/military IP allocations

    return False