"""RedPulse - DNS TXT Verification.

Performs live DNS TXT lookups using dnspython to verify target domain ownership.
Used in the `dns_txt` authorization method.

The flow:
1. Authorization request generates a random verification token
2. Token is stored on the Authorization row with verified=False
3. User adds TXT record to their DNS:  RedPulse-verify=<token>
4. This function performs a live DNS TXT lookup to check if the record exists
5. Match â†’ verified=True, Engagement becomes authorized
6. No match â†’ allow retry (nothing changed)
"""

import uuid

import dns.resolver

from app.services.global_exclusions import is_excluded


def generate_verification_token() -> str:
    """Generate a random verification token for DNS TXT verification."""
    return f"RedPulse-verify-{uuid.uuid4().hex[:32]}"


def verify_dns_txt(target_domain: str, expected_token: str) -> bool:
    """
    Perform a live DNS TXT lookup to verify domain ownership.

    Checks if a TXT record containing the expected_token exists for the
    target domain. The DNS TXT record should be formatted as:
    RedPulse-verify=<token>

    This function also checks global exclusions first - if the domain is
    in the exclusion list, verification fails immediately.

    Args:
        target_domain: The domain to verify (e.g., "example.com")
        expected_token: The expected verification token

    Returns:
        True if verification succeeds, False otherwise.
    """
    # Global exclusions always take priority
    if is_excluded(target_domain):
        return False

    # Remove wildcard prefix for DNS lookup if present
    lookup_domain = target_domain
    # dns.resolver can handle the domain lookup

    try:
        # Query for TXT records
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(lookup_domain, "TXT")

        for rdata in answers:
            # dns.resolver returns TXT records as objects with str_rep attribute
            # Join all string parts as the full TXT record value
            txt_value = "".join(str(rdata.str_rdata))
            # TXT records may have the value in quotes or without
            # Look for the RedPulse-verify token within the TXT value
            if expected_token in txt_value:
                return True

        return False

    except dns.resolver.NoAnswer:
        # No TXT record found - verification fails
        return False
    except dns.resolver.NXDOMAIN:
        # Domain does not exist - verification fails
        return False
    except Exception:
        # Any other DNS error - allow retry (don't block permanently)
        return False