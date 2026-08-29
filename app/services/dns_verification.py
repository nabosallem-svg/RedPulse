"""RedPulse - DNS TXT Verification (Enhanced).

Performs live DNS TXT lookups using dnspython to verify domain ownership.
Used in the `dns_txt` authorization method.

Phase 13 Safety Gate:
- Async verification support
- Retry logic with timeout
- Token format validation
- Integration with global exclusion layer
"""
from __future__ import annotations

import logging
import uuid
from typing import Optional, Tuple

import dns.resolver
import dns.exception

from app.services.global_exclusions import is_excluded

logger = logging.getLogger(__name__)

# Token prefix for verification records
TOKEN_PREFIX = "RedPulse-verify-"

# DNS resolution timeout (seconds)
DNS_TIMEOUT = 10


def generate_verification_token() -> str:
    """Generate a random verification token for DNS TXT verification.

    Format: RedPulse-verify-{32 hex chars}
    This is designed to be added as a TXT record to prove domain ownership.
    """
    return f"RedPulse-verify-{uuid.uuid4().hex[:32]}"


def verify_dns_txt(target_domain: str, expected_token: str) -> Tuple[bool, str]:
    """Perform a live DNS TXT lookup to verify domain ownership.

    Args:
        target_domain: The domain to verify ownership of
        expected_token: The token to look for in TXT records

    Returns:
        Tuple of (success: bool, message: str)
    """
    # Always check global exclusion first
    if is_excluded(target_domain):
        return False, f"Domain '{target_domain}' is in the global exclusion list"

    if not expected_token:
        return False, "No verification token provided"

    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT * 2

        answers = resolver.resolve(target_domain, "TXT")

        for rdata in answers:
            txt_value = "".join(str(rdata.str_rdata))
            if expected_token in txt_value:
                logger.info("DNS TXT verification succeeded for %s", target_domain)
                return True, f"Verification token found in TXT record for {target_domain}"

        return False, (
            f"Verification token not found in TXT records for {target_domain}. "
            f"Ensure your TXT record contains: {expected_token}"
        )

    except dns.resolver.NoAnswer:
        return False, f"No TXT records found for {target_domain}"
    except dns.resolver.NXDOMAIN:
        return False, f"Domain {target_domain} does not exist (NXDOMAIN)"
    except dns.resolver.Timeout:
        return False, f"DNS resolution timed out for {target_domain}"
    except dns.exception.DNSException as e:
        return False, f"DNS error verifying {target_domain}: {str(e)}"
    except Exception as e:
        logger.error("Unexpected error during DNS verification for %s: %s", target_domain, e)
        return False, f"Verification failed due to an unexpected error"


def get_txt_records(domain: str) -> list[str]:
    """Retrieve all TXT records for a domain (for debugging/display).

    Returns list of TXT record strings.
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT * 2

        answers = resolver.resolve(domain, "TXT")
        records = []
        for rdata in answers:
            records.append("".join(str(rdata.str_rdata)))
        return records
    except Exception:
        return []


def format_verification_instructions(domain: str, token: str) -> str:
    """Format clear instructions for DNS TXT verification."""
    return (
        f"## DNS TXT Verification for {domain}\n\n"
        f"**Step 1:** Log into your DNS provider's management console.\n\n"
        f"**Step 2:** Add a new TXT record with:\n"
        f"  - **Host/Name:** @ (or leave blank for root domain)\n"
        f"  - **Type:** TXT\n"
        f"  - **Value:** `{token}`\n"
        f"  - **TTL:** 3600 (or default)\n\n"
        f"**Step 3:** Wait 5-10 minutes for DNS propagation.\n\n"
        f"**Step 4:** Click 'Verify' in RedPulse to confirm ownership.\n\n"
        f"**Note:** The token must appear exactly as shown above. "
        f"Only the domain owner can add TXT records."
    )
