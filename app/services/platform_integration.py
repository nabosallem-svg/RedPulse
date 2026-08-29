"""RedPulse - Bug Bounty Platform API Integration.

Pulls official scope from HackerOne and Bugcrowd programs to ensure
scan targets match the program's authorized scope exactly.

Phase 13 Safety Gate: Real API integration for scope pulling.
"""
from __future__ import annotations

import logging
from typing import Optional, Tuple, Dict, Any

import httpx

logger = logging.getLogger(__name__)

# API endpoints
HACKERONE_API_BASE = "https://api.hackerone.com/v1"
BUGCROWD_API_BASE = "https://api.bugcrowd.com/v2"


class BountyPlatformError(Exception):
    """Raised when a bounty platform API call fails."""
    pass


class HackerOneClient:
    """HackerOne API client for scope pulling and program verification."""

    def __init__(self, api_token: str, username: str):
        self.api_token = api_token
        self.username = username
        self.base_url = HACKERONE_API_BASE

    def _get_headers(self) -> Dict[str, str]:
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _auth(self) -> Tuple[str, str]:
        return (self.username, self.api_token)

    async def get_program_scope(self, program_handle: str) -> Tuple[bool, str, list[dict]]:
        """Fetch the official in-scope and out-of-scope assets for a program.

        Returns:
            Tuple of (success, message, scope_rules)
            scope_rules: [{"pattern": "*.example.com", "rule_type": "include"}, ...]
        """
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                # Get program details
                resp = await client.get(
                    f"{self.base_url}/hackers/programs/{program_handle}",
                    auth=self._auth(),
                    headers=self._get_headers(),
                )

                if resp.status_code == 401:
                    return False, "Invalid HackerOne API credentials", []
                if resp.status_code == 404:
                    return False, f"Program '{program_handle}' not found on HackerOne", []
                if resp.status_code != 200:
                    return False, f"HackerOne API error: {resp.status_code}", []

                data = resp.json()
                program_data = data.get("data", {})
                attributes = program_data.get("attributes", {})

                # Get structured scope from the program
                structured_scope = attributes.get("structured_scopes", [])

                if not structured_scope:
                    return False, f"No scope defined for program '{program_handle}'", []

                scope_rules = []
                for scope_entry in structured_scope:
                    asset_type = scope_entry.get("asset_type", "")
                    asset_identifier = scope_entry.get("asset_identifier", "")
                    eligibility = scope_entry.get("eligible_for_submission", True)

                    if not asset_identifier:
                        continue

                    # Map HackerOne asset types to our patterns
                    rule_type = "include" if eligibility else "exclude"

                    # Handle wildcards - HackerOne uses *.example.com format
                    pattern = asset_identifier.strip()

                    scope_rules.append({
                        "pattern": pattern,
                        "rule_type": rule_type,
                        "asset_type": asset_type,
                        "eligible": eligibility,
                    })

                return True, f"Loaded {len(scope_rules)} scope rules from HackerOne", scope_rules

        except httpx.TimeoutException:
            return False, "HackerOne API request timed out", []
        except httpx.RequestError as e:
            return False, f"HackerOne API connection error: {str(e)}", []
        except Exception as e:
            logger.error("HackerOne API unexpected error: %s", e)
            return False, f"Unexpected error fetching HackerOne scope: {str(e)}", []

    async def verify_program_exists(self, program_handle: str) -> Tuple[bool, str]:
        """Verify that a HackerOne program exists and accepts submissions."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"{self.base_url}/hackers/programs/{program_handle}",
                    auth=self._auth(),
                    headers=self._get_headers(),
                )
                if resp.status_code == 200:
                    return True, f"Program '{program_handle}' verified on HackerOne"
                elif resp.status_code == 404:
                    return False, f"Program '{program_handle}' not found"
                else:
                    return False, f"HackerOne API returned {resp.status_code}"
        except Exception as e:
            return False, f"Failed to verify program: {str(e)}"


class BugcrowdClient:
    """Bugcrowd API client for scope pulling and program verification."""

    def __init__(self, api_token: str):
        self.api_token = api_token
        self.base_url = BUGCROWD_API_BASE

    def _get_headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Token {self.api_token}",
            "Accept": "application/vnd.bugcrowd+json",
            "Content-Type": "application/json",
            "Bugcrowd-Version": "2024-01-01",
        }

    async def get_program_scope(self, program_code: str) -> Tuple[bool, str, list[dict]]:
        """Fetch the official scope for a Bugcrowd program.

        Returns:
            Tuple of (success, message, scope_rules)
        """
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                # Search for the program
                resp = await client.get(
                    f"{self.base_url}/programs",
                    headers=self._get_headers(),
                    params={"code": program_code},
                )

                if resp.status_code == 401:
                    return False, "Invalid Bugcrowd API credentials", []
                if resp.status_code != 200:
                    return False, f"Bugcrowd API error: {resp.status_code}", []

                programs = resp.json().get("data", [])
                if not programs:
                    return False, f"Program '{program_code}' not found on Bugcrowd", []

                program = programs[0]
                program_id = program.get("id")

                # Get program scope
                scope_resp = await client.get(
                    f"{self.base_url}/programs/{program_id}/target_groups",
                    headers=self._get_headers(),
                )

                if scope_resp.status_code != 200:
                    return False, f"Failed to fetch program scope", []

                target_groups = scope_resp.json().get("data", [])
                scope_rules = []

                for group in target_groups:
                    targets_resp = await client.get(
                        f"{self.base_url}/target_groups/{group['id']}/targets",
                        headers=self._get_headers(),
                    )
                    if targets_resp.status_code == 200:
                        targets = targets_resp.json().get("data", [])
                        for target in targets:
                            target_name = target.get("attributes", {}).get("name", "")
                            if target_name:
                                rule_type = "include" if group.get("attributes", {}).get("in_scope", True) else "exclude"
                                scope_rules.append({
                                    "pattern": target_name,
                                    "rule_type": rule_type,
                                    "asset_type": target.get("attributes", {}).get("category", ""),
                                })

                return True, f"Loaded {len(scope_rules)} scope rules from Bugcrowd", scope_rules

        except httpx.TimeoutException:
            return False, "Bugcrowd API request timed out", []
        except httpx.RequestError as e:
            return False, f"Bugcrowd API connection error: {str(e)}", []
        except Exception as e:
            logger.error("Bugcrowd API unexpected error: %s", e)
            return False, f"Unexpected error fetching Bugcrowd scope: {str(e)}", []


async def pull_scope_from_platform(
    platform: str,
    program_handle: str,
    api_token: str,
    username: Optional[str] = None,
) -> Tuple[bool, str, list[dict]]:
    """Unified interface to pull scope from any supported bounty platform.

    Args:
        platform: "hackerone" or "bugcrowd"
        program_handle: The program identifier on the platform
        api_token: API authentication token
        username: Required for HackerOne (basic auth)

    Returns:
        Tuple of (success, message, scope_rules)
    """
    if platform == "hackerone":
        if not username:
            return False, "HackerOne requires a username for API authentication", []
        client = HackerOneClient(api_token=api_token, username=username)
        return await client.get_program_scope(program_handle)

    elif platform == "bugcrowd":
        client = BugcrowdClient(api_token=api_token)
        return await client.get_program_scope(program_handle)

    else:
        return False, f"Unsupported platform: {platform}. Supported: hackerone, bugcrowd", []
