"""RedPulse - Subfinder Adapter.

Wraps subfinder for passive subdomain enumeration.
Output: newline-separated subdomains.
"""

import json
from typing import Optional

from app.services.tools.base import ToolAdapter, ToolResult


class SubfinderAdapter(ToolAdapter):
    """Subfinder adapter for passive subdomain discovery."""

    def __init__(self, binary_path: str = "subfinder", timeout: int = 300):
        super().__init__(binary_path=binary_path, timeout=timeout)

    async def discover(self, target: str, extra_args: Optional[list[str]] = None) -> ToolResult:
        """Run subfinder against a domain.

        Args:
            target: Domain name (e.g. example.com)
            extra_args: Additional subfinder arguments

        Returns:
            ToolResult with data containing list of subdomain strings
        """
        args = ["-d", target, "-silent"]
        if extra_args:
            args.extend(extra_args)

        result = await self.run(args)
        if not result.success:
            return result

        # Parse: each line is a subdomain
        subdomains = []
        for line in result.raw_output.strip().splitlines():
            line = line.strip()
            if line and not line.startswith("["):
                subdomains.append(line)

        result.data = subdomains
        return result
