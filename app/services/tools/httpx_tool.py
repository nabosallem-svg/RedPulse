"""RedPulse - httpx Adapter.

Wraps httpx (projectdiscovery) for HTTP probing and technology detection.
Input: list of hosts (stdin).
Output: JSON lines with status codes, titles, technologies, etc.
"""

import json
from typing import Optional

from app.services.tools.base import ToolAdapter, ToolResult


class HttpxAdapter(ToolAdapter):
    """httpx adapter for HTTP probing and tech fingerprinting."""

    def __init__(self, binary_path: str = "httpx", timeout: int = 300):
        super().__init__(binary_path=binary_path, timeout=timeout)

    async def discover(self, target: str, extra_args: Optional[list[str]] = None) -> ToolResult:
        """Run httpx against a list of hosts.

        Args:
            target: Newline-separated list of hostnames or IPs
            extra_args: Additional httpx arguments

        Returns:
            ToolResult with data containing list of dicts:
            [{host, ip, port, protocol, status_code, title, technologies, webserver}]
        """
        args = [
            "-silent",
            "-json",
            "-status-code",
            "-title",
            "-tech-detect",
            "-web-server",
            "-ip",
            "-follow-redirects",
        ]
        if extra_args:
            args.extend(extra_args)

        result = await self.run(args, stdin_data=target)
        if not result.success:
            return result

        # Parse JSON lines output
        parsed = []
        for line in result.raw_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                parsed.append({
                    "host": obj.get("host", ""),
                    "ip": obj.get("ip", ""),
                    "port": obj.get("port", 443 if obj.get("scheme") == "https" else 80),
                    "protocol": obj.get("scheme", "https"),
                    "status_code": obj.get("status_code"),
                    "title": obj.get("title", ""),
                    "technologies": obj.get("tech", []),
                    "webserver": obj.get("webserver", ""),
                })
            except json.JSONDecodeError:
                continue

        result.data = parsed
        return result
