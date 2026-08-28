"""RedPulse - Nmap Adapter.

Wraps nmap for port scanning and service detection.
Output: XML parsed for services and versions.
"""

import asyncio
import json
import tempfile
import os
from typing import Optional

from app.services.tools.base import ToolAdapter, ToolResult


class NmapAdapter(ToolAdapter):
    """Nmap adapter for port scanning and service detection."""

    def __init__(self, binary_path: str = "nmap", timeout: int = 300):
        super().__init__(binary_path=binary_path, timeout=timeout)

    async def discover(self, target: str, extra_args: Optional[list[str]] = None) -> ToolResult:
        """Run nmap against a target.

        Args:
            target: Hostname or IP to scan
            extra_args: Additional nmap arguments (e.g. ["-p", "80,443"])

        Returns:
            ToolResult with data containing list of service dicts:
            [{host, ip, port, protocol, service, version, state}]
        """
        # Default: top 100 ports, service detection, no DNS resolution
        args = ["-sV", "-T4", "--top-ports", "100", "-oX", "-", "--open", "-n"]
        if extra_args:
            args.extend(extra_args)
        args.append(target)

        result = await self.run(args)
        if not result.success:
            return result

        # Parse XML output
        parsed = self._parse_xml(result.raw_output)
        result.data = parsed
        return result

    def _parse_xml(self, xml_output: str) -> list[dict]:
        """Parse nmap XML output into structured records."""
        import xml.etree.ElementTree as ET

        services = []
        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError:
            return services

        for host_el in root.findall(".//host"):
            addr_el = host_el.find("address")
            ip = addr_el.get("addr", "") if addr_el is not None else ""
            hostname_el = host_el.find(".//hostname")
            hostname = hostname_el.get("name", "") if hostname_el is not None else ip

            for port_el in host_el.findall(".//port"):
                portid = port_el.get("portid", "")
                protocol = port_el.get("protocol", "tcp")
                state_el = port_el.find("state")
                state = state_el.get("state", "") if state_el is not None else ""

                service_el = port_el.find("service")
                service_name = ""
                product = ""
                version = ""
                if service_el is not None:
                    service_name = service_el.get("name", "")
                    product = service_el.get("product", "")
                    version = service_el.get("version", "")

                if state == "open":
                    svc_str = f"{product} {version}".strip() if product else service_name
                    services.append({
                        "host": hostname,
                        "ip": ip,
                        "port": int(portid) if portid.isdigit() else 0,
                        "protocol": protocol,
                        "service": service_name,
                        "version": version,
                        "product": product,
                        "state": state,
                    })

        return services
