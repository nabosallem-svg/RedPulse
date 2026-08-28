"""RedPulse - Tool Adapter Base.

Abstract base class for all recon tool adapters.
Each adapter wraps an external tool (subfinder, httpx, nmap) and provides:
- availability detection
- version detection
- timeout handling
- process failure handling
- structured output parsing
- logging
"""

import asyncio
import logging
import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("redpulse.tools")


@dataclass
class ToolResult:
    """Standardized result from a tool adapter."""

    success: bool
    raw_output: str = ""
    error: Optional[str] = None
    data: list = field(default_factory=list)  # parsed normalized records
    tool: str = ""
    version: Optional[str] = None
    duration_seconds: float = 0.0


class ToolAdapter(ABC):
    """Base class for all recon tool adapters."""

    def __init__(self, binary_path: str, timeout: int = 300):
        self.binary_path = binary_path
        self.timeout = timeout
        self._available: Optional[bool] = None
        self._version: Optional[str] = None

    @property
    def tool_name(self) -> str:
        return self.__class__.__name__

    async def is_available(self) -> bool:
        """Check if the tool binary exists and is executable."""
        if self._available is not None:
            return self._available
        self._available = shutil.which(self.binary_path) is not None
        if not self._available:
            logger.warning(f"Tool not found: {self.binary_path}")
        return self._available

    async def get_version(self) -> Optional[str]:
        """Get tool version. Override in subclass."""
        if self._version is not None:
            return self._version
        try:
            proc = await asyncio.create_subprocess_exec(
                self.binary_path, "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            self._version = stdout.decode(errors="replace").strip().split("\n")[0]
            return self._version
        except Exception as e:
            logger.debug(f"Could not get version for {self.tool_name}: {e}")
            return None

    async def run(self, args: list[str], stdin_data: Optional[str] = None) -> ToolResult:
        """Execute the tool with given arguments and timeout."""
        if not await self.is_available():
            return ToolResult(
                success=False,
                error=f"Tool not available: {self.binary_path}",
                tool=self.tool_name,
            )

        import time
        start = time.monotonic()
        cmd = [self.binary_path] + args
        logger.info(f"Running {self.tool_name}: {' '.join(cmd[:5])}...")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if stdin_data else None,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=stdin_data.encode() if stdin_data else None),
                timeout=self.timeout,
            )
            duration = time.monotonic() - start
            raw = stdout.decode(errors="replace")
            err_text = stderr.decode(errors="replace")

            if proc.returncode != 0 and not raw.strip():
                return ToolResult(
                    success=False,
                    raw_output=raw,
                    error=f"{self.tool_name} exited with code {proc.returncode}: {err_text[:500]}",
                    tool=self.tool_name,
                    duration_seconds=duration,
                )

            return ToolResult(
                success=True,
                raw_output=raw,
                tool=self.tool_name,
                version=await self.get_version(),
                duration_seconds=duration,
            )
        except asyncio.TimeoutError:
            logger.error(f"{self.tool_name} timed out after {self.timeout}s")
            try:
                proc.kill()
            except Exception:
                pass
            return ToolResult(
                success=False,
                error=f"{self.tool_name} timed out after {self.timeout}s",
                tool=self.tool_name,
                duration_seconds=self.timeout,
            )
        except FileNotFoundError:
            self._available = False
            return ToolResult(
                success=False,
                error=f"Binary not found: {self.binary_path}",
                tool=self.tool_name,
            )
        except Exception as e:
            logger.error(f"{self.tool_name} failed: {e}")
            return ToolResult(
                success=False,
                error=str(e),
                tool=self.tool_name,
            )

    @abstractmethod
    async def discover(self, target: str, extra_args: Optional[list[str]] = None) -> ToolResult:
        """Run the tool against a target and return normalized results."""
        ...
