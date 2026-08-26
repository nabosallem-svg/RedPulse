from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional
import asyncio
import logging

from app.core.config import settings
from app.services.scope_validator import validate_target, ScopeViolation

logger = logging.getLogger(__name__)


class ReconEngine:
    """Reconnaissance engine for subnet collection and port scanning."""

    def __init__(self, db, current_user, engagement_id: str):
        self.db = db
        self.current_user = current_user
        self.engagement_id = engagement_id

    async def collect_subnets(self, target: str, max_workers: int = 10) -> List[Dict[str, Any]]:
        """Collect subnets/subdomains for a target using thread-pool parallelism.

        In a full implementation this would call external tools (subfinder, amass, etc.).
        For now, performs a basic DNS-based discovery using dnspython.
        """
        discovered: List[Dict[str, Any]] = []

        # Run the blocking DNS work in a thread pool so the event loop isn't blocked
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self._dns_discover, target): target}
            for future in as_completed(futures):
                try:
                    results = future.result()
                    discovered.extend(results)
                except Exception as exc:  # pylint: disable=broad-except
                    logger.error(f"DNS discovery error for {futures[future]}: {exc}")

        # Deduplicate by hostname
        seen = set()
        unique: List[Dict[str, Any]] = []
        for entry in discovered:
            host = entry.get("host") or ""
            if host not in seen:
                seen.add(host)
                unique.append(entry)

        return unique

    def _dns_discover(self, target: str) -> List[Dict[str, Any]]:
        """Blocking DNS discovery helper.

        Resolves A/AAAA records for the given target and returns
        a list of dicts with hostname and IP address.
        """
        import dns.resolver

        results: List[Dict[str, Any]] = []
        domains = [target] if "." in target else [f"{target}.local"]

        for domain in domains:
            try:
                resolver = dns.resolver.Resolver()
                resolver.lifetime = 5
                answers = resolver.resolve(domain, "A")
                for rdata in answers:
                    results.append({"host": domain, "ip": str(rdata), "type": "A"})
            except Exception as e:  # pylint: disable=broad-except
                logger.debug(f"DNS resolve failed for {domain}: {e}")

            try:
                resolver.lifetime = 5
                answers = resolver.resolve(domain, "AAAA")
                for rdata in answers:
                    results.append({"host": domain, "ip": str(rdata), "type": "AAAA"})
            except Exception as e:  # pylint: disable=broad-except
                logger.debug(f"DNS AAAA resolve failed for {domain}: {e}")

        return results

    async def scan_ports(self, host: str, ports: Optional[List[int]] = None) -> List[Dict[str, Any]]:
        """Scan ports on a given host using httpx-style probing.

        Returns a list of open ports with banners where available.
        """
        if ports is None:
            # Common ports if none specified
            ports = [21, 22, 23, 25, 53, 80, 110, 115, 123, 143, 443, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888, 9090]

        open_ports: List[Dict[str, Any]] = []

        async def _probe_port(port: int) -> Optional[Dict[str, Any]]:
            try:
                import httpx

                # Use http:// for common ports, https for 443/8443
                scheme = "https" if port in (443, 8443) else "http"
                url = f"{scheme}://{host}:{port}"

                async with httpx.AsyncClient(timeout=2.0) as client:
                    response = await client.get(url, follow_redirects=False)
                    banner = ""
                    if response.is_success and response.text:
                        banner = response.text[:100]
                    return {"port": port, "status": "open", "banner": banner}
            except Exception:  # pylint: disable=broad-except
                return None

        # Run probes concurrently
        tasks = [_probe_port(p) for p in ports]
        results = await asyncio.gather(*tasks)

        for result in results:
            if result is not None:
                open_ports.append(result)

        return open_ports

    async def notify_telegram(self, message: str) -> bool:
        """Send a message to a Telegram chat via the Bot API.

        Requires TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID to be set in config.
        Returns True if the message was sent successfully.
        """
        token = settings.TELEGRAM_BOT_TOKEN
        chat_id = settings.TELEGRAM_CHAT_ID

        if not token or not chat_id:
            logger.warning("Telegram bot token or chat ID not configured; skipping notification")
            return False

        import httpx

        url = f"https://api.telegram.org/bot{token}/sendMessage"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    url,
                    json={"chat_id": chat_id, "text": message},
                )
                resp.raise_for_status()
                logger.info(f"Telegram notification sent: {message[:80]}...")
                return True
        except Exception as e:  # pylint: disable=broad-except
            logger.error(f"Failed to send Telegram notification: {e}")
            return False

    async def run_recon_job(self, target: str, port_range: Optional[List[int]] = None) -> Dict[str, Any]:
        """Run a full recon cycle: validate target, collect subnets, scan ports, notify.

        This is the main entry point for a recon job. It:
        1. Validates the target through the scope validator
        2. Collects subnets/subdomains
        3. Scans common ports
        4. Sends a Telegram notification on completion
        """
        # 1. Scope validation
        try:
            await validate_target(
                engagement_id=self.engagement_id,
                host_or_url=target,
                db=self.db,
                current_user=self.current_user,
            )
        except ScopeViolation as e:
            logger.warning(f"Scope violation for target {target}: {e}")
            raise

        # 2. Collect subnets
        subnets = await self.collect_subnets(target)

        # 3. Scan ports on each discovered host
        scan_results: List[Dict[str, Any]] = []
        for entry in subnets:
            host = entry.get("ip") or entry.get("host")
            if not host:
                continue
            open_ports = await self.scan_ports(host, port_range)
            scan_results.append(
                {"host": host, "subnet_info": entry, "open_ports": open_ports}
            )

        # 4. Notify via Telegram
        summary = f"Recon complete for {target}: {len(subnets)} hosts, {sum(len(r['open_ports']) for r in scan_results)} total open ports found"
        await self.notify_telegram(summary)

        return {
            "target": target,
            "subnets": subnets,
            "scan_results": scan_results,
            "summary": summary,
        }