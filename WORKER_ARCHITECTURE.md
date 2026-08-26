# ReconPilot - Worker Architecture

## 1. Design Philosophy

### 1.1. asyncio-First Approach
- All I/O-bound operations use asyncio (subprocess execution, database queries, network calls)
- No OS threads for worker tasks - use asyncio.Task instead
- Single-event-loop model with concurrent task scheduling

### 1.2. Prepared for Redis Worker Processes
- Initial MVP: asyncio workers running within FastAPI lifespan
- Phase 8+: Redis/RQ integration for dedicated worker processes
- No state sharing between workers - use database as coordination point

### 1.3. Worker Communication Pattern
- Workers read/write to database for state coordination
- No in-process shared state between different FastAPI worker instances
- Database serves as the single source of truth for scan state

## 2. Worker Types

### 2.1. Recon Worker
**Purpose**: Executes reconnaissance tools (subfinder, httpx) against project targets.

**Lifecycle**:
1. Poll `scan_jobs` table for jobs with status="pending"
2. Update job status to "running"
3. Execute recon tools against authorized targets
4. Update job with `recon_results`
5. Update scan status based on results
6. Mark job as "completed" or "failed"

**Tool Execution Pattern**:
```python
async def run_recon_tool(targets: List[str], tool_name: str) -> Dict[str, Any]:
    """Run a recon tool against a list of targets."""
    config = get_settings()
    
    if tool_name == "subfinder":
        binary = config.SUBFINDER_BIN
        # subfinder -list -d <target> -json
        cmd = [binary, "-list"] + targets  # simplified
    elif tool_name == "httpx":
        binary = config.HTTPX_BIN
        # httpx -json -status-code -title <targets>
        cmd = [binary, "-json", "-status-code", "-title"] + targets
    elif tool_name == "nuclei":
        binary = config.NUCLEI_BIN
        # nuclei -t <template> -l <targets>
        cmd = [binary, "-t", "cves", "-l"] + targets  # simplified
    
    # Execute with proper safety measures
    return await execute_scanner_subprocess(cmd, timeout=config.RECON_TIMEOUT_SECONDS)
```

**Concurrency Control**:
- Semaphore-limited concurrent processes (default: 50 for recon, 100 for subfinder)
- Per-target timeout handling
- Stderr capture and structured logging
- Automatic process cleanup on completion/cancellation

### 2.2. Monitoring Worker
**Purpose**: Runs continuous monitoring cycles at configured intervals.

**Lifecycle**:
1. Check `monitoring_configs` for active configurations
2. For each config, discover new assets using recon engine
3. Compare with historical state in `assets` table
4. Detect changes (new, removed, modified assets)
5. Process new/changed assets through scope engine
6. Generate findings for new security issues
7. Deduplicate findings using fingerprint matching
8. Send notifications for important changes
9. Update monitoring config last_run timestamp

**Schedule Support**:
- Every 6 hours
- Daily
- Weekly
- Configurable via `MonitoringConfig.frequency`

### 2.3. Notification Worker
**Purpose**: Sends notifications through configured providers.

**Lifecycle**:
1. Poll `notifications` table for unread notifications
2. For each notification, send through active provider
3. Mark notification as sent/read after delivery
4. Handle delivery failures gracefully

**Initial Provider**: Telegram Bot API
**Future Providers**: Discord, Slack, Email, Webhooks

**Notification Categories**:
- NEW_ASSET
- IMPORTANT_CHANGE
- HIGH_FINDING
- CRITICAL_FINDING
- SCAN_FAILED
- SCAN_COMPLETED
- REGRESSION

### 2.4. Report Worker
**Purpose**: Generates professional report drafts.

**Lifecycle**:
1. Check for reports with status="draft"
2. Query findings and assets for the project
3. Generate HTML and JSON report formats
4. Apply report quality checker
5. Mark report as "reviewed" when user confirms

## 3. Subprocess Execution Pattern

### 3.1. Safe Scanner Execution
All external tool execution follows this pattern:

```python
import asyncio
from typing import Tuple

async def execute_scanner_subprocess(
    cmd: List[str],
    timeout: int = 300,
) -> Tuple[str, str, int]:
    """Execute a scanner subprocess safely.
    
    Returns: (stdout, stderr, return_code)
    """
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,  # Never shell=True - arguments as array
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise ScannerTimeoutError(
                f"Scanner subprocess timed out after {timeout}s"
            )
        
        if process.returncode != 0:
            # Log non-fatal errors but don't necessarily fail
            # Some tools return non-zero for non-vulnerable results
            pass
        
        stdout_text = stdout.decode(errors="replace")
        stderr_text = stderr.decode(errors="replace")
        
        return stdout_text, stderr_text, process.returncode or 0
        
    except Exception:
        # Ensure process cleanup
        if process and process.returncode is None:
            process.kill()
            await process.wait()
        raise
```

### 3.2. Key Safety Measures
- **Never use shell=True** - arguments passed as arrays only
- **Command injection prevention** - all user input validated/sanitized before use
- **Timeout enforcement** - hard timeout on all subprocess execution
- **Stderr capture** - always capture stderr for logging/analysis
- **Exit code handling** - deliberate choice: non-zero doesn't always fail (some tools use it for "no findings")
- **Process cleanup** - guaranteed cleanup on completion, cancellation, or timeout
- **No hardcoded binary paths** - configurable via environment variables (SUBFINDER_BIN, HTTPX_BIN, NUCLEI_BIN)
- **Custom path allowance** - users can set binary paths to custom locations

### 3.3. Concurrency Limits
```python
# Global concurrency semaphores
recon_semaphore = asyncio.Semaphore(50)   # max concurrent recon operations
scanner_semaphore = asyncio.Semaphore(20)  # max concurrent scanner operations

async def limited_execute(cmd, timeout):
    async with recon_semaphore:
        return await execute_scanner_subprocess(cmd, timeout)
```

### 3.4. Retry Policy
- Transient errors only (exit code 1 with stderr suggesting transient issue)
- Maximum 2 retries with exponential backoff
- No retry on timeout, SIGKILL, or explicit user cancellation
- Each retry respects the full timeout limit

## 4. Worker Lifecycle Management

### 4.1. FastAPI Lifespan Integration
Workers are created during FastAPI application startup and cleaned up on shutdown:

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    app.state.recon_worker = ReconWorker(app.db, app.config)
    await app.state.recon_worker.start()
    
    app.state.monitoring_worker = MonitoringWorker(app.db, app.config)
    await app.state.monitoring_worker.start()
    
    yield  # Application runs
    
    # Shutdown
    await app.state.recon_worker.stop()
    await app.state.monitoring_worker.stop()
    # Cleanup any running processes
```

### 4.2. Graceful Shutdown
- SIGTERM/SIGINT handlers
- Running jobs can be cancelled via asyncio.Task.cancel()
- In-progress subprocesses are killed
- Database state is consistent (no half-completed jobs)
- Notification worker finishes current batch before exiting

### 4.3. Error Handling per Worker Type
- **Recon Worker**: Individual target failures don't stop the whole job. Failed targets are logged and remaining targets continue.
- **Monitoring Worker**: Cycle failures are logged; next cycle runs at next scheduled interval. Partial results are preserved.
- **Notification Worker**: Delivery failures don't mark notification as sent. Retry logic with exponential backoff.
- **Report Worker**: Generation failures leave report as draft. User can regenerate.

## 5. Database-Coordinated Worker Pattern

### 5.1. State Machine per Scan Job
```
pending → running → completed/failed
     ↑               |
     └── cancelled --+
```

### 5.2. Job Polling Pattern
 Workers use "claim-and-run" pattern:
1. SELECT scan_job WHERE status='pending' LIMIT 1 FOR UPDATE SKIP LOCKED
2. UPDATE status = 'running', set started_at = NOW()
3. Run the job
4. UPDATE status = 'completed'/'failed', set completed_at = NOW(), populate results

This allows multiple worker instances to coordinate without race conditions.

### 5.3. Heartbeat/Lease Mechanism
- Running jobs have a `heartbeat_at` timestamp
- Stale jobs (no heartbeat within timeout) can be reclaimed
- Prevents deadlocks from crashed workers

## 6. Monitoring and Observability

### 6.1. Structured Logging
Every worker operation uses structured logging with context:
- worker_type, job_id, project_id, scan_id
- event, status, duration, error_info

### 6.2. Metrics (Preparation for Phase 13)
- Jobs processed per hour
- Success/failure rates
- Average execution time
- Concurrency usage
- Error rates by tool/type

These would use a metrics library (prometheus_client) in Phase 13+.