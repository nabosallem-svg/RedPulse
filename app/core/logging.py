"""RedPulse - Structured Logging Module.

Every major operation should have:
- timestamp
- project_id
- scan_id
- job_id
- event
- level
- error information

Never log: passwords, API keys, bot tokens, authentication tokens, sensitive secrets.
"""

import json
import logging
import sys
import uuid
from typing import Any, Dict, Optional
from datetime import datetime


# Custom JSON formatter for structured logs
class StructuredFormatter(logging.Formatter):
    """Formatter that outputs JSON-structured log lines."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add structured context if present
        if hasattr(record, "project_id"):
            log_entry["project_id"] = record.project_id
        if hasattr(record, "scan_id"):
            log_entry["scan_id"] = record.scan_id
        if hasattr(record, "job_id"):
            log_entry["job_id"] = record.job_id
        if hasattr(record, "event"):
            log_entry["event"] = record.event
        if hasattr(record, "error"):
            log_entry["error"] = record.error

        return json.dumps(log_entry)


# Create handler and logger
def setup_logging(
    level: str = "INFO",
    log_format: str = "json",
) -> logging.Logger:
    """Set up structured logging for the application.

    Args:
        level: Logging level (INFO, DEBUG, WARNING, ERROR, CRITICAL)
        log_format: Format style (json or text)

    Returns:
        Configured logger instance
    """
    # Remove default handlers
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Set level
    level_num = getattr(logging, level.upper(), logging.INFO)
    root_logger.setLevel(level_num)

    # Create handler
    handler = logging.StreamHandler(sys.stdout)

    if log_format.lower() == "json":
        handler.setFormatter(StructuredFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        ))

    root_logger.addHandler(handler)

    return root_logger


def structured_log(
    event: str,
    project_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    job_id: Optional[str] = None,
    event_type: str = "custom",
    **kwargs: Any,
) -> logging.Logger:
    """Log a structured event with context.

    Args:
        event: Event name/identifier
        project_id: Associated project identifier
        scan_id: Associated scan identifier
        job_id: Associated job identifier
        event_type: Type of event (e.g., "scope_decision", "scan_started")
        **kwargs: Additional context fields

    Returns:
        Logger with structured event
    """
    logger = logging.getLogger(f"RedPulse.{event_type}")

    # Build structured context, filtering sensitive data
    context: Dict[str, Any] = {
        "event": event,
        "event_type": event_type,
    }

    if project_id:
        context["project_id"] = project_id
    if scan_id:
        context["scan_id"] = scan_id
    if job_id:
        context["job_id"] = job_id

    # Add any additional context, but filter known-sensitive keys
    sensitive_keys = {"password", "token", "key", "secret", "credential"}
    for key, value in kwargs.items():
        # Check if key contains sensitive substrings (case-insensitive)
        lower_key = key.lower()
        if not any(s in lower_key for s in sensitive_keys):
            context[key] = value

    # Log as JSON
    logger.info(json.dumps(context))

    return logger