"""REDPULSE - Legal Documents API.

Serves ToS / Privacy / AUP markdown that is already stored under docs/legal/.
No auth required (public), cached in memory after first read.
"""
from __future__ import annotations

import pathlib
from functools import lru_cache

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse

router = APIRouter(tags=["legal"])

_DOC_ROOT = pathlib.Path(__file__).resolve().parents[3] / "docs" / "legal"
_ALLOWED = {
    "terms": "TERMS_OF_SERVICE.md",
    "privacy": "PRIVACY_POLICY.md",
    "acceptable-use": "ACCEPTABLE_USE.md",
    "aup": "ACCEPTABLE_USE.md",
}


@lru_cache(maxsize=8)
def _read_doc(filename: str) -> str:
    path = _DOC_ROOT / filename
    if not path.exists():
        raise FileNotFoundError(filename)
    return path.read_text(encoding="utf-8")


@router.get("/legal/{doc_key}")
async def get_legal_doc(doc_key: str):
    """Get a legal document by key: terms | privacy | acceptable-use | aup.

    Returns markdown with text/markdown content-type. Public (no auth).
    Use X-API-Version header from main middleware for cache busting.
    """
    key = doc_key.lower().strip()
    filename = _ALLOWED.get(key)
    if not filename:
        raise HTTPException(status_code=404, detail=f"Unknown legal doc '{doc_key}'. Allowed: {', '.join(sorted(_ALLOWED))}")
    try:
        content = _read_doc(filename)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Legal document not found on server")
    return PlainTextResponse(content, media_type="text/markdown; charset=utf-8")


@router.get("/legal")
async def list_legal_docs():
    """List available legal documents (public)."""
    return {
        "docs": [
            {"key": "terms", "title": "Terms of Service", "path": "/api/v1/legal/terms", "file": "TERMS_OF_SERVICE.md"},
            {"key": "privacy", "title": "Privacy Policy", "path": "/api/v1/legal/privacy", "file": "PRIVACY_POLICY.md"},
            {"key": "acceptable-use", "title": "Acceptable Use Policy", "path": "/api/v1/legal/acceptable-use", "file": "ACCEPTABLE_USE.md"},
        ]
    }
