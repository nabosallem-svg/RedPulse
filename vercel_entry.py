"""RedPulse - Vercel FastAPI entrypoint.

Vercel's FastAPI preset requires a module-level `app` object. The backend
uses a `create_app()` factory (see app/main.py), so we instantiate it here
and expose it as `app`. Kept at the repo root (outside Vercel's reserved
`api/` directory) to avoid serverless-function conflicts.
"""
from app.main import create_app

app = create_app()
