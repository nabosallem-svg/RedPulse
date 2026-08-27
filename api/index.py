"""RedPulse - Vercel serverless entrypoint.

Vercel's @vercel/python ASGI runtime expects a module-level `app` object.
The backend uses a `create_app()` factory (see app/main.py), so we
instantiate it here and expose it as `app` for Vercel to discover and serve
as a Serverless Function.
"""
from app.main import create_app

app = create_app()
