# Vercel Python entrypoint - exposes FastAPI app as `app` for @vercel/python
# This allows Vercel to serve both Next.js frontend (frontend/) and Python API (/api/*) from same project
from app.main import create_app

app = create_app()
