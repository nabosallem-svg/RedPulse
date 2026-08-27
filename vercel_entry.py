"""RedPulse - Vercel FastAPI entrypoint.

Vercel's FastAPI preset requires a module-level `app` object. The backend
uses a `create_app()` factory (see app/main.py), so we instantiate it here
and expose it as `app`. Kept at the repo root (outside Vercel's reserved
`api/` directory) to avoid serverless-function conflicts.
"""
import traceback

try:
    from app.main import create_app

    app = create_app()
except Exception:
    _traceback = traceback.format_exc()

    async def app(scope, receive, send):
        if scope.get("type") == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
            return

        body = _traceback.encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": 500,
                "headers": [(b"content-type", b"text/plain; charset=utf-8")],
            }
        )
        await send({"type": "http.response.body", "body": body})
