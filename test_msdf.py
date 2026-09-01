import asyncio, os
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./dev.db"
from app.core.security import create_access_token
import httpx

async def test():
    token = create_access_token(subject="msdif@gmail.com")
    print("token for msdif", token[:20])
    async with httpx.AsyncClient() as client:
        headers={"Authorization": f"Bearer {token}"}
        # get projects
        r = await client.get("http://127.0.0.1:8000/api/v1/projects/", headers=headers)
        print("projects", r.status_code, r.text[:500])
        # try pentest for My-First-Hack Eng-1
        data={"engagement_id":"1514b619-418b-4bf5-8a92-9f76417dcd55","targets":["testphp.vulnweb.com"],"format":"json"}
        r2 = await client.post("http://127.0.0.1:8000/api/v1/projects/0710e468-fb4a-480b-8edc-f252c0d068f7/pentest/report", json=data, headers=headers)
        print("pentest", r2.status_code)
        print(r2.text[:1000])

import asyncio
asyncio.run(test())