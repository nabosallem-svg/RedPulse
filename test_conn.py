import asyncpg
import os

async def test():
    try:
        conn = await asyncpg.connect(
            user='RedPulse',
            password='test_password',
            database='RedPulse',
            host='localhost',
            port=5432
        )
        print('Connected via TCP!')
        await conn.close()
    except Exception as e:
        print(f'TCP connect failed: {type(e).__name__}: {e}')
    
    try:
        conn = await asyncpg.connect(
            user='RedPulse',
            password='test_password',
            database='RedPulse'
        )
        print('Connected via default host!')
        await conn.close()
    except Exception as e:
        print(f'Default connect failed: {type(e).__name__}: {e}')

import asyncio
asyncio.run(test())