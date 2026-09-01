import asyncpg
import asyncio

async def test_socket():
    try:
        conn = await asyncpg.connect(
            user='RedPulse',
            password='test_password',
            database='RedPulse'
        )
        print('Connected via Unix socket!')
        await conn.close()
    except Exception as e:
        print(f'Unix socket connect failed: {type(e).__name__}: {e}')

asyncio.run(test_socket())