import sqlite3
from datetime import datetime, timezone
conn = sqlite3.connect('dev.db')
cur = conn.cursor()
now = datetime.now(timezone.utc).isoformat()
cur.execute("UPDATE authorizations SET verified=1, verified_at=? WHERE engagement_id='a7acfa35-fc69-4c5f-8f02-debc46373b19'", (now,))
print('updated', cur.rowcount)
conn.commit()
cur.execute("SELECT target_domain, verified, verified_at FROM authorizations WHERE engagement_id='a7acfa35-fc69-4c5f-8f02-debc46373b19'")
print(cur.fetchall())