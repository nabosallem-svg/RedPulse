import sqlite3
from datetime import datetime, timezone
conn = sqlite3.connect('dev.db')
cur = conn.cursor()
now = datetime.now(timezone.utc).isoformat()
cur.execute("UPDATE authorizations SET verified=1, verified_at=? WHERE engagement_id='1514b619-418b-4bf5-8a92-9f76417dcd55'", (now,))
print('updated', cur.rowcount)
conn.commit()
cur.execute("SELECT target_domain, verified FROM authorizations WHERE engagement_id='1514b619-418b-4bf5-8a92-9f76417dcd55'")
print(cur.fetchall())