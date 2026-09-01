import sqlite3
conn = sqlite3.connect('dev.db')
cur = conn.cursor()
cur.execute("UPDATE findings SET endpoint='testphp.vulnweb.com', evidence='Passive check for testphp.vulnweb.com' WHERE id='3739ed4a-15b6-447e-bc7f-cf1239d73d69'")
print('updated', cur.rowcount)
conn.commit()
cur.execute("SELECT endpoint, evidence FROM findings WHERE id='3739ed4a-15b6-447e-bc7f-cf1239d73d69'")
print(cur.fetchone())