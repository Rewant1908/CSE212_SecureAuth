import os
import psycopg2
import psycopg2.extras

conn = psycopg2.connect(
    host="aws-1-ap-northeast-1.pooler.supabase.com",
    port=6543,
    dbname="postgres",
    user="postgres.wmbbgawkfweejuwxesxk",
    password="AnshSecureSafecse212",
    cursor_factory=psycopg2.extras.RealDictCursor
)
cur = conn.cursor()
cur.execute("SELECT id, username, email, role FROM users")
rows = cur.fetchall()
for r in rows:
    print(r)
