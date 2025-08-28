import sqlite3
# connect ke database (kalau file user.db tak ada, auto create)
conn = sqlite3.connect("user.db")
cursor = conn.cursor()

#table users
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
)
""")

print("Database and table created successfully!")

conn.commit()
conn.close()