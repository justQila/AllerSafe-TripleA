import sqlite3
from werkzeug.security import generate_password_hash

def init_db():
    conn = sqlite3.connect("allergy_app.db")
    cursor = conn.cursor()

    # Admin table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS admins (
        admin_key INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        recovery_code TEXT NOT NULL
    );
    ''')

    # Insert 3 admins if not already there
    admins = [
        ("admin1", generate_password_hash("password1"), "apple123"),
        ("admin2", generate_password_hash("password2"), "banana456"),
        ("admin3", generate_password_hash("password3"), "cherry789"),
    ]
    for admin in admins:
        try:
            cursor.execute("INSERT INTO admins (username, password, recovery_code) VALUES (?, ?, ?)", admin)
        except sqlite3.IntegrityError:
            # Already exists
            pass

    conn.commit()
    conn.close()
