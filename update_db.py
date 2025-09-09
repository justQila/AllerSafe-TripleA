import sqlite3
from werkzeug.security import generate_password_hash

DB_NAME = "allergy_app.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    # Create admins table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS admins (
        admin_key INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        secret_code TEXT,
        role TEXT DEFAULT 'admin'
    )
    """)
   
    # Create audit_log table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        role TEXT,
        action TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    # Ensure secret_code column exists in admins
    try:
        cursor.execute("ALTER TABLE admins ADD COLUMN secret_code TEXT;")
        print("Added secret_code column to admins")
    except sqlite3.OperationalError:
        print("secret_code column already exists")

    # Insert 3 sample admins if not exists
    default_admins = [
        ("admin1", "adminpass1", "SECRET111"),
        ("admin2", "adminpass2", "SECRET222"),
        ("admin3", "adminpass3", "SECRET333"),
    ]

    for username, password, secret_code in default_admins:
        cursor.execute("SELECT * FROM admins WHERE username=?", (username,))
        if not cursor.fetchone():
            hashed_pw = generate_password_hash(password)
            cursor.execute("""
            INSERT INTO admins (username, password, secret_code, role)
            VALUES (?, ?, ?, ?)
            """, (username, hashed_pw, secret_code, "admin"))
            print(f"Inserted {username} (password={password}, secret_code={secret_code})")

    conn.commit()
    conn.close()
    print(f"Database '{DB_NAME}' is ready.")

if __name__ == "__main__":
    init_db()
