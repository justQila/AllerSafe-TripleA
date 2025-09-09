import sqlite3
from flask import g

DATABASE = "allergy_app.db"

# ---------------- DB CONNECTION ---------------- #
def get_db():
    """Get a database connection (one per request)."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row  # rows behave like dictionaries
    return g.db

def close_db(e=None):
    """Close the database connection at the end of the request."""
    db = g.pop("db", None)
    if db is not None:
        db.close()

# ---------------- DB INIT ---------------- #
def init_db():
    """Initialize database tables if they don’t exist."""
    db = get_db()
    cursor = db.cursor()

    # Admins table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS admins (
        admin_key INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,    
        password TEXT NOT NULL
    )
    """)

    # Audit log table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        role TEXT,
        action TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    db.commit()

# ---------------- AUDIT LOGGER ---------------- #
def log_action(user_id, role, action):
    """Log an action performed by a user into the audit_log table."""

