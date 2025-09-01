import sqlite3
from flask import g

DATABASE = "app.db"


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    cursor = db.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT CHECK(role IN ('admin','user')) NOT NULL
    )
    """)

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

    db.commit()
    db.close()


def log_action(user_id, role, action):
    db = get_db()
    db.execute("INSERT INTO audit_log (user_id, role, action) VALUES (?,?,?)",
               (user_id, role, action))
    db.commit()
