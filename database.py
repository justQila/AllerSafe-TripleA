import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets
import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

DB_NAME = 'admin_panel.db'

SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
FROM_EMAIL = os.getenv("FROM_EMAIL", "adore623@gmail.com")

# ---------------------- DATABASE INITIALIZATION ----------------------

def init_db():
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys = ON')

        # Admins
        conn.execute('''
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                reset_token TEXT,
                token_expiry DATETIME
            )
        ''')

        # Password reset tokens
        conn.execute('''
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER,
                token TEXT NOT NULL,
                expires_at DATETIME NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE CASCADE
            )
        ''')

        # Users
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                full_name TEXT NOT NULL,
                status TEXT DEFAULT 'active',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Audit log
        conn.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER,
                user_id INTEGER,
                action TEXT NOT NULL,
                target_type TEXT,
                target_id INTEGER,
                details TEXT,
                ip_address TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (admin_id) REFERENCES admins(id)
            )
        ''')

        # Allergies
        conn.execute('''
            CREATE TABLE IF NOT EXISTS allergies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                category TEXT NOT NULL,
                severity TEXT DEFAULT 'medium',
                description TEXT,
                cross_reactivity TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Recipe allergies (junction)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS recipe_allergies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recipe_id INTEGER,
                allergy_id INTEGER,
                FOREIGN KEY (recipe_id) REFERENCES recipes(id) ON DELETE CASCADE,
                FOREIGN KEY (allergy_id) REFERENCES allergies(id) ON DELETE CASCADE,
                UNIQUE(recipe_id, allergy_id)
            )
        ''')

        # Recipe reports
        conn.execute('''
            CREATE TABLE IF NOT EXISTS recipe_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recipe_id INTEGER,
                reporter_id INTEGER,
                reason TEXT NOT NULL,
                description TEXT,
                status TEXT DEFAULT 'pending',
                handled_by INTEGER,
                action_taken TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (recipe_id) REFERENCES recipes(id) ON DELETE CASCADE,
                FOREIGN KEY (reporter_id) REFERENCES users(id) ON DELETE SET NULL,
                FOREIGN KEY (handled_by) REFERENCES admins(id) ON DELETE SET NULL
            )
        ''')

        # Guidelines
        conn.execute('''
            CREATE TABLE IF NOT EXISTS guidelines (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT DEFAULT 'info',
                is_active INTEGER DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # User warnings
        conn.execute('''
            CREATE TABLE IF NOT EXISTS user_warnings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                admin_id INTEGER,
                guideline_id INTEGER,
                custom_reason TEXT,
                severity TEXT DEFAULT 'warning',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE SET NULL,
                FOREIGN KEY (guideline_id) REFERENCES guidelines(id) ON DELETE SET NULL
            )
        ''')

        add_sample_allergies(conn)
        add_sample_guidelines(conn)
        seed_admins()

        conn.commit()
        print("Database initialized successfully!")

    except Exception as e:
        if conn:
            conn.rollback()
        print(f"Error initializing database: {e}")
        raise e
    finally:
        if conn:
            conn.close()

# ---------------------- SAMPLE DATA ----------------------

def add_sample_allergies(conn):
    samples = [
        ('Peanuts', 'Food', 'high', 'Common severe allergy', 'Tree nuts'),
        ('Tree Nuts', 'Food', 'high', 'Includes almonds, walnuts, etc', 'Peanuts'),
        ('Shellfish', 'Food', 'high', 'Crustaceans and mollusks', 'Fish'),
        ('Fish', 'Food', 'medium', 'All finned fish', 'Shellfish'),
        ('Milk', 'Food', 'medium', 'Dairy products', None),
        ('Eggs', 'Food', 'medium', 'Chicken eggs most common', None),
        ('Soy', 'Food', 'low', 'Soybean products', 'Legumes'),
        ('Wheat', 'Food', 'medium', 'Contains gluten', 'Gluten grains'),
    ]
    for name, cat, sev, desc, cross in samples:
        if not conn.execute('SELECT 1 FROM allergies WHERE name=?', (name,)).fetchone():
            conn.execute('INSERT INTO allergies (name, category, severity, description, cross_reactivity) VALUES (?, ?, ?, ?, ?)',
                         (name, cat, sev, desc, cross))

def add_sample_guidelines(conn):
    samples = [
        ('Recipe Quality Standards', 'All recipes must include clear ingredients and step-by-step instructions', 'Recipe', 'warning'),
        ('Allergy Information', 'All recipes must clearly indicate potential allergens', 'Safety', 'critical'),
        ('Appropriate Content', 'No offensive or inappropriate content in recipes or comments', 'Community', 'warning'),
    ]
    for t, c, cat, sev in samples:
        if not conn.execute('SELECT 1 FROM guidelines WHERE title=?', (t,)).fetchone():
            conn.execute('INSERT INTO guidelines (title, content, category, severity) VALUES (?, ?, ?, ?)',
                         (t, c, cat, sev))

# ---------------------- PASSWORD UTILS ----------------------

def hash_password(password):
    return generate_password_hash(password)

def verify_password(password, password_hash):
    return check_password_hash(password_hash, password)

# ---------------------- ADMIN FUNCTIONS ----------------------

def seed_admins():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    try:
        if cursor.execute("SELECT COUNT(*) FROM admins").fetchone()[0] == 0:
            admins = [
                ("admin1", "password1", "adore623@gmail.com"),
                ("admin2", "password2", "admin2@example.com"),
                ("admin3", "password3", "admin3@example.com"),
            ]
            for username, pwd, email in admins:
                try:
                    cursor.execute("INSERT INTO admins (username, password_hash, email) VALUES (?, ?, ?)",
                                   (username, generate_password_hash(pwd), email))
                except sqlite3.IntegrityError:
                    pass
            conn.commit()
    finally:
        conn.close()

# ---------------------- USERS ----------------------

def get_all_users():
    conn = sqlite3.connect("user.db")
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_user_by_id(user_id):
    conn = sqlite3.connect("user.db")
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

def get_user_name_by_id(user_id):
    u = get_user_by_id(user_id)
    return u["username"] if u else "Unknown"

# ---------------------- RECIPES ----------------------

def get_all_recipes():
    conn = sqlite3.connect("recipe.db")
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM recipes ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_recipe_by_id(recipe_id):
    conn = sqlite3.connect("recipe.db")
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM recipes WHERE id=?", (recipe_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

def update_recipe_status(recipe_id, status):
    conn = sqlite3.connect("recipe.db")
    conn.execute("UPDATE recipes SET status=? WHERE id=?", (status, recipe_id))
    conn.commit()
    conn.close()

def delete_recipe(recipe_id):
    conn = sqlite3.connect("recipe.db")
    conn.execute("DELETE FROM recipes WHERE id=?", (recipe_id,))
    conn.commit()
    conn.close()

def get_pending_recipes():
    conn = sqlite3.connect("recipe.db")  # ✅ FIXED
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM recipes WHERE status='pending' ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ---------------------- GUIDELINES ----------------------

def toggle_guideline_status(guideline_id, is_active):
    conn = sqlite3.connect(DB_NAME)
    try:
        conn.execute("UPDATE guidelines SET is_active=?, updated_at=datetime('now') WHERE id=?",
                     (is_active, guideline_id))
        conn.commit()
    finally:
        conn.close()

# ---------------------- MAIN ----------------------

if __name__ == "__main__":
    print("Initializing DB...")
    init_db()
    print("✅ Done")
