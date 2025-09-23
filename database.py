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
        
        # Enable foreign keys
        conn.execute('PRAGMA foreign_keys = ON')
        
        # Admins table
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
        
        # Password reset tokens table
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
        
        # Users table
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
        
        # Recipes table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS recipes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT UNIQUE NOT NULL,
                description TEXT,
                ingredients TEXT,
                instructions TEXT,
                category TEXT,
                status TEXT DEFAULT 'active',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                author_id INTEGER,
                FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE SET NULL
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
        
        # Recipe allergies junction
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

        # Add sample data (these functions protect against duplicates)
        add_sample_users(conn)
        add_sample_recipes(conn)
        add_sample_allergies(conn)
        add_sample_guidelines(conn)
        
        # Seed admins (separate function)
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

def add_sample_users(conn):
    """Add sample users if they do not exist"""
    sample_users = [
        ('john_doe', 'john@example.com', 'John Doe'),
        ('jane_smith', 'jane@example.com', 'Jane Smith'),
        ('bob_wilson', 'bob@example.com', 'Bob Wilson')
    ]
    for username, email, full_name in sample_users:
        existing_user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if not existing_user:
            conn.execute(
                'INSERT INTO users (username, email, full_name) VALUES (?, ?, ?)',
                (username, email, full_name)
            )

def add_sample_recipes(conn):
    """Add sample recipes if they do not exist"""
    john_user = conn.execute('SELECT * FROM users WHERE username = ?', ('john_doe',)).fetchone()
    jane_user = conn.execute('SELECT * FROM users WHERE username = ?', ('jane_smith',)).fetchone()
    bob_user = conn.execute('SELECT * FROM users WHERE username = ?', ('bob_wilson',)).fetchone()
    john_id = john_user['id'] if john_user else None
    jane_id = jane_user['id'] if jane_user else None
    bob_id = bob_user['id'] if bob_user else None
    
    sample_recipes = [
        ('Spaghetti Carbonara', 'Classic Italian pasta dish', 'Pasta, Eggs, Cheese, Pancetta', 
         '1. Cook pasta 2. Mix ingredients 3. Serve hot', 'Pasta', 'active', john_id),
        ('Chocolate Cake', 'Rich chocolate dessert', 'Flour, Sugar, Cocoa, Eggs, Milk', 
         '1. Mix dry ingredients 2. Add wet ingredients 3. Bake at 350°F for 30min', 'Dessert', 'active', jane_id),
        ('Pending Cookies', 'Awaiting approval', 'Flour, Sugar, Butter', 
         'Mix and bake', 'Dessert', 'pending', bob_id),
    ]
    for title, description, ingredients, instructions, category, status, author_id in sample_recipes:
        existing_recipe = conn.execute('SELECT * FROM recipes WHERE title = ?', (title,)).fetchone()
        if not existing_recipe:
            conn.execute(
                'INSERT INTO recipes (title, description, ingredients, instructions, category, status, author_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
                (title, description, ingredients, instructions, category, status, author_id)
            )

def add_sample_allergies(conn):
    """Add sample allergy data"""
    sample_allergies = [
        ('Peanuts', 'Food', 'high', 'Common severe allergy', 'Tree nuts'),
        ('Tree Nuts', 'Food', 'high', 'Includes almonds, walnuts, etc', 'Peanuts'),
        ('Shellfish', 'Food', 'high', 'Crustaceans and mollusks', 'Fish'),
        ('Fish', 'Food', 'medium', 'All finned fish', 'Shellfish'),
        ('Milk', 'Food', 'medium', 'Dairy products', None),
        ('Eggs', 'Food', 'medium', 'Chicken eggs most common', None),
        ('Soy', 'Food', 'low', 'Soybean products', 'Legumes'),
        ('Wheat', 'Food', 'medium', 'Contains gluten', 'Gluten grains'),
    ]
    
    for name, category, severity, description, cross_reactivity in sample_allergies:
        existing = conn.execute('SELECT * FROM allergies WHERE name = ?', (name,)).fetchone()
        if not existing:
            conn.execute(
                'INSERT INTO allergies (name, category, severity, description, cross_reactivity) VALUES (?, ?, ?, ?, ?)',
                (name, category, severity, description, cross_reactivity)
            )

def add_sample_guidelines(conn):
    """Add sample guidelines"""
    sample_guidelines = [
        ('Recipe Quality Standards', 'All recipes must include clear ingredients and step-by-step instructions', 'Recipe', 'warning'),
        ('Allergy Information', 'All recipes must clearly indicate potential allergens', 'Safety', 'critical'),
        ('Appropriate Content', 'No offensive or inappropriate content in recipes or comments', 'Community', 'warning'),
    ]
    
    for title, content, category, severity in sample_guidelines:
        existing = conn.execute('SELECT * FROM guidelines WHERE title = ?', (title,)).fetchone()
        if not existing:
            conn.execute(
                'INSERT INTO guidelines (title, content, category, severity) VALUES (?, ?, ?, ?)',
                (title, content, category, severity)
            )

# ---------------------- PASSWORD UTILS ----------------------

def hash_password(password):
    return generate_password_hash(password)

def verify_password(password, password_hash):
    return check_password_hash(password_hash, password)

# ---------------------- ADMIN FUNCTIONS ----------------------

def get_admin_by_username(username):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    admin = conn.execute('SELECT * FROM admins WHERE username = ?', (username,)).fetchone()
    conn.close()
    return dict(admin) if admin else None

def get_admin_by_email(email):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    admin = conn.execute("SELECT * FROM admins WHERE email = ?", (email,)).fetchone()
    conn.close()
    return dict(admin) if admin else None

def get_admin_by_id(admin_id):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    admin = conn.execute('SELECT * FROM admins WHERE id = ?', (admin_id,)).fetchone()
    conn.close()
    return dict(admin) if admin else None

def seed_admins():
    conn = None
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        # Check if admins already exist
        existing_count = cursor.execute("SELECT COUNT(*) FROM admins").fetchone()[0]
        if existing_count > 0:
            print("Admin accounts already exist, skipping seed.")
            return
        
        admins = [
            {"username": "admin1", "password": "password1", "email": "adore623@gmail.com"},
            {"username": "admin2", "password": "password2", "email": "admin2@example.com"},
            {"username": "admin3", "password": "password3", "email": "admin3@example.com"}
        ]
        
        for a in admins:
            hashed = generate_password_hash(a['password'])
            try:
                cursor.execute("INSERT INTO admins (username, password_hash, email) VALUES (?, ?, ?)",
                               (a['username'], hashed, a['email']))
            except sqlite3.IntegrityError:
                pass  # Admin already exists, skip
        
        conn.commit()
        print("Admin accounts created successfully!")
    except Exception as e:
        print(f"Error seeding admins: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            conn.close()

# ---------------------- PASSWORD RESET ----------------------

def set_reset_token(email, token):
    admin = get_admin_by_email(email)
    if not admin:
        return False
    expires_at = datetime.utcnow() + timedelta(hours=1)
    conn = sqlite3.connect(DB_NAME)
    conn.execute('INSERT INTO password_reset_tokens (admin_id, token, expires_at) VALUES (?, ?, ?)',
                 (admin['id'], token, expires_at.isoformat(sep=" ", timespec="seconds")))
    conn.commit()
    conn.close()
    return True

def is_token_valid(token):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    row = conn.execute('SELECT * FROM password_reset_tokens WHERE token = ?', (token,)).fetchone()
    conn.close()
    if row:
        try:
            expiry = datetime.fromisoformat(row['expires_at'])
        except Exception:
            expiry = datetime.strptime(row['expires_at'], "%Y-%m-%d %H:%M:%S")
        return expiry > datetime.utcnow()
    return False

def get_admin_by_token(token):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    row = conn.execute('''
        SELECT a.* 
        FROM admins a 
        JOIN password_reset_tokens t ON a.id = t.admin_id 
        WHERE t.token = ?
    ''', (token,)).fetchone()
    conn.close()
    return dict(row) if row else None

def update_password(admin_id, new_password):
    hashed = hash_password(new_password)
    conn = sqlite3.connect(DB_NAME)
    conn.execute('UPDATE admins SET password_hash = ? WHERE id = ?', (hashed, admin_id))
    conn.commit()
    conn.close()

# ---------------------- AUDIT LOG ----------------------

def add_audit_log(admin_id=None, user_id=None, action=None, target_type=None, target_id=None, details=None, ip_address=None):
    """Add audit log entry (supports admin or user actions)"""
    conn = sqlite3.connect(DB_NAME)
    try:
        conn.execute('''
            INSERT INTO audit_log (admin_id, user_id, action, target_type, target_id, details, ip_address)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (admin_id, user_id, action, target_type, target_id, details, ip_address))
        conn.commit()
    except Exception as e:
        print(f"Error adding audit log: {e}")
        conn.rollback()
    finally:
        conn.close()

def add_user_audit_log(user_id, action, target_type=None, target_id=None, details=None, ip_address=None):
    """Convenience wrapper to log user actions (maps to audit_log.user_id)"""
    add_audit_log(admin_id=None, user_id=user_id, action=action, target_type=target_type,
                  target_id=target_id, details=details, ip_address=ip_address)

def get_audit_logs(limit=None):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    query = 'SELECT * FROM audit_log ORDER BY created_at DESC'
    if limit:
        query += f' LIMIT {int(limit)}'
    rows = conn.execute(query).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def upgrade_audit_log_table():
    """Upgrade audit_log table to add optional columns (safe to re-run)"""
    conn = sqlite3.connect(DB_NAME)
    try:
        cursor = conn.execute("PRAGMA table_info(audit_log)")
        columns = [col[1] for col in cursor.fetchall()]
        changes_made = []
        # Example: add user_type column if you want (keeps backward compat)
        if 'user_type' not in columns:
            conn.execute('ALTER TABLE audit_log ADD COLUMN user_type TEXT DEFAULT "admin"')
            changes_made.append('user_type')
        if changes_made:
            conn.commit()
            print(f"Added columns to audit_log: {', '.join(changes_made)}")
        else:
            print("audit_log table is already up to date")
    except Exception as e:
        print(f"Error upgrading audit_log table: {e}")
        conn.rollback()
    finally:
        conn.close()

# ---------------------- USERS ----------------------

def get_all_users():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()
    return [dict(u) for u in users]

def get_user_by_id(user_id):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    return dict(user) if user else None

def update_user_status(user_id, status):
    conn = sqlite3.connect(DB_NAME)
    conn.execute('UPDATE users SET status = ? WHERE id = ?', (status, user_id))
    conn.commit()
    conn.close()

def delete_user(user_id):
    conn = sqlite3.connect(DB_NAME)
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

# ---------------------- RECIPES ----------------------

def get_all_recipes_with_authors():
    """Get all recipes with author information joined"""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    recipes = conn.execute('''
        SELECT r.*, u.username as author_username, u.full_name as author_name
        FROM recipes r
        LEFT JOIN users u ON r.author_id = u.id
        ORDER BY r.created_at DESC
    ''').fetchall()
    conn.close()
    return [dict(r) for r in recipes]

def get_recipes_by_allergy_with_authors(allergy_id):
    """Get recipes by allergy with author information"""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    rows = conn.execute('''
        SELECT r.*, u.username as author_username, u.full_name as author_name
        FROM recipes r
        LEFT JOIN users u ON r.author_id = u.id
        JOIN recipe_allergies ra ON r.id = ra.recipe_id
        WHERE ra.allergy_id = ?
    ''', (allergy_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_recipes_without_allergy_with_authors(allergy_id):
    """Get recipes without specific allergy with author information"""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    rows = conn.execute('''
        SELECT r.*, u.username as author_username, u.full_name as author_name
        FROM recipes r
        LEFT JOIN users u ON r.author_id = u.id
        WHERE r.id NOT IN (
            SELECT recipe_id FROM recipe_allergies WHERE allergy_id = ?
        )
    ''', (allergy_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_all_recipes():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    recipes = conn.execute('SELECT * FROM recipes').fetchall()
    conn.close()
    return [dict(r) for r in recipes]

def get_recipe_by_id(recipe_id):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    recipe = conn.execute('SELECT * FROM recipes WHERE id = ?', (recipe_id,)).fetchone()
    conn.close()
    return dict(recipe) if recipe else None

def update_recipe_status(recipe_id, status):
    conn = sqlite3.connect(DB_NAME)
    conn.execute('UPDATE recipes SET status = ? WHERE id = ?', (status, recipe_id))
    conn.commit()
    conn.close()

def delete_recipe(recipe_id):
    conn = sqlite3.connect(DB_NAME)
    conn.execute('DELETE FROM recipes WHERE id = ?', (recipe_id,))
    conn.commit()
    conn.close()

def approve_recipe(recipe_id):
    update_recipe_status(recipe_id, 'active')

def reject_recipe(recipe_id, reason=None):
    # reason optional; you may want to create a rejection log elsewhere
    update_recipe_status(recipe_id, 'rejected')

# ---------------------- RECIPE REPORTS ----------------------

def get_all_recipe_reports():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    reports = conn.execute('SELECT * FROM recipe_reports ORDER BY created_at DESC').fetchall()
    conn.close()
    return [dict(r) for r in reports]

def handle_recipe_report(report_id, admin_id, action_taken):
    conn = sqlite3.connect(DB_NAME)
    conn.execute('UPDATE recipe_reports SET status = "handled", handled_by = ?, action_taken = ? WHERE id = ?', 
                 (admin_id, action_taken, report_id))
    conn.commit()
    conn.close()

# ---------------------- ALLERGIES ----------------------

def get_all_allergies():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    allergies = conn.execute('SELECT * FROM allergies ORDER BY name COLLATE NOCASE').fetchall()
    conn.close()
    return [dict(a) for a in allergies]

def get_recipe_allergies(recipe_id):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    rows = conn.execute('''
        SELECT a.* FROM allergies a 
        JOIN recipe_allergies ra ON a.id = ra.allergy_id 
        WHERE ra.recipe_id = ?
    ''', (recipe_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_allergies_for_recipes(recipe_ids):
    if not recipe_ids:
        return {}
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    placeholders = ','.join(['?']*len(recipe_ids))
    query = f"SELECT * FROM recipe_allergies WHERE recipe_id IN ({placeholders})"
    rows = conn.execute(query, recipe_ids).fetchall()
    conn.close()
    result = {}
    for row in rows:
        result.setdefault(row['recipe_id'], []).append(row['allergy_id'])
    return result

def get_recipes_by_allergy(allergy_id):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    rows = conn.execute('''
        SELECT r.* FROM recipes r
        JOIN recipe_allergies ra ON r.id = ra.recipe_id
        WHERE ra.allergy_id = ?
    ''', (allergy_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_recipes_without_allergy(allergy_id):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    rows = conn.execute('''
        SELECT * FROM recipes WHERE id NOT IN (
            SELECT recipe_id FROM recipe_allergies WHERE allergy_id = ?
        )
    ''', (allergy_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def insert_allergy(name, category, severity, description=None, cross_reactivity=None):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO allergies (name, category, severity, description, cross_reactivity) 
        VALUES (?, ?, ?, ?, ?)
    ''', (name, category, severity, description, cross_reactivity))
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return new_id

def update_allergy(allergy_id, name, category, severity, description=None, cross_reactivity=None):
    conn = sqlite3.connect(DB_NAME)
    conn.execute('''
        UPDATE allergies 
        SET name=?, category=?, severity=?, description=?, cross_reactivity=? 
        WHERE id=?
    ''', (name, category, severity, description, cross_reactivity, allergy_id))
    conn.commit()
    conn.close()

def delete_allergy(allergy_id):
    conn = sqlite3.connect(DB_NAME)
    conn.execute('DELETE FROM allergies WHERE id = ?', (allergy_id,))
    conn.commit()
    conn.close()

# ---------------------- GUIDELINES ----------------------

def get_all_guidelines():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    rows = conn.execute('SELECT * FROM guidelines ORDER BY created_at DESC').fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_guideline_by_id(guideline_id):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    row = conn.execute('SELECT * FROM guidelines WHERE id = ?', (guideline_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

def add_guideline(title, content, category, severity='info'):
    conn = sqlite3.connect(DB_NAME)
    conn.execute('INSERT INTO guidelines (title, content, category, severity) VALUES (?, ?, ?, ?)',
                 (title, content, category, severity))
    conn.commit()
    conn.close()

def update_guideline(guideline_id, title, content, category, severity):
    conn = sqlite3.connect(DB_NAME)
    conn.execute('UPDATE guidelines SET title=?, content=?, category=?, severity=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
                 (title, content, category, severity, guideline_id))
    conn.commit()
    conn.close()

def insert_guideline(title, content, category, severity='info'):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO guidelines (title, content, category, severity) VALUES (?, ?, ?, ?)',
                   (title, content, category, severity))
    conn.commit()
    new_id = cursor.lastrowid
    conn.close()
    return new_id

def delete_guideline(guideline_id):
    conn = sqlite3.connect(DB_NAME)
    conn.execute('DELETE FROM guidelines WHERE id = ?', (guideline_id,))
    conn.commit()
    conn.close()

# ---------------------- USER WARNINGS ----------------------

def add_user_warning(user_id, admin_id, guideline_id=None, custom_reason=None, severity='warning'):
    conn = sqlite3.connect(DB_NAME)
    conn.execute('''
        INSERT INTO user_warnings (user_id, admin_id, guideline_id, custom_reason, severity)
        VALUES (?, ?, ?, ?, ?)
    ''', (user_id, admin_id, guideline_id, custom_reason, severity))
    conn.commit()
    conn.close()

def get_all_warnings():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    rows = conn.execute('SELECT * FROM user_warnings').fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_user_warnings(user_id):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    rows = conn.execute('SELECT * FROM user_warnings WHERE user_id = ?', (user_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ---------------------- PENDING RECIPES ----------------------

def get_pending_recipes():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    rows = conn.execute('SELECT * FROM recipes WHERE status = "pending" ORDER BY created_at DESC').fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ---------------------- SENDGRID EMAIL ----------------------

def send_reset_email(to_email, reset_url):
    if not SENDGRID_API_KEY:
        print("Warning: SENDGRID_API_KEY not set - skipping actual email send.")
        print(f"Would send reset link to {to_email}: {reset_url}")
        return
        
    html_content = f"""
    <html>
    <body>
        <p>Hello,</p>
        <p>We received a request to reset your password for your AllerSafe Recipe(s) account.</p>
        <p><a href="{reset_url}" style="padding:10px 20px;background-color:#af4c0f;color:white;text-decoration:none;border-radius:5px;">Reset Password</a></p>
        <p>If you did not request a password reset, please ignore this email.</p>
    </body>
    </html>
    """
    
    message = Mail(
        from_email=FROM_EMAIL,
        to_emails=to_email,
        subject="Password Reset - AllerSafe Recipe(s)",
        html_content=html_content
    )
    
    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)
        print(f"Email sent! Status code: {response.status_code}")
    except Exception as e:
        print(f"Error sending email: {e}")

# ---------------------- MAIN EXECUTION ----------------------

if __name__ == "__main__":
    print("Initializing database with fixes...")
    init_db()
    print("Database initialization complete!")
    print("\nYou can now log in with:")
    print("Username: admin1, Password: password1")
    print("Username: admin2, Password: password2") 
    print("Username: admin3, Password: password3\n")

    # Demo: add a user log
    try:
        add_user_audit_log(user_id=1, action="demo_login", details="Demo: user logged in via script")
        print("Demo audit log entry inserted.")
        logs = get_audit_logs(limit=5)
        print("Recent audit logs (latest first):")
        for l in logs:
            print(l)
    except Exception as e:
        print(f"Demo logging failed: {e}")
