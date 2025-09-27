import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets
import os
from dotenv import load_dotenv
load_dotenv()

# Gmail SMTP instead of SendGrid
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

DB_NAME = 'admin_panel.db'

# Gmail configuration
GMAIL_EMAIL = os.getenv("GMAIL_EMAIL")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")

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
        add_sample_guidelines(conn)
        
        # Seed admins (separate function)
        seed_admins()
        
        # Add is_active column to guidelines if it doesn't exist
        cursor = conn.execute("PRAGMA table_info(guidelines)")
        columns = [col[1] for col in cursor.fetchall()]
        if "is_active" not in columns:
            conn.execute("ALTER TABLE guidelines ADD COLUMN is_active INTEGER DEFAULT 1")
            print("Added 'is_active' column to guidelines")
        
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
            hashed = hash_password(a['password'])
            try:
                cursor.execute("INSERT INTO admins (username, password_hash, email) VALUES (?, ?, ?)",
                               (a['username'], hashed, a['email']))
                print(f"Created admin: {a['username']}")
            except sqlite3.IntegrityError as e:
                print(f"Admin {a['username']} already exists: {e}")
        
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
    conn = sqlite3.connect("user.db")
    conn.row_factory = sqlite3.Row
    users = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    return users

def get_user_by_id(user_id):
    conn = sqlite3.connect("user.db")
    conn.row_factory = sqlite3.Row
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    return dict(user) if user else None

def update_user_status(user_id, status):
    conn = sqlite3.connect("user.db")
    conn.execute('UPDATE users SET status = ? WHERE id = ?', (status, user_id))
    conn.commit()
    conn.close()

def delete_user(user_id):
    conn = sqlite3.connect("user.db")
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

# ---------------------- RECIPES ----------------------

def get_recipe_by_id(recipe_id):
    conn = sqlite3.connect("recipe.db")
    conn.row_factory = sqlite3.Row
    recipe = conn.execute('SELECT * FROM recipe WHERE id = ?', (recipe_id,)).fetchone()  
    conn.close()
    return dict(recipe) if recipe else None

def get_all_recipes():
    """Fixed version - looks in 'recipe' table"""
    conn = sqlite3.connect("recipe.db")
    conn.row_factory = sqlite3.Row
    recipes = conn.execute('SELECT * FROM recipe').fetchall()
    conn.close()
    return [dict(r) for r in recipes]

def get_all_recipes_with_authors():
    """Fixed version - looks in 'recipe' table with users from user.db"""
    conn = sqlite3.connect("recipe.db")
    conn.row_factory = sqlite3.Row
    recipes = conn.execute('''
        SELECT r.*, u.username as author_username, u.full_name as author_name
        FROM recipe r
        LEFT JOIN users u ON r.author_id = u.id
        ORDER BY r.created_at DESC
    ''').fetchall()
    conn.close()
    return [dict(r) for r in recipes]

def update_recipe_status(recipe_id, status):
    """Fixed version - updates 'recipe' table"""
    conn = sqlite3.connect("recipe.db")
    conn.execute('UPDATE recipe SET status = ? WHERE id = ?', (status, recipe_id))
    conn.commit()
    conn.close()

def delete_recipe(recipe_id):
    """Fixed version - deletes from 'recipe' table"""
    conn = sqlite3.connect("recipe.db")
    conn.execute('DELETE FROM recipe WHERE id = ?', (recipe_id,))
    conn.commit()
    conn.close()

def get_recipes_by_allergy_with_authors(allergy_id):
    """Fixed version - uses 'recipe' table"""
    conn = sqlite3.connect("recipe.db")
    conn.row_factory = sqlite3.Row
    rows = conn.execute('''
        SELECT r.*, u.username as author_username, u.full_name as author_name
        FROM recipe r
        LEFT JOIN users u ON r.author_id = u.id
        JOIN recipe_allergies ra ON r.id = ra.recipe_id
        WHERE ra.allergy_id = ?
    ''', (allergy_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_recipes_without_allergy_with_authors(allergy_id):
    """Fixed version - uses 'recipe' table"""
    conn = sqlite3.connect("recipe.db")
    conn.row_factory = sqlite3.Row
    rows = conn.execute('''
        SELECT r.*, u.username as author_username, u.full_name as author_name
        FROM recipe r
        LEFT JOIN users u ON r.author_id = u.id
        WHERE r.id NOT IN (
            SELECT recipe_id FROM recipe_allergies WHERE allergy_id = ?
        )
    ''', (allergy_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

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

def toggle_guideline_status(guideline_id, is_active):
    """Toggle guideline active/inactive status"""
    conn = sqlite3.connect(DB_NAME)
    try:
        conn.execute("""
            UPDATE guidelines 
            SET is_active = ?, updated_at = datetime('now', 'localtime')
            WHERE id = ?
        """, (is_active, guideline_id))
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()

# ---------------------- USER WARNINGS ----------------------

def add_user_warning(user_id, admin_id, guideline_id=None, custom_reason=None, severity='warning'):
    """Add a warning for a user with proper error handling"""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO user_warnings (user_id, admin_id, guideline_id, custom_reason, severity)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, admin_id, guideline_id, custom_reason, severity))
        
        conn.commit()
        warning_id = cursor.lastrowid
        print(f"Warning added successfully (ID: {warning_id})")
        return warning_id
        
    except sqlite3.Error as e:
        print(f"Error adding user warning: {e}")
        return None
    finally:
        if conn:
            conn.close()

def get_user_warnings(user_id):
    """Get all warnings for a specific user with detailed information"""
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        
        cursor = conn.execute('''
            SELECT uw.*, a.username as admin_username, g.title as guideline_title
            FROM user_warnings uw
            LEFT JOIN admins a ON uw.admin_id = a.id
            LEFT JOIN guidelines g ON uw.guideline_id = g.id
            WHERE uw.user_id = ?
            ORDER BY uw.created_at DESC
        ''', (user_id,))
        
        warnings = cursor.fetchall()
        return [dict(warning) for warning in warnings]
        
    except sqlite3.Error as e:
        print(f"Error fetching user warnings: {e}")
        return []
    finally:
        if conn:
            conn.close()

def get_all_warnings():
    """Get all warnings with user and admin details"""
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        
        cursor = conn.execute('''
            SELECT uw.*, 
                   u.username as user_username,
                   a.username as admin_username, 
                   g.title as guideline_title
            FROM user_warnings uw
            LEFT JOIN users u ON uw.user_id = u.id
            LEFT JOIN admins a ON uw.admin_id = a.id
            LEFT JOIN guidelines g ON uw.guideline_id = g.id
            ORDER BY uw.created_at DESC
        ''')
        
        warnings = cursor.fetchall()
        return [dict(warning) for warning in warnings]
        
    except sqlite3.Error as e:
        print(f"Error fetching all warnings: {e}")
        return []
    finally:
        if conn:
            conn.close()

def get_warning_count(user_id):
    """Get the number of warnings for a user"""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM user_warnings WHERE user_id = ?', (user_id,))
        count = cursor.fetchone()[0]
        return count
        
    except sqlite3.Error as e:
        print(f"Error counting warnings: {e}")
        return 0
    finally:
        if conn:
            conn.close()

def delete_warning(warning_id):
    """Delete a specific warning"""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM user_warnings WHERE id = ?', (warning_id,))
        conn.commit()
        
        if cursor.rowcount > 0:
            print(f"Warning {warning_id} deleted successfully")
            return True
        else:
            print(f"Warning {warning_id} not found")
            return False
            
    except sqlite3.Error as e:
        print(f"Error deleting warning {warning_id}: {e}")
        return False
    finally:
        if conn:
            conn.close()

# ---------------------- EMAIL FUNCTIONS (Gmail SMTP) ----------------------

def send_reset_email(to_email, reset_url):
    """Send password reset email using Gmail SMTP"""
    print(f"Attempting to send email to: {to_email}")
    print(f"Gmail email: {GMAIL_EMAIL}")
    print(f"App password present: {bool(GMAIL_APP_PASSWORD)}")
    
    if not GMAIL_APP_PASSWORD or not GMAIL_EMAIL:
        print("Gmail configuration missing!")
        print("Set GMAIL_EMAIL and GMAIL_APP_PASSWORD in your .env file")
        print(f"Would send reset link to {to_email}: {reset_url}")
        return False
    
    # Create message
    msg = MIMEMultipart('alternative')
    msg['Subject'] = "Password Reset - AllerSafe Recipe(s)"
    msg['From'] = GMAIL_EMAIL
    msg['To'] = to_email
    
    # HTML content
    html_content = f"""
    <html>
    <body>
        <h2>Password Reset Request</h2>
        <p>Hello,</p>
        <p>We received a request to reset your password for your AllerSafe Recipe(s) account.</p>
        <p>Click the button below to reset your password:</p>
        <p>
            <a href="{reset_url}" 
               style="background-color:#af4c0f;color:white;padding:15px 25px;text-decoration:none;border-radius:5px;font-weight:bold;">
               Reset Password
            </a>
        </p>
        <p>Or copy and paste this link into your browser:</p>
        <p><a href="{reset_url}">{reset_url}</a></p>
        <p>If you did not request a password reset, please ignore this email.</p>
        <p><small>This email was sent on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</small></p>
        <hr>
        <p><small>AllerSafe Recipe System</small></p>
    </body>
    </html>
    """
    
    # Plain text version (fallback)
    text_content = f"""
    Password Reset Request
    
    Hello,
    
    We received a request to reset your password for your AllerSafe Recipe(s) account.
    
    Click this link to reset your password:
    {reset_url}
    
    If you did not request a password reset, please ignore this email.
    
    Sent on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    AllerSafe Recipe System
    """
    
    # Create message parts
    part1 = MIMEText(text_content, 'plain')
    part2 = MIMEText(html_content, 'html')
    
    msg.attach(part1)
    msg.attach(part2)
    
    try:
        print("Connecting to Gmail SMTP server...")
        # Gmail SMTP configuration
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()  # Enable TLS encryption
        
        print("Logging into Gmail...")
        server.login(GMAIL_EMAIL, GMAIL_APP_PASSWORD)
        
        print("Sending email...")
        server.send_message(msg)
        server.quit()
        
        print("Email sent successfully via Gmail!")
        return True
        
    except smtplib.SMTPAuthenticationError:
        print("Gmail authentication failed!")
        print("Make sure you're using an App Password, not your regular Gmail password")
        print("Enable 2FA and create an App Password: https://myaccount.google.com/apppasswords")
        return False
    except smtplib.SMTPException as e:
        print(f"SMTP error: {e}")
        return False
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def get_user_name_by_id(user_id):
    """Helper function to get username from user.db"""
    if not user_id:  # Handle NULL author_id (admin-created recipes)
        return 'Admin'
    
    try:
        conn = sqlite3.connect("user.db")
        conn.row_factory = sqlite3.Row
        user = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
        conn.close()
        return user['username'] if user else 'Unknown User'
    except Exception as e:
        print(f"Error fetching user: {e}")
        return 'Unknown User'

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
