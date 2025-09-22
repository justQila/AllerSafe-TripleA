import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets
import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

DB_NAME = 'admin_panel.db'

# FIXED: Proper environment variable usage
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
FROM_EMAIL = os.getenv("FROM_EMAIL", "adore623@gmail.com")

# ---------------------- DATABASE INITIALIZATION ----------------------

def init_db():
    conn = None
    try:
        conn = sqlite3.connect('admin_panel.db')
        conn.row_factory = sqlite3.Row
        
        # Enable foreign keys
        conn.execute('PRAGMA foreign_keys = ON')
        
        # Create admins table
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
        
        # FIXED: Add missing password_reset_tokens table
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
        
        # Create users table
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
        
        # Create recipes table with foreign key
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
        
        # Create audit_log table
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
        
        # Create allergies table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS allergies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT NOT NULL,
                name TEXT NOT NULL,
                cross_reactivity TEXT,
                notes TEXT
            )
        ''')
        
        # Create recipe_allergies table (many-to-many relationship)
        conn.execute('''
            CREATE TABLE IF NOT EXISTS recipe_allergies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recipe_id INTEGER,
                allergy_id INTEGER,
                FOREIGN KEY (recipe_id) REFERENCES recipes (id) ON DELETE CASCADE,
                FOREIGN KEY (allergy_id) REFERENCES allergies (id) ON DELETE CASCADE
            )
        ''')
        
        # FIXED: Add missing recipe_reports table
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
        
        # FIXED: Add missing guidelines table
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
        
        # FIXED: Add missing user_warnings table
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
        
        # Insert allergy data if empty
        allergies_data = [
            ('Fruits', 'Apple', 'Birch pollen', 'Oral allergy syndrome (itchy mouth/throat)'),
            ('Fruits', 'Peach, Cherry, Plum, Apricot', 'Birch pollen', 'Stone fruits, common trigger'),
            ('Fruits', 'Kiwi', 'Latex', 'Can cause severe reactions'),
            ('Fruits', 'Banana', 'Latex', 'Often linked to latex-fruit syndrome'),
            ('Fruits', 'Mango', 'Poison ivy family', 'May cause skin + oral reactions'),
            ('Fruits', 'Avocado', 'Latex', 'High cross-reactivity risk'),
            ('Fruits', 'Strawberry', 'None strong', 'Sometimes mild, sometimes severe'),
            ('Fruits', 'Citrus (orange, lemon)', 'Grass pollen', 'May worsen hay fever'),
            ('Nuts & Seeds', 'Peanut', 'Legumes', 'Major allergen, can be life-threatening'),
            ('Nuts & Seeds', 'Almond, Cashew, Walnut, Hazelnut', 'Tree nuts', 'Strong allergen group'),
            ('Nuts & Seeds', 'Sesame', 'None strong', 'Recognized as a top allergen'),
            ('Nuts & Seeds', 'Mustard', 'Cruciferous plants', 'Common in sauces & seasonings'),
            ('Vegetables', 'Carrot', 'Birch pollen', 'Raw carrot allergy common'),
            ('Vegetables', 'Celery', 'Birch/mugwort pollen', 'Common in Europe'),
            ('Vegetables', 'Tomato', 'Grass pollen', 'Can trigger pollen-food reactions'),
            ('Other Plants', 'Pea, Lentil, Chickpea', 'Legumes', 'Cross-reactive with peanut'),
            ('Other Plants', 'Soybean', 'Legumes', 'Found in processed foods'),
            ('Other Plants', 'Wheat', 'Grass family', 'Can be food + inhalant allergen'),
            ('Animal Products', 'Cow\'s Milk', 'Goat\'s milk, sheep\'s milk', 'Very common in children'),
            ('Animal Products', 'Egg (white & yolk)', 'Chicken/duck eggs', 'Heat may reduce reaction'),
            ('Animal Products', 'Fish (salmon, cod, tuna, etc.)', 'Other fish', 'High cross-reactivity'),
            ('Animal Products', 'Shellfish (shrimp, crab, lobster)', 'All crustaceans', 'One of the most severe food allergens'),
            ('Animal Products', 'Mollusks (squid, clams, mussels, oysters)', 'Other mollusks', 'Can be hidden in sauces'),
            ('Animal Products', 'Beef', 'Cow\'s milk (rare)', 'Less common, but possible'),
            ('Animal Products', 'Pork', 'Cat serum albumin ("pork-cat syndrome")', 'Rare cross-reaction'),
            ('Animal Products', 'Chicken', 'Egg (sometimes)', 'Rare compared to egg allergy')
        ]
        
        existing_allergies = conn.execute('SELECT COUNT(*) FROM allergies').fetchone()[0]
        if existing_allergies == 0:
            conn.executemany(
                'INSERT INTO allergies (category, name, cross_reactivity, notes) VALUES (?, ?, ?, ?)',
                allergies_data
            )
        
        # Sample users
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
        
        # Get user IDs for recipes
        john_user = conn.execute('SELECT * FROM users WHERE username = ?', ('john_doe',)).fetchone()
        jane_user = conn.execute('SELECT * FROM users WHERE username = ?', ('jane_smith',)).fetchone()
        bob_user = conn.execute('SELECT * FROM users WHERE username = ?', ('bob_wilson',)).fetchone()
        john_id = john_user['id'] if john_user else None
        jane_id = jane_user['id'] if jane_user else None
        bob_id = bob_user['id'] if bob_user else None
        
        # Sample recipes
        sample_recipes = [
            ('Spaghetti Carbonara', 'Classic Italian pasta dish', 'Pasta, Eggs, Cheese, Pancetta', 
             '1. Cook pasta 2. Mix ingredients 3. Serve hot', 'Pasta', john_id),
            ('Chocolate Cake', 'Rich chocolate dessert', 'Flour, Sugar, Cocoa, Eggs, Milk', 
             '1. Mix dry ingredients 2. Add wet ingredients 3. Bake at 350°F for 30min', 'Dessert', jane_id),
            ('Chicken Curry', 'Spicy chicken dish', 'Chicken, Curry Powder, Coconut Milk, Vegetables', 
             '1. Cook chicken 2. Add curry and vegetables 3. Simmer with coconut milk', 'Main Course', bob_id),
            ('Vegetable Stir Fry', 'Healthy vegetable dish', 'Broccoli, Carrots, Bell Peppers, Soy Sauce', 
             '1. Chop vegetables 2. Stir fry 3. Add sauce', 'Vegetarian', jane_id),
            ('Beef Stew', 'Hearty beef stew', 'Beef, Potatoes, Carrots, Onions', 
             '1. Brown beef 2. Add vegetables 3. Simmer for 2 hours', 'Main Course', john_id)
        ]
        for title, description, ingredients, instructions, category, author_id in sample_recipes:
            existing_recipe = conn.execute('SELECT * FROM recipes WHERE title = ?', (title,)).fetchone()
            if not existing_recipe:
                conn.execute(
                    'INSERT INTO recipes (title, description, ingredients, instructions, category, author_id) VALUES (?, ?, ?, ?, ?, ?)',
                    (title, description, ingredients, instructions, category, author_id)
                )
        
        # FIXED: Ensure admin accounts are created properly
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
            # Hash the password before storing
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
                 (admin['id'], token, expires_at))
    conn.commit()
    conn.close()
    return True

def is_token_valid(token):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    row = conn.execute('SELECT * FROM password_reset_tokens WHERE token = ?', (token,)).fetchone()
    conn.close()
    if row and datetime.strptime(row['expires_at'], "%Y-%m-%d %H:%M:%S") > datetime.utcnow():
        return True
    return False

def get_admin_by_token(token):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    row = conn.execute('SELECT a.* FROM admins a JOIN password_reset_tokens t ON a.id = t.admin_id WHERE t.token = ?', (token,)).fetchone()
    conn.close()
    return dict(row) if row else None

def update_password(admin_id, new_password):
    hashed = hash_password(new_password)
    conn = sqlite3.connect(DB_NAME)
    conn.execute('UPDATE admins SET password_hash = ? WHERE id = ?', (hashed, admin_id))
    conn.commit()
    conn.close()

# ---------------------- SENDGRID EMAIL ----------------------
def send_reset_email(to_email, reset_url):
    if not SENDGRID_API_KEY:
        print("Warning: SENDGRID_API_KEY not set")
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

# ---------------------- AUDIT LOG ----------------------

def add_audit_log(admin_id=None, user_id=None, action=None, entity_type=None, entity_id=None, details=None, ip_address=None):
    """Add audit log entry - handles both old and new schema"""
    conn = sqlite3.connect(DB_NAME)
    
    try:
        # Check if new columns exist
        cursor = conn.execute("PRAGMA table_info(audit_log)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'user_id' in columns and 'user_type' in columns:
            user_type = 'admin' if admin_id else 'user' if user_id else 'system'
            conn.execute('''
                INSERT INTO audit_log (admin_id, user_id, user_type, action, target_type, target_id, details, ip_address)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (admin_id, user_id, user_type, action, entity_type, entity_id, details, ip_address))
        else:
            conn.execute('''
                INSERT INTO audit_log (admin_id, action, target_type, target_id, details, ip_address)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (admin_id, action, entity_type, entity_id, details, ip_address))
        
        conn.commit()
    except Exception as e:
        print(f"Error adding audit log: {e}")
        conn.rollback()
    finally:
        conn.close()


def add_user_audit_log(user_id, action, entity_type=None, entity_id=None, details=None, ip_address=None):
    """Convenience function to log user actions"""
    add_audit_log(user_id=user_id, action=action, entity_type=entity_type, 
                  entity_id=entity_id, details=details, ip_address=ip_address)

def get_audit_logs(limit=None):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    query = 'SELECT * FROM audit_log ORDER BY created_at DESC'
    if limit:
        query += f' LIMIT {limit}'
    logs = conn.execute(query).fetchall()
    conn.close()
    return [dict(log) for log in logs]

def upgrade_audit_log_table():
    """Upgrade audit_log table to support both admin and user actions"""
    conn = sqlite3.connect(DB_NAME)
    try:
        # Check if columns already exist
        cursor = conn.execute("PRAGMA table_info(audit_log)")
        columns = [column[1] for column in cursor.fetchall()]
        
        changes_made = []
        
        if 'user_id' not in columns:
            conn.execute('ALTER TABLE audit_log ADD COLUMN user_id INTEGER')
            changes_made.append('user_id')
        
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

def get_all_recipes_with_authors():
    """Get all recipes with author information joined"""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    recipes = conn.execute('''
        SELECT r.*, u.username as author_username, u.full_name as author_name
        FROM recipes r
        LEFT JOIN users u ON r.author_id = u.id
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

# ---------------------- RECIPES ----------------------

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

def reject_recipe(recipe_id, reason):
    update_recipe_status(recipe_id, 'rejected')

# ---------------------- RECIPE REPORTS ----------------------

def get_all_recipe_reports():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    reports = conn.execute('SELECT * FROM recipe_reports').fetchall()
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
    allergies = conn.execute('SELECT * FROM allergies').fetchall()
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
    query = f"SELECT * FROM recipe_allergies WHERE recipe_id IN ({','.join(['?']*len(recipe_ids))})"
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

# ---------------------- GUIDELINES ----------------------

def get_all_guidelines():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    rows = conn.execute('SELECT * FROM guidelines').fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_guideline_by_id(guideline_id):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    row = conn.execute('SELECT * FROM guidelines WHERE id = ?', (guideline_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

def add_guideline(title, content, category, severity):
    conn = sqlite3.connect(DB_NAME)
    conn.execute('INSERT INTO guidelines (title, content, category, severity) VALUES (?, ?, ?, ?)',
                 (title, content, category, severity))
    conn.commit()
    conn.close()

def update_guideline(guideline_id, title, content, category, severity):
    conn = sqlite3.connect(DB_NAME)
    conn.execute('UPDATE guidelines SET title=?, content=?, category=?, severity=? WHERE id=?',
                 (title, content, category, severity, guideline_id))
    conn.commit()
    conn.close()

def insert_guideline(title, content, category, severity):
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
    rows = conn.execute('SELECT * FROM recipes WHERE status = "pending"').fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ---------------------- MAIN EXECUTION ----------------------

if __name__ == "__main__":
    print("Initializing database with fixes...")
    init_db()
    print("Database initialization complete!")
    print("\nYou can now log in with:")
    print("Username: admin1, Password: password1")
    print("Username: admin2, Password: password2") 
    print("Username: admin3, Password: password3")
