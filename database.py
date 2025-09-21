import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta

# Simple console logging for testing
def send_reset_email(email, token):
    reset_url = f"http://localhost:5000/reset-password/{token}"
    print("=" * 50)
    print("EMAIL WOULD BE SENT:")
    print(f"To: {email}")
    print(f"Subject: Password Reset Request")
    print(f"Reset URL: {reset_url}")
    print("=" * 50)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, password_hash):
    return hash_password(password) == password_hash

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
        
        # Create three admin users if missing
        admins = [
            ('admin1', 'admin1@example.com', 'admin123'),
            ('admin2', 'admin2@example.com', 'admin456'),
            ('admin3', 'admin3@example.com', 'admin789')
        ]
        for username, email, password in admins:
            existing_admin = conn.execute('SELECT * FROM admins WHERE username = ?', (username,)).fetchone()
            if not existing_admin:
                password_hash = hash_password(password)
                conn.execute(
                    'INSERT INTO admins (username, email, password_hash) VALUES (?, ?, ?)',
                    (username, email, password_hash)
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

# Allergy management functions
def get_all_allergies():
    with sqlite3.connect('admin_panel.db') as conn:
        conn.row_factory = sqlite3.Row
        allergies = conn.execute('SELECT * FROM allergies ORDER BY category, name').fetchall()
        return allergies

def get_allergy_by_id(allergy_id):
    with sqlite3.connect('admin_panel.db') as conn:
        conn.row_factory = sqlite3.Row
        allergy = conn.execute('SELECT * FROM allergies WHERE id = ?', (allergy_id,)).fetchone()
        return allergy

def get_recipe_allergies(recipe_id):
    with sqlite3.connect('admin_panel.db') as conn:
        conn.row_factory = sqlite3.Row
        allergies = conn.execute('''
            SELECT a.* FROM allergies a 
            JOIN recipe_allergies ra ON a.id = ra.allergy_id 
            WHERE ra.recipe_id = ?
        ''', (recipe_id,)).fetchall()
        return allergies

def get_allergies_for_recipes(recipe_ids):
    if not recipe_ids:
        return {}
    
    with sqlite3.connect('admin_panel.db') as conn:
        conn.row_factory = sqlite3.Row
        placeholders = ','.join('?' * len(recipe_ids))
        query = f'''
            SELECT ra.recipe_id, a.id, a.category, a.name, a.cross_reactivity, a.notes 
            FROM allergies a 
            JOIN recipe_allergies ra ON a.id = ra.allergy_id 
            WHERE ra.recipe_id IN ({placeholders})
            ORDER BY ra.recipe_id, a.name
        '''
        results = conn.execute(query, recipe_ids).fetchall()
        
        allergies_map = {}
        for row in results:
            recipe_id = row['recipe_id']
            allergy_info = {
                'id': row['id'],
                'category': row['category'],
                'name': row['name'],
                'cross_reactivity': row['cross_reactivity'],
                'notes': row['notes']
            }
            if recipe_id not in allergies_map:
                allergies_map[recipe_id] = []
            allergies_map[recipe_id].append(allergy_info)
        
        for r_id in recipe_ids:
            if r_id not in allergies_map:
                allergies_map[r_id] = []
                
        return allergies_map

def add_recipe_allergy(recipe_id, allergy_id):
    try:
        with sqlite3.connect('admin_panel.db') as conn:
            conn.row_factory = sqlite3.Row
            existing = conn.execute(
                'SELECT * FROM recipe_allergies WHERE recipe_id = ? AND allergy_id = ?',
                (recipe_id, allergy_id)
            ).fetchone()
            
            if not existing:
                conn.execute(
                    'INSERT INTO recipe_allergies (recipe_id, allergy_id) VALUES (?, ?)',
                    (recipe_id, allergy_id)
                )
                conn.commit()
    except Exception as e:
        print(f"Error adding recipe allergy: {e}")
        raise e

def remove_recipe_allergy(recipe_id, allergy_id):
    try:
        with sqlite3.connect('admin_panel.db') as conn:
            conn.execute(
                'DELETE FROM recipe_allergies WHERE recipe_id = ? AND allergy_id = ?',
                (recipe_id, allergy_id)
            )
            conn.commit()
    except Exception as e:
        print(f"Error removing recipe allergy: {e}")
        raise e

# Admin management functions
def get_admin_by_username(username):
    with sqlite3.connect('admin_panel.db') as conn:
        conn.row_factory = sqlite3.Row
        admin = conn.execute(
            'SELECT * FROM admins WHERE username = ?', (username,)
        ).fetchone()
        return admin

def get_admin_by_email(email):
    with sqlite3.connect('admin_panel.db') as conn:
        conn.row_factory = sqlite3.Row
        admin = conn.execute(
            'SELECT * FROM admins WHERE email = ?', (email,)
        ).fetchone()
        return admin

def get_admin_by_id(admin_id):
    with sqlite3.connect('admin_panel.db') as conn:
        conn.row_factory = sqlite3.Row
        admin = conn.execute(
            'SELECT * FROM admins WHERE id = ?', (admin_id,)
        ).fetchone()
        return admin

def set_reset_token(email, token):
    expiry = datetime.now() + timedelta(hours=1)
    with sqlite3.connect('admin_panel.db') as conn:
        conn.execute(
            'UPDATE admins SET reset_token = ?, token_expiry = ? WHERE email = ?',
            (token, expiry.isoformat(), email)
        )
        conn.commit()

def get_admin_by_token(token):
    with sqlite3.connect('admin_panel.db') as conn:
        conn.row_factory = sqlite3.Row
        admin = conn.execute(
            'SELECT * FROM admins WHERE reset_token = ?', (token,)
        ).fetchone()
        return admin

def is_token_valid(token):
    with sqlite3.connect('admin_panel.db') as conn:
        conn.row_factory = sqlite3.Row
        admin = conn.execute(
            'SELECT * FROM admins WHERE reset_token = ? AND token_expiry > ?',
            (token, datetime.now().isoformat())
        ).fetchone()
        return admin is not None

def update_password(admin_id, new_password):
    password_hash = hash_password(new_password)
    with sqlite3.connect('admin_panel.db') as conn:
        conn.execute(
            'UPDATE admins SET password_hash = ?, reset_token = NULL, token_expiry = NULL WHERE id = ?',
            (password_hash, admin_id)
        )
        conn.commit()

# User management functions
def get_all_users():
    with sqlite3.connect('admin_panel.db') as conn:
        conn.row_factory = sqlite3.Row
        users = conn.execute('SELECT * FROM users ORDER BY created_at DESC').fetchall()
        return users

def get_user_by_id(user_id):
    with sqlite3.connect('admin_panel.db') as conn:
        conn.row_factory = sqlite3.Row
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        return user

def get_user_by_username(username):
    with sqlite3.connect('admin_panel.db') as conn:
        conn.row_factory = sqlite3.Row
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        return user

def update_user_status(user_id, status):
    with sqlite3.connect('admin_panel.db') as conn:
        conn.execute('UPDATE users SET status = ? WHERE id = ?', (status, user_id))
        conn.commit()

def delete_user(user_id):
    try:
        with sqlite3.connect('admin_panel.db') as conn:
            conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
            conn.commit()
    except Exception as e:
        print(f"Error deleting user: {e}")
        raise e

# Recipe management functions
def get_all_recipes():
    with sqlite3.connect('admin_panel.db') as conn:
        conn.row_factory = sqlite3.Row
        recipes = conn.execute('''
            SELECT r.*, u.username as author_username, u.full_name as author_name 
            FROM recipes r 
            LEFT JOIN users u ON r.author_id = u.id 
            ORDER BY r.id ASC
        ''').fetchall()
        return recipes

def get_recipes_by_allergy(allergy_id):
    with sqlite3.connect('admin_panel.db') as conn:
        conn.row_factory = sqlite3.Row
        recipes = conn.execute('''
            SELECT r.*, u.username as author_username, u.full_name as author_name
            FROM recipes r 
            LEFT JOIN users u ON r.author_id = u.id
            JOIN recipe_allergies ra ON r.id = ra.recipe_id 
            WHERE ra.allergy_id = ? AND r.status = 'active'
            ORDER BY r.id ASC
        ''', (allergy_id,)).fetchall()
        return recipes

def get_recipes_without_allergy(allergy_id):
    with sqlite3.connect('admin_panel.db') as conn:
        conn.row_factory = sqlite3.Row
        recipes = conn.execute('''
            SELECT r.*, u.username as author_username, u.full_name as author_name
            FROM recipes r 
            LEFT JOIN users u ON r.author_id = u.id
            WHERE r.id NOT IN (
                SELECT recipe_id FROM recipe_allergies WHERE allergy_id = ?
            ) AND r.status = 'active'
            ORDER BY r.id ASC
        ''', (allergy_id,)).fetchall()
        return recipes

def get_recipe_by_id(recipe_id):
    with sqlite3.connect('admin_panel.db') as conn:
        conn.row_factory = sqlite3.Row
        recipe = conn.execute('''
            SELECT r.*, u.username as author_username, u.full_name as author_name 
            FROM recipes r 
            LEFT JOIN users u ON r.author_id = u.id 
            WHERE r.id = ?
        ''', (recipe_id,)).fetchone()
        return recipe

def get_recipe_by_title(title):
    with sqlite3.connect('admin_panel.db') as conn:
        conn.row_factory = sqlite3.Row
        recipe = conn.execute('''
            SELECT r.*, u.username as author_username, u.full_name as author_name 
            FROM recipes r 
            LEFT JOIN users u ON r.author_id = u.id 
            WHERE r.title = ?
        ''', (title,)).fetchone()
        return recipe

def update_recipe_status(recipe_id, status):
    with sqlite3.connect('admin_panel.db') as conn:
        conn.execute('UPDATE recipes SET status = ? WHERE id = ?', (status, recipe_id))
        conn.commit()

def update_recipe(recipe_id, title, description, ingredients, instructions, category, author_id):
    try:
        with sqlite3.connect('admin_panel.db') as conn:
            conn.execute('''
                UPDATE recipes 
                SET title = ?, description = ?, ingredients = ?, instructions = ?, category = ?, author_id = ?
                WHERE id = ?
            ''', (title, description, ingredients, instructions, category, author_id, recipe_id))
            conn.commit()
    except Exception as e:
        print(f"Error updating recipe: {e}")
        raise e

def delete_recipe(recipe_id):
    try:
        with sqlite3.connect('admin_panel.db') as conn:
            conn.execute('DELETE FROM recipes WHERE id = ?', (recipe_id,))
            conn.commit()
    except Exception as e:
        print(f"Error deleting recipe: {e}")
        raise e

# Audit log functions
def add_audit_log(admin_id, action, target_type=None, target_id=None, details=None, ip_address=None):
    with sqlite3.connect('admin_panel.db') as conn:
        conn.execute(
            'INSERT INTO audit_log (admin_id, action, target_type, target_id, details, ip_address) VALUES (?, ?, ?, ?, ?, ?)',
            (admin_id, action, target_type, target_id, details, ip_address)
        )
        conn.commit()

def get_audit_logs(limit=50):
    with sqlite3.connect('admin_panel.db') as conn:
        conn.row_factory = sqlite3.Row
        logs = conn.execute('''
            SELECT al.*, a.username as admin_username 
            FROM audit_log al 
            LEFT JOIN admins a ON al.admin_id = a.id 
            ORDER BY al.created_at DESC 
            LIMIT ?
        ''', (limit,)).fetchall()
        return logs

# Main execution for testing
if __name__ == '__main__':
    init_db()
    print("\nAttempting to retrieve all recipes...")
    recipes = get_all_recipes()
    if recipes:
        print(f"Found {len(recipes)} recipes.")
        for r in recipes[:3]:
            print(f"- {r['title']} by {r['author_username']}")
    
    print("\nAttempting to retrieve a specific recipe by ID...")
    recipe_id_to_fetch = recipes[0]['id'] if recipes else 1
    recipe = get_recipe_by_id(recipe_id_to_fetch)
    if recipe:
        print(f"Found recipe: {recipe['title']}")
        
    print("\nAttempting to update a user status...")
    update_user_status(1, 'inactive')
    user = get_user_by_id(1)
    if user:
        print(f"User '{user['username']}' status is now '{user['status']}'.")
