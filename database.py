import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta

def get_db_connection():
    conn = sqlite3.connect('admin_panel.db')
    conn.row_factory = sqlite3.Row
    return conn

# Simple console logging for testing
def send_reset_email(email, token):
    reset_url = f"http://localhost:5000/reset-password/{token}"
    print("=" * 50)
    print("EMAIL WOULD BE SENT:")
    print(f"To: {email}")
    print(f"Subject: Password Reset Request")
    print(f"Reset URL: {reset_url}")
    print("=" * 50)

def init_db():
    conn = get_db_connection()
    
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
    
    # Create recipes table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS recipes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT UNIQUE NOT NULL,
            description TEXT,
            ingredients TEXT,
            instructions TEXT,
            category TEXT,
            status TEXT DEFAULT 'active',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
            FOREIGN KEY (recipe_id) REFERENCES recipes (id),
            FOREIGN KEY (allergy_id) REFERENCES allergies (id)
        )
    ''')
    
    # Insert allergy data
    allergies_data = [
        # Fruits
        ('Fruits', 'Apple', 'Birch pollen', 'Oral allergy syndrome (itchy mouth/throat)'),
        ('Fruits', 'Peach, Cherry, Plum, Apricot', 'Birch pollen', 'Stone fruits, common trigger'),
        ('Fruits', 'Kiwi', 'Latex', 'Can cause severe reactions'),
        ('Fruits', 'Banana', 'Latex', 'Often linked to latex-fruit syndrome'),
        ('Fruits', 'Mango', 'Poison ivy family', 'May cause skin + oral reactions'),
        ('Fruits', 'Avocado', 'Latex', 'High cross-reactivity risk'),
        ('Fruits', 'Strawberry', 'None strong', 'Sometimes mild, sometimes severe'),
        ('Fruits', 'Citrus (orange, lemon)', 'Grass pollen', 'May worsen hay fever'),
        
        # Nuts & Seeds
        ('Nuts & Seeds', 'Peanut', 'Legumes', 'Major allergen, can be life-threatening'),
        ('Nuts & Seeds', 'Almond, Cashew, Walnut, Hazelnut', 'Tree nuts', 'Strong allergen group'),
        ('Nuts & Seeds', 'Sesame', 'None strong', 'Recognized as a top allergen'),
        ('Nuts & Seeds', 'Mustard', 'Cruciferous plants', 'Common in sauces & seasonings'),
        
        # Vegetables
        ('Vegetables', 'Carrot', 'Birch pollen', 'Raw carrot allergy common'),
        ('Vegetables', 'Celery', 'Birch/mugwort pollen', 'Common in Europe'),
        ('Vegetables', 'Tomato', 'Grass pollen', 'Can trigger pollen-food reactions'),
        
        # Other Plants
        ('Other Plants', 'Soybean', 'Legumes', 'Found in processed foods'),
        ('Other Plants', 'Wheat', 'Grass family', 'Can be food + inhalant allergen'),
        
        # Animal Products
        ('Animal Products', 'Cow\'s Milk', 'Goat\'s milk, sheep\'s milk', 'Very common in children'),
        ('Animal Products', 'Egg (white & yolk)', 'Chicken/duck eggs', 'Heat may reduce reaction'),
        ('Animal Products', 'Fish (salmon, cod, tuna, etc.)', 'Other fish', 'High cross-reactivity'),
        ('Animal Products', 'Shellfish (shrimp, crab, lobster)', 'All crustaceans', 'One of the most severe food allergens'),
        ('Animal Products', 'Mollusks (squid, clams, mussels, oysters)', 'Other mollusks', 'Can be hidden in sauces'),
        ('Animal Products', 'Beef', 'Cow\'s milk (rare)', 'Less common, but possible'),
        ('Animal Products', 'Pork', 'Cat serum albumin ("pork–cat syndrome")', 'Rare cross-reaction'),
        ('Animal Products', 'Chicken', 'Egg (sometimes)', 'Rare compared to egg allergy')
    ]
    
    # Only insert if allergies table is empty
    existing_allergies = conn.execute('SELECT COUNT(*) FROM allergies').fetchone()[0]
    if existing_allergies == 0:
        for category, name, cross_reactivity, notes in allergies_data:
            conn.execute(
                'INSERT INTO allergies (category, name, cross_reactivity, notes) VALUES (?, ?, ?, ?)',
                (category, name, cross_reactivity, notes)
            )
    
    conn.commit()
    conn.close()


def get_all_allergies():
    conn = get_db_connection()
    allergies = conn.execute('SELECT * FROM allergies ORDER BY category, name').fetchall()
    conn.close()
    return allergies

def get_allergy_by_id(allergy_id):
    conn = get_db_connection()
    allergy = conn.execute('SELECT * FROM allergies WHERE id = ?', (allergy_id,)).fetchone()
    conn.close()
    return allergy

def get_recipe_allergies(recipe_id):
    conn = get_db_connection()
    allergies = conn.execute('''
        SELECT a.* FROM allergies a 
        JOIN recipe_allergies ra ON a.id = ra.allergy_id 
        WHERE ra.recipe_id = ?
    ''', (recipe_id,)).fetchall()
    conn.close()
    return allergies

def get_allergies_for_recipes(recipe_ids):
    """
    Batch fetch allergies for multiple recipes.
    Returns a dictionary mapping recipe_id -> list of allergy objects.
    """
    if not recipe_ids:
        return {}
    
    # Convert recipe_ids to a tuple for SQL IN clause
    if len(recipe_ids) == 1:
        recipe_ids_tuple = f"({recipe_ids[0]})"
    else:
        recipe_ids_tuple = tuple(recipe_ids)
    
    conn = get_db_connection()
    
    # Query all allergies for the given recipe IDs
    query = f'''
        SELECT ra.recipe_id, a.id, a.category, a.name, a.cross_reactivity, a.notes 
        FROM allergies a 
        JOIN recipe_allergies ra ON a.id = ra.allergy_id 
        WHERE ra.recipe_id IN {recipe_ids_tuple}
        ORDER BY ra.recipe_id, a.name
    '''
    
    results = conn.execute(query).fetchall()
    conn.close()
    
    # Build a dictionary: {recipe_id: [list_of_allergy_objects]}
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
    
    # Ensure every recipe ID in the list has an entry, even if it's an empty list
    for r_id in recipe_ids:
        if r_id not in allergies_map:
            allergies_map[r_id] = []
            
    return allergies_map

def add_recipe_allergy(recipe_id, allergy_id):
    conn = get_db_connection()
    # Check if relationship already exists
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
    
    conn.close()

def remove_recipe_allergy(recipe_id, allergy_id):
    conn = get_db_connection()
    conn.execute(
        'DELETE FROM recipe_allergies WHERE recipe_id = ? AND allergy_id = ?',
        (recipe_id, allergy_id)
    )
    conn.commit()
    conn.close()

def get_recipes_by_allergy(allergy_id):
    conn = get_db_connection()
    recipes = conn.execute('''
        SELECT r.* FROM recipes r 
        JOIN recipe_allergies ra ON r.id = ra.recipe_id 
        WHERE ra.allergy_id = ? AND r.status = 'active'
    ''', (allergy_id,)).fetchall()
    conn.close()
    return recipes

def get_recipes_without_allergy(allergy_id):
    conn = get_db_connection()
    recipes = conn.execute('''
        SELECT r.* FROM recipes r 
        WHERE r.id NOT IN (
            SELECT recipe_id FROM recipe_allergies WHERE allergy_id = ?
        ) AND r.status = 'active'
    ''', (allergy_id,)).fetchall()
    conn.close()
    return recipes
    
    # Create three admin users if they don't exist
    admins = [
        ('admin1', 'admin1@example.com', 'admin123'),
        ('admin2', 'admin2@example.com', 'admin456'),
        ('admin3', 'admin3@example.com', 'admin789')
    ]
    
    for username, email, password in admins:
        if not get_admin_by_username(username):
            password_hash = hash_password(password)
            conn.execute(
                'INSERT INTO admins (username, email, password_hash) VALUES (?, ?, ?)',
                (username, email, password_hash)
            )
    
    # Add sample users
    sample_users = [
        ('john_doe', 'john@example.com', 'John Doe'),
        ('jane_smith', 'jane@example.com', 'Jane Smith'),
        ('bob_wilson', 'bob@example.com', 'Bob Wilson')
    ]
    
    for username, email, full_name in sample_users:
        if not get_user_by_username(username):
            conn.execute(
                'INSERT INTO users (username, email, full_name) VALUES (?, ?, ?)',
                (username, email, full_name)
            )
    
    # Add sample recipes
    sample_recipes = [
        ('Spaghetti Carbonara', 'Classic Italian pasta dish', 'Pasta, Eggs, Cheese, Pancetta', '1. Cook pasta 2. Mix ingredients 3. Serve hot', 'Pasta'),
        ('Chocolate Cake', 'Rich chocolate dessert', 'Flour, Sugar, Cocoa, Eggs, Milk', '1. Mix dry ingredients 2. Add wet ingredients 3. Bake at 350°F for 30min', 'Dessert'),
        ('Chicken Curry', 'Spicy chicken dish', 'Chicken, Curry Powder, Coconut Milk, Vegetables', '1. Cook chicken 2. Add curry and vegetables 3. Simmer with coconut milk', 'Main Course')
    ]
    
    for title, description, ingredients, instructions, category in sample_recipes:
        if not get_recipe_by_title(title):
            conn.execute(
                'INSERT INTO recipes (title, description, ingredients, instructions, category) VALUES (?, ?, ?, ?, ?)',
                (title, description, ingredients, instructions, category)
            )
    
    conn.commit()
    conn.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, password_hash):
    return hash_password(password) == password_hash

def get_admin_by_username(username):
    conn = get_db_connection()
    admin = conn.execute(
        'SELECT * FROM admins WHERE username = ?', (username,)
    ).fetchone()
    conn.close()
    return admin

def get_admin_by_email(email):
    conn = get_db_connection()
    admin = conn.execute(
        'SELECT * FROM admins WHERE email = ?', (email,)
    ).fetchone()
    conn.close()
    return admin

def get_admin_by_id(admin_id):
    conn = get_db_connection()
    admin = conn.execute(
        'SELECT * FROM admins WHERE id = ?', (admin_id,)
    ).fetchone()
    conn.close()
    return admin

def set_reset_token(email, token):
    expiry = datetime.now() + timedelta(hours=1)
    conn = get_db_connection()
    conn.execute(
        'UPDATE admins SET reset_token = ?, token_expiry = ? WHERE email = ?',
        (token, expiry.isoformat(), email)
    )
    conn.commit()
    conn.close()

def get_admin_by_token(token):
    conn = get_db_connection()
    admin = conn.execute(
        'SELECT * FROM admins WHERE reset_token = ?', (token,)
    ).fetchone()
    conn.close()
    return admin

def is_token_valid(token):
    conn = get_db_connection()
    admin = conn.execute(
        'SELECT * FROM admins WHERE reset_token = ? AND token_expiry > ?',
        (token, datetime.now().isoformat())
    ).fetchone()
    conn.close()
    return admin is not None

def update_password(admin_id, new_password):
    password_hash = hash_password(new_password)
    conn = get_db_connection()
    conn.execute(
        'UPDATE admins SET password_hash = ?, reset_token = NULL, token_expiry = NULL WHERE id = ?',
        (password_hash, admin_id)
    )
    conn.commit()
    conn.close()

# User management functions
def get_all_users():
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users ORDER BY created_at DESC').fetchall()
    conn.close()
    return users

def get_user_by_id(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    return user

def get_user_by_username(username):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    return user

def update_user_status(user_id, status):
    conn = get_db_connection()
    conn.execute('UPDATE users SET status = ? WHERE id = ?', (status, user_id))
    conn.commit()
    conn.close()

def delete_user(user_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

# Recipe management functions
def get_all_recipes():
    conn = get_db_connection()
    recipes = conn.execute('SELECT * FROM recipes ORDER BY created_at DESC').fetchall()
    conn.close()
    return recipes

def get_recipe_by_id(recipe_id):
    conn = get_db_connection()
    recipe = conn.execute('SELECT * FROM recipes WHERE id = ?', (recipe_id,)).fetchone()
    conn.close()
    return recipe

def get_recipe_by_title(title):
    conn = get_db_connection()
    recipe = conn.execute('SELECT * FROM recipes WHERE title = ?', (title,)).fetchone()
    conn.close()
    return recipe

def update_recipe_status(recipe_id, status):
    conn = get_db_connection()
    conn.execute('UPDATE recipes SET status = ? WHERE id = ?', (status, recipe_id))
    conn.commit()
    conn.close()

def delete_recipe(recipe_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM recipes WHERE id = ?', (recipe_id,))
    conn.commit()
    conn.close()


# Audit log functions
def add_audit_log(admin_id, action, target_type=None, target_id=None, details=None, ip_address=None):
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO audit_log (admin_id, action, target_type, target_id, details, ip_address) VALUES (?, ?, ?, ?, ?, ?)',
        (admin_id, action, target_type, target_id, details, ip_address)
    )
    conn.commit()
    conn.close()

def get_audit_logs(limit=50):
    conn = get_db_connection()
    logs = conn.execute('''
        SELECT al.*, a.username as admin_username 
        FROM audit_log al 
        LEFT JOIN admins a ON al.admin_id = a.id 
        ORDER BY al.created_at DESC 
        LIMIT ?
    ''', (limit,)).fetchall()
    conn.close()
    return logs
