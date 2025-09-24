# =========================
# ---------------BACKEND------------------
# =========================

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy

from functools import wraps
from werkzeug.utils import secure_filename
from PIL import Image
import sqlite3
import os
import secrets
from database import *
from dotenv import load_dotenv

# =========================
# FLASK APP CONFIG
# =========================
app = Flask(__name__)
app.config['SECRET_KEY'] = 'FishyyFishhiodhwqhdqid190e71eu'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///recipe.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'

# Init database
db = SQLAlchemy(app)

# initialize the admin database when the app starts
with app.app_context():
    init_db()
    db.create_all()

# =========================
# UTILITIES
# =========================
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ---------------------- LOGIN REQUIRED DECORATOR ----------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# =========================
# ADMIN ROUTES
# =========================
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/temp-user-login')
def temp_user_login():
    """Temporary user login page for demonstration"""
    return render_template('temp_user_login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'admin_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False

        admin = get_admin_by_username(username)

        if admin and verify_password(password, admin['password_hash']):
            session['admin_id'] = admin['id']
            session['admin_username'] = admin['username']
            if remember:
                session.permanent = True
            add_audit_log(admin['id'], 'Admin Login', ip_address=request.remote_addr)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('Admin_login.html')

@app.route('/logout')
@login_required
def logout():
    add_audit_log(session['admin_id'], 'Admin Logout', ip_address=request.remote_addr)
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    admin = get_admin_by_id(session['admin_id'])

    # Stats
    with sqlite3.connect(DB_NAME) as conn:
        conn.row_factory = sqlite3.Row
        user_count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        recipe_count = conn.execute('SELECT COUNT(*) FROM recipes').fetchone()[0]
        active_users = conn.execute('SELECT COUNT(*) FROM users WHERE status="active"').fetchone()[0]

    logs = get_audit_logs(limit=5)
    return render_template('dashboard.html', admin=admin, user_count=user_count,
                           recipe_count=recipe_count, active_users=active_users, logs=logs)

# =========================
# MODELS (Amirah)
# =========================
class Recipe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    allergens = db.Column(db.String(200), nullable=False, default="")
    instruction = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Float, default=0.0)
    photo = db.Column(db.String(200))
    ingredients = db.relationship('Ingredient', backref='recipe', cascade="all, delete-orphan")

class Ingredient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    recipe_id = db.Column(db.Integer, db.ForeignKey('recipe.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    measurement = db.Column(db.String(50))

with app.app_context():
    db.create_all()

# =========================
# RECIPE MANAGEMENT ROUTES
# =========================
@app.route('/recipe-management')
@login_required
def recipe_management():
    allergy_filter = request.args.get('allergy_filter', 'all')
    exclude_allergy = request.args.get('exclude', '0') == '1'

    if allergy_filter and allergy_filter != 'all':
        allergy_id = int(allergy_filter)
        recipes = get_recipes_without_allergy_with_authors(allergy_id) if exclude_allergy else get_recipes_by_allergy_with_authors(allergy_id)
    else:
        recipes = get_all_recipes_with_authors()

    recipe_list = list(recipes)
    recipe_ids = [recipe['id'] for recipe in recipe_list]
    recipe_allergies_map = get_allergies_for_recipes(recipe_ids)
    allergies = get_all_allergies()
    
    return render_template('recipe_management.html', recipes=recipe_list,
                           allergies=allergies, selected_allergy=allergy_filter,
                           exclude_allergy=exclude_allergy, recipe_allergies_map=recipe_allergies_map)

@app.route('/manage-recipe-allergies/<int:recipe_id>')
@login_required
def manage_recipe_allergies(recipe_id):
    recipe = get_recipe_by_id(recipe_id)
    if not recipe:
        flash('Recipe not found.', 'error')
        return redirect(url_for('recipe_management'))
    
    all_allergies = get_all_allergies()
    recipe_allergies = get_recipe_allergies(recipe_id)
    recipe_allergy_ids = [a['id'] for a in recipe_allergies]
    
    return render_template('manage_recipe_allergies.html', 
                         recipe=recipe, 
                         all_allergies=all_allergies,
                         recipe_allergy_ids=recipe_allergy_ids)

@app.route('/delete-recipe/<int:recipe_id>')
@login_required
def delete_recipe_route(recipe_id):
    recipe = get_recipe_by_id(recipe_id)
    if recipe:
        delete_recipe(recipe_id)
        add_audit_log(session['admin_id'], 'Recipe Deleted', 'recipe', recipe_id, 
                      f"Deleted recipe: {recipe['title']}", request.remote_addr)
        flash(f"Recipe '{recipe['title']}' has been deleted.", 'success')
    else:
        flash('Recipe not found.', 'error')
    return redirect(url_for('recipe_management'))

# =========================
# PENDING RECIPES ROUTES
# =========================
@app.route('/pending-recipes')
@login_required
def pending_recipes():
    recipes = get_pending_recipes()
    for recipe in recipes:
        if recipe.get('author_id'):
            author = get_user_by_id(recipe['author_id'])
            recipe['author'] = author if author else {'username': 'Unknown'}
        else:
            recipe['author'] = {'username': 'Unknown'}
        recipe['category'] = {'name': recipe.get('category', 'Uncategorized')}
        ingredients = recipe.get('ingredients', '')
        recipe['ingredients'] = ingredients.split(',') if ingredients else []
    
    return render_template('pending_recipes.html', recipes=recipes)

@app.route('/approve-recipe/<int:recipe_id>')
@login_required
def approve_recipe(recipe_id):
    recipe = get_recipe_by_id(recipe_id)
    if recipe:
        update_recipe_status(recipe_id, 'active')
        add_audit_log(session['admin_id'], 'Recipe Approved', 'recipe', recipe_id, 
                      f"Approved recipe: {recipe['title']}", request.remote_addr)
        flash(f"Recipe '{recipe['title']}' has been approved.", 'success')
    else:
        flash('Recipe not found.', 'error')
    return redirect(url_for('pending_recipes'))

@app.route('/reject-recipe/<int:recipe_id>')
@login_required  
def reject_recipe(recipe_id):
    recipe = get_recipe_by_id(recipe_id)
    if recipe:
        update_recipe_status(recipe_id, 'rejected')
        add_audit_log(session['admin_id'], 'Recipe Rejected', 'recipe', recipe_id, 
                      f"Rejected recipe: {recipe['title']}", request.remote_addr)
        flash(f"Recipe '{recipe['title']}' has been rejected.", 'warning')
    else:
        flash('Recipe not found.', 'error')
    return redirect(url_for('pending_recipes'))

# =========================
# USER SYSTEM (Aqilah)
# =========================
@app.route("/AllerSafe/")
def index():
    return redirect(url_for("main"))

@app.route("/AllerSafe/main")
def main():
    selected_allergens = request.args.getlist("allergy")
    conn = sqlite3.connect("recipe.db")
    conn.row_factory = sqlite3.Row

    if selected_allergens:
        placeholders = " AND ".join(["allergens NOT LIKE ?"] * len(selected_allergens))
        params = [f"%{a}%" for a in selected_allergens]
        query = f"SELECT id, name, allergens, instruction, rating, photo FROM recipe WHERE {placeholders}"
        recipes = conn.execute(query, params).fetchall()
    else:
        recipes = conn.execute("SELECT id, name, allergens, instruction, rating, photo FROM recipe").fetchall()

    conn.close()
    return render_template("main.html", recipes=recipes)

@app.route("/AllerSafe/user_main")
def user_main():
    if "user" not in session:
        return redirect(url_for("login_user"))

    selected_allergens = request.args.getlist("allergy")
    query = Recipe.query
    for allergen in selected_allergens:
        query = query.filter(~Recipe.allergens.like(f"%{allergen}%"))

    recipes = query.all()  
    return render_template("user_main.html", username=session["user"], recipes=recipes)

# =========================
# USER SYSTEM AQILAH 
# =========================
@app.route("/AllerSafe/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        try:
            conn = sqlite3.connect("user.db", timeout=10)
            conn.execute("INSERT INTO users (username, email, password) VALUES (?,?,?)",
                         (username, email, password))
            conn.commit()
            conn.close()
            session["user"] = username
            flash("Registration successful! You can now log in", "success")
            return redirect(url_for("user_main"))
        except sqlite3.IntegrityError:
            flash("This username or email is already registered. Please log in instead.", "error")
            return redirect(url_for("register"))
    return render_template("register.html")

@app.route("/AllerSafe/login", methods=["GET", "POST"])
def login_user():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        conn = sqlite3.connect("user.db", timeout=10)
        user = conn.execute("SELECT * FROM users WHERE username = ? AND password = ?",
                            (username, password)).fetchone()
        conn.close()
        if user:
            session["user"] = user["username"]
            return redirect(url_for("user_main"))
        else:
            flash("Invalid username or password!", "error")
            return redirect(url_for("login_user"))
    return render_template("login_user.html")

@app.route("/AllerSafe/profile", methods=["GET", "POST"])
def profile():
    if "user" not in session:
        return redirect(url_for("login_user"))
    conn = sqlite3.connect("user.db", timeout=10)
    user_data = conn.execute("SELECT * FROM users WHERE username = ?", (session["user"],)).fetchone()
    conn.close()
    if request.method == "POST":
        new_name = request.form.get("name")
        if new_name and new_name != session["user"]:
            conn = sqlite3.connect("user.db", timeout=10)
            conn.execute("UPDATE users SET username = ? WHERE username = ?", (new_name, session["user"]))
            conn.commit()
            conn.close()
            session["user"] = new_name
    return render_template("profile.html", username=session["user"])

@app.route('/upgrade-db')
@login_required
def upgrade_database():
    """Upgrade database schema"""
    try:
        from database import upgrade_audit_log_table
        upgrade_audit_log_table()
        flash("Database upgraded successfully! audit_log table now supports both admin and user actions.", 'success')
        
        # Log this action
        add_audit_log(admin_id=session['admin_id'], action='Database Upgraded', 
                      details='Added user_id and user_type columns to audit_log', 
                      ip_address=request.remote_addr)
        
    except Exception as e:
        flash(f"Error upgrading database: {e}", 'error')
    
    return redirect(url_for('audit_log'))

# ---------------------- CHANGE PASSWORD ----------------------

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change admin password"""
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if new_password != confirm_password:
            flash('New passwords do not match', 'error')
            return redirect(url_for('change_password'))
        
        # Verify current password
        admin = get_admin_by_id(session['admin_id'])
        if not admin:
            flash('Admin account not found', 'error')
            return redirect(url_for('login'))
        if not verify_password(current_password, admin['password_hash']):
            flash('Current password is incorrect', 'error')
            return redirect(url_for('change_password'))
        
        # Update password
        update_password(session['admin_id'], new_password)
        add_audit_log(session['admin_id'], 'Password Changed', ip_address=request.remote_addr)
        
        flash('Password changed successfully', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('change_password.html')

# ---------------------- FORGOT PASSWORD ----------------------

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        admin = get_admin_by_email(email)
        
        if admin:
            token = secrets.token_urlsafe(32)
            set_reset_token(email, token)
            reset_url = f"{request.host_url}reset-password/{token}"
            
            # Send email via SendGrid
            send_reset_email(admin['email'], reset_url)
            
            flash('Password reset email sent! Please check your inbox.', 'info')
        else:
            flash('Email not found in our system.', 'error')
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if not is_token_valid(token):
        flash('Invalid or expired reset token.', 'error')
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html', token=token)
        admin = get_admin_by_token(token)
        update_password(admin['id'], password)
        flash('Password reset successfully. You can now login with your new password.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', token=token)


# ----------------AUDIT LOG ---------------------
@app.route('/audit-log')
@login_required
def audit_log():
    logs = get_audit_logs()
    
    # Enrich logs with admin/user info
    for log in logs:
        if log.get('admin_id'):
            admin = get_admin_by_id(log['admin_id'])
            log['admin'] = admin if admin else None
        else:
            log['admin'] = None
        
        if log.get('user_id'):
            user = get_user_by_id(log['user_id'])
            log['user'] = user if user else None
        else:
            log['user'] = None
    
    return render_template('audit_log.html', logs=logs)

#------------------------------------- USER MANAGEMENT -------------------------
@app.route('/user-management')
@login_required
def user_management():
    users = get_all_users()
    return render_template('user_management.html', users=users)

@app.route('/suspend-user/<int:user_id>')
@login_required
def suspend_user(user_id):
    user = get_user_by_id(user_id)
    if user:
        update_user_status(user_id, 'suspended')
        add_audit_log(session['admin_id'], 'User Suspended', 'user', user_id, 
                      f"Suspended user: {user['username']}", request.remote_addr)
        flash(f"User '{user['username']}' has been suspended.", 'warning')
    else:
        flash('User not found.', 'error')
    return redirect(url_for('user_management'))

@app.route('/activate-user/<int:user_id>')
@login_required
def activate_user(user_id):
    user = get_user_by_id(user_id)
    if user:
        update_user_status(user_id, 'active')
        add_audit_log(session['admin_id'], 'User Activated', 'user', user_id, 
                      f"Activated user: {user['username']}", request.remote_addr)
        flash(f"User '{user['username']}' has been activated.", 'success')

    else:
        flash('User not found.', 'error')
    return redirect(url_for('user_management'))

@app.route('/delete-user/<int:user_id>')
@login_required
def delete_user_route(user_id):
    user = get_user_by_id(user_id)
    if user:
        delete_user(user_id)
        add_audit_log(session['admin_id'], 'User Deleted', 'user', user_id, 
                      f"Deleted user: {user['username']}", request.remote_addr)
        flash(f"User '{user['username']}' has been deleted.", 'success')
    else:
        flash('User not found.', 'error')
    return redirect(url_for('user_management'))

# ---------------------- RUN ----------------------
if __name__ == '__main__':
    app.run(debug=True)
