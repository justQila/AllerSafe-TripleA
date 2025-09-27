
# =========================
# ---------------BACKEND------------------
# =========================

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image
import sqlite3
import os
import secrets
from database import *
from dotenv import load_dotenv
from datetime import datetime

# =========================
# FLASK APP CONFIG
# =========================
app = Flask(__name__)
app.config['SECRET_KEY'] = 'FishyyFishhiodhwqhdqid190e71eu'
app.config['UPLOAD_FOLDER'] = 'static/uploads'

# ---------------- SQLALCHEMY DB (Recipes) ----------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(BASE_DIR, "recipe.db")
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Init database
db = SQLAlchemy(app)

# =========================
# UTILITIES
# =========================
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def ensure_dict(obj):
    """
    Convert sqlite3.Row or dict-like to a plain dict.
    Leave other objects as-is (e.g. SQLAlchemy model instances).
    """
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj
    if isinstance(obj, sqlite3.Row):
        return dict(obj)
    return obj

# ---------------------- LOGIN REQUIRED DECORATOR ----------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ---------------------- USER HELPERS ----------------------
def get_user_by_id(user_id):
    """Fetch a user by ID from user.db and return a dict or None."""
    conn = sqlite3.connect("user.db", timeout=10)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

def get_user_name_by_id(user_id):
    """Get just the username from user.db (string)."""
    user = get_user_by_id(user_id)
    return user.get("username") if user else "Unknown"

def get_db_connection():
    """Helper used in some user flows that need direct sqlite connection."""
    conn = sqlite3.connect("user.db", timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

# =========================
# ADMIN ROUTES
# =========================
@app.route('/')
def home():
    return redirect(url_for('main'))

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

    # --- Users from user.db ---
    with sqlite3.connect("user.db") as conn_user:
        conn_user.row_factory = sqlite3.Row
        user_count = conn_user.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        active_users = conn_user.execute("SELECT COUNT(*) FROM users WHERE status='active'").fetchone()[0]

    # --- Recipes from recipe.db (via SQLAlchemy) ---
    recipe_count = Recipe.query.count()

    # --- Recent audit logs from admin_panel.db ---
    logs = get_audit_logs(limit=5)

    return render_template(
        'dashboard.html',
        admin=admin,
        user_count=user_count,
        recipe_count=recipe_count,
        active_users=active_users,
        logs=logs
    )


# =========================
# MODELS (Amirah) - SQLAlchemy (recipes stored in recipe.db)
# =========================
class Recipe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    allergens = db.Column(db.String(200), nullable=False, default="")
    instruction = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Float, default=0.0)
    photo = db.Column(db.String(200))
    status = db.Column(db.String(20), default='pending')  # 'pending', 'active', 'rejected'
    author_id = db.Column(db.Integer)  # User who submitted
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
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
    status_filter = request.args.get('status', 'all')

    query = Recipe.query
    if status_filter and status_filter != 'all':
        query = query.filter(Recipe.status == status_filter)

    recipes = query.all()

    recipe_list = []
    for recipe in recipes:
        # Resolve author name from user.db (if author_id present)
        if recipe.author_id:
            author_name = get_user_name_by_id(recipe.author_id)
        else:
            author_name = 'Admin'

        # Build canonical dict for templates (dictionary style)
        recipe_dict = {
            'id': recipe.id,
            'name': recipe.name,
            'allergens': recipe.allergens,
            'status': recipe.status or 'approved',
            'created_at': recipe.submitted_at,
            'author_name': author_name,
            'author_username': author_name,  # alias for templates
            'category': getattr(recipe, 'category', 'Uncategorized')
        }
        recipe_list.append(recipe_dict)

    return render_template('recipe_management.html',
                           recipes=recipe_list,
                           selected_status=status_filter)

@app.route('/add', methods=['GET', 'POST'])
def add_recipe():
    if request.method == 'POST':
        name = request.form['name']
        allergens = request.form['allergens']
        instruction = request.form['instruction']
        rating = float(request.form['rating']) if request.form['rating'] else 0.0

        photo = request.files.get('photo')
        photo_filename = None
        if photo and allowed_file(photo.filename):
            filename = secure_filename(photo.filename)
            photo_filename = filename
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            photo.save(filepath)
            # Resize image
            max_size = (350, 350)
            img = Image.open(filepath)
            img.thumbnail(max_size)
            img.save(filepath)

        recipe = Recipe(
            name=name,
            allergens=allergens,
            instruction=instruction,
            rating=rating,
            photo=photo_filename
        )
        db.session.add(recipe)
        db.session.commit()

        ingredients = request.form.get('ingredients', '').split("\n")
        for ing in ingredients:
            if ing.strip():
                parts = ing.split("-", 1)
                ing_name = parts[0].strip()
                measurement = parts[1].strip() if len(parts) > 1 else None
                db.session.add(Ingredient(recipe_id=recipe.id, name=ing_name, measurement=measurement))
        db.session.commit()
        return redirect(url_for('home'))
    return render_template("add_recipe.html")

@app.route('/recipe/<int:recipe_id>')
def recipe_details(recipe_id):
    recipe = Recipe.query.get_or_404(recipe_id)
    return render_template("recipe_details.html", recipe=recipe)

@app.route('/delete-recipe/<int:recipe_id>')
@login_required
def delete_recipe_route(recipe_id):
    recipe = get_recipe_by_id(recipe_id)
    if recipe:
        # recipe may be dict-like from database.py
        recipe_title = recipe.get('title') or recipe.get('name') or 'Unknown'
        delete_recipe(recipe_id)
        add_audit_log(session['admin_id'], 'Recipe Deleted', 'recipe', recipe_id,
                      f"Deleted recipe: {recipe_title}", request.remote_addr)
        flash(f"Recipe '{recipe_title}' has been deleted.", 'success')
    else:
        flash('Recipe not found.', 'error')
    return redirect(url_for('recipe_management'))

# =========================
# PENDING RECIPES ROUTES
# =========================
@app.route('/pending-recipes')
@login_required
def pending_recipes():
    recipes = get_pending_recipes()  # expected list of dicts from database.py
    recipes_fixed = []
    for recipe in recipes:
        # Normalize recipe to dict (it may already be dict)
        r = ensure_dict(recipe) or {}
        # author
        if r.get('author_id'):
            r['author'] = {'username': get_user_name_by_id(r['author_id'])}
        else:
            r['author'] = {'username': 'Admin'}
        # category normalize
        cat = r.get('category', 'Uncategorized')
        if isinstance(cat, dict):
            r['category'] = cat.get('name', 'Uncategorized')
        else:
            r['category'] = cat or 'Uncategorized'
        # ingredients normalization: comma-separated string -> list
        ingredients = r.get('ingredients', '')
        if isinstance(ingredients, str):
            r['ingredients'] = ingredients.split(',') if ingredients else []
        elif isinstance(ingredients, list):
            r['ingredients'] = ingredients
        else:
            r['ingredients'] = []
        recipes_fixed.append(r)
    return render_template('pending_recipes.html', recipes=recipes_fixed)

@app.route('/approve-recipe/<int:recipe_id>')
@login_required
def approve_recipe(recipe_id):
    recipe = get_recipe_by_id(recipe_id)
    if recipe:
        recipe_title = recipe.get('title') or recipe.get('name') or 'Unknown'
        update_recipe_status(recipe_id, 'active')
        add_audit_log(session['admin_id'], 'Recipe Approved', 'recipe', recipe_id,
                      f"Approved recipe: {recipe_title}", request.remote_addr)
        flash(f"Recipe '{recipe_title}' has been approved.", 'success')
    else:
        flash('Recipe not found.', 'error')
    return redirect(url_for('pending_recipes'))

@app.route('/reject-recipe/<int:recipe_id>')
@login_required
def reject_recipe(recipe_id):
    recipe = get_recipe_by_id(recipe_id)
    if recipe:
        recipe_title = recipe.get('title') or recipe.get('name') or 'Unknown'
        update_recipe_status(recipe_id, 'rejected')
        add_audit_log(session['admin_id'], 'Recipe Rejected', 'recipe', recipe_id,
                      f"Rejected recipe: {recipe_title}", request.remote_addr)
        flash(f"Recipe '{recipe_title}' has been rejected.", 'warning')
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
    # leave as sqlite3.Row objects for the public main template (use dict-style there)
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
# USER AUTH (register/login/profile)
# =========================
@app.route("/AllerSafe/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        # Hash password before saving
        password_hash = generate_password_hash(password)

        try:
            conn = sqlite3.connect("user.db", timeout=10)
            conn.execute(
                "INSERT INTO users (username, email, password) VALUES (?,?,?)",
                (username, email, password_hash)
            )
            conn.commit()
            conn.close()
            session["user"] = username
            flash("Registration successful! You can now log in", "success")
            return redirect(url_for("user_main"))
        except sqlite3.IntegrityError:
            flash("This username or email is already registered. Please log in instead.", "error")
            return redirect(url_for("login_user"))

    return render_template("register.html")


@app.route("/AllerSafe/login", methods=["GET", "POST"])
def login_user():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("user.db", timeout=10)
        conn.row_factory = sqlite3.Row
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session["user"] = user["username"]
            flash("Login successful!", "success")
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
    conn.row_factory = sqlite3.Row
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
    return render_template("profile.html", username=session["user"], user=user_data)

@app.route("/AllerSafe/logout")
def logout_user():
    session.pop("user", None)
    return redirect(url_for("main"))

#---------------------------------------FORGOT PASSWORD USER------------------------------------
@app.route("/AllerSafe/forgot_password", methods=["GET", "POST"])
def forgot_password_user():
    if request.method == "POST":
        email = request.form["email"]
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()
        if user:
            return render_template("reset_password_user.html", email=email)
        else:
            flash("Email not found!", "error")
    return render_template('forgot_password_user.html')

@app.route("/AllerSafe/reset_password", methods=["POST"])
def reset_password_user():
    email = request.form["email"]
    new_password = request.form["new_password"]
    confirm_password = request.form["confirm_password"]

    if new_password != confirm_password:
        return "PASSWORDS DO NOT MATCH! <a href='/AllerSafe/forgot_password'>Try again</a>"

    # Hash new password
    password_hash = generate_password_hash(new_password)

    conn = get_db_connection()
    conn.execute("UPDATE users SET password = ? WHERE email = ?", (password_hash, email))
    conn.commit()
    conn.close()

    flash("Password updated successfully. You can now log in.", "success")
    return redirect(url_for("login_user"))


# ---------------------- UPGRADE DB (audit log helper) ----------------------
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

# ---------------------- FORGOT PASSWORD (admin) ----------------------
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        admin = get_admin_by_email(email)

        if admin:
            token = secrets.token_urlsafe(32)
            set_reset_token(email, token)
            reset_url = f"{request.host_url}reset-password/{token}"

            # Send email via SendGrid (send_reset_email exists in database.py)
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

    # Enrich logs with admin/user info (ensure dicts)
    for log in logs:
        if log.get('admin_id'):
            admin = get_admin_by_id(log['admin_id'])
            log['admin'] = ensure_dict(admin)
        else:
            log['admin'] = None

        if log.get('user_id'):
            user = get_user_by_id(log['user_id'])
            log['user'] = ensure_dict(user)
        else:
            log['user'] = None

    return render_template('audit_log.html', logs=logs)

#------------------------------------- USER MANAGEMENT -------------------------
@app.route('/user-management')
@login_required
def user_management():
    users = get_all_users()  # might be sqlite3.Row list or dict list
    users_fixed = []
    for u in users:
        users_fixed.append(ensure_dict(u) or {})
    return render_template('user_management.html', users=users_fixed)

@app.route('/suspend-user/<int:user_id>')
@login_required
def suspend_user(user_id):
    user = get_user_by_id(user_id)
    if user:
        update_user_status(user_id, 'suspended')
        username = user.get('username') if isinstance(user, dict) else user['username'] if user else 'Unknown'
        add_audit_log(session['admin_id'], 'User Suspended', 'user', user_id,
                      f"Suspended user: {username}", request.remote_addr)
        flash(f"User '{username}' has been suspended.", 'warning')
    else:
        flash('User not found.', 'error')
    return redirect(url_for('user_management'))

@app.route('/activate-user/<int:user_id>')
@login_required
def activate_user(user_id):
    user = get_user_by_id(user_id)
    if user:
        update_user_status(user_id, 'active')
        username = user.get('username') if isinstance(user, dict) else user['username'] if user else 'Unknown'
        add_audit_log(session['admin_id'], 'User Activated', 'user', user_id,
                      f"Activated user: {username}", request.remote_addr)
        flash(f"User '{username}' has been activated.", 'success')
    else:
        flash('User not found.', 'error')
    return redirect(url_for('user_management'))

@app.route('/delete-user/<int:user_id>')
@login_required
def delete_user_route(user_id):
    user = get_user_by_id(user_id)
    if user:
        username = user.get('username') if isinstance(user, dict) else user['username'] if user else 'Unknown'
        delete_user(user_id)
        add_audit_log(session['admin_id'], 'User Deleted', 'user', user_id,
                      f"Deleted user: {username}", request.remote_addr)
        flash(f"User '{username}' has been deleted.", 'success')
    else:
        flash('User not found.', 'error')
    return redirect(url_for('user_management'))


# ---------------------- RECIPE REPORTS ----------------------
@app.route('/recipe-reports')
@login_required
def recipe_reports():
    """Display recipe reports"""
    reports = get_all_recipe_reports()
    reports_fixed = [ensure_dict(r) or {} for r in reports]
    return render_template('recipe_reports.html', reports=reports_fixed)

@app.route('/user-warnings')
@login_required
def user_warnings():
    """Display user warnings"""
    warnings = get_all_warnings()
    warnings_fixed = []
    for w in warnings:
        w = ensure_dict(w) or {}
        if w.get('user_id'):
            w['user'] = ensure_dict(get_user_by_id(w['user_id'])) or {'username': 'Unknown'}
        else:
            w['user'] = {'username': 'Unknown'}
        if w.get('admin_id'):
            w['admin'] = ensure_dict(get_admin_by_id(w['admin_id'])) or {'username': 'Unknown'}
        else:
            w['admin'] = {'username': 'Unknown'}
        warnings_fixed.append(w)
    return render_template('user_warnings.html', warnings=warnings_fixed)

# ---------------------- GUIDELINES ----------------------
@app.route('/guideline-management')
@login_required
def guideline_management():
    """Display guidelines management"""
    guidelines = get_all_guidelines()
    guidelines_fixed = [ensure_dict(g) or {} for g in guidelines]
    return render_template('guideline_management.html', guidelines=guidelines_fixed)

@app.route('/add-edit-guideline', methods=['GET', 'POST'])
@app.route('/add-edit-guideline/<int:guideline_id>', methods=['GET', 'POST'])
@login_required
def add_edit_guideline(guideline_id=None):
    """Add or edit a guideline"""
    guideline = None
    if guideline_id:
        guideline = get_guideline_by_id(guideline_id)
        if not guideline:
            flash('Guideline not found', 'error')
            return redirect(url_for('guideline_management'))
        guideline = ensure_dict(guideline) or {}

    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        category = request.form.get('category')
        severity = request.form.get('severity')

        if guideline_id:
            update_guideline(guideline_id, title, content, category, severity)
            add_audit_log(session['admin_id'], 'Guideline Updated', 'guideline', guideline_id,
                          f"Updated guideline: {title}", request.remote_addr)
            flash('Guideline updated successfully.', 'success')
        else:
            new_id = insert_guideline(title, content, category, severity)
            add_audit_log(session['admin_id'], 'Guideline Created', 'guideline', new_id,
                          f"Created guideline: {title}", request.remote_addr)
            flash('Guideline created successfully.', 'success')

        return redirect(url_for('guideline_management'))

    return render_template('add_edit_guideline.html', guideline=guideline)

@app.route('/delete-guideline/<int:guideline_id>')
@login_required
def delete_guideline_route(guideline_id):
    """Delete a guideline"""
    guideline = get_guideline_by_id(guideline_id)
    if guideline:
        guideline = ensure_dict(guideline) or {}
        delete_guideline(guideline_id)
        add_audit_log(session['admin_id'], 'Guideline Deleted', 'guideline', guideline_id,
                      f"Deleted guideline: {guideline.get('title', 'Unknown')}", request.remote_addr)
        flash('Guideline deleted successfully.', 'success')
    else:
        flash('Guideline not found.', 'error')
    return redirect(url_for('guideline_management'))

@app.route('/toggle-guideline/<int:guideline_id>', methods=['POST'])
@login_required
def toggle_guideline(guideline_id):
    """Toggle guideline active/inactive status"""
    guideline = get_guideline_by_id(guideline_id)
    if guideline:
        guideline = ensure_dict(guideline) or {}
        current_status = guideline.get('is_active')

        # Handle various stored types
        if isinstance(current_status, str):
            current_active = current_status.lower() in ('1', 'true', 'yes', 'active')
        elif isinstance(current_status, int):
            current_active = bool(current_status)
        else:
            current_active = bool(current_status)

        new_status = not current_active
        new_status_value = 1 if new_status else 0

        toggle_guideline_status(guideline_id, new_status_value)

        status_text = "activated" if new_status else "deactivated"
        add_audit_log(session['admin_id'], f'Guideline {status_text.title()}',
                      'guideline', guideline_id,
                      f"{status_text.title()} guideline: {guideline.get('title', 'Unknown')}",
                      request.remote_addr)

        flash(f"Guideline '{guideline.get('title', 'Unknown')}' has been {status_text}.", 'success')
    else:
        flash('Guideline not found.', 'error')

    return redirect(url_for('guideline_management'))

# ---------------------- RECIPE MANAGEMENT ACTIONS ----------------------
@app.route('/suspend-recipe/<int:recipe_id>')
@login_required
def suspend_recipe(recipe_id):
    """Suspend a recipe"""
    recipe = get_recipe_by_id(recipe_id)
    if recipe:
        recipe_title = recipe.get('title') or recipe.get('name') or 'Unknown'
        update_recipe_status(recipe_id, 'suspended')
        add_audit_log(session['admin_id'], 'Recipe Suspended', 'recipe', recipe_id,
                      f"Suspended recipe: {recipe_title}", request.remote_addr)
        flash(f"Recipe '{recipe_title}' has been suspended.", 'warning')
    else:
        flash('Recipe not found.', 'error')
    return redirect(url_for('recipe_management'))

@app.route('/activate-recipe/<int:recipe_id>')
@login_required
def activate_recipe(recipe_id):
    """Activate a recipe"""
    recipe = get_recipe_by_id(recipe_id)
    if recipe:
        recipe_title = recipe.get('title') or recipe.get('name') or 'Unknown'
        update_recipe_status(recipe_id, 'active')
        add_audit_log(session['admin_id'], 'Recipe Activated', 'recipe', recipe_id,
                      f"Activated recipe: {recipe_title}", request.remote_addr)
        flash(f"Recipe '{recipe_title}' has been activated.", 'success')
    else:
        flash('Recipe not found.', 'error')
    return redirect(url_for('recipe_management'))

@app.route('/AllerSafe/submit-recipe', methods=['GET', 'POST'])
def user_submit_recipe():
    """Users submit recipes for approval"""
    if request.method == 'POST':
        name = request.form['name']
        allergens = request.form['allergens']
        instruction = request.form['instruction']

        # Get user ID
        conn = sqlite3.connect("user.db")
        conn.row_factory = sqlite3.Row
        user = conn.execute("SELECT id FROM users WHERE username = ?", (session.get('user'),)).fetchone()
        conn.close()

        # Handle photo upload
        photo = request.files.get('photo')
        photo_filename = None
        if photo and allowed_file(photo.filename):
            filename = secure_filename(photo.filename)
            photo_filename = filename
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            photo.save(filepath)

            # Resize image
            max_size = (350, 350)
            img = Image.open(filepath)
            img.thumbnail(max_size)
            img.save(filepath)

        # Save recipe with pending status
        recipe = Recipe(
            name=name,
            allergens=allergens,
            instruction=instruction,
            photo=photo_filename,
            status='pending',
            author_id=user['id'] if user else None
        )
        db.session.add(recipe)
        db.session.commit()

        # Add ingredients
        ingredients = request.form.get('ingredients', '').split("\n")
        for ing in ingredients:
            if ing.strip():
                parts = ing.split("-", 1)
                ingredient_name = parts[0].strip()
                measurement = parts[1].strip() if len(parts) > 1 else None
                db.session.add(Ingredient(recipe_id=recipe.id, name=ingredient_name, measurement=measurement))
        db.session.commit()

        flash('Recipe submitted for approval! You will be notified once it\'s reviewed.', 'success')
        return redirect(url_for('user_main'))

    return render_template("submit_recipe.html")

@app.route('/submit-recipe', methods=['GET', 'POST'])
def submit_recipe():
    # This route is a stub in your original: keep placeholder if you extend
    prep_time = request.form.get('prep_time') if request.method == 'POST' else None
    cook_time = request.form.get('cook_time') if request.method == 'POST' else None
    servings = request.form.get('servings') if request.method == 'POST' else None
    difficulty = request.form.get('difficulty') if request.method == 'POST' else None
    return redirect(url_for('recipe_management'))

# ---------------------- RUN ----------------------
if __name__ == '__main__':
    app.run(debug=True)
    

# =========================
# ---------------BACKEND------------------
# =========================

from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image
import sqlite3
import os
import secrets
from database import *
from datetime import datetime

# =========================
# FLASK APP CONFIG
# =========================
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback-secret-key')
app.config['UPLOAD_FOLDER'] = 'static/uploads'
GMAIL_EMAIL = os.getenv("GMAIL_EMAIL", "your_email@gmail.com")
GMAIL_APP_PASSWORD = os.getenv("GMAIL_APP_PASSWORD")
DB_NAME = "admin_panel.db"

# ---------------- SQLALCHEMY DB (Recipes) ----------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(BASE_DIR, "recipe.db")
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Init database
db = SQLAlchemy(app)

# =========================
# UTILITIES
# =========================
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def ensure_dict(obj):
    """
    Convert sqlite3.Row or dict-like to a plain dict.
    Leave other objects as-is (e.g. SQLAlchemy model instances).
    """
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj
    if isinstance(obj, sqlite3.Row):
        return dict(obj)
    return obj

# ---------------------- LOGIN REQUIRED DECORATOR ----------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ---------------------- USER HELPERS ----------------------
def get_user_by_id(user_id):
    """Fetch a user by ID from user.db and return a dict or None."""
    conn = sqlite3.connect("user.db", timeout=10)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

def get_user_name_by_id(user_id):
    """Get just the username from user.db (string)."""
    user = get_user_by_id(user_id)
    return user.get("username") if user else "Unknown"

def get_db_connection():
    """Helper used in some user flows that need direct sqlite connection."""
    conn = sqlite3.connect("user.db", timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

# =========================
# ADMIN ROUTES
# =========================
@app.route('/')
def home():
    return redirect(url_for('main'))

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

    # --- Users from user.db ---
    with sqlite3.connect("user.db") as conn_user:
        conn_user.row_factory = sqlite3.Row
        user_count = conn_user.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        active_users = conn_user.execute("SELECT COUNT(*) FROM users WHERE status='active'").fetchone()[0]
    
    # --- Recipes from recipe.db ---
    recipe_count = Recipe.query.count()

    # --- Recent audit logs from admin_panel.db ---
    logs = get_audit_logs(limit=5)

    return render_template(
        'dashboard.html',
        admin=admin,
        user_count=user_count,
        recipe_count=recipe_count,
        active_users=active_users,
        logs=logs
    )


# --- Helper function to get DB connection ---
def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

# Manual
@app.route("/manual")
def manual():
    return render_template("manual.html")

# =========================
# MODELS (Amirah) - SQLAlchemy (recipes stored in recipe.db)
# =========================
class Recipe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    allergens = db.Column(db.String(200), nullable=False, default="")
    instruction = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Float, default=0.0)
    photo = db.Column(db.String(200))
    status = db.Column(db.String(20), default='pending')  # 'pending', 'active', 'rejected'
    author_id = db.Column(db.Integer)  # User who submitted
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
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
    status_filter = request.args.get('status', 'all')

    query = Recipe.query
    if status_filter and status_filter != 'all':
        query = query.filter(Recipe.status == status_filter)

    recipes = query.all()

    recipe_list = []
    for recipe in recipes:
        # Resolve author name from user.db (if author_id present)
        if recipe.author_id:
            author_name = get_user_name_by_id(recipe.author_id)
        else:
            author_name = 'Admin'

        # Build canonical dict for templates (dictionary style)
        recipe_dict = {
            'id': recipe.id,
            'name': recipe.name,
            'allergens': recipe.allergens,
            'status': recipe.status or 'approved',
            'created_at': recipe.submitted_at,
            'author_name': author_name,
            'author_username': author_name,  # alias for templates
            'category': getattr(recipe, 'category', 'Uncategorized')
        }
        recipe_list.append(recipe_dict)

    return render_template('recipe_management.html',
                           recipes=recipe_list,
                           selected_status=status_filter)

@app.route('/add', methods=['GET', 'POST'])
def add_recipe():
    if request.method == 'POST':
        name = request.form['name']
        allergens = request.form['allergens']
        instruction = request.form['instruction']
        rating = float(request.form['rating']) if request.form['rating'] else 0.0

        photo = request.files.get('photo')
        photo_filename = None
        if photo and allowed_file(photo.filename):
            filename = secure_filename(photo.filename)
            photo_filename = filename
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            photo.save(filepath)
            # Resize image
            max_size = (350, 350)
            img = Image.open(filepath)
            img.thumbnail(max_size)
            img.save(filepath)

        recipe = Recipe(
            name=name,
            allergens=allergens,
            instruction=instruction,
            rating=rating,
            photo=photo_filename
        )
        db.session.add(recipe)
        db.session.commit()

        ingredients = request.form.get('ingredients', '').split("\n")
        for ing in ingredients:
            if ing.strip():
                parts = ing.split("-", 1)
                ing_name = parts[0].strip()
                measurement = parts[1].strip() if len(parts) > 1 else None
                db.session.add(Ingredient(recipe_id=recipe.id, name=ing_name, measurement=measurement))
        db.session.commit()
        return redirect(url_for('home'))
    return render_template("add_recipe.html")

@app.route('/recipe/<int:recipe_id>')
def recipe_details(recipe_id):
    recipe = Recipe.query.get_or_404(recipe_id)
    return render_template("recipe_details.html", recipe=recipe)

@app.route('/delete-recipe/<int:recipe_id>')
@login_required
def delete_recipe_route(recipe_id):
    recipe = Recipe.query.get(recipe_id)
    if recipe:
        recipe_title = recipe.name
        db.session.delete(recipe)
        db.session.commit()
        add_audit_log(session['admin_id'], 'Recipe Deleted', 'recipe', recipe_id,
                      f"Deleted recipe: {recipe_title}", request.remote_addr)
        flash(f"Recipe '{recipe_title}' has been deleted.", 'success')
    else:
        flash('Recipe not found.', 'error')
    return redirect(url_for('recipe_management'))

def save_message(table, data):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(f"""
        INSERT INTO {table} (name, email, subject, message, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (data.get('name'), data.get('email'), data.get('subject'), data.get('message'), datetime.datetime.now()))
    conn.commit()
    conn.close()

# =========================
# PENDING RECIPES ROUTES
# =========================
@app.route('/pending-recipes')
@login_required
def pending_recipes():

    pending_recipes = Recipe.query.filter_by(status='pending').all()
    
    recipes_fixed = []
    for recipe in pending_recipes:
        recipe_dict = {
            'id': recipe.id,
            'name': recipe.name,
            'title': recipe.name,  # alias for template
            'allergens': recipe.allergens,
            'instruction': recipe.instruction,
            'ingredients': [{'name': ing.name, 'measurement': ing.measurement} for ing in recipe.ingredients],
            'photo': recipe.photo,
            'submitted_at': recipe.submitted_at,
            'author': {'username': get_user_name_by_id(recipe.author_id) if recipe.author_id else 'Admin'},
            'category': {'name': 'User Submission'}
        }
        recipes_fixed.append(recipe_dict)
    
    return render_template('pending_recipes.html', recipes=recipes_fixed)

@app.route('/approve-recipe/<int:recipe_id>')
@login_required
def approve_recipe(recipe_id):
    recipe = Recipe.query.get(recipe_id)
    if recipe:
        recipe.status = 'active'
        db.session.commit()
        add_audit_log(session['admin_id'], 'Recipe Approved', 'recipe', recipe_id,
                      f"Approved recipe: {recipe.name}", request.remote_addr)
        flash(f"Recipe '{recipe.name}' has been approved.", 'success')
    else:
        flash('Recipe not found.', 'error')
    return redirect(url_for('pending_recipes'))

@app.route('/reject-recipe/<int:recipe_id>')
@login_required
def reject_recipe(recipe_id):
    recipe = Recipe.query.get(recipe_id)
    if recipe:
        recipe.status = 'rejected'
        db.session.commit()
        add_audit_log(session['admin_id'], 'Recipe Rejected', 'recipe', recipe_id,
                      f"Rejected recipe: {recipe.name}", request.remote_addr)
        flash(f"Recipe '{recipe.name}' has been rejected.", 'warning')
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
    # leave as sqlite3.Row objects for the public main template (use dict-style there)
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
# USER AUTH (register/login/profile)
# =========================
@app.route("/AllerSafe/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        # Hash password before saving
        password_hash = generate_password_hash(password)

        try:
            conn = sqlite3.connect("user.db", timeout=10)
            conn.execute(
                "INSERT INTO users (username, email, password) VALUES (?,?,?)",
                (username, email, password_hash)
            )
            conn.commit()
            conn.close()
            session["user"] = username
            flash("Registration successful! You can now log in", "success")
            return redirect(url_for("user_main"))
        except sqlite3.IntegrityError:
            flash("This username or email is already registered. Please log in instead.", "error")
            return redirect(url_for("login_user"))

    return render_template("register.html")


@app.route("/AllerSafe/login", methods=["GET", "POST"])
def login_user():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("user.db", timeout=10)
        conn.row_factory = sqlite3.Row
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session["user"] = user["username"]
            flash("Login successful!", "success")
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
    conn.row_factory = sqlite3.Row
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
    return render_template("profile.html", username=session["user"], user=user_data)

@app.route("/AllerSafe/logout")
def logout_user():
    session.pop("user", None)
    return redirect(url_for("main"))

#---------------------------------------FORGOT PASSWORD USER------------------------------------
@app.route("/AllerSafe/forgot_password", methods=["GET", "POST"])
def forgot_password_user():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        
        # Connect directly to user.db
        conn = sqlite3.connect('user.db')
        conn.row_factory = sqlite3.Row
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()
        
        if user:
            return render_template("reset_password_user.html", email=email)
        else:
            flash("Email not found!", "error")
    return render_template('forgot_password_user.html')

@app.route("/AllerSafe/reset_password", methods=["POST"])
def reset_password_user():
    print("=== RESET PASSWORD FUNCTION CALLED ===")
    
    try:
        email = request.form.get("email", "").strip().lower()
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        
        print(f"Email: '{email}'")
        print(f"Passwords match: {new_password == confirm_password}")

        if not email or not new_password or not confirm_password:
            flash("All fields are required!", "error")
            return render_template("reset_password_user.html", email=email)

        if new_password != confirm_password:
            flash("Passwords do not match!", "error")
            return render_template("reset_password_user.html", email=email)
        
        if len(new_password) < 8:
            flash("Password must be at least 8 characters", "error")
            return render_template("reset_password_user.html", email=email)

        password_hash = generate_password_hash(new_password)
        
        # Connect directly to user.db
        conn = sqlite3.connect('user.db')
        conn.row_factory = sqlite3.Row
        
        cursor = conn.execute("UPDATE users SET password = ? WHERE email = ?", 
                            (password_hash, email))
        rows_affected = cursor.rowcount
        conn.commit()
        conn.close()
        
        print(f"Rows affected: {rows_affected}")
        
        if rows_affected == 0:
            flash("User not found!", "error")
            return render_template("reset_password_user.html", email=email)
        
        flash("Password updated successfully. You can now log in.", "success")
        return redirect("/AllerSafe/login")
        
    except Exception as e:
        print(f"ERROR: {e}")
        flash("An error occurred. Please try again.", "error")
        return render_template("reset_password_user.html", email=email)


# =========================
# Contact Me + Complain/Suggest system
# =========================

# ---------------- CONTACT MESSAGES ----------------
class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    subject = db.Column(db.String(200))
    message = db.Column(db.Text, nullable=False)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)

# ---------------- COMPLAINT / SUGGESTION ----------------
class ComplaintSuggestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=True)  # optional, if logged in
    type = db.Column(db.String(50), nullable=False)  # 'complaint' or 'suggestion'
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'reviewed', 'resolved'

with app.app_context():
    db.create_all()

@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        data = {
            "name": request.form["name"],
            "email": request.form["email"],
            "subject": request.form.get("subject", ""),
            "message": request.form["message"]
        }
        save_message("contact_messages", data)
        flash("Your message has been sent!", "success")
        return redirect(url_for("contact"))
    return render_template("contact.html")


@app.route("/complain-suggest", methods=["GET", "POST"])
def complain_suggest():
    if request.method == "POST":
        data = {
            "name": request.form.get("name", "Anonymous"),
            "email": request.form.get("email", ""),
            "subject": request.form["title"],
            "message": request.form["message"]
        }
        save_message("complain_suggest", data)
        flash("Your submission has been sent!", "success")
        return redirect(url_for("complain_suggest"))
    return render_template("complain_suggest.html")


# ---------------------- UPGRADE DB (audit log helper) ----------------------
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

# ---------------------- FORGOT PASSWORD (admin) ----------------------
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        admin = get_admin_by_email(email)

        if admin:
            token = secrets.token_urlsafe(32)
            set_reset_token(email, token)
            reset_url = f"{request.host_url}reset-password/{token}"
            send_reset_email(admin['email'], reset_url)

            flash('Password reset email sent! Please check your inbox.', 'info')
        else:
            flash('Email not found in our system.', 'error')

    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def Admin_reset_password(token):
    if not is_token_valid(token):
        flash('Invalid or expired reset token.', 'error')
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('Admin_reset_password.html', token=token)
        admin = get_admin_by_token(token)
        update_password(admin['id'], password)
        flash('Password reset successfully. You can now login with your new password.', 'success')
        return redirect(url_for('login'))
    return render_template('Admin_reset_password.html', token=token)

# ----------------AUDIT LOG ---------------------
@app.route('/audit-log')
@login_required
def audit_log():
    logs = get_audit_logs()

    # Enrich logs with admin/user info (ensure dicts)
    for log in logs:
        if log.get('admin_id'):
            admin = get_admin_by_id(log['admin_id'])
            log['admin'] = ensure_dict(admin)
        else:
            log['admin'] = None

        if log.get('user_id'):
            user = get_user_by_id(log['user_id'])
            log['user'] = ensure_dict(user)
        else:
            log['user'] = None

    return render_template('audit_log.html', logs=logs)

#------------------------------------- USER MANAGEMENT -------------------------
@app.route('/user-management')
@login_required
def user_management():
    users = get_all_users()  # might be sqlite3.Row list or dict list
    users_fixed = []
    for u in users:
        users_fixed.append(ensure_dict(u) or {})
    return render_template('user_management.html', users=users_fixed)

@app.route('/suspend-user/<int:user_id>')
@login_required
def suspend_user(user_id):
    user = get_user_by_id(user_id)
    if user:
        update_user_status(user_id, 'suspended')
        username = user.get('username') if isinstance(user, dict) else user['username'] if user else 'Unknown'
        add_audit_log(session['admin_id'], 'User Suspended', 'user', user_id,
                      f"Suspended user: {username}", request.remote_addr)
        flash(f"User '{username}' has been suspended.", 'warning')
    else:
        flash('User not found.', 'error')
    return redirect(url_for('user_management'))

@app.route('/activate-user/<int:user_id>')
@login_required
def activate_user(user_id):
    user = get_user_by_id(user_id)
    if user:
        update_user_status(user_id, 'active')
        username = user.get('username') if isinstance(user, dict) else user['username'] if user else 'Unknown'
        add_audit_log(session['admin_id'], 'User Activated', 'user', user_id,
                      f"Activated user: {username}", request.remote_addr)
        flash(f"User '{username}' has been activated.", 'success')
    else:
        flash('User not found.', 'error')
    return redirect(url_for('user_management'))

@app.route('/delete-user/<int:user_id>')
@login_required
def delete_user_route(user_id):
    user = get_user_by_id(user_id)
    if user:
        username = user.get('username') if isinstance(user, dict) else user['username'] if user else 'Unknown'
        delete_user(user_id)
        add_audit_log(session['admin_id'], 'User Deleted', 'user', user_id,
                      f"Deleted user: {username}", request.remote_addr)
        flash(f"User '{username}' has been deleted.", 'success')
    else:
        flash('User not found.', 'error')
    return redirect(url_for('user_management'))

# ---------------------- ENHANCED USER WARNINGS ----------------------
@app.route('/upgrade-warnings-table')
@login_required
def upgrade_warnings_table():
    """Add missing columns to user_warnings table"""
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        # Check current columns
        cursor.execute("PRAGMA table_info(user_warnings)")
        current_columns = [col[1] for col in cursor.fetchall()]
        
        columns_to_add = [
            "resolved INTEGER DEFAULT 0",
            "resolved_at DATETIME", 
            "resolved_by INTEGER",
            "escalated INTEGER DEFAULT 0",
            "escalation_action TEXT",
            "escalation_notes TEXT"
        ]
        
        added_columns = []
        for column_def in columns_to_add:
            column_name = column_def.split()[0]
            if column_name not in current_columns:
                try:
                    conn.execute(f"ALTER TABLE user_warnings ADD COLUMN {column_def}")
                    added_columns.append(column_name)
                except Exception as e:
                    print(f"Error adding {column_name}: {e}")
        
        conn.commit()
        conn.close()
        
        if added_columns:
            flash(f'Added columns to user_warnings: {", ".join(added_columns)}', 'success')
        else:
            flash('All columns already exist in user_warnings table', 'info')
            
    except Exception as e:
        flash(f'Error upgrading table: {e}', 'error')
    
    return redirect(url_for('user_warnings'))

@app.route('/escalate-warning/<int:warning_id>', methods=['POST'])
@login_required
def escalate_warning(warning_id):
    """Escalate a warning with additional actions"""
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        action = data.get('action')
        notes = data.get('notes', '')
        
        # Implement escalation actions
        if action == 'suspend':
            update_user_status(user_id, 'suspended')
            action_text = "User account suspended for 7 days"
        elif action == 'restrict':
            # Add to restricted users table or update user status
            action_text = "User recipe submission restricted"
        elif action == 'notify':
            action_text = "Formal notification sent to user"
        elif action == 'critical':
            action_text = "Marked as critical violation"
        else:
            return jsonify({'success': False, 'error': 'Invalid action'})
        
        # Update warning with escalation info
        conn = sqlite3.connect(DB_NAME)
        conn.execute(
            "UPDATE user_warnings SET escalated = 1, escalation_action = ?, escalation_notes = ? WHERE id = ?",
            (action, notes, warning_id)
        )
        conn.commit()
        conn.close()
        
        add_audit_log(
            admin_id=session['admin_id'],
            action='Warning Escalated',
            target_type='warning',
            target_id=warning_id,
            details=f"Escalated warning for user {user_id}: {action_text}. Notes: {notes}",
            ip_address=request.remote_addr
        )
        
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/user-warnings')
@login_required
def user_warnings():
    """Display user warnings with safe column checking"""
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.row_factory = sqlite3.Row
        
        # First, check what columns actually exist in the table
        cursor = conn.execute("PRAGMA table_info(user_warnings)")
        existing_columns = [col[1] for col in cursor.fetchall()]
        
        # Build a safe query using only existing columns
        base_columns = ["id", "user_id", "admin_id", "guideline_id", "custom_reason", "severity", "created_at"]
        
        # Only include columns that actually exist
        safe_columns = [col for col in base_columns if col in existing_columns]
        
        # Add optional columns if they exist
        optional_columns = ["resolved", "resolved_at", "resolved_by", "escalated", "escalation_action", "escalation_notes"]
        for col in optional_columns:
            if col in existing_columns:
                safe_columns.append(col)
        
        # Build the SELECT query
        columns_str = ", ".join(safe_columns)
        query = f"SELECT {columns_str} FROM user_warnings ORDER BY created_at DESC"
        
        warnings = conn.execute(query).fetchall()
        conn.close()
        
        warnings_fixed = []
        for w in warnings:
            w_dict = dict(w)
            
            # Get user info
            if w_dict.get('user_id'):
                user = get_user_by_id(w_dict['user_id'])
                w_dict['user'] = dict(user) if user else {'username': 'Unknown User'}
                w_dict['username'] = w_dict['user'].get('username', 'Unknown User')
            else:
                w_dict['user'] = {'username': 'Unknown User'}
                w_dict['username'] = 'Unknown User'
            
            # Get admin info
            if w_dict.get('admin_id'):
                admin = get_admin_by_id(w_dict['admin_id'])
                w_dict['admin'] = dict(admin) if admin else {'username': 'System'}
            else:
                w_dict['admin'] = {'username': 'System'}
            
            # Set default values for missing columns
            if 'resolved' not in w_dict:
                w_dict['resolved'] = 0
            if 'escalated' not in w_dict:
                w_dict['escalated'] = 0
            if 'resolved_at' not in w_dict:
                w_dict['resolved_at'] = None
            if 'resolved_by' not in w_dict:
                w_dict['resolved_by'] = None
            if 'escalation_action' not in w_dict:
                w_dict['escalation_action'] = None
            if 'escalation_notes' not in w_dict:
                w_dict['escalation_notes'] = None
            
            warnings_fixed.append(w_dict)
        
        return render_template('user_warnings.html', warnings=warnings_fixed)
        
    except Exception as e:
        flash(f'Error loading warnings: {e}', 'error')
        return render_template('user_warnings.html', warnings=[])

@app.route('/resolve-warning/<int:warning_id>', methods=['POST'])
@login_required
def resolve_warning(warning_id):
    """Mark a warning as resolved"""
    try:
        conn = sqlite3.connect(DB_NAME)
        
        # Check if resolved column exists
        cursor = conn.execute("PRAGMA table_info(user_warnings)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'resolved' in columns:
            conn.execute(
                "UPDATE user_warnings SET resolved = 1, resolved_at = datetime('now'), resolved_by = ? WHERE id = ?",
                (session['admin_id'], warning_id)
            )
        else:
            # Fallback for older schema
            conn.execute(
                "UPDATE user_warnings SET custom_reason = custom_reason || ' [RESOLVED]' WHERE id = ?",
                (warning_id,)
            )
        
        conn.commit()
        conn.close()
        
        add_audit_log(
            admin_id=session['admin_id'],
            action='Warning Resolved',
            target_type='warning',
            target_id=warning_id,
            details=f"Resolved warning ID: {warning_id}",
            ip_address=request.remote_addr
        )
        
        flash('Warning marked as resolved', 'success')
    except Exception as e:
        flash(f'Error resolving warning: {e}', 'error')
    
    return redirect(url_for('user_warnings'))

@app.route('/delete-warning/<int:warning_id>', methods=['POST'])
@login_required
def delete_warning_route(warning_id):
    """Delete a warning"""
    try:
        delete_warning(warning_id)  # Use your existing function
        
        add_audit_log(
            admin_id=session['admin_id'],
            action='Warning Deleted',
            target_type='warning', 
            target_id=warning_id,
            details=f"Deleted warning ID: {warning_id}",
            ip_address=request.remote_addr
        )
        
        flash('Warning deleted successfully', 'success')
    except Exception as e:
        flash(f'Error deleting warning: {e}', 'error')
    
    return redirect(url_for('user_warnings'))


# ---------------------- RECIPE REPORTS ----------------------
@app.route('/report-recipe/<int:recipe_id>', methods=['GET', 'POST'])
def report_recipe(recipe_id):
    """Allow users to report recipes safely"""
    
    def get_user_id_from_session():
        """Get user ID from session if logged in"""
        if 'user' not in session:
            return None
            
        try:
            conn = sqlite3.connect("user.db")
            conn.row_factory = sqlite3.Row
            user = conn.execute(
                "SELECT id FROM users WHERE username = ?", 
                (session['user'],)
            ).fetchone()
            user_id = user['id'] if user else None
            conn.close()
            return user_id
        except sqlite3.Error as e:
            app.logger.error(f"Database error fetching user: {e}")
            return None
    
    def get_active_guidelines():
        """Fetch active guidelines using database.py function"""
        try:
            all_guidelines = get_all_guidelines()  # This fetches from admin_panel.db
            # Filter for active guidelines (is_active = 1)
            active_guidelines = [g for g in all_guidelines if g.get('is_active', 1) == 1]
            return active_guidelines
        except Exception as e:
            app.logger.error(f"Error fetching guidelines: {e}")
            flash("Error loading reporting guidelines.", "danger")
            return []
    
    def validate_report_form(form_data):
        """Validate report form data"""
        errors = []
        
        guideline_id = form_data.get('guideline_id')
        if not guideline_id or not guideline_id.isdigit():
            errors.append("Please select a valid reporting reason.")
        
        description = form_data.get('description', '').strip()
        if len(description) > 1000:
            errors.append("Description must be less than 1000 characters.")
            
        return errors, int(guideline_id) if guideline_id and guideline_id.isdigit() else None, description
    
    def submit_report(recipe_id, user_id, guideline_id, description):
        """Submit the recipe report to admin_panel.db"""
        try:
            conn = sqlite3.connect('admin_panel.db')  # Reports go to admin_panel.db
            conn.execute('''
                INSERT INTO recipe_reports (recipe_id, reporter_id, reason, description, created_at)
                VALUES (?, ?, ?, ?, datetime('now'))
            ''', (recipe_id, user_id, f"Guideline ID: {guideline_id}", description))
            conn.commit()
            conn.close()
            
            # Add audit log entry
            try:
                add_audit_log(
                    admin_id=None,
                    user_id=user_id,
                    action="recipe_reported",
                    target_type="recipe",
                    target_id=recipe_id,
                    details=f"Recipe reported for guideline violation (ID: {guideline_id})"
                )
            except Exception as audit_error:
                app.logger.error(f"Error adding audit log: {audit_error}")
            
            return True
        except sqlite3.Error as e:
            app.logger.error(f"Database error submitting report: {e}")
            flash("Error submitting report. Please try again.", "danger")
            return False
    
    # Main route logic - Use the fixed database function
    recipe = get_recipe_by_id(recipe_id)  # This will now work correctly
    
    if not recipe:
        flash('Recipe not found.', 'danger')
        return redirect(url_for('home'))  # Redirect to a safe page
    
    guidelines = get_active_guidelines()
    
    if request.method == 'POST':
        # Validate form data
        errors, validated_guideline_id, validated_description = validate_report_form(request.form)
        
        if errors:
            for error in errors:
                flash(error, "danger")
        else:
            # Get user ID
            user_id = get_user_id_from_session()
            
            # Submit report
            if submit_report(recipe_id, user_id, validated_guideline_id, validated_description):
                flash('Recipe reported successfully. Thank you for helping keep our community safe.', 'success')
                return redirect(url_for('recipe_details', recipe_id=recipe_id))
    
    return render_template('report_recipe.html', recipe=recipe, guidelines=guidelines)




@app.route('/recipe-reports')  
def recipe_reports():
    """View all recipe reports"""
    try:
        reports = get_all_recipe_reports() # Fetch reports from admin_panel.db
        
        # Enhance the reports with additional info
        enhanced_reports = []
        for report in reports:
            # Get recipe name
            try:
                recipe = get_recipe_by_id(report['recipe_id'])
                report['recipe_name'] = recipe['name'] if recipe else f"Recipe #{report['recipe_id']}"
            except:
                report['recipe_name'] = f"Recipe #{report['recipe_id']}"
            
            # Get reporter username if available
            if report['reporter_id']:
                try:
                    user = get_user_by_id(report['reporter_id'])
                    report['reporter_name'] = user['username'] if user else 'Unknown User'
                except:
                    report['reporter_name'] = 'Unknown User'
            else:
                report['reporter_name'] = 'Anonymous'
            
            # Get admin name if handled
            if report['handled_by']:
                try:
                    admin = get_admin_by_id(report['handled_by'])
                    report['admin_name'] = admin['username'] if admin else 'Unknown Admin'
                except:
                    report['admin_name'] = 'Unknown Admin'
            else:
                report['admin_name'] = None
                
            enhanced_reports.append(report)
        
        return render_template('admin/recipe_reports.html', reports=enhanced_reports)
        
    except Exception as e:
        flash(f'Error loading reports: {e}', 'danger')
        return redirect(url_for('dashboard'))



@app.route('/handle-report/<int:report_id>', methods=['POST'])
@login_required
def handle_report(report_id):
    """Admin handles a recipe report with guideline awareness"""
    action = request.form.get('action')  # 'dismiss', 'remove_recipe', 'warn_user'
    admin_notes = request.form.get('admin_notes', '')

    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row

    # Get report details with guideline info
    report = conn.execute('''
        SELECT r.*, g.title as guideline_title, g.severity as guideline_severity
        FROM recipe_reports r
        LEFT JOIN guidelines g ON r.guideline_id = g.id
        WHERE r.id = ?
    ''', (report_id,)).fetchone()

    if not report:
        conn.close()
        flash('Report not found.', 'danger')
        return redirect(url_for('recipe_reports'))

    # Update report status
    conn.execute('''
        UPDATE recipe_reports
        SET status = 'handled', handled_by = ?, action_taken = ?
        WHERE id = ?
    ''', (session['admin_id'], action, report_id))
    conn.commit()

    # Handle recipe suspension automatically for critical guideline
    if report['guideline_severity'] == 'critical' or action == 'remove_recipe':
        recipe_id = report['recipe_id']
        recipe = get_recipe_by_id(recipe_id)
        if recipe and recipe['status'] != 'suspended':
            update_recipe_status(recipe_id, 'suspended')

    # Optional: warn user if chosen
    if action == 'warn_user' and report['reporter_id']:
        add_user_warning(
            user_id=report['reporter_id'],
            admin_id=session['admin_id'],
            guideline_id=report['guideline_id'],
            custom_reason=f"Admin noted: {admin_notes}" if admin_notes else None,
            severity=report['guideline_severity'] or 'warning'
        )

    conn.close()

    # Add audit log entry
    guideline_info = f"Guideline: {report['guideline_title']}" if report['guideline_title'] else "No guideline"
    add_audit_log(
        admin_id=session['admin_id'],
        action='Recipe Report Handled',
        target_type='report',
        target_id=report_id,
        details=f"Handled report with action: {action}. {guideline_info}. Notes: {admin_notes}",
        ip_address=request.remote_addr
    )

    flash(f'Report handled successfully with action: {action}', 'success')
    return redirect(url_for('recipe_reports'))

# ---------------------- GUIDELINES ----------------------
@app.route('/guideline-management')
@login_required
def guideline_management():
    """Display guidelines management"""
    guidelines = get_all_guidelines()
    guidelines_fixed = [ensure_dict(g) or {} for g in guidelines]
    return render_template('guideline_management.html', guidelines=guidelines_fixed)

@app.route('/add-edit-guideline', methods=['GET', 'POST'])
@app.route('/add-edit-guideline/<int:guideline_id>', methods=['GET', 'POST'])
@login_required
def add_edit_guideline(guideline_id=None):
    """Add or edit a guideline"""
    guideline = None
    if guideline_id:
        guideline = get_guideline_by_id(guideline_id)
        if not guideline:
            flash('Guideline not found', 'error')
            return redirect(url_for('guideline_management'))
        guideline = ensure_dict(guideline) or {}

    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        category = request.form.get('category')
        severity = request.form.get('severity')

        if guideline_id:
            update_guideline(guideline_id, title, content, category, severity)
            add_audit_log(session['admin_id'], 'Guideline Updated', 'guideline', guideline_id,
                          f"Updated guideline: {title}", request.remote_addr)
            flash('Guideline updated successfully.', 'success')
        else:
            new_id = insert_guideline(title, content, category, severity)
            add_audit_log(session['admin_id'], 'Guideline Created', 'guideline', new_id,
                          f"Created guideline: {title}", request.remote_addr)
            flash('Guideline created successfully.', 'success')

        return redirect(url_for('guideline_management'))

    return render_template('add_edit_guideline.html', guideline=guideline)

@app.route('/delete-guideline/<int:guideline_id>')
@login_required
def delete_guideline_route(guideline_id):
    """Delete a guideline"""
    guideline = get_guideline_by_id(guideline_id)
    if guideline:
        guideline = ensure_dict(guideline) or {}
        delete_guideline(guideline_id)
        add_audit_log(session['admin_id'], 'Guideline Deleted', 'guideline', guideline_id,
                      f"Deleted guideline: {guideline.get('title', 'Unknown')}", request.remote_addr)
        flash('Guideline deleted successfully.', 'success')
    else:
        flash('Guideline not found.', 'error')
    return redirect(url_for('guideline_management'))

@app.route('/toggle-guideline/<int:guideline_id>', methods=['POST'])
@login_required
def toggle_guideline(guideline_id):
    """Toggle guideline active/inactive status"""
    guideline = get_guideline_by_id(guideline_id)
    if guideline:
        guideline = ensure_dict(guideline) or {}
        current_status = guideline.get('is_active')

        # Handle various stored types
        if isinstance(current_status, str):
            current_active = current_status.lower() in ('1', 'true', 'yes', 'active')
        elif isinstance(current_status, int):
            current_active = bool(current_status)
        else:
            current_active = bool(current_status)

        new_status = not current_active
        new_status_value = 1 if new_status else 0

        toggle_guideline_status(guideline_id, new_status_value)

        status_text = "activated" if new_status else "deactivated"
        add_audit_log(session['admin_id'], f'Guideline {status_text.title()}',
                      'guideline', guideline_id,
                      f"{status_text.title()} guideline: {guideline.get('title', 'Unknown')}",
                      request.remote_addr)

        flash(f"Guideline '{guideline.get('title', 'Unknown')}' has been {status_text}.", 'success')
    else:
        flash('Guideline not found.', 'error')

    return redirect(url_for('guideline_management'))

# ---------------------- RECIPE MANAGEMENT ACTIONS ----------------------
@app.route('/suspend-recipe/<int:recipe_id>')
@login_required
def suspend_recipe(recipe_id):
    """Suspend a recipe"""
    recipe = get_recipe_by_id(recipe_id)
    if recipe:
        recipe_title = recipe.get('title') or recipe.get('name') or 'Unknown'
        update_recipe_status(recipe_id, 'suspended')
        add_audit_log(session['admin_id'], 'Recipe Suspended', 'recipe', recipe_id,
                      f"Suspended recipe: {recipe_title}", request.remote_addr)
        flash(f"Recipe '{recipe_title}' has been suspended.", 'warning')
    else:
        flash('Recipe not found.', 'error')
    return redirect(url_for('recipe_management'))


@app.route('/activate-recipe/<int:recipe_id>')
@login_required
def activate_recipe(recipe_id):
    """Activate a recipe"""
    recipe = get_recipe_by_id(recipe_id)
    if recipe:
        recipe_title = recipe.get('title') or recipe.get('name') or 'Unknown'
        update_recipe_status(recipe_id, 'active')
        add_audit_log(session['admin_id'], 'Recipe Activated', 'recipe', recipe_id,
                      f"Activated recipe: {recipe_title}", request.remote_addr)
        flash(f"Recipe '{recipe_title}' has been activated.", 'success')
    else:
        flash('Recipe not found.', 'error')
    return redirect(url_for('recipe_management'))

@app.route('/AllerSafe/submit-recipe', methods=['GET', 'POST'])
def user_submit_recipe():
    """Users submit recipes for approval"""
    if request.method == 'POST':
        name = request.form['name']
        allergens = request.form['allergens']
        instruction = request.form['instruction']

        # Get user ID
        conn = sqlite3.connect("user.db")
        conn.row_factory = sqlite3.Row
        user = conn.execute("SELECT id FROM users WHERE username = ?", (session.get('user'),)).fetchone()
        conn.close()

        # Handle photo upload
        photo = request.files.get('photo')
        photo_filename = None
        if photo and allowed_file(photo.filename):
            filename = secure_filename(photo.filename)
            photo_filename = filename
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            photo.save(filepath)

            # Resize image
            max_size = (350, 350)
            img = Image.open(filepath)
            img.thumbnail(max_size)
            img.save(filepath)

        # Save recipe with pending status
        recipe = Recipe(
            name=name,
            allergens=allergens,
            instruction=instruction,
            photo=photo_filename,
            status='pending',
            author_id=user['id'] if user else None
        )
        db.session.add(recipe)
        db.session.commit()

        # Add ingredients
        ingredients = request.form.get('ingredients', '').split("\n")
        for ing in ingredients:
            if ing.strip():
                parts = ing.split("-", 1)
                ingredient_name = parts[0].strip()
                measurement = parts[1].strip() if len(parts) > 1 else None
                db.session.add(Ingredient(recipe_id=recipe.id, name=ingredient_name, measurement=measurement))
        db.session.commit()

        flash('Recipe submitted for approval! You will be notified once it\'s reviewed.', 'success')
        return redirect(url_for('user_main'))

    return render_template("submit_recipe.html")

@app.route('/submit-recipe', methods=['GET', 'POST'])
def submit_recipe():
    # This route is a stub in your original: keep placeholder if you extend
    prep_time = request.form.get('prep_time') if request.method == 'POST' else None
    cook_time = request.form.get('cook_time') if request.method == 'POST' else None
    servings = request.form.get('servings') if request.method == 'POST' else None
    difficulty = request.form.get('difficulty') if request.method == 'POST' else None
    return redirect(url_for('recipe_management'))

# ---------------------- RUN ----------------------
if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)  
    
