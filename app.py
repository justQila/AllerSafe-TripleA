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

# initialize the admin database when the app starts (functions live in database.py)
with app.app_context():
    init_db()
    db.create_all()

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

    # Stats (using DB_NAME from database.py)
    with sqlite3.connect(DB_NAME) as conn:
        conn.row_factory = sqlite3.Row
        user_count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        recipe_count = conn.execute('SELECT COUNT(*) FROM recipes').fetchone()[0]
        active_users = conn.execute('SELECT COUNT(*) FROM users WHERE status="active"').fetchone()[0]

    logs = get_audit_logs(limit=5)
    return render_template('dashboard.html', admin=admin, user_count=user_count,
                           recipe_count=recipe_count, active_users=active_users, logs=logs)

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

@app.route('/allergy-management')
@login_required
def allergy_management():
    """Admin manages allergy master data"""
    allergies = get_all_allergies()
    # ensure dicts for template safety
    allergies_fixed = [ensure_dict(a) or {} for a in allergies]
    return render_template('allergy_management.html', allergies=allergies_fixed)

@app.route('/manage-recipe-allergies/<int:recipe_id>')
@login_required
def manage_recipe_allergies(recipe_id):
    """Admin assigns allergies when approving recipes"""
    recipe = get_recipe_by_id(recipe_id)
    recipe = ensure_dict(recipe) or {}
    all_allergies = get_all_allergies()
    recipe_allergies = get_recipe_allergies(recipe_id)
    recipe_allergy_ids = [a['id'] for a in recipe_allergies] if recipe_allergies else []
    return render_template('manage_recipe_allergies.html',
                           recipe=recipe,
                           all_allergies=[ensure_dict(a) or {} for a in all_allergies],
                           recipe_allergy_ids=recipe_allergy_ids)

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
