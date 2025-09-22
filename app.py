# ---------------BACKEND------------------

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
import os
from werkzeug.utils import secure_filename
from PIL import Image
import sqlite3
import secrets
from functools import wraps
from database import *

# ---------------- FLASK APP ----------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'

# ---------------- SQLALCHEMY DB (Recipes) ----------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(BASE_DIR, "recipe.db")
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)

# ---------------- MODELS ----------------
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

    if Recipe.query.count() == 0:
        recipe1 = Recipe(
            name="Quinoa & Roasted Veggie Salad",
            allergens="gluten, dairy, nut, egg",
            instruction="1. Cook quinoa.\n2. Roast zucchini and bell pepper.\n3. Season with salt, pepper, and olive oil",
            rating=4.9,
            photo=None
        )
        db.session.add(recipe1)
        db.session.commit()

        ingredients = [
            Ingredient(recipe_id=recipe1.id, name="Quinoa", measurement="1 cup"),
            Ingredient(recipe_id=recipe1.id, name="Bell pepper", measurement="2, sliced"),
            Ingredient(recipe_id=recipe1.id, name="Zucchini", measurement="1, diced"),
            Ingredient(recipe_id=recipe1.id, name="Cherry Tomatoes", measurement="1 cup"),
            Ingredient(recipe_id=recipe1.id, name="Olive Oil", measurement="2 tbsp"),
        ]
        db.session.add_all(ingredients)
        db.session.commit()

# ---------------- HELPERS ----------------
def recipe_contains_allergen(recipe: Recipe, selected_allergy: str) -> bool:
    if not recipe.allergens:
        return False
    allergens_list = [a.strip().lower() for a in recipe.allergens.split(",")]
    return any(selected_allergy.strip().lower() in allergen for allergen in allergens_list)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ---------------- ROUTES (Recipes) ----------------
@app.route('/', methods=['GET'])
def home():
    selected = request.args.getlist("allergy")
    recipes = Recipe.query.all()

    if selected:
        recipes = [
            r for r in recipes
            if not any(recipe_contains_allergen(r, allergy) for allergy in selected)
        ]

    return render_template("recipes.html", recipes=recipes, selected=selected)

@app.route('/recipe/<int:recipe_id>')
def recipe_details(recipe_id):
    recipe = Recipe.query.get_or_404(recipe_id)
    return render_template("recipe_details.html", recipe=recipe)

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

        ingredients = request.form['ingredients'].split("\n")
        for ing in ingredients:
            if ing.strip():
                parts = ing.split("-", 1)
                name = parts[0].strip()
                measurement = parts[1].strip() if len(parts) > 1 else None
                db.session.add(Ingredient(recipe_id=recipe.id, name=name, measurement=measurement))
        db.session.commit()
        return redirect(url_for('home'))
    return render_template("add_recipe.html")

# =========================
# DATABASE CONNECTION (User) =========================
def get_db_connection():
    conn = sqlite3.connect("user.db", timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

# =========================
# USER SYSTEM =========================
@app.route("/AllerSafe/")
def index():
    return redirect(url_for("main"))

@app.route("/AllerSafe/main")
def main():
    return render_template("main.html")

@app.route("/AllerSafe/user_main")
def user_main():
    if "user" not in session:
        return redirect(url_for("login_user"))
    return render_template("user_main.html", username=session["user"])

@app.route("/AllerSafe/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        try:
            conn = get_db_connection()
            conn.execute(
                "INSERT INTO users (username, email, password) VALUES (?,?,?)",
                (username, email, password)
            )
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

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? AND password = ?",
            (username, password)
        ).fetchone()
        conn.close()

        if user:
            session["user"] = user["username"]
            return redirect(url_for("user_main"))
        else:
            flash("Invalid username or password!", "error")
            return redirect(url_for("login_user"))
    return render_template("login.html")

@app.route("/AllerSafe/profile", methods=["GET", "POST"])
def profile():
    if "user" not in session:
        return redirect(url_for("login_user"))

    conn = get_db_connection()
    user_data = conn.execute("SELECT * FROM users WHERE username = ?", (session["user"],)).fetchone()
    conn.close()

    if request.method == "POST":
        new_name = request.form.get("name")
        if new_name and new_name != session["user"]:
            conn = get_db_connection()
            conn.execute("UPDATE users SET username = ? WHERE username = ?", (new_name, session["user"]))
            conn.commit()
            conn.close()
            session["user"] = new_name
    return render_template("profile.html", username=session["user"])

@app.route("/AllerSafe/logout")
def logout_user():
    session.pop("user", None)
    return redirect(url_for("main"))

@app.route("/AllerSafe/forgot_password", methods=["GET", "POST"])
def forgot_password_user():
    if request.method == "POST":
        email = request.form["email"]

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()

        if user:
            return render_template("reset_password.html", email=email)
        else:
            return "Email not found! <a href='/AllerSafe/forgot_password'>Try again</a>"
    return render_template("forgot_password.html")

@app.route("/AllerSafe/reset_password", methods=["POST"])
def reset_password_user():
    email = request.form["email"]
    new_password = request.form["new_password"]
    confirm_password = request.form["confirm_password"]

    if new_password != confirm_password:
        return "PASSWORDS DO NOT MATCH! <a href='/AllerSafe/forgot_password'>Try again</a>"
    
    conn = get_db_connection()
    conn.execute("UPDATE users SET password = ? WHERE email = ?", (new_password, email))
    conn.commit()
    conn.close()
    return redirect(url_for("login_user"))

# =========================
# ADMIN SYSTEM =========================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login_admin'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login_admin():
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
            
            add_audit_log(admin['id'], 'login', ip_address=request.remote_addr)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout_admin():
    add_audit_log(session['admin_id'], 'logout', ip_address=request.remote_addr)
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login_admin'))

@app.route('/dashboard')
@login_required
def dashboard():
    admin = get_admin_by_id(session['admin_id'])
    conn = get_db_connection()
    user_count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    recipe_count = conn.execute('SELECT COUNT(*) FROM recipes').fetchone()[0]
    active_users = conn.execute('SELECT COUNT(*) FROM users WHERE status = "active"').fetchone()[0]
    conn.close()
    logs = get_audit_logs(limit=5)
    return render_template('dashboard.html',
                          admin=admin,
                          user_count=user_count,
                          recipe_count=recipe_count,
                          active_users=active_users,
                          logs=logs)

@app.route('/audit-log')
@login_required
def audit_log():
    logs = get_audit_logs()
    return render_template('audit_log.html', logs=logs)

# =========================
# RUN APP
# =========================
if __name__ == '__main__':
    init_db()  # from database.py
    app.run(debug=True)