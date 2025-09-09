import os
from functools import wraps
from flask import Flask, render_template, session, redirect, url_for, flash, g
from model import init_db, get_db, close_db
from auth import auth_bp
from audit import audit_bp

app = Flask(__name__)

# ---------------- SECURITY CONFIGURATION ---------------- #
# Use environment variable for secret key (more secure)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
if app.secret_key == 'dev-key-change-in-production' and not app.debug:
    raise ValueError("Must set SECRET_KEY environment variable in production!")

# Security headers
@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# ---------------- DATABASE TEARDOWN ---------------- #
@app.teardown_appcontext
def close_db_handler(error):
    """Close database connection at end of request"""
    close_db(error)

# ---------------- AUTHENTICATION DECORATOR ---------------- #
def login_required(f):
    """Decorator to require login for protected routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login'))
        
        role = session.get('role', '')
        if role != 'admin':
            flash('Admin access required.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# ---------------- REGISTER BLUEPRINTS ---------------- #
app.register_blueprint(auth_bp, url_prefix="/auth")
app.register_blueprint(audit_bp, url_prefix="/audit")

# ---------------- MAIN ROUTES ---------------- #
@app.route("/")
def index():
    if 'admin_id' in session:
        return redirect(url_for('admin_dashboard'))
    return render_template('index.html')

# ---------------- ADMIN DASHBOARD ---------------- #
@app.route("/admin")
@admin_required
def admin_dashboard():
    """Main admin dashboard with overview"""
    try:
        db = get_db()
        
        # Get some basic stats for dashboard
        user_count = db.execute("SELECT COUNT(*) as count FROM users").fetchone()['count'] if table_exists('users') else 0
        recipe_count = db.execute("SELECT COUNT(*) as count FROM recipes").fetchone()['count'] if table_exists('recipes') else 0
        
        stats = {
            'users': user_count,
            'recipes': recipe_count,
            'admin_name': session.get('username', 'Admin')
        }
        
        return render_template("admin_dashboard.html", stats=stats)
    except Exception as e:
        flash(f"Error loading dashboard: {str(e)}", "danger")
        return render_template("admin_dashboard.html", stats={'users': 0, 'recipes': 0})

@app.route("/admin/users")
@admin_required
def view_users():
    """View all users"""
    try:
        db = get_db()
        if not table_exists('users'):
            flash("Users table doesn't exist yet.", "info")
            return render_template("view_users.html", users=[])
            
        users = db.execute("SELECT * FROM users").fetchall()
        return render_template("view_users.html", users=users)
    except Exception as e:
        flash(f"Error loading users: {str(e)}", "danger")
        return render_template("view_users.html", users=[])

@app.route("/admin/recipes")
@admin_required
def view_recipes():
    """View all recipes"""
    try:
        db = get_db()
        if not table_exists('recipes'):
            flash("Recipes table doesn't exist yet.", "info")
            return render_template("view_recipes.html", recipes=[])
            
        recipes = db.execute("SELECT * FROM recipes").fetchall()
        return render_template("view_recipes.html", recipes=recipes)
    except Exception as e:
        flash(f"Error loading recipes: {str(e)}", "danger")
        return render_template("view_recipes.html", recipes=[])

# ---------------- UTILITY FUNCTIONS ---------------- #
def table_exists(table_name):
    """Check if a table exists in the database."""
    db = get_db()
    result = db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,)
    ).fetchone()
    return result is not None

# ---------------- ERROR HANDLERS ---------------- #
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('errors/500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('errors/403.html'), 403

# Simple error templates if you don't have error template files:
# @app.errorhandler(404)
# def not_found_error(error):
#     return "<h1>404 - Page Not Found</h1><a href='/'>Go Home</a>", 404

# @app.errorhandler(500)
# def internal_error(error):
#     return "<h1>500 - Internal Server Error</h1><a href='/'>Go Home</a>", 500

# ---------------- DEVELOPMENT HELPERS ---------------- #
@app.context_processor
def inject_user():
    """Make current user info available in all templates"""
    return {
        'current_user': {
            'id': session.get('admin_id'),
            'username': session.get('username'),
            'role': session.get('role')
        } if 'admin_id' in session else None
    }

if __name__ == "__main__":
    with app.app_context():
        init_db()
        
    # Debug: print all registered routes
    if app.debug:
        print("\n" + "="*50)
        print("REGISTERED ROUTES:")
        print("="*50)
        for rule in app.url_map.iter_rules():
            methods = ','.join(sorted(rule.methods - {'HEAD', 'OPTIONS'}))
            print(f"{rule.endpoint:30} {methods:10} {rule.rule}")
        print("="*50 + "\n")

    # Security warning for development
    if app.debug and app.secret_key == 'dev-key-change-in-production':
        print("⚠️  WARNING: Using development secret key. Set SECRET_KEY environment variable for production!")
    
    app.run(debug=True)
