from flask import Flask, render_template, request, redirect, url_for, flash, session
from functools import wraps
from database import *
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = 'CatLuvTun123'

# ---------------------- LOGIN REQUIRED DECORATOR ----------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ---------------------- ROUTES ----------------------

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
            add_audit_log(admin['id'], 'login', ip_address=request.remote_addr)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    add_audit_log(session['admin_id'], 'logout', ip_address=request.remote_addr)
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

# ---------------------- USER MANAGEMENT ----------------------

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
        add_audit_log(session['admin_id'], 'suspend_user', 'user', user_id, f"Suspended user: {user['username']}", request.remote_addr)
        flash(f"User {user['username']} has been suspended.", 'success')
    else:
        flash('User not found.', 'error')
    return redirect(url_for('user_management'))

@app.route('/activate-user/<int:user_id>')
@login_required
def activate_user(user_id):
    user = get_user_by_id(user_id)
    if user:
        update_user_status(user_id, 'active')
        add_audit_log(session['admin_id'], 'activate_user', 'user', user_id, f"Activated user: {user['username']}", request.remote_addr)
        flash(f"User {user['username']} has been activated.", 'success')
    else:
        flash('User not found.', 'error')
    return redirect(url_for('user_management'))

@app.route('/delete-user/<int:user_id>')
@login_required
def delete_user_route(user_id):
    user = get_user_by_id(user_id)
    if user:
        delete_user(user_id)
        add_audit_log(session['admin_id'], 'delete_user', 'user', user_id, f"Deleted user: {user['username']}", request.remote_addr)
        flash(f"User {user['username']} has been deleted.", 'success')
    else:
        flash('User not found.', 'error')
    return redirect(url_for('user_management'))

# ---------------------- RECIPE MANAGEMENT ----------------------

@app.route('/recipe-management')
@login_required
def recipe_management():
    allergy_filter = request.args.get('allergy_filter', 'all')
    exclude_allergy = request.args.get('exclude', '0') == '1'

    if allergy_filter and allergy_filter != 'all':
        allergy_id = int(allergy_filter)
        recipes = get_recipes_without_allergy(allergy_id) if exclude_allergy else get_recipes_by_allergy(allergy_id)
    else:
        recipes = get_all_recipes()

    recipe_list = list(recipes)
    recipe_ids = [recipe['id'] for recipe in recipe_list]
    recipe_allergies_map = get_allergies_for_recipes(recipe_ids)
    allergies = get_all_allergies()
    return render_template('recipe_management.html', recipes=recipe_list,
                           allergies=allergies, selected_allergy=allergy_filter,
                           exclude_allergy=exclude_allergy, recipe_allergies_map=recipe_allergies_map)

@app.route('/approve-recipe/<int:recipe_id>')
@login_required
def approve_recipe_route(recipe_id):
    recipe = get_recipe_by_id(recipe_id)
    if recipe:
        approve_recipe(recipe_id)
        add_audit_log(session['admin_id'], 'approve_recipe', 'recipe', recipe_id, f"Approved recipe: {recipe['title']}", request.remote_addr)
        flash(f"Recipe '{recipe['title']}' has been approved.", 'success')
    else:
        flash('Recipe not found.', 'error')
    return redirect(url_for('recipe_management'))

@app.route('/reject-recipe/<int:recipe_id>', methods=['GET', 'POST'])
@login_required
def reject_recipe_route(recipe_id):
    recipe = get_recipe_by_id(recipe_id)
    if not recipe:
        flash('Recipe not found.', 'error')
        return redirect(url_for('recipe_management'))
    if request.method == 'POST':
        reason = request.form.get('reason', 'No reason provided')
        reject_recipe(recipe_id, reason)
        flash(f"Recipe '{recipe['title']}' has been rejected.", 'success')
        return redirect(url_for('recipe_management'))
    return render_template('reject_recipe.html', recipe=recipe)

# ---------------------- USER WARNINGS ----------------------

@app.route('/warn-user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def warn_user(user_id):
    user = get_user_by_id(user_id)
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('user_management'))

    guidelines = get_all_guidelines()
    if request.method == 'POST':
        guideline_id = request.form.get('guideline_id')
        custom_reason = request.form.get('custom_reason')
        severity = request.form.get('severity', 'warning')
        if guideline_id or custom_reason:
            add_user_warning(user_id, session['admin_id'], guideline_id, custom_reason, severity)
            reason = custom_reason if custom_reason else f"Violated guideline: {get_guideline_by_id(guideline_id)['title']}"
            add_audit_log(session['admin_id'], 'warn_user', 'user', user_id, f"Warned user {user['username']}: {reason}", request.remote_addr)
            flash(f"User {user['username']} has been warned.", 'success')
            return redirect(url_for('user_management'))
        else:
            flash('Please select a guideline or provide a custom reason.', 'error')
    return render_template('warn_user.html', user=user, guidelines=guidelines)

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

# ---------------------- RUN ----------------------
if __name__ == '__main__':
    init_db()
    app.run(debug=True)
