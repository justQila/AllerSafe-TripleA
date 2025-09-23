from flask import Flask, render_template, request, redirect, url_for, flash, session
from functools import wraps
from database import *
from dotenv import load_dotenv
import os
import secrets

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'FishyyFishhiodhwqhdqid190e71eu'

# ---------------------- LOGIN REQUIRED DECORATOR ----------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('Admin_login'))  
        return f(*args, **kwargs)
    return decorated_function

# ---------------------- ROUTES ----------------------

@app.route('/')
def home():
    return redirect(url_for('Admin_login'))

@app.route('/Admin-login', methods=['GET', 'POST'])
def Admin_login():  # Changed from 'login' to 'Admin_login'
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
    return redirect(url_for('Admin_login'))

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
        add_audit_log(session['admin_id'], 'User Suspended', 'user', user_id, 
                      f"Suspended user: {user['username']}", request.remote_addr)
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
        add_audit_log(session['admin_id'], 'User Activated', 'user', user_id, 
                      f"Activated user: {user['username']}", request.remote_addr)
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
        add_audit_log(session['admin_id'], 'User Deleted', 'user', user_id, 
                      f"Deleted user: {user['username']}", request.remote_addr)
        flash(f"User {user['username']} has been deleted.", 'success')
    else:
        flash('User not found.', 'error')
    return redirect(url_for('user_management'))

# ---------------------- RECIPE MANAGEMENT ACTIONS ----------------------

@app.route('/suspend-recipe/<int:recipe_id>')
@login_required
def suspend_recipe(recipe_id):
    """Suspend a recipe"""
    recipe = get_recipe_by_id(recipe_id)
    if recipe:
        update_recipe_status(recipe_id, 'suspended')
        add_audit_log(session['admin_id'], 'Recipe Suspended', 'recipe', recipe_id, 
                      f"Suspended recipe: {recipe['title']}", request.remote_addr)
        flash(f"Recipe '{recipe['title']}' has been suspended.", 'warning')
    else:
        flash('Recipe not found.', 'error')
    return redirect(url_for('recipe_management'))

@app.route('/activate-recipe/<int:recipe_id>')
@login_required
def activate_recipe(recipe_id):
    """Activate a recipe"""
    recipe = get_recipe_by_id(recipe_id)
    if recipe:
        update_recipe_status(recipe_id, 'active')
        add_audit_log(session['admin_id'], 'Recipe Activated', 'recipe', recipe_id, 
                      f"Activated recipe: {recipe['title']}", request.remote_addr)
        flash(f"Recipe '{recipe['title']}' has been activated.", 'success')
    else:
        flash('Recipe not found.', 'error')
    return redirect(url_for('recipe_management'))

# ---------------------- RECIPE MANAGEMENT ----------------------

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

# ----------------------- ALLERGY MANAGEMENT ----------------------
@app.route('/allergy-management')
@login_required
def allergy_management():
    """Admin manages allergy master data"""
    allergies = get_all_allergies()
    return render_template('allergy_management.html', allergies=allergies)

@app.route('/manage-recipe-allergies/<int:recipe_id>')
@login_required
def manage_recipe_allergies(recipe_id):
    """Manage allergies for a specific recipe"""
    recipe = get_recipe_by_id(recipe_id)
    if not recipe:
        flash('Recipe not found.', 'error')
        return redirect(url_for('recipe_management'))
    
@app.route('/manage-recipe-allergies/<int:recipe_id>')
@login_required  
def manage_recipe_allergies(recipe_id):
    """Admin assigns allergies when approving recipes"""
    recipe = get_recipe_by_id(recipe_id)
    all_allergies = get_all_allergies()
    recipe_allergies = get_recipe_allergies(recipe_id) 
    recipe_allergy_ids = [a['id'] for a in recipe_allergies]
    
    return render_template('manage_recipe_allergies.html', 
                         recipe=recipe, 
                         all_allergies=all_allergies,
                         recipe_allergy_ids=recipe_allergy_ids)

# ---------------------- PENDING RECIPES ----------------------

@app.route('/pending-recipes')
@login_required
def pending_recipes():
    """Display recipes pending approval"""
    recipes = get_pending_recipes()
    
    # Get author information for each recipe
    for recipe in recipes:
        if recipe.get('author_id'):
            author = get_user_by_id(recipe['author_id'])
            recipe['author'] = author if author else {'username': 'Unknown'}
        else:
            recipe['author'] = {'username': 'Unknown'}
        
        # Add category mock data since your template expects it
        recipe['category'] = {'name': recipe.get('category', 'Uncategorized')}
        
        # Mock ingredients for template
        ingredients = recipe.get('ingredients', '')
        recipe['ingredients'] = ingredients.split(',') if ingredients else []
    
    return render_template('pending_recipes.html', recipes=recipes)

@app.route('/approve-recipe/<int:recipe_id>')
@login_required
def approve_recipe(recipe_id):
    """Approve a pending recipe"""
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
    """Reject a pending recipe"""
    recipe = get_recipe_by_id(recipe_id)
    if recipe:
        update_recipe_status(recipe_id, 'rejected')
        add_audit_log(session['admin_id'], 'Recipe Rejected', 'recipe', recipe_id, 
                      f"Rejected recipe: {recipe['title']}", request.remote_addr)
        flash(f"Recipe '{recipe['title']}' has been rejected.", 'warning')
    else:
        flash('Recipe not found.', 'error')
    return redirect(url_for('pending_recipes'))

@app.route('/view-recipe/<int:recipe_id>')
@login_required
def view_recipe(recipe_id):
    """View recipe details for review"""
    recipe = get_recipe_by_id(recipe_id)
    if not recipe:
        flash('Recipe not found.', 'error')
        return redirect(url_for('pending_recipes'))
    
    # Get author info
    if recipe.get('author_id'):
        author = get_user_by_id(recipe['author_id'])
        recipe['author'] = author if author else {'username': 'Unknown'}
    else:
        recipe['author'] = {'username': 'Unknown'}
    
    # Get allergies for this recipe
    allergies = get_recipe_allergies(recipe_id)
    recipe['allergies'] = allergies
    
    return render_template('view_recipe.html', recipe=recipe)

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
            add_audit_log(session['admin_id'], 'User Warning Issued', 'user', user_id, 
                          f"Warned user {user['username']}: {reason}", request.remote_addr)
            flash(f"User {user['username']} has been warned.", 'success')
            return redirect(url_for('user_management'))
        else:
            flash('Please select a guideline or provide a custom reason.', 'error')
    return render_template('warn_user.html', user=user, guidelines=guidelines)

@app.route('/user-warnings')
@login_required
def user_warnings():
    """Display user warnings"""
    warnings = get_all_warnings()
    
    # Get user and admin info for each warning
    for warning in warnings:
        if warning.get('user_id'):
            user = get_user_by_id(warning['user_id'])
            warning['user'] = user if user else {'username': 'Unknown'}
        
        if warning.get('admin_id'):
            admin = get_admin_by_id(warning['admin_id'])
            warning['admin'] = admin if admin else {'username': 'Unknown'}
    
    return render_template('user_warnings.html', warnings=warnings)

# ---------------------- GUIDELINES ----------------------

@app.route('/guideline-management')
@login_required
def guideline_management():
    """Display guidelines management"""
    guidelines = get_all_guidelines()
    return render_template('guideline_management.html', guidelines=guidelines)

@app.route('/add-edit-guideline', methods=['GET', 'POST'])
@app.route('/add-edit-guideline/<int:guideline_id>', methods=['GET', 'POST'])
@login_required
def add_edit_guideline(guideline_id=None):
    """Add or edit a guideline"""
    guideline = None
    if guideline_id:
        guideline = get_guideline_by_id(guideline_id)
        if not guideline:
            flash('Guideline not found.', 'error')
            return redirect(url_for('guideline_management'))
    
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
        delete_guideline(guideline_id)
        add_audit_log(session['admin_id'], 'Guideline Deleted', 'guideline', guideline_id, 
                      f"Deleted guideline: {guideline['title']}", request.remote_addr)
        flash('Guideline deleted successfully.', 'success')
    else:
        flash('Guideline not found.', 'error')
    return redirect(url_for('guideline_management'))

# ---------------------- RECIPE REPORTS ----------------------

@app.route('/recipe-reports')
@login_required
def recipe_reports():
    """Display recipe reports"""
    reports = get_all_recipe_reports()
    return render_template('recipe_reports.html', reports=reports)

# ---------------------- AUDIT LOG ----------------------

@app.route('/audit-log')
@login_required
def audit_log():
    """Display complete audit log - both admin and user actions"""
    logs = get_audit_logs(limit=200)  # Increased limit for better overview
    
    # Get admin/user info for each log entry
    for log in logs:
        if log.get('admin_id'):
            admin = get_admin_by_id(log['admin_id'])
            log['admin'] = admin if admin else {'username': 'Unknown Admin'}
            log['user'] = None
        elif log.get('user_id'):
            user = get_user_by_id(log['user_id'])
            log['user'] = user if user else {'username': 'Unknown User'}
            log['admin'] = None
        else:
            log['admin'] = None
            log['user'] = None
    
    return render_template('audit_log.html', logs=logs)

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

@app.route('/Admin-forgot-password', methods=['GET', 'POST'])  
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        admin = get_admin_by_email(email)
        
        if admin:
            token = secrets.token_urlsafe(32)
            set_reset_token(email, token)
            reset_url = f"{request.host_url}Admin-reset-password/{token}" 
            
            # Send email via SendGrid
            send_reset_email(admin['email'], reset_url)
            
            flash('Password reset email sent! Please check your inbox.', 'info')
        else:
            flash('Email not found in our system.', 'error')
    
    return render_template('forgot_password.html')

@app.route('/Admin-reset-password/<token>', methods=['GET', 'POST'])
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
        return redirect(url_for('Admin_login'))  
    return render_template('Admin_reset_password.html', token=token) 

# ---------------------- RUN ----------------------
if __name__ == '__main__':
    init_db()
    app.run(debug=True)
