from flask import Flask, render_template, request, redirect, url_for, flash, session
import secrets
from functools import wraps
from database import *

app = Flask(__name__)
app.config['SECRET_KEY'] = 'CatLuvTun123'

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

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
            
            # Add to audit log
            add_audit_log(admin['id'], 'login', ip_address=request.remote_addr)
                
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

#temperory login user page
@app.route('/temp-user-login')
def temp_user_login():
    """Temporary user login page for demonstration"""
    return render_template('temp_user_login.html')

@app.route('/logout')
@login_required
def logout():
    # Add to audit log
    add_audit_log(session['admin_id'], 'logout', ip_address=request.remote_addr)
    
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    admin = get_admin_by_id(session['admin_id'])

    # Get stats for dashboard
    with sqlite3.connect('admin_panel.db') as conn:
        conn.row_factory = sqlite3.Row
        user_count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        recipe_count = conn.execute('SELECT COUNT(*) FROM recipes').fetchone()[0]
        active_users = conn.execute('SELECT COUNT(*) FROM users WHERE status = "active"').fetchone()[0]

    # Get recent audit logs
    logs = get_audit_logs(limit=5)

    return render_template(
        'dashboard.html',
        admin=admin,
        user_count=user_count,
        recipe_count=recipe_count,
        active_users=active_users,
        logs=logs
    )

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
        
        # Add to audit log
        add_audit_log(
            session['admin_id'], 
            'suspend_user', 
            'user', 
            user_id, 
            f"Suspended user: {user['username']}",
            request.remote_addr
        )
        
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
        
        # Add to audit log
        add_audit_log(
            session['admin_id'], 
            'activate_user', 
            'user', 
            user_id, 
            f"Activated user: {user['username']}",
            request.remote_addr
        )
        
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
        
        # Add to audit log
        add_audit_log(
            session['admin_id'], 
            'delete_user', 
            'user', 
            user_id, 
            f"Deleted user: {user['username']}",
            request.remote_addr
        )
        
        flash(f"User {user['username']} has been deleted.", 'success')
    else:
        flash('User not found.', 'error')
    
    return redirect(url_for('user_management'))

@app.route('/recipe-management')
@login_required
def recipe_management():
    # Handle allergy filter from the query string
    allergy_filter = request.args.get('allergy_filter', 'all')
    exclude_allergy = request.args.get('exclude', '0') == '1'

    # Fetch recipes based on the filter
    if allergy_filter and allergy_filter != 'all':
        allergy_id = int(allergy_filter)
        if exclude_allergy:
            recipes = get_recipes_without_allergy(allergy_id)
        else:
            recipes = get_recipes_by_allergy(allergy_id)
    else:
        recipes = get_all_recipes()
    
    # Convert recipes to list if it's not already (sqlite3.Row objects)
    recipe_list = list(recipes)
    
    # Get a list of all recipe IDs from the filtered recipes
    recipe_ids = [recipe['id'] for recipe in recipe_list]

    # Batch-fetch all allergies for all these recipes
    recipe_allergies_map = get_allergies_for_recipes(recipe_ids)

    allergies = get_all_allergies()
    
    return render_template(
        'recipe_management.html',
        recipes=recipe_list,
        allergies=allergies,
        selected_allergy=allergy_filter,
        exclude_allergy=exclude_allergy,
        recipe_allergies_map=recipe_allergies_map  # Pass the pre-calculated data!
    )
    
@app.route('/suspend-recipe/<int:recipe_id>')
@login_required
def suspend_recipe(recipe_id):
    recipe = get_recipe_by_id(recipe_id)
    if recipe:
        update_recipe_status(recipe_id, 'suspended')
        
        # Add to audit log
        add_audit_log(
            session['admin_id'], 
            'suspend_recipe', 
            'recipe', 
            recipe_id, 
            f"Suspended recipe: {recipe['title']}",
            request.remote_addr
        )
        
        flash(f"Recipe '{recipe['title']}' has been suspended.", 'success')
    else:
        flash('Recipe not found.', 'error')
    
    return redirect(url_for('recipe_management'))

@app.route('/activate-recipe/<int:recipe_id>')
@login_required
def activate_recipe(recipe_id):
    recipe = get_recipe_by_id(recipe_id)
    if recipe:
        update_recipe_status(recipe_id, 'active')
        
        # Add to audit log
        add_audit_log(
            session['admin_id'], 
            'activate_recipe', 
            'recipe', 
            recipe_id, 
            f"Activated recipe: {recipe['title']}",
            request.remote_addr
        )
        
        flash(f"Recipe '{recipe['title']}' has been activated.", 'success')
    else:
        flash('Recipe not found.', 'error')
    
    return redirect(url_for('recipe_management'))

@app.route('/delete-recipe/<int:recipe_id>')
@login_required
def delete_recipe_route(recipe_id):
    recipe = get_recipe_by_id(recipe_id)
    if recipe:
        delete_recipe(recipe_id)
        
        # Add to audit log
        add_audit_log(
            session['admin_id'], 
            'delete_recipe', 
            'recipe', 
            recipe_id, 
            f"Deleted recipe: {recipe['title']}",
            request.remote_addr
        )
        
        flash(f"Recipe '{recipe['title']}' has been deleted.", 'success')
    else:
        flash('Recipe not found.', 'error')
    
    return redirect(url_for('recipe_management'))


@app.route('/manage-recipe-allergies/<int:recipe_id>', methods=['GET', 'POST'])
@login_required
def manage_recipe_allergies(recipe_id):
    recipe = get_recipe_by_id(recipe_id)
    if not recipe:
        flash('Recipe not found.', 'error')
        return redirect(url_for('recipe_management'))
    
    if request.method == 'POST':
        try:
            # Use a single connection for the entire transaction
            with sqlite3.connect('admin_panel.db') as conn:
                conn.row_factory = sqlite3.Row
                
                selected_allergies = request.form.getlist('allergies')
                
                # Step 1: Remove all existing allergies for this recipe
                conn.execute('DELETE FROM recipe_allergies WHERE recipe_id = ?', (recipe_id,))
                
                # Step 2: Add selected allergies in a single batch
                allergy_data = [(recipe_id, int(allergy_id)) for allergy_id in selected_allergies]
                if allergy_data:
                    conn.executemany(
                        'INSERT INTO recipe_allergies (recipe_id, allergy_id) VALUES (?, ?)',
                        allergy_data
                    )
                

                conn.commit()
            
            add_audit_log(
                session['admin_id'], 
                'update_recipe_allergies', 
                'recipe', 
                recipe_id, 
                f"Updated allergies for recipe: {recipe['title']}",
                request.remote_addr
            )
            
            flash('Recipe allergies updated successfully.', 'success')
            return redirect(url_for('recipe_management'))
        
        except Exception as e:
            flash(f'An error occurred: {e}', 'error')
            print(f"Error in manage_recipe_allergies: {e}")
            return redirect(url_for('manage_recipe_allergies', recipe_id=recipe_id))
    
    # GET request - show form
    all_allergies = get_all_allergies()
    recipe_allergies = get_recipe_allergies(recipe_id)
    recipe_allergy_ids = [allergy['id'] for allergy in recipe_allergies]
    
    return render_template('manage_allergies.html', recipe=recipe, 
                         all_allergies=all_allergies, recipe_allergy_ids=recipe_allergy_ids)

@app.template_filter('groupby')
def groupby_filter(items, attribute):
    """Jinja2 filter to group items by an attribute"""
    from itertools import groupby
    from operator import itemgetter
    
    # Convert SQLite Row objects to dictionaries
    items = [dict(item) for item in items]
    
    # Sort by the attribute first
    items.sort(key=itemgetter(attribute))
    
    # Group by the attribute
    grouped = {}
    for key, group in groupby(items, key=itemgetter(attribute)):
        grouped[key] = list(group)
    
    return grouped.items()

@app.route('/audit-log')
@login_required
def audit_log():
    logs = get_audit_logs()
    return render_template('audit_log.html', logs=logs)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        admin = get_admin_by_email(email)
        
        if admin:
            token = secrets.token_urlsafe(32)
            set_reset_token(email, token)
            
            # In a real application, you would send an email here
            reset_url = f"{request.host_url}reset-password/{token}"
            flash(f'Password reset link: {reset_url}', 'info')
            flash('In a real application, this would be sent via email.', 'info')
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

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        admin = get_admin_by_id(session['admin_id'])
        
        if not verify_password(current_password, admin['password_hash']):
            flash('Current password is incorrect.', 'error')
        elif new_password != confirm_password:
            flash('New passwords do not match.', 'error')
        else:
            update_password(admin['id'], new_password)
            
            # Add to audit log
            add_audit_log(
                session['admin_id'], 
                'change_password', 
                ip_address=request.remote_addr
            )
            
            flash('Password changed successfully.', 'success')
            return redirect(url_for('dashboard'))
    
    return render_template('change_password.html')


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
