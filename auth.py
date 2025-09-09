from flask import Blueprint, request, session, redirect, url_for, render_template, flash
from werkzeug.security import check_password_hash, generate_password_hash
from model import get_db, log_action
import secrets
import string

auth_bp = Blueprint("auth", __name__, template_folder="templates")

def generate_secure_password(length=12):
    """Generate a secure random password"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

# ---------------- LOGIN ---------------- #
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        admin_key = request.form.get("admin_key", "").strip()

        # Input validation
        if not all([username, password, admin_key]):
            flash("All fields are required.", "danger")
            return render_template("login.html")

        db = get_db()
        admin = db.execute(
            "SELECT * FROM admins WHERE username=?",
            (username,)
        ).fetchone()

        if admin and check_password_hash(admin["password"], password) and str(admin["admin_key"]) == admin_key:
            # Store session
            session["admin_id"] = admin["admin_key"]
            session["username"] = admin["username"]
            session["role"] = admin.get("role", "admin")

            # Log successful login
            log_action(admin["admin_key"], session["role"], "Logged in")
            db.commit()  # Ensure audit log is saved
            
            flash("Login successful!", "success")
            return redirect(url_for("audit.dashboard"))
        else:
            # Log failed login attempt
            if admin:  # Username exists but wrong password/key
                log_action(admin["admin_key"], "admin", f"Failed login attempt from IP: {request.remote_addr}")
                db.commit()
            
            flash("Invalid credentials or admin key.", "danger")

    return render_template("login.html")


# ---------------- FORGOT PASSWORD ---------------- #
@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        secret_code = request.form.get("secret_code", "").strip()

        # Input validation
        if not all([username, secret_code]):
            flash("All fields are required.", "warning")
            return render_template("forgot_password.html")

        db = get_db()
        admin = db.execute(
            "SELECT * FROM admins WHERE username=? AND secret_code=?",
            (username, secret_code)
        ).fetchone()

        if admin:
            # Generate secure random password
            new_password = generate_secure_password()
            hashed_pw = generate_password_hash(new_password)

            # Update password and mark as temporary
            db.execute(
                "UPDATE admins SET password=?, temp_password=1 WHERE username=?",
                (hashed_pw, username)
            )
            db.commit()

            # Log password reset
            log_action(admin["admin_key"], "admin", "Password reset via secret code")
            
            # In production, send this via email instead of flash message
            flash(f"Password reset successful. Check your email for the new password.", "success")
            # TODO: Send email with new_password instead of flashing it
            # For now, you might log it securely or use a different method
            print(f"SECURE: New password for {username}: {new_password}")  # Remove in production
        else:
            # Log failed reset attempt
            log_action(None, "guest", f"Failed password reset attempt for username: {username} from IP: {request.remote_addr}")
            db.commit()
            flash("Invalid username or secret code.", "warning")

    return render_template("forgot_password.html")


# ---------------- CHANGE PASSWORD (for temporary passwords) ---------------- #
@auth_bp.route("/change-password", methods=["GET", "POST"])
def change_password():
    if "admin_id" not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for("auth.login"))
    
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        
        # Input validation
        if not all([current_password, new_password, confirm_password]):
            flash("All fields are required.", "danger")
            return render_template("change_password.html")
        
        if new_password != confirm_password:
            flash("New passwords do not match.", "danger")
            return render_template("change_password.html")
        
        if len(new_password) < 8:
            flash("Password must be at least 8 characters long.", "danger")
            return render_template("change_password.html")
        
        db = get_db()
        admin = db.execute(
            "SELECT * FROM admins WHERE admin_key=?",
            (session["admin_id"],)
        ).fetchone()
        
        if admin and check_password_hash(admin["password"], current_password):
            hashed_pw = generate_password_hash(new_password)
            db.execute(
                "UPDATE admins SET password=?, temp_password=0 WHERE admin_key=?",
                (hashed_pw, session["admin_id"])
            )
            db.commit()
            
            log_action(session["admin_id"], session["role"], "Changed password")
            flash("Password changed successfully.", "success")
            return redirect(url_for("audit.dashboard"))
        else:
            flash("Current password is incorrect.", "danger")
    
    return render_template("change_password.html")


# ---------------- LOGOUT ---------------- #
@auth_bp.route("/logout")
def logout():
    if "admin_id" in session:
        db = get_db()
        log_action(session["admin_id"], session.get("role", "admin"), "Logged out")
        db.commit()  # Ensure audit log is saved
    
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("auth.login"))
