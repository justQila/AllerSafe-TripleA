from flask import Blueprint, request, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from models import get_db, log_action

auth_bp = Blueprint('auth', __name__)

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        db = get_db()
        admin = db.execute("SELECT * FROM admins WHERE username=?",
                           (username,)).fetchone()

        if admin and check_password_hash(admin["password"], password):
            # store session
            session["admin_id"] = admin["admin_key"]
            session["role"] = "admin"

            log_action(admin["admin_key"], "admin", "Logged in")
            return redirect(url_for("audit.dashboard"))

        return "Invalid credentials."

    return '''
    <form method="POST">
        <input name="username" placeholder="Username">
        <input name="password" type="password" placeholder="Password">
        <button type="submit">Login</button>
    </form>
    '''

@auth_bp.route("/logout")
def logout():
    if "admin_id" in session:
        log_action(session["admin_id"], "admin", "Logged out")
    session.clear()
    return redirect(url_for("auth.login"))
