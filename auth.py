from flask import Blueprint, request, session, redirect, url_for
from models import get_db, log_action

auth_bp = Blueprint('auth', __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=? AND password=?",
                          (username, password)).fetchone()

        if user:
            session["user_id"] = user["id"]
            session["role"] = user["role"]

            log_action(user["id"], user["role"], "Logged in")
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
    if "user_id" in session:
        log_action(session["user_id"], session["role"], "Logged out")
    session.clear()
    return redirect(url_for("auth.login"))
