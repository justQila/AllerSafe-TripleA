from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import secrets
from functools import wraps
from database import *

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'

# =========================
# DATABASE CONNECTION (User)
# =========================
def get_db_connection():
    conn = sqlite3.connect("user.db", timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

# =========================
# USER SYSTEM (Aqilah)
# =========================
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
# RUN APP
# =========================
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
