from flask import Flask, render_template, request, redirect, url_for
import sqlite3

app = Flask(__name__)

# function to connect to db
def get_db_connection():
    conn = sqlite3.connect("user.db")
    conn.row_factory = sqlite3.Row
    return conn

# Home page
@app.route("/AllerSafe/")
def index():
    # terus redirect ke register page
    return redirect(url_for("register"))

# view all user
@app.route("/AllerSafe/users")
def users():
    conn = get_db_connection()
    users = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    return render_template("user.html", users=users)

# register new user
@app.route("/AllerSafe/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        conn = get_db_connection()
        conn.execute(
            "INSERT INTO users (username, email, password) VALUES (?,?,?)",
            (username, email, password)
        )
        conn.commit()
        conn.close()

        return redirect(url_for("users")) #lepas daftar pergi list users

    return render_template("register.html")

# forgot password
@app.route("/AllerSafe/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]

        #dummy action: print email
        #nanti boleh tambah logic cari dalam DB and reset password
        print(f"PASSWORD RESET REQUESTED FOR: {email}")

        return "IF THIS EMAIL EXISTS, RESET INSTRUCTIONS HAVE BEEN SENT!"

    return render_template("forgot_password.html")

# run app
if __name__ == "__main__":
    app.run(debug=True)
