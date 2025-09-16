from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3

app = Flask(__name__)
app.secret_key = "secret123" #untuk session

# function to connect to db
def get_db_connection():
    conn = sqlite3.connect("user.db")
    conn.row_factory = sqlite3.Row
    return conn

# Home page - redirect ke main page 
@app.route("/AllerSafe/")
def index():
    # terus redirect ke main page
    return redirect(url_for("main"))

# main page with recipe popup - boleh acces without login
@app.route("/AllerSafe/main")
def main():
    return render_template("main.html")

# view all user macam senarai user la
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

        return redirect(url_for("main")) #lepas daftar pergi main

    return render_template("register.html")

# login 
@app.route("/AllerSafe/login", methods=["GET", "POST"])
def login():
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
            return redirect(url_for("main"))  # lepas login pergi main page
        else:
            return "Invalid username or password! <a href='/AllerSafe/login'>Try again</a>"
    
    return render_template("login.html")

#logout
@app.route("/AllerSafe/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("main")) #lepas logout pergi main page

    
# forgot password
@app.route("/AllerSafe/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]
        print(f"PASSWORD RESET REQUESTED FOR: {email}")
        return "IF THIS EMAIL EXISTS, RESET INSTRUCTIONS HAVE BEEN SENT!"

    return render_template("forgot_password.html")

print("=== ROUTES AVAILABLE ===")
for rule in app.url_map.iter_rules():
    print(rule)
# run app
if __name__ == "__main__":
    app.run(debug=True)
