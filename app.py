from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3

app = Flask(__name__)
app.secret_key = "secret123" #untuk session

# function to connect to db
def get_db_connection():
    conn = sqlite3.connect("user.db", timeout=10)  # TAMBAH TIMEOUT 10S
    conn.row_factory = sqlite3.Row
    return conn

# Home page - redirect ke main page 
@app.route("/AllerSafe/")
def index():
    # terus redirect ke main page
    return redirect(url_for("main"))

# GUEST MAIN PAGE - ACCESS WITHOUT LOGIN
@app.route("/AllerSafe/main")
def main():
    return render_template("main.html")


# USER MAIN PAGE
@app.route("/AllerSafe/user_main")
def user_main():
    if "user" not in session:
        return redirect(url_for("login"))  # block kalau belum login
    return render_template("user_main.html", username=session["user"])


# register new user
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
            flash("Registration succesful! You can now log in", "succes")
            return redirect(url_for("user_main")) #lepas daftar pergi user_main

        except sqlite3.IntegrityError:
            flash("This username or email is already registered. Please log in instead.", "error")
            return redirect(url_for("register"))

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
            return redirect(url_for("user_main"))  # lepas login pergi user_main page
        else:
            flash("Invalid username or password!", "erroe") # <--- guna flash --->
            return redirect(url_for("user_main")) #tetap kat login page even ada salah
    
    return render_template("login.html")

# USER PROFILE
@app.route("/AllerSafe/profile", methods=["GET", "POST"])
def profile():
    if "user" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    user_data = conn.execute("SELECT * FROM users WHERE username = ?", (session["user"],)).fetchone()
    conn.close()

    if request.method == "POST":
        #ambil nama baru dari form
        new_name = request.form.get("name")
        if new_name and new_name != session["user"]:
            
            #update terus ke database
            conn = get_db_connection()
            conn.execute("UPDATE users SET username = ? WHERE username = ?", (new_name, session["user"]))
            conn.commit()
            conn.close()

            # update sessipn supaya nama baru ditunjuk
            session["user"] = new_name 

    return render_template("profile.html", username=session["user"])


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

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()

        if user:
            #terus render reset_password page dengan email
             return render_template("reset_password.html", email=email)
        else:
            return "Email not found! <a href='/AllerSafe/forgot_password'>Try again</a>"

    return render_template("forgot_password.html")


# reset password
@app.route("/AllerSafe/reset_password", methods=["POST"])
def reset_password():
    email = request.form["email"]
    new_password = request.form["new_password"]
    confirm_password = request.form["confirm_password"]

    if new_password != confirm_password:
        return "PASSWORD DO NOT MATCH! <a href='/AllerSafe/forgot_password'>Try again</a>"
    
    conn = get_db_connection()
    conn.execute("UPDATE users SET password = ? WHERE email = ?", (new_password, email))
    conn.commit()
    conn.close()

    return redirect(url_for("login"))

# ADMIN LOGIN (PART AIN)
@app.route("/AllerSafe/admin_login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        # ambil username and password dari form
        username = request.form["username"]
        password = request.form["password"]

        #untuk test wak dummy check je dulu
        if username == "admin" and password == "admin123":
            session["admin"] = username
            return f"Admin '{username}' logged in successfully! <a href='{url_for('main')}'>Go back</a>"
        else:
            return "Invalid admin credential! <a href='/AllerSafe/admin_login'>Try again</a>"

     # GET request - render admin_login.html
    return render_template("admin_login.html")


print("=== ROUTES AVAILABLE ===")
for rule in app.url_map.iter_rules():
    print(rule)
# run app
if __name__ == "__main__":
    app.run(debug=True)
