from flask import Flask, render_template , render_template, redirect, url_for
import sqlite3
from models import init_db
from auth import auth_bp
from audit import audit_bp

app = Flask(__name__)

@app.route('/admin')
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/admin/users')
def view_users():
    conn = sqlite3.connect('allergy_app.db')   # connect database
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")      # fetch all users
    users = cursor.fetchall()
    conn.close()
    return render_template('view_users.html', users=users)

@app.route('/admin/recipes')
def view_recipes():
    conn = sqlite3.connect('allergy_app.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM recipes")    # fetch all recipes
    recipes = cursor.fetchall()
    conn.close()
    return render_template('view_recipes.html', recipes=recipes)

if __name__ == "__main__":
    app.run(debug=True)
