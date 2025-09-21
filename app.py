# ---------------BACKEND------------------

from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
import re

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///./recipe.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ---------------- MODELS ----------------
class Recipe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    allergens = db.Column(db.String(200), nullable=False, default="")
    instruction = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Float, default=0.0)
    ingredients = db.relationship('Ingredient', backref='recipe', cascade="all, delete-orphan")

class Ingredient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    recipe_id = db.Column(db.Integer, db.ForeignKey('recipe.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    measurement = db.Column(db.String(50))

with app.app_context():
    db.create_all()

    if Recipe.query.count() == 0:
        recipe1 = Recipe(
            name="Quinoa & Roasted Veggie Salad",
            allergens="gluten, dairy, nut, egg",
            instruction="1. Cook quinoa.\n2. Roast zucchini and bell pepper.\n3. Season with salt, pepper, and olive oil",
            rating=4.9
        )
        db.session.add(recipe1)
        db.session.commit()

        ingredients = [
            Ingredient(recipe_id=recipe1.id, name="Quinoa", measurement="1 cup"),
            Ingredient(recipe_id=recipe1.id, name="Bell pepper", measurement="2, sliced"),
            Ingredient(recipe_id=recipe1.id, name="Zucchini", measurement="1, diced"),
            Ingredient(recipe_id=recipe1.id, name="Cherry Tomatoes", measurement="1 cup"),
            Ingredient(recipe_id=recipe1.id, name="Olive Oil", measurement="2 tbsp"),
        ]
        db.session.add_all(ingredients)
        db.session.commit()

# ---------------- HELPERS ----------------
def recipe_contains_allergen(recipe: Recipe, selected_allergy: str) -> bool:
    if not recipe.allergens:
        return False
    allergens_list = [a.strip().lower() for a in recipe.allergens.split(",")]
    return any(selected_allergy.strip().lower() in allergen for allergen in allergens_list)


# ---------------- ROUTES ----------------
@app.route('/', methods=['GET'])
def home():
    selected = request.args.getlist("allergy")
    recipes = Recipe.query.all()

    if selected:
        recipes = [
            r for r in recipes
            if not any(recipe_contains_allergen(r, allergy) for allergy in selected)
        ]

    return render_template("recipes.html", recipes=recipes, selected=selected)


@app.route('/recipe/<int:recipe_id>')
def recipe_details(recipe_id):
    recipe = Recipe.query.get_or_404(recipe_id)
    return render_template("recipe_details.html", recipe=recipe)


@app.route('/add', methods = ['GET', 'POST'])
def add_recipe():
    if request.method == 'POST':
        name = request.form ['name']
        allergens = request.form['allergens']
        instruction = request.form['instruction']
        rating = float(request.form['rating']) if request.form['rating'] else 0.0

        recipe = Recipe(
            name=name,
            allergens=allergens,
            instruction=instruction,
            rating=rating
        )
        db.session.add(recipe)
        db.session.commit()

        ingredients = request.form['ingredients'].split("\n")
        for ing in ingredients:
            if ing.strip():
                parts = ing.split("-" , 1)
                name = parts[0].strip()
                measurement = parts[1].strip() if len(parts) > 1 else None
                db.session.add(Ingredient(recipe_id=recipe.id,name=name,measurement=measurement))
        db.session.commit()
        return redirect(url_for('home'))
    return render_template("add_recipe.html")

if __name__ == '__main__':
    app.run(debug=True)