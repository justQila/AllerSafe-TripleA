from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy   #LIBRARY

app=Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///recipe.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db=SQLAlchemy(app)

class Recipe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    allergen_free = db.Column(db.String(100), nullable=False)
    instruction = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Float, default=0)

    ingredients = db.relationship('Ingredient', backref='recipe', cascade="all, delete")

class Ingredient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    recipe_id = db.Column(db.Integer, db.ForeignKey('recipe.id'),nullable=False)
    name = db.Column(db.String(100), nullable=False)
    measurement = db.Column(db.String(50), nullable=False)

with app.app_context(): #SAMPLE DATA IF EMPTY
    db.create_all()

with app.app_context():
    if Recipe.query.count()==0:
        recipe1 = Recipe(
            name = "Quinoa & Roasted Veggie Salad",
            allergen_free = "Gluten, Dairy, Nut, Egg ",
            instruction = "1. Cook quinoa.\n2. Roast zucchini and bell pepper in olive oil until soft.\n3. Season with salt, pepper, and olive oil ",
            rating = 4.9
        )
        
        db.session.add(recipe1)
        db.session.commit()

        ingredients = [
            Ingredient(recipe_id=recipe1.id, name="Quinoa", measurement="1 cup"),
            Ingredient(recipe_id=recipe1.id, name="Bell pepper", measurement="2, sliced"),
            Ingredient(recipe_id=recipe1.id, name="Zucchini", measurement="1, diced"),
            Ingredient(recipe_id=recipe1.id, name="Cherry Tomatoes", measurement="1 cup"),
            Ingredient(recipe_id=recipe1.id, name="Olive Oil", measurement="2, tbsp"),
        ]
        db.session.add_all(ingredients)
        db.session.commit()

@app.route('/')
def home():
    recipes = Recipe.query.all()
    return render_template("recipes.html", recipe=recipes)

@app.route('/recipe/<int:recipe_id>')
def recipe_details(recipe_id):
    recipe = Recipe.query.get_or_404(recipe_id)
    return render_template("recipe_details.html", reciep=recipe)

if __name__ == '__main__':
    app.run(debug=True)