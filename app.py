from flask import Flask, render_template, request

app = Flask(__name__)

# Home route → shows the homepage with filter pop-up
@app.route('/')
def home():
    return render_template("index.html")  #loads templates/index.html

# Route for filtering recipes
@app.route('/filter', methods=['POST'])
def filter_recipes():
    selected_allergies = request.form.getlist("allergies")
    print("Selected allergies:", selected_allergies)
    return render_template("recipes.html", allergies=selected_allergies)

if __name__ == '__main__':
    app.run(debug=True)