A simple web application for Admin Panel built with Flask for backend logic, SQLite3 for database management, and HTML templates for rendering the user interface.
It includes authentication, sessions, and basic database operations through database.py.

SET UP
Clone the respository
git clone <your-repo-link>
cd <your-project-folder>

Create Visual Environment
python -m venv venv
# Activate it:
# On Mac/Linux
source venv/bin/activate
# On Windows
venv\Scripts\activate

Install dependency
pip install -r requirements.txt

initialize the database
python -c "import database; database.init_db()"

run the application
flask run
or
python app.py

Open in Browser
👉 Go to: http://127.0.0.1:5000/

Project Structure
project-folder/
│── app.py              # Main Flask app  
│── database.py         # Database setup & queries  
│── templates/          # HTML templates  
│── static/             # CSS, JS, images (optional)  
│── requirements.txt    # Python dependencies  
│── README.md           # Project documentation  

r
