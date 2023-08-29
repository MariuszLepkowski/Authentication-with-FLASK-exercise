from select import select

from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']

#configure Flask app to use Flask_Login
login_manager = LoginManager()
login_manager.init_app(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['SQLALCHEMY_DATABASE_URI']
db = SQLAlchemy()
db.init_app(app)


# CREATE TABLE IN DB
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


with app.app_context():
    db.create_all()

class CustomUser(UserMixin):
    def __init__(self, user_id):
        self.id = user_id


#create a user_loader callback
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Hashing and salting the password entered by the user
        hash_and_salted_password = generate_password_hash(
            request.form.get('password'),
            method='pbkdf2:sha256',
            salt_length=8
        )
        # Storing the hashed password in our database
        new_user = User(
            email=request.form.get('email'),
            name=request.form.get('name'),
            password=hash_and_salted_password,
        )

        db.session.add(new_user)
        db.session.commit()

        return render_template("secrets.html", name=request.form.get('name'))

    return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    email = request.form.get("email")
    password = request.form.get("password")
    user = User.query.filter_by(email=email).first()

    if request.method == 'POST' and user:
        if check_password_hash(password=password, pwhash=user.password):
            user = CustomUser(user_id=user.id)
            login_user(user)
            return redirect(url_for("secrets"))
        else:
            return "Login failed!"
    else:
        return "The user does not exist."

    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    user = current_user
    return render_template("secrets.html", user=user)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    return send_from_directory('static', path="files/cheat_sheet.pdf")


if __name__ == "__main__":
    app.run(debug=True)
