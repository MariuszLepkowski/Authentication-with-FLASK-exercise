import sqlalchemy.exc
from flask import Flask, render_template, request, url_for, redirect, send_from_directory, get_flashed_messages
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

# create a user_loader callback
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    try:
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

            return render_template("secrets.html", user=new_user)

    except sqlalchemy.exc.IntegrityError:
        return redirect(url_for('login', error="registration"))

    return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    flashed_error = get_flashed_messages(category_filter=["error"])

    if request.args.get('error') == 'registration':
        error = "You've already signed up with that email. Log in instead."

    if request.method == 'POST':
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()

        if user:
            if check_password_hash(password=password, pwhash=user.password):
                login_user(user)
                return redirect(url_for("secrets"))
            else:
                error = "Wrong password!"
        else:
            error = "The email does not exist. Please try again."
    return render_template("login.html", error=error, flashed_error=flashed_error)


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
