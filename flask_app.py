from flask import Flask, redirect, render_template, request, url_for, session, Response
from flask_sqlalchemy import SQLAlchemy
import flask
from flask import jsonify, flash
import os
from flask_bcrypt import Bcrypt
from flask_bcrypt import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired
import flask_login
from flask_login  import LoginManager, UserMixin, login_required, login_user, logout_user
from wtforms import Form, BooleanField, StringField, PasswordField, validators, SubmitField




app = Flask(__name__)
app.config.update(
    DEBUG = True,
    SECRET_KEY = 'thatmysecret'
)
bcrypt = Bcrypt(app)

# flask-login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


SQLALCHEMY_DATABASE_URI = "mysql+mysqlconnector://{username}:{password}@{hostname}/{databasename}".format(
    username="Kireta",
    password="@Mdpdepasse2468",
    hostname="Kireta.mysql.pythonanywhere-services.com",
    databasename="Kireta$tesserakt",
)
app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_POOL_RECYCLE"] = 299
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
bcrypt = Bcrypt(app)

db = SQLAlchemy(app)

SECRET_KEY = os.getenv("SECRET_KEY")

class LoginForm(FlaskForm):
    email = StringField('email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

class UserData(db.Model):

    __tablename__ = "userdata"

    id = db.Column(db.Integer, primary_key=True)
    id_exercice = db.Column(db.Integer)
    mail = db.Column(db.String(255))
    date_start = db.Column(db.DateTime)
    date_end = db.Column(db.DateTime)


class User(db.Model, UserMixin):
    def __init__(self, emailUser, userPassword):
        self.email = emailUser
        self.password = userPassword
        isAdmin = 0
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True) # primary keys are required by SQLAlchemy
    email = db.Column(db.String(100))
    password = db.Column(db.String(100))
    isAdmin = db.Column(db.Integer)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True) # primary keys are required by SQLAlchemy
    email = db.Column(db.String(100))
    status = db.Column(db.String(100))

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if request.method == 'POST':
        userEmail = form.email.data
        password = form.password.data
        user=User.query.filter_by(email=userEmail).first()
        if bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return render_template('infos.html')
        else:
            return jsonify('erreur: 401')
    else:
        return render_template('login.html', form=form)

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if request.method == 'POST':
        userEmail = form.email.data
        password = form.password.data
        user=User.query.filter_by(email=userEmail).first()
        if user is None:
            user = User(userEmail, bcrypt.generate_password_hash(password))
            db.session.add(user)
            db.session.commit()
            return render_template('infos.html')
        else:
            return jsonify('erreur: 401')
    else:
        return render_template('register.html', form=form)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return Response('<p>Logged out</p>')

@app.errorhandler(401)
def page_not_found(e):
    return Response('<p>Login failed</p>')

@login_manager.user_loader
def load_user(userEmail):
    user=User.query.filter_by(email=userEmail).first()
    return user

@app.route('/protected')
@flask_login.login_required
def protected():
    return 'Logged in as: ' + flask_login.current_user.id

@login_manager.unauthorized_handler
def unauthorized_handler():
    return 'Unauthorized'

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/setUserDataByMail", methods=["GET", "POST"])
def setUserDataByMail():
    json_data = flask.request.json
    user_mail = json_data['mail']
    password = json_data['password']
    userdata = json_date['userdata']
    user=User.query.filter_by(mail=user_mail).first()
    if(user.verify_password(password)):
        return jsonify('c\'est okay')


