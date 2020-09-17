from flask import Flask, redirect, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
from flask import jsonify, flash
import jwt
import os
import hashlib
from flask_bcrypt import Bcrypt
from flask_bcrypt import generate_password_hash, check_password_hash
from wtforms import Form, BooleanField, StringField, PasswordField, validators

app = Flask(__name__)
app.config["DEBUG"] = True

app.secret_key = 'thatsmysikritki'

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

class UserData(db.Model):

    __tablename__ = "userdata"

    id = db.Column(db.Integer, primary_key=True)
    id_exercice = db.Column(db.Integer)
    mail = db.Column(db.String(255))
    date_start = db.Column(db.DateTime)
    date_end = db.Column(db.DateTime)

class User(db.Model):

    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    mail = db.Column(db.String(255))
    password = db.Column(db.String(255))
    token = db.Column(db.String(255))

    def __init__(self, mail, password):
        self.mail = mail
        self.password = password

    def hash_password(self):
        self.password = generate_password_hash(self.password).decode('utf8')

    def check_password(self, password):
        return check_password_hash(self.password, password)

class RegistrationForm(Form):
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email Address', [validators.Length(min=6, max=35)])
    password = PasswordField('New Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')
    accept_tos = BooleanField('I accept the TOS', [validators.DataRequired()])

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/getToken/<user_mail>")
def getTokenWithMail(user_mail):
    user=User.query.filter_by(mail=user_mail).first()
    id = user.id
    return jsonify(encode_auth_token(id))

@app.route("/setUserDataByMail", methods=["GET", "POST"])
def setUserDataByMail():
    json_data = flask.request.json
    user_mail = json_data['mail']
    password = json_data['password']
    userdata = json_date['userdata']
    user=User.query.filter_by(mail=user_mail).first()
    if(user.verify_password(password)):
        return jsonify('c\'est okay')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        user = User(form.email.data, form.password.data)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('register.html', form=form)

def encode_auth_token(user_id):
    """
    Generates the Auth Token
    :return: string
    """
    try:
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=5),
            'iat': datetime.datetime.utcnow(),
            'sub': user_id
        }
        return jwt.encode(
            payload,
            SECRET_KEY,
            algorithm='HS256'
        )
    except Exception as e:
        return e

@staticmethod
def decode_auth_token(auth_token):
    """
    Decodes the auth token
    :param auth_token:
    :return: integer|string
    """
    try:
        payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'))
        return payload['sub']  #should return 1
    except jwt.ExpiredSignatureError:
        return 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'
