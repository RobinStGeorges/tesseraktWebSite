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
from wtforms import Form, BooleanField, StringField, PasswordField, validators, SubmitField, IntegerField
from wtforms.widgets import TextArea
###############################################################################

#APP CONF
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
################################################################################

#FORMULAIRES
class LoginForm(FlaskForm):
    email = StringField('email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Connexion')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('enregistrer')

class CoursForm(FlaskForm):
    id_exercice = IntegerField('id_exercice', validators=[DataRequired()])
    titre = StringField('titre', validators=[DataRequired()])
    description = StringField('description', widget=TextArea(), validators=[DataRequired()])
    contenue =  StringField('contenue', widget=TextArea(), validators=[DataRequired()])
    mediaPath =  StringField('mediaPath', validators=[DataRequired()])
    submit = SubmitField('Ajouter')

class ExerciceForm(FlaskForm):
    titre = StringField('titre', validators=[DataRequired()])
    description = StringField('description', widget=TextArea(), validators=[DataRequired()])
    contenue =  StringField('contenue', widget=TextArea(), validators=[DataRequired()])
    mediaPath =  StringField('mediaPath', validators=[DataRequired()])
    id_reponse = IntegerField('id_reponse', validators=[DataRequired()])
    imgPath =  StringField('imgPath', validators=[DataRequired()])
    imgReponsePath =  StringField('imgReponsePath', validators=[DataRequired()])
    cube_needed =  StringField('cube_needed',widget=TextArea(), validators=[DataRequired()])
    matrix_size_x = IntegerField('matrix_size_x', validators=[DataRequired()])
    matrix_size_y = IntegerField('matrix_size_y', validators=[DataRequired()])
    disponible = IntegerField('disponible', validators=[DataRequired()])
    matrix_size_x_board = IntegerField('matrix_size_x_board', validators=[DataRequired()])
    matrix_size_y_board = IntegerField('matrix_size_y_board', validators=[DataRequired()])
    coord_finish =  StringField('coord_finish', validators=[DataRequired()])
    x_start = IntegerField('x_start', validators=[DataRequired()])
    y_start = IntegerField('y_start', validators=[DataRequired()])

    submit = SubmitField('Ajouter')
################################################################################

#CLASS
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
        self.isAdmin = 0
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True) # primary keys are required by SQLAlchemy
    email = db.Column(db.String(100))
    password = db.Column(db.String(100))
    isAdmin = db.Column(db.Integer)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True) # primary keys are required by SQLAlchemy
    email = db.Column(db.String(100))
    status = db.Column(db.String(100))

class Cours(db.Model):
    def __init__(self, id_exercice, titre, description, contenue, mediaPath):
        self.id_exercice = id_exercice
        self.titre = titre
        self.description = description
        self.contenue = contenue
        self.mediaPath = mediaPath

    id_cours = db.Column(db.Integer, primary_key=True) # primary keys are required by SQLAlchemy
    id_exercice = db.Column(db.Integer)
    titre = db.Column(db.String(100))
    description = db.Column(db.String(255))
    contenue =  db.Column(db.String(255))
    mediaPath =  db.Column(db.String(255))

class Exercice(db.Model):

    def __init__(self, titre, description, contenue, mediaPath, id_reponse, imgPath, cube_needed, matrix_size_x, matrix_size_y, disponible, matrix_size_x_board, matrix_size_y_board, coord_finish, x_start, y_start):
        self.titre = titre
        self.description = description
        self.contenue = contenue
        self.mediaPath = mediaPath
        self.id_reponse = id_reponse
        self.imgPath = imgPath
        self.cube_needed = cube_needed
        self.matrix_size_x = matrix_size_x
        self.matrix_size_y = matrix_size_y
        self.disponible = disponible
        self.matrix_size_x_board = matrix_size_x_board
        self.matrix_size_y_board = matrix_size_y_board
        self.coord_finish = coord_finish
        self.x_start = x_start
        self.y_start = y_start
    id_exercice = db.Column(db.Integer, primary_key=True)
    titre = db.Column(db.String(100))
    description = db.Column(db.String(255))
    contenue =  db.Column(db.String(255))
    mediaPath =  db.Column(db.String(255))
    id_reponse = db.Column(db.Integer)
    imgPath = db.Column(db.String(255))
    imgReponsePath = db.Column(db.String(255))
    cube_needed = db.Column(db.String(255))
    matrix_size_x = db.Column(db.Integer)
    matrix_size_y = db.Column(db.Integer)
    disponible = db.Column(db.Integer)
    matrix_size_x_board = db.Column(db.Integer)
    matrix_size_y_board = db.Column(db.Integer)
    coord_finish = db.Column(db.String(30))
    x_start = db.Column(db.Integer)
    y_start = db.Column(db.Integer)

class UserResponse(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        email = db.Column(db.String(255))
        coord_x = db.Column(db.Integer)
        coord_y = db.Column(db.Integer)

################################################################################

#ROUTES APP
@app.route("/")
def index():
    if  session.get("isLoggedIn") is None:
        session['isLoggedIn'] = 0
    if  session.get("isAdmin") is None:
        session['isAdmin'] = 0
    return render_template("index.html",  admin=session['isAdmin'], isLoggedIn=session['isLoggedIn'])

@app.route("/index", methods=["GET", "POST"])
def indexPath():
    if  session.get("isLoggedIn") is None:
        session['isLoggedIn'] = 0
    if  session.get("isAdmin") is None:
        session['isAdmin'] = 0
    return render_template("index.html", admin=session['isAdmin'], isLoggedIn=session['isLoggedIn'])

@app.route("/login", methods=["GET", "POST"])
def login():
    if  session.get("isLoggedIn") is None:
        session['isLoggedIn'] = 0
    if  session.get("isAdmin") is None:
        session['isAdmin'] = 0
    form = LoginForm()
    if request.method == 'POST':
        userEmail = form.email.data
        password = form.password.data
        user=User.query.filter_by(email=userEmail).first()
        if bcrypt.check_password_hash(user.password, password):
            login_user(user)
            session['isLoggedIn'] = 1
            session['email'] = user.email
            session['isAdmin'] = user.isAdmin
            return redirect(url_for('info'))
        else:
            return jsonify('erreur: 401')
    else:
        return render_template('login.html', form=form)

@app.route("/register", methods=["GET", "POST"])
def register():
    if  session.get("isLoggedIn") is None:
        session['isLoggedIn'] = 0
    if  session.get("isAdmin") is None:
        session['isAdmin'] = 0
    form = RegisterForm()
    if request.method == 'POST':
        userEmail = form.email.data
        password = form.password.data
        user=User.query.filter_by(email=userEmail).first()
        if user is None:
            user = User(userEmail, bcrypt.generate_password_hash(password))
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('info'))
        else:
            return jsonify('erreur: 401')
    else:
        return render_template('register.html', form=form, admin=session['isAdmin'], isLoggedIn=session['isLoggedIn'])

@app.route("/logout")
@login_required
def logout():
    if  session.get("isLoggedIn") is None:
        session['isLoggedIn'] = 0
    if  session.get("isAdmin") is None:
        session['isAdmin'] = 0
    logout_user()
    session['isAdmin'] = 0
    session['isLoggedIn'] = 0
    return redirect(url_for('login'))

@app.route('/infos')
def info():
    if  session.get("isLoggedIn") is None:
        session['isLoggedIn'] = 0
    if  session.get("isAdmin") is None:
        session['isAdmin'] = 0
    return render_template('infos.html', admin=session['isAdmin'], isLoggedIn=session['isLoggedIn'])

@app.route('/protected')
@flask_login.login_required
def protected():
    if  session.get("isLoggedIn") is None:
        session['isLoggedIn'] = 0
    if  session.get("isAdmin") is None:
        session['isAdmin'] = 0
    return 'Logged in as: ' + flask_login.current_user.id

@app.route("/addCours", methods=["GET", "POST"])
def addCours():
    if  session.get("isLoggedIn") is None:
        session['isLoggedIn'] = 0
    if  session.get("isAdmin") is None:
        session['isAdmin'] = 0
    form = CoursForm()
    if request.method == 'POST':
        id_exercice = form.id_exercice.data
        titre = form.titre.data
        description = form.description.data
        contenue = form.contenue.data
        mediaPath = form.mediaPath.data
        cours = Cours(id_exercice, titre, description, contenue, mediaPath)
        db.session.add(cours)
        db.session.commit()
        return redirect(url_for('info'))
    else:
        return render_template('addCours.html', form=form, admin=session['isAdmin'], isLoggedIn=session['isLoggedIn'])

@app.route("/addExercice", methods=["GET", "POST"])
def addExercice():
    if  session.get("isLoggedIn") is None:
        session['isLoggedIn'] = 0
    if  session.get("isAdmin") is None:
        session['isAdmin'] = 0
    form = ExerciceForm()
    if request.method == 'POST':
        titre = form.titre.data
        description = form.description.data
        contenue = form.contenue.data
        mediaPath = form.mediaPath.data
        id_reponse = form.id_reponse.data
        imgPath = form.imgPath.data
        imgReponsePath = form.imgReponsePath.data
        cube_needed = form.cube_needed.data
        matrix_size_x = form.matrix_size_x.data
        matrix_size_y = form.matrix_size_y.data
        disponible = form.disponible.data
        matrix_size_x_board = form.matrix_size_x_board.data
        matrix_size_y_board = form.matrix_size_y_board.data
        coord_finish = form.coord_finish.data
        x_start = form.x_start.data
        y_start = form.y_start.data
        exercice = Exercice(titre, description, contenue, mediaPath, id_reponse, imgPath, cube_needed, matrix_size_x, matrix_size_y, disponible, matrix_size_x_board, matrix_size_y_board, coord_finish, x_start, y_start)
        db.session.add(exercice)
        db.session.commit()
        return redirect(url_for('info'))
    else:
        return render_template('addExercice.html', form=form, admin=session['isAdmin'], isLoggedIn=session['isLoggedIn'])
################################################################################

#ROUTE FUNCTION
@app.route('/setUserData', methods=["GET", "POST"])
def setUserData():
    data = request.get_json()
    email = data.email
    return jsonify('c\'est okay')

@app.route('/setUserResponse', methods=["GET", "POST"])
def setUserResponse():
    data = request.get_json()
    email = data.email
    return jsonify('c\'est okay')

@app.route('/getCoursData', methods=["GET", "POST"])
def getCoursData():
    cours = Cours.query.all()
    return jsonify(cours)

@app.route('/getExerciceData', methods=["GET", "POST"])
def getExerciceData():
    exercices = Exercice.query.all()
    return jsonify(exercices)

################################################################################

#HANDLER
@app.errorhandler(401)
def page_not_found(e):
    return Response('<p>Login failed</p>')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@login_manager.unauthorized_handler
def unauthorized_handler():
    return 'Unauthorized'
################################################################################





#OLD
@app.route("/setUserDataByMail", methods=["GET", "POST"])
def setUserDataByMail():
    json_data = flask.request.json
    user_mail = json_data['mail']
    password = json_data['password']
    userdata = json_date['userdata']
    user=User.query.filter_by(mail=user_mail).first()
    if(user.verify_password(password)):
        return jsonify('c\'est okay')
################################################################################

