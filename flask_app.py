from flask import Flask, redirect, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config["DEBUG"] = True

SQLALCHEMY_DATABASE_URI = "mysql+mysqlconnector://{username}:{password}@{hostname}/{databasename}".format(
    username="Kireta",
    password="@Mdpdepasse2468",
    hostname="Kireta.mysql.pythonanywhere-services.com",
    databasename="Kireta$tesserakt",
)
app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_POOL_RECYCLE"] = 299
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

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

@app.route("/")
def index():
    return render_template("index.html")

#@app.route("/test", methods=["GET", "POST"])
#def test():
#    if request.method == "GET":
#        return render_template("main_page.html", comments=Comment.query.all())

#    comment = Comment(content=request.form["contents"])
#    db.session.add(comment)
#    db.session.commit()
#    return redirect(url_for('index'))

#@app.route("/testIndex")
#def testIndex():
#    if request.method == "GET":
#        return render_template("main_page.html", comments=Comment.query.all())

#    comment = Comment(content=request.form["contents"])
#    db.session.add(comment)
#    db.session.commit()
#    return redirect(url_for('index'))