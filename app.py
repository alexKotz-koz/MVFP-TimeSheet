import os
import time
from random import *

from datetime import datetime, time, date, timedelta

from flask import Flask, request, render_template, redirect, session, flash, url_for, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import insert
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from flask_json import FlaskJSON, json_response
from flask_hashing import Hashing

app = Flask(__name__, static_url_path="/static")
hashing = Hashing(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

json = FlaskJSON(app)
json.init_app(app)


def generate_SK():
    import string
    characters = string.ascii_letters + string.punctuation + string.digits
    random_string = "".join(choice(characters) for x in range(256))
    return random_string


random_SKstring = generate_SK()
app.config['SECRET_KEY'] = random_SKstring
login_manager = LoginManager(app)
login_manager.init_app(app)


class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40), unique=True, nullable=False)
    password = db.Column(db.String(40), nullable=False)
    name = db.Column(db.String(40), nullable=False)
    entries = db.relationship('Account', backref='user')


class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    clockInEntry = db.Column(db.String(8))
    clockOutEntry = db.Column(db.String(8))
    date = db.Column(db.DATE)
    rowTotal = db.Column(db.String(12))


@login_manager.user_loader
def load_user(uid):
    user = Users.query.get(uid)
    return user


@app.route('/', methods=['GET', 'POST'])
def login():
    db.create_all()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hash = hashing.hash_value(password, salt='5gz')
        user = Users.query.filter_by(username=username).first()
        if user is not None:
            if hash == user.password:
                login_user(user)
                session['username'] = username
                return redirect('/home')
            else:
                flash('Username/Password Combination Incorrect')
                return redirect('/')
        else:
            flash("Username/password combination incorrect")
            return redirect('/')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/')


@app.route('/createAccount', methods=['GET', 'POST'])
def createAccount():
    db.create_all()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm = request.form['password2']
        name = request.form['name']
        if password != confirm:
            return render_template('password_error.html')
            redirect('/')
        else:
            hash = hashing.hash_value(password, salt='5gz')
            db.session.add(Users(username=username, password=hash, name=name))
            db.session.commit()
            return redirect('/')
    return render_template('createAccount.html')


@app.route('/home', methods=['GET', 'POST'])
@login_required
def home():
    user = current_user.username
    account = Account.query.filter_by(owner_id=current_user.id)
    name = current_user.name
    rowTotal = 3000

    def ceil_dt(dt, delta):
        return dt + (datetime.min - dt) % delta

    clockInTime = ceil_dt(datetime.now(), timedelta(minutes=15))

    clockInTime1 = str(datetime.now())
    clockInTime = str(clockInTime)
    clockInTime.split(" ")
    clockInTime = clockInTime[11:]

    clockOutTime = ceil_dt(datetime.now(), timedelta(minutes=15))
    clockOutTime1 = str(datetime.now())
    clockOutTime = str(clockOutTime)
    clockOutTime.split(" ")
    clockOutTime = clockOutTime[11:]

    if request.method == 'POST':
        currentTime = datetime.now().time()
        currentDate = date.today()
        # timesheet = request.form['timesheet']
        if request.form['clock'] == 'clockInButton':
            if not session.get('clockedIn'):
                session['clockedIn'] = True
                session['tempClockIn'] = clockInTime
        elif request.form['clock'] == 'clockOutButton':
            if not session.get('clockedIn'):
                flash("No Clock In Time")
                return redirect('/home')
            if session['clockedIn'] == True:
                session['clockedIn'] = False
                # if session['tempClockIn'] == clockOutTime:
                # Uncomment When completed
                # flash("Invalid Time Entry")
                # Uncomment when complete
                # return redirect('/home')

                newClockOutEntry = Account(owner_id=current_user.id, clockInEntry=session['tempClockIn'],
                                           clockOutEntry=clockOutTime, date=currentDate)
                db.session.add(newClockOutEntry)
                db.session.commit()
                return redirect('/timesheet')
    return render_template('home.html', user=user, account=account, name=name, clockInTime=clockInTime)


@app.route('/timesheet', methods=['POST', 'GET'])
@login_required
def timesheet():
    user = Account.query.all()
    account = Account.query.filter_by(owner_id=current_user.id)
    name = current_user.name
    clockInEntries = []
    clockOutEntries = []
    individualClockInEntry = Account.query.filter_by(owner_id=current_user.id)
    individualClockOutEntry = Account.query.filter_by(owner_id=current_user.id)

    diff = []

    def __datetime(date_str):
        return datetime.strptime(date_str, '%H:%M:%S')

    for i in account:
        start = __datetime(i.clockInEntry)
        end = __datetime(i.clockOutEntry)

        delta = end - start

        delta = str(delta)
        diff.append(delta)
        print(diff)

    return render_template('viewTimesheet.html', user=user, account=account, name=name, rowTotal=diff)  # rowTotal=rowTotal)


@app.route('/profile', methods=['POST', 'GET'])
@login_required
def profile():
    if request.method == "POST":
        currentPassword = request.form['currentPassword']
        newPassword = request.form['newPassword']
        confirmNewPassword = request.form['confirmNewPassword']
        password = current_user.password
        currentPasswordHash = hashing.hash_value(currentPassword, salt='5gz')
        newPasswordHash = hashing.hash_value(newPassword, salt='5gz')
        if password == currentPasswordHash:
            if newPassword != confirmNewPassword:
                return redirect('password_error.html')
            elif newPassword == confirmNewPassword:
                current_user.password = newPasswordHash
                db.session.commit()
                logout_user()
                return redirect('/')
        else:
            return redirect('password_error.html')
    redirect('/')
    return render_template('profile.html')


@app.errorhandler(404)
def error(err):
    return render_template('404.html', err=err)


@app.errorhandler(401)
def error(err):
    return render_template('401.html', err=err)


if __name__ == '__main__':
    app.run(debug=True)
