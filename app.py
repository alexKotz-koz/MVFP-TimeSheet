import os
from random import *

from datetime import datetime

from flask import Flask, request, render_template, redirect, flash, url_for, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from flask_json import FlaskJSON, json_response
from flask_hashing import Hashing

UPLOAD_FOLDER_SONG = '~/static/song'
UPLOAD_FOLDER_COVER = '~/static/cover'
ALLOWED_EXTENSIONS = {'wav', 'mp3'}

app = Flask(__name__, static_url_path="/static")
hashing = Hashing(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER_SONG'] = UPLOAD_FOLDER_SONG
app.config['UPLOAD_FOLDER_COVER'] = UPLOAD_FOLDER_COVER
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
    songName = db.Column(db.String(40))
    songFile = db.Column(db.String(100))
    coverArtFile = db.Column(db.String(100))
    jsonObject = db.Column(db.String(800))
    owner_id = db.Column(db.Integer, db.ForeignKey('users.id'))


@login_manager.user_loader
def load_user(uid):
    user = Users.query.get(uid)
    return user


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hash = hashing.hash_value(password, salt='5gz')
        user = Users.query.filter_by(username=username).first()
        if user != None:
            if hash == user.password:
                login_user(user)
                return redirect('/home')

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
    clockedIn = False
    currentTime = datetime.now()
    clockInTime = 0
    clock = request.form['clock']
    timesheet = request.form['timesheet']
    user = current_user.username
    account = Account.query.filter_by(owner_id=current_user.id)
    if clockedIn==False:
        clockedIn = True
        currentTime = clockInTime


    return render_template('home.html', user=user, account=account)

@app.route('/browse')
def browse():
    users = Users.query.all()
    account = ""

    account = Account.query.all()

    return render_template('browse.html', users=users, account=account)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    db.create_all()
    if request.method == 'POST':
        songname = request.form['songName']
        songfile = request.files['songfile']
        coverartfile = request.files['coverartfile']
        songfilename = secure_filename(songfile.filename)
        coverartfilename = secure_filename(coverartfile.filename)
        if songname == "":
            return redirect('/upload')
        try:
            pathS = "static/song"
            fullPathS = os.path.join(pathS, songfilename)
            songfile.save(fullPathS)
        except:
            return redirect('/upload')

        try:
            pathC = "static/cover"
            fullPathC = os.path.join(pathC, coverartfilename)
            coverartfile.save(fullPathC)
        except:
            return redirect('/upload')
        newEntry = Account(owner_id=current_user.id, songName=songname, songFile=fullPathS, coverArtFile=fullPathC)

        db.session.add(newEntry)
        db.session.commit()
        return redirect('/home')
    return render_template('upload.html')


@app.route('/delete/<id>', methods=['POST', 'GET'])
def delete(id):
    id = Account.query.filter_by(id=id).first()
    db.session.delete(id)
    db.session.commit()
    return redirect('/home')


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


@app.route('/all.json')
def createJSON():
    songs = Account.query.all()
    songNames = []
    songFiles = []
    coverArtFiles = []
    for song in songs:
        songNames.append(song.songName)
        songFiles.append("http://10.0.2.2:5000/getSong/" + str(song.id))
        coverArtFiles.append("http://10.0.2.2:5000/getCover/" + str(song.id))
    return jsonify(songName=songNames, songFile=songFiles, coverArt=coverArtFiles)


@app.route('/getSong/<id>')
def getSongFile(id):
    songs = Account.query.all()
    id = Account.query.filter_by(id=id).first()
    for song in songs:
        return send_file(id.songFile)


@app.route('/getCover/<id>')
def getCoverFile(id):
    covers = Account.query.all()
    id = Account.query.filter_by(id=id).first()
    for cover in covers:
        return send_file(id.coverArtFile)


@app.route('/getSongName/<id>')
def getSongFileName(id):
    songNames = Account.query.all()
    id = Account.query.filter_by(id=id).first()
    for songName in songNames:
        return id.songName

@app.errorhandler(404)
def error(err):
    return render_template('404.html', err=err)


@app.errorhandler(401)
def error(err):
    return render_template('401.html', err=err)


if __name__ == '__main__':
    app.run(debug=True)
