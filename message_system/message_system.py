from flask import Flask, render_template, flash, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse  # Updated import
from datetime import datetime
import os

# Config
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///app.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

# App Initialization
app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
login = LoginManager(app)
login.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    role = db.Column(db.String(10))  # 'student' or 'teacher'
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    body = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')

# User Loader
@login.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
@app.route('/index')
@login_required
def index():
    return render_template('index.html', title='Home')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user is None or not user.check_password(password):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=request.form.get('remember'))
        next_page = request.args.get('next')
        if not next_page or urlparse(next_page).netloc != '':
            next_page = url_for('profile')
        return redirect(next_page)
    return render_template('login.html', title='Sign In')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', title='Profile', user=current_user)

@app.route('/dashboard')
@login_required
def dashboard():
    messages_sent = Message.query.filter_by(sender_id=current_user.id).all()
    messages_received = Message.query.filter_by(receiver_id=current_user.id).all()
    return render_template('dashboard.html', title='Dashboard', messages_sent=messages_sent, messages_received=messages_received)

@app.route('/send_message', methods=['GET', 'POST'])
@login_required
def send_message():
    if request.method == 'POST':
        receiver_username = request.form['receiver']
        body = request.form['body']
        receiver = User.query.filter_by(username=receiver_username).first()
        if receiver:
            message = Message(sender_id=current_user.id, receiver_id=receiver.id, body=body)
            db.session.add(message)
            db.session.commit()
            flash('Message sent!')
            return redirect(url_for('dashboard'))
        else:
            flash('User not found')
    return render_template('message.html', title='Send Message')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Username or email already exists. Please choose another one.')
            return redirect(url_for('register'))
        
        new_user = User(username=username, email=email, role=role)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    
    return render_template('register.html', title='Register')

# Main
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
