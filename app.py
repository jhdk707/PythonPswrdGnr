# app.py
from flask import Flask, render_template, request, redirect, url_for, flash
import secrets
import string
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate  
from forms import RegistrationForm, LoginForm
from models import db, User, Password 
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import base64
import os
from dotenv import load_dotenv
from datetime import datetime

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///passwords_encrypted.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy with the Flask app
db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)  # Initialize Flask-Migrate

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

def generate_secure_password(length=12):
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special_characters = string.punctuation
    all_characters = lowercase + uppercase + digits + special_characters

    password = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
        secrets.choice(special_characters)
    ]

    password += [secrets.choice(all_characters) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(password)
    return ''.join(password)


def encrypt_password(password):
    key = PBKDF2(app.config['SECRET_KEY'].encode(), base64.b64decode(os.getenv('SALT')), dkLen=32)
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(password.encode('utf-8'))
    return base64.b64encode(nonce + tag + ciphertext).decode('utf-8')

def decrypt_password(encrypted_password):
    key = PBKDF2(app.config['SECRET_KEY'].encode(), base64.b64decode(os.getenv('SALT')), dkLen=32)
    encrypted_data = base64.b64decode(encrypted_password)
    nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

def save_password(website, username, password, user_id):
    encrypted_password = encrypt_password(password)
    new_password = Password(website=website, username=username, password=encrypted_password, user_id=user_id)
    db.session.add(new_password)
    db.session.commit()

def get_saved_passwords(user_id):
    passwords = Password.query.filter_by(user_id=user_id).all()
    decrypted_passwords = []
    for p in passwords:
        try:
            decrypted_password = decrypt_password(p.password)
            formatted_date = p.date_created.strftime('%Y-%m-%d %H:%M:%S')
            decrypted_passwords.append((p.website, p.username, decrypted_password, formatted_date, p.id))
        except ValueError as e:
            print(f"Error decrypting password for {p.website}: {e}")
            decrypted_passwords.append((p.website, p.username, "Decryption Failed", p.date_created.strftime('%Y-%m-%d %H:%M:%S'), p.id))
    return decrypted_passwords




@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    password = ''
    if request.method == 'POST':
        length = int(request.form.get('length', 12))
        website = request.form.get('website')
        username = request.form.get('username')
        if website and username:
            password = generate_secure_password(length)
            save_password(website, username, password, current_user.id)
            return redirect(url_for('index', password=password))
        else:
            print("Missing website or username")
    password = request.args.get('password', '')
    return render_template('index.html', password=password)

@app.route('/saved_passwords')
@login_required
def saved_passwords():
    passwords = get_saved_passwords(current_user.id)
    return render_template('saved_passwords.html', passwords=passwords)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You can now log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/delete_password/<int:password_id>', methods=['POST'])
@login_required
def delete_password(password_id):
    password = Password.query.get_or_404(password_id)
    if password.user_id != current_user.id:
        flash('You do not have permission to delete this password.', 'danger')
        return redirect(url_for('saved_passwords'))
    db.session.delete(password)
    db.session.commit()
    flash('Password deleted successfully.', 'success')
    return redirect(url_for('saved_passwords'))

@app.route('/update_password/<int:password_id>', methods=['POST'])
@login_required
def update_password(password_id):
    password = Password.query.get_or_404(password_id)
    if password.user_id != current_user.id:
        flash('You do not have permission to update this password.', 'danger')
        return redirect(url_for('saved_passwords'))
    original_length = len(decrypt_password(password.password))
    new_password = generate_secure_password(original_length)
    password.password = encrypt_password(new_password)
    password.date_created = datetime.utcnow()  # Update the date_created to the current datetime
    db.session.commit()
    flash('Password updated successfully.', 'success')
    return redirect(url_for('saved_passwords'))





@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            return redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
