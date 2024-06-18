from flask import Flask, render_template, request, redirect, url_for
import secrets
import string
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import base64
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

DATABASE_URL = 'sqlite:///passwords_encrypted.db'
SECRET_KEY = os.getenv('SECRET_KEY').encode()  # Load and encode the secret key
SALT = base64.b64decode(os.getenv('SALT'))  # Load and decode the salt

engine = create_engine(DATABASE_URL)
Base = declarative_base()

class Password(Base):
    __tablename__ = 'passwords'
    id = Column(Integer, primary_key=True)
    website = Column(String, nullable=False)
    username = Column(String, nullable=False)
    password = Column(String, nullable=False)

Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()

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
    key = PBKDF2(SECRET_KEY, SALT, dkLen=32)
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(password.encode('utf-8'))
    return base64.b64encode(nonce + tag + ciphertext).decode('utf-8')

def decrypt_password(encrypted_password):
    key = PBKDF2(SECRET_KEY, SALT, dkLen=32)
    encrypted_data = base64.b64decode(encrypted_password)
    nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

def save_password(website, username, password):
    encrypted_password = encrypt_password(password)
    new_password = Password(website=website, username=username, password=encrypted_password)
    session.add(new_password)
    session.commit()

def get_saved_passwords():
    passwords = session.query(Password).all()
    decrypted_passwords = []
    for p in passwords:
        try:
            decrypted_password = decrypt_password(p.password)
            decrypted_passwords.append((p.website, p.username, decrypted_password))
        except ValueError as e:
            print(f"Error decrypting password for {p.website}: {e}")
            decrypted_passwords.append((p.website, p.username, "Decryption Failed"))
    return decrypted_passwords

@app.route('/', methods=['GET', 'POST'])
def index():
    password = ''
    if request.method == 'POST':
        length = int(request.form.get('length', 12))
        website = request.form.get('website')
        username = request.form.get('username')
        if website and username:
            password = generate_secure_password(length)
            save_password(website, username, password)
            return redirect(url_for('index', password=password))
        else:
            print("Missing website or username")
    password = request.args.get('password', '')
    return render_template('index.html', password=password)

@app.route('/saved_passwords')
def saved_passwords():
    passwords = get_saved_passwords()
    return render_template('saved_passwords.html', passwords=passwords)

if __name__ == '__main__':
    app.run(debug=True)
