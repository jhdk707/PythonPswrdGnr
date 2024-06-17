from flask import Flask, render_template, request, redirect, url_for
import secrets
import string
import sqlite3
from contextlib import closing

app = Flask(__name__)
DATABASE = 'passwords.db'


def connect_db():
    return sqlite3.connect(DATABASE)


def init_db():
    with closing(connect_db()) as db:
        with open('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()


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


def save_password(website, username, password):
    try:
        with connect_db() as db:
            db.execute('INSERT INTO passwords (website, username, password) VALUES (?, ?, ?)',
                       (website, username, password))
            db.commit()
    except sqlite3.IntegrityError as e:
        print(f"IntegrityError: {e}")
    except Exception as e:
        print(f"Error: {e}")


def get_saved_passwords():
    with connect_db() as db:
        cur = db.execute('SELECT website, username, password FROM passwords')
        passwords = cur.fetchall()
    return passwords


@app.route('/', methods=['GET', 'POST'])
def index():
    password = ''
    if request.method == 'POST':
        length = int(request.form.get('length', 12))
        website = request.form.get('website')
        username = request.form.get('username')

        print(f"Website: {website}")
        print(f"Username: {username}")
        print(f"Length: {length}")

        if website and username:
            password = generate_secure_password(length)
            save_password(website, username, password)
        else:
            print("Missing website or username")

    return render_template('index.html', password=password)


@app.route('/saved_passwords')
def saved_passwords():
    passwords = get_saved_passwords()
    return render_template('saved_passwords.html', passwords=passwords)


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
