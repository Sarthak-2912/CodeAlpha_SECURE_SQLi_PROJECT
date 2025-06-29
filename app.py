from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
from security import encrypt_data
import os
from Crypto.Cipher import AES
import base64

# AES-256 key (must be 32 bytes long)
SECRET_KEY = b'ThisIsMySuperSecureKey12345678!!'  # 32 bytes exactly

def pad(data):
    pad_len = AES.block_size - len(data) % AES.block_size
    return data + chr(pad_len) * pad_len

def encrypt_password(password):
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    padded_password = pad(password)
    encrypted_bytes = cipher.encrypt(padded_password.encode('utf-8'))
    encrypted_b64 = base64.b64encode(encrypted_bytes).decode('utf-8')
    return encrypted_b64

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except:
            return jsonify({'message': 'Token is invalid!'}), 403
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def index():
    return render_template('index.html')

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        data = request.form

        # Check if user already exists
        existing_user = User.query.filter_by(username=data["username"]).first()
        if existing_user:
            return render_template("register.html", error="⚠ Username already exists. Please try another.")

        # If not, continue as usual
        encrypted_password = encrypt_password(data["password"])
        hashed_password = generate_password_hash(encrypted_password, method='pbkdf2:sha256', salt_length=16)
        user = User(username=data["username"], password=hashed_password)
        db.session.add(user)
        db.session.commit()
        return redirect("/login")

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        data = request.form
        username = data["username"]
        password = data["password"]

        user = User.query.filter_by(username=username).first()
        if user:
            # Encrypt the entered password before checking
            encrypted_password = encrypt_password(password)

            if check_password_hash(user.password, encrypted_password):
                # Generate JWT Token
                token = jwt.encode(
                    {"user": username, "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)},
                    app.config["SECRET_KEY"],
                    algorithm="HS256",
                )
                return render_template("dashboard.html", token=token)

        return render_template("login.html", error="❌ Invalid credentials")

    return render_template("login.html")


@app.route('/secure-data')
@token_required
def secure_data():
    return jsonify({'message': 'This is protected data accessible only with a valid token.'})

@app.route("/test-sqli", methods=["POST"])
def test_sqli():
    user_input = request.form.get("sql_input", "").lower()  # accept from HTML form

    sqli_keywords = [
        "'", "--", ";", "\"", "/*", "*/", "@@", 
        "char", "nchar", "varchar", "nvarchar", 
        "alter", "begin", "cast", "create", "cursor", 
        "declare", "delete", "drop", "end", "exec", 
        "execute", "fetch", "insert", "kill", 
        "open", "select", "sys", "sysobjects", "syscolumns", 
        "table", "update", " or ", " and "
    ]

    if any(keyword in user_input for keyword in sqli_keywords):
        return render_template("dashboard.html", token=request.args.get("token"), result="⚠️ SQL Injection Detected!")
    else:
        return render_template("dashboard.html", token=request.args.get("token"), result="✅ Input is safe.")


if __name__ == '__main__':
    if not os.path.exists('users.db'):
        with app.app_context():
            db.create_all()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

