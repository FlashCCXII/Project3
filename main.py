from flask import Flask, jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
from datetime import datetime, timedelta, timezone
import sqlite3
import bcrypt
import base64
import os
import uuid
from time import time

app = Flask(__name__)
db_file = 'totally_not_my_privateKeys.db'

# Rate limiting
limiter = Limiter(get_remote_address, app=app, default_limits=["100 per day", "25 per hour"], headers_enabled=True)
auth_limit = "10 per second"

# Secret key for JWT encoding
SECRET_KEY = 'your_secret_key'


def int_to_base64url(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


def init_db():
    """Initialize the database with all required schemas"""
    conn = sqlite3.connect(db_file)
    c = conn.cursor()

    # Create keys table
    c.execute('''CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL)''')

    # Create users table
    c.execute('''CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP)''')

    # Create auth_logs table
    c.execute('''CREATE TABLE IF NOT EXISTS auth_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id))''')

    conn.commit()
    conn.close()


def generate_jwt_token(user_id, expired=False):
    """Generate a JWT token for the user"""
    try:
        expiration = datetime.utcnow() + timedelta(hours=1)
        if expired:
            expiration = datetime.utcnow() - timedelta(hours=1)

        payload = {
            'user_id': user_id,
            'exp': expiration
        }
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
        return token if isinstance(token, bytes) else token.encode('utf-8')
    except Exception as e:
        print(f"Error generating JWT token: {e}")
        return None


def decode_jwt_token(token):
    """Decode a JWT token"""
    try:
        if not isinstance(token, bytes):
            token = token.encode('utf-8')
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return {'error': 'Token has expired'}
    except jwt.InvalidTokenError as e:
        return {'error': str(e)}


def store_key(key_pem, exp_timestamp):
    """Store a private key and its expiration in the database"""
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (key_pem, exp_timestamp))
    kid = c.lastrowid
    conn.commit()
    conn.close()
    return kid


def generate_and_store_keys():
    """Generate and store both valid and expired keys"""
    # Generate expired key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    exp_timestamp = int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())
    store_key(pem, exp_timestamp)

    # Generate valid key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    exp_timestamp = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp())
    store_key(pem, exp_timestamp)


@app.route('/auth', methods=['POST'])
@limiter.limit(auth_limit)
def auth():
    """Authenticate a user and return JWT token"""
    try:
        data = request.get_json()

        if not data or 'username' not in data or 'password' not in data:
            return jsonify({"error": "Username and password are required."}), 400

        username = data['username']
        password = data['password']

        conn = sqlite3.connect(db_file)
        c = conn.cursor()
        c.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()

        if user is None or not bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
            # Log failed login attempt
            conn = sqlite3.connect(db_file)
            c = conn.cursor()
            c.execute('INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)', (request.remote_addr, None))
            conn.commit()
            conn.close()
            return jsonify({"error": "Invalid username or password."}), 401

        user_id = user[0]
        token = generate_jwt_token(user_id)
        if not token:
            return jsonify({"error": "Token generation failed."}), 500

        request_ip = request.remote_addr
        conn = sqlite3.connect(db_file)
        c = conn.cursor()
        c.execute('INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)', (request_ip, user_id))
        conn.commit()
        conn.close()

        return jsonify({'token': token.decode('utf-8')}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/register', methods=['POST'])
def register():
    """Register a new user"""
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')

    if not username or not email:
        return jsonify({"error": "Username and email are required."}), 400

    # Generate a secure random password
    password = str(uuid.uuid4())
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)',
                  (username, password_hash, email))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Username or email already exists."}), 409
    finally:
        conn.close()

    return jsonify({"password": password}), 201


@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    """Return JWKS for public keys"""
    keys = []
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute('SELECT kid, key FROM keys WHERE exp > ?', (int(time()),))
    results = c.fetchall()
    conn.close()

    for kid, key_pem in results:
        private_key = serialization.load_pem_private_key(key_pem, password=None)
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()

        keys.append({
            'kid': str(kid),
            'kty': 'RSA',
            'n': int_to_base64url(public_numbers.n),
            'e': int_to_base64url(public_numbers.e),
            'alg': 'RS256',
            'use': 'sig'
        })

    return jsonify({'keys': keys})

# Initialize database and generate keys on startup
init_db()
generate_and_store_keys()

if __name__ == '__main__':
    app.run(debug=True, port=8080)
