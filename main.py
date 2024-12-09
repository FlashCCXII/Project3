from flask import Flask, jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import jwt
from datetime import datetime, timedelta, timezone
import sqlite3
import bcrypt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import os
import uuid
from time import time


app = Flask(__name__)
db_file = 'totally_not_my_privateKeys.db'

# rate limiting
limiter = Limiter(get_remote_address, app=app, default_limits=["100 per day", "25 per hour"], headers_enabled=True)
auth_limit = "10 per second"

# secret key for jwt encoding
SECRET_KEY = 'your_secret_key'


def int_to_base64url(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


def init_db():
    """Initialize the database with the required schema"""
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute(''' CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL)''')
    conn.commit()
    conn.close()


def init_users_table():
    """Initialize the users table in the database"""
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute(''' CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP      
    )''')
    conn.commit()
    conn.close()


def init_auth_logs_table():
    """Initialize the authentication logs table in database"""
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute(''' CREATE TABLE IF NOT EXISTS auth_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,  
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    conn.commit()
    conn.close()


def generate_jwt_token(user_id):
    """Generate jwt token for user id"""
    try:
        expiration = datetime.utcnow() + timedelta(hours=1)

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
    """decode a jwt token"""
    try:
        if not isinstance(token, bytes):
            token = token.encode('utf-8')

        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return {'error': 'Token has expired'}
    except jwt.InvalidTokenError as e:
        return {'error': str(e)}


def get_encryption_key():
    """ Get the encryption key"""
    key = os.environ.get('NOT_MY_KEY')
    if key is None:
        raise ValueError("Environment variable NOT_MY_KEY is not set.")
    return base64.urlsafe_b64decode(key)


def encrypt_key(key_pem):
    """encrypt a key using AES encryption"""
    key = get_encryption_key()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # pads key to match size of cipher
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(key_pem) + padder.finalize()

    encrypted_key = iv + encryptor.update(padded_data) + encryptor.finalize()
    return base64.urlsafe_b64encode(encrypted_key).decode('utf-8')


def decrypt_key(encrypted_key):
    """decrypt AES encrypted key"""
    key = get_encryption_key()
    encrypted_key_bytes = base64.urlsafe_b64decode(encrypted_key)

    iv = encrypted_key_bytes[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    #  decrypt and remove padding
    decrypted_padded_data = decryptor.update(encrypted_key_bytes[16:]) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return decrypted_data


def store_key(key_pem, exp_timestamp):
    """Store a private key and its expiration in the database"""
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute('INSERT INTO keys (key, exp) VALUES (?,?)',
              (key_pem, exp_timestamp))

    kid = c.lastrowid
    conn.commit()
    conn.close()
    return kid


def get_valid_key():
    """Get a non-expired private key from the database"""
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    current_time = int(datetime.now(timezone.utc).timestamp())
    c.execute('SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1',
              (current_time,))
    result = c.fetchone()
    conn.close()

    if result:
        kid, encrypted_key, exp = result
        decrypted_key = decrypt_key(encrypted_key)
        return kid, decrypted_key, exp
    return None


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
    """Authenticate an user and return jwt token"""
    try:
        data = request.get_json()

        if not data or 'password' not in data or 'username' not in data:
            return jsonify({"error": "Username and password are required."}), 400

        username = data['username']
        password = data['password']
        # check user in the database
        conn = sqlite3.connect(db_file)
        c = conn.cursor()
        c.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()

        # validate user and password using bcrypt
        if user is None or not bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
            return jsonify({"error": "Invalid username or password."}), 401

        user_id = user[0]
        request_ip = request.remote_addr

        token = generate_jwt_token(user_id)
        if not token:
            return jsonify({"error": "Token generation failed."}), 500

        # Log the authentication request
        conn = sqlite3.connect(db_file)
        c = conn.cursor()
        c.execute('INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)', (request_ip, user_id))
        conn.commit()
        conn.close()

        return jsonify({'token': token})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/register', methods=['POST'])
def register():
    """Register a new user"""
    try:
        data = request.get_json()
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({"error": "Username and password are required."}), 400

        username = data['username']
        password = data['password']
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        conn = sqlite3.connect(db_file)
        c = conn.cursor()
        c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash))
        conn.commit()
        conn.close()

        return jsonify({"message": "User registered successfully!"})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    init_db()
    init_users_table()
    init_auth_logs_table()
    generate_and_store_keys()
    app.run(debug=True)
