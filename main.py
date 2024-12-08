import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from urllib.parse import urlparse, parse_qs
import uuid
from flask import Flask, request, jsonify
import bcrypt
import base64
import json
import jwt
from datetime import datetime, timezone, timedelta
import sqlite3
from threading import Thread


# Server configuration
hostName = "localhost"
serverPort = 8080

DATABASE = "totally_not_my_privateKeys.db"

# Initialize SQLite database
conn = sqlite3.connect("totally_not_my_privateKeys.db", check_same_thread=False)
cursor = conn.cursor()

# Create table for storing keys if it doesn’t exist
cursor.execute('''
    CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    )
''')
conn.commit()

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

def save_key_to_db(key, expiration_time):
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, expiration_time))
    conn.commit()


# Generate a valid and expired key for testing
signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
now = int(datetime.now(timezone.utc).timestamp())
one_hour_key = now + 3600
expired_time = now - 3600
save_key_to_db(signing_key, one_hour_key)
save_key_to_db(signing_key, expired_time)


def get_private_key(expired=False):
    now = int(datetime.now(timezone.utc).timestamp())
    if expired:
        cursor.execute("SELECT kid, key FROM keys WHERE exp < ?", (now,))
    else:
        cursor.execute("SELECT kid, key FROM keys WHERE exp > ?", (now,))

    row = cursor.fetchone()
    if row:
        kid, key_pem = row[0], row[1]
        private_key = serialization.load_pem_private_key(
            key_pem,
            password=None,
        )
        return private_key, key_pem, kid
    return None, None, None

def get_aes_key():
    """
    Retrieve and validate the AES key from the environment variable.
    Ensures the key is 16, 24, or 32 bytes (AES-128, AES-192, AES-256).
    """
    aes_key = os.getenv('NOT_MY_KEY')
    if aes_key is None:
        raise ValueError("Environment variable NOT_MY_KEY is not set.")

    aes_key = aes_key.encode("utf-8")
    if len(aes_key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes. Current key length: {}".format(len(aes_key)))
    return aes_key

def create_users_table():
    """Create the users table if it doesn't exist."""
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email TEXT UNIQUE,
                date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            );
        """)

create_users_table()

def generate_password():
    """Generates a secure random password using UUIDv4"""
    return str(uuid.uuid4())[:12]  # Truncate to 12 characters

def hash_password(password):
    """Hashes the password using Argon2"""
    # Choose appropriate settings for time, memory, parallelism, key length, and salt
    # Example with recommended settings from OWASP:
    # https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode('utf-8')

def register_user(username, email):
    """Registers a new user and returns the generated password"""
    hashed_password = hash_password(generate_password())
    cursor.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                   (username, hashed_password, email))
    conn.commit()
    return {"password": generate_password()}  # Return only the generated password

def create_auth_logs_table():
    """Create the auth_logs table if it doesn't exist."""
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS auth_logs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_ip TEXT NOT NULL,
                request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
        """)

create_auth_logs_table()


def log_auth_attempt(ip_address, user_id):
    """Logs an authentication attempt"""
    cursor.execute("INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)", (ip_address, user_id))
    conn.commit()

def authenticate_user(username, password):
    """Authenticate the user by verifying the provided credentials."""
    cursor.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    if user:
        user_id, stored_password_hash = user
        # Verify the password
        if bcrypt.checkpw(password.encode(), stored_password_hash.encode()):
            return True, user_id
    return False, None
#---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
class MyServer(BaseHTTPRequestHandler):
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            # Parse JSON data from request body
            content_length = int(self.headers.get('Content-Length', 0))
            data = self.rfile.read(content_length).decode('utf-8')
            try:
                auth_data = json.loads(data)
                username = auth_data.get("username")
                password = auth_data.get("password")

                if not username or not password:
                    self.send_response(400, "Bad Request")
                    self.end_headers()
                    self.wfile.write(b"Missing username or password in request body.")
                    return

                # Authenticate the user
                authentication_successful, user_id = authenticate_user(username, password)

                if authentication_successful:
                    # Log the successful authentication attempt
                    log_auth_attempt(self.client_address[0], user_id)

                    # Retrieve the correct private key
                    private_key, key_pem, kid = get_private_key(expired='expired' in params)

                    if private_key:
                        headers = {"kid": str(kid)}  # Set kid from database in header
                        token_payload = {
                            "user": username,
                            "exp": (datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()
                            if 'expired' not in params else
                            (datetime.now(timezone.utc) - timedelta(hours=1)).timestamp()
                        }
                        # Sign the JWT using the private key in PEM format
                        encoded_jwt = jwt.encode(token_payload, key_pem, algorithm="RS256", headers=headers)

                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(bytes(json.dumps({"token": encoded_jwt}), "utf-8"))
                        return
                    else:
                        self.send_response(404, "Not Found")
                        self.end_headers()
                        self.wfile.write(b"Key not found.")
                        return
                else:
                    # Log the failed authentication attempt
                    log_auth_attempt(self.client_address[0], None)
                    self.send_response(401, "Unauthorized")
                    self.end_headers()
                    self.wfile.write(b"Invalid username or password.")
                    return
            except json.JSONDecodeError:
                self.send_response(400, "Bad Request")
                self.end_headers()
                self.wfile.write(b"Invalid JSON format in request body.")
                return

        self.send_response(405)
        self.end_headers()

        if parsed_path.path == "/register":
            content_length = int(self.headers.get('Content-Length', 0))
            data = self.rfile.read(content_length).decode('utf-8')
            try:
                user_data = json.loads(data)
                username = user_data.get("username")
                email = user_data.get("email")
                if username and email:
                    # Validate username and email (optional)
                    # Check for existing username and email

                    # Register user and return generated password
                    registered_user = register_user(username, email)
                    self.send_response(201, "Created")  # Use CREATED for user creation
                    self.send_header("Content-type", "application/json")
                    self.end_headers()
                    self.wfile.write(bytes(json.dumps(registered_user), "utf-8"))
                    return
                else:
                    self.send_response(400, "Bad Request")
                    self.end_headers()
                    self.wfile.write(b"Missing username or email in request body.")
                    return
            except json.JSONDecodeError:
                self.send_response(400, "Bad Request")
                self.end_headers()
                self.wfile.write(b"Invalid JSON format in request body.")
                return

        self.send_response(405)
        self.end_headers()


    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            now = int(datetime.now(timezone.utc).timestamp())
            cursor.execute("SELECT kid, key FROM keys WHERE exp > ?", (now,))
            keys = []
            for row in cursor.fetchall():
                kid, key_pem = row[0], row[1]
                public_key = serialization.load_pem_private_key(
                    key_pem,
                    password=None,
                ).public_key()

                keys.append({
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": str(kid),
                    "n": int_to_base64(public_key.public_numbers().n),
                    "e": int_to_base64(public_key.public_numbers().e),
                })
            jwks = {"keys": keys}
            self.wfile.write(bytes(json.dumps(jwks), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()

    def do_PUT(self):
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()

if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        print(f"Server started at http://{hostName}:{serverPort}")
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    conn.close()
    print("Server stopped.")
