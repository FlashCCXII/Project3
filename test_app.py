import unittest
from main import app
import json
import sqlite3

class TestFlaskApp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Set up the test database."""
        cls.db_name = "test_keys.db"
        conn = sqlite3.connect(cls.db_name)
        cur = conn.cursor()

        # Create required tables for testing
        cur.execute('''CREATE TABLE IF NOT EXISTS keys(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            encrypted_key BLOB NOT NULL,
            expiration INTEGER NOT NULL
        )''')
        cur.execute('''CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )''')
        cur.execute('''CREATE TABLE IF NOT EXISTS auth_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')
        conn.commit()
        conn.close()

    @classmethod
    def tearDownClass(cls):
        """Clean up the test database."""
        conn = sqlite3.connect(cls.db_name)
        cur = conn.cursor()
        cur.execute("DROP TABLE keys")
        cur.execute("DROP TABLE users")
        cur.execute("DROP TABLE auth_logs")
        conn.commit()
        conn.close()

    def setUp(self):
        """Configure the app for testing."""
        self.app = app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def test_register(self):
        """Test the /register endpoint."""
        data = {"username": "testuser", "email": "test@example.com"}
        response = self.client.post("/register", data=json.dumps(data), content_type="application/json")
        self.assertEqual(response.status_code, 200)
        self.assertIn("password", response.get_json())

    def test_auth(self):
        """Test the /auth endpoint."""
        # Insert a test user
        conn = sqlite3.connect(self.db_name)
        cur = conn.cursor()
        cur.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", ("testuser", "hashedpassword"))
        conn.commit()
        conn.close()

        # Make an authentication request
        data = {"username": "testuser"}
        response = self.client.post("/auth", data=json.dumps(data), content_type="application/json")
        self.assertEqual(response.status_code, 200)
        self.assertIn("token", response.get_json())

    def test_jwks(self):
        """Test the /.well-known/jwks.json endpoint."""
        response = self.client.get("/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)
        self.assertIn("keys", response.get_json())

if __name__ == "__main__":
    unittest.main()
