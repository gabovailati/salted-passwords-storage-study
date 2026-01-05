from flask import Flask, request, jsonify
import sqlite3
import bcrypt
import os
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Database setup: Create a simple database and users table.
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Input validation helper
def validate_input(username, password):
    """Validate username and password meet security requirements."""
    errors = []

    if not username:
        errors.append("Username is required")
    elif len(username) < 3:
        errors.append("Username must be at least 3 characters")
    elif len(username) > 50:
        errors.append("Username must not exceed 50 characters")

    if not password:
        errors.append("Password is required")
    elif len(password) < 8:
        errors.append("Password must be at least 8 characters")
    elif len(password) > 128:
        errors.append("Password must not exceed 128 characters")

    return errors

# Helper function to hash a password.
# Note: bcrypt automatically generates and includes the salt in the hash
def hash_password(password):
    """Hash a password using bcrypt. The salt is automatically included in the hash."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Helper function to check password.
def check_password(stored_hash, password):
    """Verify a password against a stored bcrypt hash."""
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash)

# Security headers middleware
@app.after_request
def set_security_headers(response):
    """Add security headers to all responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# Endpoint to register a new user.
@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    """Register a new user with username and password."""
    # Validate content type
    if not request.is_json:
        return jsonify({"status": "error", "message": "Content-Type must be application/json"}), 415

    # Get request data
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Validate input
    validation_errors = validate_input(username, password)
    if validation_errors:
        return jsonify({"status": "error", "message": validation_errors}), 400

    # Hash password (salt is automatically included by bcrypt)
    hashed = hash_password(password)

    # Save to database with error handling
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                  (username, hashed))
        conn.commit()
        conn.close()
        return jsonify({"status": "success", "message": "User registered successfully"}), 201
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"status": "error", "message": "Username already exists"}), 409
    except Exception as e:
        conn.close()
        return jsonify({"status": "error", "message": "An error occurred during registration"}), 500

# Endpoint for user login.
@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    """Authenticate a user with username and password."""
    # Validate content type
    if not request.is_json:
        return jsonify({"status": "error", "message": "Content-Type must be application/json"}), 415

    # Get request data
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Basic input validation
    if not username or not password:
        return jsonify({"status": "error", "message": "Username and password are required"}), 400

    # Query database
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()

    # Check credentials
    if user and check_password(user[0], password):
        return jsonify({"status": "success", "message": "Login successful"}), 200
    else:
        return jsonify({"status": "error", "message": "Invalid username or password"}), 401


if __name__ == '__main__':
    init_db()
    # Use environment variables for debug mode
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes')
    app.run(debug=debug_mode)
