from flask import Flask, request, jsonify
import sqlite3
import bcrypt
import base64

app = Flask(__name__)

# Database setup: Create a simple database and users table.
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            salt TEXT NOT NULL,
            hash TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Helper function to hash a password with a salt.
def hash_password(password):
    salt = bcrypt.gensalt()
    return salt, bcrypt.hashpw(password.encode(), salt)

# Helper function to check password.
def check_password(stored_hash, password, stored_salt):
    return bcrypt.checkpw(password.encode(), stored_hash)

# Endpoint to register a new user.
@app.route('/register', methods=['POST'])
def register():
    username = request.json['username']
    password = request.json['password']
    salt, hashed = hash_password(password)
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('INSERT INTO users (username, salt, hash) VALUES (?, ?, ?)', (username, salt, hashed))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"}), 201

# Endpoint for user login.
@app.route('/login', methods=['POST'])
def login():
    username = request.json['username']
    password = request.json['password']
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT salt, hash FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()
    if user and check_password(user[1], password, user[0]):
        return jsonify({"status": "Login successful"}), 200
    else:
        return jsonify({"status": "Invalid username or password"}), 401

# Endpoint to list all user details.
@app.route('/users', methods=['GET'])
def list_users():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT username, salt, hash FROM users')
    users = c.fetchall()  # This fetches all rows as a list of tuples
    conn.close()
    user_details = [
        {
            'username': user[0],
            'salt': base64.b64encode(user[1]).decode('utf-8'),  # Encode bytes to base64 and then decode to string
            'hash': base64.b64encode(user[2]).decode('utf-8')   # Same here
        } for user in users
    ]
    return jsonify(user_details), 200


if __name__ == '__main__':
    init_db()
    app.run(debug=True)

