from flask import Flask, request, jsonify
import sqlite3
import bcrypt

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


if __name__ == '__main__':
    init_db()
    app.run(debug=True)

