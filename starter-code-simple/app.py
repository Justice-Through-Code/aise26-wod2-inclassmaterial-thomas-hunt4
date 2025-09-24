# Secure Python API - Fixed Version
# Safe for development and pre-commit checks

import os
import sqlite3

from dotenv import load_dotenv
from flask import Flask, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
load_dotenv()  # Load environment variables from .env

# Use environment variables for sensitive info
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///users.db")  # fallback for dev
API_SECRET = os.getenv("API_SECRET", "dev-secret")  # fallback for dev


def get_db_connection():
    """Return a SQLite connection"""
    return sqlite3.connect("users.db")


@app.route("/health")
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "database": DATABASE_URL})


@app.route("/users", methods=["GET"])
def get_users():
    """Return all users (id and username)"""
    conn = get_db_connection()
    users = conn.execute("SELECT id, username FROM users").fetchall()
    conn.close()
    return jsonify({"users": [{"id": u[0], "username": u[1]} for u in users]})


@app.route("/users", methods=["POST"])
def create_user():
    """Create a new user safely"""
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    # Use strong password hashing
    hashed_password = generate_password_hash(password)

    conn = get_db_connection()
    # Use parameterized query to prevent SQL injection
    conn.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (username, hashed_password),
    )
    conn.commit()
    conn.close()

    # Log only non-sensitive info
    print(f"Created user: {username}")
    return jsonify({"message": "User created", "username": username})


@app.route("/login", methods=["POST"])
def login():
    """Login user safely"""
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    conn = get_db_connection()
    # Fetch hashed password safely using parameterized query
    user = conn.execute(
        "SELECT id, password FROM users WHERE username=?", (username,)
    ).fetchone()
    conn.close()

    if user and check_password_hash(user[1], password):
        return jsonify({"message": "Login successful", "user_id": user[0]})
    return jsonify({"message": "Invalid credentials"}), 401


def init_db():
    """Initialize the database"""
    conn = get_db_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    app.run(debug=False)
