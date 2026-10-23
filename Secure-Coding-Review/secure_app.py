
# CodeAlpha Task 3 - Secure Coding Review
# Secure educational login demonstration.

import getpass
import hashlib
import hmac
import secrets
import sqlite3

ITERATIONS = 600_000


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        ITERATIONS,
    )


def create_user(connection, username, password):
    salt = secrets.token_bytes(16)
    password_hash = hash_password(password, salt)

    try:
        connection.execute(
            "INSERT INTO users (username, salt, password_hash) "
            "VALUES (?, ?, ?)",
            (username, salt, password_hash),
        )
        connection.commit()
        return True
    except sqlite3.IntegrityError:
        print("That username already exists.")
        return False


def login(connection, username, password):
    row = connection.execute(
        "SELECT salt, password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    if row is None:
        print("Login failed.")
        return False

    salt, stored_hash = row
    submitted_hash = hash_password(password, salt)

    if hmac.compare_digest(submitted_hash, stored_hash):
        print("Login successful.")
        return True

    print("Login failed.")
    return False


def main():
    connection = sqlite3.connect(":memory:")
    connection.execute("""
        CREATE TABLE users (
            username TEXT PRIMARY KEY,
            salt BLOB NOT NULL,
            password_hash BLOB NOT NULL
        )
    """)

    print("Create a demo account.")
    username = input("Choose a username: ").strip()
    password = getpass.getpass("Choose a password: ")

    if not username or not password:
        print("Username and password cannot be empty.")
        connection.close()
        return

    if not create_user(connection, username, password):
        connection.close()
        return

    print("\nNow test your login.")
    login_username = input("Username: ").strip()
    login_password = getpass.getpass("Password: ")

    login(connection, login_username, login_password)
    connection.close()


if __name__ == "__main__":
    main()