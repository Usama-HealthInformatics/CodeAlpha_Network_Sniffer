
# CodeAlpha Task 3 - Secure Coding Review
# Intentionally vulnerable demo for educational review only.
# Never use this example with real credentials or data.

import sqlite3

def login(username, password):
    connection = sqlite3.connect(":memory:")
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE users (
            username TEXT,
            password TEXT
        )
    """)

    cursor.execute(
        "INSERT INTO users VALUES ('admin', 'admin123')"
    )

    # SECURITY ISSUE: SQL query built using string formatting.
    query = (
        f"SELECT * FROM users WHERE username = '{username}' "
        f"AND password = '{password}'"
    )

    print("Executing login query:", query)
    cursor.execute(query)

    result = cursor.fetchone()
    connection.close()

    if result:
        print("Login successful")
        return True

    print("Login failed")
    return False


if __name__ == "__main__":
    user = input("Username: ")
    secret = input("Password: ")
    login(user, secret)
