
import sqlite3
import unittest
import secure_app


class SecureAppTests(unittest.TestCase):

    def setUp(self):
        self.connection = sqlite3.connect(":memory:")
        self.connection.execute("""
            CREATE TABLE users (
                username TEXT PRIMARY KEY,
                salt BLOB NOT NULL,
                password_hash BLOB NOT NULL
            )
        """)

    def tearDown(self):
        self.connection.close()

    def test_valid_login(self):
        secure_app.create_user(
            self.connection, "alice", "CorrectPass123!"
        )
        self.assertTrue(
            secure_app.login(
                self.connection, "alice", "CorrectPass123!"
            )
        )

    def test_wrong_password_is_rejected(self):
        secure_app.create_user(
            self.connection, "alice", "CorrectPass123!"
        )
        self.assertFalse(
            secure_app.login(
                self.connection, "alice", "WrongPass123!"
            )
        )

    def test_unknown_user_is_rejected(self):
        self.assertFalse(
            secure_app.login(
                self.connection, "unknown_user", "AnyPass123!"
            )
        )

    def test_sql_injection_input_is_rejected(self):
        secure_app.create_user(
            self.connection, "alice", "CorrectPass123!"
        )
        self.assertFalse(
            secure_app.login(
                self.connection,
                "' OR '1'='1' --",
                "AnyPass123!"
            )
        )

    def test_password_is_not_stored_as_plaintext(self):
        secure_app.create_user(
            self.connection, "alice", "PlainPass123!"
        )
        salt, stored_hash = self.connection.execute(
            "SELECT salt, password_hash FROM users WHERE username = ?",
            ("alice",)
        ).fetchone()

        self.assertEqual(len(salt), 16)
        self.assertNotEqual(stored_hash, b"PlainPass123!")
        self.assertNotEqual(stored_hash.decode("latin1", errors="ignore"),
                            "PlainPass123!")


if __name__ == "__main__":
    unittest.main()
