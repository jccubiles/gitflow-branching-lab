import hashlib
import secrets
from datetime import datetime, timedelta


class AuthenticationManager:
    def __init__(self):
        self.users = {}
        self.active_sessions = {}

    def _hash_password(self, password, salt):
        """Create secure password hash with salt."""
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            100000,
        )

    def register_user(self, username, password):
        """Register a new user with hashed password."""
        if username in self.users:
            raise ValueError(f"User {username} already exists")

        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long")

        salt = secrets.token_hex(32)
        password_hash = self._hash_password(password, salt)

        self.users[username] = {
            "password_hash": password_hash,
            "salt": salt,
            "sessions": [],
            "created_at": datetime.now(),
            "active": True,
        }

        return f"User {username} registered successfully"

    def authenticate(self, username, password):
        """Authenticate user and create session token."""
        if username not in self.users:
            raise ValueError("Invalid username or password")

        user_data = self.users[username]

        if not user_data["active"]:
            raise ValueError("Account is deactivated")

        password_hash = self._hash_password(password, user_data["salt"])

        if password_hash != user_data["password_hash"]:
            raise ValueError("Invalid username or password")

        session_token = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(hours=24)

        self.active_sessions[session_token] = {
            "username": username,
            "expires_at": expires_at,
            "created_at": datetime.now(),
        }

        self.users[username]["sessions"].append(
            {
                "token": session_token,
                "created_at": datetime.now(),
                "expires_at": expires_at,
            }
        )

        return session_token

    def validate_session(self, session_token):
        """Validate active session token."""
        if session_token not in self.active_sessions:
            return False

        session_data = self.active_sessions[session_token]

        if datetime.now() > session_data["expires_at"]:
            del self.active_sessions[session_token]
            return False

        return session_data["username"]

    def logout(self, session_token):
        """Logout user and invalidate session."""
        if session_token in self.active_sessions:
            username = self.active_sessions[session_token]["username"]
            del self.active_sessions[session_token]

            return f"User {username} logged out successfully"

        return "Session not found or already expired"

    def get_user_sessions(self, username):
        """Get all active sessions for a user."""
        if username not in self.users:
            return []

        active_sessions = []

        for token, session_data in self.active_sessions.items():
            if session_data["username"] == username:
                active_sessions.append(
                    {
                        "token": token[:8] + "...",
                        "created_at": session_data["created_at"],
                        "expires_at": session_data["expires_at"],
                    }
                )

        return active_sessions


if __name__ == "__main__":
    auth = AuthenticationManager()

    print("=== User Authentication System Demo ===")

    print(auth.register_user("alice", "secure_password123"))
    print(auth.register_user("bob", "another_secure_pass"))

    alice_token = auth.authenticate("alice", "secure_password123")
    bob_token = auth.authenticate("bob", "another_secure_pass")

    print(f"Alice authenticated with token: {alice_token[:8]}...")
    print(f"Bob authenticated with token: {bob_token[:8]}...")

    print(f"Alice session valid: {auth.validate_session(alice_token)}")
    print(f"Bob session valid: {auth.validate_session(bob_token)}")

    print(f"Alice active sessions: {len(auth.get_user_sessions('alice'))}")

    print(auth.logout(alice_token))
    print(f"Alice session after logout: {auth.validate_session(alice_token)}")