from auth import AuthenticationManager
from user_manager import UserManager


class SecureUserManager(UserManager):
    def __init__(self):
        super().__init__()
        self.auth_manager = AuthenticationManager()

    def register_user(self, username, email, password):
        """Register user with authentication."""
        self.auth_manager.register_user(username, password)
        self.add_user(username, email)

        return f"User {username} registered with authentication enabled"

    def login_user(self, username, password):
        """Authenticate and login user."""
        session_token = self.auth_manager.authenticate(username, password)

        return {
            "session_token": session_token,
            "user_data": self.get_user(username),
            "message": f"User {username} authenticated successfully",
        }

    def validate_user_session(self, session_token):
        """Validate user session for secure operations."""
        username = self.auth_manager.validate_session(session_token)

        if username:
            return {
                "valid": True,
                "username": username,
                "user_data": self.get_user(username),
            }

        return {
            "valid": False,
            "message": "Invalid or expired session",
        }


if __name__ == "__main__":
    secure_manager = SecureUserManager()

    print("Secure User Management System initialized")

    secure_manager.register_user(
        "test_user",
        "test@example.com",
        "secure_password123",
    )

    login_result = secure_manager.login_user(
        "test_user",
        "secure_password123",
    )

    print(f"Login successful: {login_result['message']}")

    validation = secure_manager.validate_user_session(
        login_result["session_token"]
    )

    print(f"Session validation: {validation['valid']}")