from cryptography.fernet import Fernet
import base64

class PasswordManager:
    def __init__(self, master_password):
        # Use a consistent encryption key
        self.key = self._load_or_generate_key()
        self.cipher = Fernet(self.key)

    def _load_or_generate_key(self):
        try:
            with open("key.key", "rb") as key_file:
                return key_file.read()
        except FileNotFoundError:
            key = Fernet.generate_key()
            with open("key.key", "wb") as key_file:
                key_file.write(key)
            return key

    def encrypt_password(self, password):
        # Encrypt the password and encode it as Base64
        encrypted = self.cipher.encrypt(password.encode('utf-8'))
        return base64.b64encode(encrypted).decode('utf-8')  # Store as Base64 string

    def decrypt_password(self, encrypted_password):
        # Decode the Base64 string and decrypt it
        encrypted_bytes = base64.b64decode(encrypted_password.encode('utf-8'))
        return self.cipher.decrypt(encrypted_bytes).decode('utf-8')