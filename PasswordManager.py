from PasswordEncryptor import PasswordEncryptor

class PasswordManager:
    def __init__(self, master_password, salt=None):
        # Initialize AES-256 encryptor with master password and optional salt
        self.encryptor = PasswordEncryptor(master_password, salt)

    def encrypt_password(self, password):
        # Encrypt the password using AES-256
        return self.encryptor.encrypt(password)

    def decrypt_password(self, encrypted_password):
        # Decrypt the password using AES-256
        return self.encryptor.decrypt(encrypted_password)
