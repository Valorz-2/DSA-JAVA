from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

class PasswordEncryptor:
    def __init__(self, master_password):
        self.salt = get_random_bytes(16)  # Generate a random salt
        # Use scrypt for key derivation (more secure than PBKDF2)
        self.key = scrypt(master_password.encode('utf-8'), self.salt, key_len=32, N=2**20, r=8, p=1)

    def encrypt(self, password):
        iv = get_random_bytes(16)  # Initialization vector
        cipher = AES.new(self.key, AES.MODE_GCM, iv)
        encrypted_password, tag = cipher.encrypt_and_digest(pad(password.encode('utf-8'), AES.block_size))
        # Store IV, encrypted password, and tag together
        combined_data = iv + encrypted_password + tag
        return base64.b64encode(combined_data).decode('utf-8')

    def decrypt(self, encrypted_password):
        encrypted_data = base64.b64decode(encrypted_password)
        iv = encrypted_data[:16]
        encrypted_password = encrypted_data[16:-16]
        tag = encrypted_data[-16:]
        cipher = AES.new(self.key, AES.MODE_GCM, iv)
        decrypted_password = unpad(cipher.decrypt_and_verify(encrypted_password, tag), AES.block_size)
        return decrypted_password.decode('utf-8')