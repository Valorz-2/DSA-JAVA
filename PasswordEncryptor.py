from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

class PasswordEncryptor:
    def __init__(self, master_password, salt=None):
        # Store master password
        self.master_password = master_password
        # Use provided salt or generate a new one
        self.salt = salt if salt else get_random_bytes(16)
        # Derive key using scrypt
        self.key = scrypt(master_password.encode('utf-8'), self.salt, key_len=32, N=2**20, r=8, p=1)

    def encrypt(self, password):
        iv = get_random_bytes(16)  # Initialization vector
        cipher = AES.new(self.key, AES.MODE_GCM, iv)
        encrypted_password, tag = cipher.encrypt_and_digest(pad(password.encode('utf-8'), AES.block_size))
        # Combine salt, IV, encrypted password, and tag
        combined_data = self.salt + iv + encrypted_password + tag
        return base64.b64encode(combined_data).decode('utf-8')

    def decrypt(self, encrypted_password):
        encrypted_data = base64.b64decode(encrypted_password)
        # Extract salt (16 bytes), IV (16 bytes), tag (16 bytes), and encrypted password
        salt = encrypted_data[:16]
        iv = encrypted_data[16:32]
        encrypted_password = encrypted_data[32:-16]
        tag = encrypted_data[-16:]
        # Re-derive key using the stored salt and master password
        key = scrypt(self.master_password.encode('utf-8'), salt, key_len=32, N=2**20, r=8, p=1)
        cipher = AES.new(key, AES.MODE_GCM, iv)
        decrypted_password = unpad(cipher.decrypt_and_verify(encrypted_password, tag), AES.block_size)
        return decrypted_password.decode('utf-8')

    def get_salt(self):
        return self.salt
