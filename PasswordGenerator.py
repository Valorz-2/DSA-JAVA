import random
import string

class PasswordGenerator:
    def __init__(self, length=12, use_numbers=True, use_symbols=True):
        self.length = length
        self.use_numbers = use_numbers
        self.use_symbols = use_symbols

    def generate(self):
        chars = string.ascii_letters
        if self.use_numbers:
            chars += string.digits
        if self.use_symbols:
            chars += string.punctuation

        password = ''.join(random.choice(chars) for _ in range(self.length))
        return password