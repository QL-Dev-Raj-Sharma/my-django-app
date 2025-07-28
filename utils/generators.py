import string
import random


class Generator:

    @staticmethod
    def generate_otp():
        return ''.join(random.choices(string.digits, k=6))