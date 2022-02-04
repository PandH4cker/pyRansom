import string
import sys

from Crypto.Random.random import choice


def generate_password(length: int, alphabet: str) -> str:
    return ''.join([choice(alphabet) for _ in range(length)])


if __name__ == '__main__':
    try:
        print(generate_password(int(sys.argv[1]), string.printable[:-6]))
    except (ValueError, IndexError):
        print("Usage: generate_password.py length")
