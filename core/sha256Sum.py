import sys

from Crypto.Hash import SHA256
from binascii import hexlify


def Sha256Sum(filename: str) -> bytes:
    try:
        with open(filename, 'rb') as f:
            h = SHA256.new()
            while b := f.read(2048): h.update(b)
            return h.digest()
    except FileNotFoundError:
        return b''


if __name__ == '__main__':
    try:
        print(hexlify(Sha256Sum(sys.argv[1])).decode())
    except (IndexError, TypeError):
        print("Usage: sha256Sum.py filename")
