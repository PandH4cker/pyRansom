import string

from Crypto.Hash import SHA256
from binascii import hexlify

from Crypto.Hash.SHA256 import SHA256Hash

from core import generate_password, generate_keys

ROUND_KEY_COUNTER = 8192
CIPHER_KEY = 0x000
INTEGRITY_KEY = 0x001


def round_keys(password: bytes, salt: bytes, N: int) -> [bytes]:
    h = SHA256.new()
    hN = password
    for i in range(N):
        h.update(hN + salt + i.to_bytes(4, 'little'))
        hN = h.digest()
    return h.digest()


def derivative_keys(_password, _salt):
    km = round_keys(_password, _salt, ROUND_KEY_COUNTER)
    kc = SHA256Hash(km + CIPHER_KEY.to_bytes(4, 'little')).digest()
    ki = SHA256Hash(km + INTEGRITY_KEY.to_bytes(4, 'little')).digest()
    return kc, ki


if __name__ == '__main__':
    print(hexlify(
        round_keys(
            generate_password(12, string.printable[:-6]).encode(),
            generate_keys(16),
            10
        )
    ).decode())
