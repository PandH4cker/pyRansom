import string

from Crypto.Hash import SHA256
from binascii import hexlify

from generate_keys import generate_keys
from generate_password import generate_password


def round_keys(password: bytes, salt: bytes, N: int) -> [bytes]:
    h = SHA256.new()
    hN = password
    for i in range(N):
        h.update(hN + salt + i.to_bytes(4, 'little'))
        hN = h.digest()
    return h.digest()


if __name__ == '__main__':
    print(hexlify(
        round_keys(
            generate_password(12, string.printable[:-6]).encode(),
            generate_keys(16),
            10
        )
    ).decode())
