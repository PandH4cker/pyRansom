from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad

from core import derivative_keys, generate_keys

CHUNK_SIZE = 2048


def symEncryptFile(_inputFile: str, _outputFile: str, _password: bytes, _salt: bytes):
    kc, ki = derivative_keys(_password, _salt)

    with open(_outputFile, 'wb') as writer:
        with open(_inputFile, 'rb') as reader:
            _mac_bytes = HMAC.new(ki, digestmod=SHA256)
            cipher = AES.new(kc, AES.MODE_CBC, iv=generate_keys(AES.block_size))
            writer.write(_salt)
            writer.write(cipher.iv)
            while chunk := reader.read(CHUNK_SIZE):
                encrypted_bytes = symEncryptBlock(cipher, chunk, AES.block_size)
                writer.write(encrypted_bytes)
                _mac_bytes.update(encrypted_bytes)
            writer.write(_mac_bytes.digest())


def symEncryptBlock(cipher, chunk, blockSize):
    return cipher.encrypt(pad(chunk, block_size=blockSize))
