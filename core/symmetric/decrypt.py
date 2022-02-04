from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import unpad

from core import derivative_keys
from utils import getFileSize

CHUNK_SIZE = 2048
SALT_SIZE = 8


def symDecryptFile(_inputFile: str, _outputFile: str, _password: bytes):
    try:
        with open(_outputFile, 'wb') as writer:
            with open(_inputFile, 'rb') as reader:
                salt = reader.read(SALT_SIZE)
                iv = reader.read(AES.block_size)

                kc, ki = derivative_keys(_password, salt)
                _mac_bytes = HMAC.new(ki, digestmod=SHA256)

                currentCursorPosition = reader.tell()
                fileSize = getFileSize(reader)

                reader.seek(currentCursorPosition, 0)

                decipher = AES.new(kc, AES.MODE_CBC, iv=iv)
                while True:
                    remainingBytes = fileSize - reader.tell()
                    if remainingBytes - CHUNK_SIZE > SHA256.digest_size:
                        chunk = reader.read(CHUNK_SIZE)
                    elif remainingBytes - SHA256.digest_size > SHA256.digest_size:
                        chunk = reader.read(remainingBytes - SHA256.digest_size)
                    else:
                        break

                    decrypted_bytes = symDecryptBlock(decipher, chunk, AES.block_size)
                    writer.write(decrypted_bytes)
                    _mac_bytes.update(chunk)

                mac = reader.read(SHA256.digest_size)
                _mac_bytes.verify(mac)
    except ValueError as e:
        print("[-]", e)


def symDecryptBlock(decipher, chunk, block_size):
    return unpad(decipher.decrypt(chunk), block_size=block_size)
