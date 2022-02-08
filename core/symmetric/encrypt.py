from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad

from core import derivative_keys, generate_keys

CHUNK_SIZE = 2048


def symEncryptFile(inputFile: str, outputFile: str, password: bytes, salt: bytes) -> None:
    """
    Symmetrical Encryption of a file.
    File format: SALT(8) | IV(16) | ENCRYPTED(?) | HMAC-Signature(32)
    :param inputFile: File to be encrypted
    :param outputFile: File to save the encrypted data
    :param password: Password used during keys generation
    :param salt: Salt used during keys generation
    :return: None
    """
    kc, ki = derivative_keys(password, salt)

    with open(outputFile, 'wb') as writer, open(inputFile, 'rb') as reader:
        _mac_bytes = HMAC.new(ki, digestmod=SHA256)
        cipher = AES.new(kc, AES.MODE_CBC, iv=generate_keys(AES.block_size))

        writer.write(salt)
        writer.write(cipher.iv)

        _mac_bytes.update(cipher.iv)\
                  .update(salt)

        while chunk := reader.read(CHUNK_SIZE):
            encrypted_bytes = symEncryptBlock(cipher, chunk, AES.block_size)
            writer.write(encrypted_bytes)
            _mac_bytes.update(encrypted_bytes)

            cipher = AES.new(kc, AES.MODE_CBC, iv=encrypted_bytes[-AES.block_size:])
        writer.write(_mac_bytes.digest())


def symEncryptBlock(cipher, chunk: bytes, blockSize: int) -> bytes:
    return cipher.encrypt(pad(chunk, block_size=blockSize))
