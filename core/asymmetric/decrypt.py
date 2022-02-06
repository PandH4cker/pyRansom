from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss

from core import generate_keys
from core.symmetric.decrypt import symDecryptBlock
from core.symmetric.encrypt import symEncryptBlock
from utils import getFileSize

CHUNK_SIZE = 2048


def asymDecryptFile(inputFile: str, outputFile: str, privateKey: str, publicKey: str) -> None:
    """
    Asymmetrically Decrypt File.
    :param inputFile: File to be encrypted
    :param outputFile: File to save the encrypted data
    :param privateKey: Private Key
    :param publicKey: Public Key
    :return: None
    """
    RSAPrivateModuleSize = int(RSA.importKey(open(privateKey).read()).size_in_bytes())
    RSAPublicModuleSize = int(RSA.importKey(open(publicKey).read()).size_in_bytes())

    with open(outputFile, 'wb') as writer, open(inputFile, 'rb') as reader:
        try:
            cipheredKey = reader.read(RSAPrivateModuleSize)
            iv = reader.read(AES.block_size)

            RSAOAEPCipher = PKCS1_OAEP.new(
                RSA.importKey(open(privateKey).read()),
                hashAlgo=SHA256.new()
            )
            kc = RSAOAEPCipher.decrypt(cipheredKey)

            PSS = pss.new(
                RSA.importKey(open(publicKey).read())
            )
            h = SHA256.new()
            h.update(cipheredKey)
            h.update(iv)

            currentCursorPosition = reader.tell()
            fileSize = getFileSize(reader)

            reader.seek(currentCursorPosition, 0)

            decipher = AES.new(kc, AES.MODE_CBC, iv=iv)
            while True:
                remainingBytes = fileSize - reader.tell()
                if remainingBytes - CHUNK_SIZE > RSAPublicModuleSize:
                    chunk = reader.read(CHUNK_SIZE)
                elif remainingBytes - RSAPublicModuleSize > RSAPublicModuleSize:
                    chunk = reader.read(remainingBytes - RSAPublicModuleSize)
                else:
                    break

                decrypted_bytes = symDecryptBlock(decipher, chunk, AES.block_size)
                writer.write(decrypted_bytes)
                h.update(chunk)

            signature = reader.read(RSAPublicModuleSize)
            PSS.verify(h, signature)
        except ValueError as e:
            print('[-]', e)
