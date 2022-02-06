from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss

from core import generate_keys
from core.symmetric.encrypt import symEncryptBlock

CHUNK_SIZE = 2048


def asymEncryptFile(inputFile: str, outputFile: str, privateKey: str, publicKey: str) -> None:
    """
    Asymmetrically Encrypt File.
    File Format: CIPHERED_KEY | IV | ENCRYPTED | RSA-PSS-Signature
    :param inputFile: File to be encrypted
    :param outputFile: File to save the encrypted data
    :param privateKey: Private Key
    :param publicKey: Public Key
    :return: None
    """
    kc = generate_keys(AES.key_size[2])

    with open(outputFile, 'wb') as writer, open(inputFile, 'rb') as reader:
        RSAOAEPCipher = PKCS1_OAEP.new(
            RSA.importKey(open(publicKey).read()),
            hashAlgo=SHA256.new()
        )
        AESCipher = AES.new(kc, AES.MODE_CBC, iv=generate_keys(AES.block_size))

        PSS = pss.new(
            RSA.importKey(open(privateKey).read())
        )
        h = SHA256.new()

        cipheredKey = RSAOAEPCipher.encrypt(kc)

        writer.write(cipheredKey)
        writer.write(AESCipher.iv)

        h.update(cipheredKey)
        h.update(AESCipher.iv)

        while chunk := reader.read(CHUNK_SIZE):
            encrypted_bytes = symEncryptBlock(AESCipher, chunk, AES.block_size)
            writer.write(encrypted_bytes)
            h.update(encrypted_bytes)
        writer.write(PSS.sign(h))
