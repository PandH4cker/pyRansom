from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Hash.SHA256 import SHA256Hash
from Crypto.PublicKey import RSA
from Crypto.Signature import pss

from core import generate_keys
from core.symmetric.encrypt import symEncryptBlock

CHUNK_SIZE = 2048


def asymEncryptFile(inputFile: str, outputFile: str, privateKey: str, publicKey: str, users: list = None) -> None:
    """
    Asymmetrically Encrypt File.
    File Format: CIPHERED_KEY(RSA_MODULE_SIZE) | IV(16) | ENCRYPTED(?) | RSA-PSS-Signature(RSA_MODULE_SIZE)
    Multi-Protect Format: 0x00(1) | Sha256(OWN_PUBLIC_KEY)(32) | OWN_PUBLIC_KEY(KC | IV)(RSA_MODULE_SIZE) |
                          0x00(1) | Sha256(USER_1_PUB_KEY)(32) | USER_1_PUB_KEY(KC | IV)(RSA_MODULE_SIZE) ... |
                          0x01(1) | ENCRYPTED(?) | RSA-PSS(RSA_MODULE_SIZE)
    :param users: List of users that will have access to this file
    :param inputFile: File to be encrypted
    :param outputFile: File to save the encrypted data
    :param privateKey: Private Key
    :param publicKey: Public Key
    :return: None
    """
    kc = generate_keys(AES.key_size[2])

    with open(outputFile, 'wb') as writer, open(inputFile, 'rb') as reader:
        AESCipher = AES.new(kc, AES.MODE_CBC, iv=generate_keys(AES.block_size))

        PSS = pss.new(
            RSA.importKey(open(privateKey).read())
        )
        h = SHA256.new()

        if users:
            appendReceiver(AESCipher, h, kc, publicKey, writer)
            for userPublicKey in users:
                appendReceiver(AESCipher, h, kc, userPublicKey, writer)

            writer.write(0x01.to_bytes(4, 'little'))
            h.update(0x01.to_bytes(4, 'little'))
        else:
            RSAOAEPCipher = PKCS1_OAEP.new(
                RSA.importKey(open(publicKey).read()),
                hashAlgo=SHA256.new()
            )
            cipheredKey = RSAOAEPCipher.encrypt(kc)
            writer.write(cipheredKey)
            writer.write(AESCipher.iv)
            h.update(cipheredKey)
            h.update(AESCipher.iv)

        while chunk := reader.read(CHUNK_SIZE):
            encrypted_bytes = symEncryptBlock(AESCipher, chunk, AES.block_size)
            writer.write(encrypted_bytes)
            h.update(encrypted_bytes)

            AESCipher = AES.new(kc, AES.MODE_CBC, iv=encrypted_bytes[-AES.block_size:])
        writer.write(PSS.sign(h))


def appendReceiver(cipher, _hash, cipherKey, userPublicKey, writer):
    writer.write(0x00.to_bytes(4, 'little'))
    _hash.update(0x00.to_bytes(4, 'little'))
    userPublicKeySha256Sum = SHA256Hash(open(userPublicKey, 'rb').read()).digest()
    writer.write(userPublicKeySha256Sum)
    _hash.update(userPublicKeySha256Sum)
    UserRSAOAEPCipher = PKCS1_OAEP.new(
        RSA.importKey(open(userPublicKey).read()),
        hashAlgo=SHA256.new()
    )
    cipheredKeyIV = UserRSAOAEPCipher.encrypt(cipherKey + cipher.iv)
    writer.write(cipheredKeyIV)
    _hash.update(cipheredKeyIV)
