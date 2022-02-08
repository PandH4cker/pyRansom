from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Hash.SHA256 import SHA256Hash
from Crypto.PublicKey import RSA
from Crypto.Signature import pss

from core.symmetric.decrypt import symDecryptBlock
from utils import getFileSize

CHUNK_SIZE = 2064


def asymDecryptFile(inputFile: str, outputFile: str, privateKey: str, publicKey: str, userPublicKey: str = "") -> None:
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

    PSS = pss.new(
        RSA.importKey(open(publicKey).read())
    )
    h = SHA256.new()

    with open(outputFile, 'wb') as writer, open(inputFile, 'rb') as reader:
        try:
            if userPublicKey:
                userPublicKeySha256Sum = SHA256Hash(open(userPublicKey, 'rb').read()).digest()
                while (flag := reader.read(4)) != 0x01.to_bytes(4, 'little'):
                    h.update(flag)

                    pubKeyNSha256Sum = reader.read(SHA256.digest_size)
                    h.update(pubKeyNSha256Sum)

                    if pubKeyNSha256Sum == userPublicKeySha256Sum:
                        cipheredKeyIV = reader.read(RSAPrivateModuleSize)
                        h.update(cipheredKeyIV)

                        UserRSAOAEPCipher = PKCS1_OAEP.new(
                            RSA.importKey(open(privateKey).read()),
                            hashAlgo=SHA256.new()
                        )
                        kcIV = UserRSAOAEPCipher.decrypt(cipheredKeyIV)
                        kc = kcIV[:AES.key_size[2]]
                        iv = kcIV[-AES.block_size:]
                    else: h.update(reader.read(RSAPrivateModuleSize))

                h.update(flag)

                if 'kc' not in locals() or 'iv' not in locals():
                    raise ValueError("You are not intended to read this file.")
            else:
                cipheredKey = reader.read(RSAPrivateModuleSize)
                iv = reader.read(AES.block_size)

                RSAOAEPCipher = PKCS1_OAEP.new(
                    RSA.importKey(open(privateKey).read()),
                    hashAlgo=SHA256.new()
                )
                kc = RSAOAEPCipher.decrypt(cipheredKey)

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
