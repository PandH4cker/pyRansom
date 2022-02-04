import string, sys, argparse

from Crypto.Cipher import AES
from Crypto.Hash.SHA256 import SHA256Hash
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad, unpad

from generate_keys import generate_keys
from generate_password import generate_password
from round_keys import round_keys


def encryptData(data: bytes, password: bytes, _salt: bytes):
    km = round_keys(password, _salt, 10)
    kc = SHA256Hash(km + (0x4c).to_bytes(32, 'little')).digest()
    ki = SHA256Hash(km + (0x4d).to_bytes(32, 'little')).digest()

    cipher = AES.new(kc, AES.MODE_CBC, iv=generate_keys(16))
    encrypted_bytes = cipher.encrypt(pad(data, AES.block_size))

    _mac_bytes = HMAC.new(ki, encrypted_bytes, digestmod=SHA256).digest()

    return _mac_bytes, cipher.iv, _salt, encrypted_bytes


def decryptData(_encrypted: bytes, _password: bytes, _salt: bytes, iv: bytes, mac: bytes):
    km = round_keys(_password, _salt, 10)
    kc = SHA256Hash(km + (0x4c).to_bytes(32, 'little')).digest()
    ki = SHA256Hash(km + (0x4d).to_bytes(32, 'little')).digest()

    HMAC.new(ki, _encrypted, digestmod=SHA256).verify(mac)

    uncipher = AES.new(kc, AES.MODE_CBC, iv=iv)
    decrypted_bytes = unpad(uncipher.decrypt(_encrypted), AES.block_size)

    return decrypted_bytes


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Encrypt/Decrypt given file")

    parser.add_argument(
        "--password",
        '-p',
        type=str,
        metavar="<Password>",
        help="Password to be used to encrypt/decrypt the file",
        required=True
    )

    inputOutputGroup = parser.add_argument_group("I/O")
    inputOutputGroup.add_argument(
        "--input",
        "-i",
        type=str,
        metavar="<Input Filename>",
        help="Input file to Encrypt/Decrypt",
        required=True
    )
    inputOutputGroup.add_argument(
        "--output",
        "-o",
        type=str,
        metavar="<Output Filename>",
        help="Output file to save the encrypted/decrypted",
        required=True
    )

    group = parser.add_argument_group("Cipher Mode")
    cipherGroup = group.add_mutually_exclusive_group(required=True)
    cipherGroup.add_argument(
        '--encrypt',
        '-e',
        help="Encrypt mode",
        action="store_true"
    )
    cipherGroup.add_argument(
        '--decrypt',
        '-d',
        help="Decrypt mode",
        action="store_true"
    )

    args = parser.parse_args()

    password = args.password
    inputFile = args.input
    outputFile = args.output

    if args.encrypt:
        with open(inputFile, 'rb') as f:
            mac, iv, salt, encrypted = encryptData(f.read(), password.encode(), generate_keys(8))

        with open(outputFile, 'wb') as writer:
            writer.write(salt)
            writer.write(iv)
            writer.write(mac)
            writer.write(encrypted)

    elif args.decrypt:
        with open(inputFile, "rb") as f:
            salt = f.read(8)
            iv = f.read(16)
            mac = f.read(32)
            decrypted = decryptData(f.read(), password.encode(), salt, iv, mac)

        with open(outputFile, "wb") as writer:
            writer.write(decrypted)