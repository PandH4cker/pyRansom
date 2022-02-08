import sys

from core import symEncryptFile, symDecryptFile, generate_keys
from core.asymmetric import asymEncryptFile
from core.asymmetric.decrypt import asymDecryptFile
from parsers import buildParser

SALT_SIZE = 8

if __name__ == '__main__':
    args = buildParser().parse_args()

    inputFile = args.input
    outputFile = args.output

    if args.cmd == 'sym':
        password = args.password
        if args.encrypt:
            symEncryptFile(inputFile, outputFile, password.encode(), generate_keys(SALT_SIZE))
        elif args.decrypt:
            symDecryptFile(inputFile, outputFile, password.encode())
    elif args.cmd == 'asym':
        privateKey = args.private_key
        publicKey = args.public_key
        if args.encrypt:
            asymEncryptFile(inputFile, outputFile, privateKey, publicKey, vars(args)['users-public-keys'])
        if args.decrypt:
            asymDecryptFile(inputFile, outputFile, privateKey, publicKey, vars(args)['users-public-keys'][0])
