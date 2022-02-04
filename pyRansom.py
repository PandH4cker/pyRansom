from core import symEncryptFile, symDecryptFile, generate_keys
from parsers import buildParser

SALT_SIZE = 8

if __name__ == '__main__':
    args = buildParser().parse_args()

    password = args.password
    inputFile = args.input
    outputFile = args.output

    if args.encrypt:
        symEncryptFile(inputFile, outputFile, password.encode(), generate_keys(SALT_SIZE))

    elif args.decrypt:
        symDecryptFile(inputFile, outputFile, password.encode())
