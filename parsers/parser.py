import argparse


def buildParser() -> argparse.ArgumentParser:
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

    return parser
