import argparse


def buildParser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Encrypt/Decrypt given file")

    subparsers = parser.add_subparsers(help="Encryption Mode")

    symmetricParser = subparsers.add_parser("sym", help="Symmetric Mode")
    symmetricParser.set_defaults(cmd="sym")

    asymmetricParser = subparsers.add_parser("asym", help="Asymmetric Mode")
    asymmetricParser.set_defaults(cmd="asym")

    symmetricEncryptionGroup = symmetricParser.add_argument_group("Symmetric Encryption")
    symmetricEncryptionGroup.add_argument(
        "--password",
        '-p',
        type=str,
        metavar="<Password>",
        help="Password to be used to encrypt/decrypt the file",
        required=True
    )

    asymmetricEncryptionGroup = asymmetricParser.add_argument_group("Asymmetric Encryption")
    asymmetricEncryptionGroup.add_argument(
        '--private-key',
        '-priv',
        type=str,
        metavar="<Private Key Filename>",
        help="Receiver/Sender Private Key",
        required=True
    )
    asymmetricEncryptionGroup.add_argument(
        '--public-key',
        '-pub',
        type=str,
        metavar="<Public Key Filename>",
        help="Receiver/Sender Public Key",
        required=True
    )
    asymmetricEncryptionGroup.add_argument(
        'users-public-keys',
        nargs='*',
        type=str,
        metavar="<User Public Key>",
        help="User Public Key (Multi-Protected File)"
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
