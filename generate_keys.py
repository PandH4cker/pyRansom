from Crypto.Random import get_random_bytes


def generate_keys(N: int) -> bytes:
    try:
        return get_random_bytes(N)
    except ValueError:
        return b''


if __name__ == '__main__':
    print(generate_keys(-1))
