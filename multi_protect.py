from sys import argv, executable
from os import system

if __name__ == '__main__':
    try:
        if argv[1] == '-e':
            exit(system(f"{executable} pyRansom.py -e "
                        f"--input {argv[2]} "
                        f"--output {argv[3]} "
                        f"asym -priv {argv[4]} "
                        f"-pub {argv[5]} {' '.join(argv[6:])}"))
        elif argv[1] == '-d':
            exit(system(f"{executable} pyRansom.py -d "
                        f"--input {argv[2]} --output {argv[3]} "
                        f"asym -priv {argv[4]} "
                        f"-pub {argv[5]} {argv[6]}"))
    except IndexError as e:
        print(f"Usage: {argv[0]} -e|-d <input_file> <output_file> <private_key> <public_key> [<user1_public_key... ["
              "userN_public_key]]|<sender_public_key>")
