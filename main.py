import string
import random


def main():
    print(passwordGenerator())
    return


def passwordGenerator(s=10):
    possible_characters = string.ascii_letters + string.digits + "%$#()*"
    password = ""
    while s > 0:
        password = password + random.choice(possible_characters)
        s = s - 1
    return password


if __name__ == '__main__':
    main()
