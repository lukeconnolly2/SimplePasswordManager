import string
import random
from os.path import exists
import bcrypt


def main():
    if not exists("masterpassword.bin"):
        create_password()

    master_password = input("Enter your master password: ")

    if not bcrypt.checkpw(master_password.encode("utf-8"), load_master_password()):
        print("Wrong Password")
        exit(1)

    print("Password was correct")
    return


def password_generator(s=10):
    possible_characters = string.ascii_letters + string.digits + "%$#()*"
    password = ""
    while s > 0:
        password = password + random.choice(possible_characters)
        s = s - 1
    return password


def create_password():
    master_password = input("Enter a master password for your password manager: ")
    master_password_reinput = input("Re-Enter the password again: ")

    if master_password != master_password_reinput:
        print("Passwords do not match, Try again!")
        create_password()

    masterpassword_bytes = master_password.encode('utf-8')
    salt = bcrypt.gensalt()
    hash = bcrypt.hashpw(masterpassword_bytes, salt)
    with open("masterpassword.bin", "wb") as f:
        f.write(hash)
    print("Successfully wrote password to file")


def load_master_password():
    with open("masterpassword.bin", "rb") as f:
        return f.read()


if __name__ == '__main__':
    main()
