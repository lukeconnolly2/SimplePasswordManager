import base64
import json
import string
import random
from os.path import exists
import bcrypt
from cryptography.fernet import Fernet


def main():
    if not exists("masterpassword.bin"):
        create_password()

    master_password = input("Enter your master password: ").encode("utf-8")


    if not bcrypt.checkpw(master_password, load_master_password()):
        print("Wrong Password")
        exit(1)



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


def write_passwords(dict, masterpassword):
    key = base64.urlsafe_b64encode(bcrypt.kdf(masterpassword, b"salt", 32, 50))
    fernet = Fernet(key)
    passwords_data = json.dumps(dict)
    passwords_encrypted = fernet.encrypt(passwords_data.encode("utf-8"))
    with open("passwords.bin", "wb") as f:
        f.write(passwords_encrypted)

def load_passwords(masterpassword):
    key = base64.urlsafe_b64encode(bcrypt.kdf(masterpassword,b"salt" ,32, 50))
    fernet = Fernet(key)

    with open("passwords.bin", "rb") as f:
        dict_encrypted = f.read()
    dict_decyrpted = fernet.decrypt(dict_encrypted)
    return json.loads(dict_decyrpted)

if __name__ == '__main__':
    main()
