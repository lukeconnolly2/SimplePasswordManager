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

    key = base64.urlsafe_b64encode(bcrypt.kdf(master_password, b"salt", 32, 50))

    if exists("passwords.bin"):
        passwords = load_passwords(key)
        print("Current stored passwords:")
        print(passwords)
    else:
        print("No passwords saved")
        passwords = {}

    if input("Do you want to add a password: (yes/no)").lower() == "yes":
        passwords = add_password(passwords)
        write_passwords(passwords, key)

    passwords = load_passwords(key)
    print(passwords)
    return


# Generate a password of size s
def password_generator(s=10):
    possible_characters = string.ascii_letters + string.digits + "%$#()*"
    password = ""
    while s > 0:
        password = password + random.choice(possible_characters)
        s = s - 1
    return password


# Function to create a master password
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


# Returns encrypted master password from file
def load_master_password():
    with open("masterpassword.bin", "rb") as f:
        return f.read()


# Writes password dictonary to encrypted file
def write_passwords(dict, key):
    fernet = Fernet(key)
    passwords_data = json.dumps(dict)
    passwords_encrypted = fernet.encrypt(passwords_data.encode("utf-8"))
    with open("passwords.bin", "wb") as f:
        f.write(passwords_encrypted)


# Loads and returns passwords dictionary from file
def load_passwords(key):
    fernet = Fernet(key)
    with open("passwords.bin", "rb") as f:
        dict_encrypted = f.read()
    dict_decyrpted = fernet.decrypt(dict_encrypted)
    return json.loads(dict_decyrpted)


def add_password(passwords):
    name = input("Name of password: ")
    use_generated = input("Use generated password? (yes/no): ").lower()
    if use_generated == "yes":
        password = password_generator()
        print(f"Your generated password is : {password}")
    else:
        password = input("Enter your password: ")

    passwords.update({name : password})
    return passwords

if __name__ == '__main__':
    main()
