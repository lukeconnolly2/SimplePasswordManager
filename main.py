import base64
import json
import string
import random
from os.path import exists
import bcrypt
from cryptography.fernet import Fernet


# For future use
class PasswordInfo:
    name = ""
    password = ""
    url = ""

    def __init__(self, name, password, url=None):
        name = self.name
        password = self.password
        url = self.url


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
        display_passwords(passwords)
    else:
        print("No passwords saved")
        passwords = {}
        write_passwords(passwords, key)

    main_menu(key)

    return


def main_menu(key):
    while True:
        passwords = load_passwords(key)
        user_input = input("\n\nEnter 1 to display passwords\n"
                           "Enter 2 to add a new password\n"
                           "Enter 3 to remove a stored password\n"
                           "Enter 4 to update a password\n"
                           "Enter 5 to exit\n")
        if user_input == "1":
            display_passwords(passwords)
        elif user_input == "2":
            add_password(passwords, key)
        elif user_input == "3":
            remove_password(passwords, key)
        elif user_input == "4":
            update_password(passwords, key)
        elif user_input == "5":
            exit(1)
        else:
            print("Input not allowed")


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


def add_password(passwords, key):
    name = input("Name of password: ").lower()
    if name in passwords.keys():
        user_input = input(
            f"{name} already has an entry: {passwords.get(name)}, do you want to overwrite it? (yes/no): ").lower()
        if user_input == "no":
            return

    use_generated = input("Use generated password? (yes/no): ").lower()
    if use_generated == "yes":
        password = password_generator()
        print(f"Your generated password is : {password}")
    else:
        password = input("Enter your password: ")

    passwords.update({name: password})
    write_passwords(passwords, key)


def display_passwords(passwords):
    for key in passwords.keys():
        print(f"{key}: {passwords.get(key)}")


def remove_password(passwords, key):
    if len(passwords) == 0:
        print("No Passwords to remove !")
        return
    display_passwords(passwords)
    while True:
        title = input("Enter the name of the password to remove: ")
        if title not in passwords.keys():
            passwords.pop(title)
            write_passwords(passwords, key)
            print("Password Sucsessfully removed")
            break
        else:
            print("Name doesnt refer to any passwords?!?! ")


def update_password(passwords, key):
    display_passwords(passwords)
    if len(passwords) == 0:
        print("No Passwords to update !")
        return
    user_input = input("What password would you like to update: ").lower()
    if not user_input in passwords.keys():
        create_new_password = input(
            "This password is not in the database, Would you like to add it? (yes/no): ").lower()
    if create_new_password == "no":
        return

    password_can_be_updated = False
    while not password_can_be_updated:
        new_password = input("Enter what to update the password to: ")
        re_new_password = input("Re-Enter the password: ")
        if new_password != re_new_password:
            print("Passwords dont match, Try again")
        else:
            password_can_be_updated = True

    passwords.update({user_input: new_password})
    write_passwords(passwords, key)
    print(f"Successfully updated, {user_input} : {new_password}")


if __name__ == '__main__':
    main()
