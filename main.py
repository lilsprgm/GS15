import numpy as np
import bitarray
import os
import json
import KDF
import Cobra
from Cobra import inv_sbox, inv_bits_order, trans_lineaire, key_scheduling, split_binary_file, inv_trans_lineaire, \
    feistel, inv_feistel


def setup_user_repo():
    """
    Ensure the 'users' repository exists.
    """
    repo_name = "users"
    if not os.path.exists(repo_name):
        os.makedirs(repo_name)
        print(f"The '{repo_name}' repository has been created.")

    # Make sure the repo is only accessible by the program, or that the json file are only readable by the program itself or the admin.

def key_derivation_function(password):
    public_key = KDF.derive_key_from_password(password)
    return public_key

def save_user_profile(username, password):
    """
    Save the user profile to a file with the username as the filename.
    """
    # Ensure the users directory exists
    setup_user_repo()

    # Hash the password


    # Define the user profile with only username and hashed password
    user_profile = {
        "username": username,
        "hashed_password": key_derivation_function(password),  # decode for JSON compatibility
        "public_key": "",
        "private_key": "",
        "permissions": []
    }

    # File path for the user profile
    file_path = os.path.join("users", f"{username}.json")

    # Save the user profile as a JSON file
    with open(file_path, 'w') as file:
        json.dump(user_profile, file, indent=4)

    print(f"User profile for '{username}' has been created.")


def create_new_user():
    """
    Collects username and password, validates password, and saves the user profile.
    """

    username = input("Enter username: ")

    # Password validation loop
    while True:
        password = input("Enter password: ")

        # Validate password
        if len(password) < 8:
            print("Password must be at least 8 characters long.")
        elif not any(char.isupper() for char in password):
            print("Password must contain at least one uppercase letter.")
        elif not any(char.isdigit() for char in password):
            print("Password must contain at least one number.")
        else:
            # Save user profile if password is valid
            save_user_profile(username, password)
            break


#def login():


def menu(input):
    if input==1:
        create_new_user()
    elif input==2:
        login()


if __name__ == '__main__':
    key = KDF.create_password()
    Cobra.sym_encryption_cobra('test.txt', key, 1)
    Cobra.sym_decryption_cobra('test.txt', key, 1)

    """
    bin_file = Cobra.sbox(bin_file)
    bin_file = inv_sbox(bin_file)
  
    while True:
        nb_menu = int(input("Choose function :\n"
              "1 : Create new user \n"
              "2 : Login\n"))
        menu(nb_menu)   """

