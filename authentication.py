# authentication.py

import hashlib
import os

def hash_password(password):
    """
    Hashes the given password using a secure hashing algorithm.

    Args:
        password (str): The user's password.

    Returns:
        str: The hashed password.
    """
    # Generate a random salt
    salt = os.urandom(32)

    # Combine the password and salt and hash using SHA-256
    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)

    # Return the hashed password and salt as a tuple
    return hashed_password, salt

def verify_password(input_password, stored_password, salt):
    """
    Verifies the input password against the stored hashed password.

    Args:
        input_password (str): The password entered by the user.
        stored_password (str): The hashed password stored in the database.
        salt (str): The salt used during password hashing.

    Returns:
        bool: True if the passwords match, False otherwise.
    """
    # Hash the input password with the stored salt
    hashed_input_password = hashlib.pbkdf2_hmac('sha256', input_password.encode('utf-8'), salt, 100000)

    # Compare the hashed input password with the stored hashed password
    return hashed_input_password == stored_password
