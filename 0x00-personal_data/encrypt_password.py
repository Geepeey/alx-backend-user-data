#!/usr/bin/env python3
"""
Defines a hash_password function to return a hashed password
"""
import bcrypt
from bcrypt import hashpw


def hash_password(password: str) -> bytes:
    """
    A hash_password function that expects one
    string argument name password and returns a
    salted, hashed password, which is a byte string
    """
    b = password.encode()
    hashed = hashpw(b, bcrypt.gensalt())
    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Function that expects 2 arguments and returns a boolean
    """
    return bcrypt.checkpw(password.encode(), hashed_password)
