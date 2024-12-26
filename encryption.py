from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15


import base64

BLOCK_SIZE = 16  # AES block size

def pad(data):
    padding = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + (chr(padding) * padding).encode()

def unpad(data):
    padding = data[-1]
    return data[:-padding]

def encrypt_message_aes(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(plaintext.encode()))
    return base64.b64encode(encrypted).decode()

def decrypt_message_aes(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(base64.b64decode(ciphertext.encode())))
    return decrypted.decode()

def generate_key():
    return get_random_bytes(16)  # 16 bytes = 128-bit key


