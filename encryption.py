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


def generate_rsa_keys():
    """
    Generate an RSA key pair.
    :return: A tuple of (private_key, public_key)
    """
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


# def encrypt_with_rsa(aes_key, recipient_public_key):
#     """
#     Encrypt data using an RSA public key.
#     :param aes_key: Data to encrypt (bytes)
#     :param recipient_public_key: The RSA public key object
#     :return: Encrypted data as bytes
#     """
#     rsa_key = RSA.import_key(recipient_public_key)
#     cipher = PKCS1_OAEP.new(rsa_key)

#     # Ensure the AES key is the right size (16 bytes for AES-128)
#     if len(aes_key) > 245:  # Maximum size for RSA-2048 with PKCS1_OAEP
#         raise ValueError("AES key is too large for RSA encryption.")

#     encrypted_aes_key = cipher.encrypt(aes_key.encode())
#     return base64.b64encode(encrypted_aes_key).decode() # Return as raw bytes




# def decrypt_with_rsa(encrypted_aes_key, private_key):
#     """
#     Decrypt data using an RSA private key.
#     :param encrypted_aes_key: Base64-encoded encrypted AES key
#     :param private_key: The RSA private key object
#     :return: Decrypted AES key (bytes)
#     """
#     # Decrypt using RSA private key
#     rsa_key = RSA.import_key(private_key)
#     cipher = PKCS1_OAEP.new(rsa_key)
#     decrypted_aes_key = cipher.decrypt(base64.b64decode(encrypted_aes_key.encode()))
#     return decrypted_aes_key.decode()


def encrypt_with_rsa(aes_key, recipient_public_key):
    """
    Encrypt data using an RSA public key.
    :param aes_key: Data to encrypt (bytes)
    :param recipient_public_key: The RSA public key object
    :return: Encrypted data as bytes
    """
    rsa_key = RSA.import_key(recipient_public_key)
    cipher = PKCS1_OAEP.new(rsa_key)

    # Ensure the AES key is the right size (16 bytes for AES-128)
    if len(aes_key) > 245:  # Maximum size for RSA-2048 with PKCS1_OAEP
        raise ValueError("AES key is too large for RSA encryption.")

    encrypted_aes_key = cipher.encrypt(aes_key)
    return encrypted_aes_key  # Return as raw bytes



def decrypt_with_rsa(encrypted_aes_key, private_key):
    """
    Decrypt data using an RSA private key.
    :param encrypted_aes_key: Base64-encoded encrypted AES key
    :param private_key: The RSA private key object
    :return: Decrypted AES key (bytes)
    """
    # Decrypt using RSA private key
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    decrypted_aes_key = cipher.decrypt(encrypted_aes_key)
    return decrypted_aes_key



def hash_message(message):
    """
    Hash the message using SHA-256.
    :param message: The original message (str)
    :return: The hash digest (bytes)
    """
    hash_object = SHA256.new(message.encode())
    return hash_object

def sign_message(message, private_key):
    """
    Sign the hashed message with the sender's private key.
    :param message: The original message (str)
    :param private_key: Sender's RSA private key (PEM format)
    :return: The digital signature (bytes)
    """
    rsa_key = RSA.import_key(private_key)
    hashed_message = hash_message(message)
    signature = pkcs1_15.new(rsa_key).sign(hashed_message)
    return signature

def verify_signature(message, signature, public_key):
    """
    Verify the digital signature of a message.
    :param message: The received message (str)
    :param signature: The digital signature (bytes)
    :param public_key: Sender's RSA public key (PEM format)
    :return: True if valid, False otherwise
    """
    rsa_key = RSA.import_key(public_key)
    hashed_message = hash_message(message)
    try:
        pkcs1_15.new(rsa_key).verify(hashed_message, signature)
        return True
    except (ValueError, TypeError):
        return False
