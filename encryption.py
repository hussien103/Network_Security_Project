from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
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