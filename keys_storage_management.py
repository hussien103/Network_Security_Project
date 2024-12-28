
import json
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from encryption import decrypt_message_aes, encrypt_message_aes
def derive_aes_key_from_passphrase(passphrase: str, iterations: int = 100000) -> bytes:
    """Derive a 256-bit AES key from the passphrase using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key for AES
        salt = b"constant_salt",
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())
def save_keys(client_id, rsa_public_key, rsa_private_key, private_dh_key, aes_key):
    """Save the keys to a JSON file encrypted with AES."""
    key_data = {
        "rsa_public_key": rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8'),
        "rsa_private_key": rsa_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8'),
        "private_dh_key": private_dh_key
    }

    # Encrypt the key data with AES
    encrypted_key_data = encrypt_message_aes(json.dumps(key_data), aes_key)

    # Store the encrypted data and the AES key securely (or just store the encrypted data for simplicity)
    save_data = {
        "encrypted_key_data": encrypted_key_data,
    }

    with open(f"{client_id}_keys_encrypted.json", "w") as key_file:
        json.dump(save_data, key_file)
    print(f"[{client_id}] Keys saved to encrypted file.")

def load_keys(client_id, aes_key):
    """Load and decrypt the keys from a JSON file."""
    if os.path.exists(f"{client_id}_keys_encrypted.json"):
        with open(f"{client_id}_keys_encrypted.json", "r") as key_file:
            encrypted_data = json.load(key_file)
        
        # Decrypt the key data using the AES key
        decrypted_key_data = decrypt_message_aes(encrypted_data["encrypted_key_data"], aes_key)
        key_data = json.loads(decrypted_key_data)
        
        rsa_public_key = serialization.load_pem_public_key(
            key_data["rsa_public_key"].encode('utf-8')
        )
        rsa_private_key = serialization.load_pem_private_key(
            key_data["rsa_private_key"].encode('utf-8'),
            password=None
        )
        private_dh_key = key_data["private_dh_key"]
        print(f"[{client_id}] Keys loaded from encrypted file.")
        return rsa_public_key, rsa_private_key, private_dh_key
    return None, None, None