from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def generate_rsa_keys():
    """
    Generate a pair of RSA keys (private and public).
    
    Returns:
        tuple: (public_key, private_key)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return public_key, private_key

def export_public_key(public_key: rsa.RSAPublicKey) -> bytes:
    """
    Export the RSA public key as PEM bytes.
    """
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem

def load_public_key(public_key_pem: bytes) -> rsa.RSAPublicKey:
    """
    Load the public key from a PEM-encoded format (bytes) into an RSAPublicKey object.
    """
    return serialization.load_pem_public_key(public_key_pem)

def sign_message(message, private_key):
    """
    Sign a message using the RSA private key.
    
    Args:
        message (str): The message to sign.
        private_key: RSA private key object.
    
    Returns:
        bytes: The digital signature.
    """
    signature = private_key.sign(
        message.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(message, signature, public_key):
    """
    Verify a message signature using the RSA public key.
    
    Args:
        message (str): The original message.
        signature (bytes): The digital signature.
        public_key: RSA public key object.
    
    Returns:
        bool: True if the signature is valid, False otherwise.
    """

    try:
        public_key.verify(
            signature,
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False