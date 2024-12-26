import random
from hashlib import sha256

def generate_dh_params():
    """Generate large prime number (q) and primitive root (alpha)."""
    q = int("""
        FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
        29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
        EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
        E485B576 625E7EC6 F44C42E9 A63A3620 FFFFFFFF FFFFFFFF
    """.replace(" ", "").replace("\n", ""), 16)
    alpha = 2
    return q, alpha

def generate_private_dh_key():
    """Generate a random private key for Diffie-Hellman."""
    return random.randint(2, 2**2048)

def compute_public_key(private_key, q, alpha):
    """Compute the public key for Diffie-Hellman."""
    return pow(alpha, private_key, q)

def compute_shared_key(public_key, private_key, q):
    """Compute the shared key using the other party's public key."""
    return pow(public_key, private_key, q)

def derive_aes_key(shared_key):
    """Derive a 256-bit AES key from the shared key using a hash function."""
    shared_key_bytes = str(shared_key).encode()
    return sha256(shared_key_bytes).digest()
