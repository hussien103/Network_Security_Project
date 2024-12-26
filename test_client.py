import unittest
from unittest.mock import Mock, patch, MagicMock
import os
import json
import base64
from encryption import encrypt_message_aes, decrypt_message_aes
from diffie_hellman import compute_shared_key, compute_public_key, derive_aes_key
from rsa_key import generate_rsa_keys, sign_message, verify_signature
from cryptography.hazmat.primitives import serialization
from client import save_keys, load_keys, authenticate


class TestClientApplication(unittest.TestCase):

    def setUp(self):
        # Setup reusable keys and data
        self.rsa_public_key, self.rsa_private_key = generate_rsa_keys()
        self.private_dh_key = 12345
        self.q = 23
        self.alpha = 5
        self.other_dh_public_key = compute_public_key(self.private_dh_key, self.q, self.alpha)
        self.shared_key = compute_shared_key(self.other_dh_public_key, self.private_dh_key, self.q)
        self.aes_key = derive_aes_key(self.shared_key)

    def test_save_and_load_keys(self):
        client_id = "client 1"
        save_keys(client_id, self.rsa_public_key, self.rsa_private_key, self.private_dh_key)
        loaded_public_key, loaded_private_key, loaded_dh_key = load_keys(client_id)

        # Validate RSA keys
        self.assertEqual(
            self.rsa_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            loaded_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
        self.assertEqual(
            self.rsa_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ),
            loaded_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
        # Validate DH private key
        self.assertEqual(self.private_dh_key, loaded_dh_key)

        # Cleanup
        os.remove(f"{client_id}_keys.json")

    def test_aes_encryption_decryption(self):
        message = "Test Message"
        encrypted_message = encrypt_message_aes(message, self.aes_key)
        decrypted_message = decrypt_message_aes(encrypted_message, self.aes_key)
        self.assertEqual(message, decrypted_message)

    def test_signature_verification(self):
        message = "Verify this message"
        signature = sign_message(message, self.rsa_private_key)
        self.assertTrue(verify_signature(message, signature, self.rsa_public_key))

    @patch('builtins.input', return_value="test_password")
    @patch('socket.socket')
    def test_authenticate_success(self, mock_socket, mock_input):
        mock_socket.recv = MagicMock(side_effect=["AUTH_SUCCESS".encode()])
        client_id = "client 1"
        result = authenticate(mock_socket, client_id)
        self.assertTrue(result)

    @patch('builtins.input', return_value="test_password")
    @patch('socket.socket')
    def test_authenticate_failure(self, mock_socket, mock_input):
        mock_socket.recv = MagicMock(side_effect=["AUTH_FAILED".encode()])
        client_id = "client 1"
        result = authenticate(mock_socket, client_id)
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
