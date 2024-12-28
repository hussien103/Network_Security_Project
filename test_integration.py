import unittest
from unittest.mock import Mock, patch, MagicMock
import os
import json
import base64
from encryption import encrypt_message_aes, decrypt_message_aes
from diffie_hellman import compute_shared_key, compute_public_key, derive_aes_key
from rsa_key import generate_rsa_keys, sign_message, verify_signature
from cryptography.hazmat.primitives import serialization
from client import save_keys, load_keys, authenticate, send_messages, receive_messages,derive_aes_key_from_passphrase  # Import necessary functions from client.py


class TestClientServerIntegration(unittest.TestCase):

    def setUp(self):
        # Setup reusable keys and data for both client and server
        self.passphrase = "test"
        self.owner_aes_key = derive_aes_key_from_passphrase("test")
        self.rsa_public_key, self.rsa_private_key = generate_rsa_keys()
        self.private_dh_key = 12345
        self.q = 23
        self.alpha = 5
        self.other_dh_public_key = compute_public_key(self.private_dh_key, self.q, self.alpha)
        self.shared_key = compute_shared_key(self.other_dh_public_key, self.private_dh_key, self.q)
        self.aes_key = derive_aes_key(self.shared_key)

        self.client_id = "client 1"

    @patch('socket.socket')
    def test_integration_scenario(self, mock_socket):
        # 1. Setup mock server and socket for communication
        
        message = "Test message"
        mock_socket.recv = MagicMock(side_effect=[  # Mocking server's responses as bytes
            b"AUTH_SUCCESS",  # Simulate server authentication response
          base64.b64encode(sign_message(message,self.rsa_private_key)).decode('utf-8')+"::" + encrypt_message_aes(message, self.aes_key),  # Simulate server sending an encrypted message back
        ])

        # 2. Save keys (simulating storing of RSA and DH keys)
        save_keys(self.client_id, self.rsa_public_key, self.rsa_private_key, self.private_dh_key,self.owner_aes_key)

        # 3. Client authenticates with the server
        result = authenticate(mock_socket, self.client_id)
        self.assertTrue(result, "Authentication failed")

        # 4. Client sends an encrypted message to the server
       
        encrypted_message = encrypt_message_aes(message, self.aes_key)
        print("Encryption passed")
        signature = sign_message(message,self.rsa_private_key)
        # Here we simulate sending the message over the socket
        mock_socket.sendall(encrypted_message.encode())

  
        # 6. Client receives the encrypted server response and decrypts it
        encrypted_response = mock_socket.recv(1024)
        signature, encrypted_message = encrypted_response.split("::")  # Split on byte delimiters

        signature = base64.b64decode(signature)
        decrypted_message = decrypt_message_aes(encrypted_message, self.aes_key)

        # Verify the decrypted response from the server matches the expected message
        self.assertEqual(decrypted_message, "Test message")
        if(decrypted_message == "Test message"):
            print("Decryption passed")
        else :
            print("Decryption failed")    
        # 7. Message signature verification (client signs and server verifies)
      
        self.assertTrue(verify_signature(message, signature, self.rsa_public_key), "Signature verification failed")
        print("Signature verified")
        # Cleanup
        os.remove(f"{self.client_id}_keys_encrypted.json")

    def tearDown(self):
        # Additional cleanup can go here if necessary
        pass


if __name__ == "__main__":
    unittest.main()
