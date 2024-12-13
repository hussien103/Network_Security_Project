# Updated client.py
import socket
import threading
from encryption import *

def send_messages(client_socket, aes_key, client_id, private_key):
    """Thread function to send messages."""
    while True:
        message = input(f"[{client_id}] Enter message: ")
        signature = sign_message(message, private_key)

        # Convert the signature to Base64 encoding to avoid decoding issues
        signature_base64 = base64.b64encode(signature).decode('utf-8')

        # Combine the signature and the encrypted message
        encrypted_message = encrypt_message_aes(message, aes_key)
        payload = f"{signature_base64}::{encrypted_message}"

        client_socket.sendall(payload.encode())
        print(f"[{client_id}] Sent (Encrypted): {encrypted_message}")

        if message.lower() == "exit":
            break

def receive_messages(client_socket, aes_key, client_id, other_public_key):
    """Thread function to receive messages."""
    while True:
        try:
            data = client_socket.recv(4096).decode()
            if not data:
                print(f"[{client_id}] Connection closed by server.")
                break

            # Split the received payload into signature and encrypted message
            signature, encrypted_message = data.split("::")
            signature = base64.b64decode(signature)

            decrypted_message = decrypt_message_aes(encrypted_message, aes_key)

            # Verify the signature using the decrypted message
            if verify_signature(decrypted_message, signature, other_public_key):
                print(f"[{client_id}] Received (Verified): {decrypted_message}")
            else:
                print(f"[{client_id}] Received message failed verification.")

        except ConnectionResetError:
            print(f"[{client_id}] Server connection lost.")
            break

def start_client(client_id):
    host = '127.0.0.1'
    port = 65432

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))
        client_socket.sendall(client_id.encode())  # Send client ID to the server
        print(f"[{client_id}] Connected to server at {host}:{port}")

        # Generate RSA keys
        private_key, public_key = generate_rsa_keys()
        client_socket.sendall(public_key)  # Send public key to the server
        print(f"[{client_id}] Sent RSA public key to server.")

        # Receive the other client's public key
        other_public_key = client_socket.recv(2048)
        print(f"[{client_id}] Received RSA public key from the other client.")

        # Key exchange logic
        aes_key = b""
        if client_id == "Client 1":
            encrypted_aes_key = client_socket.recv(256)
            print(f"[{client_id}] Received encrypted AES key from Client 2.")
            aes_key = decrypt_with_rsa(encrypted_aes_key, private_key)
            print(f"[{client_id}] Decrypted AES key: {aes_key}")
        elif client_id == "Client 2":
            aes_key = generate_key()
            print(f"[{client_id}] Generated AES key: {aes_key}")
            encrypted_aes_key = encrypt_with_rsa(aes_key, other_public_key)
            client_socket.sendall(encrypted_aes_key)
            print(f"[{client_id}] Sent encrypted AES key to Client 1.")

        # Start threads for communication
        send_thread = threading.Thread(target=send_messages, args=(client_socket, aes_key, client_id, private_key))
        receive_thread = threading.Thread(target=receive_messages, args=(client_socket, aes_key, client_id, other_public_key))

        send_thread.start()
        receive_thread.start()

        # Wait for threads to finish
        send_thread.join()
        receive_thread.join()

if __name__ == "__main__":
    client_id = input("Enter Client ID (e.g., Client 1 or Client 2): ")
    start_client(client_id)