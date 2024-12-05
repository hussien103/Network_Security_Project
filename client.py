import socket
import threading
from encryption import *

def send_messages(client_socket, aes_key, client_id):
    """Thread function to send messages."""
    while True:
        message = input(f"[{client_id}] Enter message: ")
        encrypted_message = encrypt_message_aes(message, aes_key)
        client_socket.sendall(encrypted_message.encode())
        print(f"[{client_id}] Sent: {encrypted_message}")
        if message.lower() == "exit":
            break

def receive_messages(client_socket, shared_aes_key, client_id):
    """Thread function to receive messages."""
    while True:
        try:
            data = client_socket.recv(2048)
            if not data:
                print(f"[{client_id}] Connection closed by server.")
                break
            decrypted_message = decrypt_message_aes(data.decode(), shared_aes_key)
            print(f"[{client_id}] Received (Decrypted): {decrypted_message}")
        except ConnectionResetError:
            print(f"[{client_id}] Server connection lost.")
            break

def start_client(client_id):
    host = '127.0.0.1'
    port = 65432

    other_rsa_private_key, other_rsa_public_key = generate_rsa_keys()
    # private_key2, public_key2 = generate_rsa_keys()
    # Generate AES key
    aes_key = generate_key()
    print(f"[{client_id}] Generated AES Key: {aes_key}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))
        print(f"[{client_id}] Connected to {host}:{port}")
        
        encrypted_aes_key = encrypt_with_rsa(aes_key, other_rsa_public_key)
        # Send AES key to the server
        client_socket.sendall(encrypted_aes_key)
        print(f"[{client_id}] Sent Encrypted AES Key to Server.")
        print(f"{encrypted_aes_key}")
        # Receive the other client's AES key from the server
        shared_aes_key = client_socket.recv(256)  # 16 bytes for AES-128
        print(f"[{client_id}] Received Shared Encrypted AES Key: {shared_aes_key}")

        decrypt_aes_key = decrypt_with_rsa(shared_aes_key,other_rsa_private_key)
        print(f"{decrypt_aes_key}")

        # Start send and receive threads
        send_thread = threading.Thread(target=send_messages, args=(client_socket, aes_key,client_id))
        receive_thread = threading.Thread(target=receive_messages, args=(client_socket, decrypt_aes_key, client_id))

        send_thread.start()
        receive_thread.start()

        # Wait for threads to finish
        send_thread.join()
        receive_thread.join()

if __name__ == "__main__":
    client_id = input("Enter Client ID (e.g., Client 1): ")
    start_client(client_id)
