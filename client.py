import socket
import threading
from encryption import *

def send_messages(client_socket, aes_key, client_id):
    """Thread function to send messages."""
    while True:
        message = input(f"[{client_id}] Enter message: ")
        encrypted_message = encrypt_message_aes(message, aes_key)
        client_socket.sendall(encrypted_message.encode())
        print(f"[{client_id}] Sent (Encrypted): {encrypted_message}")
        if message.lower() == "exit":
            break

def receive_messages(client_socket, aes_key, client_id):
    """Thread function to receive messages."""
    while True:
        try:
            data = client_socket.recv(2048)
            if not data:
                print(f"[{client_id}] Connection closed by server.")
                break
            decrypted_message = decrypt_message_aes(data.decode(), aes_key)
            print(f"[{client_id}] Received (Decrypted): {decrypted_message}")
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
        aes_key = b""      
        # Client 1 specific logic
        if client_id == "Client 1":
            rsa_private_key, rsa_public_key = generate_rsa_keys()
            client_socket.sendall(rsa_public_key)  # Send public key to server
            print(f"[{client_id}] Sent RSA public key to server.")

            # Receive encrypted AES key from Client 2
            encrypted_aes_key = client_socket.recv(256)
            print(f"[{client_id}] Received encrypted AES key from Client 2.")
            aes_key = decrypt_with_rsa(encrypted_aes_key, rsa_private_key)
            print(f"[{client_id}] Decrypted AES key: {aes_key}")

        # Client 2 specific logic
        elif client_id == "Client 2":
            # Receive RSA public key of Client 1
            client_1_public_key = client_socket.recv(2048)
            print(f"[{client_id}] Received RSA public key from Client 1.")

            # Generate AES key and encrypt with Client 1's public key
            aes_key= generate_key()
            print(f"[{client_id}] aes key = {aes_key}")
            encrypted_aes_key = encrypt_with_rsa(aes_key, client_1_public_key)
            client_socket.sendall(encrypted_aes_key)  # Send encrypted AES key to server
            print(f"[{client_id}] Sent encrypted AES key to Client 1.")

        # Start threads for communication
        send_thread = threading.Thread(target=send_messages, args=(client_socket, aes_key, client_id))
        receive_thread = threading.Thread(target=receive_messages, args=(client_socket, aes_key, client_id))

        send_thread.start()
        receive_thread.start()

        # Wait for threads to finish
        send_thread.join()
        receive_thread.join()

if __name__ == "__main__":
    client_id = input("Enter Client ID (e.g., Client 1 or Client 2): ")
    start_client(client_id)



#  if client_id==2 :
#         other_rsa_private_key, other_rsa_public_key = generate_rsa_keys()
#         client_socket.sendall(other_rsa_public_key)
    
#     if client_id==1:
#         my_rsa_private_key, my_rsa_public_key = generate_rsa_keys()
#         other_rsa_public_key = client_socket.recv(256)