import json
import os
import socket
import threading
import base64
from encryption import decrypt_message_aes,encrypt_message_aes,generate_key
from diffie_hellman import generate_dh_params, compute_shared_key, compute_public_key, generate_private_dh_key, derive_aes_key
from rsa_key import *    # Assuming these functions are defined
from keys_storage_management import load_keys,save_keys,derive_aes_key_from_passphrase
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
            print("encrypted_message"+encrypted_message)
            print("aes key")
            print(aes_key)
            # Decrypt the message using AES key
            decrypted_message = decrypt_message_aes(encrypted_message, aes_key)
            print(f"Decrypted Message: {decrypted_message}")  # Debugging

            # Verify the signature using the decrypted message and RSA public key
            print(f"Signature for verification: {signature}")  # Debugging
            if verify_signature(decrypted_message, signature, other_public_key):
                print(f"[{client_id}] Received (Verified): {decrypted_message}")
            else:
                print(f"[{client_id}] Received message failed verification.")
        except ConnectionResetError:
            print(f"[{client_id}] Server connection lost.")
            break


        

def authenticate(client_socket, client_id):
    password = input(f"Enter password for {client_id}: ")
    
    # Send client ID, password, and RSA public key as raw bytes
    client_socket.sendall(f"{client_id}::{password}".encode())
    
    response = client_socket.recv(1024).decode()

    if response == "AUTH_SUCCESS":
        print(f"[{client_id}] Authentication successful.")
        return True
    elif response == "REGISTERED_SUCCESS":
        print(f"[{client_id}] Registration successful.")
        return True
    else:
        print(f"[{client_id}] Authentication failed.")
        return False



def start_client(client_id):
    host = '127.0.0.1'
    port = 65432

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        
        passphrase = input("Enter your passphrase: ")

        client_socket.connect((host, port))
        print(f"[{client_id}] Connected to server at {host}:{port}")

        owner_aes_key = derive_aes_key_from_passphrase(passphrase)        # Load keys or generate new ones
        rsa_public_key, rsa_private_key, private_dh_key = load_keys(client_id,owner_aes_key)
        if not rsa_public_key or not rsa_private_key or not private_dh_key:
            rsa_public_key, rsa_private_key = generate_rsa_keys()
            private_dh_key = generate_private_dh_key()
            save_keys(client_id, rsa_public_key, rsa_private_key, private_dh_key,owner_aes_key)
        else:
            print(f"[{client_id}] Using existing keys.")

        # Step 2: Authentication and send RSA public key as raw bytes
        if not authenticate(client_socket, client_id):
            return
        rsa_public_key_pem = export_public_key(rsa_public_key)
        client_socket.sendall(rsa_public_key_pem)  # Send RSA public key in PEM format
        print(f"[{client_id}] Sent RSA public key.")

        # Step 3: Receive other client's RSA public key (raw bytes)
        other_public_key = client_socket.recv(1024)
        print(f"[{client_id}] Received other client's RSA public key.")
        other_public_key = load_public_key(other_public_key)

        # Step 4: Receive Diffie-Hellman parameters
        dh_params = client_socket.recv(1024).decode().split("::")
        q = int(dh_params[0])
        alpha = int(dh_params[1])
        print(f"[{client_id}] Received DH parameters: q={q}, alpha={alpha}")

        # Step 5: Generate and send public DH key
        public_dh_key = compute_public_key(private_dh_key, q, alpha)
        client_socket.sendall(str(public_dh_key).encode())
        print(f"[{client_id}] Sent DH public key.")

        # Step 6: Receive the other client's public DH key
        other_public_dh_key = int(client_socket.recv(1024).decode())
        print(f"[{client_id}] Received other client's DH public key: {other_public_dh_key}")

        # Step 7: Compute shared AES key
        shared_key = compute_shared_key(other_public_dh_key, private_dh_key, q)
        aes_key = derive_aes_key(shared_key)
        print(f"[{client_id}] Shared AES key established.")

        # Start communication threads
        send_thread = threading.Thread(target=send_messages, args=(client_socket, aes_key, client_id, rsa_private_key))
        receive_thread = threading.Thread(target=receive_messages, args=(client_socket, aes_key, client_id, other_public_key))

        send_thread.start()
        receive_thread.start()

        send_thread.join()
        receive_thread.join()

if __name__ == "__main__":
    client_id = input("Enter Client ID (Client 1 or Client 2): ")
    start_client(client_id)
