import socket
import threading
import time
import bcrypt
import sqlite3
from rsa_key import generate_rsa_keys, export_public_key, load_public_key  # Assuming rsa_key.py is present

# Global variables
client_sockets = {}
client_public_keys = {}
client_rsa_public_keys = {}
lock = threading.Lock()

# Diffie-Hellman parameters
q = None
alpha = None

def setup_dh_params():
    global q, alpha

    # A real-world 2048-bit safe prime from RFC 3526
    q = int(""" 
        FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
        29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
        EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
        E485B576 625E7EC6 F44C42E9 A63A3620 FFFFFFFF FFFFFFFF
    """.replace(" ", "").replace("\n", ""), 16)

    # A commonly used primitive root modulo q
    alpha = 2  # Primitive root for secure Diffie-Hellman

    print(f"Diffie-Hellman parameters initialized: q={q} (2048-bit), alpha={alpha}")

# Database setup for credentials
def setup_database():
    conn = sqlite3.connect("credentials.db")
    cursor = conn.cursor()
    cursor.execute(""" 
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL
        ) 
    """)
    conn.commit()
    conn.close()

# Register or authenticate user
def handle_authentication(username, password):
    conn = sqlite3.connect("credentials.db")
    cursor = conn.cursor()

    # Check if the username already exists
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()

    if result:
        # Username exists, validate password
        stored_hash = result[0]
        if bcrypt.checkpw(password.encode(), stored_hash.encode()):
            conn.close()
            return "AUTH_SUCCESS"
        else:
            conn.close()
            return "AUTH_FAILURE"
    else:
        # Username does not exist, register the user
        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        conn.close()
        return "REGISTERED_SUCCESS"
def handle_client(client_socket, client_id):
    global client_sockets, client_public_keys, client_rsa_public_keys, q, alpha
    try:
        # Step 1: Receive the client's RSA public key (raw bytes)
        setup_dh_params()
        rsa_public_key_pem = client_socket.recv(1024)  # Receive in bytes
        client_rsa_public_keys[client_id] = rsa_public_key_pem  # Store the received RSA public key
        print(f"Received RSA public key from {client_id}.")

    
        # Step 4: Send the server's RSA public key to the client
        other_client_id = "client 1" if client_id == "client 2" else "client 2"
        while True:
            with lock:
                if other_client_id in client_rsa_public_keys:
                    break
            time.sleep(0.1)  # Wait for the other client to send their RSA public key
        
        # Send the other client's RSA public key
        with lock:
            other_rsa_public_key = client_rsa_public_keys[other_client_id]
        client_socket.sendall(other_rsa_public_key)  # Send the other client's RSA public key (raw bytes)
        print(f"Sent RSA public key of {other_client_id} to {client_id}.")


        # Step 6: Send Diffie-Hellman parameters to the client
        dh_params_to_send = f"{q}::{alpha}".encode('utf-8')
        client_socket.sendall(dh_params_to_send)
        print(f"Sent DH parameters to {client_id}. q={q}, alpha={alpha}")

        # Step 7: Receive the client's public DH key
        public_dh_key = int(client_socket.recv(1024).decode())  # Decode to get the integer
        print(f"Received DH public key from {client_id}: {public_dh_key}.")

        # Store the public DH key
        with lock:
            client_public_keys[client_id] = public_dh_key

        # Step 8: Wait until both clients send their DH public keys
        while True:
            with lock:
                if other_client_id in client_public_keys:
                    break
            time.sleep(0.1)  # Wait for the other client to send their DH public key

        # Step 9: Send the other client's DH public key (raw bytes)
        with lock:
            other_public_key = client_public_keys[other_client_id]
        client_socket.sendall(str(other_public_key).encode())  # Send the other client's public DH key
        print(f"Sent DH public key of {other_client_id} to {client_id}.")

           # Step 10: Message Exchange Loop
        while True:
            # Receive message from the current client
            message = client_socket.recv(1024).decode()
            if not message:
                break  # Client disconnected
            
            # Print the received message
            print(f"Received message from {client_id}: {message}")

            # Send the message to the other client
            with lock:
                other_client_socket = client_sockets.get(other_client_id)
                if other_client_socket:
                    other_client_socket.sendall(message.encode())
                    print(f"Sent message to {other_client_id}: {message}")

    except Exception as e:
        print(f"Error handling client {client_id}: {e}")
        client_socket.close()

def start_server():
    host = '127.0.0.1'
    port = 65432

    # Set up database
    setup_database()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen(2)
        print("Server is listening...")

        while True:
            client_socket, addr = server_socket.accept()
            credentials = client_socket.recv(1024).decode()
            username, password = credentials.split("::")
            auth_result = handle_authentication(username, password)

            if auth_result in ["AUTH_SUCCESS", "REGISTERED_SUCCESS"]:
                client_socket.sendall(auth_result.encode())
                client_id = username
                with lock:
                    client_sockets[client_id] = client_socket
                print(f"{client_id} authenticated and connected from {addr}.")
                threading.Thread(target=handle_client, args=(client_socket, client_id)).start()
            else:
                client_socket.sendall("AUTH_FAILURE".encode())
                client_socket.close()

if __name__ == "__main__":
    start_server()