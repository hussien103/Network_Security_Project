# server.py
import socket
import threading
import bcrypt
import sqlite3

client_sockets = {}
client_keys = {}
lock = threading.Lock()

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
    global client_sockets, client_keys
    try:
        while True:
            data = client_socket.recv(4096)
            if not data:
                break

            if client_id not in client_keys:
                # Store the public key
                with lock:
                    client_keys[client_id] = data
                    print(f"Received public key from {client_id}")

                    # Forward the stored keys to both clients if both are connected
                    other_client_id = "Client 1" if client_id == "Client 2" else "Client 2"
                    if other_client_id in client_sockets:
                        # Send the other client's public key to the current client
                        client_socket.sendall(client_keys[other_client_id])
                        print(f"Forwarded public key from {other_client_id} to {client_id}.")

                        # Send the current client's public key to the other client
                        client_sockets[other_client_id].sendall(data)
                        print(f"Forwarded public key from {client_id} to {other_client_id}.")
            else:
                # Forward encrypted messages and signatures between clients
                other_client_id = "Client 1" if client_id == "Client 2" else "Client 2"
                with lock:
                    if other_client_id in client_sockets:
                        client_sockets[other_client_id].sendall(data)
                        print(f"Forwarded message from {client_id} to {other_client_id}.")
    except (ConnectionResetError, BrokenPipeError):
        print(f"{client_id} disconnected.")
    finally:
        with lock:
            client_sockets.pop(client_id, None)
            client_keys.pop(client_id, None)
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
