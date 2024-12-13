import socket
import threading

# Global dictionaries to store client sockets and public keys
client_sockets = {}
client_keys = {}
lock = threading.Lock()

def handle_client(client_socket, client_id):
    """Handle communication with a client."""
    global client_sockets, client_keys
    try:
        while True:
            data = client_socket.recv(1024)
            if not data:
                break

            if client_id not in client_keys:
                # Store the public key
                with lock:
                    client_keys[client_id] = data
                    print(f"Received public key from {client_id}")

                    # Exchange public keys when both clients are connected
                    other_client_id = "Client 1" if client_id == "Client 2" else "Client 2"
                    if other_client_id in client_sockets:
                        # Send the other client's public key to the current client
                        client_socket.sendall(client_keys[other_client_id])
                        print(f"Forwarded public key from {other_client_id} to {client_id}.")

                        # Send the current client's public key to the other client
                        client_sockets[other_client_id].sendall(data)
                        print(f"Forwarded public key from {client_id} to {other_client_id}.")
            else:
                # Forward encrypted messages between clients
                other_client_id = "Client 1" if client_id == "Client 2" else "Client 2"
                with lock:
                    if other_client_id in client_sockets:
                        client_sockets[other_client_id].sendall(data)
                        print(f"Forwarded message from {client_id} to {other_client_id}.")
    except (ConnectionResetError, BrokenPipeError):
        print(f"{client_id} disconnected.")
    finally:
        # Clean up on client disconnection
        with lock:
            client_sockets.pop(client_id, None)
            client_keys.pop(client_id, None)
        client_socket.close()

def start_server():
    """Start the server to handle client connections."""
    host = '127.0.0.1'
    port = 65432

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen(2)
        print("Server is listening...")

        while True:
            client_socket, addr = server_socket.accept()
            client_id = client_socket.recv(1024).decode()
            with lock:
                client_sockets[client_id] = client_socket
            print(f"{client_id} connected from {addr}.")

            threading.Thread(target=handle_client, args=(client_socket, client_id)).start()

if __name__ == "__main__":
    start_server()
