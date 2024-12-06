import socket
import threading

client_sockets = {}
client_keys = {}

def handle_client(client_socket, client_id):
    """Handle communication with a client."""
    global client_sockets, client_keys
    try:
        # Receive and store the client's public key
        public_key = client_socket.recv(2048)
        client_keys[client_id] = public_key
        print(f"Received public key from {client_id}.")

        # Send the other client's public key
        other_client_id = "Client 1" if client_id == "Client 2" else "Client 2"
        if other_client_id in client_keys:
            client_socket.sendall(client_keys[other_client_id])
            print(f"Sent {other_client_id}'s public key to {client_id}.")
        
        # Relay AES keys
        while True:
            data = client_socket.recv(256)
            if not data:
                break
            if other_client_id in client_sockets:
                client_sockets[other_client_id].sendall(data)
                print(f"Relayed encrypted AES key from {client_id} to {other_client_id}.")
    except ConnectionResetError:
        print(f"{client_id} disconnected.")
    finally:
        client_socket.close()

def start_server():
    host = '127.0.0.1'
    port = 65432

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen(2)
        print("Server is listening...")

        while len(client_sockets) < 2:
            client_socket, addr = server_socket.accept()
            client_id = client_socket.recv(1024).decode()
            client_sockets[client_id] = client_socket
            print(f"{client_id} connected from {addr}.")
            threading.Thread(target=handle_client, args=(client_socket, client_id)).start()

if __name__ == "__main__":
    start_server()
