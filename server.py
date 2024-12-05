import socket
import threading

client_sockets = {}
client_keys = {}

def handle_client(client_socket, client_id):
    """Handle communication with a client."""
    global client_sockets, client_keys
    while True:
        try:
            data = client_socket.recv(1024)
            if not data:
                break

            if client_id == "Client 1":
                # Store Client 1's public key and send it to Client 2
                client_keys["Client 1"] = data
                print(f"Received public key from {client_id}")
                if "Client 2" in client_sockets:
                    client_sockets["Client 2"].sendall(data)
                    print("Sent public key from Client 1 to Client 2")

            elif client_id == "Client 2":
                # Relay messages from Client 2 to Client 1
                if "Client 1" in client_sockets:
                    client_sockets["Client 1"].sendall(data)
        except ConnectionResetError:
            break

    print(f"{client_id} disconnected.")
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
