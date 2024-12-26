import socket
import threading

client_sockets = {}
client_dh_keys = {}
lock = threading.Lock()

def handle_client(client_socket, client_id):
    global client_sockets, client_dh_keys
    try:
        # Receive Diffie-Hellman public key
        dh_public_key = client_socket.recv(2048)
        with lock:
            client_dh_keys[client_id] = dh_public_key
            print(f"[Server] Received Diffie-Hellman public key from {client_id}")

            # Check if the other client is connected
            other_client_id = "Client 1" if client_id == "Client 2" else "Client 2"
            if other_client_id in client_sockets:
                # Forward Diffie-Hellman keys
                client_socket.sendall(client_dh_keys[other_client_id])
                client_sockets[other_client_id].sendall(dh_public_key)
                print(f"[Server] Exchanged Diffie-Hellman keys between {client_id} and {other_client_id}")

        while True:
            # Forward encrypted messages between clients
            data = client_socket.recv(4096)
            if not data:
                break

            with lock:
                if other_client_id in client_sockets:
                    client_sockets[other_client_id].sendall(data)
                    print(f"[Server] Forwarded message from {client_id} to {other_client_id}")
    except (ConnectionResetError, BrokenPipeError):
        print(f"[Server] {client_id} disconnected.")
    finally:
        with lock:
            client_sockets.pop(client_id, None)
            client_dh_keys.pop(client_id, None)
        client_socket.close()

def start_server():
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
