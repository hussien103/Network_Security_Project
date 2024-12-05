import socket
import threading

def handle_client(client_socket, other_socket, client_id, other_id):
    # Receive the AES key from the client
    aes_key = client_socket.recv(16)  # 16 bytes for AES-128
    print(f"[{client_id}] Received AES key: {aes_key}")
    
    # Send the AES key to the other client
    other_socket.sendall(aes_key)
    print(f"[{client_id}] Sent AES key to [{other_id}]")

    while True:
        try:
            # Relay encrypted messages between clients
            data = client_socket.recv(1024)
            if not data:
                print(f"[{client_id}] Disconnected")
                break
            print(f"[{client_id}] Received: {data}")
            other_socket.sendall(data)
            print(f"[{client_id}] Relayed message to [{other_id}]")
        except ConnectionResetError:
            print(f"[{client_id}] Connection lost")
            break

def start_server():
    host = '127.0.0.1'
    port = 65432

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen(2)  # Limit to 2 clients
        print(f"Server listening on {host}:{port}")

        # Accept connections from both clients
        print("Waiting for Client 1...")
        client1_socket, client1_addr = server_socket.accept()
        print(f"Client 1 connected: {client1_addr}")

        print("Waiting for Client 2...")
        client2_socket, client2_addr = server_socket.accept()
        print(f"Client 2 connected: {client2_addr}")

        # Start threads to handle communication
        client1_thread = threading.Thread(target=handle_client, args=(client1_socket, client2_socket, "Client 1", "Client 2"))
        client2_thread = threading.Thread(target=handle_client, args=(client2_socket, client1_socket, "Client 2", "Client 1"))

        client1_thread.start()
        client2_thread.start()

        client1_thread.join()
        client2_thread.join()

if __name__ == "__main__":
    start_server()
