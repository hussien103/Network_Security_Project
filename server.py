import socket
import threading

def handle_client(client_socket, other_socket, client_id, other_id):
    try:
        while True:
            # Step 1: Receive the encrypted AES key
            encrypted_aes_key = client_socket.recv(256)  # RSA-encrypted AES key
            if not encrypted_aes_key:
                print(f"[{client_id}] Disconnected")
                break
            other_socket.sendall(encrypted_aes_key)  # Forward encrypted AES key to the other client
            print(f"[{client_id}] Relayed encrypted AES key to [{other_id}]")

            # Step 2: Receive the encrypted message
            encrypted_message = client_socket.recv(2048)  # Encrypted message
            if not encrypted_message:
                print(f"[{client_id}] Disconnected")
                break
            other_socket.sendall(encrypted_message)  # Forward encrypted message to the other client
            print(f"[{client_id}] Relayed encrypted message to [{other_id}]")
    
    except Exception as e:
        print(f"[{client_id}] Error: {e}")
    finally:
        client_socket.close()
        other_socket.close()
        print(f"[{client_id}] Connection closed.")


def start_server():
    host = '127.0.0.1'
    port = 65432

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen(2)  # Limit to 2 clients
        print(f"Server listening on {host}:{port}")

        # Accept connections from both clients
        print("Waiting for Client 1...")
        client1_socket, _ = server_socket.accept()
        print("Client 1 connected.")

        print("Waiting for Client 2...")
        client2_socket, _ = server_socket.accept()
        print("Client 2 connected.")

        # Start threads to handle communication between clients
        client1_thread = threading.Thread(target=handle_client, args=(client1_socket, client2_socket, "Client 1", "Client 2"))
        client2_thread = threading.Thread(target=handle_client, args=(client2_socket, client1_socket, "Client 2", "Client 1"))

        client1_thread.start()
        client2_thread.start()

        client1_thread.join()
        client2_thread.join()

if __name__ == "__main__":
    start_server()
