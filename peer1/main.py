import asyncio
import socket
from threading import Thread
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.fernet import Fernet
from kademlia.network import Server
import base64

# DHT Node Implementation
class DHTNode:
    def __init__(self, port):
        self.server = Server()
        self.port = port

    async def start(self):
        await self.server.listen(self.port)
        print(f"DHT Node listening on port {self.port}")

    async def bootstrap(self, bootstrap_node):
        # Bootstrapping the DHT to a known node (self in this case)
        await self.server.bootstrap([bootstrap_node])

    async def store_key(self, key, value):
        await self.server.set(key, value)

    async def get_key(self, key):
        return await self.server.get(key)


# ECDH Key Exchange Implementation
def generate_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(public_key_bytes):
    return serialization.load_pem_public_key(public_key_bytes)

def compute_shared_secret(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b'key-exchange'
    ).derive(shared_secret)
    return derived_key


# Message Encryption/Decryption Implementation
def generate_fernet_key(shared_secret):
    # Extract the first 32 bytes of the derived key and base64 encode it to be URL-safe
    key = base64.urlsafe_b64encode(shared_secret[:32])
    return key

def encrypt_message(shared_secret, message):
    key = generate_fernet_key(shared_secret)
    fernet = Fernet(key)
    return fernet.encrypt(message.encode())

def decrypt_message(shared_secret, encrypted_message):
    key = generate_fernet_key(shared_secret)
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message).decode()


# P2P Server Implementation
def start_server(port, handle_client):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("127.0.0.1", port))
    server_socket.listen(5)
    print(f"Server listening on port {port}")

    def client_thread(conn):
        handle_client(conn)

    while True:
        conn, _ = server_socket.accept()
        Thread(target=client_thread, args=(conn,)).start()


# P2P Client Implementation
def connect_to_peer(host, port, data_to_send):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    client_socket.sendall(data_to_send)
    response = client_socket.recv(1024)
    client_socket.close()
    return response


# Main Program for peer1
async def main():
    # Initialize DHT Node
    node = DHTNode(port=8468)
    await node.start()

    # Bootstrap DHT (connect to peer2)
    await node.bootstrap(('10.40.142.175', 8469))

    # Generate ECDH Keys
    private_key, public_key = generate_keys()
    serialized_public_key = serialize_public_key(public_key)

    # Store Public Key in DHT
    await node.store_key("peer1", serialized_public_key)
    print("Key stored in DHT successfully.")

    # Add a delay to allow time for the key to propagate across the network
    await asyncio.sleep(5)

    # Start P2P Server
    def handle_client(conn):
        peer_key_bytes = conn.recv(1024)
        peer_public_key = deserialize_public_key(peer_key_bytes)
        conn.sendall(serialized_public_key)

        # Compute Shared Secret
        shared_secret = compute_shared_secret(private_key, peer_public_key)
        print("Shared Secret Computed!")

        # Encrypt and Decrypt a Message
        message = "Hello, Peer!"
        encrypted_message = encrypt_message(shared_secret, message)
        print("Encrypted Message:", encrypted_message)
        decrypted_message = decrypt_message(shared_secret, encrypted_message)
        print("Decrypted Message:", decrypted_message)

    Thread(target=start_server, args=(65432, handle_client)).start()

    # Retrieve the peer's public key from DHT
    peer_key_bytes = await node.get_key("peer2")
    if not peer_key_bytes:
        print("No peer public key found in DHT. Exiting.")
        return

    peer_public_key = deserialize_public_key(peer_key_bytes)

    # Compute Shared Secret
    shared_secret = compute_shared_secret(private_key, peer_public_key)
    print("Shared Secret:", shared_secret)

    # Encrypt and Decrypt a Message
    message = "Hello, Peer!"
    encrypted_message = encrypt_message(shared_secret, message)
    print("Encrypted Message:", encrypted_message)
    decrypted_message = decrypt_message(shared_secret, encrypted_message)
    print("Decrypted Message:", decrypted_message)


# Run the program
asyncio.run(main())
