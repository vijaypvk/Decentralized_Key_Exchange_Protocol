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


class DHTNode:
    def __init__(self, port):
        self.server = Server()
        self.port = port

    async def start(self):
        await self.server.listen(self.port)
        print(f"DHT Node listening on port {self.port}")

    async def bootstrap(self, bootstrap_node):
        try:
            await self.server.bootstrap([bootstrap_node])
            print(f"Bootstrap successful to {bootstrap_node}")
        except Exception as e:
            print(f"Bootstrap failed: {e}")

    async def store_key(self, key, value):
        try:
            await self.server.set(key, value)
            print("Key stored in DHT successfully.")
        except Exception as e:
            print(f"Error storing key: {e}")

    async def get_key(self, key, retries=3, delay=5):
        """Attempt to get a key with retries."""
        try:
            value = await self.server.get(key)
            if value:
                print(f"Key retrieved from DHT: {value}")
                return value
            else:
                print(f"No value found for key {key}. Retrying...")
                if retries > 0:
                    await asyncio.sleep(delay)
                    return await self.get_key(key, retries-1, delay)
                else:
                    print(f"Failed to retrieve key {key} after retries.")
                    return None
        except Exception as e:
            print(f"Error retrieving key: {e}")
            return None


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


# Main Program
async def main():
    # Initialize DHT Node for peer2
    node = DHTNode(port=8469)
    await node.start()

    # Bootstrap DHT (connect to peer1 with IP 10.40.142.40, port 8468)
    await node.bootstrap(('10.40.142.40', 8468))

    # Generate ECDH Keys
    private_key, public_key = generate_keys()
    serialized_public_key = serialize_public_key(public_key)

    # Store Public Key in DHT
    await node.store_key("peer2", serialized_public_key)

    # Wait a bit for DHT propagation
    await asyncio.sleep(2)

    # Start P2P Server to listen for connections
    def handle_client(conn):
        peer_key_bytes = conn.recv(1024)
        peer_public_key = deserialize_public_key(peer_key_bytes)
        conn.sendall(serialized_public_key)

        # Compute Shared Secret
        shared_secret = compute_shared_secret(private_key, peer_public_key)
        print("Shared Secret Computed!")

    Thread(target=start_server, args=(65433, handle_client)).start()

    # Retrieve the peer's public key from DHT (after storing it)
    peer_key_bytes = await node.get_key("peer1")
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
