# Decentralized Key Exchange Protocol

## Overview
This project implements a **decentralized key exchange protocol** for secure communication between peers in a peer-to-peer (P2P) network. The protocol allows parties to securely exchange cryptographic keys without the need for a trusted third party (such as a certificate authority), and it is designed to be resilient against **man-in-the-middle (MITM) attacks**.

The protocol leverages **Elliptic Curve Diffie-Hellman (ECDH)** for secure key exchange and **Fernet encryption** for ensuring the confidentiality of messages exchanged between peers.

## Features
- **Peer-to-peer communication**: The system operates in a decentralized manner, where peers exchange keys and messages directly without the need for a central server.
- **Elliptic Curve Diffie-Hellman (ECDH)**: ECDH is used for generating a shared secret between peers using their public keys.
- **Secure communication with Fernet encryption**: After the shared secret is derived, communication between peers is encrypted using Fernet, ensuring confidentiality.
- **Distributed Hash Table (DHT)**: DHT is used for storing and retrieving public keys in a decentralized manner, enabling peers to find each other’s keys without relying on a third-party.
- **Resilience against MITM attacks**: The protocol ensures that only the correct public keys are exchanged, preventing MITM attacks.

## How it Works

1. **Key Generation**:
   - Each peer generates a public-private key pair using the **Elliptic Curve SECP256R1** curve.
   - The public keys are exchanged through the **Distributed Hash Table (DHT)**, ensuring decentralization and availability.

2. **Key Exchange**:
   - Using **ECDH**, each peer computes a shared secret based on the other peer’s public key and their own private key.
   - The shared secret is used to derive a symmetric encryption key.

3. **Message Encryption**:
   - The shared secret is used to generate a **Fernet key**, which is then used to encrypt and decrypt messages exchanged between peers.
   - Fernet ensures that even if an attacker intercepts the encrypted message, they cannot decrypt it without the correct key.

4. **DHT for Key Storage**:
   - Peers store their public keys in a DHT, making it accessible to other peers without relying on a central server.
   - Peers bootstrap to each other’s DHT nodes and retrieve public keys to begin the key exchange.

## Requirements

- Python 3.6+
- `cryptography` package for cryptographic operations.
- `kademlia` package for implementing the Distributed Hash Table (DHT).
- `asyncio` for asynchronous programming.

### Install dependencies:

```bash
pip install cryptography kademlia
