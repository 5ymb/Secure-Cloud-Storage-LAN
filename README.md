# 🛡️ Secure Cloud Storage (Zero-Knowledge E2EE)

> **Developed by Abdulqader** ![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge&logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Security-E2EE-red?style=for-the-badge&logo=security&logoColor=white)
![Cryptography](https://img.shields.io/badge/Cryptography-AES--256--GCM-success?style=for-the-badge)
![Network](https://img.shields.io/badge/Network-TLS%2FSSL-yellow?style=for-the-badge)

A proof-of-concept Secure Cloud Storage system implementing a **Zero-Knowledge architecture**. This project features a robust Python socket server and a sleek Tkinter graphical client. It ensures that user data is encrypted locally *before* transmission, meaning the server never has access to plaintext files, encryption keys, or passwords.

---

## ✨ Key Features

### 💻 Client-Side (The GUI)
* **Local Encryption:** Files are encrypted using AES-256-GCM locally before leaving the device.
* **Key Derivation:** Uses PBKDF2HMAC (SHA-256, 600,000 iterations) to derive strong keys from user passwords.
* **Integrity Checks:** Secondary HMAC-SHA256 verification to detect any server-side tampering.
* **Secure Sharing:** Re-encrypts files with a one-time password and generates a secure, randomized share token.
* **Modern UI:** Custom dark-themed Tkinter interface for seamless interaction.

### 🖥️ Server-Side (The Backend)
* **Zero-Knowledge Storage:** Stores only AES ciphertexts, salts, nonces, and HMACs.
* **TLS/SSL Security:** All socket communication is wrapped in TLS to prevent Man-in-the-Middle (MITM) attacks.
* **Multi-threaded Design:** Handles multiple concurrent client connections safely.
* **Path Traversal Protection:** Sanitizes all filenames and tokens to prevent directory escape attacks.

---

## 🔐 Cryptographic Architecture

This project utilizes the industry-standard `cryptography` library to enforce strict confidentiality and integrity:

1. **Authentication:** The client authenticates with a username over a TLS-encrypted tunnel. The password is *never* transmitted to the server.
2. **Key Generation:** A unique 16-byte salt is generated per file. The user's master password + salt are fed into `PBKDF2HMAC` to generate a 32-byte (256-bit) key.
3. **Encryption:** The plaintext is encrypted using `AES-GCM` (Galois/Counter Mode) with a random 12-byte nonce.
4. **Integrity:** An additional `HMAC-SHA256` is computed over the ciphertext. Upon download, the client verifies this HMAC before attempting decryption. If the server or an attacker tampers with the ciphertext, the HMAC check fails immediately.

---

## 🚀 Prerequisites & Setup

### 1. Install Dependencies
You will need Python installed along with the required cryptography package for the client:
```bash
pip install cryptography
