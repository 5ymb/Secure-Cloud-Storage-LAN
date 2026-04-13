<div align="center">
<h1>☁️ Secure Cloud Storage (Zero-Knowledge E2EE)</h1>

<p>
A proof-of-concept, GUI-based Python application that encrypts and decrypts files locally using the
<strong>AES-256-GCM</strong> algorithm before uploading them to a TLS-secured server. Developed by <strong>Abdulqader</strong>, this project demonstrates symmetric key derivation (PBKDF2HMAC), secure file sharing, Zero-Knowledge architecture, and a modern user interface design using Tkinter.
</p>
<img src="https://img.shields.io/badge/Language-Python_3.10+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python">
<img src="https://img.shields.io/badge/Security-E2E_Encryption-red?style=for-the-badge" alt="Security">
<img src="https://img.shields.io/badge/Network-TLS%2FSSL-yellow?style=for-the-badge" alt="TLS">
</div>
<hr>

<h2>✨ Features</h2>
<ul>
<li><strong>Zero-Knowledge Server:</strong> The backend only stores AES ciphertexts, salts, nonces, and HMACs. It never has access to plaintext files, encryption keys, or user passwords.</li>
<li><strong>Local Encryption & Integrity:</strong> Files are encrypted using AES-256-GCM locally. A secondary HMAC-SHA256 verification is used upon download to immediately detect if the server or an attacker tampered with the data.</li>
<li><strong>Secure File Sharing:</strong> Easily share files by locally decrypting and re-encrypting them with a one-time password, generating a secure share token for the recipient.</li>
<li><strong>Clean UI Output:</strong> Custom dark-themed Tkinter interface for seamless interaction, file selection, and status updates.</li>
<li><strong>Encrypted Tunneling:</strong> All socket communication between the client and server is wrapped in TLS to prevent Man-in-the-Middle (MITM) attacks.</li>
</ul>

<hr>

<h2>⚙️ Prerequisites</h2>
<p>To run this application, you will need:</p>
<ul>
<li><strong>Python:</strong> Version 3.10 or higher.</li>
<li><strong>Cryptography Library:</strong> Install it via pip: <code>pip install cryptography</code></li>
<li><strong>OpenSSL:</strong> Required to generate the self-signed TLS certificates for the server.</li>
</ul>

<hr>

<h2>🚀 How to Run</h2>
<p>Follow these steps to run the client and server from your terminal:</p>

<ol>
<li><strong>Clone the repository:</strong>


<pre><code>git clone https://github.com/5ymb/Secure-Cloud-Storage-LAN.git</code></pre>
</li>
<li><strong>Navigate to the directory:</strong>


<pre><code>cd Secure-Cloud-Storage</code></pre>
</li>
<li><strong>Generate the TLS Certificate:</strong>


<pre><code>openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes</code></pre>
</li>
<li><strong>Start the Server:</strong>


<pre><code>python Server.py</code></pre>
</li>
<li><strong>Run the Client App (Open a new terminal window):</strong>


<pre><code>python Client.py</code></pre>
</li>
</ol>

<p><em>Once the client is running, enter a username and password to securely connect to the server and start encrypting files!</em></p>

<hr>

<h2>⚠️ Security Disclaimer</h2>
<blockquote>
<p><strong>Note on Implementation:</strong> This project utilizes strong cryptographic algorithms (AES-256-GCM, PBKDF2HMAC) and TLS. However, it is built for <strong>educational and portfolio purposes</strong>. A production-ready application would require further hardening, professional Certificate Authority (CA) integration (instead of self-signed certificates), and formal security auditing.</p>
</blockquote>

<hr>

<p align="center">
<i>Author: Abdulqader</i>
</p>
<p align="center">
<i>Built with Python, Tkinter, and the python-cryptography library.</i>
</p>
