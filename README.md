<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Cloud Storage E2EE</title>
    <style>
        :root {
            --bg-color: #0d1117;
            --container-bg: #161b22;
            --text-main: #c9d1d9;
            --text-muted: #8b949e;
            --accent: #58a6ff;
            --accent-hover: #3182ce;
            --success: #2ea043;
            --danger: #f85149;
            --border: #30363d;
            --code-bg: #010409;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif, "Apple Color Emoji", "Segoe UI Emoji";
            background-color: var(--bg-color);
            color: var(--text-main);
            line-height: 1.6;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 900px;
            margin: 0 auto;
            background-color: var(--container-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 40px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }
        h1, h2, h3 {
            color: #ffffff;
            border-bottom: 1px solid var(--border);
            padding-bottom: 8px;
            margin-top: 30px;
            font-weight: 600;
        }
        h1 { font-size: 2.2em; border-bottom: 2px solid var(--border); margin-top: 0; }
        h2 { font-size: 1.5em; }
        h3 { font-size: 1.25em; border-bottom: none; }
        p { margin-top: 0; margin-bottom: 16px; }
        a { color: var(--accent); text-decoration: none; }
        a:hover { text-decoration: underline; }
        ul { margin-bottom: 16px; padding-left: 24px; }
        li { margin-bottom: 8px; }
        code {
            font-family: ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, Liberation Mono, monospace;
            background-color: rgba(110,118,129,0.4);
            padding: 0.2em 0.4em;
            border-radius: 6px;
            font-size: 85%;
        }
        pre {
            background-color: var(--code-bg);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 16px;
            overflow: auto;
            font-size: 85%;
            line-height: 1.45;
        }
        pre code {
            background-color: transparent;
            padding: 0;
        }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 2em;
            font-size: 12px;
            font-weight: 600;
            margin-right: 6px;
            margin-bottom: 12px;
        }
        .badge-crypto { background-color: rgba(88,166,255,0.1); color: var(--accent); border: 1px solid var(--accent); }
        .badge-python { background-color: rgba(46,160,67,0.1); color: var(--success); border: 1px solid var(--success); }
        .badge-security { background-color: rgba(248,81,73,0.1); color: var(--danger); border: 1px solid var(--danger); }
        .note {
            padding: 16px;
            background-color: rgba(88,166,255,0.1);
            border-left: 4px solid var(--accent);
            border-radius: 0 6px 6px 0;
            margin-bottom: 16px;
        }
        .grid-2 {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        @media (max-width: 600px) {
            .grid-2 { grid-template-columns: 1fr; }
            .container { padding: 20px; }
        }
    </style>
</head>
<body>

<div class="container">
    <h1>🛡️ Secure Cloud Storage (Zero-Knowledge E2EE)</h1>
    <div>
        <span class="badge badge-python">Python 3.10+</span>
        <span class="badge badge-crypto">Cryptography</span>
        <span class="badge badge-security">End-to-End Encryption</span>
        <span class="badge badge-security">TLS/SSL</span>
    </div>
    <p>A proof-of-concept Secure Cloud Storage system implementing a <strong>Zero-Knowledge architecture</strong>. This project features a robust Python socket server and a sleek Tkinter graphical client. It ensures that user data is encrypted locally before transmission, meaning the server never has access to plaintext files, encryption keys, or passwords.</p>
    <h2>✨ Key Features</h2>
    <div class="grid-2">
        <div>
            <h3>Client-Side (The GUI)</h3>
            <ul>
                <li><strong>Local Encryption:</strong> Files are encrypted using AES-256-GCM locally before leaving the device.</li>
                <li><strong>Key Derivation:</strong> Uses PBKDF2HMAC (SHA256, 600,000 iterations) to derive strong keys from user passwords.</li>
                <li><strong>Integrity Checks:</strong> Secondary HMAC-SHA256 verification to detect server-side tampering.</li>
                <li><strong>Secure Sharing:</strong> Re-encrypts files with a one-time password and generates a secure share token.</li>
                <li><strong>Modern UI:</strong> Custom dark-themed Tkinter interface for seamless interaction.</li>
            </ul>
        </div>
        <div>
            <h3>Server-Side (The Backend)</h3>
            <ul>
                <li><strong>Zero-Knowledge:</strong> Stores only AES ciphertexts, salts, nonces, and HMACs.</li>
                <li><strong>TLS/SSL Security:</strong> All socket communication is wrapped in TLS to prevent Man-in-the-Middle (MITM) attacks.</li>
                <li><strong>Multi-threaded:</strong> Handles multiple concurrent client connections safely.</li>
                <li><strong>Path Traversal Protection:</strong> Sanitizes all filenames and tokens to prevent directory escape attacks.</li>
            </ul>
        </div>
    </div>
    <h2>🔐 Cryptographic Architecture</h2>
    <p>This project utilizes the industry-standard <code>cryptography</code> library to enforce confidentiality and integrity:</p>
    <ol>
        <li><strong>Authentication:</strong> The client authenticates with a username over a TLS-encrypted tunnel. The password is <em>never</em> transmitted to the server.</li>
        <li><strong>Key Generation:</strong> A unique 16-byte salt is generated per file. The user's master password + salt are fed into <code>PBKDF2HMAC</code> to generate a 32-byte (256-bit) key.</li>
        <li><strong>Encryption:</strong> The plaintext is encrypted using <code>AES-GCM</code> (Galois/Counter Mode) with a random 12-byte nonce.</li>
        <li><strong>Integrity:</strong> An additional <code>HMAC-SHA256</code> is computed over the ciphertext. Upon download, the client verifies this HMAC before attempting decryption. If the server or an attacker tampers with the ciphertext, the HMAC check fails immediately.</li>
    </ol>
    <h2>🚀 Prerequisites & Setup</h2>
    <h3>1. Install Dependencies</h3>
    <p>You will need Python installed along with the required cryptography package for the client:</p>
    <pre><code>pip install cryptography</code></pre>
    <h3>2. Generate TLS Certificates (Crucial)</h3>
    <p>The server requires an SSL/TLS certificate to secure data in transit. Generate a self-signed certificate in the root directory by running:</p>
    <pre><code>openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes</code></pre>
    <h2>💻 Usage Guide</h2>
    <h3>Starting the Server</h3>
    <p>Run the server script first. It will automatically create the required <code>server_storage</code> and <code>server_shares</code> directories.</p>
    <pre><code>python Server.py</code></pre>
    <h3>Starting the Client</h3>
    <p>Launch the graphical client interface:</p>
    <pre><code>python Client.py</code></pre>
    <h3>How to Share Files Securely</h3>
    <ol>
        <li>Select an encrypted file from your list and click <strong>Share File</strong>.</li>
        <li>The client will locally decrypt the file, prompt you for a <em>new one-time share password</em>, and re-encrypt the file with it.</li>
        <li>The client generates a Share Token and uploads the newly encrypted blob to the <code>server_shares</code> directory.</li>
        <li>Send the <strong>Share Token</strong> and the <strong>Share Password</strong> to your recipient via a secure out-of-band channel.</li>
        <li>The recipient clicks <strong>Receive Files</strong>, enters the token and password, and safely downloads and decrypts the file.</li>
    </ol>
    <h2>📁 Project Structure</h2>
    <pre><code>.
├── Client.py            # GUI and cryptographic logic
├── Server.py            # TLS Socket server and storage logic
├── cert.pem             # Generated TLS Public Certificate (do not commit)
├── key.pem              # Generated TLS Private Key (do not commit)
├── server_storage/      # Auto-generated: Stores user-specific encrypted blobs
└── server_shares/       # Auto-generated: Stores shared encrypted blobs
</code></pre>
    <div class="note">
        <strong>⚠️ Disclaimer:</strong> This project is built for educational and portfolio purposes to demonstrate the practical implementation of cryptographic primitives, TLS, and Zero-Knowledge architectures. While it uses strong algorithms, a production-ready application would require further hardening, professional certificate authority (CA) integration, and formal security auditing.
    </div>

</div>

</body>
</html>
