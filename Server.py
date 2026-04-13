import socket
import ssl
import threading
import json
import os

HOST         = '127.0.0.1'
PORT         = 65432
STORAGE_ROOT = 'server_storage'   
SHARES_ROOT  = 'server_shares'    


os.makedirs(STORAGE_ROOT, exist_ok=True)
os.makedirs(SHARES_ROOT,  exist_ok=True)


try:
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')
    print("[TLS] Certificate loaded successfully.")
except FileNotFoundError:
    print("[ERROR] 'cert.pem' or 'key.pem' not found.")
    print("Generate a self-signed certificate with:")
    print("  openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes")
    exit(1)


def _recvall(sock: ssl.SSLSocket, n: int) -> bytes:
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Client disconnected.")
        buf += chunk
    return buf


def send_msg(sock: ssl.SSLSocket, obj: dict) -> None:
    payload = json.dumps(obj).encode('utf-8')
    sock.sendall(len(payload).to_bytes(4, 'big') + payload)


def recv_msg(sock: ssl.SSLSocket) -> dict:
    length = int.from_bytes(_recvall(sock, 4), 'big')
    return json.loads(_recvall(sock, length).decode('utf-8'))


def _safe_name(name: str) -> str:
    return os.path.basename(name).replace('..', '').strip()


def _safe_token(token: str) -> str:
    return ''.join(c for c in token if c.isalnum())[:32]


def _validate_blob(blob: object) -> bool:
    if not isinstance(blob, dict):
        return False
    return all(k in blob for k in ('salt', 'nonce', 'ciphertext', 'hmac'))


def cmd_auth(sock: ssl.SSLSocket, msg: dict) -> str | None:
    username = msg.get("username", "").strip()

    if not username or '/' in username or '\\' in username or '..' in username:
        send_msg(sock, {"status": "error", "message": "Invalid username."})
        return None

    user_dir = os.path.join(STORAGE_ROOT, username)
    os.makedirs(user_dir, exist_ok=True)

    send_msg(sock, {"status": "ok"})
    print(f"  [AUTH]     '{username}' connected.")
    return username


def cmd_list(sock: ssl.SSLSocket, username: str, _msg: dict) -> None:

    user_dir = os.path.join(STORAGE_ROOT, username)
    files = sorted(
        f[:-4]                              
        for f in os.listdir(user_dir)
        if f.endswith('.enc')
    )
    send_msg(sock, {"status": "ok", "files": files})
    print(f"  [LIST]     '{username}' — {len(files)} file(s).")


def cmd_upload(sock: ssl.SSLSocket, username: str, msg: dict) -> None:
    filename = _safe_name(msg.get("filename", ""))
    blob     = msg.get("blob")

    if not filename:
        send_msg(sock, {"status": "error", "message": "Missing filename."}); return
    if not _validate_blob(blob):
        send_msg(sock, {"status": "error", "message": "Invalid or incomplete encrypted blob."}); return

    path = os.path.join(STORAGE_ROOT, username, filename + '.enc')
    with open(path, 'w') as fh:
        json.dump(blob, fh)

    send_msg(sock, {"status": "ok"})
    print(f"  [UPLOAD]   '{username}' stored '{filename}' (server sees only ciphertext).")


def cmd_download(sock: ssl.SSLSocket, username: str, msg: dict) -> None:
    filename = _safe_name(msg.get("filename", ""))
    path     = os.path.join(STORAGE_ROOT, username, filename + '.enc')

    if not os.path.exists(path):
        send_msg(sock, {"status": "error", "message": f"'{filename}' not found."}); return

    with open(path, 'r') as fh:
        blob = json.load(fh)

    send_msg(sock, {"status": "ok", "blob": blob})
    print(f"  [DOWNLOAD] '{username}' retrieved '{filename}'.")


def cmd_delete(sock: ssl.SSLSocket, username: str, msg: dict) -> None:
    filename = _safe_name(msg.get("filename", ""))
    path     = os.path.join(STORAGE_ROOT, username, filename + '.enc')

    if not os.path.exists(path):
        send_msg(sock, {"status": "error", "message": f"'{filename}' not found."}); return

    os.remove(path)
    send_msg(sock, {"status": "ok", "message": f"'{filename}' deleted."})
    print(f"  [DELETE]   '{username}' deleted '{filename}'.")


def cmd_share(sock: ssl.SSLSocket, username: str, msg: dict) -> None:
    token = _safe_token(msg.get("token", ""))
    blob  = msg.get("blob")

    if not token:
        send_msg(sock, {"status": "error", "message": "Missing token."}); return
    if not _validate_blob(blob):
        send_msg(sock, {"status": "error", "message": "Invalid encrypted blob."}); return

    path = os.path.join(SHARES_ROOT, token + '.enc')
    with open(path, 'w') as fh:
        json.dump(blob, fh)

    send_msg(sock, {"status": "ok"})
    print(f"  [SHARE]    '{username}' created share token '{token}'.")


def cmd_get_shared(sock: ssl.SSLSocket, _username: str, msg: dict) -> None:
    token = _safe_token(msg.get("token", ""))
    path  = os.path.join(SHARES_ROOT, token + '.enc')

    if not os.path.exists(path):
        send_msg(sock, {"status": "error", "message": "Share token not found or expired."}); return

    with open(path, 'r') as fh:
        blob = json.load(fh)

    send_msg(sock, {"status": "ok", "blob": blob})
    print(f"  [GET_SHARED] Token '{token}' retrieved.")


COMMAND_HANDLERS = {
    "LIST":       cmd_list,
    "UPLOAD":     cmd_upload,
    "DOWNLOAD":   cmd_download,
    "DELETE":     cmd_delete,
    "SHARE":      cmd_share,
    "GET_SHARED": cmd_get_shared,
}


def handle_client(ssl_sock: ssl.SSLSocket, addr: tuple) -> None:
    print(f"[+] New connection from {addr}")
    username = None

    try:
        first_msg = recv_msg(ssl_sock)
        if first_msg.get("cmd", "").upper() != "AUTH":
            send_msg(ssl_sock, {"status": "error", "message": "First message must be AUTH."})
            return

        username = cmd_auth(ssl_sock, first_msg)
        if not username:
            return

        while True:
            msg = recv_msg(ssl_sock)
            cmd = msg.get("cmd", "").upper()

            handler = COMMAND_HANDLERS.get(cmd)
            if handler:
                handler(ssl_sock, username, msg)
            else:
                send_msg(ssl_sock, {"status": "error", "message": f"Unknown command: '{cmd}'."})
                print(f"  [WARN]     Unknown command '{cmd}' from '{username}'.")

    except (ConnectionError, json.JSONDecodeError):
        print(f"[-] '{username or addr}' disconnected.")
    except Exception as e:
        print(f"[-] Error with '{username or addr}': {e}")
    finally:
        ssl_sock.close()
        print(f"[-] Connection closed: {addr}")


if __name__ == "__main__":
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen(10)

    print("=" * 60)
    print("Secure Cloud Storage Server")
    print("=" * 60)
    print(f"  Listening : {HOST}:{PORT}")
    print(f"  Storage   : {os.path.abspath(STORAGE_ROOT)}")
    print(f"  Shares    : {os.path.abspath(SHARES_ROOT)}")
    print("  Note      : Server stores ciphertext ONLY. No keys here.")
    print("=" * 60)

    try:
        while True:
            raw_sock, addr = server_sock.accept()

            try:
                ssl_client = tls_context.wrap_socket(raw_sock, server_side=True)
            except ssl.SSLError as e:
                print(f"[TLS] Handshake failed with {addr}: {e}")
                raw_sock.close()
                continue

            t = threading.Thread(
                target=handle_client,
                args=(ssl_client, addr),
                daemon=True        
            )
            t.start()

    except KeyboardInterrupt:
        print("\n[INFO] Server shutting down (Ctrl+C).")
    finally:
        server_sock.close()
