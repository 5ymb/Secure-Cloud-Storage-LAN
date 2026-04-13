import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
import socket
import ssl
import json
import base64
import os
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

HOST = '127.0.0.1'
PORT = 65432


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,          
        salt=salt,
        iterations=600_000, 
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))


def encrypt_file(plaintext: bytes, password: str) -> dict:
    salt  = os.urandom(16)   
    nonce = os.urandom(12)   
    key   = derive_key(password, salt)

    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)

    h = crypto_hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(ciphertext)
    mac = h.finalize()

    return {
        'salt':       base64.b64encode(salt).decode(),
        'nonce':      base64.b64encode(nonce).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'hmac':       base64.b64encode(mac).decode()
    }


def decrypt_file(blob: dict, password: str) -> bytes:
    salt       = base64.b64decode(blob['salt'])
    nonce      = base64.b64decode(blob['nonce'])
    ciphertext = base64.b64decode(blob['ciphertext'])
    stored_mac = base64.b64decode(blob['hmac'])
    key        = derive_key(password, salt)

    h = crypto_hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(ciphertext)
    h.verify(stored_mac)   

    return AESGCM(key).decrypt(nonce, ciphertext, None)

def _recvall(sock: ssl.SSLSocket, n: int) -> bytes:
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Server closed the connection unexpectedly.")
        buf += chunk
    return buf


def send_msg(sock: ssl.SSLSocket, obj: dict) -> None:
    payload = json.dumps(obj).encode('utf-8')
    sock.sendall(len(payload).to_bytes(4, 'big') + payload)


def recv_msg(sock: ssl.SSLSocket) -> dict:
    length = int.from_bytes(_recvall(sock, 4), 'big')
    return json.loads(_recvall(sock, length).decode('utf-8'))


C = {
    "bg":         "#1a1a2e",   
    "bg2":        "#16213e",   
    "bg3":        "#0f3460",  
    "header":     "#0d0d1a",   
    "accent":     "#4a90d9",   
    "accent2":    "#e94560",   
    "text":       "#e0e0e0",   
    "text_dim":   "#8888aa",  
    "btn_bg":     "#2a2a4a",   
    "btn_active": "#3a3a6a",   
    "success":    "#2ecc71",   
    "warning":    "#e74c3c",   
    "border":     "#2a2a4a",   
}


class SecureStorageClient:

    def __init__(self, root: tk.Tk):
        self.root     = root
        self.ssl_sock = None
        self.username = None
        self.password = None  

        self.root.title("Secure Cloud Storage")
        self.root.geometry("780x590")
        self.root.resizable(False, False)
        self.root.configure(bg=C["bg"])

        self._show_login()

    def _dark_dialog(self, dlg: tk.Toplevel):
        """Applies dark background to a Toplevel dialog."""
        dlg.configure(bg=C["bg"])

    def _label(self, parent, text, font=("Helvetica", 11), fg=None, **kw):
        return tk.Label(parent, text=text, font=font,
                        fg=fg or C["text"], bg=C["bg"], **kw)

    def _btn(self, parent, text, command, width=14, color=None):
        """Creates a styled dark-mode button."""
        bg = color or C["btn_bg"]
        b = tk.Button(
            parent, text=text, command=command,
            font=("Helvetica", 11), width=width,
            bg=bg, fg=C["text"],
            activebackground=C["btn_active"], activeforeground=C["text"],
            relief=tk.FLAT, bd=0, padx=6, pady=6,
            cursor="hand2"
        )
        b.bind("<Enter>", lambda e: b.config(bg=C["btn_active"]))
        b.bind("<Leave>", lambda e: b.config(bg=bg))
        return b

    def _entry(self, parent, textvariable, show=None, width=22):
        """Creates a styled dark-mode entry field."""
        return tk.Entry(
            parent, textvariable=textvariable, show=show,
            width=width, font=("Helvetica", 11),
            bg=C["bg3"], fg=C["text"],
            insertbackground=C["text"],
            relief=tk.FLAT, bd=4,
        )

    def _show_login(self):
        dlg = tk.Toplevel(self.root)
        dlg.title("Secure Login")
        dlg.grab_set()
        dlg.resizable(False, False)
        dlg.geometry("400x280")
        dlg.configure(bg=C["bg"])


        tk.Label(dlg, text="Connect to Secure Cloud Storage",
                 font=("Helvetica", 13, "bold"),
                 bg=C["bg"], fg=C["text"]).pack(pady=(4, 16))

        # Form frame
        form = tk.Frame(dlg, bg=C["bg"])
        form.pack()

        tk.Label(form, text="Username:", font=("Helvetica", 11),
                 bg=C["bg"], fg=C["text_dim"]).grid(row=0, column=0, padx=10, pady=8, sticky='e')
        tk.Label(form, text="Password:", font=("Helvetica", 11),
                 bg=C["bg"], fg=C["text_dim"]).grid(row=1, column=0, padx=10, pady=8, sticky='e')

        u_var = tk.StringVar()
        p_var = tk.StringVar()
        u_entry = self._entry(form, u_var)
        p_entry = self._entry(form, p_var, show='*')
        u_entry.grid(row=0, column=1, padx=10, pady=8, ipady=4)
        p_entry.grid(row=1, column=1, padx=10, pady=8, ipady=4)
        u_entry.focus()

        def _submit(event=None):
            u = u_var.get().strip()
            p = p_var.get()
            if not u or not p:
                messagebox.showerror("Error", "Both username and password are required.", parent=dlg)
                return
            self.username = u
            self.password = p
            dlg.destroy()

        connect_btn = self._btn(dlg, "  Connect  ", _submit, width=18, color=C["accent"])
        connect_btn.configure(fg="white")
        connect_btn.pack(pady=16)

        dlg.bind('<Return>', _submit)
        dlg.wait_window()

        if not self.username:
            self.root.destroy()
            return

        self._build_main_ui()
        self._connect_to_server()


    def _build_main_ui(self):
        self.root.title(f"Secure Storage  —  {self.username}")

        header = tk.Frame(self.root, bg=C["header"], height=56)
        header.pack(fill=tk.X)
        header.pack_propagate(False)

        tk.Label(header, text="🔒  Secure Storage",
                 bg=C["header"], fg=C["accent"],
                 font=("Helvetica", 15, "bold")).pack(side=tk.LEFT, padx=16, pady=14)

        tk.Label(header, text=f"User: {self.username}",
                 bg=C["header"], fg=C["text_dim"],
                 font=("Helvetica", 11)).pack(side=tk.RIGHT, padx=16, pady=14)

        tk.Frame(self.root, bg=C["accent"], height=2).pack(fill=tk.X)

        list_outer = tk.Frame(self.root, bg=C["bg2"], bd=0)
        list_outer.pack(fill=tk.BOTH, expand=True, padx=16, pady=14)

        tk.Label(list_outer, text="  Encrypted Files on Server",
                 font=("Helvetica", 10, "italic"),
                 bg=C["bg2"], fg=C["text_dim"],
                 anchor='w').pack(fill=tk.X, pady=(8, 4))

        list_frame = tk.Frame(list_outer, bg=C["bg3"], bd=0)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        scroll = tk.Scrollbar(list_frame, bg=C["bg2"],
                              troughcolor=C["bg3"], relief=tk.FLAT)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.file_listbox = tk.Listbox(
            list_frame,
            yscrollcommand=scroll.set,
            font=("Courier New", 12),
            selectmode=tk.SINGLE,
            bg=C["bg3"],
            fg=C["text"],
            selectbackground=C["accent"],
            selectforeground="white",
            activestyle='none',
            relief=tk.FLAT,
            bd=0,
            highlightthickness=0,
        )
        self.file_listbox.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        scroll.config(command=self.file_listbox.yview)

        btn_frame1 = tk.Frame(self.root, bg=C["bg"])
        btn_frame1.pack(fill=tk.X, padx=16, pady=(0, 6))

        btn_frame2 = tk.Frame(self.root, bg=C["bg"])
        btn_frame2.pack(fill=tk.X, padx=16, pady=(0, 12))

        # Row 1
        self._btn(btn_frame1, "⬆  Upload",   self._upload).pack(side=tk.LEFT, padx=4)
        self._btn(btn_frame1, "⬇  Download", self._download).pack(side=tk.LEFT, padx=4)
        self._btn(btn_frame1, "🗑  Delete",   self._delete,
                  color=C["accent2"]).pack(side=tk.LEFT, padx=4)

        # Row 2
        self._btn(btn_frame2, "🔗  Share File", self._share_file).pack(side=tk.LEFT, padx=4)
        self._btn(btn_frame2, "📥  Recive Files", self._get_shared).pack(side=tk.LEFT, padx=4)
        self._btn(btn_frame2, "🔄  Refresh",    self._list_files).pack(side=tk.LEFT, padx=4)

        status_bar = tk.Frame(self.root, bg=C["header"], height=28)
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        status_bar.pack_propagate(False)

        self.status_var = tk.StringVar(value="Connecting…")
        tk.Label(status_bar, textvariable=self.status_var,
                 anchor='w', bg=C["header"], fg=C["text_dim"],
                 font=("Helvetica", 9)).pack(fill=tk.X, padx=10, pady=5)


    def _set_status(self, msg: str):
        self.status_var.set(msg)
        self.root.update_idletasks()


    def _connect_to_server(self):
        try:
            raw_sock = socket.create_connection((HOST, PORT), timeout=10)

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE

            self.ssl_sock = ctx.wrap_socket(raw_sock, server_hostname=HOST)

            # AUTH: send username only. Password never leaves the client.
            send_msg(self.ssl_sock, {"cmd": "AUTH", "username": self.username})
            resp = recv_msg(self.ssl_sock)

            if resp.get("status") != "ok":
                raise ConnectionError(resp.get("message", "Authentication failed."))

            self._set_status("✔  Connected securely via TLS. Your password never leaves this device.")
            self._list_files()

        except Exception as e:
            messagebox.showerror("Connection Error", str(e))
            self._set_status(f"Connection failed: {e}")


    def _list_files(self):
        try:
            send_msg(self.ssl_sock, {"cmd": "LIST"})
            resp = recv_msg(self.ssl_sock)
            files = resp.get("files", [])
            self.file_listbox.delete(0, tk.END)
            for fname in files:
                self.file_listbox.insert(tk.END, f"  🔐  {fname}")
            self._set_status(f"✔  {len(files)} encrypted file(s) on server.")
        except Exception as e:
            self._set_status(f"List error: {e}")

    def _upload(self):
        path = filedialog.askopenfilename(title="Select file to encrypt and upload")
        if not path:
            return

        filename = os.path.basename(path)

        try:
            with open(path, 'rb') as fh:
                plaintext = fh.read()

            self._set_status("Encrypting file with AES-256-GCM…")
            blob = encrypt_file(plaintext, self.password)
            blob['original_filename'] = filename

            self._set_status("Uploading ciphertext to server…")
            send_msg(self.ssl_sock, {"cmd": "UPLOAD", "filename": filename, "blob": blob})
            resp = recv_msg(self.ssl_sock)

            if resp.get("status") == "ok":
                self._set_status(f"✔  '{filename}' encrypted and uploaded. Server sees only ciphertext.")
                self._list_files()
            else:
                self._set_status(f"Upload failed: {resp.get('message')}")

        except Exception as e:
            self._set_status(f"Upload error: {e}")
            messagebox.showerror("Upload Error", str(e))

    def _download(self):
        sel = self.file_listbox.curselection()
        if not sel:
            messagebox.showwarning("No File Selected", "Please select a file from the list.")
            return

        filename = self.file_listbox.get(sel[0]).strip().replace("🔐  ", "")
        save_path = filedialog.asksaveasfilename(
            title="Save decrypted file as…",
            initialfile=filename
        )
        if not save_path:
            return

        try:
            send_msg(self.ssl_sock, {"cmd": "DOWNLOAD", "filename": filename})
            resp = recv_msg(self.ssl_sock)

            if resp.get("status") != "ok":
                messagebox.showerror("Download Error", resp.get("message", "File not found."))
                return

            self._set_status("Verifying HMAC integrity and decrypting…")
            plaintext = decrypt_file(resp["blob"], self.password)

            with open(save_path, 'wb') as fh:
                fh.write(plaintext)

            self._set_status(f"✔  '{filename}' — integrity verified and decrypted successfully.")

        except InvalidSignature:
            messagebox.showerror(
                "⚠ Integrity Check FAILED",
                "HMAC verification failed!\n\n"
                "The file may have been tampered with on the server.\n"
                "Do NOT use this file."
            )
            self._set_status("⚠  Integrity check FAILED — possible tampering detected!")

        except Exception as e:
            messagebox.showerror("Decryption Error",
                                 f"Decryption failed.\n\nDetails: {e}\n\nWrong password?")
            self._set_status(f"Decryption error: {e}")

    def _delete(self):
        sel = self.file_listbox.curselection()
        if not sel:
            messagebox.showwarning("No File Selected", "Please select a file to delete.")
            return

        filename = self.file_listbox.get(sel[0]).strip().replace("🔐  ", "")
        if not messagebox.askyesno("Confirm Delete", f"Permanently delete '{filename}' from the server?"):
            return

        try:
            send_msg(self.ssl_sock, {"cmd": "DELETE", "filename": filename})
            resp = recv_msg(self.ssl_sock)
            self._set_status(resp.get("message", "File deleted."))
            self._list_files()
        except Exception as e:
            self._set_status(f"Delete error: {e}")

    def _share_file(self):
        sel = self.file_listbox.curselection()
        if not sel:
            messagebox.showwarning("No File Selected", "Select a file to share.")
            return

        filename = self.file_listbox.get(sel[0]).strip().replace("🔐  ", "")

        share_password = simpledialog.askstring(
            "Share Password",
            "Enter a password the recipient will use to decrypt:\n"
            "(Different from your own master password)",
            show='*', parent=self.root
        )
        if not share_password:
            return

        try:
            send_msg(self.ssl_sock, {"cmd": "DOWNLOAD", "filename": filename})
            resp = recv_msg(self.ssl_sock)
            if resp.get("status") != "ok":
                messagebox.showerror("Error", resp.get("message"))
                return

            self._set_status("Decrypting with your password…")
            plaintext = decrypt_file(resp["blob"], self.password)

            self._set_status("Re-encrypting with share password…")
            share_blob = encrypt_file(plaintext, share_password)
            share_blob['original_filename'] = filename

            token = secrets.token_hex(8)
            send_msg(self.ssl_sock, {"cmd": "SHARE", "token": token, "blob": share_blob})
            resp2 = recv_msg(self.ssl_sock)

            if resp2.get("status") == "ok":
                self._show_token_dialog(token)
                self._set_status(f"✔  File shared. Token: {token}")
            else:
                self._set_status(f"Share failed: {resp2.get('message')}")

        except InvalidSignature:
            messagebox.showerror("Integrity Error", "HMAC check failed. File may be corrupted.")
        except Exception as e:
            self._set_status(f"Share error: {e}")
            messagebox.showerror("Share Error", str(e))

    def _show_token_dialog(self, token: str):
        dlg = tk.Toplevel(self.root)
        dlg.title("File Shared")
        dlg.grab_set()
        dlg.resizable(False, False)
        dlg.geometry("460x260")
        dlg.configure(bg=C["bg"])

        tk.Label(dlg, text="✔  File Shared Successfully!",
                 font=("Helvetica", 13, "bold"),
                 bg=C["bg"], fg=C["success"]).pack(pady=(22, 6))

        tk.Label(dlg, text="Share Token — click the button to copy:",
                 font=("Helvetica", 10),
                 bg=C["bg"], fg=C["text_dim"]).pack()

        # Read-only token field
        token_var = tk.StringVar(value=token)
        token_entry = tk.Entry(
            dlg, textvariable=token_var,
            font=("Courier New", 14, "bold"),
            justify='center',
            fg=C["accent"], bg=C["bg3"],
            readonlybackground=C["bg3"],
            relief=tk.FLAT, bd=6,
            state='readonly', width=22,
        )
        token_entry.pack(pady=10, ipady=6)

        def copy_token():
            dlg.clipboard_clear()
            dlg.clipboard_append(token)
            copy_btn.config(text="✔  Copied to Clipboard!", bg=C["success"], fg="white")
            dlg.after(2000, lambda: copy_btn.config(
                text="📋  Copy Token", bg=C["btn_bg"], fg=C["text"]))

        copy_btn = tk.Button(
            dlg, text="📋  Copy Token", command=copy_token,
            font=("Helvetica", 11), width=20,
            bg=C["btn_bg"], fg=C["text"],
            activebackground=C["btn_active"], activeforeground=C["text"],
            relief=tk.FLAT, bd=0, pady=6, cursor="hand2"
        )
        copy_btn.pack(pady=(0, 8))

        tk.Label(dlg, text="Give this token + the share password to the recipient.",
                 font=("Helvetica", 9), bg=C["bg"], fg=C["text_dim"]).pack()

        tk.Button(dlg, text="Close", command=dlg.destroy,
                  font=("Helvetica", 10), width=10,
                  bg=C["btn_bg"], fg=C["text"],
                  activebackground=C["btn_active"],
                  relief=tk.FLAT, bd=0, pady=5).pack(pady=12)

    def _get_shared(self):
        token = simpledialog.askstring(
            "Receive Shared File", "Enter the share token:", parent=self.root
        )
        if not token:
            return

        share_password = simpledialog.askstring(
            "Share Password", "Enter the share password:", show='*', parent=self.root
        )
        if not share_password:
            return

        try:
            send_msg(self.ssl_sock, {"cmd": "GET_SHARED", "token": token.strip()})
            resp = recv_msg(self.ssl_sock)

            if resp.get("status") != "ok":
                messagebox.showerror("Error", resp.get("message", "Token not found."))
                return

            self._set_status("Verifying integrity and decrypting shared file…")
            plaintext = decrypt_file(resp["blob"], share_password)

            orig_name = resp["blob"].get("original_filename", "shared_file")
            save_path = filedialog.asksaveasfilename(
                title="Save shared file as…", initialfile=orig_name
            )
            if save_path:
                with open(save_path, 'wb') as fh:
                    fh.write(plaintext)
                self._set_status(f"✔  Shared file decrypted and saved.")

        except InvalidSignature:
            messagebox.showerror(
                "⚠ Integrity Check FAILED",
                "HMAC verification failed!\n\nWrong password or file was tampered with."
            )
            self._set_status("⚠  Integrity check FAILED on shared file!")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to retrieve shared file:\n{e}")
            self._set_status(f"Get-shared error: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    root.withdraw()                   
    app = SecureStorageClient(root)
    root.deiconify()
    root.mainloop()
