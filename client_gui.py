"""
client_gui.py
=============
CipherLink — a GUI secure-chat client.

What happens under the hood, in order, every time you chat with someone
for the first time in a session:

  1. You log in over the socket (password authenticated by the server).
  2. Your app generates a fresh RSA-2048 keypair and PUBLISHES the
     public half to the server, which broadcasts it to everyone online.
  3. You open a chat with "bob". Your client asks the server for bob's
     RSA public key (public info, fine to hand out).
  4. Your client invents a random AES-256 key (the SESSION KEY) just
     for this conversation, encrypts it with bob's RSA public key
     (RSA-OAEP), and sends that blob to bob. Only bob's private key
     (which never left his machine) can open it.
  5. From then on, every message you two send is AES-256-GCM encrypted
     with that shared session key. The server relays bytes it cannot
     decrypt — true end-to-end encryption.

The "Encryption Console" panel on the right lets you SEE this happening
live: the session key fingerprint (so you can verbally confirm with
your peer that you both derived the same key — this defeats a
man-in-the-middle who tried to swap public keys in transit) and the
raw ciphertext of the last message, so you can see this is not just a
label — the bytes on the wire really are unreadable.

Run:  python3 client_gui.py [server_host] [server_port]
"""

import sys
import os
import json
import socket
import threading
import queue
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

from crypto_utils import (
    generate_rsa_keypair, serialize_public_key, deserialize_public_key,
    serialize_private_key, deserialize_private_key,
    rsa_encrypt, rsa_decrypt,
    generate_session_key, aes_encrypt, aes_decrypt, key_fingerprint,
    pack, unpack,
)

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 5555

KEY_DIR = os.path.join(os.path.dirname(__file__), "keys")
os.makedirs(KEY_DIR, exist_ok=True)

BG = "#0e1117"
PANEL = "#161b22"
ACCENT = "#39d353"
ACCENT_DIM = "#1f6feb"
FG = "#c9d1d9"
BUBBLE_ME = "#1f6feb"
BUBBLE_THEM = "#21262d"


class CipherLinkClient:
    def __init__(self, root):
        self.root = root
        self.root.title("CipherLink — Secure Vault Chat")
        self.root.geometry("980x640")
        self.root.configure(bg=BG)

        self.sock = None
        self.username = None
        self.private_key = None
        self.public_key = None

        self.peer_pubkeys = {}      # username -> RSA public key obj
        self.session_keys = {}      # username -> AES-256 session key bytes
        self.chat_logs = {}         # username -> list of (who, text)
        self.online_users = []
        self.current_peer = None

        self.incoming = queue.Queue()
        self.pending_pubkey_requests = {}  # username -> "start_chat" flag

        self.build_login_screen()

    # ------------------------------------------------------------------
    # LOGIN / REGISTER SCREEN
    # ------------------------------------------------------------------
    def build_login_screen(self):
        self.login_frame = tk.Frame(self.root, bg=BG)
        self.login_frame.pack(expand=True, fill="both")

        card = tk.Frame(self.login_frame, bg=PANEL, padx=40, pady=36)
        card.place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(card, text="🔒 CipherLink", font=("Helvetica", 24, "bold"),
                 bg=PANEL, fg=ACCENT).pack(pady=(0, 4))
        tk.Label(card, text="End-to-end encrypted chat  •  RSA-2048 + AES-256-GCM",
                 font=("Helvetica", 10), bg=PANEL, fg=FG).pack(pady=(0, 20))

        tk.Label(card, text="Username", bg=PANEL, fg=FG, anchor="w").pack(fill="x")
        self.user_entry = tk.Entry(card, width=30, bg="#0d1117", fg=FG,
                                    insertbackground=FG, relief="flat")
        self.user_entry.pack(pady=(2, 12), ipady=5)

        tk.Label(card, text="Password", bg=PANEL, fg=FG, anchor="w").pack(fill="x")
        self.pass_entry = tk.Entry(card, width=30, show="•", bg="#0d1117", fg=FG,
                                    insertbackground=FG, relief="flat")
        self.pass_entry.pack(pady=(2, 18), ipady=5)

        btn_row = tk.Frame(card, bg=PANEL)
        btn_row.pack(fill="x")
        tk.Button(btn_row, text="Login", bg=ACCENT, fg="#02240d", relief="flat",
                  font=("Helvetica", 10, "bold"), width=12,
                  command=self.do_login).pack(side="left", padx=(0, 8))
        tk.Button(btn_row, text="Register", bg=ACCENT_DIM, fg="white", relief="flat",
                  font=("Helvetica", 10, "bold"), width=12,
                  command=self.do_register).pack(side="left")

        self.login_status = tk.Label(card, text=f"Server: {HOST}:{PORT}",
                                      bg=PANEL, fg="#8b949e", font=("Helvetica", 9))
        self.login_status.pack(pady=(16, 0))

    def connect_socket(self):
        if self.sock:
            return True
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((HOST, PORT))
            threading.Thread(target=self.listen_loop, daemon=True).start()
            return True
        except OSError as e:
            messagebox.showerror("Connection failed", str(e))
            self.sock = None
            return False

    def do_register(self):
        if not self.connect_socket():
            return
        u, p = self.user_entry.get().strip(), self.pass_entry.get()
        if not u or not p:
            self.login_status.config(text="Enter a username and password first.")
            return
        self.sock.sendall(pack({"type": "register", "username": u, "password": p}))
        self._await_auth_result(u, p, then_login=True)

    def do_login(self):
        if not self.connect_socket():
            return
        u, p = self.user_entry.get().strip(), self.pass_entry.get()
        if not u or not p:
            self.login_status.config(text="Enter a username and password first.")
            return
        self.sock.sendall(pack({"type": "login", "username": u, "password": p}))
        self._await_auth_result(u, p, then_login=False)

    def _await_auth_result(self, username, password, then_login):
        def wait():
            try:
                msg = self.incoming.get(timeout=5)
            except queue.Empty:
                self.root.after(0, lambda: self.login_status.config(text="No response from server."))
                return
            if msg.get("type") != "auth_result":
                return
            if msg["ok"]:
                if then_login:
                    self.root.after(0, lambda: self.login_status.config(
                        text="Registered! Logging you in..."))
                    self.sock.sendall(pack({"type": "login", "username": username, "password": password}))
                    self._await_auth_result(username, password, then_login=False)
                else:
                    self.username = username
                    self.root.after(0, lambda: self.on_logged_in(username, password))
            else:
                self.root.after(0, lambda: self.login_status.config(text=msg["msg"]))
        threading.Thread(target=wait, daemon=True).start()

    # ------------------------------------------------------------------
    # POST-LOGIN: keys + main chat UI
    # ------------------------------------------------------------------
    def on_logged_in(self, username, password):
        self.setup_identity_keys(username, password)
        self.sock.sendall(pack({
            "type": "publish_pubkey",
            "pubkey": serialize_public_key(self.public_key),
        }))
        self.login_frame.destroy()
        self.build_chat_ui()

    def setup_identity_keys(self, username, password):
        """Load an existing RSA identity for this user, or create one.
        The private key is stored encrypted at rest with the user's
        own login password — never in plaintext on disk."""
        path = os.path.join(KEY_DIR, f"{username}.pem")
        pw_bytes = password.encode()
        if os.path.exists(path):
            with open(path, "rb") as f:
                pem = f.read()
            self.private_key = deserialize_private_key(pem, pw_bytes)
            self.public_key = self.private_key.public_key()
        else:
            self.private_key, self.public_key = generate_rsa_keypair()
            with open(path, "wb") as f:
                f.write(serialize_private_key(self.private_key, pw_bytes))

    def build_chat_ui(self):
        top = tk.Frame(self.root, bg=PANEL, height=44)
        top.pack(fill="x")
        tk.Label(top, text=f"🔒 CipherLink", font=("Helvetica", 13, "bold"),
                 bg=PANEL, fg=ACCENT).pack(side="left", padx=14, pady=8)
        tk.Label(top, text=f"logged in as {self.username}", bg=PANEL, fg="#8b949e",
                 font=("Helvetica", 10)).pack(side="left")

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill="both", expand=True)

        # ---- left: contacts ----
        left = tk.Frame(body, bg=PANEL, width=200)
        left.pack(side="left", fill="y")
        tk.Label(left, text="ONLINE", bg=PANEL, fg="#8b949e",
                 font=("Helvetica", 9, "bold")).pack(anchor="w", padx=12, pady=(12, 4))
        self.contacts_box = tk.Listbox(left, bg=PANEL, fg=FG, bd=0, highlightthickness=0,
                                        activestyle="none", font=("Helvetica", 11),
                                        selectbackground=ACCENT_DIM)
        self.contacts_box.pack(fill="both", expand=True, padx=6)
        self.contacts_box.bind("<<ListboxSelect>>", self.on_select_contact)

        # ---- center: chat ----
        center = tk.Frame(body, bg=BG)
        center.pack(side="left", fill="both", expand=True)

        self.chat_header = tk.Label(center, text="Select a contact to start an encrypted chat",
                                     bg=BG, fg=FG, font=("Helvetica", 11, "bold"), anchor="w")
        self.chat_header.pack(fill="x", padx=12, pady=(10, 4))

        self.chat_display = scrolledtext.ScrolledText(
            center, bg="#0d1117", fg=FG, wrap="word", bd=0,
            font=("Helvetica", 11), state="disabled")
        self.chat_display.pack(fill="both", expand=True, padx=12, pady=4)
        self.chat_display.tag_config("me", justify="right", foreground=FG,
                                      background=BUBBLE_ME, spacing1=4, spacing3=4)
        self.chat_display.tag_config("them", justify="left", foreground=FG,
                                      background=BUBBLE_THEM, spacing1=4, spacing3=4)
        self.chat_display.tag_config("sys", justify="center", foreground="#8b949e",
                                      font=("Helvetica", 9, "italic"))

        entry_row = tk.Frame(center, bg=BG)
        entry_row.pack(fill="x", padx=12, pady=(0, 12))
        self.msg_entry = tk.Entry(entry_row, bg="#0d1117", fg=FG,
                                   insertbackground=FG, relief="flat", font=("Helvetica", 11))
        self.msg_entry.pack(side="left", fill="x", expand=True, ipady=8, padx=(0, 8))
        self.msg_entry.bind("<Return>", lambda e: self.send_message())
        tk.Button(entry_row, text="Send", bg=ACCENT, fg="#02240d", relief="flat",
                  font=("Helvetica", 10, "bold"), command=self.send_message).pack(side="left")

        # ---- right: encryption console (the "prove it" panel) ----
        right = tk.Frame(body, bg=PANEL, width=270)
        right.pack(side="right", fill="y")
        tk.Label(right, text="🔐 ENCRYPTION CONSOLE", bg=PANEL, fg=ACCENT,
                 font=("Helvetica", 10, "bold")).pack(anchor="w", padx=12, pady=(12, 8))

        self.console = tk.Text(right, bg=PANEL, fg=FG, bd=0, wrap="word",
                                font=("Consolas", 9), height=34, width=34, state="disabled")
        self.console.pack(padx=10, fill="both", expand=True)
        self.log_console("Waiting for peer selection...\n")

        self.poll_queue()

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def log_console(self, text):
        self.console.config(state="normal")
        self.console.insert("end", text + "\n")
        self.console.see("end")
        self.console.config(state="disabled")

    def append_bubble(self, who_tag, prefix, text):
        self.chat_display.config(state="normal")
        self.chat_display.insert("end", f"{prefix}{text}\n", who_tag)
        self.chat_display.see("end")
        self.chat_display.config(state="disabled")

    def append_system(self, text):
        self.chat_display.config(state="normal")
        self.chat_display.insert("end", f"— {text} —\n", "sys")
        self.chat_display.see("end")
        self.chat_display.config(state="disabled")

    def redraw_chat(self, peer):
        self.chat_display.config(state="normal")
        self.chat_display.delete("1.0", "end")
        self.chat_display.config(state="disabled")
        for who, text in self.chat_logs.get(peer, []):
            if who == "sys":
                self.append_system(text)
            elif who == "me":
                self.append_bubble("me", "You: ", text)
            else:
                self.append_bubble("them", f"{peer}: ", text)

    # ------------------------------------------------------------------
    # contact selection & key exchange
    # ------------------------------------------------------------------
    def on_select_contact(self, event):
        sel = self.contacts_box.curselection()
        if not sel:
            return
        peer = self.contacts_box.get(sel[0])
        self.current_peer = peer
        self.chat_logs.setdefault(peer, [])
        self.chat_header.config(text=f"🔒 {peer}   (end-to-end encrypted)")
        self.redraw_chat(peer)

        if peer not in self.session_keys:
            self.append_system("No secure session yet — starting key exchange...")
            self.pending_pubkey_requests[peer] = "start_chat"
            self.sock.sendall(pack({"type": "request_pubkey", "target": peer}))
            self.log_console(f"\n>>> Requesting {peer}'s RSA public key from server...")
        else:
            fp = key_fingerprint(self.session_keys[peer])
            self.log_console(f"\n>>> Existing session with {peer}. Key fingerprint: {fp}")

    def start_key_exchange_as_initiator(self, peer):
        """We already have peer's public key — invent a session key and send it."""
        session_key = generate_session_key()
        self.session_keys[peer] = session_key
        wrapped = rsa_encrypt(self.peer_pubkeys[peer], session_key)
        self.sock.sendall(pack({
            "type": "key_exchange",
            "target": peer,
            "enc_session_key": __import__("base64").b64encode(wrapped).decode(),
        }))
        fp = key_fingerprint(session_key)
        self.log_console(f">>> Generated AES-256 session key for {peer}.")
        self.log_console(f">>> Encrypted it with {peer}'s RSA-2048 public key (RSA-OAEP).")
        self.log_console(f">>> Sent over socket — server cannot decrypt it.")
        self.log_console(f">>> Session key fingerprint: {fp}")
        self.log_console(f">>> (Ask {peer} to confirm this fingerprint matches on their screen)")
        self.append_system(f"Secure session established with {peer}  [{fp}]")

    # ------------------------------------------------------------------
    # sending
    # ------------------------------------------------------------------
    def send_message(self):
        peer = self.current_peer
        text = self.msg_entry.get().strip()
        if not peer or not text:
            return
        if peer not in self.session_keys:
            self.append_system("Still setting up the secure session — try again in a second.")
            return
        session_key = self.session_keys[peer]
        payload = aes_encrypt(session_key, text)
        self.sock.sendall(pack({
            "type": "message",
            "target": peer,
            "nonce": payload["nonce"],
            "ciphertext": payload["ciphertext"],
        }))
        self.chat_logs.setdefault(peer, []).append(("me", text))
        self.append_bubble("me", "You: ", text)
        self.msg_entry.delete(0, "end")

        self.log_console(f"\n>>> Sent to {peer}")
        self.log_console(f"    plaintext : {text}")
        self.log_console(f"    ciphertext: {payload['ciphertext'][:60]}...")
        self.log_console(f"    (AES-256-GCM, fresh nonce {payload['nonce'][:16]}...)")

    # ------------------------------------------------------------------
    # background socket listener + queue polling
    # ------------------------------------------------------------------
    def listen_loop(self):
        buf = ""
        try:
            while True:
                data = self.sock.recv(4096)
                if not data:
                    break
                buf += data.decode()
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    if line.strip():
                        self.incoming.put(unpack(line))
        except OSError:
            pass

    def poll_queue(self):
        try:
            while True:
                msg = self.incoming.get_nowait()
                self.handle_server_message(msg)
        except queue.Empty:
            pass
        self.root.after(100, self.poll_queue)

    def handle_server_message(self, msg):
        mtype = msg.get("type")

        if mtype == "user_list":
            self.online_users = [u for u in msg["users"] if u != self.username]
            self.contacts_box.delete(0, "end")
            for u in self.online_users:
                self.contacts_box.insert("end", u)

        elif mtype == "pubkey":
            peer = msg["username"]
            self.peer_pubkeys[peer] = deserialize_public_key(msg["pubkey"])
            self.log_console(f">>> Received {peer}'s RSA public key.")
            if self.pending_pubkey_requests.pop(peer, None) == "start_chat":
                self.start_key_exchange_as_initiator(peer)

        elif mtype == "key_exchange":
            peer = msg["from"]
            import base64
            wrapped = base64.b64decode(msg["enc_session_key"])
            session_key = rsa_decrypt(self.private_key, wrapped)
            self.session_keys[peer] = session_key
            fp = key_fingerprint(session_key)
            self.log_console(f"\n>>> Received a session-key handshake from {peer}.")
            self.log_console(f">>> Decrypted it with MY RSA private key (never left this machine).")
            self.log_console(f">>> Session key fingerprint: {fp}")
            self.chat_logs.setdefault(peer, []).append(
                ("sys", f"Secure session established with {peer}  [{fp}]"))
            if self.current_peer == peer:
                self.redraw_chat(peer)

        elif mtype == "message":
            peer = msg["from"]
            session_key = self.session_keys.get(peer)
            if not session_key:
                self.log_console(f"\n>>> Message from {peer} arrived before key exchange — dropped.")
                return
            text = aes_decrypt(session_key, {"nonce": msg["nonce"], "ciphertext": msg["ciphertext"]})
            self.chat_logs.setdefault(peer, []).append(("them", text))
            self.log_console(f"\n>>> Received from {peer}")
            self.log_console(f"    ciphertext: {msg['ciphertext'][:60]}...")
            self.log_console(f"    decrypted : {text}")
            if self.current_peer == peer:
                self.append_bubble("them", f"{peer}: ", text)
            else:
                self.append_system(f"New message from {peer}")

        elif mtype == "system":
            if self.current_peer:
                self.append_system(msg["text"])


if __name__ == "__main__":
    root = tk.Tk()
    app = CipherLinkClient(root)
    root.mainloop()
