"""
server.py
=========
The relay server for the Secure Chat Application.

IMPORTANT SECURITY NOTE (this is the whole point of the assignment):
The server authenticates users and shuffles bytes between them, but it
never has the ability to read a single chat message. It only ever
handles:
  - login/registration (plaintext password over the wire -> see README
    for the "wrap this in TLS for production" note)
  - RSA PUBLIC keys (public by definition, safe to see)
  - key_exchange blobs  = an AES session key encrypted with the
    RECIPIENT's RSA public key -> the server has no matching private
    key, so this is opaque garbage to it.
  - message blobs       = AES-GCM ciphertext -> opaque garbage too.

Run:  python3 server.py [port]   (default port 5555)
"""

import socket
import threading
import sys

from crypto_utils import pack, unpack
import auth

HOST = "0.0.0.0"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 5555

# username -> {"conn": socket, "pubkey": b64pem or None}
clients = {}
clients_lock = threading.Lock()


def log(msg):
    print(f"[SERVER] {msg}")


def broadcast_user_list():
    with clients_lock:
        online = [u for u, info in clients.items() if info["pubkey"]]
        payload = pack({"type": "user_list", "users": online})
        for info in clients.values():
            try:
                info["conn"].sendall(payload)
            except OSError:
                pass


def send_to(username, msg: dict) -> bool:
    with clients_lock:
        info = clients.get(username)
        if not info:
            return False
        try:
            info["conn"].sendall(pack(msg))
            return True
        except OSError:
            return False


def handle_client(conn: socket.socket, addr):
    username = None
    buf = ""
    log(f"Connection from {addr}")
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            buf += data.decode()
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                if not line.strip():
                    continue
                msg = unpack(line)
                mtype = msg.get("type")

                # ---------------- authentication ----------------
                if mtype == "register":
                    ok, text = auth.register(msg["username"], msg["password"])
                    conn.sendall(pack({"type": "auth_result", "ok": ok, "msg": text}))

                elif mtype == "login":
                    ok, text = auth.login(msg["username"], msg["password"])
                    if ok:
                        uname = msg["username"]
                        with clients_lock:
                            if uname in clients:
                                ok, text = False, "User already logged in elsewhere."
                        if ok:
                            username = uname
                            with clients_lock:
                                clients[username] = {"conn": conn, "pubkey": None}
                            log(f"{username} authenticated from {addr}")
                    conn.sendall(pack({"type": "auth_result", "ok": ok, "msg": text}))

                # ------------- public key exchange --------------
                elif mtype == "publish_pubkey" and username:
                    with clients_lock:
                        clients[username]["pubkey"] = msg["pubkey"]
                    log(f"{username} published RSA public key")
                    broadcast_user_list()

                elif mtype == "request_pubkey" and username:
                    target = msg["target"]
                    with clients_lock:
                        info = clients.get(target)
                    if info and info["pubkey"]:
                        conn.sendall(pack({
                            "type": "pubkey",
                            "username": target,
                            "pubkey": info["pubkey"],
                        }))

                # ------------- forwarded, opaque to server -------------
                elif mtype in ("key_exchange", "message") and username:
                    target = msg.get("target")
                    msg["from"] = username
                    delivered = send_to(target, msg)
                    if not delivered:
                        conn.sendall(pack({
                            "type": "system",
                            "text": f"{target} is not online. Message not delivered.",
                        }))
                    else:
                        kind = "session key" if mtype == "key_exchange" else "encrypted message"
                        log(f"relayed {kind}: {username} -> {target} "
                            f"(server cannot read the content)")

    except (ConnectionResetError, OSError):
        pass
    finally:
        if username:
            with clients_lock:
                clients.pop(username, None)
            log(f"{username} disconnected")
            broadcast_user_list()
        conn.close()


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(20)
    log(f"Listening on {HOST}:{PORT}")
    try:
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        log("Shutting down.")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
