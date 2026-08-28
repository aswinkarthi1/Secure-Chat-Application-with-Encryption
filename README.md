# CipherLink — Secure Chat Application with Encryption

A socket-programmed, end-to-end encrypted chat application built in Python,
with a dark-themed Tkinter GUI and a live "Encryption Console" that shows
the cryptography happening in real time.

---

# 1. Features (mapped to the assignment brief)

| Requirement | How it's implemented |
|---|---|
| Secure Communication | Every message is encrypted with **AES-256-GCM** before it touches the socket. |
| User Authentication | Username/password login. Passwords are hashed with **PBKDF2-HMAC-SHA256** (200,000 iterations, random salt per user) — never stored or sent in plaintext. |
| End-to-End Encryption | The relay server only ever sees ciphertext and public keys. It has no way to decrypt a message — see §3. |
| Key Exchange | **RSA-2048 (OAEP)** hybrid key exchange: each pair of chatters agrees on a fresh AES-256 session key, wrapped with the recipient's RSA public key. |
| GUI Interface | Tkinter app ("CipherLink") — login screen, contact list, chat bubbles, and a live console showing keys/ciphertext as they're generated. |

---

# 2. Files

```
secure_chat/
├── server.py         # Relay server — routes messages, never decrypts them
├── client_gui.py      # The Tkinter GUI client ("CipherLink")
├── crypto_utils.py    # All cryptography: RSA, AES-GCM, PBKDF2, wire format
├── auth.py             # Server-side user store (users.json), password hashing/verification
├── requirements.txt
└── README.md
```

# 3. Design: how the encryption actually works

**Asymmetric layer — RSA-2048, used only for the handshake.**
When you log in, your client generates an RSA-2048 keypair (or loads your
existing one, decrypted from disk using your login password). Your public
key is published to the server, which acts purely as a phone book, handing
your public key to anyone who asks. Your private key is never transmitted —
it is generated locally and, when saved to disk, is itself encrypted with
your password (`keys/<username>.pem`, PKCS8 + password-based encryption).

**Symmetric layer — AES-256-GCM, used for every chat message.**
RSA is slow and can't encrypt arbitrary-length messages, so as soon as you
open a chat with someone, your client invents a random AES-256 "session
key" just for that conversation, encrypts it with the recipient's RSA
public key (RSA-OAEP padding), and sends the wrapped key over the socket.
Only the recipient's private key can unwrap it. From then on every message
between you two is AES-256-GCM encrypted with that shared key — GCM mode
also gives built-in tamper detection (an authentication tag), so a
modified ciphertext will fail to decrypt rather than silently corrupt.

**Why the server can't read your messages.**
The server (`server.py`) only ever handles three kinds of payloads:
public keys (public by definition), RSA-wrapped AES session keys (it has
no private key to unwrap them with), and AES-GCM ciphertext (it has no
session key to decrypt it with). It logs *that* it relayed a message, never
*what* the message says — you can see this yourself in the server console
output.

**Key fingerprint verification (anti man-in-the-middle).**
The Encryption Console shows a short fingerprint (SHA-256 of the session
key, first 12 hex chars) whenever a secure session is established. Two
people in a call can read this fingerprint aloud to each other — if they
match, no one tampered with the key exchange in transit.

# 4. Setup & running it

```bash
pip install -r requirements.txt

# Terminal 1 — start the relay server (defaults to port 5555)
python3 server.py

# Terminal 2 — first client
python3 client_gui.py 127.0.0.1 5555

# Terminal 3 — second client (different machine: use the server's real IP)
python3 client_gui.py 127.0.0.1 5555
```

1. In each client window, **Register** a username/password (min 6 chars),
   it logs you in automatically.
2. Once both clients are online, each will appear in the other's **ONLINE**
   list on the left.
3. Click a contact's name — this triggers the automatic RSA key exchange
   (watch the **Encryption Console** on the right to see it happen).
4. Type a message and hit Enter / Send. Watch the console show the
   plaintext going in and the ciphertext going out on the wire.

# 5. Demonstrating the "secure" part

- Run `python3 server.py` in a visible terminal while chatting — the log
  only ever prints `relayed encrypted message: alice -> bob (server cannot
  read the content)`, never the message text.
- The Encryption Console panel in the GUI prints the actual base64
  ciphertext of every message sent/received, so you can visually confirm
  it's unreadable garbage on the wire, alongside the decrypted plaintext
  once your own private key has unwrapped it.
- Two clients that establish a session will show the same key
  fingerprint in their consoles — a live, verifiable proof both sides
  derived the identical AES session key.

# 6. Known limitations / production notes

- The login handshake (username+password) itself travels as plain JSON,
  not TLS — fine for a coursework/LAN demo, but a production deployment
  should wrap the whole TCP connection in TLS (`ssl.wrap_socket`) so even
  the login step is encrypted in transit.
- This implements one-to-one E2E encrypted chats. Group chat would extend
  the same hybrid pattern by wrapping the session key separately for each
  group member.
- `users.json` and the `keys/` folder are created at runtime in the same
  directory as the scripts — delete them to reset all accounts/identities.
