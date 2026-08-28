"""
auth.py
=======
Very small user-authentication store for the server side.

Users are kept in users.json as:
    { "username": {"hash": "...", "salt": "..."} }

Only the PBKDF2 hash + salt are stored — never the plaintext password,
and never a message's content (this file has nothing to do with the
E2E message encryption, it only gates who is allowed to join the chat).
"""

import json
import os
import threading

from crypto_utils import hash_password, verify_password

DB_FILE = os.path.join(os.path.dirname(__file__), "users.json")
_lock = threading.Lock()


def _load():
    if not os.path.exists(DB_FILE):
        return {}
    with open(DB_FILE, "r") as f:
        return json.load(f)


def _save(data):
    with open(DB_FILE, "w") as f:
        json.dump(data, f, indent=2)


def register(username: str, password: str) -> tuple[bool, str]:
    with _lock:
        users = _load()
        if username in users:
            return False, "Username already taken."
        if len(password) < 6:
            return False, "Password must be at least 6 characters."
        h, s = hash_password(password)
        users[username] = {"hash": h, "salt": s}
        _save(users)
        return True, "Registered successfully."


def login(username: str, password: str) -> tuple[bool, str]:
    with _lock:
        users = _load()
        if username not in users:
            return False, "No such user."
        record = users[username]
        if verify_password(password, record["hash"], record["salt"]):
            return True, "Login successful."
        return False, "Incorrect password."
