from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
import base64
import hashlib
import json
import os
import secrets
import time
import uuid


ROOT = Path(os.environ.get("BROKEN_ARROW_ROOT", Path(__file__).resolve().parents[1] / "outputs"))
OLD_DATA_FILE = ROOT / "broken-arrow-data.json"
DB_FILE = ROOT / "broken-arrow-db.json"
SESSION_DAYS = 30
PBKDF2_ROUNDS = 120_000


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def default_db():
    return {
        "users": [],
        "sessions": {},
        "matches": [],
    }


def read_db():
    if DB_FILE.exists():
        try:
            data = json.loads(DB_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("users"), list) and isinstance(data.get("matches"), list):
                data.setdefault("sessions", {})
                return data
        except Exception:
            pass

    db = default_db()
    if OLD_DATA_FILE.exists():
        try:
            old_matches = json.loads(OLD_DATA_FILE.read_text(encoding="utf-8"))
            if isinstance(old_matches, list):
                for match in old_matches:
                    if isinstance(match, dict):
                        match.setdefault("id", str(uuid.uuid4()))
                        match["userId"] = "legacy-local"
                        db["matches"].append(match)
        except Exception:
            pass
    write_db(db)
    return db


def write_db(db):
    DB_FILE.write_text(json.dumps(db, indent=2), encoding="utf-8")


def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PBKDF2_ROUNDS,
    )
    return base64.b64encode(digest).decode("ascii"), salt


def verify_password(password, salt, password_hash):
    candidate, _ = hash_password(password, salt)
    return secrets.compare_digest(candidate, password_hash)


def sanitize_user(user):
    return {
        "id": user["id"],
        "name": user["name"],
        "public": bool(user.get("public", True)),
        "createdAt": user.get("createdAt"),
        "updatedAt": user.get("updatedAt"),
    }


def find_user_by_name(db, name):
    target = name.strip().lower()
    return next((user for user in db["users"] if user.get("name", "").strip().lower() == target), None)


def find_user_by_id(db, user_id):
    return next((user for user in db["users"] if user.get("id") == user_id), None)


def prune_sessions(db):
    now_ts = time.time()
    sessions = db.get("sessions", {})
    expired = [token for token, session in sessions.items() if session.get("expiresAt", 0) <= now_ts]
    for token in expired:
        sessions.pop(token, None)


def create_session(db, user_id):
    prune_sessions(db)
    token = secrets.token_urlsafe(32)
    db["sessions"][token] = {
        "userId": user_id,
        "expiresAt": time.time() + SESSION_DAYS * 24 * 60 * 60,
        "createdAt": now(),
    }
    return token


def get_session_user(db, token):
    if not token:
        return None
    prune_sessions(db)
    session = db.get("sessions", {}).get(token)
    if not session:
        return None
    return find_user_by_id(db, session.get("userId"))


def public_db(db):
    public_user_ids = {user["id"] for user in db["users"] if user.get("public")}
    return {
        "users": [sanitize_user(user) for user in db["users"] if user.get("public")],
        "matches": [match for match in db["matches"] if match.get("userId") in public_user_ids],
    }


def can_read_user_matches(db, user_id, auth_user):
    target = find_user_by_id(db, user_id)
    if not target:
        return False
    if auth_user and auth_user.get("id") == user_id:
        return True
    return bool(target.get("public"))


class BrokenArrowHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def get_auth_token(self):
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:].strip()
        return ""

    def get_auth_user(self, db):
        return get_session_user(db, self.get_auth_token())

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        db = read_db()

        if path == "/api/db":
            auth_user = self.get_auth_user(db)
            if not auth_user:
                self.send_error(401)
                return
            self.send_json({
                "users": [sanitize_user(auth_user)],
                "matches": [match for match in db["matches"] if match.get("userId") == auth_user["id"]],
            })
            return

        if path == "/api/public":
            self.send_json(public_db(db))
            return

        if path == "/api/users":
            self.send_json(public_db(db)["users"])
            return

        if path == "/api/auth/me":
            auth_user = self.get_auth_user(db)
            if not auth_user:
                self.send_error(401)
                return
            self.send_json(sanitize_user(auth_user))
            return

        if path == "/api/matches":
            user_id = query.get("userId", [None])[0]
            auth_user = self.get_auth_user(db)
            if not user_id:
                if not auth_user:
                    self.send_error(401)
                    return
                user_id = auth_user["id"]
            if not can_read_user_matches(db, user_id, auth_user):
                self.send_error(403)
                return
            self.send_json([match for match in db["matches"] if match.get("userId") == user_id])
            return

        super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        body = self.read_json()
        db = read_db()

        try:
            if path == "/api/auth/register":
                name = str(body.get("username") or body.get("name", "")).strip()[:48]
                password = str(body.get("password", ""))
                if not name:
                    raise ValueError("Username is required")
                if len(password) < 6:
                    raise ValueError("Password must be at least 6 characters")
                if find_user_by_name(db, name):
                    raise ValueError("Username already exists")
                password_hash, salt = hash_password(password)
                user = {
                    "id": str(uuid.uuid4()),
                    "name": name,
                    "passwordHash": password_hash,
                    "passwordSalt": salt,
                    "public": bool(body.get("public", True)),
                    "createdAt": now(),
                    "updatedAt": now(),
                }
                db["users"].append(user)
                token = create_session(db, user["id"])
                write_db(db)
                self.send_json({"token": token, "user": sanitize_user(user)})
                return

            if path == "/api/auth/login":
                name = str(body.get("username") or body.get("name", "")).strip()
                password = str(body.get("password", ""))
                user = find_user_by_name(db, name)
                if not user or not verify_password(password, user.get("passwordSalt", ""), user.get("passwordHash", "")):
                    raise ValueError("Invalid username or password")
                token = create_session(db, user["id"])
                write_db(db)
                self.send_json({"token": token, "user": sanitize_user(user)})
                return

            if path == "/api/auth/logout":
                token = self.get_auth_token()
                if token and token in db.get("sessions", {}):
                    db["sessions"].pop(token, None)
                    write_db(db)
                self.send_json({"ok": True})
                return

            auth_user = self.get_auth_user(db)
            if not auth_user:
                self.send_error(401)
                return

            if path == "/api/users/public":
                public = bool(body.get("public", True))
                auth_user["public"] = public
                auth_user["updatedAt"] = now()
                write_db(db)
                self.send_json(sanitize_user(auth_user))
                return

            if path == "/api/matches":
                user_id = auth_user["id"]
                matches = body if isinstance(body, list) else body.get("matches", [])
                if not isinstance(matches, list):
                    raise ValueError("Expected matches list")
                db["matches"] = [match for match in db["matches"] if match.get("userId") != user_id]
                for match in matches:
                    if isinstance(match, dict):
                        match.setdefault("id", str(uuid.uuid4()))
                        match["userId"] = user_id
                        match["updatedAt"] = match.get("updatedAt") or now()
                        db["matches"].append(match)
                write_db(db)
                self.send_json({"ok": True, "count": len(matches)})
                return

            self.send_error(404)
        except ValueError as exc:
            self.send_json_error(400, str(exc))
        except Exception as exc:
            self.send_json_error(400, str(exc))

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        if not raw:
            return {}
        return json.loads(raw.decode("utf-8"))

    def send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_json_error(self, status, message):
        body = json.dumps({"ok": False, "error": message}).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8787"))
    ROOT.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer((host, port), BrokenArrowHandler)
    print(f"Broken Arrow stats server running on http://{host}:{port}/")
    server.serve_forever()