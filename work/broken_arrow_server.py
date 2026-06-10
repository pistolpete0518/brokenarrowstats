from db_store import get_store, storage_backend, test_database_connection, update_db as store_update_db
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
import base64
import copy
import hashlib
import json
import os
import secrets
import threading
import time
import uuid


ROOT = Path(os.environ.get("BROKEN_ARROW_ROOT", Path(__file__).resolve().parents[1] / "outputs"))
SESSION_DAYS = 30
PBKDF2_ROUNDS = 120_000
_DB_LOCK = threading.Lock()


def public_site_url():
    url = os.environ.get("PUBLIC_SITE_URL", "").strip().rstrip("/")
    if not url:
        return None
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def read_db():
    with _DB_LOCK:
        store = get_store()
        db = store.read()
        if ensure_admin_user(db):
            store.write(db)
        return copy.deepcopy(db)


def update_db(mutator):
    def mutate(db):
        ensure_admin_user(db)
        return mutator(db)

    return store_update_db(mutate)


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


def user_role(user):
    return user.get("role", "user")


def is_admin(user):
    return user_role(user) == "admin"


def sanitize_user(user):
    return {
        "id": user["id"],
        "name": user["name"],
        "role": user_role(user),
        "public": bool(user.get("public", True)),
        "createdAt": user.get("createdAt"),
        "updatedAt": user.get("updatedAt"),
    }


def admin_user_row(user, db):
    return {
        **sanitize_user(user),
        "matchCount": sum(1 for match in db["matches"] if match.get("userId") == user["id"]),
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


def remove_user_sessions(db, user_id):
    sessions = db.get("sessions", {})
    for token, session in list(sessions.items()):
        if session.get("userId") == user_id:
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


def ensure_admin_user(db):
    admin_name = os.environ.get("ADMIN_USERNAME", "").strip()
    if not admin_name:
        return False

    admin_password = os.environ.get("ADMIN_PASSWORD", "").strip()
    user = find_user_by_name(db, admin_name)
    changed = False

    if user:
        if user_role(user) != "admin":
            user["role"] = "admin"
            changed = True
        if admin_password and len(admin_password) >= 6:
            password_hash, salt = hash_password(admin_password)
            user["passwordHash"] = password_hash
            user["passwordSalt"] = salt
            user["updatedAt"] = now()
            changed = True
    else:
        password = admin_password if admin_password and len(admin_password) >= 6 else secrets.token_urlsafe(12)
        password_hash, salt = hash_password(password)
        db["users"].append({
            "id": str(uuid.uuid4()),
            "name": admin_name,
            "passwordHash": password_hash,
            "passwordSalt": salt,
            "public": False,
            "role": "admin",
            "createdAt": now(),
            "updatedAt": now(),
        })
        changed = True

    return changed


def build_user(body, existing=None):
    name = str(body.get("username") or body.get("name", "")).strip()[:48]
    password = str(body.get("password", ""))
    if not name:
        raise ValueError("Username is required")
    if existing is None and len(password) < 6:
        raise ValueError("Password must be at least 6 characters")

    user = existing or {
        "id": str(uuid.uuid4()),
        "createdAt": now(),
    }
    user["name"] = name
    if "public" in body:
        user["public"] = bool(body.get("public"))
    elif existing is None:
        user["public"] = bool(body.get("public", True))
    if "role" in body:
        user["role"] = "admin" if body.get("role") == "admin" else "user"
    elif existing is None:
        user["role"] = "user"
    user["updatedAt"] = now()

    if password:
        if len(password) < 6:
            raise ValueError("Password must be at least 6 characters")
        password_hash, salt = hash_password(password)
        user["passwordHash"] = password_hash
        user["passwordSalt"] = salt
    elif existing is None:
        raise ValueError("Password is required")

    return user


def public_db(db):
    public_user_ids = {user["id"] for user in db["users"] if user.get("public")}
    return {
        "users": [sanitize_user(user) for user in db["users"] if user.get("public")],
        "matches": [match for match in db["matches"] if match.get("userId") in public_user_ids],
    }


def apply_user_matches(db, user_id, matches, replace=False):
    if not isinstance(matches, list):
        raise ValueError("Expected matches list")

    if replace:
        db["matches"] = [match for match in db["matches"] if match.get("userId") != user_id]
        if not matches:
            return 0

    existing = {
        match["id"]: match
        for match in db["matches"]
        if match.get("userId") == user_id and match.get("id")
    }
    applied = 0
    for match in matches:
        if not isinstance(match, dict):
            continue
        match = dict(match)
        match.setdefault("id", str(uuid.uuid4()))
        match["userId"] = user_id
        match["updatedAt"] = match.get("updatedAt") or now()
        match_id = match["id"]
        current = existing.get(match_id)
        if not current or str(match.get("updatedAt", "")) >= str(current.get("updatedAt", "")):
            existing[match_id] = match
            applied += 1

    db["matches"] = [
        match for match in db["matches"]
        if match.get("userId") != user_id
    ] + list(existing.values())
    return applied


def parse_matches_payload(body):
    if isinstance(body, list):
        return body, False
    if isinstance(body, dict):
        if body.get("replace"):
            matches = body.get("matches", [])
            return matches if isinstance(matches, list) else [], True
        matches = body.get("matches", [])
        return matches if isinstance(matches, list) else [], False
    return [], False


def can_read_user_matches(db, user_id, auth_user):
    target = find_user_by_id(db, user_id)
    if not target:
        return False
    if auth_user and auth_user.get("id") == user_id:
        return True
    if auth_user and is_admin(auth_user):
        return True
    return bool(target.get("public"))


def parse_admin_user_path(path):
    prefix = "/api/admin/users/"
    if not path.startswith(prefix):
        return None, None
    remainder = path[len(prefix):]
    parts = remainder.split("/")
    user_id = parts[0] if parts and parts[0] else None
    action = parts[1] if len(parts) > 1 else None
    return user_id, action


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

    def require_admin(self, db):
        auth_user = self.get_auth_user(db)
        if not auth_user or not is_admin(auth_user):
            self.send_error(403)
            return None
        return auth_user

    def maybe_redirect_public_site(self, path):
        canonical = public_site_url()
        if not canonical:
            return False
        host = self.headers.get("Host", "").split(":")[0].lower()
        canonical_host = urlparse(canonical).netloc.lower()
        if not host or not canonical_host or host == canonical_host:
            return False
        if not host.endswith(".onrender.com"):
            return False
        target = f"{canonical}{path}"
        self.send_response(301)
        self.send_header("Location", target)
        self.end_headers()
        return True

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        if not path.startswith("/api/") and self.maybe_redirect_public_site(parsed.path + (f"?{parsed.query}" if parsed.query else "")):
            return
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

        if path == "/api/config":
            canonical = public_site_url()
            self.send_json({
                "publicSiteUrl": canonical or "",
                "defaultUrl": f"https://{self.headers.get('Host', 'brokenarrowstats.onrender.com')}",
            })
            return

        if path == "/api/health":
            status = test_database_connection() if os.environ.get("DATABASE_URL", "").strip() else {
                "ok": True,
                "storage": storage_backend(),
                "users": len(db["users"]),
                "matches": len(db["matches"]),
            }
            self.send_json({
                **status,
                "users": status.get("users", len(db["users"])),
                "matches": status.get("matches", len(db["matches"])),
                "publicSiteUrl": public_site_url() or "",
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

        if path == "/api/admin/overview":
            if not self.require_admin(db):
                return
            self.send_json({
                "users": len(db["users"]),
                "admins": sum(1 for user in db["users"] if is_admin(user)),
                "matches": len(db["matches"]),
                "publicUsers": sum(1 for user in db["users"] if user.get("public")),
            })
            return

        if path == "/api/admin/users":
            if not self.require_admin(db):
                return
            self.send_json([admin_user_row(user, db) for user in db["users"]])
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
        body = self.read_json()
        token = self.get_auth_token()

        try:
            if path == "/api/auth/register":
                def mutate(db):
                    name = str(body.get("username") or body.get("name", "")).strip()[:48]
                    password = str(body.get("password", ""))
                    if not name:
                        raise ValueError("Username is required")
                    if len(password) < 6:
                        raise ValueError("Password must be at least 6 characters")
                    if find_user_by_name(db, name):
                        raise ValueError("Username already exists")
                    user = build_user(body)
                    user["role"] = "user"
                    db["users"].append(user)
                    session_token = create_session(db, user["id"])
                    return {"token": session_token, "user": sanitize_user(user)}

                self.send_json(update_db(mutate))
                return

            if path == "/api/auth/login":
                def mutate(db):
                    name = str(body.get("username") or body.get("name", "")).strip()
                    password = str(body.get("password", ""))
                    user = find_user_by_name(db, name)
                    if not user or not verify_password(password, user.get("passwordSalt", ""), user.get("passwordHash", "")):
                        raise ValueError("Invalid username or password")
                    session_token = create_session(db, user["id"])
                    return {"token": session_token, "user": sanitize_user(user)}

                self.send_json(update_db(mutate))
                return

            if path == "/api/auth/logout":
                def mutate(db):
                    if token and token in db.get("sessions", {}):
                        db["sessions"].pop(token, None)
                    return {"ok": True}

                self.send_json(update_db(mutate))
                return

            if path == "/api/users/public":
                def mutate(db):
                    auth_user = get_session_user(db, token)
                    if not auth_user:
                        raise ValueError("Unauthorized")
                    auth_user["public"] = bool(body.get("public", True))
                    auth_user["updatedAt"] = now()
                    return sanitize_user(auth_user)

                self.send_json(update_db(mutate))
                return

            if path == "/api/admin/users":
                def mutate(db):
                    auth_user = get_session_user(db, token)
                    if not auth_user or not is_admin(auth_user):
                        raise ValueError("Forbidden")
                    if find_user_by_name(db, str(body.get("username") or body.get("name", "")).strip()):
                        raise ValueError("Username already exists")
                    user = build_user(body)
                    db["users"].append(user)
                    return admin_user_row(user, db)

                self.send_json(update_db(mutate))
                return

            if path == "/api/matches":
                def mutate(db):
                    auth_user = get_session_user(db, token)
                    if not auth_user:
                        raise ValueError("Unauthorized")
                    user_id = auth_user["id"]
                    matches, replace = parse_matches_payload(body)
                    count = apply_user_matches(db, user_id, matches, replace=replace)
                    return {"ok": True, "count": count}

                self.send_json(update_db(mutate))
                return

            self.send_error(404)
        except ValueError as exc:
            message = str(exc)
            if message == "Unauthorized":
                self.send_error(401)
                return
            if message == "Forbidden":
                self.send_error(403)
                return
            self.send_json_error(400, message)
        except Exception as exc:
            self.send_json_error(400, str(exc))

    def do_PATCH(self):
        parsed = urlparse(self.path)
        path = parsed.path
        body = self.read_json()
        token = self.get_auth_token()

        try:
            user_id, action = parse_admin_user_path(path)
            if not user_id or action:
                self.send_error(404)
                return

            def mutate(db):
                auth_user = get_session_user(db, token)
                if not auth_user or not is_admin(auth_user):
                    raise ValueError("Forbidden")
                target = find_user_by_id(db, user_id)
                if not target:
                    raise ValueError("User not found")
                if is_admin(target) and target["id"] != auth_user["id"] and body.get("role") == "user":
                    admins = [user for user in db["users"] if is_admin(user)]
                    if len(admins) <= 1:
                        raise ValueError("Cannot remove the last admin")
                new_name = str(body.get("username") or body.get("name", target["name"])).strip()[:48]
                existing = find_user_by_name(db, new_name)
                if existing and existing["id"] != target["id"]:
                    raise ValueError("Username already exists")
                updated = build_user({**body, "username": new_name, "name": new_name}, existing=target)
                return admin_user_row(updated, db)

            self.send_json(update_db(mutate))
        except ValueError as exc:
            message = str(exc)
            if message == "Forbidden":
                self.send_error(403)
                return
            self.send_json_error(400, message)

    def do_DELETE(self):
        parsed = urlparse(self.path)
        path = parsed.path
        token = self.get_auth_token()

        try:
            if path.startswith("/api/admin/matches/"):
                match_id = path.split("/api/admin/matches/", 1)[1]

                def mutate(db):
                    auth_user = get_session_user(db, token)
                    if not auth_user or not is_admin(auth_user):
                        raise ValueError("Forbidden")
                    before = len(db["matches"])
                    db["matches"] = [match for match in db["matches"] if match.get("id") != match_id]
                    if len(db["matches"]) == before:
                        raise ValueError("Match not found")
                    return {"ok": True}

                self.send_json(update_db(mutate))
                return

            user_id, action = parse_admin_user_path(path)
            if not user_id:
                self.send_error(404)
                return

            def mutate(db):
                auth_user = get_session_user(db, token)
                if not auth_user or not is_admin(auth_user):
                    raise ValueError("Forbidden")
                target = find_user_by_id(db, user_id)
                if not target:
                    raise ValueError("User not found")

                if action == "matches":
                    removed = sum(1 for match in db["matches"] if match.get("userId") == user_id)
                    db["matches"] = [match for match in db["matches"] if match.get("userId") != user_id]
                    return {"ok": True, "removed": removed}

                if action:
                    raise ValueError("Not found")

                if is_admin(target):
                    admins = [user for user in db["users"] if is_admin(user)]
                    if len(admins) <= 1:
                        raise ValueError("Cannot delete the last admin")

                db["users"] = [user for user in db["users"] if user.get("id") != user_id]
                db["matches"] = [match for match in db["matches"] if match.get("userId") != user_id]
                remove_user_sessions(db, user_id)
                return {"ok": True}

            self.send_json(update_db(mutate))
        except ValueError as exc:
            message = str(exc)
            if message == "Forbidden":
                self.send_error(403)
                return
            if message == "Not found":
                self.send_error(404)
                return
            self.send_json_error(400, message)

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
    database_url = os.environ.get("DATABASE_URL", "").strip()
    if database_url:
        status = test_database_connection()
        if status.get("ok"):
            print(
                "Neon/Postgres connected. "
                f"users={status.get('users', 0)} matches={status.get('matches', 0)}"
            )
        else:
            print(f"ERROR: DATABASE_URL is set but connection failed: {status.get('error')}")
    else:
        print("WARNING: DATABASE_URL is not set. Stats and logins are lost on Render restarts.")
    print(f"BrokenArrowStats server running on http://{host}:{port}/ (storage={storage_backend()})")
    server.serve_forever()