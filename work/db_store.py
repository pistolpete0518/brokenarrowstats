import copy
import json
import os
import threading
import uuid
from pathlib import Path

_LOCK = threading.Lock()
_STORE = None

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    public BOOLEAN NOT NULL DEFAULT TRUE,
    country TEXT NOT NULL DEFAULT '',
    profile_picture TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at DOUBLE PRECISION NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS matches (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    payload JSONB NOT NULL,
    updated_at TEXT NOT NULL
);
"""


def default_db():
    return {
        "users": [],
        "sessions": {},
        "matches": [],
    }


def normalize_database_url(url):
    url = url.strip()
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    if "neon.tech" in url:
        separator = "&" if "?" in url else "?"
        if "sslmode=" not in url:
            url = f"{url}{separator}sslmode=require"
            separator = "&"
        if "connect_timeout=" not in url:
            url = f"{url}{separator}connect_timeout=10"
    return url


class JsonStore:
    def __init__(self, root):
        self.root = Path(root)
        self.db_file = self.root / "broken-arrow-db.json"
        self.old_data_file = self.root / "broken-arrow-data.json"

    def _load_raw(self):
        self.root.mkdir(parents=True, exist_ok=True)
        candidates = [self.db_file, self.db_file.with_suffix(".json.bak")]
        for path in candidates:
            if not path.exists():
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, dict) and isinstance(data.get("users"), list) and isinstance(data.get("matches"), list):
                    data.setdefault("sessions", {})
                    return data
            except Exception:
                continue

        db = default_db()
        if self.old_data_file.exists():
            try:
                old_matches = json.loads(self.old_data_file.read_text(encoding="utf-8"))
                if isinstance(old_matches, list):
                    for match in old_matches:
                        if isinstance(match, dict):
                            match.setdefault("id", str(uuid.uuid4()))
                            match["userId"] = "legacy-local"
                            db["matches"].append(match)
            except Exception:
                pass
        return db

    def _save_raw(self, db):
        self.root.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(db, indent=2)
        temp_file = self.db_file.with_suffix(".json.tmp")
        temp_file.write_text(payload, encoding="utf-8")
        if self.db_file.exists():
            backup_file = self.db_file.with_suffix(".json.bak")
            backup_file.write_text(self.db_file.read_text(encoding="utf-8"), encoding="utf-8")
        os.replace(temp_file, self.db_file)

    def read(self):
        return self._load_raw()

    def write(self, db):
        self._save_raw(db)

    def backend_name(self):
        return "json"


class PostgresStore:
    def __init__(self, database_url):
        import psycopg2
        from psycopg2.extras import Json

        self.psycopg2 = psycopg2
        self.Json = Json
        self.database_url = normalize_database_url(database_url)
        self._ensure_schema()

    def _connect(self):
        return self.psycopg2.connect(self.database_url)

    def _ensure_schema(self):
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(SCHEMA_SQL)
                cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS country TEXT NOT NULL DEFAULT ''")
                cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS profile_picture TEXT NOT NULL DEFAULT ''")
            conn.commit()

    def _row_to_user(self, row):
        return {
            "id": row[0],
            "name": row[1],
            "passwordHash": row[2],
            "passwordSalt": row[3],
            "role": row[4],
            "public": bool(row[5]),
            "country": row[6] or "",
            "profilePicture": row[7] or "",
            "createdAt": row[8],
            "updatedAt": row[9],
        }

    def read(self):
        db = default_db()
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, name, password_hash, password_salt, role, public, country, profile_picture, created_at, updated_at
                    FROM users ORDER BY created_at
                    """
                )
                db["users"] = [self._row_to_user(row) for row in cur.fetchall()]

                cur.execute("SELECT token, user_id, expires_at, created_at FROM sessions")
                for token, user_id, expires_at, created_at in cur.fetchall():
                    db["sessions"][token] = {
                        "userId": user_id,
                        "expiresAt": float(expires_at),
                        "createdAt": created_at,
                    }

                cur.execute("SELECT payload FROM matches ORDER BY updated_at")
                for (payload,) in cur.fetchall():
                    if isinstance(payload, dict):
                        db["matches"].append(payload)
        return db

    def write(self, db):
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM users")
                existing_users = {row[0] for row in cur.fetchall()}
                incoming_users = {user["id"] for user in db.get("users", []) if user.get("id")}

                for user in db.get("users", []):
                    cur.execute(
                        """
                        INSERT INTO users (id, name, password_hash, password_salt, role, public, country, profile_picture, created_at, updated_at)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (id) DO UPDATE SET
                            name = EXCLUDED.name,
                            password_hash = EXCLUDED.password_hash,
                            password_salt = EXCLUDED.password_salt,
                            role = EXCLUDED.role,
                            public = EXCLUDED.public,
                            country = EXCLUDED.country,
                            profile_picture = EXCLUDED.profile_picture,
                            updated_at = EXCLUDED.updated_at
                        """,
                        (
                            user["id"],
                            user["name"],
                            user.get("passwordHash", ""),
                            user.get("passwordSalt", ""),
                            user.get("role", "user"),
                            bool(user.get("public", True)),
                            user.get("country", "") or "",
                            user.get("profilePicture", "") or "",
                            user.get("createdAt"),
                            user.get("updatedAt"),
                        ),
                    )

                for removed_id in existing_users - incoming_users:
                    cur.execute("DELETE FROM users WHERE id = %s", (removed_id,))

                cur.execute("DELETE FROM sessions")
                for token, session in db.get("sessions", {}).items():
                    cur.execute(
                        """
                        INSERT INTO sessions (token, user_id, expires_at, created_at)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (
                            token,
                            session.get("userId"),
                            float(session.get("expiresAt", 0)),
                            session.get("createdAt"),
                        ),
                    )

                cur.execute("DELETE FROM matches")
                for match in db.get("matches", []):
                    if not isinstance(match, dict):
                        continue
                    match_id = match.get("id") or str(uuid.uuid4())
                    user_id = match.get("userId")
                    if not user_id:
                        continue
                    cur.execute(
                        """
                        INSERT INTO matches (id, user_id, payload, updated_at)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (
                            match_id,
                            user_id,
                            self.Json(match),
                            match.get("updatedAt") or "",
                        ),
                    )
            conn.commit()

    def backend_name(self):
        return "postgres"


def get_store():
    global _STORE
    if _STORE is None:
        database_url = os.environ.get("DATABASE_URL", "").strip()
        if database_url:
            _STORE = PostgresStore(database_url)
        else:
            root = os.environ.get(
                "BROKEN_ARROW_ROOT",
                str(Path(__file__).resolve().parents[1] / "outputs"),
            )
            _STORE = JsonStore(root)
    return _STORE


def storage_backend():
    return get_store().backend_name()


def test_database_connection():
    database_url = os.environ.get("DATABASE_URL", "").strip()
    if not database_url:
        return {"ok": False, "storage": "json", "error": "DATABASE_URL is not set"}
    try:
        store = PostgresStore(database_url)
        db = store.read()
        return {
            "ok": True,
            "storage": "postgres",
            "users": len(db.get("users", [])),
            "matches": len(db.get("matches", [])),
        }
    except Exception as exc:
        return {"ok": False, "storage": "postgres", "error": str(exc)}


def read_db_copy():
    with _LOCK:
        return copy.deepcopy(get_store().read())


def update_db(mutator):
    with _LOCK:
        store = get_store()
        db = store.read()
        result = mutator(db)
        store.write(db)
        return result