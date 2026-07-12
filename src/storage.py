import sqlite3
from datetime import datetime
from ..models import Secret, SecretStatus, AccessLog

class VaultStore:
    def __init__(self, db_path='vault.db'):
        self.db_path = db_path
        self._init_db()
    def _init_db(self):
        with sqlite3.connect(self.db_path) as c:
            c.execute('CREATE TABLE IF NOT EXISTS secrets (name TEXT PRIMARY KEY, encrypted_value BLOB, nonce BLOB, salt BLOB, version INTEGER DEFAULT 1, status TEXT DEFAULT "active", created_at TEXT, updated_at TEXT, expires_at TEXT, created_by TEXT DEFAULT "system", description TEXT DEFAULT "")')
            c.execute('CREATE TABLE IF NOT EXISTS secret_versions (id INTEGER PRIMARY KEY AUTOINCREMENT, secret_name TEXT, version INTEGER, encrypted_value BLOB, nonce BLOB, created_at TEXT, created_by TEXT DEFAULT "system")')
            c.execute('CREATE TABLE IF NOT EXISTS access_log (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT, secret_name TEXT, user_name TEXT, timestamp TEXT, success INTEGER, ip_address TEXT DEFAULT "")')
    def store_secret(self, secret):
        with sqlite3.connect(self.db_path) as c:
            c.execute('INSERT OR REPLACE INTO secrets (name,encrypted_value,nonce,salt,version,status,created_at,updated_at,expires_at,created_by,description) VALUES (?,?,?,?,?,?,?,?,?,?,?)', (secret.name, secret.encrypted_value, secret.nonce, secret.salt, secret.version, secret.status.value, secret.created_at, secret.updated_at, secret.expires_at, secret.created_by, secret.description))
            c.execute('INSERT INTO secret_versions (secret_name,version,encrypted_value,nonce,created_at,created_by) VALUES (?,?,?,?,?,?)', (secret.name, secret.version, secret.encrypted_value, secret.nonce, secret.created_at, secret.created_by))
    def get_secret(self, name):
        with sqlite3.connect(self.db_path) as c:
            c.row_factory = sqlite3.Row
            row = c.execute("SELECT * FROM secrets WHERE name=? AND status='active'", (name,)).fetchone()
            if row:
                return Secret(name=row['name'], encrypted_value=row['encrypted_value'], nonce=row['nonce'], salt=row['salt'], version=row['version'], status=SecretStatus(row['status']), created_at=row['created_at'], updated_at=row['updated_at'], expires_at=row['expires_at'], created_by=row['created_by'], description=row['description'])
            return None
    def list_secrets(self):
        with sqlite3.connect(self.db_path) as c:
            c.row_factory = sqlite3.Row
            return [dict(r) for r in c.execute("SELECT name,version,status,created_at,description FROM secrets WHERE status='active'").fetchall()]
    def delete_secret(self, name):
        with sqlite3.connect(self.db_path) as c:
            r = c.execute('UPDATE secrets SET status="revoked",updated_at=? WHERE name=?', (datetime.now().isoformat(), name))
            return r.rowcount > 0
    def get_versions(self, name):
        with sqlite3.connect(self.db_path) as c:
            c.row_factory = sqlite3.Row
            return [dict(r) for r in c.execute('SELECT secret_name,version,created_at,created_by FROM secret_versions WHERE secret_name=? ORDER BY version DESC', (name,)).fetchall()]
    def log_access(self, log):
        with sqlite3.connect(self.db_path) as c:
            c.execute('INSERT INTO access_log (action,secret_name,user_name,timestamp,success,ip_address) VALUES (?,?,?,?,?,?)', (log.action, log.secret_name, log.user, log.timestamp, int(log.success), ''))
