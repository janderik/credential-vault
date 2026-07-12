import os
import click
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from .crypto.engine import VaultCrypto
from .storage import VaultStore
from .models import Secret, SecretStatus, AccessLog

app = FastAPI(title="Credential Vault", version="1.0.0")
store = VaultStore()
crypto = None

class SecretCreate(BaseModel):
    name: str
    value: str
    description: str = ""

def get_crypto():
    global crypto
    if crypto is None:
        pw = os.environ.get("VAULT_MASTER_PASSWORD", "default-dev-password")
        crypto = VaultCrypto(master_password=pw)
    return crypto

@app.on_event("startup")
def startup():
    get_crypto()

@app.get("/")
def root():
    return {"service": "Credential Vault", "version": "1.0.0"}

@app.post("/secrets")
def create_secret(req: SecretCreate):
    c = get_crypto()
    enc, nonce, salt = c.encrypt(req.value)
    secret = Secret(name=req.name, encrypted_value=enc, nonce=nonce, salt=salt, description=req.description)
    store.store_secret(secret)
    store.log_access(AccessLog(action="create", secret_name=req.name, user="api"))
    return {"status": "created", "name": req.name, "version": secret.version}

@app.get("/secrets/{name}")
def get_secret(name: str):
    c = get_crypto()
    secret = store.get_secret(name)
    if not secret:
        raise HTTPException(status_code=404, detail="Not found")
    value = c.decrypt(secret.encrypted_value, secret.nonce)
    store.log_access(AccessLog(action="read", secret_name=name, user="api"))
    return {"name": secret.name, "value": value, "version": secret.version}

@app.get("/secrets")
def list_secrets():
    return {"secrets": store.list_secrets()}

@app.delete("/secrets/{name}")
def delete_secret(name: str):
    if store.delete_secret(name):
        store.log_access(AccessLog(action="delete", secret_name=name, user="api"))
        return {"status": "deleted", "name": name}
    raise HTTPException(status_code=404, detail="Not found")

@app.get("/secrets/{name}/history")
def get_history(name: str):
    return {"versions": store.get_versions(name)}

@app.get("/health")
def health():
    return {"status": "healthy"}

@click.group()
def cli():
    pass

@cli.command()
def init():
    get_crypto()
    store._init_db()
    click.echo("[+] Vault initialized")

@cli.command()
@click.option("--port", default=8000)
def serve(port):
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=port)

if __name__ == "__main__":
    cli()
