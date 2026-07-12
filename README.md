# Credential Vault

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg) ![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg) ![Encryption](https://img.shields.io/badge/Encryption-AES--256-red.svg)

Secure secret management system with AES-256-GCM encryption.

## Features

- AES-256-GCM encryption at rest
- PBKDF2 key derivation (600K iterations)
- FastAPI REST API with CRUD
- Secret versioning and history
- Access logging and audit trail
- Expiry management

## Quick Start

```bash
pip install -r requirements.txt
python -m src.main init
python -m src.main serve
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /secrets | Create secret |
| GET | /secrets/{name} | Get secret |
| DELETE | /secrets/{name} | Delete secret |
| GET | /secrets | List secrets |

## License

MIT
