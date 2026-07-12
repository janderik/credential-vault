from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from enum import Enum

class SecretStatus(Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"

@dataclass
class Secret:
    name: str
    encrypted_value: bytes
    nonce: bytes
    salt: bytes
    version: int = 1
    status: SecretStatus = SecretStatus.ACTIVE
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    expires_at: Optional[str] = None
    created_by: str = "system"
    description: str = ""

@dataclass
class AccessLog:
    action: str
    secret_name: str
    user: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    success: bool = True
