from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class DomainLockoutPolicy:
    """Domain password lockout policy from LDAP."""

    lockout_threshold: int = 0
    lockout_duration_seconds: int = 0
    lockout_observation_window_seconds: int = 0
    source_host: str = ""

    @property
    def lockout_enabled(self) -> bool:
        return self.lockout_threshold > 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "lockout_threshold": self.lockout_threshold,
            "lockout_duration_seconds": self.lockout_duration_seconds,
            "lockout_observation_window_seconds": self.lockout_observation_window_seconds,
            "source_host": self.source_host,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DomainLockoutPolicy:
        return cls(
            lockout_threshold=int(data.get("lockout_threshold", 0)),
            lockout_duration_seconds=int(data.get("lockout_duration_seconds", 0)),
            lockout_observation_window_seconds=int(
                data.get("lockout_observation_window_seconds", 0)
            ),
            source_host=str(data.get("source_host", "")),
        )


@dataclass
class SprayAttempt:
    password: str
    users_tested: int
    hits: list[str] = field(default_factory=list)
    method: str = "ldap"
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "password": self.password,
            "users_tested": self.users_tested,
            "hits": list(self.hits),
            "method": self.method,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SprayAttempt:
        return cls(
            password=str(data.get("password", "")),
            users_tested=int(data.get("users_tested", 0)),
            hits=list(data.get("hits") or []),
            method=str(data.get("method", "ldap")),
            timestamp=str(data.get("timestamp", datetime.now(UTC).isoformat())),
        )
