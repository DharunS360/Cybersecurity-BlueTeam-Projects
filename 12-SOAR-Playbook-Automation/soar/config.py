"""Configuration. Secrets come only from environment variables or a local .env file."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def load_dotenv(path: Path) -> None:
    """Minimal .env loader. Never overrides variables already set in the environment."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip().strip('"').strip("'")
        if value:
            os.environ.setdefault(key.strip(), value)


@dataclass(frozen=True)
class Settings:
    vt_key: str = ""
    abuseipdb_key: str = ""
    otx_key: str = ""
    abusech_key: str = ""
    data_dir: Path = PROJECT_ROOT / "data"
    http_timeout: float = 20.0
    max_iocs: int = 50
    ttl_hash_hours: float = 24.0
    ttl_default_hours: float = 6.0
    max_workers: int = 8

    @property
    def db_path(self) -> Path:
        return self.data_dir / "soar.db"

    @property
    def feeds_dir(self) -> Path:
        return self.data_dir / "feeds"

    @property
    def allowlist_path(self) -> Path:
        return self.data_dir / "allowlist.txt"

    @classmethod
    def load(cls, dotenv: bool = True) -> "Settings":
        if dotenv:
            load_dotenv(PROJECT_ROOT / ".env")
        env = os.environ
        data_dir = Path(env.get("SOAR_DATA_DIR") or (PROJECT_ROOT / "data"))
        return cls(
            vt_key=env.get("VT_API_KEY", "").strip(),
            abuseipdb_key=env.get("ABUSEIPDB_API_KEY", "").strip(),
            otx_key=env.get("OTX_API_KEY", "").strip(),
            abusech_key=env.get("ABUSECH_API_KEY", "").strip(),
            data_dir=data_dir,
            max_iocs=int(env.get("SOAR_MAX_IOCS", "50")),
        )