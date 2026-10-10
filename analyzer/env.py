import os
from pathlib import Path

ROOT_ENV = Path(__file__).resolve().parent.parent / ".env"


def load_root_env(path: Path = ROOT_ENV) -> None:
    """Read KEY=VALUE lines from the repo-root .env. Real environment variables win."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return  # no .env is fine: every key is optional
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("\"'"))
