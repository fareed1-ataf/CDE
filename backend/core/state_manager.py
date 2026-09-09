# core/state_manager.py  ─  Cyber Data Engine v1.0.0
# =============================================================================
# PERSISTENCE & CACHING
# Handles saving/loading providers, caching hashed file contents to avoid
# re-processing, and directly appending outputs to disk to prevent data loss.
# =============================================================================
"""
state_manager.py  —  Persistence & Caching Layer

Responsibilities:
  1. Provider persistence  — serialise/deserialise ProviderConfig list to/from
     config/providers.json. API keys are stored as ${ENV_VAR} placeholders and
     resolved at load time via os.path.expandvars().
  2. Content-hash cache   — MD5-based deduplication prevents the same file from
     being processed twice. Cache is stored in config/cache.json.
  3. Output appending     — atomically appends generated JSONL records to both a
     per-file output file and a global master file inside output/.

Known Limitations:
  - append_to_output file writes are not lock-protected under high concurrency.
  - save_providers() writes the resolved plaintext API key, not the ${VAR} token.

Fixed in TASK-3.1:
  - Cache is now backed by SQLite with threading.Lock — race condition eliminated.
"""

import json
import hashlib
import os
import sqlite3
import threading
from pathlib import Path

from .providers import ProviderConfig, ProviderType

CONFIG_DIR = Path("config")
OUTPUT_DIR = Path("output")

PROVIDERS_FILE = CONFIG_DIR / "providers.json"
CACHE_DB       = CONFIG_DIR / "cache.db"

# Ensure directories exist
CONFIG_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# Providers Persistence
# ─────────────────────────────────────────────────────────────────────────────

# SERIALISE — write the full provider list to config/providers.json.
# Args:    providers: list[ProviderConfig] — all providers (enabled and disabled).
# Returns: None
# Side effects: overwrites config/providers.json entirely.
# WARNING: writes p.api_key as-is; if load_providers() already resolved
#          ${ENV_VAR} to a plaintext key, that plaintext key is written back.
def save_providers(providers: list[ProviderConfig]) -> None:
    data = []
    for p in providers:
        data.append({
            "name":               p.name,
            "provider_type":      p.provider_type.value,
            "endpoint":           p.endpoint,
            "model":              p.model,
            "api_key":            p.api_key,
            "temperature":        p.temperature,
            "max_tokens":         p.max_tokens,
            "timeout":            p.timeout,
            "max_retries":        getattr(p, "max_retries", 3),
            "enabled":            p.enabled,
            "preferred_schemas":  getattr(p, "preferred_schemas", []),
        })
    with open(PROVIDERS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

# LOAD — read and deserialise providers from config/providers.json.
# Args:    None
# Returns: list[ProviderConfig] — empty list if file missing or unparseable.
# Side effects: calls os.path.expandvars() on each api_key field, resolving
#               ${VARNAME} syntax to the actual environment variable value.
def load_providers() -> list[ProviderConfig]:
    if not PROVIDERS_FILE.exists():
        return []
    try:
        with open(PROVIDERS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        loaded = []
        for d in data:
            try:
                loaded.append(ProviderConfig(
                    name=              d.get("name", "unnamed"),
                    provider_type=     ProviderType(d.get("provider_type", "ollama")),
                    endpoint=          d.get("endpoint", ""),
                    model=             d.get("model", ""),
                    api_key=           os.path.expandvars(d.get("api_key", "")),
                    temperature=       d.get("temperature", 0.15),
                    max_tokens=        d.get("max_tokens", 8000),
                    timeout=           d.get("timeout", 180),
                    max_retries=       d.get("max_retries", 3),
                    enabled=           d.get("enabled", True),
                    preferred_schemas= d.get("preferred_schemas", []),
                ))
            except Exception:
                pass
        return loaded
    except Exception:
        return []

# ─────────────────────────────────────────────────────────────────────────────
# Smart Cache (Deduplication) — TASK-3.1: SQLite + threading.Lock
# ─────────────────────────────────────────────────────────────────────────────

# HASH — produce an MD5 digest of the input text for cache keying.
# Args:    text: str — raw file content.
# Returns: str — 32-char hexadecimal MD5 digest.
# Note: MD5 is used for speed and deduplication, not cryptographic security.
def _get_hash(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()

# Module-level lock — shared across all threads in this process.
# Prevents concurrent workers from racing on SQLite writes.
_CACHE_LOCK = threading.Lock()


def _init_cache_db() -> None:
    """Create the chunk_cache table if it does not exist."""
    conn = sqlite3.connect(str(CACHE_DB), check_same_thread=False)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS chunk_cache "
        "(hash TEXT PRIMARY KEY, ts INTEGER DEFAULT (strftime('%s','now')))"
    )
    conn.commit()
    conn.close()


# Initialise DB at import time — idempotent, safe to call repeatedly.
_init_cache_db()


# CHECK — determine if file content has already been processed.
# Args:    text: str — raw file content.
# Returns: bool — True if the content hash exists in cache.db.
# Thread-safe: protected by _CACHE_LOCK.
def is_cached(text: str) -> bool:
    with _CACHE_LOCK:
        conn = sqlite3.connect(str(CACHE_DB), check_same_thread=False)
        row = conn.execute(
            "SELECT 1 FROM chunk_cache WHERE hash=?", (_get_hash(text),)
        ).fetchone()
        conn.close()
        return row is not None


# REGISTER — mark file content as processed in cache.db.
# Args:    text: str — raw file content whose hash should be cached.
# Returns: None
# Thread-safe: INSERT OR IGNORE ensures no duplicates even on concurrent calls.
def add_to_cache(text: str) -> None:
    with _CACHE_LOCK:
        conn = sqlite3.connect(str(CACHE_DB), check_same_thread=False)
        conn.execute(
            "INSERT OR IGNORE INTO chunk_cache (hash) VALUES (?)",
            (_get_hash(text),)
        )
        conn.commit()
        conn.close()

# ─────────────────────────────────────────────────────────────────────────────
# Auto-Save Outputs
# ─────────────────────────────────────────────────────────────────────────────

# APPEND — persist generated JSONL records to both a master and per-file output.
# Args:    source_filename: str  — original uploaded filename; used to derive
#                                   the per-file output path. Must not contain
#                                   path separators (see Phase 2 flag M5).
#          records: list[str]    — JSONL lines to append (one record per line).
#          is_rich: bool         — if True, writes to *_rich.jsonl files;
#                                   otherwise writes to standard Alpaca files.
# Returns: None
# Side effects: opens and appends to two files on disk per call.
# WARNING: not lock-protected; concurrent callers can interleave writes.
def append_to_output(source_filename: str, records: list[str], is_rich: bool = False) -> None:
    """Appends JSONL lines to both a master file and a per-file jsonl."""
    if not records:
        return
        
    master_name = "all_rich_records.jsonl" if is_rich else "all_records.jsonl"
    per_file_name = f"{source_filename}_rich.jsonl" if is_rich else f"{source_filename}.jsonl"
    
    master_path = OUTPUT_DIR / master_name
    per_file_path = OUTPUT_DIR / per_file_name
    
    # Write to master file
    with open(master_path, "a", encoding="utf-8") as f_master:
        for record in records:
            line = record.strip()
            if line:
                f_master.write(line + "\n")
                
    # Write to per-file
    with open(per_file_path, "a", encoding="utf-8") as f_per:
        for record in records:
            line = record.strip()
            if line:
                f_per.write(line + "\n")
