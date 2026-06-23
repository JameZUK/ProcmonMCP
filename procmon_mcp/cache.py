"""On-disk cache of parsed captures so repeat loads are near-instant.

Parsing a large Procmon XML file is expensive (tens of seconds to minutes).
The fully-optimized in-memory representation (events, interners, indices,
process tables) is picklable, so we serialize it keyed on the source file's
identity (path + size + mtime) and the load options. A later load of the same
unchanged file with the same options deserializes instead of re-parsing.

Notes:
- The cache is keyed on size + mtime, not a content hash, so re-reading a 2+ GB
  file is not required just to look it up. A modified file changes its mtime and
  therefore misses the cache.
- CACHE_VERSION invalidates every cache entry when the serialized format or the
  parser output changes.
- Any cache read/write error is non-fatal: the caller falls back to parsing.
- SECURITY: cache files are pickles (chosen per the feature request, since the
  optimized structures serialize directly). They are written by this tool into a
  user-owned directory (~/.procmonmcp/cache) and read back only from there. Only
  this tool's own output is ever unpickled; do not point CACHE_DIR at a location
  other users can write to, and treat a planted cache file as untrusted input.
"""
import os
import json
import pickle  # nosec B403 - see SECURITY note above; only our own output is loaded
import hashlib
import logging
from typing import Optional, Dict, Any

from .models import ProcmonLogData

logger = logging.getLogger(__name__)

# Bump when the serialized structures or parser output change in an
# incompatible way; old entries will then be ignored.
# v2: parser now repairs double-encoded (mojibake) non-ASCII names.
CACHE_VERSION = 2

CACHE_DIR = os.path.join(os.path.expanduser("~"), ".procmonmcp", "cache")


def compute_key(filename_abs: str, load_stack: bool, load_extra: bool) -> Optional[Dict[str, Any]]:
    """Builds the cache key (file identity + load options + version), or None.

    Returns None if the file cannot be stat'd, which disables caching for it.
    """
    try:
        st = os.stat(filename_abs)
    except OSError as e:
        logger.debug(f"cache: cannot stat '{filename_abs}': {e}")
        return None
    return {
        "path": os.path.abspath(filename_abs),
        "size": st.st_size,
        "mtime_ns": st.st_mtime_ns,
        "load_stack": bool(load_stack),
        "load_extra": bool(load_extra),
        "version": CACHE_VERSION,
    }


def _cache_file(key: Dict[str, Any]) -> str:
    digest = hashlib.sha256(json.dumps(key, sort_keys=True).encode("utf-8")).hexdigest()
    return os.path.join(CACHE_DIR, f"{digest}.pkl")


def load(key: Optional[Dict[str, Any]]) -> Optional[ProcmonLogData]:
    """Returns the cached ProcmonLogData for `key`, or None on miss/any error."""
    if not key:
        return None
    path = _cache_file(key)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "rb") as f:
            payload = pickle.load(f)  # nosec B301 - trusted, tool-written cache only
    except Exception as e:
        logger.warning(f"cache: failed to read '{path}': {e}; ignoring.")
        return None
    # Validate the embedded header against the requested key (defense in depth
    # against hash collisions or a stale/incompatible entry).
    if not isinstance(payload, dict) or payload.get("header") != key:
        logger.warning(f"cache: header mismatch in '{path}'; ignoring.")
        return None
    data = payload.get("data")
    if not isinstance(data, ProcmonLogData) or not data.is_loaded():
        logger.warning(f"cache: invalid payload in '{path}'; ignoring.")
        return None
    data.loaded_from_cache = True
    return data


def save(key: Optional[Dict[str, Any]], log_data: ProcmonLogData) -> bool:
    """Atomically writes `log_data` to the cache under `key`. Returns success."""
    if not key:
        return False
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
    except OSError as e:
        logger.warning(f"cache: cannot create cache directory '{CACHE_DIR}': {e}")
        return False
    path = _cache_file(key)
    tmp = f"{path}.tmp{os.getpid()}"
    prev_flag = getattr(log_data, "loaded_from_cache", False)
    try:
        # Persist with the flag cleared so a cache hit can set it to True.
        log_data.loaded_from_cache = False
        with open(tmp, "wb") as f:
            pickle.dump({"header": key, "data": log_data}, f, protocol=pickle.HIGHEST_PROTOCOL)
        os.replace(tmp, path)
        return True
    except Exception as e:
        logger.warning(f"cache: failed to write '{path}': {e}")
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass
        return False
    finally:
        log_data.loaded_from_cache = prev_flag


def clear() -> int:
    """Removes all cached captures. Returns the number of files removed."""
    count = 0
    if os.path.isdir(CACHE_DIR):
        for name in os.listdir(CACHE_DIR):
            if name.endswith(".pkl"):
                try:
                    os.remove(os.path.join(CACHE_DIR, name))
                    count += 1
                except OSError as e:
                    logger.warning(f"cache: could not remove '{name}': {e}")
    return count
