"""User configuration storage for ProcmonMCP.

Stores and recalls user preferences in ~/.procmonmcp/config.json.
"""
import json
import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".procmonmcp")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")

# Default configuration values
_DEFAULTS: Dict[str, Any] = {
    "last_file": None,
    "no_stack_traces": False,
    "no_extra_data": False,
}


def _ensure_config_dir() -> bool:
    """Creates the config directory if it does not exist. Returns True on success."""
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        return True
    except OSError as e:
        logger.warning(f"Could not create config directory '{CONFIG_DIR}': {e}")
        return False


def load_config() -> Dict[str, Any]:
    """Loads configuration from disk. Returns defaults if the file is missing or corrupt."""
    config = dict(_DEFAULTS)
    if not os.path.isfile(CONFIG_FILE):
        return config
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            stored = json.load(f)
        if isinstance(stored, dict):
            for key in _DEFAULTS:
                if key in stored:
                    config[key] = stored[key]
        else:
            logger.warning(f"Config file '{CONFIG_FILE}' does not contain a JSON object. Using defaults.")
    except (json.JSONDecodeError, OSError) as e:
        logger.warning(f"Could not read config file '{CONFIG_FILE}': {e}. Using defaults.")
    return config


def save_config(config: Dict[str, Any]) -> bool:
    """Persists the given configuration to disk. Returns True on success."""
    if not _ensure_config_dir():
        return False
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        return True
    except OSError as e:
        logger.warning(f"Could not write config file '{CONFIG_FILE}': {e}")
        return False


def get_last_file() -> Optional[str]:
    """Returns the last loaded file path from config, or None."""
    return load_config().get("last_file")


def set_last_file(file_path: str) -> None:
    """Stores the last loaded file path in config."""
    config = load_config()
    config["last_file"] = file_path
    save_config(config)
