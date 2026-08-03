#!/usr/bin/env python3
"""
PHANTOM CONFIG LOADER
Single source of truth for runtime settings. Reads configs/phantom_config.json
(if present) over a set of safe defaults, so editing that file actually changes
behaviour — database location, AI backend, logging, and report output.

Search order for the config file:
  1. $PHANTOM_CONFIG                       (explicit override)
  2. <workspace>/configs/phantom_config.json
  3. ~/.phantom/phantom_config.json
"""

import os
import json

_DEFAULTS = {
    "version": "2.0",
    "project_name": "PHANTOM Framework",
    "database": {"path": "~/.phantom/scans.db", "type": "sqlite3"},
    "ai": {
        "engine": "llama", "model": "llama2",
        "host": "127.0.0.1", "port": 11434, "enabled": True,
    },
    "agent": {
        "enabled": True, "auto_phase_advance": True,
        "guidance_level": "detailed", "save_workflows": True,
    },
    "logging": {"path": "~/.phantom_logs", "level": "INFO"},
    "reports": {"path": "~/.phantom/reports"},
}

_SRC_DIR = os.path.dirname(os.path.abspath(__file__))
_WORKSPACE = os.path.dirname(_SRC_DIR)

_cache = None


def _candidate_paths():
    env = os.environ.get("PHANTOM_CONFIG")
    if env:
        yield os.path.expanduser(env)
    yield os.path.join(_WORKSPACE, "configs", "phantom_config.json")
    yield os.path.expanduser("~/.phantom/phantom_config.json")


def _deep_merge(base, override):
    """Recursively merge override into a copy of base."""
    result = dict(base)
    for key, val in (override or {}).items():
        if isinstance(val, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


def load(force=False):
    """Return the merged config dict (cached)."""
    global _cache
    if _cache is not None and not force:
        return _cache
    merged = dict(_DEFAULTS)
    for path in _candidate_paths():
        try:
            with open(path, "r", encoding="utf-8") as fh:
                merged = _deep_merge(_DEFAULTS, json.load(fh))
            break
        except (FileNotFoundError, OSError):
            continue
        except ValueError:
            # malformed JSON: fall back to defaults rather than crash
            break
    _cache = merged
    return merged


def get(dotted, default=None):
    """Look up a dotted key, e.g. get('ai.port', 11434)."""
    node = load()
    for part in dotted.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return default
    return node


def _expand(path):
    return os.path.expanduser(str(path))


def db_path():
    return _expand(get("database.path", _DEFAULTS["database"]["path"]))


def logs_dir():
    return _expand(get("logging.path", _DEFAULTS["logging"]["path"]))


def log_level():
    return str(get("logging.level", "INFO")).upper()


def reports_dir():
    return _expand(get("reports.path", _DEFAULTS["reports"]["path"]))


def ai_settings():
    ai = get("ai", {}) or {}
    return {
        "engine": ai.get("engine", "llama"),
        "model": ai.get("model", "llama2"),
        "host": ai.get("host", "127.0.0.1"),
        "port": int(ai.get("port", 11434)),
        "enabled": bool(ai.get("enabled", True)),
    }
