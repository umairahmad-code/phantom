#!/usr/bin/env python3
"""
PHANTOM LOGGING
Central logger factory: a rotating file handler (under the configured logs
directory) plus a console handler. Replaces scattered print() calls and gives
every module consistent, timestamped, level-tagged output that persists to disk.
"""

import os
import logging
from logging.handlers import RotatingFileHandler

try:
    import phantom_config as config
except ImportError:  # imported as src.phantom_logging
    from src import phantom_config as config

_configured = set()


def get_logger(name="phantom"):
    """Return a configured logger. Safe to call repeatedly."""
    logger = logging.getLogger(name)
    if name in _configured:
        return logger

    level = getattr(logging, config.log_level(), logging.INFO)
    logger.setLevel(level)
    logger.propagate = False

    fmt = logging.Formatter(
        "%(asctime)s  %(levelname)-7s  %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # File handler (best-effort: never let logging break the app).
    try:
        logs_dir = config.logs_dir()
        os.makedirs(logs_dir, exist_ok=True)
        fh = RotatingFileHandler(
            os.path.join(logs_dir, "phantom.log"),
            maxBytes=2_000_000, backupCount=5, encoding="utf-8",
        )
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except OSError:
        pass

    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    _configured.add(name)
    return logger
