#!/usr/bin/env python3
"""
PHANTOM BRANDING / WHITE-LABEL

Stores the assessor's branding (company name, logo, accent colour) so every
report carries their identity — essential for selling assessments under your
own name and for reselling the tool to other consultants/MSPs (white-label).

Branding lives in ~/.phantom/branding.json. The logo is embedded into reports
as a base64 data URI so the HTML/PDF is fully self-contained (no external
image dependency).
"""

import os
import io
import json
import base64
import mimetypes

BRANDING_PATH = os.path.expanduser("~/.phantom/branding.json")

DEFAULTS = {
    "company_name": "PHANTOM Security",
    "tagline": "Security Assessment Services",
    "primary_color": "#0f2440",   # cover background
    "accent_color": "#0ea5a5",    # highlights
    "logo_path": "",              # source image on disk (optional)
    "footer_note": "",            # extra confidentiality/contact line
}

_MAX_LOGO_BYTES = 512 * 1024      # keep reports small; refuse huge logos


def load():
    """Return the branding dict (defaults merged with saved overrides)."""
    data = dict(DEFAULTS)
    try:
        with open(BRANDING_PATH, "r", encoding="utf-8") as fh:
            saved = json.load(fh)
        if isinstance(saved, dict):
            data.update({k: v for k, v in saved.items() if k in DEFAULTS})
    except (FileNotFoundError, ValueError, OSError):
        pass
    return data


def save(branding):
    """Persist the given branding dict (only known keys)."""
    clean = {k: branding.get(k, DEFAULTS[k]) for k in DEFAULTS}
    try:
        os.makedirs(os.path.dirname(BRANDING_PATH), exist_ok=True)
        with open(BRANDING_PATH, "w", encoding="utf-8") as fh:
            json.dump(clean, fh, indent=2)
        return True
    except OSError:
        return False


def logo_data_uri(logo_path=None):
    """
    Return a `data:` URI for the logo image, or "" if none/invalid.

    Embedding keeps reports self-contained and printable. Oversized images are
    refused so reports stay a sensible size.
    """
    path = logo_path if logo_path is not None else load().get("logo_path", "")
    if not path or not os.path.isfile(path):
        return ""
    try:
        if os.path.getsize(path) > _MAX_LOGO_BYTES:
            return ""
        mime, _ = mimetypes.guess_type(path)
        if not mime or not mime.startswith("image/"):
            return ""
        with open(path, "rb") as fh:
            b64 = base64.b64encode(fh.read()).decode("ascii")
        return f"data:{mime};base64,{b64}"
    except OSError:
        return ""


def apply_to_engagement(engagement):
    """
    Merge branding into an engagement dict for the reporter, without
    overwriting per-engagement values the caller already set.
    """
    b = load()
    eng = dict(engagement or {})
    eng.setdefault("prepared_by", b["company_name"])
    eng.setdefault("branding", b)
    eng.setdefault("logo_uri", logo_data_uri(b.get("logo_path", "")))
    return eng


if __name__ == "__main__":
    print(json.dumps(load(), indent=2))
