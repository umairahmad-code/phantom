#!/usr/bin/env python3
"""
PHANTOM PDF ENGINE (headless-Chrome renderer)

Turns PHANTOM's already-branded, print-ready HTML reports into pixel-perfect,
client-grade PDFs — with zero fragile Python PDF dependencies.

Why Chrome instead of reportlab/weasyprint?
  * The HTML deliverables (Cyber Essentials / framework readiness / exec
    summary / retest) are the sales-grade output. Rendering *those* to PDF
    means the PDF matches the HTML exactly: same branding, colours, layout,
    severity pills and remediation roadmap.
  * Chrome/Chromium is present on virtually every assessor's machine and its
    print engine is best-in-class for CSS. No wheels to compile, no system
    libraries (cairo/pango) to install.

Public API:
    available()                       -> bool
    find_chrome()                     -> str | None   (path to the browser)
    html_to_pdf(html_path, pdf_path)  -> str | None   (pdf path on success)
    html_string_to_pdf(html, pdf_path)-> str | None
"""

import os
import shutil
import subprocess
import tempfile

# Candidate executables, in preference order. Covers macOS, Linux and Windows.
_CHROME_CANDIDATES = [
    # macOS
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    # Windows
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
]

# Names to look for on PATH (Linux distros vary a lot here).
_CHROME_PATH_NAMES = [
    "google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
    "chrome", "brave-browser", "microsoft-edge", "msedge",
]


def find_chrome():
    """Return the path to a usable Chrome/Chromium/Edge binary, or None."""
    env = os.environ.get("PHANTOM_CHROME") or os.environ.get("CHROME_PATH")
    if env and os.path.isfile(env):
        return env
    for name in _CHROME_PATH_NAMES:
        found = shutil.which(name)
        if found:
            return found
    for path in _CHROME_CANDIDATES:
        if os.path.isfile(path):
            return path
    return None


def available():
    """True if a headless-Chrome PDF render is possible on this machine."""
    return find_chrome() is not None


def html_to_pdf(html_path, pdf_path=None, timeout=60):
    """
    Render an HTML file to PDF via headless Chrome.

    Returns the PDF path on success, or None (with a printed reason) on failure.
    """
    chrome = find_chrome()
    if not chrome:
        print("⚠ No Chrome/Chromium/Edge found for PDF rendering. "
              "Set PHANTOM_CHROME=/path/to/chrome, or install Google Chrome.")
        return None

    html_path = os.path.abspath(html_path)
    if not os.path.isfile(html_path):
        print(f"❌ HTML source not found: {html_path}")
        return None
    if not pdf_path:
        pdf_path = os.path.splitext(html_path)[0] + ".pdf"
    pdf_path = os.path.abspath(pdf_path)

    # A dedicated, throwaway profile keeps this from touching the user's real
    # Chrome session and avoids "profile in use" locks.
    with tempfile.TemporaryDirectory(prefix="phantom_chrome_") as profile:
        cmd = [
            chrome,
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            "--no-pdf-header-footer",
            "--no-first-run",
            "--no-default-browser-check",
            f"--user-data-dir={profile}",
            f"--print-to-pdf={pdf_path}",
            _file_uri(html_path),
        ]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            print(f"❌ PDF render timed out after {timeout}s.")
            return None
        except OSError as e:
            print(f"❌ Could not launch browser for PDF: {e}")
            return None

    if os.path.isfile(pdf_path) and os.path.getsize(pdf_path) > 0:
        return pdf_path

    # Older Chrome builds reject the new headless flag; retry once with legacy.
    if "--headless=new" in cmd:
        return _retry_legacy_headless(chrome, html_path, pdf_path, timeout)

    err = (proc.stderr or proc.stdout or "").strip().splitlines()
    reason = err[-1] if err else "unknown error"
    print(f"❌ PDF render failed: {reason}")
    return None


def _retry_legacy_headless(chrome, html_path, pdf_path, timeout):
    with tempfile.TemporaryDirectory(prefix="phantom_chrome_") as profile:
        cmd = [
            chrome, "--headless", "--disable-gpu", "--no-sandbox",
            "--no-first-run", "--no-default-browser-check",
            f"--user-data-dir={profile}",
            f"--print-to-pdf={pdf_path}", _file_uri(html_path),
        ]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except (subprocess.TimeoutExpired, OSError):
            return None
    if os.path.isfile(pdf_path) and os.path.getsize(pdf_path) > 0:
        return pdf_path
    return None


def html_string_to_pdf(html, pdf_path, timeout=60):
    """Render an in-memory HTML string to PDF (writes a temp .html first)."""
    tmp_html = None
    try:
        fd, tmp_html = tempfile.mkstemp(suffix=".html", prefix="phantom_")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(html)
        return html_to_pdf(tmp_html, pdf_path, timeout=timeout)
    finally:
        if tmp_html and os.path.isfile(tmp_html):
            try:
                os.remove(tmp_html)
            except OSError:
                pass


def _file_uri(path):
    """Build a file:// URI that survives spaces and non-ASCII characters."""
    from urllib.request import pathname2url
    return "file://" + pathname2url(os.path.abspath(path))


if __name__ == "__main__":
    print("Chrome PDF renderer:",
          "available" if available() else "NOT available")
    c = find_chrome()
    if c:
        print("Using:", c)
