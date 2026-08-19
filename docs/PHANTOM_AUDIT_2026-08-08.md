# PHANTOM — Pre-Commercial Quality Audit
**Date:** 8 August 2026
**Scope:** `PHANTOM_WORKSPACE/src`, `agents`, `tests` — readiness to put in front of paying clients.

---

## Verdict

**PHANTOM is in unusually good shape for a solo/student project.** The
architecture is clean, responsibilities are well separated, security hygiene is
strong (scope authorisation gate + injection/argument-injection checks), and the
whole suite passes: **74/74 tests green**. It is much closer to sellable than
most projects at this stage.

The gaps below are the difference between "works on my machine" and "a client
pays for the deliverable." The two revenue-critical ones are now **fixed** in
this session (see *Changes made*).

---

## What's strong (keep it)

| Area | Why it matters commercially |
|------|------------------------------|
| **Scope authorisation gate** (`phantom_scope.py`) | Blocks out-of-scope targets and shell/argument injection. This is your legal & safety backbone — clients and your own liability depend on it. |
| **Two-layer findings** (`phantom_findings.py` + `phantom_knowledge.py`) | Every finding has a technical *and* a plain-English explanation + remediation. This is exactly what makes a report readable by a non-technical business owner. |
| **Compliance mapping** (`phantom_frameworks.py`) | One scan → Cyber Essentials, IASME, GDPR, PCI deliverables. Multiplies what you can sell per engagement. |
| **Retest / change-tracking** (`phantom_retest.py`) | Turns one-off tests into recurring retainer revenue ("you fixed 4, 2 new appeared"). |
| **White-label branding** (`phantom_branding.py`) | Self-contained branded reports — required to sell under your own name. |
| **Branded HTML reports** (`phantom_reports.py`) | Genuinely client-grade: navy/teal cover, verdict card, severity tiles, remediation roadmap. |

---

## Gaps found

### 1. PDF output was the weakest link — **FIXED** ✅ (revenue-critical)
- **Was:** the PDF path used `reportlab` (not installed → PDFs silently skipped),
  rendered a dark "hacker green-on-black" layout, truncated descriptions to 40
  chars, capped at 10 findings, and ignored branding, CVSS and compliance data.
  The polished HTML deliverable never became a PDF.
- **Impact:** the PDF is what a client keeps, forwards to their board, and shows
  an auditor. A weak PDF undercuts the whole engagement.
- **Fix:** new `phantom_pdf.py` renders the *branded HTML* to PDF via headless
  Chrome (no fragile Python PDF deps). Reporter now emits client-grade PDFs for
  every deliverable; `reportlab` remains only as a fallback.

### 2. No CVSS score / OWASP mapping on findings — **FIXED** ✅
- **Was:** findings had severity words but no CVSS number and no OWASP Top 10
  category — both are expected on professional reports.
- **Fix:** new `phantom_owasp.py` adds an *indicative* CVSS v3.1 base score +
  band and the OWASP Top 10 (2021) category to every finding; surfaced in the
  report cards. (Clearly labelled "indicative" — see *Honesty notes*.)

### 3. `generate_report()` didn't expose the sellable deliverables — **FIXED** ✅
- **Was:** only `json/html/pdf/ce` were reachable via the one-line helper;
  framework / exec-summary / retest and any PDF variant needed manual calls.
- **Fix:** added `ce-pdf`, `framework`, `framework-pdf`, `exec`, `exec-pdf`
  formats (framework id via `engagement["framework_id"]`).

### 4. Minor robustness (recommended, not yet changed)
- `generate_pdf_report()` reportlab fallback does `host.get("os","N/A")[:20]`;
  if a host dict carries an explicit `os: None`, `.get` returns `None` and the
  slice raises. Low risk (the Chrome path is now primary), but worth a guard.
- No dependency manifest note that **Google Chrome** is now the preferred PDF
  engine. Add to `README.md` / `requirements.txt` comments.
- `pytest` isn't installed; tests run as standalone scripts. Fine, but adding
  `pytest` to the dev extras would let `pytest tests/` work as documented.

---

## Honesty notes (important for a security product)

- The **CVSS score is indicative**, derived from a representative base vector per
  finding class — not hand-scored from the target's exact environment. It is
  labelled "indicative" in the report so it is never mistaken for a bespoke
  vector. Keep that label; over-claiming precision is a credibility risk.
- The **CVE set is a curated offline list** of famous, banner-detectable
  versions — not a live CVE feed. Good for demos and common cases; disclose it as
  "known-signature detection" and back critical findings with manual validation.

---

## Changes made this session

| File | Change |
|------|--------|
| `src/phantom_pdf.py` *(new)* | Headless-Chrome HTML→PDF engine (cross-platform browser discovery, temp profile, legacy-headless retry). |
| `src/phantom_owasp.py` *(new)* | OWASP Top 10 (2021) mapping + indicative CVSS v3.1 scoring + coverage summary. |
| `src/phantom_reports.py` | Enrich findings with OWASP/CVSS; CVSS+OWASP+CVE in finding cards; Chrome-first `generate_pdf_report`; new `generate_*_pdf` deliverable methods; extended `generate_report` formats. |
| `tests/demo_full_report.py` *(new)* | One command → full HTML+PDF deliverable set for a demo client. |

**Regression:** 74/74 existing tests still pass; full deliverable set renders
(CE, PCI, exec summary, technical — HTML + PDF) and verified in-browser.

---

## Recommended next steps (highest leverage first)

1. **Add tests** for `phantom_owasp` (mapping/scoring) and a `phantom_pdf`
   availability guard, so the new revenue paths are covered.
2. **Ship the sample** (see `docs/SERVICE_OFFERING.md` + the generated PDFs) to a
   handful of local SMBs / nonprofits for testimonials.
3. **CVSS depth (optional):** allow a real per-finding vector override when an
   assessor wants to hand-score.
4. **Live CVE enrichment (later):** optional online feed behind a flag; keep the
   offline set as the always-available default.
