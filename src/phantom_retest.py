#!/usr/bin/env python3
"""
PHANTOM RETEST / CHANGE-TRACKING

Compares two sets of findings (an earlier scan vs a later one) and reports what
changed: which issues were FIXED, which are NEW, and which still PERSIST.

This is what turns a one-off assessment into a recurring, retainer-friendly
service — the client sees measurable progress ("you fixed 4, 2 new appeared")
month over month.

Findings are the enriched dicts produced by phantom_findings.extract_findings.
Each is fingerprinted by (title, evidence) so the same issue matches across
scans even when list order differs.
"""

try:
    import phantom_knowledge as kb
    import phantom_findings as findings_mod
except ImportError:  # imported as src.phantom_retest
    from src import phantom_knowledge as kb
    from src import phantom_findings as findings_mod


def _fingerprint(f):
    """Stable identity for a finding across scans."""
    ident = f.get("cve") or f.get("evidence") or ""
    return (str(f.get("title", "")).strip().lower(), str(ident).strip().lower())


def diff_findings(old_findings, new_findings):
    """
    Compare two finding lists.

    Returns:
        {
          "fixed":      [findings present before, gone now],
          "new":        [findings that appeared],
          "persisting": [findings present in both],
          "summary":    {fixed, new, persisting, before, after,
                         net_change, improved(bool)},
        }
    """
    old_map = {_fingerprint(f): f for f in (old_findings or [])}
    new_map = {_fingerprint(f): f for f in (new_findings or [])}

    fixed_keys = old_map.keys() - new_map.keys()
    new_keys = new_map.keys() - old_map.keys()
    persist_keys = old_map.keys() & new_map.keys()

    def _sort(items):
        return sorted(items, key=lambda f: -kb.severity_rank(f.get("severity")))

    fixed = _sort([old_map[k] for k in fixed_keys])
    new = _sort([new_map[k] for k in new_keys])
    persisting = _sort([new_map[k] for k in persist_keys])

    before, after = len(old_map), len(new_map)
    summary = {
        "fixed": len(fixed),
        "new": len(new),
        "persisting": len(persisting),
        "before": before,
        "after": after,
        "net_change": after - before,
        # "Improved" = risk went down: more fixed than newly introduced.
        "improved": len(fixed) > len(new),
    }
    return {"fixed": fixed, "new": new, "persisting": persisting, "summary": summary}


def diff_from_results(old_results, new_results, target=""):
    """Convenience: run extraction on two raw result sets, then diff."""
    old_f = findings_mod.extract_findings(old_results or [], target)
    new_f = findings_mod.extract_findings(new_results or [], target)
    return diff_findings(old_f, new_f)


def headline(diff):
    """One plain-language sentence summarising the change (for the client)."""
    s = diff["summary"]
    if s["before"] == 0 and s["after"] == 0:
        return "No issues detected in either assessment."
    if s["fixed"] == 0 and s["new"] == 0:
        return (f"No change since the last assessment — "
                f"{s['persisting']} issue(s) still outstanding.")
    bits = []
    if s["fixed"]:
        bits.append(f"{s['fixed']} issue(s) resolved")
    if s["new"]:
        bits.append(f"{s['new']} new issue(s) appeared")
    if s["persisting"]:
        bits.append(f"{s['persisting']} still outstanding")
    trend = "Overall security has improved." if s["improved"] else (
        "Overall risk has increased — new issues outweigh fixes."
        if s["new"] > s["fixed"] else "Security posture is roughly unchanged.")
    return ", ".join(bits) + ". " + trend


if __name__ == "__main__":
    print("✓ Retest / change-tracking module ready")
