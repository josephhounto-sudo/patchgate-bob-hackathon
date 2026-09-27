"""Evidence-first review of a Git diff. Python standard library only."""

from __future__ import annotations

import argparse
import ast
import hashlib
import html
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    path: str
    line: int
    evidence: str
    reason: str
    action: str


RULES = (
    (
        "hardcoded-secret", "critical",
        re.compile(r"(?i)\b(?:api[_-]?key|secret|password|access[_-]?token)\b\s*[:=]\s*['\"][^'\"\s]{8,}['\"]"),
        "A credential-like value was added to source.",
        "Remove it from the commit, rotate it if real, and load it from a secret store.",
    ),
    (
        "unsafe-eval", "high", re.compile(r"\b(?:eval|exec)\s*\("),
        "Dynamic code execution can turn untrusted input into executable code.",
        "Replace with a parser or allowlisted operation; inspect the input boundary.",
    ),
    (
        "subprocess-shell", "high", re.compile(r"\bshell\s*=\s*True\b"),
        "A shell-enabled subprocess can expose command injection paths.",
        "Pass an argument list and avoid shell=True unless inputs are tightly controlled.",
    ),
    (
        "disabled-tls", "high", re.compile(r"\bverify\s*=\s*False\b"),
        "TLS verification was explicitly disabled.",
        "Restore certificate validation and handle the trust issue explicitly.",
    ),
    (
        "broad-exception", "medium", re.compile(r"\bexcept\s+(?:Exception|BaseException)(?:\s+as\s+\w+)?\s*:"),
        "A broad exception handler may hide failures.",
        "Catch expected errors and preserve actionable diagnostics.",
    ),
    (
        "todo-marker", "low", re.compile(r"\b(?:TODO|FIXME)\b"),
        "An unfinished task was introduced in this change.",
        "Resolve it or record a tracked follow-up before release.",
    ),
)

CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_-]?key|secret|password|access[_-]?token)\b\s*[:=]\s*(['\"])[^'\"\s]{8,}\1"
)

_IMPACT_LIMITATIONS = (
    "This is a static name-based heuristic. "
    "It cannot confirm the test exercises the changed lines, "
    "cannot detect indirect calls or dynamic dispatch, "
    "and cannot substitute for runtime coverage or manual review."
)


def safe_evidence(content: str) -> str:
    """Mask credential-like values even when another rule matches the same line."""
    return CREDENTIAL_ASSIGNMENT.sub("[REDACTED: potential credential]", content).strip()[:180]


def parse_diff(diff: str) -> tuple[list[Finding], dict[str, int]]:
    findings: list[Finding] = []
    stats = {"files": 0, "added": 0, "removed": 0}
    path = ""
    new_line = 0
    in_hunk = False
    for raw in diff.splitlines():
        if raw.startswith("diff --git "):
            path = ""
            stats["files"] += 1
            new_line = 0
            in_hunk = False
        elif raw.startswith("+++ ") and not in_hunk:
            # Use the destination path; ignore deleted files and malformed headers.
            target = raw[4:].strip()
            path = target[2:] if target.startswith("b/") else ""
            if path.startswith("../") or path.startswith("/"):
                path = ""
        elif raw.startswith("--- ") and not in_hunk:
            # Source-file header, not a deleted source line.
            continue
        elif raw.startswith("@@ "):
            match = re.search(r"\+(\d+)(?:,\d+)?", raw)
            if match:
                new_line = int(match.group(1))
                in_hunk = True
        elif raw.startswith("+") and in_hunk:
            stats["added"] += 1
            content = raw[1:]
            comment_only = content.lstrip().startswith(("#", "//", "/*", "*", "<!--", "--"))
            if path:
                for rule, severity, pattern, reason, action in RULES:
                    if comment_only and rule not in ("hardcoded-secret", "todo-marker"):
                        continue
                    if pattern.search(content):
                        evidence = safe_evidence(content)
                        findings.append(Finding(rule, severity, path, new_line,
                                                evidence, reason, action))
            new_line += 1
        elif raw.startswith("-") and in_hunk:
            stats["removed"] += 1
        elif raw.startswith(" ") and in_hunk:
            new_line += 1
    return findings, stats


def _parse_diff_changed_lines(diff: str) -> dict[str, set[int]]:
    """Return a mapping of destination path → set of new-file line numbers that were
    explicitly added (``+``) in the diff.

    Only added lines are recorded.  Context lines (`` ``) advance the new-file
    line counter but are not added to the set, so a neighboring function whose
    body was not modified is not falsely identified as changed.

    Removed lines (``-``) never have a new-file number, so they are not added
    to the set either; a function whose body was only deleted will not appear
    (the destination file no longer contains it).
    """
    changed: dict[str, set[int]] = {}
    path = ""
    new_line = 0
    in_hunk = False
    hunk_lines: set[int] = set()

    for raw in diff.splitlines():
        if raw.startswith("diff --git "):
            path = ""
            new_line = 0
            in_hunk = False
            hunk_lines = set()
        elif raw.startswith("+++ ") and not in_hunk:
            target = raw[4:].strip()
            candidate = target[2:] if target.startswith("b/") else ""
            if candidate.startswith("../") or candidate.startswith("/"):
                candidate = ""
            path = candidate
            if path:
                hunk_lines = changed.setdefault(path, set())
        elif raw.startswith("--- ") and not in_hunk:
            continue
        elif raw.startswith("@@ "):
            match = re.search(r"\+(\d+)(?:,\d+)?", raw)
            if match:
                new_line = int(match.group(1))
                in_hunk = True
        elif raw.startswith("+") and in_hunk:
            if path:
                hunk_lines.add(new_line)
            new_line += 1
        elif raw.startswith("-") and in_hunk:
            pass  # removed lines do not advance new_line
        elif raw.startswith(" ") and in_hunk:
            # Context line: advance the new-file counter but do NOT record the line.
            # Recording context lines causes neighboring unchanged functions to be
            # falsely identified as changed when they appear inside the hunk window.
            new_line += 1

    return changed


@dataclass(frozen=True)
class ChangedFunction:
    name: str
    source_path: str
    source_line: int


def detect_changed_functions(diff: str, repo_root: Path) -> list[ChangedFunction]:
    """Identify top-level Python functions whose bodies were touched by *diff*.

    Uses ``ast`` to locate function definitions in the on-disk source files.
    A function is considered changed when any line in any hunk that touches
    its destination file falls within its definition span (from the ``def``
    line to the last line of the function body, inclusive).

    Only top-level ``FunctionDef`` / ``AsyncFunctionDef`` nodes are considered
    (i.e. functions defined at module scope).  Methods inside classes are
    excluded because the diff format does not give us reliable class context,
    and the feature specification asks for top-level functions only.

    No code from the repository is executed or imported.
    """
    path_lines = _parse_diff_changed_lines(diff)
    results: list[ChangedFunction] = []

    for rel_path, touched_lines in path_lines.items():
        if not rel_path.endswith(".py"):
            continue
        abs_path = repo_root / rel_path
        if not abs_path.is_file():
            # File may have been deleted or the path may be a rename; skip.
            continue
        try:
            source = abs_path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=rel_path)
        except SyntaxError:
            continue

        # Compute line spans for each top-level function.
        for node in ast.iter_child_nodes(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            func_start = node.lineno
            func_end = node.end_lineno if node.end_lineno is not None else node.lineno
            span = set(range(func_start, func_end + 1))
            if span & touched_lines:
                results.append(ChangedFunction(
                    name=node.name,
                    source_path=rel_path,
                    source_line=func_start,
                ))

    return results


@dataclass(frozen=True)
class TestMatch:
    test_path: str
    test_line: int


def find_test_references(func_name: str, repo_root: Path) -> list[TestMatch]:
    """Search Python test files under *repo_root* for call-site references to
    *func_name* inside test functions or test methods.

    A match requires an ``ast.Call`` node whose ``func`` field is a ``Name``
    or ``Attribute`` whose identifier equals *func_name*, and that call must
    appear inside the body of a function or method whose name starts with
    ``test_``.  Bare name references that are not callees (e.g. variable
    assignments like ``fn = calculate_total``) are excluded, as are
    module-level import statements.

    References inside string literals or comments are excluded because the
    Python AST parser does not produce identifier nodes for those positions.

    Test files are those whose filename matches ``test_*.py`` or ``*_test.py``
    anywhere under *repo_root*, following the standard ``unittest`` / ``pytest``
    discovery convention.

    This is a static name-based heuristic only.  It cannot confirm that the
    test exercises the changed lines, cannot detect indirect calls or dynamic
    dispatch, and cannot substitute for runtime coverage or manual review.

    No code is executed or imported.
    """
    matches: list[TestMatch] = []

    test_files = list(repo_root.rglob("test_*.py")) + list(repo_root.rglob("*_test.py"))
    # Deduplicate while preserving a deterministic order.
    seen: set[Path] = set()
    unique_test_files: list[Path] = []
    for tf in test_files:
        if tf not in seen:
            seen.add(tf)
            unique_test_files.append(tf)

    for test_file in sorted(unique_test_files):
        try:
            source = test_file.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(test_file))
        except SyntaxError:
            continue

        rel = str(test_file.relative_to(repo_root)).replace("\\", "/")

        # Collect all test function / test method bodies anywhere in the file.
        # We use ast.walk on the whole tree to find FunctionDef nodes at any
        # nesting depth (handles test methods inside TestCase classes).
        for func_node in ast.walk(tree):
            if not isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not func_node.name.startswith("test_"):
                continue
            # Walk the body of this test function looking for ast.Call nodes
            # whose callee (the ``func`` field) names the target function.
            # Bare Name references that are not callees — e.g. assignments like
            # ``fn = calculate_total`` — are intentionally excluded.
            for node in ast.walk(func_node):
                if not isinstance(node, ast.Call):
                    continue
                callee = node.func
                if isinstance(callee, ast.Name) and callee.id == func_name:
                    matches.append(TestMatch(test_path=rel, test_line=callee.lineno))
                elif isinstance(callee, ast.Attribute) and callee.attr == func_name:
                    matches.append(TestMatch(test_path=rel, test_line=callee.lineno))

    # Sort for determinism and deduplicate exact duplicates.
    matches = sorted(set(matches), key=lambda m: (m.test_path, m.test_line))
    return matches


def build_impact(diff: str, repo_root: Path) -> list[dict]:
    """Build the impact list for the JSON report.

    Each entry contains the changed function metadata plus test match evidence
    (or a ``result`` of ``"no_name_match"`` when none is found).
    """
    changed = detect_changed_functions(diff, repo_root)
    impact: list[dict] = []

    for cf in changed:
        refs = find_test_references(cf.name, repo_root)
        entry: dict = {
            "function": cf.name,
            "source_path": cf.source_path,
            "source_line": cf.source_line,
            "analysis_method": "ast_name_reference",
            "limitations": _IMPACT_LIMITATIONS,
        }
        if refs:
            entry["test_matches"] = [{"test_path": r.test_path, "test_line": r.test_line} for r in refs]
            entry["result"] = "name_match_found"
        else:
            entry["test_matches"] = []
            entry["result"] = "no_name_match"
        impact.append(entry)

    return impact


def git_diff(repo: Path, base: str | None) -> str:
    # A repository can configure external diff and textconv commands. Neither
    # may run while we inspect a repository supplied for review.
    args = ["git", "-C", str(repo), "diff", "--no-ext-diff", "--no-textconv", "--unified=3"]
    if base:
        if base.startswith("-"):
            raise ValueError("The base revision must not start with '-'")
        # A revision is an argument, never shell text. `--` separates paths.
        args.extend([base, "--"])
    else:
        args.append("HEAD")
    run = subprocess.run(args, capture_output=True, text=True, check=False)
    if run.returncode:
        raise ValueError(run.stderr.strip() or "Could not read the Git diff")
    return run.stdout


def report(diff: str, label: str, repo_root: Path | None = None) -> dict:
    findings, stats = parse_diff(diff)
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    highest = max((rank[f.severity] for f in findings), default=0)
    status = "REVIEW REQUIRED" if highest >= 3 else "READY FOR HUMAN REVIEW"
    report_id = hashlib.sha256(diff.encode("utf-8")).hexdigest()[:16]
    data = {
        "title": label,
        "report_id": report_id,
        "review_id": report_id,
        "status": status,
        "stats": stats,
        "findings": [{**asdict(f), "decision": "pending"} for f in findings],
        "review_summary": {"accepted": 0, "fix": 0, "pending": len(findings)},
        "limitations": [
            "Pattern matches are review prompts, not proven vulnerabilities.",
            "Only added lines in tracked changes are scanned; untracked and binary files are outside scope.",
            "This does not replace tests or security review. Avoid confidential input in shared reports.",
        ],
        "impact": [],
    }
    if repo_root is not None:
        data["impact"] = build_impact(diff, repo_root)
    return data


def apply_decisions(data: dict, exported: object) -> dict:
    """Load a review export only when it matches this exact diff and findings."""
    if not isinstance(exported, dict) or exported.get("report_id") != data["report_id"]:
        raise ValueError("Decision file does not match this diff (report_id mismatch)")
    entries = exported.get("decisions")
    if not isinstance(entries, list) or len(entries) != len(data["findings"]):
        raise ValueError("Decision file must contain one entry per finding")
    choices = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Invalid decision entry")
        path, line, rule, choice = (entry.get(k) for k in ("path", "line", "rule", "decision"))
        if not isinstance(path, str) or type(line) is not int or not isinstance(rule, str):
            raise ValueError("Invalid decision identity")
        if choice not in ("pending", "fix", "accepted"):
            raise ValueError("Invalid review decision")
        identity = (path, line, rule)
        if identity in choices:
            raise ValueError("Duplicate decision entry")
        choices[identity] = choice
    expected = {(f["path"], f["line"], f["rule"]) for f in data["findings"]}
    if set(choices) != expected:
        raise ValueError("Decision entries do not match the current findings")
    summary = {"accepted": 0, "fix": 0, "pending": 0}
    for f in data["findings"]:
        f["decision"] = choices[(f["path"], f["line"], f["rule"])]
        summary[f["decision"]] += 1
    data["review_summary"] = summary
    normalized = json.dumps(entries, sort_keys=True, separators=(",", ":"))
    data["review_id"] = data["report_id"] + "-" + hashlib.sha256(normalized.encode()).hexdigest()[:12]
    return data


REVIEW_SCRIPT = r'''<script>
(() => {
  const root = document.querySelector('main');
  const cards = [...document.querySelectorAll('.finding')];
  const key = 'patchgate:' + root.dataset.reviewId;
  const allowed = new Set(['pending', 'fix', 'accepted']);
  let decisions = {};
  for (const card of cards) decisions[card.dataset.id] = card.dataset.initial;
  try { decisions = JSON.parse(localStorage.getItem(key) || 'null') || decisions; } catch (_) { /* use imported defaults */ }
  function paint() {
    let reviewed = 0;
    for (const card of cards) {
      const choice = allowed.has(decisions[card.dataset.id]) ? decisions[card.dataset.id] : 'pending';
      if (choice !== 'pending') reviewed++;
      for (const button of card.querySelectorAll('button[data-decision]')) {
        button.setAttribute('aria-pressed', String(button.dataset.decision === choice));
      }
      card.querySelector('.decision-label').textContent =
        choice === 'fix' ? 'Needs fix' : choice === 'accepted' ? 'Reviewed' : 'Pending';
    }
    document.getElementById('progress').textContent = reviewed + '/' + cards.length + ' reviewed';
  }
  root.addEventListener('click', event => {
    const button = event.target.closest('button[data-decision]');
    if (!button) return;
    const card = button.closest('.finding');
    decisions[card.dataset.id] = button.dataset.decision;
    try { localStorage.setItem(key, JSON.stringify(decisions)); } catch (_) { /* export remains available */ }
    paint();
  });
  document.getElementById('export').addEventListener('click', () => {
    const result = {
      report_id: root.dataset.reportId,
      title: root.querySelector('h1').textContent,
      decisions: cards.map(card => ({
        path: card.dataset.path, line: Number(card.dataset.line), rule: card.dataset.rule,
        decision: allowed.has(decisions[card.dataset.id]) ? decisions[card.dataset.id] : 'pending'
      }))
    };
    const url = URL.createObjectURL(new Blob([JSON.stringify(result, null, 2)], {type: 'application/json'}));
    const link = document.createElement('a');
    link.href = url; link.download = 'patchgate-decisions-' + root.dataset.reportId + '.json';
    link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  });
  paint();
})();
</script>'''


def _render_impact_section(impact: list[dict]) -> str:
    """Render the Change Impact Evidence section for the HTML report.

    All repository-controlled content (function names, file paths, etc.) is
    escaped with html.escape before insertion.
    """
    esc = lambda value: html.escape(str(value), quote=True)

    if not impact:
        return (
            '<section class="impact-section">'
            '<h2>Change Impact Evidence</h2>'
            '<p class="heuristic-label">Name-based heuristic \u2014 not a coverage report</p>'
            '<p class="empty">No Python function changes detected in this diff.</p>'
            '</section>'
        )

    rows: list[str] = []
    matched_count = 0
    no_match_count = 0

    for entry in impact:
        fn = esc(entry["function"])
        sp = esc(entry["source_path"])
        sl = int(entry["source_line"])
        matches = entry.get("test_matches", [])
        result = entry.get("result", "")

        if matches:
            matched_count += 1
            match_items = "".join(
                f'<li class="test-match">{esc(m["test_path"])}:{int(m["test_line"])}</li>'
                for m in matches
            )
            rows.append(
                f'<li class="impact-row matched">'
                f'<span class="fn-name">{fn}</span> '
                f'<span class="fn-loc">{sp}:{sl}</span>'
                f'<ul class="test-list">{match_items}</ul>'
                f'</li>'
            )
        else:
            no_match_count += 1
            rows.append(
                f'<li class="impact-row no-match">'
                f'<span class="fn-name">{fn}</span> '
                f'<span class="fn-loc">{sp}:{sl}</span>'
                f'<span class="no-match-label">'
                f'No name reference found in test files \u2014 manual verification recommended'
                f'</span>'
                f'</li>'
            )

    rows_html = "\n".join(rows)

    # Summary paragraph — intentionally conservative wording.
    summary_parts: list[str] = []
    if matched_count:
        summary_parts.append(
            f"{matched_count} function{'s' if matched_count != 1 else ''} "
            f"had a name-based reference found in test files."
        )
    if no_match_count:
        summary_parts.append(
            f"{no_match_count} function{'s' if no_match_count != 1 else ''} "
            f"had no name reference found in test files; "
            f"manual verification is recommended before release."
        )
    summary_parts.append(
        "A name reference does not confirm the test exercises the changed lines, "
        "and its absence does not prove the function lacks test coverage. "
        "This analysis cannot detect indirect calls, dynamic dispatch, or runtime behaviour."
    )
    summary = " ".join(summary_parts)

    return (
        '<section class="impact-section">'
        '<h2>Change Impact Evidence</h2>'
        '<p class="heuristic-label">Name-based heuristic \u2014 not a coverage report</p>'
        f'<ul class="impact-list">{rows_html}</ul>'
        f'<p class="impact-summary">{esc(summary)}</p>'
        '</section>'
    )


def render_html(data: dict) -> str:
    esc = lambda value: html.escape(str(value), quote=True)
    cards = []
    for index, f in enumerate(data["findings"]):
        cards.append(
            f'<article class="finding" data-id="{index}" data-path="{esc(f["path"])}" '
            f'data-line="{f["line"]}" data-rule="{esc(f["rule"])}" '
            f'data-initial="{esc(f["decision"])}">'
            f'<div class="meta"><span class="badge {esc(f["severity"])}">{esc(f["severity"])}</span>'
            f'<span>{esc(f["rule"])}</span><span>{esc(f["path"])}:{f["line"]}</span></div>'
            f'<p>{esc(f["reason"])}</p><pre>{esc(f["evidence"])}</pre>'
            f'<p class="action">Next: {esc(f["action"])}</p>'
            '<div class="review" role="group" aria-label="Review decision">'
            '<button type="button" data-decision="fix">Needs fix</button>'
            '<button type="button" data-decision="accepted">Reviewed</button>'
            '<button type="button" data-decision="pending">Reset</button>'
            '<span class="decision-label" aria-live="polite">Pending</span></div></article>'
        )
    findings = "\n".join(cards) or '<p class="empty">No configured patterns matched added lines.</p>'
    s = data["stats"]
    impact_section = _render_impact_section(data.get("impact", []))
    return f'''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PatchGate | {esc(data["title"])}</title>
<style>
:root{{font:16px/1.55 system-ui,sans-serif;color:#e8eef6;background:#0b1420}}
*{{box-sizing:border-box}}body{{margin:0}}main{{max-width:960px;margin:auto;padding:36px 20px 80px}}
.eyebrow{{color:#87d7c6;letter-spacing:.17em;text-transform:uppercase;font-size:.75rem;font-weight:700}}
h1{{font-size:clamp(2rem,6vw,4rem);margin:8px 0}}h2{{margin-top:36px}}
.summary{{color:#9eafc2}}.status{{display:inline-block;padding:9px 13px;border-radius:8px;background:#173b40;color:#9ef3d5;font-weight:800}}
.stats{{display:flex;gap:12px;flex-wrap:wrap;margin-top:22px}}.stats span{{background:#142337;border:1px solid #2a4058;border-radius:10px;padding:12px 16px}}
.finding{{background:#142337;border:1px solid #2a4058;border-radius:12px;padding:20px;margin:13px 0}}
.meta{{display:flex;align-items:center;gap:12px;flex-wrap:wrap;color:#a7b9cc;font-size:.84rem}}
.badge{{text-transform:uppercase;border-radius:4px;padding:3px 8px;font-weight:800;color:#111}}
.critical{{background:#ff8a8a}}.high{{background:#ffbd84}}.medium{{background:#ffe18a}}.low{{background:#9fdfd2}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;color:#d6ecfa;background:#0b1420;padding:12px;border-radius:8px}}
.action{{color:#9fe3d3}}footer{{border-top:1px solid #2a4058;padding-top:18px;color:#a7b9cc}}
.review{{display:flex;gap:8px;align-items:center;flex-wrap:wrap;border-top:1px solid #2a4058;padding-top:14px}}
button{{font:inherit;border:1px solid #53839a;border-radius:7px;padding:7px 11px;background:#20364b;color:#eef6fc;cursor:pointer}}
button:hover,button:focus-visible{{background:#31536d}}button[aria-pressed="true"]{{background:#9fe3d3;color:#09251e;border-color:#9fe3d3}}
.decision-label{{margin-left:auto;color:#b9cddd}}.toolbar{{display:flex;gap:16px;align-items:center;flex-wrap:wrap;margin-top:20px}}
.note{{color:#9eafc2;font-size:.85rem}}
.impact-section{{background:#101e30;border:1px solid #2a4058;border-radius:12px;padding:20px;margin:20px 0}}
.heuristic-label{{display:inline-block;background:#2a2000;color:#ffe18a;border:1px solid #8a6a00;border-radius:4px;padding:4px 10px;font-size:.82rem;font-weight:700;margin-bottom:12px}}
.impact-list{{list-style:none;padding:0;margin:0}}
.impact-row{{padding:10px 0;border-bottom:1px solid #1e3248}}
.impact-row:last-child{{border-bottom:none}}
.fn-name{{font-family:monospace;font-size:.95rem;color:#87d7c6;font-weight:700}}
.fn-loc{{font-family:monospace;font-size:.85rem;color:#7a9ab8;margin-left:8px}}
.test-list{{list-style:none;padding:0 0 0 16px;margin:4px 0 0 0}}
.test-list li{{font-family:monospace;font-size:.85rem;color:#9fe3d3}}
.no-match-label{{display:block;margin-top:4px;font-size:.85rem;color:#ffbd84;font-style:italic}}
.impact-summary{{color:#9eafc2;font-size:.88rem;margin-top:14px;border-top:1px solid #1e3248;padding-top:12px}}
</style><main data-report-id="{esc(data['report_id'])}" data-review-id="{esc(data['review_id'])}"><div class="eyebrow">PatchGate / Change review</div>
<h1>{esc(data["title"])}</h1><p class="summary">Evidence-linked review before merge or release.</p>
<div class="status">{esc(data["status"])}</div>
<div class="stats"><span>{s["files"]} changed files</span><span>+{s["added"]} additions</span><span>-{s["removed"]} deletions</span><span>{len(data["findings"])} review prompts</span></div>
<div class="toolbar"><strong id="progress" aria-live="polite">0/{len(data['findings'])} reviewed</strong><button type="button" id="export">Export decisions</button></div>
<p class="note">Decisions stay in this browser when local storage is available. Export a copy before sharing or switching devices.</p>
{impact_section}
<h2>Findings</h2>{findings}<footer><strong>Scope:</strong> {esc(' '.join(data['limitations']))}</footer></main>''' + REVIEW_SCRIPT + '</html>'


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Review added lines in a Git diff")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--diff", type=Path, help="Existing unified diff file")
    source.add_argument("--repo", type=Path, help="Git repository to inspect")
    parser.add_argument("--base", help="Git revision to compare with the working tree")
    parser.add_argument("--out", type=Path, default=Path("report.html"))
    parser.add_argument("--json", type=Path, help="Optional machine-readable report")
    parser.add_argument("--decisions", type=Path, help="Review decisions exported from the HTML report")
    parser.add_argument("--check-decisions", action="store_true", help="Exit 3 if any finding is pending or needs a fix")
    parser.add_argument("--repo-root", type=Path, help="Repository root for impact analysis when using --diff")
    args = parser.parse_args(argv)
    if args.diff and args.base:
        parser.error("--base only applies to --repo")
    if args.check_decisions and not args.decisions:
        parser.error("--check-decisions requires --decisions")
    try:
        diff = args.diff.read_text(encoding="utf-8") if args.diff else git_diff(args.repo, args.base)
        # Determine repo_root for impact analysis.
        if args.repo:
            repo_root = args.repo.resolve()
        elif args.repo_root:
            repo_root = args.repo_root.resolve()
        else:
            # Default: treat the current working directory as the repository root
            # when a diff file is supplied without an explicit --repo-root.
            repo_root = Path.cwd()
        data = report(diff, args.repo.name if args.repo else args.diff.stem, repo_root=repo_root)
        if args.decisions:
            apply_decisions(data, json.loads(args.decisions.read_text(encoding="utf-8")))
        args.out.write_text(render_html(data), encoding="utf-8")
        if args.json:
            args.json.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except (OSError, UnicodeError, ValueError) as exc:
        parser.exit(2, f"PatchGate: {exc}\n")
    open_count = data["review_summary"]["pending"] + data["review_summary"]["fix"]
    print(f"{data['status']} | {len(data['findings'])} findings | open: {open_count} | {args.out}")
    return 3 if args.check_decisions and open_count else 0


if __name__ == "__main__":
    sys.exit(main())
