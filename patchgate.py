"""Evidence-first review of a Git diff. Python standard library only."""

from __future__ import annotations

import argparse
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


def report(diff: str, label: str) -> dict:
    findings, stats = parse_diff(diff)
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    highest = max((rank[f.severity] for f in findings), default=0)
    status = "REVIEW REQUIRED" if highest >= 3 else "READY FOR HUMAN REVIEW"
    report_id = hashlib.sha256(diff.encode("utf-8")).hexdigest()[:16]
    return {
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
    }


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
</style><main data-report-id="{esc(data['report_id'])}" data-review-id="{esc(data['review_id'])}"><div class="eyebrow">PatchGate / Change review</div>
<h1>{esc(data["title"])}</h1><p class="summary">Evidence-linked review before merge or release.</p>
<div class="status">{esc(data["status"])}</div>
<div class="stats"><span>{s["files"]} changed files</span><span>+{s["added"]} additions</span><span>-{s["removed"]} deletions</span><span>{len(data["findings"])} review prompts</span></div>
<div class="toolbar"><strong id="progress" aria-live="polite">0/{len(data['findings'])} reviewed</strong><button type="button" id="export">Export decisions</button></div>
<p class="note">Decisions stay in this browser when local storage is available. Export a copy before sharing or switching devices.</p>
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
    args = parser.parse_args(argv)
    if args.diff and args.base:
        parser.error("--base only applies to --repo")
    if args.check_decisions and not args.decisions:
        parser.error("--check-decisions requires --decisions")
    try:
        diff = args.diff.read_text(encoding="utf-8") if args.diff else git_diff(args.repo, args.base)
        data = report(diff, args.repo.name if args.repo else args.diff.stem)
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
