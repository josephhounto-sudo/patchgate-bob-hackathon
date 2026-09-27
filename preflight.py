"""Local readiness checks; never substitutes for verifying the actual submission."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=ROOT, capture_output=True, text=True, check=False)


def is_png(path: Path) -> bool:
    if not path.is_file() or path.stat().st_size <= 1000:
        return False
    with path.open("rb") as image:
        return image.read(8) == PNG_SIGNATURE


def impact_fixture_passes() -> bool:
    with tempfile.TemporaryDirectory() as temp_dir:
        out = Path(temp_dir) / "impact.html"
        data = Path(temp_dir) / "impact.json"
        generated = run([
            sys.executable, "patchgate.py", "--diff", "fixtures/impact.diff",
            "--out", str(out), "--json", str(data),
        ])
        if generated.returncode != 0 or not out.is_file() or not data.is_file():
            return False
        try:
            report = json.loads(data.read_text(encoding="utf-8"))
            impact = {item["function"]: item for item in report["impact"]}
            total = impact["calculate_total"]
            payment = impact["authorize_payment"]
            matches = total["test_matches"]
            return (
                any(match["test_path"] == "tests/test_checkout_example.py"
                    and match["test_line"] == 9 for match in matches)
                and not any(match["test_path"] == "tests/test_checkout_example.py"
                            and match["test_line"] == 4 for match in matches)
                and payment["result"] == "no_name_match"
                and not payment["test_matches"]
                and "Change Impact Evidence" in out.read_text(encoding="utf-8")
            )
        except (KeyError, TypeError, ValueError, OSError):
            return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check local PatchGate submission blockers")
    parser.add_argument("--video-url", help="Public demo video URL to verify manually")
    args = parser.parse_args(argv)
    checks: list[tuple[str, bool, str]] = []

    tests = run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-q"])
    checks.append(("Tests", tests.returncode == 0, "Run python3 -m unittest discover -s tests -v"))
    checks.append(("Impact example", impact_fixture_passes(),
                   "Generate fixtures/impact.diff and verify the test call at line 9, the unmatched function, and HTML output"))

    state = run(["git", "status", "--porcelain"])
    checks.append(("Clean Git working tree", state.returncode == 0 and not state.stdout.strip(),
                   "Review changes and commit only after verifying them"))

    remote = run(["git", "remote", "get-url", "origin"])
    checks.append(("Git remote", remote.returncode == 0 and bool(remote.stdout.strip()),
                   "Create a dedicated public PatchGate repository and add it as origin"))

    screenshots = list((ROOT / "bob_sessions").glob("*.png"))
    required = ("task-01-impact.png", "task-02-review.png")
    valid = all(is_png(ROOT / "bob_sessions" / name) for name in required)
    checks.append(("Bob task screenshots", valid and all(is_png(p) for p in screenshots),
                   "Add genuine task-01-impact.png and task-02-review.png summaries in bob_sessions/"))

    video = args.video_url or ""
    checks.append(("Video link supplied", video.startswith("https://") and len(video) > 12,
                   "Provide a public HTTPS demo video and test it while logged out"))

    for label, passed, action in checks:
        print(f"{'PASS' if passed else 'BLOCKED'}  {label}")
        if not passed:
            print(f"         Next: {action}")
    print("Manual check: confirm Bob provenance, screenshot authenticity, public URLs and lablab submission.")
    return 0 if all(passed for _, passed, _ in checks) else 2


if __name__ == "__main__":
    sys.exit(main())
