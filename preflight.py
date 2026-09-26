"""Local readiness checks; never substitutes for verifying the actual submission."""

from __future__ import annotations

import argparse
import subprocess
import sys
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check local PatchGate submission blockers")
    parser.add_argument("--video-url", help="Public demo video URL to verify manually")
    args = parser.parse_args(argv)
    checks: list[tuple[str, bool, str]] = []

    tests = run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-q"])
    checks.append(("Tests", tests.returncode == 0, "Run python3 -m unittest discover -s tests -v"))

    state = run(["git", "status", "--porcelain"])
    checks.append(("Clean Git working tree", state.returncode == 0 and not state.stdout.strip(),
                   "Review changes and commit only after verifying them"))

    remote = run(["git", "remote", "get-url", "origin"])
    checks.append(("Git remote", remote.returncode == 0 and bool(remote.stdout.strip()),
                   "Create a dedicated public PatchGate repository and add it as origin"))

    screenshots = list((ROOT / "bob_sessions").glob("*.png"))
    valid = [p for p in screenshots if is_png(p)]
    checks.append(("Bob task screenshots", bool(valid) and len(valid) == len(screenshots),
                   "Add genuine PNG summaries for every relevant Bob IDE task and participant"))

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
