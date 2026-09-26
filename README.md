# PatchGate

An evidence-first change review for small engineering teams. It reads a Git diff, highlights added lines that deserve human review, and produces a shareable HTML report. The first slice is deterministic and runs locally with Python 3.10+ and no external packages.

## Quick demo

```bash
python3 patchgate.py --diff fixtures/sample.diff --out demo.html --json demo.json
python3 -m unittest discover -s tests -v
```

Open `demo.html` in a browser. Each finding can be marked **Needs fix** or **Reviewed**. The progress count updates immediately. Decisions are kept in that browser when local storage is available; use **Export decisions** to save a portable JSON record. To inspect a real Git repository, run:

```bash
python3 patchgate.py --repo /path/to/repo --base HEAD~1 --out report.html
```

To resume a review on another machine, pass its exported JSON file back to the CLI. `--check-decisions` returns exit code **3** when a finding is pending or marked Needs fix, and **0** when all findings are marked Reviewed. It rejects an export from a different diff or one with mismatched findings. This is a review-workflow check, **not** a claim that the code is safe.

```bash
python3 patchgate.py --diff fixtures/sample.diff --decisions fixtures/sample-decisions.json \
  --check-decisions --out reviewed.html --json reviewed.json
# The synthetic review intentionally exits 3: its credential-like line needs a fix.
```

The tool never executes changed code. With `--repo`, it compares tracked working-tree changes to `HEAD` (or the supplied base revision), including staged and unstaged edits; untracked and binary files are outside scope. Findings are prompts to review, not proof of vulnerabilities. Credential-like assignments matched by the configured pattern are masked in the report, but this is not comprehensive redaction. Do not put secrets or personal data in demonstration diffs or screenshots.

## Hackathon purpose

Developer workflow: change preparation → line-linked risk detection → recorded human decision → release readiness. The measurable baseline is time spent locating risky additions and preparing a review summary. The demonstrator includes a synthetic diff with a fake credential, shell-enabled subprocess, broad exception and TODO.

This initial baseline was prepared outside IBM Bob IDE. **It does not yet meet the hackathon's Bob usage requirement.** A participant must open this project in the provisioned IBM Bob IDE, use Bob substantially to implement and validate the next product feature, and capture genuine task-session summaries in `bob_sessions/`. Never fabricate screenshots or imply that the baseline was authored with Bob.

The distributed project includes a local Git baseline commit so Bob's implementation can be reviewed as a real diff. It has no remote repository or account credentials.

## Next feature in Bob IDE

Implement the change-impact analyzer described in `BOB_TASK.md`. Then use Bob to run the reviewer workflow in `BOB_REVIEW_TASK.md` and document the actual results. The two tasks make Bob's contribution visible in implementation and review. Keep an evaluation showing before/after on the fixture.

`fixtures/impact.diff`, `examples/checkout/app.py` and `tests/test_checkout_example.py` form a synthetic acceptance case: one changed function has a matching test call and one does not. The baseline analyzer does not yet produce impact links.

## Submission still needed

- Genuine Bob IDE task session summary PNGs for each participant in `bob_sessions/`.
- Public source repository, demonstration video, submission details and feedback form per the live guide and lablab form.
- Verify final time zone and precise submission fields in the platform before submitting.

See `PREMORTEM_2026-09-26.md` for the current go/no-go criteria and `DEMO_SCRIPT.md` for the recording plan. Neither document substitutes for real Bob task evidence.

Before submission, run `python3 preflight.py --video-url https://your-public-video-url`. It checks local tests, Git state, a configured remote, the presence and basic PNG validity of Bob summaries, and whether a video URL was supplied. It cannot authenticate the screenshots, confirm a URL is public, or submit the lablab form; verify those manually.

No part of this project uses code, datasets or patient information from Sentinelle or medical records.
