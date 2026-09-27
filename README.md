# PatchGate

An evidence-first change review for small engineering teams. It reads a Git diff, highlights added lines that deserve human review, links changed top-level Python functions to direct calls found in test functions, and produces a shareable HTML report. It is deterministic and runs locally with Python 3.10+ and no external packages.

## Quick demo

Open `index.html` for the guided, interactive showcase. It embeds the two
generated synthetic reports and works as a static site without a backend.
The reports are committed for preview; regenerate them after changing the
analyzer:

```bash
python3 patchgate.py --diff fixtures/sample.diff --out demo.html --json demo.json
python3 patchgate.py --diff fixtures/impact.diff --out impact.html --json impact.json
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

To view the impact example, run:

```bash
python3 patchgate.py --diff fixtures/impact.diff --out impact.html --json impact.json
```

In that example, `calculate_total` has a direct call in `tests/test_checkout_example.py:9`; `authorize_payment` has no name match. This is static name matching, not runtime coverage. It can associate unrelated functions with the same name, miss indirect calls, and miss deletion-only function changes. The HTML report explicitly flags deletions for manual review.

## Hackathon purpose

Developer workflow: change preparation → line-linked risk detection → recorded human decision → release readiness. The measurable baseline is time spent locating risky additions and preparing a review summary. The demonstrator includes a synthetic diff with a fake credential, shell-enabled subprocess, broad exception and TODO.

The initial baseline was prepared outside IBM Bob IDE. Bob subsequently implemented and reviewed the impact feature; see `reviews/bob_review.md` and the repository history. Session screenshots, where required, must be genuine. Never fabricate them or imply the baseline was authored with Bob.

The distributed ZIP includes a local Git baseline commit so Bob's implementation can be reviewed as a real diff. The public project repository is [josephhounto-sudo/patchgate-bob-hackathon](https://github.com/josephhounto-sudo/patchgate-bob-hackathon); clone that repository to continue in Bob IDE. No account credentials are stored in the project.

## Development history

`BOB_TASK.md` and `BOB_REVIEW_TASK.md` are historical task prompts, already executed. `fixtures/impact.diff`, `examples/checkout/app.py` and `tests/test_checkout_example.py` form the synthetic acceptance case.

The IBM Bob 2.0 hackathon has ended. `PREMORTEM_2026-09-26.md` and `DEMO_SCRIPT.md` document that event's preparation, not a current submission checklist.

`preflight.py` is specific to the IBM Bob event. It checks local tests, Git state, a configured remote, the presence and basic PNG validity of Bob summaries, and whether a video URL was supplied. It cannot authenticate screenshots, confirm a URL is public, or submit a form.

No part of this project uses code, datasets or patient information from Sentinelle or medical records.

## Prior art and distinction

PatchGate was informed at the concept level by [DiffGate](https://github.com/diffgate), [reviewdog](https://github.com/reviewdog/reviewdog), and [diff-cover](https://github.com/Bachmann1234/diff_cover). This implementation was produced independently and does not copy source code from those projects.

PatchGate's distinguishing evidence chain is: changed line → changed function → related test evidence → recorded human decision → portable release review. The goal is a traceable, human-owned audit trail that travels with the diff rather than a CI metric that lives in an external system.
