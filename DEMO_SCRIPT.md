# PatchGate — concise video plan

**Recording target:** about 2–3 minutes. This is a shooting outline, not a claim that the missing Bob work has already happened. Replace the bracketed items with actual evidence before recording.

| Time | Screen | Narration |
| --- | --- | --- |
| 0:00–0:20 | Synthetic Git diff and the two example functions | “Reviewers need to spot risky changes, decide what to fix, and find the tests most relevant to a patch. A raw diff makes that first pass manual.” |
| 0:20–0:45 | Terminal running the sample command, then `demo.html` | “PatchGate turns added lines into a review checklist with exact paths and line numbers. The four prompts in this sample are deliberately synthetic; they are not proven vulnerabilities.” |
| 0:45–1:10 | Mark two findings and export decisions; show the `--decisions --check-decisions` command | “A reviewer records dispositions and carries them between machines. The check remains open while an issue needs a fix. It does not certify the code as secure.” |
| 1:10–1:45 | [Actual Bob-built impact report] with function and test paths | “[Describe the real Bob implementation and show the matched `calculate_total` test and unmatched `authorize_payment`. State that this is a name-based heuristic, not measured test coverage.]” |
| 1:45–2:10 | [Actual Bob IDE task history and screenshots, code diff] | “[Show what Bob changed and how Bob helped review the synthetic patch. Point to the genuine task summaries in the repository.]” |
| 2:10–2:30 | [Public GitHub repository and test output] | “The prototype runs locally with Python’s standard library. The test command and synthetic fixtures are in the repository. [State the actual number of passing tests and any outstanding limits.]” |

## Recording checks

- Screen-record only synthetic data. Close unrelated tabs, personal documents and account details before recording.
- Use legible terminal font and zoom the report enough for paths and lines to be readable.
- Test the public video link in a private or logged-out window before entering it in lablab.
- Do not quote a percentage productivity improvement unless it was measured with a described method.

## Prepare the screens after Bob finishes

Run these in the Bob project folder on Windows (use `python` if `py -3` is unavailable):

```powershell
py -3 patchgate.py --diff fixtures/sample.diff --out demo.html --json demo.json
py -3 patchgate.py --diff fixtures/impact.diff --out impact.html --json impact.json
py -3 -m unittest discover -s tests -v
```

Open `demo.html` and `impact.html` in a browser. At normal zoom, make the report title, file paths and line numbers readable. For the impact shot, show the real call in `tests/test_checkout_example.py:9` and the manual-verification prompt for `authorize_payment` together. Use the actual headings and labels Bob produced; do not narrate an unimplemented control.

Capture the two genuine Bob task summaries together after implementation and review, while both tasks remain accessible in Bob history. Save them as `bob_sessions/task-01-impact.png` and `bob_sessions/task-02-review.png`. These images show Bob participation; the running demo and test output show the product behavior.
