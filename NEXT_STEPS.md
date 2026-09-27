# PatchGate — next engineering decisions (27 September 2026)

## Current evidence

The synthetic fixture demonstrates four pattern prompts and two changed top-level Python functions. A direct call to `calculate_total` appears at `tests/test_checkout_example.py:9`; no direct name match is found for `authorize_payment`. This does not measure executed test coverage or prove a vulnerability.

## Ranked weaknesses

| Priority | Weakness | Consequence | Smallest useful next step |
| --- | --- | --- | --- |
| P0 | Deletion-only function edits are not linked to impact entries. | The list can omit relevant changes. | Map deletions with old-file AST evidence, or report them as unresolved without guessing a function. Keep a test at a neighboring-function boundary. |
| P0 | Same-name calls in unrelated modules can be linked to the wrong changed function. | A test match looks more convincing than the evidence warrants. | Resolve imports where unambiguous; otherwise label the match ambiguous and request human review. |
| P1 | Demo is a local HTML file. | A hackathon judge cannot use the prototype online from a GitHub link alone. | Host an interactive demo that accepts only synthetic examples; validate any uploaded diff before public release. |
| P1 | Pattern rules cover a narrow set of Python-like additions. | Findings may miss other languages, secret formats, and semantics. | Measure precision/recall on a documented, non-sensitive fixture set before broadening rules. |
| P1 | The browser stores decisions locally, with no reviewer identity or trusted audit log. | An export is a portable note, not authenticated approval. | Keep the current honest label; design signed or server-side review only if an actual user needs it. |

## Competition fit

TechEx Amsterdam lists online building for 16–19 October and a submission close at 19:00 UTC on 19 October. Its detailed tracks are still TBA. The general lablab guide expects a usable online prototype, video and pitch deck; it says most events require core AI functionality developed during the event. PatchGate's current deterministic analyzer is neither hosted nor AI-powered. Verify the event-specific rules when published. Do not submit the existing repository as a newly built AI project; preserve its prior history and clearly distinguish any work done during the event.

## Focused prompt for the next coding session

```text
In PatchGate, inspect the current repository and git status first. Work only on impact attribution in patchgate.py and focused tests. Two known limits: deletion-only edits can disappear, and direct test calls can refer to a different module's same-named function.

Choose ONE of these after inspecting the implementation: (A) make deletion-only edits visible as unresolved evidence without assigning an unproven function, OR (B) distinguish unambiguous imported calls from ambiguous same-name calls. Prefer the smaller reliable fix. Add regression tests with adjacent functions or two modules with the same function name, as applicable. Preserve existing JSON fields and HTML escaping. State any remaining ambiguity plainly. Run the full test suite once, show the exact result, git diff --check, and git diff --stat. Do not add an AI feature, hosting, or event claims.
```

This prompt can be run with Bob, Claude, or another coding tool. It is not urgent; no further Bob credits are needed for the current visual correction.
