# Bob IDE task: implement change-impact links

Use the hackathon-provisioned IBM Bob IDE account and open this directory as your workspace. This is a real implementation task, not a request for a decorative description.

Prompt to give Bob in Agent mode:

> Extend PatchGate with an evidence-linked change-impact analyzer. Given a unified diff and the local Python repository, identify changed top-level Python functions, find test functions that refer to them by name, and include an `impact` section in the JSON and HTML report. For each relationship, cite the path and line of the changed function and the matching test. Clearly label this as a heuristic: absence of a match is not proof of missing coverage. Add focused tests for renamed files, multiple hunks, false matches in comments, and the current fixture. Do not run arbitrary code from the analyzed repository and do not send its contents to external APIs. Preserve the existing CLI behavior, including `--decisions` and `--check-decisions`. Report exactly what you changed and run the tests.

After Bob completes, inspect its diff and correct errors. Capture the real task session consumption summary in Bob IDE (Tasks → task → task header), then put the PNG in `bob_sessions/`. Do the same for any additional Bob tasks. The final demonstration must show the impact links working on a change where a function has a matching test, and one where it does not.

Use `fixtures/impact.diff` against `examples/checkout/app.py` and `tests/test_checkout_example.py` as the primary acceptance case. `calculate_total` has a matching test call; `authorize_payment` does not. Report this as a name-based heuristic, not a verified coverage result. The existing `fixtures/sample.diff` remains the risk-review demonstration.
