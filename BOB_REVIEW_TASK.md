# Bob IDE task 2: use PatchGate in a review workflow

Run this after `BOB_TASK.md` has produced real impact links and its tests pass. Keep this as a separate Bob IDE task so the second task session summary can be captured.

Prompt for Bob Agent mode:

> Act as a release reviewer of the synthetic PatchGate examples. First run the project tests and generate a report for `fixtures/sample.diff`. Inspect each of its four configured findings and record what the evidence does and does not establish. Next generate a report for `fixtures/impact.diff` using the impact feature you implemented. Verify with file and line references that `calculate_total` has a name-based test match and `authorize_payment` has no match. Write `reviews/bob_review.md` with a concise release decision, an ordered manual verification plan, exact commands and outputs you actually observed, and a limitations section. Do not claim runtime coverage or a measured time saving. Do not use external services, credentials, personal information, patient data or unrelated projects. Do not alter the fixture merely to make the report pass. If any expectation fails, diagnose it, make a focused correction to the code, rerun the tests and record the before/after evidence.

Review the generated file and the actual command output. Save a genuine task session summary screenshot under `bob_sessions/` with an unambiguous task number. If Bob cannot execute a step, record the limitation honestly instead of inventing the output.
