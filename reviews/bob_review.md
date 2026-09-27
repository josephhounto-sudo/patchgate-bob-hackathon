# PatchGate — Bob IDE Review Session

**Reviewer:** Bob (IBM Bob IDE)  
**Date:** 2026-09-27  
**Branch:** main  
**Diff reviewed:** `fixtures/sample.diff` (sample), `fixtures/impact.diff` (impact)

---

## Commands and observed output

```
$ python3 -m unittest discover -s tests -v
...
Ran 52 tests in 0.989s
OK

$ python3 patchgate.py --diff fixtures/sample.diff --out demo.html --json demo.json
REVIEW REQUIRED | 4 findings | open: 4 | demo.html

$ python3 patchgate.py --diff fixtures/impact.diff --out impact.html --json impact.json
READY FOR HUMAN REVIEW | 0 findings | open: 0 | impact.html
```

---

## Sample diff — four findings (fixtures/sample.diff)

| # | Rule | Path | Line | Severity |
|---|------|------|------|----------|
| 1 | `hardcoded-secret` | `app.py` | 4 | critical |
| 2 | `todo-marker` | `app.py` | 5 | low |
| 3 | `subprocess-shell` | `app.py` | 6 | high |
| 4 | `broad-exception` | `app.py` | 9 | medium |

All four findings are synthetic (fake credential, deliberate TODO, shell=True, bare except). Status: **REVIEW REQUIRED** (highest severity: critical).

---

## Impact diff — function change evidence (fixtures/impact.diff)

### calculate_total

```json
{
  "function": "calculate_total",
  "source_path": "examples/checkout/app.py",
  "source_line": 6,
  "analysis_method": "ast_name_reference",
  "test_matches": [
    {
      "test_path": "tests/test_checkout_example.py",
      "test_line": 9
    }
  ],
  "result": "name_match_found",
  "limitations": "This is a static name-based heuristic. It cannot confirm the test exercises the changed lines, cannot detect indirect calls or dynamic dispatch, and cannot substitute for runtime coverage or manual review."
}
```

Line 9 of `tests/test_checkout_example.py` is a direct `ast.Call` expression inside `test_calculate_total_rounds_to_cents`. The import at line 4 was deliberately excluded — imports alone do not demonstrate that the changed lines are exercised.

### authorize_payment

```json
{
  "function": "authorize_payment",
  "source_path": "examples/checkout/app.py",
  "source_line": 11,
  "analysis_method": "ast_name_reference",
  "test_matches": [],
  "result": "no_name_match",
  "limitations": "This is a static name-based heuristic. It cannot confirm the test exercises the changed lines, cannot detect indirect calls or dynamic dispatch, and cannot substitute for runtime coverage or manual review."
}
```

No test function in any `test_*.py` file under the repository contains a call expression whose callee is `authorize_payment`. **This is a prompt for manual verification, not a statement that the function is untested or that coverage is absent.**

---

## Release decision

The sample diff contains a synthetic hardcoded credential (`demo_not_real_key_12345`) and a shell-enabled subprocess. Both are intentional demonstration artefacts; neither is a real secret. The impact diff modifies two checkout functions using only safe arithmetic. No external dependencies are introduced. All 52 unit tests pass.

**Decision: SYNTHETIC DEMO — acceptable for publication to the hackathon repository. Not a production release.**

A real release would require:
- Resolving every `needs-fix` finding before merging.
- Human confirmation that `authorize_payment` is covered by an integration or system test, or adding a unit test for it.
- Exporting and committing the decision JSON so the gate is auditable.

---

## Limitations recorded

1. **`find_test_references` detects `ast.Call` callees only.** It cannot detect indirect calls (`apply(f, args)`), dynamic dispatch (`getattr(obj, name)()`), or calls made through a local alias (`fn = calculate_total; fn(x)`).
2. **Deletion-only hunks are unsupported for changed-function detection.** A hunk that contains only `-` lines and no `+` lines produces no entries in `touched_lines` (removed lines have no new-file number), so a function whose entire body was deleted will not appear in the impact list. This is a known, recorded limitation.
3. **Only `.py` files and `test_*.py` / `*_test.py` naming conventions are supported.**
4. **No runtime coverage is claimed.** A name match at a call site does not prove the test exercises the changed lines; it is a structural heuristic only.
5. **`result: "no_name_match"` does not mean a function lacks test coverage.** It means no matching call expression was found statically. Tests exercising the function through higher-level code will not be detected.
