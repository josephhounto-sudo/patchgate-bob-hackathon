import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from patchgate import (
    apply_decisions,
    build_impact,
    detect_changed_functions,
    find_test_references,
    git_diff,
    main,
    parse_diff,
    render_html,
    report,
)

FIXTURE = (Path(__file__).resolve().parents[1] / "fixtures" / "sample.diff").read_text()
PROJECT_ROOT = Path(__file__).resolve().parents[1]
IMPACT_DIFF = (PROJECT_ROOT / "fixtures" / "impact.diff").read_text()


# ---------------------------------------------------------------------------
# Existing tests (preserved exactly)
# ---------------------------------------------------------------------------

class PatchGateTests(unittest.TestCase):
    def test_line_numbers_and_severities(self):
        findings, stats = parse_diff(FIXTURE)
        self.assertEqual(stats, {"files": 1, "added": 7, "removed": 0})
        self.assertIn(("hardcoded-secret", 4), {(f.rule, f.line) for f in findings})
        self.assertIn(("subprocess-shell", 6), {(f.rule, f.line) for f in findings})
        self.assertEqual(report(FIXTURE, "sample")["status"], "REVIEW REQUIRED")
        self.assertNotIn("demo_not_real_key_12345", render_html(report(FIXTURE, "sample")))

    def test_html_escapes_untrusted_diff(self):
        malicious = FIXTURE.replace("# TODO:", "# TODO: <script>alert(1)</script>")
        page = render_html(report(malicious, "<script>"))
        self.assertEqual(page.count("<script>"), 1)  # the app's own static script
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;", page)

    def test_multiple_hunks_renamed_path_and_exception_alias(self):
        diff = ("diff --git a/old.py b/new.py\nrename from old.py\nrename to new.py\n"
                "--- a/old.py\n+++ b/new.py\n@@ -2,0 +3,2 @@\n+safe = 1\n+except Exception as error:\n"
                "@@ -20,0 +25 @@\n+eval(input_value)\n")
        findings, stats = parse_diff(diff)
        self.assertEqual([(f.rule, f.path, f.line) for f in findings],
                         [("broad-exception", "new.py", 4), ("unsafe-eval", "new.py", 25)])
        self.assertEqual(stats, {"files": 1, "added": 3, "removed": 0})

    def test_added_source_line_beginning_with_two_plus_signs(self):
        diff = "diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -0,0 +1 @@\n+++TODO = 1\n"
        findings, stats = parse_diff(diff)
        self.assertEqual(stats["added"], 1)
        self.assertEqual([(f.rule, f.line) for f in findings], [("todo-marker", 1)])

    def test_impact_acceptance_fixture_is_a_valid_baseline_diff(self):
        project = Path(__file__).resolve().parents[1]
        fixture_path = project / "fixtures" / "impact.diff"
        findings, stats = parse_diff(fixture_path.read_text())
        self.assertEqual(stats, {"files": 1, "added": 3, "removed": 2})
        self.assertEqual(findings, [])
        current = (project / "examples" / "checkout" / "app.py").read_text()
        previous = (current.replace('    tax = subtotal * tax_rate\n    return (subtotal + tax).quantize(Decimal("0.01"))',
                                    '    return subtotal + subtotal * tax_rate')
                    .replace('    return amount > Decimal("0.00")',
                             '    return amount >= Decimal("0.00")'))
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "examples" / "checkout" / "app.py"
            target.parent.mkdir(parents=True)
            target.write_text(previous)
            subprocess.run(["git", "apply", str(fixture_path)], cwd=directory, check=True,
                           capture_output=True)
            self.assertEqual(target.read_text(), current)

    def test_git_repository_end_to_end(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            def git(*args):
                subprocess.run(["git", "-C", str(repo), *args], check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            git("init", "-q")
            git("config", "user.name", "PatchGate Test")
            git("config", "user.email", "patchgate@example.invalid")
            marker = repo / "textconv-ran"
            git("config", "diff.demo.textconv", f"sh -c 'touch {marker}'")
            (repo / ".gitattributes").write_text("app.py diff=demo\n")
            source = repo / "app.py"
            source.write_text("value = 1\n")
            git("add", "app.py", ".gitattributes")
            git("commit", "-qm", "baseline")
            source.write_text("value = 1\n# TODO: review this\n")
            (repo / "untracked.py").write_text("eval(untrusted)\n")
            data = report(git_diff(repo, None), "repo")
            self.assertEqual([(f["path"], f["line"], f["rule"]) for f in data["findings"]],
                             [("app.py", 2, "todo-marker")])
            self.assertEqual(data["stats"]["files"], 1)
            self.assertFalse(marker.exists(), "Git textconv must not run during inspection")

    def test_decision_round_trip_and_gate(self):
        data = report(FIXTURE, "sample")
        exported = {"report_id": data["report_id"], "decisions": [
            {"path": f["path"], "line": f["line"], "rule": f["rule"],
             "decision": "fix" if i == 0 else "accepted"}
            for i, f in enumerate(data["findings"])
        ]}
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            diff_file = folder / "sample.diff"
            decision_file = folder / "decisions.json"
            out = folder / "review.html"
            result = folder / "review.json"
            diff_file.write_text(FIXTURE)
            decision_file.write_text(json.dumps(exported))
            self.assertEqual(main(["--diff", str(diff_file), "--decisions", str(decision_file),
                                   "--check-decisions", "--out", str(out), "--json", str(result)]), 3)
            loaded = json.loads(result.read_text())
            self.assertEqual(loaded["review_summary"], {"accepted": 3, "fix": 1, "pending": 0})
            self.assertIn('data-initial="fix"', out.read_text())
            exported["decisions"][0]["decision"] = "accepted"
            decision_file.write_text(json.dumps(exported))
            self.assertEqual(main(["--diff", str(diff_file), "--decisions", str(decision_file),
                                   "--check-decisions", "--out", str(out)]), 0)

    def test_rejects_decisions_from_other_diff_or_unknown_findings(self):
        data = report(FIXTURE, "sample")
        entries = [{"path": f["path"], "line": f["line"], "rule": f["rule"],
                    "decision": "accepted"} for f in data["findings"]]
        with self.assertRaisesRegex(ValueError, "report_id mismatch"):
            apply_decisions(data, {"report_id": "wrong", "decisions": entries})
        entries[0]["line"] = 999
        with self.assertRaisesRegex(ValueError, "do not match"):
            apply_decisions(data, {"report_id": data["report_id"], "decisions": entries})

    def test_invalid_decisions_do_not_create_report(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            source = folder / "change.diff"
            decisions = folder / "invalid.json"
            output = folder / "review.html"
            source.write_text(FIXTURE)
            decisions.write_text('{"report_id": "stale", "decisions": []}')
            with self.assertRaises(SystemExit) as failure:
                main(["--diff", str(source), "--decisions", str(decisions), "--out", str(output)])
            self.assertEqual(failure.exception.code, 2)
            self.assertFalse(output.exists())

    def test_deleted_line_is_not_a_finding(self):
        diff = "diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-password = 'real_looking_secret'\n+safe = 1\n"
        self.assertEqual(parse_diff(diff)[0], [])

    def test_comment_only_code_examples_are_not_high_risk_findings(self):
        diff = ("diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -0,0 +1,3 @@\n"
                "+# eval(sample) is unsafe\n+// shell=True example\n+# TODO: review examples\n")
        findings, _ = parse_diff(diff)
        self.assertEqual([(f.rule, f.line) for f in findings], [("todo-marker", 3)])

    def test_secret_stays_masked_when_same_line_has_other_findings(self):
        diff = "diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -0,0 +1 @@\n+password = 'really_private_123'; eval(user_input)  # TODO\n"
        output = report(diff, "mixed")
        self.assertEqual({f["rule"] for f in output["findings"]},
                         {"hardcoded-secret", "unsafe-eval", "todo-marker"})
        self.assertNotIn("really_private_123", str(output))
        self.assertNotIn("really_private_123", render_html(output))


# ---------------------------------------------------------------------------
# Feature 1 & 2: detect_changed_functions / find_test_references unit tests
# ---------------------------------------------------------------------------

class DetectChangedFunctionsTests(unittest.TestCase):

    def _make_repo(self, tmpdir: str) -> tuple[Path, Path]:
        """Write a synthetic Python source file and return (repo_root, src_path)."""
        root = Path(tmpdir)
        src = root / "mymodule.py"
        src.write_text(
            "def alpha():\n"          # line 1
            "    return 1\n"          # line 2
            "\n"                      # line 3
            "def beta():\n"           # line 4
            "    return 2\n"          # line 5
            "\n"                      # line 6
            "def gamma():\n"          # line 7
            "    return 3\n",         # line 8
            encoding="utf-8",
        )
        return root, src

    def test_single_function_in_hunk(self):
        """A diff touching only beta's body should identify only beta."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root, _ = self._make_repo(tmpdir)
            diff = (
                "diff --git a/mymodule.py b/mymodule.py\n"
                "--- a/mymodule.py\n+++ b/mymodule.py\n"
                "@@ -4,2 +4,2 @@\n"
                " def beta():\n"
                "-    return 2\n"
                "+    return 99\n"
            )
            changed = detect_changed_functions(diff, root)
            self.assertEqual([(c.name, c.source_line) for c in changed], [("beta", 4)])

    def test_multiple_hunks_multiple_functions(self):
        """Two hunks in one diff, each touching a different function."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root, _ = self._make_repo(tmpdir)
            diff = (
                "diff --git a/mymodule.py b/mymodule.py\n"
                "--- a/mymodule.py\n+++ b/mymodule.py\n"
                "@@ -1,2 +1,2 @@\n"
                " def alpha():\n"
                "-    return 1\n"
                "+    return 10\n"
                "@@ -7,2 +7,2 @@\n"
                " def gamma():\n"
                "-    return 3\n"
                "+    return 30\n"
            )
            changed = detect_changed_functions(diff, root)
            names = {c.name for c in changed}
            self.assertIn("alpha", names)
            self.assertIn("gamma", names)
            self.assertNotIn("beta", names)

    def test_renamed_or_moved_file_not_on_disk_is_skipped(self):
        """If the destination path does not exist on disk, no crash and no result."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            diff = (
                "diff --git a/old.py b/renamed_gone.py\n"
                "--- a/old.py\n+++ b/renamed_gone.py\n"
                "@@ -1,1 +1,1 @@\n"
                "-def foo(): pass\n"
                "+def foo(): return 1\n"
            )
            # renamed_gone.py does not exist in tmpdir
            changed = detect_changed_functions(diff, root)
            self.assertEqual(changed, [])

    def test_non_python_file_skipped(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "README.md").write_text("# hello\n")
            diff = (
                "diff --git a/README.md b/README.md\n"
                "--- a/README.md\n+++ b/README.md\n"
                "@@ -1,1 +1,1 @@\n"
                "-# hello\n"
                "+# hi\n"
            )
            self.assertEqual(detect_changed_functions(diff, root), [])

    def test_source_line_is_function_definition_line(self):
        """source_line must be the def line, not a body line."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "mod.py").write_text(
                "x = 1\n"            # line 1
                "\n"                  # line 2
                "def my_func():\n"   # line 3
                "    pass\n",         # line 4
                encoding="utf-8",
            )
            diff = (
                "diff --git a/mod.py b/mod.py\n"
                "--- a/mod.py\n+++ b/mod.py\n"
                "@@ -4,1 +4,1 @@\n"
                "-    pass\n"
                "+    return 42\n"
            )
            changed = detect_changed_functions(diff, root)
            self.assertEqual(len(changed), 1)
            self.assertEqual(changed[0].name, "my_func")
            self.assertEqual(changed[0].source_line, 3)

    def test_neighboring_unchanged_function_not_detected(self):
        """A context line in a hunk must not cause an unchanged neighboring function
        to be identified as changed.

        This is the regression for the bug where context lines (`` ``) were added to
        the touched-lines set, causing any function whose definition appeared as a
        context line in the same hunk to be falsely reported as changed.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            # Two adjacent functions; only first is changed.
            (root / "svc.py").write_text(
                "def first():\n"       # line 1
                "    return 1\n"       # line 2
                "\n"                   # line 3
                "def second():\n"      # line 4
                "    return 2\n",      # line 5
                encoding="utf-8",
            )
            # The hunk touches only first(); second() appears only as a context line.
            diff = (
                "diff --git a/svc.py b/svc.py\n"
                "--- a/svc.py\n+++ b/svc.py\n"
                "@@ -1,4 +1,4 @@\n"
                " def first():\n"         # context, new_line=1
                "-    return 1\n"         # removed
                "+    return 10\n"        # added, new_line=2
                " \n"                     # context, new_line=3
                " def second():\n"        # context — must NOT mark second() as changed
            )
            changed = detect_changed_functions(diff, root)
            names = {c.name for c in changed}
            self.assertIn("first", names, "first() has an added line and must be detected")
            self.assertNotIn("second", names,
                             "second() only appears as a context line and must NOT be detected")


class FindTestReferencesTests(unittest.TestCase):

    def test_structural_reference_found(self):
        """A function call in a test file must be found."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            tests_dir = root / "tests"
            tests_dir.mkdir()
            (tests_dir / "test_foo.py").write_text(
                "def test_something():\n"
                "    result = my_func()\n"   # line 2 — Name node
                "    assert result == 1\n",
                encoding="utf-8",
            )
            matches = find_test_references("my_func", root)
            self.assertTrue(any(m.test_path.endswith("test_foo.py") for m in matches))
            lines = [m.test_line for m in matches if m.test_path.endswith("test_foo.py")]
            self.assertIn(2, lines)

    def test_comment_reference_excluded(self):
        """A name that appears only in a comment must not produce a match."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            tests_dir = root / "tests"
            tests_dir.mkdir()
            (tests_dir / "test_bar.py").write_text(
                "# Tests for my_func\n"         # line 1 — comment, excluded
                "def test_nothing():\n"          # line 2
                "    pass\n",                    # line 3
                encoding="utf-8",
            )
            matches = find_test_references("my_func", root)
            self.assertEqual(matches, [])

    def test_string_literal_reference_excluded(self):
        """A name inside a string literal must not produce a match."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            tests_dir = root / "tests"
            tests_dir.mkdir()
            (tests_dir / "test_str.py").write_text(
                'def test_nothing():\n'
                '    assert "my_func" == "my_func"\n'  # line 2 — string literal
                '    pass\n',
                encoding="utf-8",
            )
            matches = find_test_references("my_func", root)
            self.assertEqual(matches, [])

    def test_call_inside_test_function_found(self):
        """A call inside a test function body must be found; the import must not be."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            tests_dir = root / "tests"
            tests_dir.mkdir()
            (tests_dir / "test_import.py").write_text(
                "from mymodule import calculate_total\n"  # line 1 — import only
                "\n"                                      # line 2
                "def test_it():\n"                        # line 3
                "    calculate_total(1, 2)\n",            # line 4 — call site
                encoding="utf-8",
            )
            matches = find_test_references("calculate_total", root)
            # The call at line 4 must be found.
            lines = [m.test_line for m in matches if "test_import.py" in m.test_path]
            self.assertIn(4, lines, "Expected call at line 4 to be found")
            # The import at line 1 must NOT be a separate match entry.
            self.assertNotIn(1, lines, "Import-only line must not appear as a match")

    def test_import_alone_does_not_count_as_match(self):
        """A test file that imports the function but never calls it must return no matches."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            tests_dir = root / "tests"
            tests_dir.mkdir()
            (tests_dir / "test_import_only.py").write_text(
                "from mymodule import my_func\n"  # line 1 — import, no call
                "\n"
                "def test_nothing():\n"
                "    pass\n",
                encoding="utf-8",
            )
            matches = find_test_references("my_func", root)
            self.assertEqual(matches, [], "Import-only reference must not produce a match")

    def test_assignment_without_call_is_not_a_match(self):
        """Assigning the target function to a variable inside a test function
        must not count as a match.  Only call expressions qualify.

        E.g.  ``fn = calculate_total``  is NOT a match;
              ``result = calculate_total(x)``  IS a match.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            tests_dir = root / "tests"
            tests_dir.mkdir()
            (tests_dir / "test_assign.py").write_text(
                "def test_nothing():\n"          # line 1
                "    fn = my_func\n"             # line 2 — name, no call
                "    assert fn is not None\n",   # line 3
                encoding="utf-8",
            )
            matches = find_test_references("my_func", root)
            self.assertEqual(matches, [],
                             "Variable assignment without a call must not produce a match")

    def test_no_test_files_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            # No test files at all
            matches = find_test_references("any_func", root)
            self.assertEqual(matches, [])


# ---------------------------------------------------------------------------
# Feature 3: Impact section in JSON report
# ---------------------------------------------------------------------------

class ImpactAcceptanceFixtureTests(unittest.TestCase):
    """Acceptance criteria for the impact.diff fixture."""

    def setUp(self):
        self.impact = build_impact(IMPACT_DIFF, PROJECT_ROOT)
        self.by_name = {e["function"]: e for e in self.impact}

    def test_calculate_total_present(self):
        self.assertIn("calculate_total", self.by_name)

    def test_authorize_payment_present(self):
        self.assertIn("authorize_payment", self.by_name)

    def test_calculate_total_source_path(self):
        entry = self.by_name["calculate_total"]
        self.assertEqual(entry["source_path"], "examples/checkout/app.py")

    def test_calculate_total_source_line(self):
        entry = self.by_name["calculate_total"]
        # The function def is at line 6 of examples/checkout/app.py
        self.assertEqual(entry["source_line"], 6)

    def test_calculate_total_has_test_match_to_test_checkout_example(self):
        entry = self.by_name["calculate_total"]
        self.assertTrue(len(entry["test_matches"]) > 0, "Expected at least one test match")
        paths = [m["test_path"] for m in entry["test_matches"]]
        self.assertTrue(
            any("test_checkout_example.py" in p for p in paths),
            f"Expected tests/test_checkout_example.py in matches, got: {paths}",
        )

    def test_calculate_total_match_is_call_at_line_9_not_import(self):
        """The match must point to the call site (line 9), not the import (line 4)."""
        entry = self.by_name["calculate_total"]
        checkout_matches = [
            m for m in entry["test_matches"]
            if "test_checkout_example.py" in m["test_path"]
        ]
        lines = [m["test_line"] for m in checkout_matches]
        self.assertIn(9, lines, f"Expected call-site line 9, got lines: {lines}")
        self.assertNotIn(4, lines, "Import at line 4 must not appear as a match")

    def test_calculate_total_result_not_no_name_match(self):
        entry = self.by_name["calculate_total"]
        self.assertNotEqual(entry["result"], "no_name_match")

    def test_authorize_payment_no_name_match(self):
        entry = self.by_name["authorize_payment"]
        self.assertEqual(entry["result"], "no_name_match")

    def test_authorize_payment_empty_test_matches(self):
        entry = self.by_name["authorize_payment"]
        self.assertEqual(entry["test_matches"], [])

    def test_limitations_field_present_on_all_entries(self):
        for entry in self.impact:
            self.assertIn("limitations", entry, f"Missing 'limitations' on {entry['function']}")
            self.assertTrue(len(entry["limitations"]) > 0)

    def test_analysis_method_field(self):
        for entry in self.impact:
            self.assertEqual(entry["analysis_method"], "ast_name_reference")

    def test_report_impact_key_present(self):
        data = report(IMPACT_DIFF, "impact", repo_root=PROJECT_ROOT)
        self.assertIn("impact", data)
        self.assertIsInstance(data["impact"], list)

    def test_report_without_repo_root_has_empty_impact(self):
        data = report(IMPACT_DIFF, "impact")
        self.assertEqual(data["impact"], [])


# ---------------------------------------------------------------------------
# Feature 4: HTML Change Impact Evidence section
# ---------------------------------------------------------------------------

class HtmlImpactSectionTests(unittest.TestCase):

    def test_deletions_are_called_out_for_manual_review(self):
        page = render_html(report(IMPACT_DIFF, "impact", repo_root=PROJECT_ROOT))
        self.assertIn("Manual review needed", page)
        self.assertIn("deletion-only function changes", page)
        clean_page = render_html(report(FIXTURE, "sample"))
        self.assertNotIn("deletion-only function changes", clean_page)

    def test_impact_section_heading_present(self):
        data = report(IMPACT_DIFF, "impact", repo_root=PROJECT_ROOT)
        page = render_html(data)
        self.assertIn("Change Impact Evidence", page)

    def test_heuristic_label_present(self):
        data = report(IMPACT_DIFF, "impact", repo_root=PROJECT_ROOT)
        page = render_html(data)
        self.assertIn("Name-based heuristic", page)
        self.assertIn("not a coverage report", page)

    def test_impact_section_appears_before_findings_section(self):
        data = report(IMPACT_DIFF, "impact", repo_root=PROJECT_ROOT)
        page = render_html(data)
        impact_pos = page.find("Change Impact Evidence")
        findings_pos = page.find("<h2>Findings</h2>")
        self.assertLess(impact_pos, findings_pos)

    def test_authorize_payment_shown_with_manual_verification_prompt(self):
        data = report(IMPACT_DIFF, "impact", repo_root=PROJECT_ROOT)
        page = render_html(data)
        self.assertIn("authorize_payment", page)
        self.assertIn("manual verification", page)

    def test_authorize_payment_not_described_as_proof_of_missing_coverage(self):
        data = report(IMPACT_DIFF, "impact", repo_root=PROJECT_ROOT)
        page = render_html(data)
        # Must not positively assert coverage is absent or that the function is untested.
        # "does not prove the function is untested" is the correct honest phrasing (allowed);
        # claiming "no coverage" or "missing coverage" as fact is not allowed.
        self.assertNotIn("no coverage", page)
        self.assertNotIn("missing coverage", page)
        # Must not contain a bare positive claim that the function is untested.
        self.assertNotIn("is untested", page)
        self.assertNotIn("confirmed untested", page)

    def test_function_names_are_html_escaped(self):
        """Function names with special chars must be escaped."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            # Synthesise a source file with a harmless name, then patch the impact list
            (root / "mod.py").write_text("def safe_func():\n    pass\n")
            # Build a fake impact entry with a name that would be dangerous unescaped
            data = report(IMPACT_DIFF, "impact", repo_root=PROJECT_ROOT)
            # Inject a dangerous function name directly to test escaping
            data["impact"].append({
                "function": "<script>alert(1)</script>",
                "source_path": "mod.py",
                "source_line": 1,
                "test_matches": [],
                "result": "no_name_match",
                "analysis_method": "ast_name_reference",
                "limitations": "test",
            })
            page = render_html(data)
            self.assertNotIn("<script>alert(1)</script>", page)
            self.assertIn("&lt;script&gt;", page)

    def test_test_path_reference_format(self):
        """Test match references must be in path:line format with the call-site line."""
        data = report(IMPACT_DIFF, "impact", repo_root=PROJECT_ROOT)
        page = render_html(data)
        # calculate_total must show the call at line 9, not the import at line 4.
        self.assertIn("test_checkout_example.py:9", page)
        self.assertNotIn("test_checkout_example.py:4", page)

    def test_empty_impact_list_renders_section(self):
        """Even with no impact data the section header must appear."""
        data = report(FIXTURE, "sample")  # no repo_root → empty impact
        page = render_html(data)
        self.assertIn("Change Impact Evidence", page)
        self.assertIn("No Python function changes detected", page)


# ---------------------------------------------------------------------------
# Feature 6: Additional edge-case and regression tests
# ---------------------------------------------------------------------------

class EdgeCaseImpactTests(unittest.TestCase):

    def test_diff_with_multiple_hunks_same_file(self):
        """Two hunks in one diff, each spanning a different function, both detected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "svc.py").write_text(
                "def process(x):\n"       # line 1
                "    return x * 2\n"      # line 2
                "\n"                      # line 3
                "def validate(x):\n"      # line 4
                "    return x > 0\n",     # line 5
                encoding="utf-8",
            )
            diff = (
                "diff --git a/svc.py b/svc.py\n"
                "--- a/svc.py\n+++ b/svc.py\n"
                "@@ -1,2 +1,2 @@\n"
                " def process(x):\n"
                "-    return x * 2\n"
                "+    return x * 3\n"
                "@@ -4,2 +4,2 @@\n"
                " def validate(x):\n"
                "-    return x > 0\n"
                "+    return x >= 0\n"
            )
            changed = detect_changed_functions(diff, root)
            names = {c.name for c in changed}
            self.assertIn("process", names)
            self.assertIn("validate", names)

    def test_comment_and_string_only_references_excluded(self):
        """Names appearing only in comments/strings must not appear as test matches."""
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            tests_dir = root / "tests"
            tests_dir.mkdir()
            (tests_dir / "test_noise.py").write_text(
                '# authorize_payment is called by checkout\n'   # comment
                'DOC = "authorize_payment usage example"\n'      # string
                'def test_nothing():\n'
                '    pass\n',
                encoding="utf-8",
            )
            matches = find_test_references("authorize_payment", root)
            self.assertEqual(matches, [])

    def test_decisions_workflow_preserved_with_new_code_paths(self):
        """The --decisions workflow and exit codes must work unchanged."""
        with tempfile.TemporaryDirectory() as tmpdir:
            folder = Path(tmpdir)
            diff_file = folder / "sample.diff"
            decision_file = folder / "decisions.json"
            out = folder / "review.html"
            result_json = folder / "review.json"
            diff_file.write_text(FIXTURE)
            # Build valid decisions for all findings
            data = report(FIXTURE, "sample")
            exported = {
                "report_id": data["report_id"],
                "decisions": [
                    {"path": f["path"], "line": f["line"], "rule": f["rule"], "decision": "accepted"}
                    for f in data["findings"]
                ],
            }
            decision_file.write_text(json.dumps(exported))
            exit_code = main([
                "--diff", str(diff_file),
                "--decisions", str(decision_file),
                "--check-decisions",
                "--out", str(out),
                "--json", str(result_json),
            ])
            # All accepted → exit 0
            self.assertEqual(exit_code, 0)
            loaded = json.loads(result_json.read_text())
            self.assertEqual(loaded["review_summary"]["accepted"], len(data["findings"]))
            self.assertEqual(loaded["review_summary"]["pending"], 0)
            self.assertEqual(loaded["review_summary"]["fix"], 0)

    def test_exit_code_3_when_fix_pending(self):
        """Exit code 3 when at least one finding requires a fix."""
        with tempfile.TemporaryDirectory() as tmpdir:
            folder = Path(tmpdir)
            diff_file = folder / "s.diff"
            decision_file = folder / "d.json"
            out = folder / "r.html"
            diff_file.write_text(FIXTURE)
            data = report(FIXTURE, "sample")
            exported = {
                "report_id": data["report_id"],
                "decisions": [
                    {"path": f["path"], "line": f["line"], "rule": f["rule"],
                     "decision": "fix" if i == 0 else "accepted"}
                    for i, f in enumerate(data["findings"])
                ],
            }
            decision_file.write_text(json.dumps(exported))
            exit_code = main([
                "--diff", str(diff_file),
                "--decisions", str(decision_file),
                "--check-decisions",
                "--out", str(out),
            ])
            self.assertEqual(exit_code, 3)

    def test_impact_diff_end_to_end_json_keys(self):
        """End-to-end: impact.diff via CLI produces JSON with correct impact keys."""
        with tempfile.TemporaryDirectory() as tmpdir:
            folder = Path(tmpdir)
            out_html = folder / "impact.html"
            out_json = folder / "impact.json"
            exit_code = main([
                "--diff", str(PROJECT_ROOT / "fixtures" / "impact.diff"),
                "--out", str(out_html),
                "--json", str(out_json),
                "--repo-root", str(PROJECT_ROOT),
            ])
            self.assertEqual(exit_code, 0)
            loaded = json.loads(out_json.read_text())
            self.assertIn("impact", loaded)
            by_name = {e["function"]: e for e in loaded["impact"]}
            self.assertIn("calculate_total", by_name)
            self.assertIn("authorize_payment", by_name)
            ct = by_name["calculate_total"]
            ap = by_name["authorize_payment"]
            # calculate_total must link to test_checkout_example.py
            self.assertTrue(
                any("test_checkout_example.py" in m["test_path"] for m in ct["test_matches"]),
                f"No link to test_checkout_example.py: {ct['test_matches']}",
            )
            # authorize_payment must have no_name_match
            self.assertEqual(ap["result"], "no_name_match")


if __name__ == "__main__":
    unittest.main()
