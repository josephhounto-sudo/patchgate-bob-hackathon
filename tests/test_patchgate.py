import unittest
import subprocess
import tempfile
from pathlib import Path
from patchgate import apply_decisions, git_diff, main, parse_diff, render_html, report


FIXTURE = (Path(__file__).resolve().parents[1] / "fixtures" / "sample.diff").read_text()


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
            import json
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


if __name__ == "__main__":
    unittest.main()
