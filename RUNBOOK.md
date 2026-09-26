# PatchGate — hackathon runbook

## Goal and honest status

Produce a working change-review demonstrator and show a substantial IBM Bob IDE contribution. The baseline CLI, synthetic fixture, automated tests and example report are ready. **No Bob task, Bob screenshot, public repository, video or hackathon submission is claimed yet.** An enterprise-account invitation alone is not proof of Bob work or a team membership.

## Immediate participant actions

1. Open the project directory in IBM Bob IDE using the email registered for the hackathon. In Settings → General, verify the provisioned Bob instance (the guide illustrates `ibm-coding-challenge-uat`, region `us-east`). The IBM Cloud/SaaS invitation's “team member” wording does not establish a lablab team. Do not paste credentials into this project.
2. Run the two commands in `README.md` to establish the baseline. Examine `demo.html`.
3. Give Bob the implementation task in `BOB_TASK.md` in Agent mode. Review Bob's changes, run the tests and reproduce the feature on the synthetic example. Then use `BOB_REVIEW_TASK.md` for a separate Bob task that runs the workflow and writes a grounded review. Bob should contribute to several real steps, not only documentation.
4. Capture each genuine Bob task session consumption summary from the IDE into `bob_sessions/`. Do not substitute a mock screenshot. Exclude any personal account details from publicly shared images if possible.
5. Put the working code, documentation, fixture and genuine evidence in a public source repository only after checking that it contains no secrets, personal data or unrelated work.
6. Record a short product demo using `DEMO_SCRIPT.md`, then complete the submission fields and any participant feedback required by the live hackathon guide. Check the deadline displayed in the actual submission form.
7. Run `python3 preflight.py --video-url <public HTTPS video>` and resolve every BLOCKED line. Manually verify that the repository and video open while logged out, and that the lablab form shows a completed submission.

## Demo script (about 90 seconds)

- Describe the bottleneck: a reviewer must understand what a change touches and which additions need attention.
- Show the synthetic `sample.diff`, then run `python3 patchgate.py --diff fixtures/sample.diff --out demo.html --json demo.json`.
- Show the HTML report: changed-file statistics, numbered findings, severity and next-step text. Mark one issue **Needs fix** and one **Reviewed**, then export the decisions JSON. Stress that findings are review prompts, not proven vulnerabilities.
- Reimport the exported JSON with `--decisions --check-decisions`. Show exit code 3 while a fix remains; explain that this checks review decisions, not code safety.
- After Bob's feature is implemented, show an evidence-linked function-to-test impact relationship and one unmatched function; explain the heuristic's limits.
- Show the genuine Bob session evidence and state exactly which feature Bob implemented. Close with what remains manual and what would improve in a longer build.

## Measurable evaluation (do not invent results)

For one synthetic change, have a reviewer find all configured risky additions and identify potentially affected tests without the tool, then repeat with PatchGate. Record elapsed time, correctly located findings, false alerts and links that required correction. The fixture intentionally has four rule hits; this is not a benchmark result. If there is no controlled comparison, report only functional counts and test outcomes, not a percentage time saving.

## Time boundary

The official lablab event page currently states Sunday **27 September 2026 at 15:00 UTC** as the submission close. Target a completed submission by **12:00 UTC** to leave room for upload and form failures. Keep the separate Matter to Life application (1 October) on track; PatchGate does not use Sentinelle, patient records or other private dossiers.
