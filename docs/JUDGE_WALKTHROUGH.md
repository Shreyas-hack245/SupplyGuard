# Showing SupplyGuard to the judges

The story to tell, in one line: **SupplyGuard does not count vulnerabilities. It decides which ones your application can actually reach, and fixes those first.**

Run `scripts/preflight.sh` before you walk up to the judges. Every line it prints should be `[OK]`. If it prints `[FAIL]` for OSV.dev, do not start the demo until that is fixed, because every result depends on live vulnerability data.

## 1. Setup (about 3 minutes, do it before judging)

```bash
cd supplyguard
pip install -r backend/requirements.txt
export GITHUB_TOKEN=ghp_xxx          # fine-grained token: Contents: read/write, Pull requests: read/write, on ONE test repo
./scripts/preflight.sh
./run.sh                             # dashboard at http://localhost:8000
```

Create a test repository on GitHub and push `examples/vulnerable-app/` to it (it needs `package.json` and `package-lock.json` at the root). This is the repo the PR will target.

## 2. The flow to show (about 5 minutes)

**a. Scan the SBOM first.** Upload `examples/vulnerable-app/sbom.cdx.json` under "Scan SBOM".
Point out the **data banner** at the top. It says LIVE, PARTIAL, or UNAVAILABLE, and the score is withheld unless the data is live. Say: "Most scanners show you a number even when the vulnerability database is down. This one refuses to give you a false all-clear."

**b. Scan the repository.** Zip the folder (`cd examples && zip -r vulnerable-app.zip vulnerable-app -x '*/node_modules/*'`) and upload it under "Scan repository". This is the important step: an SBOM alone cannot say whether code is reachable. The repository scan can.

**c. Show the prioritized table.** Sorted by risk score, not CVSS. Point to the highest-priority finding and to any finding marked NOT_REACHABLE. Say: "This one has a high CVSS score, but our code never loads this package, so it is capped at 39 and shown as LOW. Fix that one last."

**d. Open a finding.** Click a row. Show three things:
- **Why is this risky?** The import path, for example `src/server.js -> src/routes/users.js -> src/services/parser.js -> lodash`. This is the proof, not an assertion. Walk the judges along it.
- **Risk breakdown.** Every point is attributed to a named factor (CVSS, reachability, exploit status, exposure, direct/transitive, fix availability, depth). Nothing is a black box.
- **Recommended fix** and the exact command.

**e. Show the confidence and the limits.** Point at the `confidence` field and the Limitations section. Say: "We state that reachability is package-level. We would rather tell you what we cannot prove than overclaim."

**f. Create the remediation PR.** Enter the owner and repo of your test repository and click "Create remediation PR". The server:
1. fetches `package.json` and `package-lock.json` from GitHub,
2. patches the version and regenerates the lockfile with `npm install --package-lock-only --ignore-scripts`, which runs no project code,
3. re-queries OSV.dev for the patched version and **refuses to open the PR if the vulnerability is still reported**,
4. creates a `security/fix-<CVE>` branch, commits, and opens the PR.

Open the PR on GitHub and show the body: the reason, the reachability path, the verification results, and "requires human review. It has not been merged."

**g. Show before and after.** The "after" numbers come from rescanning the patched lockfile, not from a hardcoded value. Say: "These numbers are recomputed, not decorative."

## 3. Commands to show the engine without the browser

```bash
python -m app.cli scan examples/vulnerable-app --out reports/   # terminal table + report.md + report.json
python -m pytest -q backend/tests                               # 48 tests, including the refusal cases
```

Showing a refusal is persuasive: run the tests and point at `test_pr_refused_when_vulnerability_persists` and `test_failed_intel_never_produces_a_score_or_clean_result`.

## 4. What the judges will ask, and the honest answer

| Question | Answer |
|---|---|
| "Is the reachability real or a guess?" | Static analysis of `require`/`import` statements from the entry points in `package.json`. It is package-level. If the code uses dynamic `require()` or cannot resolve an import, the answer becomes UNKNOWN, never NOT_REACHABLE. |
| "Did you run their tests?" | No. Running a repository's test suite on our server would execute the project's code, which we refuse to do. Tests run in the project's CI on the PR. The PR body says so. |
| "Can it auto-merge?" | No. It never merges. A human has to approve. |
| "What if OSV.dev is down?" | The banner says UNAVAILABLE, the score is withheld, and no PR is created. We do not fall back to made-up data. |
| "Why not React?" | The dashboard is a single dependency-free HTML file served by the API, so there is no build step to fail on stage. The API is complete and a React frontend can be built on top of it. |
| "Exploit data?" | Taken from the CISA KEV catalogue. If that feed is unreachable, exploit status is shown as unavailable, not as "not exploited". |

## 5. Things that are real vs. limited

**Real and tested:** SBOM parsing (CycloneDX, SPDX, npm lockfile v2/v3, requirements.txt, pyproject.toml), dependency graph and depth, OSV.dev lookups with caching, CVSS 3.x scoring, reachability, risk scoring, remediation planning, safe archive handling, the GitHub PR flow including verification, and the lockfile regeneration step (run against the real npm registry).

**Limited, and stated in the product:** reachability is package-level, not function-level. Python reachability does not trace transitive packages without a lockfile. Internet exposure is a heuristic based on imported server frameworks. Monorepos with several `package.json` files are scanned, but remediation patches only the root manifest.

**Exact CVE results depend on live data at the time of the demo.** Do not promise specific CVE numbers. Run the scan once beforehand, look at the real output, and talk about what you see.
