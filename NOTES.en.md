# NOTES

My learning notes from building a DevSecOps pipeline on top of OWASP Juice Shop. This is not full documentation. It holds what I actually understood after running each tool myself. Findings, analysis and details live in the notes/ folder (in Indonesian).

| Part | Details |
|---|---|
| Phase 0: setup | [notes/setup.md](notes/setup.md) |
| gitleaks (secret scanning) | [notes/gitleaks.md](notes/gitleaks.md) |
| Semgrep (SAST) | [notes/semgrep.md](notes/semgrep.md) |
| Trivy (SCA) | [notes/trivy.md](notes/trivy.md) |
| ZAP (DAST) | [notes/zap.md](notes/zap.md) |

## Setup

- This repo is a frozen snapshot of Juice Shop at commit 717f5efa8 (v20.3.0+7). All findings are tied to that version of the code.
- Access to the Docker socket is the same as root access. The daemon runs as root, so anyone who can use the socket can mount / into a container.
- A multi-stage build only drops what sits outside the app folder. Files like .env still end up in the image unless .dockerignore excludes them.
- Ports should be bound to 127.0.0.1. I tested it: with -p 3000:3000, another laptop on the same Wi-Fi could open my app, and UFW did not stop it because Docker redirects the packet before it ever reaches UFW.
- Treat a leaked secret as stolen. Rotate first, audit, and only then clean the history.

## What applies to every tool

- Exit 0 does not mean safe. Each tool has its own exit code rules: gitleaks uses 1 for both a leak and an error, Semgrep and Trivy return 0 even with findings by default, and ZAP uses 1 for FAIL, 2 for WARN and 3 for errors. A gate has to tell "there are findings" apart from "the scanner broke", and a broken scanner must always fail the build.
- A clean scan can mean the tool was blind. My first trivy fs run found 0 CVEs because there was no lock file. ZAP lost 4 rules without any error. Semgrep failed to parse 54 files and still exited 0. Besides the results, check that the tool actually saw everything.
- Findings fall into three groups: real and must be fixed, real but accepted (planted on purpose or low risk), and false positives (the tool was wrong). Never label a real finding as a false positive, because false positives get ignored forever.
- Severity is not priority. Severity from a tool or CVSS has no context. Priority comes from context: is it reachable, is there a real exploit, is there a fix, and who can reach the app.
- A safe ignore is narrow, has a reason, and can be reviewed later. Ignore per finding, not per folder. Ignore what you have checked, not places you have not checked.
- Baseline: accept the old debt, block new findings. gitleaks has --baseline-path and Semgrep has --baseline-commit. Trivy has neither, so I compare against the scan of main.
- Results can change while the code stays the same, because Semgrep's rule registry, Trivy's DB and ZAP's add-ons keep updating. Record the version and scan date.
- Triage starts by grouping findings by rule, folder and severity, not by reading them one by one from the top.

## gitleaks

gitleaks looks for secrets across the whole git history using keywords, regex and entropy. My biggest lesson: deleting a file does not delete the secret. A Vagrant SSH key committed in 2017 and deleted the same day was still found, because the old commit is still there. Copies have also spread to clones, forks and caches, so the right fix is to rotate the key, not just clean the history.

generic-api-key is the noisiest rule because its pattern is loose. Secret scanning also needs several layers (pre-commit, push protection, CI, scheduled scans), because each position has gaps.

## Semgrep

Semgrep reads the code and tracks data from source to sink. The SQL injection in routes/search.ts taught me that cutting input length is not sanitizing, and that parameterized queries work because they keep the query structure apart from the data.

But Semgrep only finds what its rules model. A NoSQL injection in MarsDB slipped through because no rule covers that sink. An IDOR and an obfuscated route slipped through too, because the bug was a missing check or a design flaw, not a code pattern. In Mongo the attacker sends structure through a JSON object instead of syntax through quotes, so type validation is what closes it.

## Trivy

Trivy builds a list of packages and matches it against a CVE database. It never reads the code, so it cannot tell whether the vulnerable function is used. crypto-js is rated CRITICAL, but its PBKDF2 is never called, so its priority is low. A gate that only looks at severity can end up backwards: it blocks the unreachable CRITICAL and lets through the HIGH that is already being exploited.

Other things that clicked for me: a transitive dependency is fixed through its parent or with overrides, not by installing it at the root. Rescanning only detects, and rebuilding is what brings in patches. trivy fs and trivy image look at different things, so I run both.

## ZAP

ZAP tests the running app from the outside. The baseline scan is called passive, but its spider still sends real requests. I ran it on an internal Docker network so Juice Shop could not reach out, and that isolation quietly switched off 4 beta rules that need the internet. The exit code did not change, so the number of loaded rules has to be checked as well.

ACAO * looks dangerous, but on its own it cannot steal a session, because CORS forbids the wildcard together with credentials. The classic spider cannot see SPA routes. That is a URL discovery problem, solved by the AJAX spider, not by an active scan. Signature-based rules also do not recognize an Express stack trace.

## SAST vs DAST

- SAST runs earlier, points to the exact line, and sees code that the UI never reaches. It has more false positives.
- DAST sees what only exists at runtime (headers, cookies, error messages) and can prove a bug is exploitable. But it only sees what the spider finds.
- Some bugs no tool finds: business logic, IDOR and race conditions. Those need manual review and pentesting.

## Next

Phase 2: my own GitHub Actions workflow with one job per tool, starting with gitleaks and Semgrep. The decisions for the gate and CI are in the "Untuk fase berikutnya" (for the next phase) section of each file in notes/.
