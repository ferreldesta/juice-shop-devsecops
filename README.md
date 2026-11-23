# juice-shop-devsecops

A DevSecOps pipeline built step by step on [OWASP Juice Shop](https://github.com/juice-shop/juice-shop), a deliberately vulnerable web application.

I run each scanner by hand and triage its output before adding it to CI. For every tool I record what it finds, what it misses, and what its exit codes mean.

> This repository is a copy of OWASP Juice Shop with my security work on top. The application code and its commit history belong to the upstream project; my part is the pipeline, the notes and the reports listed below. The original documentation is in the [upstream README](https://github.com/juice-shop/juice-shop#readme).
>
> Juice Shop is intentionally insecure. Do not deploy it on a reachable network.

## Status

| Phase | Scope | Status |
|---|---|---|
| 0 | Setup: full-history clone, Docker image bound to `127.0.0.1`, Dockerfile review | Done |
| 1 | Run each scanner by hand and triage the results | Done |
| 2 | GitHub Actions: one job per tool, own workflows only | In progress |
| 3 | SARIF upload to code scanning and a build gate that fails on findings | Planned |
| 4 | Bash script that parses scanner output and decides pass or fail | Planned |
| 5 | STRIDE threat model and a manual code review report | Planned |
| 6 | Small vulnerable API of my own, with CWE-labelled ground truth | Planned |

## Tools

| Tool | Category | What it scans |
|---|---|---|
| [gitleaks](https://github.com/gitleaks/gitleaks) | Secret scanning | Every commit on every ref, including deleted files |
| [Semgrep](https://semgrep.dev) | SAST | TypeScript source, GitHub Actions workflows and Terraform, with `p/typescript` and `p/owasp-top-ten` |
| [Trivy](https://trivy.dev) | SCA and misconfiguration | npm dependencies (`trivy fs`) and the built container image (`trivy image`) |
| [OWASP ZAP](https://www.zaproxy.org) | DAST | The running app, with a passive baseline scan on an isolated Docker network |

## Phase 1 findings

- gitleaks found an SSH private key that Vagrant generated and someone committed in 2017, then deleted the same day. The key is still in history, so the fix is to rotate it and check whether it was used. Rewriting history comes after that.
- `routes/search.ts` builds a raw Sequelize query from `req.query.q`. The input is cut to 200 characters first, which still leaves room for a UNION payload.
- Semgrep scanned five files with known bugs and reported nothing for them. They include an IDOR and a NoSQL operator injection (`{"id": {"$ne": -1}}`) against a MarsDB call that no rule covers, plus a hidden route protected only by obfuscation in the frontend.
- The first `trivy fs` run reported zero npm CVEs and exited 0. The repo has no lock file, so Trivy had nothing to read.
- A CRITICAL `crypto-js` CVE about weak PBKDF2 defaults arrives through `pdfkit`. `pdfkit` uses `crypto-js` for MD5, RC4, AES and SHA256, never PBKDF2, so I rated it low priority while keeping it as an open finding.
- On an `--internal` Docker network, ZAP could not download its beta passive rules. Four rules disappeared with no error and the exit code stayed the same. In CI I will build a ZAP image with those rules installed and run it with `-silent`.
- The tools disagree on exit codes. gitleaks returns 1 for a leak and also for a tool error. Semgrep and Trivy return 0 on findings unless told otherwise. ZAP baseline returns 1 for FAIL, 2 for WARN and 3 for errors. The Phase 3 gate has to handle each one separately.

## Notes

Setup decisions, checkpoint answers, triage and each tool's blind spots for Phases 0 and 1:

- [NOTES.en.md](NOTES.en.md) (English)
- [NOTES.md](NOTES.md) (Indonesian, original)

Raw scanner output stays on my machine. `reports/raw/` is in `.gitignore` because the raw gitleaks report contains secrets in clear text. I will commit only redacted reports and summaries.

## License

The upstream code is MIT licensed, Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors. See [LICENSE](LICENSE).
