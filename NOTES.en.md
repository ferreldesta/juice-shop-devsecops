# NOTES

English version of NOTES.md. The Indonesian file is the original.

## Phase 0: Setup

### Repo contents

| File/folder | Contents |
|---|---|
| README.md | Overview of OWASP Juice Shop. |
| package.json | Project metadata, runnable scripts, dependencies, and the required engine (Node) version. |
| Dockerfile | Instructions for building the Docker image. |
| .gitignore | Files and folders that must not go into the git repo. |
| .dockerignore | Files and folders left out of the build context, so they are never copied into the image. |
| routes/ | Logic that handles each API endpoint, not only the routing. |
| frontend/ | Frontend code. |
| data/ | Database and seed data (users, products, challenges). |
| .github/workflows/ | GitHub Actions workflows (16 files): CI/test, release, CodeQL, and repo automation (stale, lock, compliance). Example: codeql-analysis.yml runs on every push to any branch and on every pull request. |

### Dockerfile

- There are two stages:
  1. installer (base node:24): installs dependencies, cleans up, and sets file permissions.
  2. The final image.
- The final stage takes only the /juice-shop folder from installer (COPY --from=installer --chown=65532:0 /juice-shop .).
  - Only the app code and production node_modules go into the final image, because the app needs them at runtime. devDependencies are left out because of npm install --omit=dev, not because of multi-stage.
  - Everything in node:24 (bash, apt, curl, git, compilers), the global tools (typescript and cyclonedx-npm, installed in /usr/local/lib, not in /juice-shop) and the npm cache stay behind in installer.
  - For security, an attacker finds no tools in the final image. Fewer OS packages also mean fewer CVEs in Trivy and less to patch, and build tools never reach production.
  - Multi-stage only filters what lives outside /juice-shop. Files in the build context such as .env are still copied into /juice-shop and end up in the final image. .dockerignore prevents that; multi-stage does not.
- The final base image is gcr.io/distroless/nodejs24-debian13. Distroless shrinks the attack surface, but with no shell inside, debugging is harder.
- The container runs as USER 65532, a non-root UID.

### Checkpoint

1. Why is a user in the docker group equivalent to root?
The Docker daemon runs as root. Anyone who can reach the Docker socket can start a container with -v /:/host and mount anything from the host, including the whole filesystem. Docker only checks whether you may use the socket. It does not check whether you may read /etc/.

2. Why not use a shallow clone?
gitleaks scans the whole commit history, including secrets that were later overwritten. A shallow clone fetches only part of the history, so the rest goes unchecked and the repo looks clean when it is not.

3. Why must the new repo be completely empty before the push?
If the new repo already has files (README, license) or other commits, its history differs from the local history. The push is rejected, or I have to force push and damage the history.

4. Why turn Actions off first?
So the bundled workflows I do not understand do not run. Those workflows also need secrets I do not have, so they would fail. The repo would fill up with red marks and use up Actions quota.

5. Decision on the bundled workflows?
Disabled. I will write my own workflows and use the originals as reference.

6. Dockerfile findings?
See the Dockerfile section above.

7. Why bind the port to 127.0.0.1?
So the app is reachable only from my own laptop. People on the same Wi-Fi cannot open it.

8. What goes wrong if the local node_modules/ gets into the build?
The build context becomes large and slow. The local node_modules/ is compiled for the laptop's OS and Node version, which probably differ from the container's. The image then depends on what is on the laptop instead of package.json, so SCA results may be wrong.

9. Why scan my own built image instead of the official one?
The official image does not reflect my commit or the base image I pulled. I should scan the artifact I ship, not someone else's or one from a different point in time.

10. Why is deleting history not the fix for a leaked secret?
A secret that has leaked must be treated as stolen, and deleting history does not pull back copies that already exist elsewhere. What to do:
- Rotate: revoke the old secret at its source, then issue a new one.
- Audit: check the old secret's usage logs to see whether someone else used it.
- Only then clean the history, and add prevention such as gitleaks in pre-commit or CI.

11. What is the difference between a bare and a non-bare repo, and why is the backup bare?
A bare repo holds only the contents of .git/ (history and data) with no working tree, so you cannot edit files in it directly. A non-bare repo is what git init or a normal git clone gives you, with a working tree. The backup is bare because:
- No duplicated files, so it is smaller.
- It cannot be edited by accident.
- A bare repo is the normal push target. Pushing to the checked-out branch of a non-bare repo is rejected by default (receive.denyCurrentBranch). Git servers such as GitHub also store repos as bare.

## Phase 1: Manual scans

### Step 1: gitleaks

- Version: gitleaks 8.30.1 (binary from GitHub Releases). The apt version 8.16 was removed because its rules are old and it lacks the git/dir subcommands.
- Scan: the full history (about 24 thousand commits, all refs) finished in 5.41 seconds. Raw output in reports/raw/gitleaks.json.
- Exit code: 1 means findings, 0 means none. A tool error also exits with 1, so the gate has to tell them apart.
- Total findings: 225.

| Rule | Count |
|---|---|
| generic-api-key | 164 |
| jwt | 54 |
| private-key | 7 |

I triaged by grouping findings per path instead of opening them one by one. 196 of 225 findings (87%) are in test/spec files. They are fixture data, not real credentials.

Classification of the 7 private-key findings:
- 6 were planted on purpose as Juice Shop challenges (lib/insecurity.js, terraform/networking.tf, infrastructure/terraform/networking.tf, test/files/passkeyVictimCredential.json). They carry markers such as vuln-code-snippet or the file name insecurity.
- 1 true positive: vagrant/.vagrant/machines/default/virtualbox/private_key. This is an SSH key that Vagrant generates automatically and that should have been ignored. It was committed on 2017-03-03 ("Include latest changes") and deleted the same day ("Remove vagrant folder"). The commit exists only on the gh-pages branch, so it was detected only because the backup was made with --mirror (all refs). Impact is low because the key is only for a local VM, but it is still classified as a true positive. vagrant/.vagrant/ is now in .gitignore.

47 of the 64 unique files (73%) that triggered findings no longer exist in the working tree.

Why is a secret in a deleted file still a problem?
Deleting a file only creates a new commit that says "this file no longer exists". The old commits that contain the file stay intact in the Git database, and anyone with a clone, fork, or mirror can still read them. Scanning only the current files (gitleaks dir) would miss the Vagrant key. It shows up only with gitleaks git, which walks every commit on every ref. Copies of the secret have already spread and cannot be pulled back, so deleting the file or cleaning history is not enough. Treat the secret as stolen: the main steps are rotate and audit (see Q10).

### Step 2: Semgrep

- Version: semgrep 1.184.0. Registry pack contents change over time, so the version and scan date (2026-11-14) must be recorded.
- Rulesets: p/typescript, because most of the repo is TypeScript. p/owasp-top-ten, because most Juice Shop vulnerabilities fall into Top 10 categories. Both were combined in one scan.
- p/owasp-top-ten covers many languages, not only TypeScript, so there are also findings in GitHub Actions YAML, Terraform, and .npmrc.
- Command: run twice, once with --json (reports/raw/semgrep.json) and once with --sarif (reports/raw/semgrep.sarif). A single run with --json-output=FILE and --sarif-output=FILE is more efficient.
- Exit code: 0, even with 43 findings. By default Semgrep does not fail on findings. To exit 1 on findings, use --error. This matters for the Phase 3 gate.
- The extra.lines field says "requires login" because I was not logged in to Semgrep. The code has to be opened by hand at path:line. Side benefit: the raw report does not copy code snippets or secrets.

I counted and grouped findings by severity, rule, and folder first instead of reading top to bottom.

Total: 43 findings and 54 errors. Errors are files that failed analysis, not findings.

| Severity | Count |
|---|---|
| WARNING | 28 |
| ERROR | 13 |
| MEDIUM | 2 |

MEDIUM comes from a supply chain rule (npm-missing-minimum-release-age) that uses a different scale from ERROR/WARNING.

| Rule | Count |
|---|---|
| github-actions-mutable-action-tag | 7 |
| express-sequelize-injection | 6 |
| run-shell-injection | 5 |
| insecure-load-balancer-tls-version | 5 |
| express-check-directory-listing | 5 |
| aws-subnet-has-public-ip-address | 5 |
| express-res-sendfile | 4 |
| npm-missing-minimum-release-age | 2 |
| hardcoded-jwt-secret | 1 |
| gha-curl-pipe-shell | 1 |
| express-open-redirect | 1 |
| code-string-concat | 1 |

| Folder | Count |
|---|---|
| .github | 13 |
| data | 10 |
| routes | 8 |
| (root) | 6 |
| terraform | 2 |
| infrastructure | 2 |
| lib | 1 |
| frontend | 1 |

Classification by path (production or not):

| Class | Count | Path |
|---|---|---|
| PROD-SERVER | 14 | routes/ (8 files), server.ts (5), lib/insecurity.ts (1) |
| NON-PROD: coding-challenge snippet | 10 | data/static/codefixes/ |
| INFRA/CONFIG | 19 | .github/workflows/ (13), terraform/ and infrastructure/terraform/ (4), .npmrc and frontend/.npmrc (2) |

The automatic classification got one file wrong. frontend/.npmrc first landed in PROD-CLIENT because the regex matched the frontend/ folder first. The file is npm configuration, not code that runs in the browser, so it belongs in INFRA/CONFIG. Classify by file type first, then by folder.

INFRA/CONFIG notes:
- Non-production files still carry risk. run-shell-injection in a CI workflow can be used to steal secrets or the GITHUB_TOKEN, so the risk is real (supply chain).
- The Terraform files come from the "Vulnerable Infrastructure" challenge (commit 458c66e82), so they were planted on purpose.

#### Triage: routes/search.ts:23

Rule: express-sequelize-injection (subcategory vuln, severity ERROR, CWE-89, likelihood/impact/confidence HIGH). Flow traced with --dataflow-traces.

| Step | Line | Code | Role |
|---|---|---|---|
| Source | 21 | criteria = req.query.q | user input from the query string; criteria only carries the taint |
| Transformation | 22 | criteria.substring(0, 200) | only cuts the length, not a sanitizer |
| Sink | 23 | models.sequelize.query("... LIKE '%${criteria}%' ...") | criteria is inserted straight into the SQL string |

Verdict: true positive. criteria reaches the SQL command with no parameterization (replacements/bind) and no cleaning. The 200-character limit does not stop SQLi because a UNION payload fits in under 200 characters.

The vuln-code-snippet marker does flag the challenge, but the verdict has to rest on the flow, because real repos have no markers.

#### Noise decision: data/static/codefixes/

I chose .semgrepignore.

| Method | Pros | Cons |
|---|---|---|
| .semgrepignore | lives in the repo, consistent locally and in CI | anyone who can commit can hide code from the scanner, so changes to it need review; creating this file overrides Semgrep's default ignore patterns |
| --exclude | quick for experiments | lives on the command line; forget it and the results differ |
| nosemgrep | precise per line, the reason can go in the comment | has to be written on every finding line, not suited to a whole folder |

#### Errors (54)

Errors are Semgrep's own failures during the scan, not findings. All are at warn level, so the scan keeps going. Each error is still a blind spot: code that was not analyzed, so coverage is below 100%.

| Type | Count | Location | Assessment |
|---|---|---|---|
| PartialParsing | 35 | .github workflows, codefixes, and production frontend files (payment, wallet, deluxe-user, etc.) | parts of files skipped; the production frontend ones deserve attention |
| Syntax error | 16 | data/static/codefixes/ | expected, the snippets are incomplete by design |
| Timeout | 3 | frontend/src/assets/private/three.js | expected, a large vendor library |

#### S5: false negatives and the limits of SAST

The vuln-code-snippet start markers serve as ground truth (places where a bug definitely exists) and are compared with the paths in the Semgrep report (comm -23). Result: 5 files with bugs that Semgrep did not find:
- frontend/src/app/app.routing.ts
- frontend/src/app/search-result/search-result.component.ts
- lib/codingChallenges.ts
- routes/chat.ts
- routes/updateProductReviews.ts

The first hypothesis, "parsing failed", was checked against the data and turned out wrong: all five files are in paths.scanned and none are in errors. Semgrep read the code, but no rule matched. These are pure false negatives.

Bug 1: frontend/src/app/app.routing.ts (tokenSaleChallenge)
- A secret route is hidden with obfuscation (token1, token2) in frontend code.
- There is no source and no sink, so taint rules have nothing to hold on to.
- Frontend code is sent to the browser, so anyone can read and decode it.
- This is security through obscurity (CWE-656), a design flaw rather than a code pattern, so pattern-based SAST cannot see it.

Bug 2: routes/updateProductReviews.ts (forgedReviewChallenge)
- Line 16 fetches the logged-in user, but that user value is never used to limit which reviews may be changed. The update filters only on _id from req.body.id.
- As a result a user can change other people's reviews: IDOR / broken access control.
- Semgrep missed it because the database is MarsDB (similar to MongoDB). Every injection rule in the report has a Sequelize sink. There is no rule for MarsDB sinks, and data ownership checks are business logic with no fixed code pattern.

Bug 3: routes/updateProductReviews.ts (noSqlReviewsChallenge)
- Source req.body.id, sink db.reviewsCollection.update(...) with multi: true.
- The body {"id": {"$ne": -1}, "message": "hacked"} produces the query { _id: { $ne: -1 } }. In MongoDB/MarsDB a key starting with $ is an operator. $ne means not equal, so the query asks for reviews whose id is not -1, which matches every review. This NoSQL injection changes the structure and logic of the query. multi: true makes the database update every matching document instead of only the first, so every message becomes hacked.
- Unlike SQLi, the operator is slipped in through the data structure (a JSON object), not through quote characters.
- To fix it, require typeof req.body.id === 'string' or reject keys starting with $, then add author: user.data.email to the filter. The author condition also closes the IDOR in Bug 2.
- PoC attempt (2026-11-14): PATCH /rest/products/reviews with body {"$ne": -1} returned {"modified":0}. It failed because the operator was sent at the top level instead of as the id value, so req.body.id was empty and no review matched. The correct body: {"id": {"$ne": -1}, "message": "hacked"}.

### SAST vs DAST

SAST (static, reads the code, whitebox):
- Sees code that the UI cannot reach, for example handlers in routes/ that no UI links to, so a crawler never finds them.
- Gives the bug location directly (file and line), while DAST only gives a URL.
- Sees secrets and cryptography in the source.
- Sees infrastructure as code, for example Terraform.

DAST (dynamic, tests the running app the way a penetration test does):
- Sees HTTP headers, because their values exist only while the app runs.
- Sees cookie attributes in real responses.
- Sees error messages and stack traces that appear at runtime.
- Sees the effect of reverse proxy or WAF configuration and how components behave together.

Main points:
- DAST proves a bug can actually be exploited, so it has fewer false positives.
- SAST has more false positives, but it runs earlier, before the app is deployed.
- The two complement each other, and this pipeline uses both.

### Semgrep status

Done on 2026-11-14 (slim scope).

Carried into later phases:
- Create .semgrepignore for data/static/codefixes/ (decided, file not created yet). Copy Semgrep's default ignore patterns into it first.
- Phase 3 gate: Semgrep needs --error to exit 1 on findings.
- One run for both formats: --json-output=FILE and --sarif-output=FILE.
- Optional: repeat the NoSQL PoC with the correct body.
- routes/login.ts:34 was not triaged (slim scope). Same pattern as search.ts.

### Step 3: Trivy

- Version: Trivy 0.76.2, vulnerability DB version 2 (UpdatedAt 2026-11-20). Details in reports/raw/trivy-version.txt. The DB is downloaded again every day, so scan results can change even when the code does not.
- Trivy does SCA (Software Composition Analysis). Semgrep looks for bugs in our own code, while Trivy looks for CVEs in other people's code that we use: npm dependencies and OS packages in the image.

Final commands:
- trivy fs --scanners vuln,secret,misconfig --include-dev-deps --skip-dirs reports --format json --output reports/raw/trivy-fs.json .
- trivy image --scanners vuln,secret,misconfig --image-config-scanners misconfig,secret --format json --output reports/raw/trivy-image.json juice-shop-local:latest

The default scanners are vuln,secret. misconfig was added because it is useful for the Dockerfile and Terraform. license and --list-all-pkgs were dropped: license is a compliance concern, not a security one, and --list-all-pkgs is only needed for an SBOM.

Mistakes in the first scan:
- trivy fs found no npm CVEs at all. The log only said INFO "Number of language-specific files num=0". The repo has no package-lock.json (.npmrc contains package-lock=false) and no node_modules. For Node, trivy fs needs a lock file because package.json holds only version ranges. A clean scan with exit 0 is not proof of safety; the tool may be blind.
- I then generated lock files for root and frontend with npm install --package-lock-only.
- Trivy scanned its own reports: reports/raw/gitleaks.json produced 108 secrets, because the raw gitleaks report holds unredacted secrets. --skip-dirs reports fixed it. This also proves reports/raw/ must be in .gitignore.

Lock files:
- A lock file keeps dependency versions identical on every machine. In real projects lock files are committed.
- Here the lock files are not committed, because upstream deliberately uses package-lock=false and these lock files are only a scanning aid.
- This causes drift. The image is built without a lock file, so versions are chosen at build time, while the lock files pin the versions of 2026-11-20.
- --ignore-scripts matters when running npm on untrusted code. preinstall/postinstall scripts run arbitrary code with the user's permissions, for example reading ~/.ssh or tokens in env, so they can become a supply chain attack.

Exit code: 0 by default, even with findings. Trivy exits 1 on error. If --exit-code 1 is used for findings, the gate cannot tell "CVE found" from "Trivy crashed" (the same problem as gitleaks). In Phase 3, use --exit-code 2 and --severity HIGH,CRITICAL.

T2: vulnerability counts

| Severity | fs | image |
|---|---|---|
| CRITICAL | 9 | 9 |
| HIGH | 29 | 28 |
| MEDIUM | 30 | 81 |
| LOW | 4 | 16 |
| UNKNOWN | 0 | 4 |

FixedVersion is the lowest version that patches the vulnerability. Not every finding has one.
- fs: 64 with a fix, 8 without.
- image: 65 with a fix, 73 without. 66 of the 68 Debian OS package findings have no fix (Status affected): Debian has not released a patch, so upgrading npm packages does not help. The options are to wait, switch base image, or accept the risk.

T3: why fs and image differ
They scan different things. fs scans the repo folder. image scans the build output that actually ships to production.
- Only in fs: devDependencies (--omit=dev removes them from the image) and Dockerfile misconfigurations.
- Only in image: OS packages from the distroless base image (class os-pkgs) and image metadata misconfigurations (USER, HEALTHCHECK).
- Package versions can differ because of lock file drift.
- Test files and Terraform end up in the image because .dockerignore does not exclude them. .dockerignore excludes only terraform/ and test/ at the root, so infrastructure/terraform/, data/static/codefixes/, and frontend/src/**/*.spec.ts still go in. The installer stage runs COPY . /juice-shop, then the final stage copies all of /juice-shop.

T4: dissecting crypto-js (CVE-2023-46233)

| Question | Answer |
|---|---|
| Package | crypto-js 3.3.0, CRITICAL, CVSS 9.1, CWE-916/327/328 |
| The CVE | PBKDF2 defaults to SHA1 and 1 iteration, far weaker than the standard |
| Direct or transitive | transitive. Not in Juice Shop's package.json; its parent is pdfkit 0.11.0 (checked in package-lock.json, then in pdfkit's package.json inside the image) |
| Installed to fixed | 3.3.0 to 4.2.0. Status fixed means upstream has released a patch, not that the installed version is safe |
| Reachable | no. pdfkit uses crypto-js for MD5 (generateFileID, always called), RC4, AES, and SHA256 (PDF encryption), but never PBKDF2. Juice Shop uses pdfkit in routes/order.ts without encryption |
| Priority | low. Still a finding and still worth upgrading through pdfkit, but the vulnerable function is unreachable |

The first check in T4 had two mistakes. Status fixed was misread as safe. grep "crypto-js|CryptoJS|PBKDF2" without -E treats | as a literal character, so an empty result meant nothing. Reachability has to be checked in the code (js/pdfkit.js), not in package.json.

T5: Trivy blind spots
- Bugs in our own code (Semgrep's job).
- Runtime behavior (ZAP's job).
- Reachability: whether the vulnerable function is actually used.
- Dependencies that are not in the lock file.
- Vendor code without a package.json, for example frontend/src/assets/private/three.js. Trivy does not know its version.
- Frontend dependencies in the image are already bundled into built JS, with no package.json. trivy image is blind to frontend CVEs; only trivy fs with a lock file sees them. That is why both are run.

### Trivy status

Done on 2026-11-20 (slim scope).

Carried into later phases:
- Phase 3 gate: --exit-code 2 and --severity HIGH,CRITICAL; consider --ignore-unfixed for OS packages without a patch.
- CI needs lock files for trivy fs, or the image scan as the SCA source for the backend.
- Tighten .dockerignore (infrastructure/, data/static/codefixes/, spec files) so the image does not carry non-production files.

### Step 4: ZAP

- Image: ghcr.io/zaproxy/zaproxy:stable (the old owasp/zap2docker-* images are deprecated).
- ZAP is the DAST tool. It tests the running app from outside over HTTP, without reading the code.

Z1: is baseline passive or active?
Passive: according to the docs, it sends no malicious payloads to the target. The spider runs for 1 minute by default; change it with -m <minutes>. Passive does not mean no traffic, though. The spider still crawls every link and can submit forms, so GET endpoints that change state (for example /logout or /delete?id=1) can still fire. Only the analysis is passive, because ZAP just reads the responses that pass by.

Z2: why a full scan must not target something you do not own
A full scan runs an active scan and sends malicious payloads such as SQLi and XSS. That can damage data and counts as a real attack. Without written permission (scope/RoE) it is illegal access (Indonesia's UU ITE Articles 30 and 33). An active scan also sends thousands of requests and can slow the target down or take it offline, so even on your own systems a full scan goes to staging, not production.

Baseline flags:

| Flag | Purpose |
|---|---|
| -t | target |
| -r | HTML report |
| -J | JSON report, the one used for parsing |
| -I | WARN does not produce exit 2. It only changes the exit code; the report still contains the WARNs |
| -m | spider duration in minutes |
| -g / -c | -g generates a rule config file, -c uses that file to set each rule to IGNORE/WARN/FAIL. This is how noise is tuned in ZAP |

Exit codes (checked in the source of /zap/zap-baseline.py inside the image): 1 if there is a FAIL, 2 if there is a WARN and -I is not used, 0 if everything passes, 3 for other errors. The first scan was reported as exit 0 although it had 7 WARNs without -I, so that was a measuring mistake. A gate that misreads the exit code always passes. Do not use -I in the Phase 3 gate without a clear reason.

The ZAP container cannot use 127.0.0.1 to reach the app, because 127.0.0.1 inside a container is the container itself.
- Path A, --network host: ZAP shares the host's network namespace. Every service on the host's 127.0.0.1 is reachable, and ZAP's own port is open on the host. Easiest, weakest isolation. The official zaproxy/action-baseline action in GitHub Actions uses this path.
- Path B, user-defined network: ZAP and juice share one network, and the target is addressed by container name (http://juice:3000). Chosen for isolation.

Z3: what ZAP can reach on a regular network (zapnet)
More than Juice Shop. Every port of every container on that network, the host through the gateway (172.20.0.1, and the host has a listener on 0.0.0.0:80), and the internet because internal=false. docker network connect adds a network instead of moving the container: at that point juice was attached to both bridge and zapnet.

Z3b: how to close it
docker network create --internal zapnet-int. Containers on an internal network can talk only to other containers on that network and cannot reach the internet. Port publishing (-p) does nothing for a container attached only to an internal network. Trade-off: the browser on the host can no longer open Juice Shop, so manual checks are done from a container on the same network.

Isolation holds only when every non-internal network is detached. As long as juice is still attached to bridge or zapnet, it has a way out and -p stays active.

Z3b verification (Docker 29.1.3):
- 6a, -p is ignored: a test container with -p 127.0.0.1:3001:3000 on zapnet-int. The Ports column shows only 3000/tcp with no arrow (just the EXPOSE from the Dockerfile, not a port open on the host), and curl to 127.0.0.1:3001 fails. -p is accepted without an error but silently ignored. A security setting that looks right is not necessarily active; always verify.
- 6b, no internet, blocked at two layers:
  - DNS: curl https://google.com fails with exit 6 (Could not resolve host). Docker's internal DNS does not forward outside names.
  - Routing: curl https://1.1.1.1 (a direct IP, no DNS) fails with exit 7 after 0 ms. Failing instantly means there is no outbound route; the packet is never sent.
  - docker run passes through the exit code of the process inside the container, so echo $? after docker run gives 6, the same as curl's exit code.
- 6c, container to container works: curl to http://juice:3000 from a container on zapnet-int returns 200 OK. Docker's internal DNS resolves the name juice.
- 6d, the host is unreachable: curl http://172.21.0.1:80 fails with exit 28 (timeout after 5 seconds). A timeout means the packet was sent but silently dropped by the firewall (DROP). The first attempt used 127.21.0.1 because of a typo; that is the ZAP container's own loopback, so it proved nothing.
- curl errors mean different things. An instant failure with no reply (exit 7, 0 ms) means no route. A timeout (exit 28) means the packet was sent but dropped on the way. Connection refused (also exit 7, with a different message) means the packet arrived but nothing listens on that port. Exit 7 has two meanings, so read the message, not only the number.
- The claim in Z3 that zapnet can reach host:80 through the gateway is inferred from the configuration (internal=false and the 0.0.0.0:80 listener). It was not tested directly because zapnet had already been deleted.

The juice container disappeared mid-step. An old container started without -d in another terminal was stopped with Ctrl+C. docker events recorded kill sig=28 (SIGWINCH, terminal resized), kill sig=2 (SIGINT, Ctrl+C), die exit=0, then destroy because of --rm. Ctrl+C in an attached terminal kills the container; to detach without killing it, press Ctrl+P then Ctrl+Q. docker logs -f is a safe way to watch logs, and --rm also removes the network configuration and logs. Recovery takes one command, docker run --rm -d --name juice --network zapnet-int juice-shop-local.

Baseline scan (step 7):
- Command: docker run --rm -t --network zapnet-int -v "$(pwd)/reports/raw:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://juice:3000 -J zap-baseline.json -r zap-baseline.html
- Result: FAIL-NEW 0, WARN-NEW 7, PASS 61. Exit code 2, matching the source logic (WARNs present, no -I).
- Files in reports/raw: zap-baseline.json, zap-baseline.html, and zap.yaml. zap.yaml is the Automation Framework plan that zap-baseline.py generates automatically (jobs: passiveScan-config, 1-minute spider, passiveScan-wait, outputSummary, two report jobs).
- The console shows at most 5 URLs per rule even when the count is higher (for example 10049 x 6, 90004 x 10). The full list is in the report.
- The JSON report contains only 3 alerts (10038, 10098, 10109), while the list of 7 WARNs came from the first scan on zapnet, which still had internet. The cause is in the Root cause section below. The exit code is computed from an internal summary file (/home/zap/zap_out.json), not from the JSON report. So a gate that reads the JSON report can see different results from the exit code.
- Insights in the JSON: 77 errors and 3 warnings recorded in zap.log, 45 network failures. zap.log lives inside the container and is lost with --rm.

Root cause: 4 rules missing on the internal network
- zap-baseline.py lines 434-439: without -silent, ZAP starts with -addonupdate -addoninstall pscanrulesBeta. The comment there: "In case we're running in the stable container". The stable image ships only pscanrules-release and pscan-alpha, not pscanrulesBeta.
- zapnet-int has no internet, so the install fails. The only trace in zap.log is "ERROR CommandLine - Check for updates call failed". The list of loaded rules contains no beta rules at all.
- The missing rules are all beta: 10049 Storable and Cacheable Content, 10063 Permissions Policy, 10110 Dangerous JS Functions, 90004 Insufficient Site Isolation.
- The scan still finishes with exit 2 and no error on the console. Coverage drops silently.
- All 86 ERRORs in zap.log are failed calls home (cfu.zaproxy.org for check for updates, tel.zaproxy.org for telemetry). This also proves the isolation works: ZAP cannot send telemetry out.
- Isolation and coverage pull against each other. Network hardening can disable part of a scanner with no sign of failure. Count the loaded rules instead of looking only at the exit code.
- zap.log was saved by running the container without --rm, then docker cp zapscan:/home/zap/.ZAP/zap.log reports/raw/, then docker rm zapscan.

Z4: grouping the 7 WARNs (from the scan with internet)

| Group | Rule | Risk (confidence) | Notes |
|---|---|---|---|
| Real vulnerability (still a possibility) | 10098 Cross-Domain Misconfiguration | Medium (Medium) | triggered by the Access-Control-Allow-Origin: * seen in 6c. Dissected in Z5 |
| Header hardening | 10038 CSP Header Not Set | Medium (High) | an extra defense layer against XSS, not a hole that can be exploited on its own |
| Header hardening | 10063 Deprecated Feature Policy Header Set | Low, beta | this rule also alerts when Permissions-Policy is missing. Here the deprecated Feature-Policy header variant fired (seen in 6c) |
| Header hardening | 90004 Insufficient Site Isolation (Spectre) | Low, beta | the COEP missing variant. There are three variants: CORP, COEP, COOP |
| Informational | 10109 Modern Web Application | Informational (Medium) | marks the app as an SPA, so the classic spider probably misses some routes. This is about scan coverage |
| Informational | 10049 Storable and Cacheable Content | Informational, beta | Cache-Control: public, max-age=0 |
| Hint of a real vulnerability | 10110 Dangerous JS Functions | Low, beta | only matches function patterns in the response, but the matched pattern is what causes XSS. See the 10110 section below |

Directory listing on /ftp was not reported because Directory Browsing (ID 0) is an active scan rule. Baseline runs only passive rules.

Z4b: how to get the beta rules without opening the internet
- A, go back to a non-internal network: the deliberately vulnerable Juice Shop can reach out again, and a typo in -t could hit a real site. A middle ground is to attach ZAP to two networks (zapnet-int and a regular one) and keep Juice Shop only on zapnet-int. Juice Shop stays isolated, but ZAP itself can reach the internet and the host.
- B, own image FROM ghcr.io/zaproxy/zaproxy:stable with pscanrulesBeta installed at build time, then scan with -z "-silent": closest to a real pipeline. Rules are downloaded at build time instead of run time, so the rule version is pinned and scans are repeatable. The downside is that the image needs periodic rebuilds to get new rules. -silent is still needed so ZAP does not try to update at run time.
- C, accept running without the beta rules: not acceptable, because the rules exist and can run; they just were not downloaded. This is a configuration gap, not a tool blind spot.
- By default ZAP downloads the latest add-on versions on every run, which is a supply chain risk. Scan results can change with no code change, and if the add-on server is compromised, that code runs straight inside the scanner.
- I chose B, to be done when ZAP goes into CI. For Phase 1, the list of 7 WARNs from the scan with internet is enough.

10110 Dangerous JS Functions is a real lead
- main.js contains 10 bypassSecurityTrust calls (8 bypassSecurityTrustHtml, 2 bypassSecurityTrustUrl). These Angular functions turn off the built-in sanitizer, so HTML is rendered as is.
- They come from 9 lines in frontend/src/app (grep excluding spec files). Juice Shop marks two of them as vulnerable lines: search-result.component.ts:146 (localXssChallenge, the search parameter from the URL is rendered directly) and search-result.component.ts:113 (restfulXssChallenge, product description from the API).
- ZAP sees only the pattern and does not know which data the attacker controls. Example: queryParam in search comes from the URL (dangerous), while captcha in data-export comes from the server. Telling them apart requires reading the code (source to sink).
- Semgrep (the rulesets used in Step 2) reported none of those 9 lines. A ZAP beta rule found a lead that SAST missed.
- grep in zap-baseline.html returns nothing because that report comes from the offline scan, which did not run the beta rules.

Stack trace on /ftp/encrypt.pyc (403)
- The odd URL /juice-shop/node_modules/express/lib/router/index.js:286:9 in the spider results is not a real file. It is one stack trace frame (file, line 286, column 9) on the 403 error page. The spider read that path text as a link.
- What the error page leaks:
  - The application name OWASP Juice Shop and the framework Express ^4.22.1. The ^ marks a range from package.json, not the installed version.
  - The Node.js runtime, visible from the node:fs frame.
  - The filter rule: only .md and .pdf may be downloaded.
  - The absolute install path (/juice-shop/) and the build output folder structure (build/routes/fileServer.js).
  - The exact location of the filter check: the verify function in fileServer.js line 68. An attacker knows which filter to bypass and can read its logic in the open source.
  - The serve-index middleware, the module that produces the /ftp directory listing.
- ZAP did not report it, even though the rules Application Error Disclosure (90022) and Information Disclosure - Debug Error Messages (10023) were loaded. Their detection patterns are in pscanrules-release-77.zap (xml/application_errors.xml and xml/debug-error-messages.txt). They contain patterns for PHP, ASP.NET, Java, IIS, and database error messages. There are no patterns for Node.js or Express stack traces.
- Signature-based rules find only the patterns someone wrote. ZAP even crawled the path from that stack trace without recognizing it as a leak. This blind spot needs manual review or extra rules.

Z5: dissecting 10098 Cross-Domain Misconfiguration

| Question | Answer |
|---|---|
| Trigger | the Access-Control-Allow-Origin: * header on every response. Source: server.ts:183-184, app.options('*', cors()) and app.use(cors()) with no options, so the origin defaults to * |
| Meaning of the header | any website may read Juice Shop responses through JavaScript, as long as the request is sent without credentials |
| How the frontend logs in | the token is stored in two places: localStorage (login.component.ts:110) and the token cookie (login.component.ts:113). request.interceptor.ts:16 sends Authorization: Bearer from localStorage on every request |
| How the backend reads the token | mixed. isAuthorized (lib/insecurity.ts:52) uses expressJwt without a custom getToken, so it reads only the Authorization header. Some routes read the cookie: currentUser.ts, dataErasure.ts, profileImageFileUpload.ts, profileImageUrlUpload.ts, updateUserProfile.ts, userProfile.ts. insecurity.ts:187 prefers the cookie and uses the header only as a fallback |
| Can it steal a logged-in user's data? | not through ACAO * alone |
| Priority | low for Juice Shop, which is public anyway. Higher if the same app runs on an internal network |

Why ACAO * alone is not enough to steal a session:
- Routes that use the header: a malicious website does not have the victim's token. localStorage is bound to its origin, so JavaScript on another domain cannot read it, and the browser never adds the Authorization header automatically.
- Routes that use the cookie: the browser sends cookies only when the request uses credentials: 'include'. For such requests, CORS rules forbid JavaScript from reading the response if the header is ACAO: *. The origin has to be named exactly, and Access-Control-Allow-Credentials: true has to be present.
- CORS blocks reading the response, not sending the request. Cookie-based routes can still receive requests from other sites (CSRF), but that is a separate problem and ACAO * does not cause it.

Real risks of ACAO *:
- Data readable without login can be pulled by any website through its visitors' browsers.
- Internal network scenario: if the app runs on an intranet, an outside website opened by an employee can read the internal app through that employee's browser. The network boundary stops meaning anything.
- The truly dangerous configuration is an origin reflected from the request's Origin header plus Allow-Credentials: true.

ZAP's Medium rating is generic. The real risk depends on how the app stores logins and who can reach the app.

Z6: ZAP baseline blind spots
- 10109 Modern Web Application: the classic spider reads only links in HTML and does not run JavaScript. Angular routes (#/...) are built by JavaScript in main.js, so the spider cannot see them. The 1-minute duration is not the main problem. The fix is the AJAX spider (-j), which uses a headless browser.
- /ftp: directory listing was not reported because the Directory Browsing rule (ID 0) is active, while baseline runs only passive rules.
- Stack trace: the 403 page leaks the Express framework, the directory structure, and the .md/.pdf filter rule. The error disclosure rules have no pattern for Node.js/Express stack traces, so there is no alert.
- 4 beta rules went missing because ZAP on the internal network could not download pscanrulesBeta. This is a configuration gap, not a tool limit, and the exit code does not show it.
- ZAP labels 10098 as Medium without knowing the app's auth model. ZAP's risk rating has no context.
- bypassSecurityTrustHtml: ZAP (beta rule 10110) sees the pattern but cannot tell which data the attacker controls and does not prove XSS. Baseline also sends no payload to test it.
- Additional:
  - The scan ran without login. Everything behind login (basket, profile, admin pages) went untested.
  - Passive only. Injections such as the SQLi in routes/search.ts that Semgrep found cannot be found by baseline.
  - API endpoints not linked from HTML (/rest/..., /api/...) are not found by the spider. That needs an OpenAPI definition and zap-api-scan.py.
  - Business logic (for example negative quantities in the basket or the wallet balance) cannot be detected by any tool.
  - Instance counts are not accurate. zap.log records "Disabling passive scan rule ... as it has raised more than 10 alerts" (maxAlertsPerRule 10), so counts are a lower bound, not a total.

### ZAP status

Done on 2026-11-21 (slim scope).

Carried into later phases:
- Own ZAP image with pscanrulesBeta installed at build time, scan with -z "-silent" (decision Z4b B).
- Phase 3 gate: exit 1 for FAIL, 2 for WARN, 3 for error. Tune rules to IGNORE/WARN/FAIL with -g and -c. Do not use -I without a reason.
- Phase 4 script: do not read only the JSON report. Also check the number of loaded rules, because coverage can drop without an error.
- Consider the AJAX spider (-j), an authenticated scan, and zap-api-scan.py.
- Network choices in CI differ, because a GitHub Actions runner is a single-use VM with internet access.
