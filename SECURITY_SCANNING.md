# Purpeye — CI/CD Security Scanning

This pipeline runs four classes of security scanning automatically on every
push and pull request, plus a weekly scheduled run.

| Stage | Tool | Catches |
|-------|------|---------|
| SAST | Semgrep | Vulnerable patterns in **your own code** (SQLi, command injection, unsafe deserialization, hardcoded logic flaws) |
| Dependency scan | pip-audit | Known **CVEs in the packages you import** |
| Secret scan | Gitleaks | API keys, tokens, passwords committed **anywhere in history** |
| Container/FS scan | Trivy | **CVEs in OS packages and dependencies** (image or filesystem) |

## The four scan types — know the difference

- **SAST reads code you wrote.** It flags a line like
  `cursor.execute("SELECT * FROM users WHERE id=" + user_input)` as SQLi.
  It does **not** know about CVEs in libraries.
- **Dependency scanning reads your requirements**, not your code. It says
  "you're on requests 2.19.0, which has CVE-XXXX, upgrade to 2.20.0."
- **Container/FS scanning** looks at the whole filesystem or a built image —
  OS-level packages (openssl, glibc) and language deps — for known CVEs.
- **Secret scanning** greps history for things that look like credentials.

These overlap a little (Trivy also reads Python deps) but they answer
different questions. In short: **SAST finds bugs you introduced;
dependency scanning finds bugs you inherited.**

## How to run it

1. `.github/workflows/security.yml` runs automatically on every push and PR
   to `main`, plus weekly.
2. Open the repo on GitHub → **Actions** tab → watch the run.
3. Findings land in the **Security** tab → Code scanning alerts (Semgrep and
   Trivy upload there via SARIF). pip-audit and Gitleaks output show in the
   Actions run logs.

## Test locally

```bash
pip install semgrep pip-audit
semgrep scan --config=auto            # SAST
pip-audit -r requirements.txt --desc  # dependency scan

# Trivy (Linux):
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
trivy fs .                            # filesystem scan
```

## Notes on findings

- The HTTPS-redirect check (`scanner/checks/https_redirect_check.py`)
  intentionally sends a plaintext HTTP request to verify the target upgrades
  to HTTPS. Semgrep flagged this as insecure transport; it is a documented
  false positive, suppressed inline with `nosemgrep`.

## Turning it from "report" into "gate" (future work)

The scanners currently report but don't fail the build (`|| true`,
`exit-code: '0'`). To make it a blocking security gate:

- Semgrep: remove `|| true` so a finding fails the job.
- Trivy: set `exit-code: '1'` to fail on CRITICAL/HIGH.

## Common mistakes

- **Wrong file path.** Must be `.github/workflows/security.yml`. A typo and
  GitHub silently ignores it — no error, just no run.
- **Forgetting `permissions:`.** Without `security-events: write`, the SARIF
  upload fails.
- **Gitleaks flagging test fixtures.** Add a `.gitleaks.toml` allowlist rather
  than deleting the tests.
- **Trivy version pinning.** If a step breaks, check the action's latest
  release tag.
