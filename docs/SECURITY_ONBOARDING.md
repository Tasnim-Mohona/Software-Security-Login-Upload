# Developer Security Onboarding Guide
## CS 4417/6417 – Secure SDLC Project

This document explains the full security gate every developer must pass through
before code reaches the `main` branch. Read this before writing your first commit.

---

## The Three Lines of Defense

```
Developer machine          GitHub (remote)           main branch
────────────────────       ──────────────────        ─────────────
git commit                 Pull Request opened       All jobs green?
    │                           │                         │
    ▼                           ▼                         ▼
Pre-commit hooks            GitHub Actions CI         Branch Protection
(blocks bad commit)         (blocks bad PR)           (enforces rules)
```

No code bypasses all three. Here is what each layer checks.

---

## Layer 1 — Pre-commit Hooks (Your Machine)

These run the moment you type `git commit`. If any hook fails, the commit is
aborted and you see exactly what went wrong.

### One-time Setup

```bash
pip install pre-commit
pre-commit install      # installs hooks into your local .git/hooks/
```

That's it. From now on every commit is automatically checked.

### What Hooks Run

| Hook | Catches | OWASP Category |
|------|---------|----------------|
| **Gitleaks** | Hardcoded secrets, API keys, JWT secrets | Data Protection |
| **check-dotenv** | `.env` files staged for commit | Authentication |
| **detect-private-key** | SSH/TLS private keys in code | Cryptography |
| **Bandit** | Python security anti-patterns (`eval`, `shell=True`, weak hash) | Input Validation |
| **Ruff** | Python style and safety linting | General Coding Practices |
| **ESLint** | JS/TS `eval()`, `dangerouslySetInnerHTML`, implied eval | Output Encoding |
| **npm audit** | Known CVEs in your dependencies | General Coding Practices |
| **Hadolint** | Dockerfile running as root, `ADD` vs `COPY` | System Configuration |
| **check-large-files** | Binary dumps, data files >1MB | Data Protection |

### Running Hooks Manually

```bash
pre-commit run --all-files       # check everything
pre-commit run bandit            # check only bandit
pre-commit run gitleaks          # check only secret detection
```

---

## Layer 2 — GitHub Actions CI (Remote)

When you push a branch and open a Pull Request, 9 jobs run in parallel.
**Every job must pass green before the PR can be merged.**

### Job Summary

```
┌─────────────────────────────────────────────────────────────────┐
│  PR Opened → All 9 jobs trigger simultaneously                  │
│                                                                 │
│  ① Secret Detection      (Gitleaks + .env check)               │
│  ② Dependency Audit      (npm audit + pip-audit)                │
│  ③ Static Analysis       (Bandit + ESLint + Semgrep OWASP)      │
│  ④ Backend Tests         (pytest unit + integration, 75% cov)   │
│  ⑤ Frontend Tests        (jest + lint + build)                  │
│  ⑥ Auth Security Tests   (brute force, JWT, RBAC)               │
│  ⑦ File Upload Tests     (type spoofing, path traversal)        │
│  ⑧ Fuzzing               (hypothesis — 1000+ generated inputs)  │
│  ⑨ SonarCloud Gate       (security hotspots, coverage, bugs)    │
│                                                                 │
│  If ANY job fails → PR cannot merge                             │
└─────────────────────────────────────────────────────────────────┘
```

### OWASP Category → CI Job Mapping

| OWASP Category | CI Job | Tool |
|---|---|---|
| Input Validation | ③ Static Analysis, ⑧ Fuzzing | Semgrep, Hypothesis |
| Output Encoding | ③ Static Analysis | Semgrep, ESLint |
| Authentication & Passwords | ④ Backend Tests, ⑥ Auth Tests | pytest |
| Session Management | ⑥ Auth Security Tests | pytest |
| Access Control (RBAC) | ⑥ Auth Security Tests | pytest |
| Cryptographic Practices | ④ Backend Tests | pytest |
| Error Handling & Logging | ④ Backend Tests | pytest |
| Data Protection | ① Secret Detection | Gitleaks |
| Communication Security | ⑨ SonarCloud | SonarCloud |
| System Configuration | ② Dependency Audit | pip-audit, npm audit |
| Database Security | ③ Static Analysis, ④ Backend Tests | Semgrep, pytest |
| File Management | ⑦ File Upload Tests | pytest |
| General Coding Practices | ③ Static Analysis | Bandit, ESLint |

---

## Layer 3 — Branch Protection Rules (Configure Once)

A repository admin must configure these in GitHub:
`Settings → Branches → Add rule → Branch name: main`

### Required Settings

```
✅ Require a pull request before merging
   ✅ Require approvals: 1
   ✅ Dismiss stale pull request approvals when new commits are pushed

✅ Require status checks to pass before merging
   ✅ Require branches to be up to date before merging

   Required status checks (add all of these):
   ─────────────────────────────────────────
   • Secret & Credential Detection
   • Dependency Vulnerability Scan
   • Static Analysis (SAST)
   • Backend Tests (Unit + Integration)
   • Frontend Tests & Build
   • Auth & Session Security Tests
   • File Upload Security Tests
   • Input Validation Fuzzing
   • SonarCloud Quality Gate

✅ Require conversation resolution before merging
✅ Do not allow bypassing the above settings
```

> ⚠️ "Do not allow bypassing" prevents even admins from force-pushing to main.
> This provides the audit trail your report requires.

---

## Developer Workflow (Step by Step)

```bash
# 1. Never work directly on main
git checkout -b feature/my-feature-name

# 2. Write code. Pre-commit hooks validate on every commit.
git add .
git commit -m "feat: add input validation for feedback endpoint"
# ↑ Gitleaks, Bandit, ESLint all run automatically here

# 3. Push your branch
git push origin feature/my-feature-name

# 4. Open a Pull Request on GitHub
#    → All 9 CI jobs trigger automatically
#    → Request review from a teammate

# 5. Fix any failures. Re-push to the same branch.
#    → CI reruns automatically on every push

# 6. Once all 9 jobs are green AND you have 1 approval → Merge
```

---

## Common Failure Scenarios & Fixes

### ❌ Gitleaks found a secret
```
# Find what triggered it
gitleaks detect --source . --verbose

# If it's a false positive, add to .gitleaks.toml:
[[rules.allowlist]]
description = "Allow test fixture"
regexes = ["test-secret-key-for-ci-only"]
```

### ❌ Bandit: B106 - hardcoded password
```python
# Bad — Bandit flags this
password = "admin123"

# Good — use environment variables
import os
password = os.getenv("ADMIN_PASSWORD")
```

### ❌ npm audit found HIGH vulnerability
```bash
# Try automatic fix first
npm audit fix

# If that fails, check if a patch exists
npm audit fix --force   # careful: may break things

# If no fix exists, document it as an accepted risk in your report
```

### ❌ SonarCloud: Unreviewed security hotspot
```
1. Go to your SonarCloud project dashboard
2. Click "Security Hotspots" tab
3. Review each hotspot — mark as "Safe" or "To Fix"
4. All hotspots must be reviewed before PR can merge
```

### ❌ Backend tests: coverage below 75%
```bash
# Run locally to see what's missing
pytest --cov=app --cov-report=html
open htmlcov/index.html  # see which lines are uncovered

# Add tests for uncovered security-critical paths
```

---

## SonarCloud First-Time Setup

```bash
# 1. Go to https://sonarcloud.io
# 2. Sign in with GitHub
# 3. Import your repository (click + → Analyze new project)
# 4. Choose "GitHub Actions" as the CI method
# 5. Copy your SONAR_TOKEN

# 6. Add to GitHub Secrets:
#    Settings → Secrets and variables → Actions → New repository secret
#    Name: SONAR_TOKEN
#    Value: (paste your token)

# 7. Update sonar-project.properties with your project key and org
```

---

## Report Documentation Checklist

For your CS 4417/6417 report, document evidence of each security activity:

- [ ] Screenshot of pre-commit hook blocking a commit (try committing a test secret)
- [ ] Screenshot of all 9 GitHub Actions jobs passing green on a PR
- [ ] Screenshot of SonarCloud dashboard showing Security Rating: A
- [ ] Screenshot of branch protection settings
- [ ] Bandit JSON report (uploaded as CI artifact)
- [ ] pytest coverage report (uploaded as CI artifact)
- [ ] Hypothesis fuzzing output showing number of examples tested
- [ ] Table mapping each OWASP checklist item to its test in your test suite
