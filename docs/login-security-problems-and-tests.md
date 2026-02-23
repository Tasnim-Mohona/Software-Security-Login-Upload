# Login Security Problems (React + Express + PostgreSQL) and Automated QA Tests

This document is a QA-focused checklist of common login-page security weaknesses and the automated tests you can run for each one.

## 1) Common Security Problems on Login Pages

| # | Security Problem | Typical Impact | Relevant CWE | What to Verify |
|---|---|---|---|---|
| 1 | SQL/NoSQL injection in login inputs | Auth bypass, data theft | CWE-89 | Login endpoint uses parameterized queries and rejects crafted payloads. |
| 2 | User enumeration via error messages | Helps attackers target valid accounts | CWE-203 | Error responses are generic (`Invalid credentials`) for all failures. |
| 3 | Weak password policy | Easy brute-force or credential stuffing success | CWE-521 | Strong password rules exist for registration/password change flows. |
| 4 | Missing rate-limiting / lockout | Online brute-force attacks | CWE-307 | Repeated failed attempts trigger delays, lockouts, or throttling. |
| 5 | Missing MFA for sensitive roles | Single-factor compromise risk | CWE-287 | Admin or privileged users must complete MFA before session issuance. |
| 6 | Insecure session cookies | Session hijacking risk | CWE-614 | Cookies use `HttpOnly`, `Secure`, `SameSite` and short expiration. |
| 7 | Session fixation | Attacker reuses known session identifiers | CWE-384 | Session ID is regenerated after successful login. |
| 8 | CSRF on login and password operations | Forced authentication state changes | CWE-352 | CSRF token or same-site protections are enforced correctly. |
| 9 | Missing security headers | Clickjacking/content-type abuse | CWE-1021 | Responses include `X-Frame-Options`, `X-Content-Type-Options`, CSP. |
| 10 | Sensitive data in logs | Password/token leakage in logs | CWE-532 | Passwords and secrets are redacted; auth events are structured. |
| 11 | Plaintext or weak password storage | Full account takeover after DB breach | CWE-256 | Passwords hashed with bcrypt/argon2 and proper cost parameters. |
| 12 | Verbose backend errors | Leaks SQL/schema/internal stack traces | CWE-209 | API returns sanitized errors without implementation details. |

---

## 2) Automated Security Test Plan for QA

Use this as a CI-friendly matrix for your React + Express + PostgreSQL stack.

| Test Category | What to Automate | Suggested Tooling |
|---|---|---|
| API negative testing | Invalid payloads, injection strings, malformed JSON | Jest + Supertest |
| Authentication abuse | Brute-force/rate-limit behavior and lockout reset windows | Jest + Supertest + fake timers |
| Session/cookie checks | `Set-Cookie` flags (`HttpOnly`, `Secure`, `SameSite`) | Supertest assertions |
| Security header checks | `X-Frame-Options`, `X-Content-Type-Options`, CSP, HSTS | Supertest assertions |
| Dependency risk checks | Known vulnerable packages in frontend/backend | `npm audit` / `pnpm audit` |
| Static security linting | Risky coding patterns and known anti-patterns | ESLint security plugins, Semgrep |
| Dynamic baseline scan | OWASP Top 10 style endpoint probing | OWASP ZAP baseline action |

---

## 3) Included Starter Automation in This Repository

A starter script is included at `scripts/security/login-security-tests.mjs` to run lightweight security smoke checks against your login endpoint.

Current checks:
1. Reject malformed login payloads.
2. Reject SQL injection-like payloads.
3. Ensure baseline security headers are present.
4. Ensure auth failure messages do not leak user-enumeration hints.

Configure the script using environment variables:
- `BASE_URL` (default `http://127.0.0.1:3000`)
- `LOGIN_PATH` (default `/api/auth/login`)
- `USERNAME_FIELD` (default `email`)
- `PASSWORD_FIELD` (default `password`)

Example local run:

```bash
BASE_URL=http://127.0.0.1:3000 \
LOGIN_PATH=/api/auth/login \
node scripts/security/login-security-tests.mjs
```

---



## 4) Practical QA Acceptance Criteria for Login Security

A pull request that changes authentication should fail unless:
- Injection payload tests pass.
- Rate-limit behavior is verified.
- Generic auth error messaging is preserved.
- Cookie/header checks pass.
- `npm audit` has no high/critical unresolved issues (or waivers are documented).

This turns security from a one-time review into a repeatable QA gate.
