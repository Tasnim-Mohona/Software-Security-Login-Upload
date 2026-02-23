#!/usr/bin/env node

/**
 * Lightweight security smoke tests for login endpoints.
 *
 * Usage:
 *   node scripts/security/login-security-tests.mjs
 *
 * Environment variables:
 *   BASE_URL       (default: http://127.0.0.1:3000)
 *   LOGIN_PATH     (default: /api/auth/login)
 *   USERNAME_FIELD (default: email)
 *   PASSWORD_FIELD (default: password)
 */

const BASE_URL = process.env.BASE_URL ?? 'http://127.0.0.1:3000';
const LOGIN_PATH = process.env.LOGIN_PATH ?? '/api/auth/login';
const USERNAME_FIELD = process.env.USERNAME_FIELD ?? 'email';
const PASSWORD_FIELD = process.env.PASSWORD_FIELD ?? 'password';

const endpoint = new URL(LOGIN_PATH, BASE_URL).toString();

const checks = [];

function addResult(name, status, detail) {
  checks.push({ name, status, detail });
}

function printSummary() {
  console.log('\nSecurity test summary:');
  for (const check of checks) {
    const icon = check.status === 'pass' ? '✅' : '❌';
    console.log(`${icon} ${check.name} - ${check.detail}`);
  }

  const failed = checks.filter((c) => c.status === 'fail');
  if (failed.length > 0) {
    console.error(`\n${failed.length} security check(s) failed.`);
    process.exit(1);
  }

  console.log('\nAll security checks passed.');
}

async function postLogin(payload, extraHeaders = {}) {
  const res = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...extraHeaders,
    },
    body: JSON.stringify(payload),
    redirect: 'manual',
  });

  let bodyText = '';
  try {
    bodyText = await res.text();
  } catch {
    bodyText = '';
  }

  return { res, bodyText };
}

(async () => {
  // 1) Endpoint should reject malformed payloads.
  {
    const { res } = await postLogin({ unexpected: 'value' });
    const ok = res.status >= 400 && res.status < 500;
    addResult(
      'Reject malformed login payload',
      ok ? 'pass' : 'fail',
      `received HTTP ${res.status}`,
    );
  }

  // 2) Endpoint should reject SQL injection-style payloads.
  {
    const injection = "' OR '1'='1";
    const payload = {
      [USERNAME_FIELD]: injection,
      [PASSWORD_FIELD]: injection,
    };

    const { res, bodyText } = await postLogin(payload);
    const rejected = res.status === 400 || res.status === 401 || res.status === 403;
    const noStackTrace = !/sql|syntax error|sequelize|postgres|stack|exception/i.test(bodyText);

    addResult(
      'Reject SQL injection payload without verbose error leakage',
      rejected && noStackTrace ? 'pass' : 'fail',
      `status=${res.status}, leakCheck=${noStackTrace ? 'clean' : 'possible leakage'}`,
    );
  }

  // 3) Response should set protective security headers (best-effort baseline).
  {
    const payload = {
      [USERNAME_FIELD]: 'invalid@example.com',
      [PASSWORD_FIELD]: 'bad-password',
    };

    const { res } = await postLogin(payload);
    const requiredHeaders = ['x-content-type-options', 'x-frame-options'];
    const missing = requiredHeaders.filter((header) => !res.headers.get(header));

    addResult(
      'Expose baseline security headers',
      missing.length === 0 ? 'pass' : 'fail',
      missing.length === 0 ? 'all required headers present' : `missing: ${missing.join(', ')}`,
    );
  }

  // 4) Verify login failure message is generic and avoids user enumeration hints.
  {
    const payload = {
      [USERNAME_FIELD]: 'non-existent-user@example.com',
      [PASSWORD_FIELD]: 'WrongPassword123!',
    };

    const { res, bodyText } = await postLogin(payload);
    const isAuthFailure = res.status === 401 || res.status === 403 || res.status === 400;
    const looksGeneric = !/user not found|email does not exist|unknown account/i.test(bodyText);

    addResult(
      'Avoid account enumeration in auth errors',
      isAuthFailure && looksGeneric ? 'pass' : 'fail',
      `status=${res.status}, genericMessage=${looksGeneric}`,
    );
  }

  printSummary();
})().catch((err) => {
  console.error('Security test runner crashed:', err);
  process.exit(1);
});
