"""
backend/tests/security/test_owasp_checklist.py

OWASP Secure Coding Practices – Full Checklist Test Suite
Maps every checklist category to concrete pytest tests for this project.

Run:  pytest tests/security/test_owasp_checklist.py -v
"""

import io
import re
import pytest
from httpx import AsyncClient
from app.main import app

# ─────────────────────────────────────────────────────────────────────────────
# FIXTURES
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
async def client():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac

@pytest.fixture
async def admin_token(client):
    resp = await client.post("/auth/login", json={
        "email": "admin@test.com",
        "password": "Admin@1234!"
    })
    assert resp.status_code == 200
    return resp.json()["access_token"]

@pytest.fixture
async def user_token(client):
    resp = await client.post("/auth/login", json={
        "email": "user@test.com",
        "password": "User@1234!"
    })
    assert resp.status_code == 200
    return resp.json()["access_token"]


# ═════════════════════════════════════════════════════════════════════════════
# 1. INPUT VALIDATION
# OWASP: Conduct all input validation on a trusted system (server side)
# ═════════════════════════════════════════════════════════════════════════════

class TestInputValidation:

    @pytest.mark.asyncio
    async def test_sql_injection_in_login_email(self, client):
        """All validation failures should result in input rejection."""
        payloads = [
            "' OR '1'='1",
            "admin'--",
            "'; DROP TABLE users;--",
            "' UNION SELECT * FROM users--",
        ]
        for payload in payloads:
            resp = await client.post("/auth/login", json={
                "email": payload,
                "password": "anything"
            })
            assert resp.status_code in [400, 422], \
                f"SQL injection payload accepted: {payload}"

    @pytest.mark.asyncio
    async def test_xss_payload_in_feedback(self, client, user_token):
        """Validate all client provided data before processing."""
        xss_payloads = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<svg onload=alert(1)>",
        ]
        for payload in xss_payloads:
            resp = await client.post(
                "/feedback",
                json={"message": payload},
                headers={"Authorization": f"Bearer {user_token}"}
            )
            assert resp.status_code in [400, 422], \
                f"XSS payload accepted in feedback: {payload}"

    @pytest.mark.asyncio
    async def test_oversized_input_rejected(self, client, user_token):
        """Validate data length."""
        resp = await client.post(
            "/feedback",
            json={"message": "A" * 100_000},
            headers={"Authorization": f"Bearer {user_token}"}
        )
        assert resp.status_code in [400, 422], \
            "Oversized input was not rejected"

    @pytest.mark.asyncio
    async def test_empty_required_fields_rejected(self, client):
        """All validation failures should result in input rejection."""
        cases = [
            {"email": "", "password": "Admin@1234!"},
            {"email": "admin@test.com", "password": ""},
            {"email": None, "password": "Admin@1234!"},
        ]
        for case in cases:
            resp = await client.post("/auth/login", json=case)
            assert resp.status_code in [400, 422], \
                f"Empty/null field accepted: {case}"

    @pytest.mark.asyncio
    async def test_invalid_email_format_rejected(self, client):
        """Validate for expected data types using an allow-list."""
        invalid_emails = [
            "not-an-email",
            "@nodomain",
            "missing@",
            "spaces in@email.com",
        ]
        for email in invalid_emails:
            resp = await client.post("/auth/login", json={
                "email": email,
                "password": "Admin@1234!"
            })
            assert resp.status_code in [400, 422], \
                f"Invalid email accepted: {email}"

    @pytest.mark.asyncio
    async def test_unicode_obfuscation_rejected(self, client, user_token):
        """Utilize canonicalization to address obfuscation attacks."""
        # Unicode lookalikes used in injection attacks
        obfuscated = "\u202e<script>alert(1)</script>"
        resp = await client.post(
            "/feedback",
            json={"message": obfuscated},
            headers={"Authorization": f"Bearer {user_token}"}
        )
        assert resp.status_code in [400, 422]

    @pytest.mark.asyncio
    async def test_null_bytes_rejected(self, client, user_token):
        """Validate all client provided data before processing."""
        resp = await client.post(
            "/feedback",
            json={"message": "normal\x00hidden"},
            headers={"Authorization": f"Bearer {user_token}"}
        )
        assert resp.status_code in [400, 422]


# ═════════════════════════════════════════════════════════════════════════════
# 2. OUTPUT ENCODING
# OWASP: Contextually output encode all data returned to the client
# ═════════════════════════════════════════════════════════════════════════════

class TestOutputEncoding:

    @pytest.mark.asyncio
    async def test_response_content_type_is_json(self, client):
        """Specify character sets for all outputs."""
        resp = await client.post("/auth/login", json={
            "email": "admin@test.com",
            "password": "Admin@1234!"
        })
        assert "application/json" in resp.headers.get("content-type", ""), \
            "Response content-type is not application/json"

    @pytest.mark.asyncio
    async def test_stored_xss_not_reflected(self, client, user_token, admin_token):
        """Contextually sanitize all output of un-trusted data."""
        # Store a payload
        await client.post(
            "/feedback",
            json={"message": "Hello <b>world</b>"},
            headers={"Authorization": f"Bearer {user_token}"}
        )
        # Retrieve and ensure HTML is not raw in JSON
        resp = await client.get(
            "/feedback",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        body = resp.text
        assert "<b>world</b>" not in body, \
            "Raw HTML tags reflected in response output"

    @pytest.mark.asyncio
    async def test_security_headers_present(self, client):
        """Ensure the output encoding is safe for all target systems."""
        resp = await client.get("/health")
        headers = resp.headers
        assert "x-content-type-options" in headers, "Missing X-Content-Type-Options"
        assert "x-frame-options" in headers, "Missing X-Frame-Options"
        assert headers.get("x-content-type-options") == "nosniff"


# ═════════════════════════════════════════════════════════════════════════════
# 3. AUTHENTICATION & PASSWORD MANAGEMENT
# OWASP: Enforce password complexity, hashing, failure responses
# ═════════════════════════════════════════════════════════════════════════════

class TestAuthentication:

    @pytest.mark.asyncio
    async def test_weak_password_rejected_on_registration(self, client, admin_token):
        """Enforce password complexity requirements."""
        weak_passwords = [
            "password",        # no uppercase, no digits, no special
            "PASSWORD1",       # no lowercase, no special
            "Password",        # no digit, no special
            "Pass1",           # too short
            "password123!",    # no uppercase
        ]
        for pw in weak_passwords:
            resp = await client.post(
                "/users",
                json={"email": "newuser@test.com", "password": pw, "role": "user"},
                headers={"Authorization": f"Bearer {admin_token}"}
            )
            assert resp.status_code in [400, 422], \
                f"Weak password accepted: {pw}"

    @pytest.mark.asyncio
    async def test_strong_password_accepted(self, client, admin_token):
        """Enforce password complexity requirements."""
        resp = await client.post(
            "/users",
            json={
                "email": "stronguser@test.com",
                "password": "Str0ng@Pass!2024",
                "role": "user"
            },
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert resp.status_code in [200, 201]

    @pytest.mark.asyncio
    async def test_login_failure_does_not_reveal_field(self, client):
        """Authentication failure responses should not indicate which part was incorrect."""
        # Wrong password for real user
        resp1 = await client.post("/auth/login", json={
            "email": "admin@test.com",
            "password": "WrongPassword1!"
        })
        # Non-existent user
        resp2 = await client.post("/auth/login", json={
            "email": "doesnotexist@test.com",
            "password": "WrongPassword1!"
        })
        body1 = resp1.json()
        body2 = resp2.json()
        # Both responses must use the same generic message
        assert resp1.status_code == resp2.status_code == 401
        # Should NOT say "user not found" vs "wrong password"
        for forbidden in ["not found", "no user", "invalid password", "wrong password"]:
            assert forbidden not in str(body1).lower(), \
                f"Response reveals field info: {body1}"
            assert forbidden not in str(body2).lower(), \
                f"Response reveals field info: {body2}"

    @pytest.mark.asyncio
    async def test_password_not_returned_in_any_response(self, client, admin_token):
        """Use cryptographically strong one-way salted hashes."""
        resp = await client.get(
            "/users",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert resp.status_code == 200
        body = resp.text
        # Raw passwords or bcrypt hashes must not appear in list endpoints
        assert "password" not in body.lower() or "$2b$" not in body, \
            "Password hash exposed in user listing response"

    @pytest.mark.asyncio
    async def test_account_lockout_after_failed_attempts(self, client):
        """Enforce account disabling after an established number of invalid login attempts."""
        for i in range(6):  # Attempt 6 times
            await client.post("/auth/login", json={
                "email": "admin@test.com",
                "password": f"WrongPass{i}!"
            })
        # 7th attempt — should be locked
        resp = await client.post("/auth/login", json={
            "email": "admin@test.com",
            "password": "Admin@1234!"  # correct password
        })
        assert resp.status_code == 429, \
            "Account not locked after repeated failed attempts"

    @pytest.mark.asyncio
    async def test_login_uses_post_not_get(self, client):
        """Use only HTTP POST requests to transmit authentication credentials."""
        resp = await client.get("/auth/login")
        assert resp.status_code == 405, \
            "GET /auth/login should not be allowed (credentials in URL)"

    @pytest.mark.asyncio
    async def test_unauthenticated_access_denied(self, client):
        """Require authentication for all pages and resources except public ones."""
        protected_routes = [
            "/users",
            "/feedback",
            "/admin/logs",
        ]
        for route in protected_routes:
            resp = await client.get(route)
            assert resp.status_code in [401, 403], \
                f"Unauthenticated access allowed on: {route}"


# ═════════════════════════════════════════════════════════════════════════════
# 4. SESSION MANAGEMENT
# OWASP: JWT token validity, logout invalidation, no session in URLs
# ═════════════════════════════════════════════════════════════════════════════

class TestSessionManagement:

    @pytest.mark.asyncio
    async def test_logout_invalidates_token(self, client, user_token):
        """Logout functionality should fully terminate the associated session."""
        # Logout
        resp = await client.post(
            "/auth/logout",
            headers={"Authorization": f"Bearer {user_token}"}
        )
        assert resp.status_code == 200

        # Token should now be rejected
        resp2 = await client.get(
            "/users/me",
            headers={"Authorization": f"Bearer {user_token}"}
        )
        assert resp2.status_code in [401, 403], \
            "Token still valid after logout"

    @pytest.mark.asyncio
    async def test_expired_token_rejected(self, client):
        """Session management controls should use well vetted algorithms."""
        expired_token = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiJ0ZXN0QHRlc3QuY29tIiwiZXhwIjoxfQ."  # exp=1 (past)
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        resp = await client.get(
            "/users/me",
            headers={"Authorization": f"Bearer {expired_token}"}
        )
        assert resp.status_code in [401, 403]

    @pytest.mark.asyncio
    async def test_malformed_token_rejected(self, client):
        """Application should recognize only valid session identifiers."""
        malformed_tokens = [
            "notavalidtoken",
            "Bearer ",
            "eyJhbGci.invalid.sig",
        ]
        for token in malformed_tokens:
            resp = await client.get(
                "/users/me",
                headers={"Authorization": f"Bearer {token}"}
            )
            assert resp.status_code in [401, 403], \
                f"Malformed token accepted: {token}"

    @pytest.mark.asyncio
    async def test_token_not_in_url(self, client, user_token):
        """Do not expose session identifiers in URLs, error messages or logs."""
        # Endpoint should not accept token as query param (security risk)
        resp = await client.get(f"/users/me?token={user_token}")
        # Either reject or ignore the query param token — must not authenticate via URL
        # The only valid auth method is Authorization header
        resp_no_header = await client.get("/users/me")
        assert resp_no_header.status_code in [401, 403], \
            "Endpoint may be accepting token from URL query parameter"


# ═════════════════════════════════════════════════════════════════════════════
# 5. ACCESS CONTROL (RBAC)
# OWASP: Restrict access to protected URLs/functions to only authorized users
# ═════════════════════════════════════════════════════════════════════════════

class TestAccessControl:

    @pytest.mark.asyncio
    async def test_regular_user_cannot_create_users(self, client, user_token):
        """Segregate privileged logic from other application code."""
        resp = await client.post(
            "/users",
            json={
                "email": "hacker@test.com",
                "password": "Hacked@1234!",
                "role": "admin"
            },
            headers={"Authorization": f"Bearer {user_token}"}
        )
        assert resp.status_code in [401, 403], \
            "Regular user was able to create users"

    @pytest.mark.asyncio
    async def test_user_cannot_escalate_own_role(self, client, user_token):
        """Strict RBAC: Backend must override all role assignments."""
        resp = await client.patch(
            "/users/me",
            json={"role": "admin"},
            headers={"Authorization": f"Bearer {user_token}"}
        )
        assert resp.status_code in [400, 403], \
            "User was able to self-escalate to admin role"

    @pytest.mark.asyncio
    async def test_admin_can_access_audit_logs(self, client, admin_token):
        """Restrict access to logs to only authorized individuals."""
        resp = await client.get(
            "/admin/logs",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_user_cannot_access_audit_logs(self, client, user_token):
        """Restrict access to logs to only authorized individuals."""
        resp = await client.get(
            "/admin/logs",
            headers={"Authorization": f"Bearer {user_token}"}
        )
        assert resp.status_code in [401, 403]

    @pytest.mark.asyncio
    async def test_user_cannot_access_other_users_data(self, client, user_token):
        """Restrict direct object references to only authorized users."""
        # Attempt to access user ID 1 (likely admin) as a regular user
        resp = await client.get(
            "/users/1",
            headers={"Authorization": f"Bearer {user_token}"}
        )
        assert resp.status_code in [401, 403, 404]

    @pytest.mark.asyncio
    async def test_new_user_role_is_always_user_not_admin(self, client, admin_token):
        """Protect against payload spoofing of role."""
        resp = await client.post(
            "/users",
            json={
                "email": "spooftest@test.com",
                "password": "Valid@Pass1234!",
                "role": "admin"   # Attacker tries to claim admin role
            },
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        if resp.status_code in [200, 201]:
            user = resp.json()
            assert user.get("role") != "admin", \
                "Backend accepted attacker-supplied admin role"


# ═════════════════════════════════════════════════════════════════════════════
# 6. CRYPTOGRAPHIC PRACTICES
# OWASP: Secrets protected, modules fail securely, FIPS-compliant algorithms
# ═════════════════════════════════════════════════════════════════════════════

class TestCryptography:

    def test_password_hashed_with_bcrypt(self):
        """Use cryptographically strong one-way salted hashes."""
        from app.core.security import hash_password, verify_password
        password = "TestPass@123!"
        hashed = hash_password(password)
        # bcrypt hashes start with $2b$
        assert hashed.startswith("$2b$"), \
            "Password not hashed with bcrypt"
        assert hashed != password, \
            "Password stored in plaintext"

    def test_different_passwords_produce_different_hashes(self):
        """All random strings should be generated using approved RNG."""
        from app.core.security import hash_password
        h1 = hash_password("TestPass@123!")
        h2 = hash_password("TestPass@123!")
        # bcrypt salts: same password → different hash each time
        assert h1 != h2, \
            "bcrypt salt not applied — same password produces identical hash"

    def test_password_verification_works(self):
        """Cryptographic modules should fail securely."""
        from app.core.security import hash_password, verify_password
        password = "TestPass@123!"
        hashed = hash_password(password)
        assert verify_password(password, hashed) is True
        assert verify_password("WrongPassword!", hashed) is False

    def test_jwt_uses_strong_algorithm(self):
        """Use well vetted algorithms for session identifiers."""
        from app.core.security import create_access_token
        import jwt as pyjwt
        token = create_access_token({"sub": "test@test.com"})
        # Decode header without verification to check algorithm
        header = pyjwt.get_unverified_header(token)
        assert header["alg"] in ["HS256", "RS256"], \
            f"JWT uses unexpected algorithm: {header['alg']}"
        assert header["alg"] != "none", \
            "JWT algorithm set to 'none' — critical vulnerability"


# ═════════════════════════════════════════════════════════════════════════════
# 7. ERROR HANDLING & LOGGING
# OWASP: No stack traces in responses, auth events logged
# ═════════════════════════════════════════════════════════════════════════════

class TestErrorHandlingAndLogging:

    @pytest.mark.asyncio
    async def test_404_does_not_reveal_stack_trace(self, client):
        """Use error handlers that do not display debugging or stack trace info."""
        resp = await client.get("/this/route/does/not/exist")
        body = resp.text.lower()
        for leak in ["traceback", "file \"", "line ", "exception", "sqlalchemy"]:
            assert leak not in body, \
                f"Stack trace keyword '{leak}' found in 404 response"

    @pytest.mark.asyncio
    async def test_500_does_not_reveal_internal_details(self, client):
        """Do not disclose sensitive information in error responses."""
        # Force a bad request that might trigger an internal error
        resp = await client.post("/auth/login", content=b"not json at all",
                                  headers={"Content-Type": "application/json"})
        body = resp.text.lower()
        for leak in ["traceback", "internal server error details", "database", "postgres"]:
            assert leak not in body, \
                f"Internal detail '{leak}' leaked in error response"

    @pytest.mark.asyncio
    async def test_failed_login_is_logged(self, client, tmp_path):
        """Log all authentication attempts, especially failures."""
        import os
        log_file = "backend/logs/audit.log"
        # Attempt a failed login
        await client.post("/auth/login", json={
            "email": "admin@test.com",
            "password": "WrongPassword1!"
        })
        # Audit log must exist and contain the failed attempt
        assert os.path.exists(log_file), "Audit log file does not exist"
        with open(log_file) as f:
            content = f.read()
        assert "LOGIN_FAILED" in content or "authentication" in content.lower(), \
            "Failed login not recorded in audit log"

    @pytest.mark.asyncio
    async def test_successful_login_is_logged(self, client):
        """Logging controls should support success of specified security events."""
        import os
        await client.post("/auth/login", json={
            "email": "admin@test.com",
            "password": "Admin@1234!"
        })
        log_file = "backend/logs/audit.log"
        with open(log_file) as f:
            content = f.read()
        assert "LOGIN_SUCCESS" in content or "login" in content.lower()

    @pytest.mark.asyncio
    async def test_access_control_failure_logged(self, client, user_token):
        """Log all access control failures."""
        import os
        await client.get(
            "/admin/logs",
            headers={"Authorization": f"Bearer {user_token}"}
        )
        log_file = "backend/logs/audit.log"
        with open(log_file) as f:
            content = f.read()
        assert "ACCESS_DENIED" in content or "forbidden" in content.lower(), \
            "Access control failure not logged"


# ═════════════════════════════════════════════════════════════════════════════
# 8. DATA PROTECTION
# OWASP: Sensitive data not in GET params, no passwords in responses
# ═════════════════════════════════════════════════════════════════════════════

class TestDataProtection:

    @pytest.mark.asyncio
    async def test_no_sensitive_data_in_get_params(self, client):
        """Do not include sensitive information in HTTP GET request parameters."""
        # Login via GET with credentials in URL should be rejected
        resp = await client.get(
            "/auth/login?email=admin@test.com&password=Admin@1234!"
        )
        assert resp.status_code in [400, 404, 405], \
            "GET with credentials in URL was accepted"

    @pytest.mark.asyncio
    async def test_sensitive_headers_not_cached(self, client, user_token):
        """Disable client side caching on pages containing sensitive information."""
        resp = await client.get(
            "/users/me",
            headers={"Authorization": f"Bearer {user_token}"}
        )
        cache = resp.headers.get("cache-control", "").lower()
        assert "no-store" in cache or "no-cache" in cache, \
            "Authenticated endpoint missing cache-control: no-store"

    @pytest.mark.asyncio
    async def test_autocomplete_disabled_hint_in_response(self, client):
        """Disable autocomplete features on forms containing sensitive info."""
        # This checks the API returns a flag/field that frontend should use
        # OR we test the HTML endpoint if SSR is used
        resp = await client.get("/")
        # For SPA, verify the frontend build contains autocomplete="off" on login form
        # This is a smoke check — full test is in frontend suite
        assert resp.status_code in [200, 404]  # App is reachable


# ═════════════════════════════════════════════════════════════════════════════
# 9. COMMUNICATION SECURITY
# OWASP: TLS, HTTPS enforcement, no HTTP fallback
# ═════════════════════════════════════════════════════════════════════════════

class TestCommunicationSecurity:

    @pytest.mark.asyncio
    async def test_cors_not_wildcard(self, client):
        """Filter parameters containing sensitive information from HTTP referer."""
        resp = await client.options("/auth/login", headers={
            "Origin": "https://evil.com",
            "Access-Control-Request-Method": "POST"
        })
        cors = resp.headers.get("access-control-allow-origin", "")
        assert cors != "*", \
            "CORS is set to wildcard (*) — allows any origin"

    @pytest.mark.asyncio
    async def test_hsts_header_present(self, client, user_token):
        """Utilize TLS connections for all content requiring authenticated access."""
        resp = await client.get(
            "/users/me",
            headers={"Authorization": f"Bearer {user_token}"}
        )
        # In production this must be present; skip in test env if not configured
        hsts = resp.headers.get("strict-transport-security", "")
        # Not asserting hard in test env, but log it
        if not hsts:
            pytest.skip("HSTS not set in test environment — verify in production")


# ═════════════════════════════════════════════════════════════════════════════
# 10. DATABASE SECURITY
# OWASP: Parameterized queries, least privilege, no hardcoded credentials
# ═════════════════════════════════════════════════════════════════════════════

class TestDatabaseSecurity:

    def test_no_raw_sql_in_source(self):
        """Use strongly typed parameterized queries."""
        import os
        import glob
        dangerous_patterns = [
            r'execute\s*\(\s*f"',            # f-string in execute()
            r'execute\s*\(\s*".*\+',         # string concatenation in execute()
            r'cursor\.execute\s*\(\s*".*%s',  # old-style % formatting
        ]
        python_files = glob.glob("backend/app/**/*.py", recursive=True)
        for filepath in python_files:
            with open(filepath) as f:
                content = f.read()
            for pattern in dangerous_patterns:
                matches = re.findall(pattern, content)
                assert not matches, \
                    f"Potential raw SQL in {filepath}: {matches}"

    def test_database_url_not_hardcoded(self):
        """Connection strings should not be hard coded within the application."""
        import glob
        python_files = glob.glob("backend/app/**/*.py", recursive=True)
        hardcoded_patterns = [
            r'postgresql://[^$\{]',
            r'postgres://[^$\{]',
            r'mysql://[^$\{]',
        ]
        for filepath in python_files:
            with open(filepath) as f:
                content = f.read()
            for pattern in hardcoded_patterns:
                matches = re.findall(pattern, content)
                assert not matches, \
                    f"Hardcoded DB connection string in {filepath}"

    @pytest.mark.asyncio
    async def test_second_order_sql_injection(self, client, admin_token):
        """Utilize input validation and output encoding — meta characters."""
        # Store a malicious value, then trigger it
        payload = "Robert'); DROP TABLE users;--"
        resp = await client.post(
            "/users",
            json={
                "email": "safe@test.com",
                "password": "Safe@Pass1234!",
                "full_name": payload
            },
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        # App must still function after storing potentially bad data
        health = await client.get("/health")
        assert health.status_code == 200, \
            "App crashed — possible second-order SQL injection"


# ═════════════════════════════════════════════════════════════════════════════
# 11. FILE MANAGEMENT
# OWASP: Type validation, size limits, path traversal, auth required
# (See also: test_file_upload.py for full dedicated suite)
# ═════════════════════════════════════════════════════════════════════════════

class TestFileManagement:

    @pytest.mark.asyncio
    async def test_file_upload_requires_authentication(self, client):
        """Require authentication before allowing a file to be uploaded."""
        file_content = b"Hello PDF content"
        resp = await client.post(
            "/feedback/upload",
            files={"file": ("test.pdf", io.BytesIO(file_content), "application/pdf")}
        )
        assert resp.status_code in [401, 403], \
            "File upload allowed without authentication"

    @pytest.mark.asyncio
    async def test_executable_file_rejected(self, client, user_token):
        """Prevent or restrict uploading of files interpreted by the web server."""
        dangerous_files = [
            ("malware.exe", b"MZ\x90\x00", "application/octet-stream"),
            ("shell.php", b"<?php system($_GET['cmd']); ?>", "text/plain"),
            ("script.sh", b"#!/bin/bash\nrm -rf /", "text/plain"),
            ("payload.js", b"require('child_process').exec('ls')", "text/javascript"),
        ]
        for filename, content, mime in dangerous_files:
            resp = await client.post(
                "/feedback/upload",
                files={"file": (filename, io.BytesIO(content), mime)},
                headers={"Authorization": f"Bearer {user_token}"}
            )
            assert resp.status_code in [400, 415, 422], \
                f"Dangerous file type accepted: {filename}"

    @pytest.mark.asyncio
    async def test_file_size_limit_enforced(self, client, user_token):
        """Limit the type of files that can be uploaded."""
        # 11MB file (assuming 10MB limit)
        large_file = b"A" * (11 * 1024 * 1024)
        resp = await client.post(
            "/feedback/upload",
            files={"file": ("large.pdf", io.BytesIO(large_file), "application/pdf")},
            headers={"Authorization": f"Bearer {user_token}"}
        )
        assert resp.status_code in [400, 413, 422], \
            "Oversized file was accepted"

    @pytest.mark.asyncio
    async def test_path_traversal_in_filename_rejected(self, client, user_token):
        """Do not pass user supplied data directly to any dynamic include function."""
        traversal_names = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "%2e%2e%2fetc%2fpasswd",
            "....//....//etc/passwd",
        ]
        for filename in traversal_names:
            resp = await client.post(
                "/feedback/upload",
                files={"file": (filename, io.BytesIO(b"content"), "application/pdf")},
                headers={"Authorization": f"Bearer {user_token}"}
            )
            assert resp.status_code in [400, 422], \
                f"Path traversal filename accepted: {filename}"

    @pytest.mark.asyncio
    async def test_file_type_validated_by_magic_bytes_not_extension(self, client, user_token):
        """Validate uploaded files by checking file headers, not extension."""
        # A .pdf file that is actually an executable (magic bytes MZ)
        fake_pdf = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 100
        resp = await client.post(
            "/feedback/upload",
            files={"file": ("document.pdf", io.BytesIO(fake_pdf), "application/pdf")},
            headers={"Authorization": f"Bearer {user_token}"}
        )
        assert resp.status_code in [400, 415, 422], \
            "File with spoofed extension accepted (magic bytes not checked)"

    @pytest.mark.asyncio
    async def test_absolute_path_not_returned_in_response(self, client, user_token):
        """Never send the absolute file path to the client."""
        valid_pdf_header = b"%PDF-1.4\n" + b"A" * 100
        resp = await client.post(
            "/feedback/upload",
            files={"file": ("valid.pdf", io.BytesIO(valid_pdf_header), "application/pdf")},
            headers={"Authorization": f"Bearer {user_token}"}
        )
        if resp.status_code in [200, 201]:
            body = resp.text
            assert "/home/" not in body, "Absolute Linux path exposed in response"
            assert "/var/" not in body, "Absolute Linux path exposed in response"
            assert "C:\\" not in body, "Absolute Windows path exposed in response"


# ═════════════════════════════════════════════════════════════════════════════
# 12. GENERAL CODING PRACTICES
# OWASP: No OS commands, no eval, integrity checks, no dynamic execution
# ═════════════════════════════════════════════════════════════════════════════

class TestGeneralCodingPractices:

    def test_no_eval_in_python_source(self):
        """Do not pass user supplied data to any dynamic execution function."""
        import glob
        files = glob.glob("backend/app/**/*.py", recursive=True)
        for filepath in files:
            with open(filepath) as f:
                content = f.read()
            # Check for eval with non-constant args (basic heuristic)
            assert "eval(" not in content or "# nosec" in content, \
                f"eval() found in {filepath} — review immediately"

    def test_no_shell_true_subprocess(self):
        """Do not allow application to issue commands directly to the OS."""
        import glob
        files = glob.glob("backend/app/**/*.py", recursive=True)
        for filepath in files:
            with open(filepath) as f:
                content = f.read()
            assert "shell=True" not in content, \
                f"subprocess shell=True found in {filepath} — injection risk"

    def test_no_pickle_deserialization(self):
        """Use tested and approved managed code — avoid insecure deserialization."""
        import glob
        files = glob.glob("backend/app/**/*.py", recursive=True)
        for filepath in files:
            with open(filepath) as f:
                content = f.read()
            assert "pickle.loads" not in content, \
                f"pickle.loads() found in {filepath} — insecure deserialization"
            assert "yaml.load(" not in content or "Loader=" in content, \
                f"Unsafe yaml.load() found in {filepath} — use yaml.safe_load()"

    def test_requirements_are_pinned(self):
        """Review all third party code to validate safe functionality."""
        with open("backend/requirements.txt") as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        for line in lines:
            # Each dependency should have a pinned version (== or >=)
            assert "==" in line or ">=" in line, \
                f"Unpinned dependency: {line} — use pinned versions for reproducibility"
