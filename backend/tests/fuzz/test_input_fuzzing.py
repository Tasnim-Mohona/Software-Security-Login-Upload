"""
backend/tests/fuzz/test_input_fuzzing.py

Hypothesis-based fuzzing for OWASP Input Validation & Output Encoding.
Generates thousands of edge-case inputs automatically to find validator gaps.

OWASP: Validate all data from untrusted sources
       Utilize canonicalization to address obfuscation attacks

Run:  pytest tests/fuzz/ -v --hypothesis-seed=0
"""

import pytest
from hypothesis import given, settings, strategies as st
from httpx import AsyncClient
from app.main import app


@pytest.fixture
async def client():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac


# ─────────────────────────────────────────────────────────────────────────────
# PASSWORD COMPLEXITY FUZZER
# OWASP: Enforce password complexity requirements
# ─────────────────────────────────────────────────────────────────────────────

WEAK_PASSWORD_PATTERN = st.one_of(
    st.text(alphabet=st.characters(whitelist_categories=("Ll",)), min_size=8, max_size=20),  # lowercase only
    st.text(alphabet=st.characters(whitelist_categories=("Lu",)), min_size=8, max_size=20),  # uppercase only
    st.text(alphabet="0123456789", min_size=8, max_size=20),                                 # digits only
    st.text(min_size=1, max_size=5),                                                          # too short
)

@given(password=WEAK_PASSWORD_PATTERN)
@settings(max_examples=200)
def test_fuzz_weak_passwords_always_rejected(password):
    """Any password lacking uppercase+lowercase+digit+special should be rejected."""
    from app.core.validators import validate_password_complexity
    # The validator should return False for all weak passwords
    result = validate_password_complexity(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
    has_length = len(password) >= 8

    is_strong = has_upper and has_lower and has_digit and has_special and has_length
    if not is_strong:
        assert result is False, \
            f"Weak password accepted by validator: '{password}'"


# ─────────────────────────────────────────────────────────────────────────────
# EMAIL FORMAT FUZZER
# OWASP: Validate for expected data types using an allow-list
# ─────────────────────────────────────────────────────────────────────────────

INVALID_EMAIL_STRATEGY = st.one_of(
    st.text(min_size=0, max_size=5),          # too short / no @
    st.just(""),                               # empty
    st.just(" "),                              # whitespace
    st.just("@"),                              # just @
    st.just("user@"),                          # no domain
    st.just("@domain.com"),                    # no local part
    st.from_regex(r"[^@]{1,20}@[^.]{1,10}"),  # missing TLD
)

@given(email=INVALID_EMAIL_STRATEGY)
@settings(max_examples=200)
def test_fuzz_invalid_emails_always_rejected(email):
    """Invalid email formats must always fail validation."""
    from app.core.validators import validate_email_format
    import re
    # RFC 5322 simplified pattern
    email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    result = validate_email_format(email)
    if not email_pattern.match(email):
        assert result is False, \
            f"Invalid email accepted: '{email}'"


# ─────────────────────────────────────────────────────────────────────────────
# FEEDBACK MESSAGE FUZZER
# OWASP: Validate data length, Validate all client provided data
# ─────────────────────────────────────────────────────────────────────────────

@given(message=st.text(min_size=0, max_size=200_000))
@settings(max_examples=300)
def test_fuzz_feedback_message_length(message):
    """Messages exceeding max length must be rejected; valid length accepted."""
    from app.core.validators import validate_feedback_message
    MAX_LENGTH = 5000  # your app's defined limit

    result = validate_feedback_message(message)
    if len(message) > MAX_LENGTH:
        assert result is False, \
            f"Oversized message ({len(message)} chars) accepted"
    elif len(message) == 0:
        assert result is False, \
            "Empty message accepted"


# ─────────────────────────────────────────────────────────────────────────────
# XSS PAYLOAD FUZZER
# OWASP: Contextually sanitize all output of un-trusted data
# ─────────────────────────────────────────────────────────────────────────────

XSS_PATTERNS = st.one_of(
    st.just("<script>alert(1)</script>"),
    st.just("<img src=x onerror=alert(1)>"),
    st.just("javascript:alert(1)"),
    st.just("<svg onload=alert(1)>"),
    st.just("';alert(1)//"),
    st.just("\"><script>alert(1)</script>"),
    st.just("<SCRIPT>alert(1)</SCRIPT>"),         # uppercase bypass
    st.just("<scr\x00ipt>alert(1)</scr\x00ipt>"),  # null byte bypass
    st.just("&#60;script&#62;alert(1)&#60;/script&#62;"),  # HTML entity
    st.text(
        alphabet=st.sampled_from("<>\"'&;/\\"),
        min_size=1,
        max_size=50
    ),
)

@given(payload=XSS_PATTERNS)
@settings(max_examples=200)
def test_fuzz_xss_payloads_sanitized(payload):
    """XSS-pattern inputs must be rejected or sanitized."""
    from app.core.validators import validate_feedback_message
    import re
    # Any input containing raw HTML tags or JS event handlers should fail
    dangerous = re.compile(r'<[a-z][\s\S]*?>|javascript:|on\w+\s*=', re.IGNORECASE)
    result = validate_feedback_message(payload)
    if dangerous.search(payload):
        assert result is False, \
            f"XSS payload passed validation: '{payload}'"


# ─────────────────────────────────────────────────────────────────────────────
# SQL INJECTION FUZZER
# OWASP: Contextually sanitize all output of un-trusted data to queries for SQL
# ─────────────────────────────────────────────────────────────────────────────

SQL_INJECTION_PATTERNS = st.one_of(
    st.just("' OR '1'='1"),
    st.just("'; DROP TABLE users;--"),
    st.just("1' UNION SELECT null, null--"),
    st.just("admin'--"),
    st.just("' OR 1=1--"),
    st.just("\" OR \"\"=\""),
    st.just("1; SELECT * FROM users"),
    # Generated variations
    st.from_regex(r"[a-z]{1,5}'[\s]*(OR|AND|UNION|SELECT|DROP|INSERT)[^;]{0,30}"),
)

@given(payload=SQL_INJECTION_PATTERNS)
@settings(max_examples=150)
def test_fuzz_sql_injection_payloads_rejected(payload):
    """SQL injection patterns must not pass input validation."""
    from app.core.validators import validate_email_format
    result = validate_email_format(payload)
    assert result is False, \
        f"SQL injection payload passed email validation: '{payload}'"


# ─────────────────────────────────────────────────────────────────────────────
# FILENAME FUZZER (for file upload)
# OWASP: File Management — path traversal, null bytes, special chars
# ─────────────────────────────────────────────────────────────────────────────

DANGEROUS_FILENAMES = st.one_of(
    st.just("../../../etc/passwd"),
    st.just("..\\..\\windows\\system32\\config"),
    st.just("\x00harmless.pdf"),
    st.just("file\nname.pdf"),
    st.just("file\rname.pdf"),
    st.just("CON"),                  # Windows reserved name
    st.just("NUL.pdf"),              # Windows reserved name
    st.just("a" * 300 + ".pdf"),     # Extremely long filename
    st.from_regex(r"\.\.[/\\]{1,5}[a-z]{1,10}"),
)

@given(filename=DANGEROUS_FILENAMES)
@settings(max_examples=100)
def test_fuzz_dangerous_filenames_rejected(filename):
    """Dangerous filenames must be rejected by the file upload validator."""
    from app.core.validators import validate_upload_filename
    result = validate_upload_filename(filename)
    assert result is False, \
        f"Dangerous filename passed validation: '{filename}'"
