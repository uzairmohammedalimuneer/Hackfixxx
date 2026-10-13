import pytest
from app.scanner.ssrf_validator import (
    validate_url_safety,
    redact_sensitive_data,
    redact_dict
)


def test_scheme_validation():
    # Only HTTP and HTTPS allowed
    is_safe, _, err = validate_url_safety("ftp://example.com/file")
    assert not is_safe
    assert "Only http:// and https://" in err

    is_safe, _, err = validate_url_safety("file:///etc/passwd")
    assert not is_safe
    assert "Only http:// and https://" in err

    is_safe, _, err = validate_url_safety("javascript:alert(1)")
    assert not is_safe


def test_embedded_credentials_blocked():
    is_safe, _, err = validate_url_safety("http://admin:secret@example.com")
    assert not is_safe
    assert "Embedded credentials" in err


def test_cloud_metadata_blocked():
    # AWS / GCP metadata
    is_safe, _, err = validate_url_safety("http://169.254.169.254/latest/meta-data/")
    assert not is_safe
    assert "metadata" in err.lower()

    is_safe, _, err = validate_url_safety("http://metadata.google.internal/computeMetadata/v1/")
    assert not is_safe
    assert "metadata" in err.lower()


def test_loopback_and_allowed_hosts():
    # Localhost should be allowed because it is in SCAN_ALLOWED_HOSTS for development
    is_safe, norm, err = validate_url_safety("http://localhost:8001/")
    assert is_safe
    assert "http://localhost:8001/" in norm

    is_safe, norm, err = validate_url_safety("http://127.0.0.1:8001/")
    assert is_safe
    assert "http://127.0.0.1:8001/" in norm


def test_redact_sensitive_tokens():
    text = "Authorization: Bearer my_super_secret_jwt_token_1234567890"
    redacted = redact_sensitive_data(text)
    assert "my_super_secret_jwt" not in redacted
    assert "REDACTED" in redacted

    api_text = "API_KEY=AIzaSyD-sample12345678901234567890123"
    assert "AIzaSyD" not in redact_sensitive_data(api_text)


def test_redact_dictionary():
    data = {
        "user": "alice",
        "api_key": "secret_abc123456",
        "nested": {
            "password": "my_password_xyz",
            "info": "public"
        }
    }
    redacted = redact_dict(data)
    assert redacted["api_key"] == "***REDACTED***"
    assert redacted["nested"]["password"] == "***REDACTED***"
    assert redacted["nested"]["info"] == "public"

