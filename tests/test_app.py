"""
Tests unitaires - Application DevSecOps FastAPI
"""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.app import app
from src.utils import sanitize_input, get_app_version, hash_sensitive_data

client = TestClient(app)


# ─────────────────────────────────────────────
# Tests des endpoints
# ─────────────────────────────────────────────

class TestHealthEndpoint:
    def test_health_returns_200(self):
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_contains_status(self):
        response = client.get("/health")
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data

    def test_root_returns_200(self):
        response = client.get("/")
        assert response.status_code == 200


class TestSecureEndpoint:
    def test_secure_without_token_returns_403(self):
        response = client.get("/secure/data")
        assert response.status_code == 403

    def test_secure_with_invalid_token_returns_401(self):
        response = client.get(
            "/secure/data",
            headers={"Authorization": "Bearer invalid-token-xyz"}
        )
        assert response.status_code == 401

    def test_secure_error_doesnt_leak_details(self):
        response = client.get(
            "/secure/data",
            headers={"Authorization": "Bearer bad"}
        )
        body = response.json()
        # Ne doit pas exposer de stack trace ou détails internes
        assert "traceback" not in str(body).lower()
        assert "secret" not in str(body).lower()


class TestEchoEndpoint:
    def test_echo_returns_sanitized_input(self):
        response = client.post("/echo", json={"key": "hello world"})
        assert response.status_code == 200
        assert response.json()["echo"]["key"] == "hello world"

    def test_echo_strips_xss(self):
        response = client.post("/echo", json={"key": "<script>alert(1)</script>"})
        data = response.json()["echo"]["key"]
        assert "<script>" not in data
        assert "alert" not in data

    def test_echo_strips_sql_injection(self):
        response = client.post("/echo", json={"key": "' OR 1=1 --"})
        data = response.json()["echo"]["key"]
        assert "--" not in data
        assert "'" not in data


# ─────────────────────────────────────────────
# Tests des utilitaires
# ─────────────────────────────────────────────

class TestSanitizeInput:
    def test_normal_string_unchanged(self):
        result = sanitize_input("Hello World 123")
        assert result == "Hello World 123"

    def test_max_length_enforced(self):
        long_input = "A" * 2000
        result = sanitize_input(long_input, max_length=100)
        assert len(result) <= 100

    def test_html_tags_removed(self):
        result = sanitize_input("<b>bold</b>")
        assert "<" not in result
        assert ">" not in result

    def test_javascript_removed(self):
        result = sanitize_input("javascript:alert(1)")
        assert "javascript:" not in result

    def test_non_string_raises_error(self):
        with pytest.raises(ValueError):
            sanitize_input(12345)


class TestHashSensitiveData:
    def test_returns_string(self):
        result = hash_sensitive_data("secret")
        assert isinstance(result, str)

    def test_ends_with_ellipsis(self):
        result = hash_sensitive_data("secret")
        assert result.endswith("...")

    def test_different_inputs_different_hashes(self):
        h1 = hash_sensitive_data("secret1")
        h2 = hash_sensitive_data("secret2")
        assert h1 != h2


class TestGetAppVersion:
    def test_returns_string(self):
        version = get_app_version()
        assert isinstance(version, str)

    def test_default_version(self):
        with patch.dict(os.environ, {}, clear=True):
            # Quand APP_VERSION n'est pas set
            version = get_app_version()
            assert version == "1.0.0"
