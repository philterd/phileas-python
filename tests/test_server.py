"""Tests for the Flask REST server."""

import json
import pytest

from phileas.server import app


@pytest.fixture()
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


class TestFilterEndpointBasic:
    def test_email_redacted(self, client):
        payload = {
            "policy": {
                "name": "test",
                "identifiers": {
                    "emailAddress": {}
                },
            },
            "text": "Contact john@example.com for details.",
            "context": "ctx",
        }
        response = client.post("/api/filter", json=payload)
        assert response.status_code == 200
        data = response.get_json()
        assert "john@example.com" not in data["filteredText"]
        assert data["context"] == "ctx"
        assert len(data["spans"]) >= 1

    def test_no_pii_unchanged(self, client):
        payload = {
            "policy": {"name": "empty"},
            "text": "Nothing sensitive here.",
            "context": "ctx",
        }
        response = client.post("/api/filter", json=payload)
        assert response.status_code == 200
        data = response.get_json()
        assert data["filteredText"] == "Nothing sensitive here."
        assert data["spans"] == []

    def test_optional_document_id(self, client):
        payload = {
            "policy": {"name": "test"},
            "text": "Hello world.",
            "context": "ctx",
            "documentId": "my-doc-123",
        }
        response = client.post("/api/filter", json=payload)
        assert response.status_code == 200
        data = response.get_json()
        assert data["documentId"] == "my-doc-123"

    def test_auto_generated_document_id(self, client):
        payload = {
            "policy": {"name": "test"},
            "text": "Hello world.",
            "context": "ctx",
        }
        response = client.post("/api/filter", json=payload)
        assert response.status_code == 200
        data = response.get_json()
        assert data["documentId"]  # non-empty auto-generated UUID


class TestFilterEndpointErrors:
    def test_missing_body_returns_400(self, client):
        response = client.post("/api/filter", data="not json", content_type="text/plain")
        assert response.status_code == 400

    def test_missing_policy_field_returns_400(self, client):
        payload = {"text": "some text", "context": "ctx"}
        response = client.post("/api/filter", json=payload)
        assert response.status_code == 400
        data = response.get_json()
        assert "policy" in data["error"]

    def test_missing_text_field_returns_400(self, client):
        payload = {"policy": {"name": "test"}, "context": "ctx"}
        response = client.post("/api/filter", json=payload)
        assert response.status_code == 400
        data = response.get_json()
        assert "text" in data["error"]

    def test_missing_context_field_returns_400(self, client):
        payload = {"policy": {"name": "test"}, "text": "hello"}
        response = client.post("/api/filter", json=payload)
        assert response.status_code == 400
        data = response.get_json()
        assert "context" in data["error"]

    def test_get_method_not_allowed(self, client):
        response = client.get("/api/filter")
        assert response.status_code == 405


class TestFilterEndpointSpans:
    def test_span_fields_present(self, client):
        payload = {
            "policy": {
                "name": "test",
                "identifiers": {"emailAddress": {}},
            },
            "text": "Send to user@example.com please.",
            "context": "myctx",
        }
        response = client.post("/api/filter", json=payload)
        assert response.status_code == 200
        data = response.get_json()
        assert len(data["spans"]) == 1
        span = data["spans"][0]
        assert "characterStart" in span
        assert "characterEnd" in span
        assert "filterType" in span
        assert "replacement" in span
        assert "ignored" in span
