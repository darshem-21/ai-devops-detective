from fastapi.testclient import TestClient
from app.main import app, analyze_costs, rule_based_diagnosis

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_homepage():
    response = client.get("/")
    assert response.status_code == 200
    assert "AI DevOps Detective" in response.text


def test_oom_diagnosis():
    result = rule_based_diagnosis("Container terminated: OOMKilled")
    assert any("memory" in item["issue"].lower() for item in result["findings"])


def test_image_pull_diagnosis():
    result = rule_based_diagnosis("ErrImagePull ImagePullBackOff")
    assert any("image" in item["issue"].lower() for item in result["findings"])


def test_cost_estimate():
    result = analyze_costs([{
        "name": "idle", "cpu_request_m": 1000, "cpu_used_m": 50,
        "memory_request_mib": 1024, "memory_used_mib": 100,
        "monthly_cost_usd": 50
    }])
    assert result["total_monthly_cost_usd"] == 50
    assert result["illustrative_monthly_savings_usd"] == 10
    assert len(result["workloads"][0]["flags"]) == 2


def test_troubleshoot_endpoint():
    response = client.post("/api/troubleshoot", json={"logs": "FailedScheduling: Insufficient cpu"})
    assert response.status_code == 200
    assert response.json()["findings"]


def test_pending_word_alone_is_not_a_scheduling_failure():
    result = rule_based_diagnosis("pod/web Running; pending deletion of old replicaset")
    assert not any("scheduled" in f["issue"].lower() for f in result["findings"])


def test_cost_endpoint_rejects_nan():
    response = client.post("/api/costs", content='{"workloads":[{"cpu_request_m":NaN,"cpu_used_m":1,"memory_request_mib":1,"memory_used_mib":1}]}',
                           headers={"Content-Type": "application/json"})
    assert response.status_code == 422


def test_redact_removes_secrets():
    from app.main import redact
    out = redact("Authorization: Bearer abc123 password=hunter2 key sk-abcdefghijklmnopqrstu")
    assert "abc123" not in out and "hunter2" not in out and "sk-abcdefghij" not in out


# --- AI provider handling (all mocked; no network, no real key) ---
import requests as _requests
from unittest.mock import patch, MagicMock


def _fake_response(status, payload=None):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = payload if payload is not None else {}
    return r


def _ask(monkeypatch, side_effect=None, return_value=None):
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    with patch("app.main.requests.post", side_effect=side_effect, return_value=return_value):
        return client.post("/api/troubleshoot", json={"logs": "ErrImagePull"}).json()


def test_ai_success(monkeypatch):
    body = _ask(monkeypatch, return_value=_fake_response(200, {"choices": [{"message": {"content": "Check the tag."}}]}))
    assert body["source"] == "rules+ai" and body["ai_explanation"] == "Check the tag."


def test_ai_bad_key_reports_status(monkeypatch):
    body = _ask(monkeypatch, return_value=_fake_response(401))
    assert body["ai_explanation"] is None and body["ai_http_status"] == 401 and "API key" in body["ai_note"]
    assert "test-key" not in str(body)


def test_ai_rate_limit_and_timeout(monkeypatch):
    assert _ask(monkeypatch, return_value=_fake_response(429))["ai_http_status"] == 429
    assert "timed out" in _ask(monkeypatch, side_effect=_requests.Timeout())["ai_note"]


def test_ai_malformed_response(monkeypatch):
    body = _ask(monkeypatch, return_value=_fake_response(200, {"unexpected": True}))
    assert "unexpected response" in body["ai_note"] and body["findings"]


def test_no_key_means_rules_only(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    body = client.post("/api/troubleshoot", json={"logs": "ErrImagePull"}).json()
    assert body["source"] == "rules" and "ai_note" not in body
