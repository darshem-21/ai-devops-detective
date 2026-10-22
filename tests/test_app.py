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
