from fastapi.testclient import TestClient

from triage.api import create_app
from triage.llm import MockTriager
from triage.notify import Notifier
from triage.pipeline import Pipeline
from triage.store import ReportStore


def client(tmp_path, secret=None):
    p = Pipeline(ReportStore(str(tmp_path / "api.db")), MockTriager(), Notifier(None))
    return TestClient(create_app(pipeline=p, webhook_secret=secret or ""))


RCE = {"title": "Remote code execution in upload", "body": "Filename goes into a shell command on /api/upload"}


def test_submit_list_approve(tmp_path):
    c = client(tmp_path)
    r = c.post("/reports", json=RCE)
    assert r.status_code == 201
    body = r.json()
    assert body["triage"]["severity"] == "critical"
    assert body["status"] == "pending_approval"

    assert len(c.get("/reports", params={"status": "pending_approval"}).json()) == 1
    assert c.post(f"/reports/{body['id']}/approve").json()["status"] == "escalated"
    assert c.post(f"/reports/{body['id']}/approve").status_code == 409


def test_webhook_secret_required(tmp_path):
    c = client(tmp_path, secret="s3cret")
    assert c.post("/reports", json=RCE).status_code == 401
    assert c.post("/reports", json=RCE, headers={"X-Webhook-Secret": "wrong"}).status_code == 401
    assert c.post("/reports", json=RCE, headers={"X-Webhook-Secret": "s3cret"}).status_code == 201


def test_input_validation(tmp_path):
    c = client(tmp_path)
    assert c.post("/reports", json={"title": "", "body": "x"}).status_code == 422
    assert c.post("/reports", json={"title": "x", "body": "y" * 20_001}).status_code == 422
    assert c.get("/reports/12345").status_code == 404
