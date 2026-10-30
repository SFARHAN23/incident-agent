import os
os.environ["DB_PATH"] = ":memory:"
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def run_tests():
    print("Testing Endpoints Locally...")

    # 1. Health check
    r = client.get("/")
    assert r.status_code == 200, f"Root health check failed: {r.status_code}"
    print("✓ Healthcheck OK")

    # 2. A2A Card
    r = client.get("/.well-known/agent-card.json")
    assert r.status_code == 200 and "supportedInterfaces" in r.json()
    print("✓ A2A Agent Card OK")

    # 3. Mailroom Propose
    case_payload = {
        "caseId": "case_101",
        "targetRecipient": "billing-dept",
        "requestedAction": "FORWARD",
        "authorizationDocument": {
            "recipient": "billing-dept",
            "status": "ACTIVE",
            "signature": "sig_valid_123"
        }
    }
    r = client.post("/mailroom/propose", json=case_payload)
    assert r.status_code == 200 and r.json().get("permitted") is True, f"Mailroom proposal failed: {r.text}"
    print("✓ Safe AI Mailroom Propose OK")

    # 4. Incident Triage (Scaling limit guard)
    inc_payload = {
        "incidentId": "inc_901",
        "state": {
            "service_name": "checkout",
            "current_replicas": 10,
            "max_replicas_permitted": 10,
            "cpu_percent": 95.0
        }
    }
    r = client.post("/incident/triage", json=inc_payload)
    assert r.status_code == 200 and r.json().get("actionTaken") == "PAGE_OWNER", f"Incident limit check failed: {r.text}"
    print("✓ Incident Triage Scaling Guard OK")

    print("\nALL LOCAL TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    run_tests()
