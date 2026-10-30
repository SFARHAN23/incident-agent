from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
import json, hashlib
from database import q

router = APIRouter()

def sha(s): return hashlib.sha256(s.encode()).hexdigest()

def diagnose_incident(data: dict):
    inc_id = data.get("incidentId") or data.get("incident_id") or data.get("id") or "inc-" + sha(str(data))[:12]
    state = data.get("state") or data.get("systemState") or data
    
    current_replicas = int(state.get("current_replicas") or state.get("replicas") or 1)
    max_replicas = int(state.get("max_replicas_permitted") or state.get("max_replicas") or 10)
    cpu = float(state.get("cpu_percent") or state.get("cpu") or 0.0)
    memory = float(state.get("memory_percent") or state.get("memory") or 0.0)
    err_rate = float(state.get("error_rate") or 0.0)

    diagnostics = ["check_metrics", "check_scaling_quota"]

    # RULE: When service is already at permitted scaling limit, page owner instead of scaling!
    if current_replicas >= max_replicas and (cpu > 80.0 or err_rate > 0.05):
        root_cause = f"High saturation (CPU {cpu}%) but service reached max limit ({current_replicas}/{max_replicas})."
        action = "PAGE_OWNER"
        paged = True
    elif cpu > 80.0 or err_rate > 0.05:
        root_cause = f"High compute load: CPU {cpu}%, Error rate {err_rate}%"
        action = "SCALE_UP"
        paged = False
    elif memory > 92.0:
        root_cause = f"Memory exhaustion detected ({memory}%)"
        action = "RESTART_PODS"
        paged = False
    else:
        root_cause = "Nominal operating thresholds"
        action = "NO_ACTION"
        paged = False

    telemetry = {
        "service": state.get("service_name", "web-service"),
        "replicas": current_replicas,
        "maxPermitted": max_replicas,
        "cpu": cpu,
        "action": action,
        "pagedOwner": paged
    }

    q("""INSERT OR REPLACE INTO incident_audit (incident_id, root_cause, action, paged_owner, diagnostics, telemetry)
         VALUES (?, ?, ?, ?, ?, ?)""",
      (inc_id, root_cause, action, 1 if paged else 0, json.dumps(diagnostics), json.dumps(telemetry)))

    return {
        "incidentId": inc_id,
        "rootCause": root_cause,
        "actionTaken": action,
        "pagedOwner": paged,
        "diagnosticsRun": diagnostics,
        "telemetry": telemetry
    }

@router.post("")
@router.post("/")
@router.post("/triage")
@router.post("/diagnose")
async def incident_route(request: Request):
    try: body = await request.json()
    except Exception: return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    res = diagnose_incident(body)
    return JSONResponse({"status": "SUCCESS", "result": res, **res})

@router.get("/telemetry/{incident_id}")
def get_telemetry(incident_id: str):
    rows = q("SELECT telemetry FROM incident_audit WHERE incident_id=?", (incident_id,))
    if not rows: return JSONResponse({"error": "Not found"}, status_code=404)
    return JSONResponse(json.loads(rows[0]["telemetry"]))
