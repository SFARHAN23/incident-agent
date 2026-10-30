from fastapi import APIRouter, Request
from fastapi.responses import Response
import json, hashlib, uuid
from datetime import datetime, timezone
from database import q, tx
from invoice_logic import extract_package_decision

router = APIRouter()

MT = "application/a2a+json"
BATCH_MT = "application/vnd.ga5.invoice-claim-batch+json"
PROP_MT = "application/vnd.ga5.invoice-action-proposals+json"
RES_MT = "application/vnd.ga5.invoice-action-results+json"
REC_MT = "application/vnd.ga5.invoice-action-receipts+json"
IR, DONE, CANC = "TASK_STATE_INPUT_REQUIRED", "TASK_STATE_COMPLETED", "TASK_STATE_CANCELED"

def canon(x): return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
def sha(s): return hashlib.sha256(s.encode()).hexdigest()
def now(): return datetime.now(timezone.utc).isoformat()
def reply(obj, status=200): return Response(json.dumps(obj, ensure_ascii=False).encode(), status_code=status, media_type=MT)
def err(status, code): return reply({"error": {"code": code, "message": "Request could not be processed."}}, status)

def gate(request: Request, need_json=False):
    h = request.headers.get("authorization", "")
    tok = h[7:].strip() if h.startswith("Bearer ") else ""
    if not tok:
        return None, err(401, "UNAUTHENTICATED")
    if request.headers.get("a2a-version") != "1.0":
        return None, err(400, "VERSION_NOT_SUPPORTED")
    if need_json:
        ct = request.headers.get("content-type", "").lower()
        if not (ct.startswith(MT) or ct.startswith("application/json")):
            return None, err(415, "UNSUPPORTED_MEDIA_TYPE")
    return sha(tok)[:32], None

@router.get("/tasks")
def list_tasks(request: Request):
    p, bad = gate(request)
    if bad: return bad
    rows = q("SELECT body FROM tasks WHERE principal=? ORDER BY rowid", (p,))
    return reply({"tasks": [json.loads(r[0]) for r in rows]})

@router.get("/tasks/{tid}")
def get_task(tid: str, request: Request):
    p, bad = gate(request)
    if bad: return bad
    rows = q("SELECT body FROM tasks WHERE id=? AND principal=?", (tid, p))
    return reply(json.loads(rows[0][0])) if rows else err(404, "NOT_FOUND")

@router.post("/tasks/{tid}:cancel")
def cancel_task(tid: str, request: Request):
    p, bad = gate(request)
    if bad: return bad
    rows = q("SELECT body FROM tasks WHERE id=? AND principal=?", (tid, p))
    if not rows: return err(404, "NOT_FOUND")
    t = json.loads(rows[0][0])
    if t["status"]["state"] in (DONE, CANC): return err(409, "TASK_NOT_CANCELABLE")
    t["status"] = {"state": CANC, "timestamp": now()}
    q("UPDATE tasks SET body=? WHERE id=? AND principal=?", (json.dumps(t), tid, p))
    return reply(t)

@router.post("/message:send")
@router.post("/message%3Asend")
async def send_message(request: Request):
    p, bad = gate(request, need_json=True)
    if bad: return bad
    try: body = await request.json()
    except Exception: return err(400, "INVALID_REQUEST")
    msg = body.get("message")
    if not isinstance(msg, dict) or not msg.get("messageId") or msg.get("role") != "ROLE_USER":
        return err(400, "INVALID_REQUEST")

    mid = str(msg["messageId"])
    h = sha(canon(msg))

    rows = q("SELECT hash, task_id FROM msgs WHERE principal=? AND mid=?", (p, mid))
    if rows:
        if rows[0][0] != h: return err(409, "IDEMPOTENCY_CONFLICT")
        t_row = q("SELECT body FROM tasks WHERE id=? AND principal=?", (rows[0][1], p))
        return reply({"task": json.loads(t_row[0][0])}) if t_row else err(404, "NOT_FOUND")

    if msg.get("taskId"):
        return handle_continuation(p, msg, mid, h)
    return handle_initial(p, msg, mid, h)

def handle_initial(p, msg, mid, h):
    parts = msg.get("parts", [])
    if not parts or parts[0].get("mediaType") != BATCH_MT: return err(400, "INVALID_REQUEST")
    data = parts[0].get("data", {})
    pkgs = data.get("packages", [])
    batch_id = data.get("batchId", "batch_default")
    if not pkgs: return err(400, "INVALID_REQUEST")

    proposals = []
    for pkg in pkgs:
        pk_id = pkg.get("packageId") or pkg.get("id")
        dec = extract_package_decision(pkg)
        action_id = "act-" + sha(f"{batch_id}|{pk_id}")[:24]
        proposals.append({
            "packageId": pk_id,
            "actionId": action_id,
            "action": dec["action"],
            "facts": dec["facts"],
            "evidenceRefs": dec["evidenceRefs"],
            "rationale": dec["rationale"]
        })

    tid, cid = "task-" + uuid.uuid4().hex, "ctx-" + uuid.uuid4().hex
    task = {
        "id": tid, "contextId": cid,
        "status": {"state": IR, "timestamp": now()},
        "artifacts": [{
            "artifactId": "art-" + uuid.uuid4().hex,
            "name": "invoice-action-proposals",
            "parts": [{"mediaType": PROP_MT, "data": {"batchId": batch_id, "proposals": proposals}}]
        }],
        "history": [{**msg, "taskId": tid, "contextId": cid}]
    }
    tx([("INSERT INTO tasks VALUES (?,?,?)", (tid, p, json.dumps(task))),
        ("INSERT INTO msgs VALUES (?,?,?,?)", (p, mid, h, tid))])
    return reply({"task": task})

def handle_continuation(p, msg, mid, h):
    tid = msg["taskId"]
    rows = q("SELECT body FROM tasks WHERE id=? AND principal=?", (tid, p))
    if not rows: return err(404, "NOT_FOUND")
    t = json.loads(rows[0][0])
    if t["status"]["state"] != IR: return err(409, "TASK_NOT_ACTIVE")

    parts = msg.get("parts", [])
    if not parts or parts[0].get("mediaType") != RES_MT: return err(400, "INVALID_REQUEST")
    res_data = parts[0].get("data", {})
    prop_data = t["artifacts"][0]["parts"][0]["data"]

    stored_props = {p["packageId"]: p for p in prop_data["proposals"]}
    executions = []
    for r in res_data.get("results", []):
        pkg_id = r.get("packageId")
        if pkg_id in stored_props and r.get("outcome") == "ACCEPTED":
            s = stored_props[pkg_id]
            executions.append({
                "packageId": pkg_id,
                "actionId": s["actionId"],
                "action": s["action"],
                "receiptNonce": r.get("receiptNonce", "nonce_default"),
                "facts": s["facts"],
                "evidenceRefs": s["evidenceRefs"]
            })

    t["artifacts"][0]["parts"].append({
        "mediaType": REC_MT,
        "data": {"batchId": prop_data["batchId"], "executions": executions}
    })
    t["history"].append(msg)
    t["status"] = {"state": DONE, "timestamp": now()}
    tx([("UPDATE tasks SET body=? WHERE id=? AND principal=?", (json.dumps(t), tid, p)),
        ("INSERT INTO msgs VALUES (?,?,?,?)", (p, mid, h, tid))])
    return reply({"task": t})
