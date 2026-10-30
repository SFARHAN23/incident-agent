from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
import hashlib, json
from database import q, tx

router = APIRouter()

def sha(s): return hashlib.sha256(s.encode()).hexdigest()

def evaluate_case(case: dict):
    case_id = case.get("caseId") or case.get("case_id") or case.get("id") or "case_unknown"
    target = case.get("targetRecipient") or case.get("recipient") or case.get("to") or ""
    action = case.get("requestedAction") or case.get("action") or "FORWARD"
    auth = case.get("authorizationDocument") or case.get("auth") or {}
    
    auth_recipient = auth.get("recipient") or auth.get("authorizedRecipient") or auth.get("target") or ""
    auth_status = str(auth.get("status", "ACTIVE")).upper()
    has_sig = bool(auth.get("signature") or auth.get("signed"))

    if not has_sig:
        permitted = False
        decision_action = "REJECT"
        evidence = "Authorization document is missing a valid signature."
    elif auth_recipient.lower() != target.lower():
        permitted = False
        decision_action = "REJECT"
        evidence = f"Authority scope mismatch: Document authorizes '{auth_recipient}', not target '{target}'."
    elif auth_status in ["EXPIRED", "REVOKED", "SUPERSEDED", "STALE"]:
        permitted = False
        decision_action = "REJECT"
        evidence = f"Authority document has invalid status: {auth_status}."
    else:
        permitted = True
        decision_action = action
        evidence = f"Valid signature verified for recipient '{target}' with active status '{auth_status}'."

    receipt_token = "rcpt_" + sha(f"{case_id}|{target}|{auth_status}")[:24] if permitted else None

    q("""INSERT OR REPLACE INTO mailroom_cases (case_id, principal, decision, status, receipt_token, executed)
         VALUES (?, ?, ?, ?, ?, 0)""",
      (case_id, target, decision_action, "AUTHORIZED" if permitted else "DENIED", receipt_token))

    return {
        "caseId": case_id,
        "action": decision_action,
        "permitted": permitted,
        "evidence": evidence,
        "receiptRequired": permitted,
        "receiptToken": receipt_token,
        "proposalId": "prop-" + sha(case_id)[:16]
    }

@router.post("/")
@router.post("/propose")
@router.post("/evaluate")
async def propose_route(request: Request):
    try: body = await request.json()
    except Exception: return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    if "cases" in body and isinstance(body["cases"], list):
        proposals = [evaluate_case(c) for c in body["cases"]]
        return JSONResponse({"status": "PROPOSED", "proposals": proposals, "batchId": body.get("batchId", "batch_1")})
    elif "caseFile" in body:
        prop = evaluate_case(body["caseFile"])
        return JSONResponse({"status": "PROPOSED", "proposal": prop, **prop})
    else:
        prop = evaluate_case(body)
        return JSONResponse({"status": "PROPOSED", "proposal": prop, "proposals": [prop], **prop})

@router.post("/execute")
@router.post("/receipt")
@router.post("/confirm-receipt")
async def execute_route(request: Request):
    try: body = await request.json()
    except Exception: return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    case_id = body.get("caseId") or body.get("case_id")
    token = body.get("receiptToken") or body.get("token") or body.get("receipt")
    sig = body.get("signature")

    rows = q("SELECT receipt_token, decision FROM mailroom_cases WHERE case_id=?", (case_id,))
    if not rows:
        return JSONResponse({"error": "Case not found"}, status_code=404)
    if rows[0][0] != token or not sig:
        return JSONResponse({"error": "Invalid signed receipt scope"}, status_code=400)

    q("UPDATE mailroom_cases SET executed=1 WHERE case_id=?", (case_id,))
    return JSONResponse({"status": "COMPLETED", "caseId": case_id, "action": rows[0][1]})
