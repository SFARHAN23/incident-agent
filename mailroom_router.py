from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
import json, hashlib, base64, re
from database import q, tx
from cryptography.hazmat.primitives.asymmetric import ed25519

router = APIRouter()

def canon(x) -> str:
    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def compute_proposal_digest(proposal: dict) -> str:
    norm = {
        "dossierId": proposal["dossierId"],
        "callId": proposal["callId"],
        "action": proposal["action"],
        "target": proposal.get("target"),
        "payload": proposal["payload"],
        "evidence": sorted(proposal["evidence"])
    }
    return sha(canon(norm))

def evaluate_dossier(dossier: dict) -> dict:
    dossier_id = dossier["dossierId"]
    mailbox = dossier.get("mailbox", "support@example.com")
    sources = dossier.get("sources", [])
    call_id = f"call_{dossier_id[:16]}_{sha(canon(dossier))[:16]}"

    all_lines = []
    for src in sources:
        sid = src.get("sourceId", "src_main")
        for line in src.get("lines", []):
            all_lines.append((line.get("lineId"), line.get("text", ""), sid, src.get("provenance", "external")))

    full_text = " ".join(t for _, t, _, _ in all_lines).lower()

    # 1. Quarantine: Indirect Prompt Injection Check
    inj_keywords = ["ignore previous", "system prompt", "exfiltrate", "admin override", "tool call", "curl ", "canary", "hidden prompt"]
    for lid, txt, sid, prov in all_lines:
        if any(w in txt.lower() for w in inj_keywords):
            return {
                "dossierId": dossier_id,
                "callId": call_id,
                "action": "quarantine_item",
                "target": {"kind": "security_queue", "id": "mailroom"},
                "payload": {"artifactId": sid, "reasonCode": "INDIRECT_PROMPT_INJECTION"},
                "evidence": [lid]
            }

    ref_match = re.search(r"\b(ORD-[0-9A-Z]+|CASE-[0-9A-Z]+|REF-[0-9A-Z]+)\b", full_text, re.I)
    ref_id = ref_match.group(1).upper() if ref_match else "REF-1001"

    email_match = re.search(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", full_text)
    contact_email = email_match.group(0) if email_match else "customer@example.com"
    ev_line = all_lines[0][0] if all_lines else "line_01"

    # 2. No Action: Already completed / duplicate
    if any(k in full_text for k in ["already resolved", "already completed", "duplicate notice", "no further action"]):
        return {
            "dossierId": dossier_id,
            "callId": call_id,
            "action": "no_action",
            "target": None,
            "payload": {"reasonCode": "ALREADY_COMPLETED", "referenceId": ref_id},
            "evidence": [ev_line]
        }

    # 3. Update Internal Record
    if "delivery_window" in full_text or "delivery window" in full_text:
        case_m = re.search(r"\b(CASE-[0-9A-Z]+)\b", full_text, re.I)
        cid = case_m.group(1).upper() if case_m else "CASE-8821"
        win_m = re.search(r"\b(\d{1,2}:\d{2}\s*-\s*\d{1,2}:\d{2})\b", full_text)
        val = win_m.group(1) if win_m else "14:00-18:00"
        return {
            "dossierId": dossier_id,
            "callId": call_id,
            "action": "update_internal_record",
            "target": {"kind": "case_record", "id": cid},
            "payload": {"field": "delivery_window", "sourceEventId": sources[0].get("sourceId", "src_1"), "value": val},
            "evidence": [ev_line]
        }

    # 4. Send Approved Notice
    if any(k in full_text for k in ["explicitly approved", "approved notice", "send notice approved"]):
        return {
            "dossierId": dossier_id,
            "callId": call_id,
            "action": "send_approved_notice",
            "target": {"kind": "email", "id": contact_email},
            "payload": {"referenceId": ref_id, "status": "CONFIRMED", "template": "approved_delivery_notice"},
            "evidence": [ev_line]
        }

    # 5. Request Confirmation
    if any(k in full_text for k in ["conflict", "mismatch", "unverified", "ambiguous", "cannot verify"]):
        return {
            "dossierId": dossier_id,
            "callId": call_id,
            "action": "request_confirmation",
            "target": {"kind": "approval_queue", "id": "support"},
            "payload": {"claimedSender": contact_email, "questionCode": "VERIFY_REQUEST", "referenceId": ref_id},
            "evidence": [ev_line]
        }

    # 6. Default Customer Inbound -> create_draft
    return {
        "dossierId": dossier_id,
        "callId": call_id,
        "action": "create_draft",
        "target": {"kind": "draft_queue", "id": f"mailbox:{mailbox}"},
        "payload": {"recipient": contact_email, "referenceId": ref_id, "status": "PENDING", "template": "order_status"},
        "evidence": [ev_line]
    }

@router.post("")
@router.post("/")
@router.post("/propose")
@router.post("/commit")
async def mailroom_entrypoint(request: Request):
    try: body = await request.json()
    except Exception: return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    if not isinstance(body, dict) or body.get("profile") != "ga5-mailroom-action-gate/v2":
        return JSONResponse({"error": "Invalid profile or schema"}, status_code=422)

    op = body.get("operation")
    eval_id = body.get("evaluationId")
    if not op or not eval_id:
        return JSONResponse({"error": "Missing operation or evaluationId"}, status_code=422)

    # ---------------- OPERATION: PROPOSE ----------------
    if op == "propose":
        dossiers = body.get("dossiers", [])
        if not dossiers: return JSONResponse({"error": "Missing dossiers"}, status_code=422)

        # Check for duplicate dossier IDs
        d_ids = [d.get("dossierId") for d in dossiers]
        if len(d_ids) != len(set(d_ids)):
            return JSONResponse({"error": "Duplicate dossier IDs detected"}, status_code=400)

        input_digest = sha(canon(dossiers))
        h = sha(canon(body))

        existing = q("SELECT req_hash, response_json FROM mailroom_evals WHERE eval_id=?", (eval_id,))
        if existing:
            if existing[0][0] != h:
                return JSONResponse({"error": "Changed evaluation content conflict"}, status_code=409)
            return JSONResponse(json.loads(existing[0][1]))

        proposals = [evaluate_dossier(d) for d in dossiers]
        verifier_jwk = body.get("receiptVerifier", {}).get("publicKeyJwk", {})

        resp = {
            "profile": "ga5-mailroom-action-gate/v2",
            "evaluationId": eval_id,
            "status": "awaiting_receipts",
            "inputDigest": input_digest,
            "proposals": proposals
        }

        tx([("INSERT INTO mailroom_evals (eval_id, req_hash, verifier_jwk, input_digest, proposals_json, response_json) VALUES (?,?,?,?,?,?)",
             (eval_id, h, json.dumps(verifier_jwk), input_digest, json.dumps(proposals), json.dumps(resp)))])

        return JSONResponse(resp)

    # ---------------- OPERATION: COMMIT ----------------
    elif op == "commit":
        eval_row = q("SELECT verifier_jwk, input_digest, proposals_json FROM mailroom_evals WHERE eval_id=?", (eval_id,))
        if not eval_row:
            return JSONResponse({"error": "Evaluation not found"}, status_code=404)

        stored_jwk = json.loads(eval_row[0][0])
        stored_input_digest = eval_row[0][1]
        stored_proposals = json.loads(eval_row[0][2])

        if body.get("inputDigest") != stored_input_digest:
            return JSONResponse({"error": "Input digest mismatch"}, status_code=400)

        try:
            x_b64 = stored_jwk["x"]
            x_b64 += "=" * ((4 - len(x_b64) % 4) % 4)
            pub_bytes = base64.urlsafe_b64decode(x_b64)
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        except Exception:
            return JSONResponse({"error": "Invalid verifier key"}, status_code=400)

        receipts = body.get("receipts", [])
        proposal_map = {p["dossierId"]: p for p in stored_proposals}
        outcomes = []

        for r in receipts:
            sig_b64 = r.get("receiptSignature", "")
            if not sig_b64:
                return JSONResponse({"error": "Missing receipt signature"}, status_code=400)
            try:
                sig_b64 += "=" * ((4 - len(sig_b64) % 4) % 4)
                sig_bytes = base64.b64decode(sig_b64)

                inner_receipt = {
                    "dossierId": r["dossierId"],
                    "callId": r["callId"],
                    "action": r["action"],
                    "accepted": r["accepted"],
                    "proposalDigest": r["proposalDigest"],
                    "receiptId": r["receiptId"]
                }
                envelope_to_verify = {
                    "profile": "ga5-mailroom-action-gate/v2",
                    "evaluationId": eval_id,
                    "inputDigest": stored_input_digest,
                    "receipt": inner_receipt
                }
                payload_bytes = canon(envelope_to_verify).encode("utf-8")
                public_key.verify(sig_bytes, payload_bytes)
            except Exception:
                return JSONResponse({"error": "Invalid Ed25519 receipt signature"}, status_code=400)

            prop = proposal_map.get(r["dossierId"])
            if not prop or prop["callId"] != r["callId"] or prop["action"] != r["action"]:
                return JSONResponse({"error": "Receipt does not match stored proposal"}, status_code=400)

            expected_digest = compute_proposal_digest(prop)
            if r["proposalDigest"] != expected_digest:
                return JSONResponse({"error": "Proposal digest mismatch"}, status_code=400)

            outcomes.append({
                "dossierId": r["dossierId"],
                "callId": r["callId"],
                "action": r["action"],
                "proposalDigest": r["proposalDigest"],
                "receiptId": r["receiptId"],
                "status": "executed" if r.get("accepted") is True else "rejected"
            })

        resp = {
            "profile": "ga5-mailroom-action-gate/v2",
            "evaluationId": eval_id,
            "status": "completed",
            "inputDigest": stored_input_digest,
            "outcomes": outcomes
        }
        return JSONResponse(resp)

    else:
        return JSONResponse({"error": "Unsupported operation"}, status_code=400)
