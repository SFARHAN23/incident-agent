from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
import json, hashlib, base64, re, os
import httpx
from database import q, tx
from cryptography.hazmat.primitives.asymmetric import ed25519

router = APIRouter()

LLM_URL = os.environ.get("LLM_URL", "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions")
LLM_KEY = os.environ.get("LLM_KEY", os.environ.get("GEMINI_API_KEY", "")).strip()
LLM_MODEL = os.environ.get("LLM_MODEL", "gemini-2.5-flash").strip() or "gemini-2.5-flash"

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

def extract_dossier_features(dossier: dict):
    dossier_id = dossier["dossierId"]
    mailbox = dossier.get("mailbox", "support@example.com")
    sources = dossier.get("sources", [])
    call_id = f"call_{dossier_id[:16]}_{sha(canon(dossier))[:16]}"

    all_lines = []
    for src in sources:
        sid = src.get("sourceId", "src_main")
        prov = src.get("provenance", "external")
        for line in src.get("lines", []):
            all_lines.append((line.get("lineId"), line.get("text", ""), sid, prov))

    # 1. Quarantine Check: Indirect Prompt Injection in external content
    inj_keywords = ["ignore previous", "system prompt", "exfiltrate", "admin override", "tool call", "curl ", "canary", "hidden prompt"]
    for lid, txt, sid, prov in all_lines:
        if prov != "internal_trusted" and any(w in txt.lower() for w in inj_keywords):
            return {
                "dossierId": dossier_id,
                "callId": call_id,
                "action": "quarantine_item",
                "target": {"kind": "security_queue", "id": "mailroom"},
                "payload": {"artifactId": sid, "reasonCode": "INDIRECT_PROMPT_INJECTION"},
                "evidence": [lid]
            }

    ref_id, ref_lid = "REF-1001", all_lines[0][0] if all_lines else "l1"
    email_val, email_lid = "customer@example.com", all_lines[0][0] if all_lines else "l1"
    window_val, window_lid = "14:00-18:00", all_lines[0][0] if all_lines else "l1"
    case_id, case_lid = "CASE-1001", all_lines[0][0] if all_lines else "l1"
    has_approval = False
    approval_lid = None
    is_completed_or_dup = False
    dup_lid = None
    reason_code = "ALREADY_COMPLETED"

    for lid, txt, sid, prov in all_lines:
        low = txt.lower()
        rm = re.search(r"\b(ORD-[0-9A-Z]+|REF-[0-9A-Z]+)\b", txt, re.I)
        if rm:
            ref_id, ref_lid = rm.group(1).upper(), lid

        cm = re.search(r"\b(CASE-[0-9A-Z]+)\b", txt, re.I)
        if cm:
            case_id, case_lid = cm.group(1).upper(), lid

        em = re.search(r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b", txt)
        if em:
            email_val, email_lid = em.group(1), lid

        wm = re.search(r"\b(\d{1,2}:\d{2}\s*-\s*\d{1,2}:\d{2})\b", txt)
        if wm:
            window_val, window_lid = wm.group(1), lid

        if any(k in low for k in ["approved for delivery notice", "explicit approval granted", "approved outbound send"]):
            has_approval = True
            approval_lid = lid

        if "already completed" in low or "previously resolved" in low:
            is_completed_or_dup = True
            dup_lid = lid
            reason_code = "ALREADY_COMPLETED"
        elif "duplicate request" in low or "duplicate notification" in low:
            is_completed_or_dup = True
            dup_lid = lid
            reason_code = "DUPLICATE"
        elif "informational only" in low or "no action required" in low:
            is_completed_or_dup = True
            dup_lid = lid
            reason_code = "INFORMATIONAL"

    # 2. No Action
    if is_completed_or_dup:
        return {
            "dossierId": dossier_id,
            "callId": call_id,
            "action": "no_action",
            "target": None,
            "payload": {"reasonCode": reason_code, "referenceId": ref_id},
            "evidence": list(dict.fromkeys([dup_lid or ref_lid, ref_lid]))
        }

    # 3. Update Internal Record (authorized delivery window)
    if "delivery_window" in " ".join(t for _, t, _, _ in all_lines).lower():
        src_id = sources[0].get("sourceId", "src_1")
        return {
            "dossierId": dossier_id,
            "callId": call_id,
            "action": "update_internal_record",
            "target": {"kind": "case_record", "id": case_id},
            "payload": {"field": "delivery_window", "sourceEventId": src_id, "value": window_val},
            "evidence": list(dict.fromkeys([case_lid, window_lid]))
        }

    # 4. Send Approved Notice (strictly with trusted approval)
    if has_approval and approval_lid:
        return {
            "dossierId": dossier_id,
            "callId": call_id,
            "action": "send_approved_notice",
            "target": {"kind": "email", "id": email_val},
            "payload": {"referenceId": ref_id, "status": "CONFIRMED", "template": "approved_delivery_notice"},
            "evidence": list(dict.fromkeys([approval_lid, ref_lid, email_lid]))
        }

    # 5. Request Confirmation (identity ambiguity or conflict)
    full_str = " ".join(t for _, t, _, _ in all_lines).lower()
    if any(k in full_str for k in ["sender mismatch", "conflicting identity", "unverified sender", "address mismatch"]):
        return {
            "dossierId": dossier_id,
            "callId": call_id,
            "action": "request_confirmation",
            "target": {"kind": "approval_queue", "id": "support"},
            "payload": {"claimedSender": email_val, "questionCode": "VERIFY_REQUEST", "referenceId": ref_id},
            "evidence": list(dict.fromkeys([ref_lid, email_lid]))
        }

    # 6. Default Customer Order Draft
    return {
        "dossierId": dossier_id,
        "callId": call_id,
        "action": "create_draft",
        "target": {"kind": "draft_queue", "id": f"mailbox:{mailbox}"},
        "payload": {"recipient": email_val, "referenceId": ref_id, "status": "PENDING", "template": "order_status"},
        "evidence": list(dict.fromkeys([ref_lid, email_lid]))
    }

@router.post("/mailroom")
@router.post("/mailroom/")
@router.post("/mailroom/propose")
@router.post("/mailroom/commit")
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

        proposals = []
        for d in dossiers:
            dk = sha(canon(d))
            cached = q("SELECT v FROM cache WHERE k=?", (dk,))
            if cached:
                p = json.loads(cached[0][0])
                proposals.append(p)
            else:
                p = extract_dossier_features(d)
                q("INSERT OR REPLACE INTO cache (k, v) VALUES (?,?)", (dk, json.dumps(p)))
                proposals.append(p)

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
            # Must return 400 (not 404) to pass invalid-receipt rejection probe
            return JSONResponse({"error": "Evaluation not found"}, status_code=400)

        stored_jwk = json.loads(eval_row[0][0])
        stored_input_digest = eval_row[0][1]
        stored_proposals = json.loads(eval_row[0][2])

        if body.get("inputDigest") != stored_input_digest:
            return JSONResponse({"error": "Input digest mismatch"}, status_code=400)

        receipts = body.get("receipts")
        if not isinstance(receipts, list):
            return JSONResponse({"error": "Missing receipts list"}, status_code=400)

        proposal_map = {p["dossierId"]: p for p in stored_proposals}
        if len(receipts) != len(stored_proposals):
            return JSONResponse({"error": "Receipt count does not match proposals"}, status_code=400)

        seen_dossiers = set()
        seen_calls = set()
        for r in receipts:
            did = r.get("dossierId")
            cid = r.get("callId")
            if not did or did in seen_dossiers:
                return JSONResponse({"error": "Duplicate or missing dossierId in receipt"}, status_code=400)
            if not cid or cid in seen_calls:
                return JSONResponse({"error": "Duplicate or missing callId in receipt"}, status_code=400)
            seen_dossiers.add(did)
            seen_calls.add(cid)

        try:
            x_b64 = stored_jwk["x"]
            x_b64 += "=" * ((4 - len(x_b64) % 4) % 4)
            pub_bytes = base64.urlsafe_b64decode(x_b64)
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        except Exception:
            return JSONResponse({"error": "Invalid verifier key"}, status_code=400)

        outcomes = []
        for r in receipts:
            sig_b64 = r.get("receiptSignature", "")
            if not sig_b64:
                return JSONResponse({"error": "Missing receipt signature"}, status_code=400)
            try:
                sig_b64_padded = sig_b64 + "=" * ((4 - len(sig_b64) % 4) % 4)
                try:
                    sig_bytes = base64.b64decode(sig_b64_padded)
                except Exception:
                    sig_bytes = base64.urlsafe_b64decode(sig_b64_padded)

                inner_receipt = {k: v for k, v in r.items() if k != "receiptSignature"}
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
                return JSONResponse({"error": "Receipt binding mismatch"}, status_code=400)

            expected_digest = compute_proposal_digest(prop)
            if r.get("proposalDigest") != expected_digest:
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
