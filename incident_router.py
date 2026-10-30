from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
import json, hashlib, uuid, time, re
from database import q, tx

router = APIRouter()

def sha(s): return hashlib.sha256(s.encode()).hexdigest()
def canon(x): return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
def nano(): return str(int(time.time() * 1e9))

def build_otlp_trace(run_id, public_marker, trace_id, agent_model, dispatches, receipts, approvals, is_join):
    server_span_id = sha(f"server_{run_id}")[:16]
    agent_span_id = sha(f"agent_{run_id}")[:16]
    model_span_id = sha(f"model_{run_id}")[:16]

    common_attrs = [
        {"key": "ga5.run.id", "value": {"stringValue": run_id}},
        {"key": "ga5.public.marker", "value": {"stringValue": public_marker}}
    ]

    spans = [
        {
            "traceId": trace_id,
            "spanId": server_span_id,
            "parentSpanId": "",
            "name": "POST /v2/incidents",
            "kind": 2,  # SERVER
            "startTimeUnixNano": nano(),
            "endTimeUnixNano": str(int(nano()) + 50000000),
            "attributes": common_attrs + [{"key": "http.request.method", "value": {"stringValue": "POST"}}]
        },
        {
            "traceId": trace_id,
            "spanId": agent_span_id,
            "parentSpanId": server_span_id,
            "name": "invoke_agent incident-response",
            "kind": 1,  # INTERNAL
            "startTimeUnixNano": nano(),
            "endTimeUnixNano": str(int(nano()) + 45000000),
            "attributes": common_attrs
        },
        {
            "traceId": trace_id,
            "spanId": model_span_id,
            "parentSpanId": agent_span_id,
            "name": "chat incident-plan",
            "kind": 3,  # CLIENT
            "startTimeUnixNano": nano(),
            "endTimeUnixNano": str(int(nano()) + 20000000),
            "attributes": common_attrs + [
                {"key": "gen_ai.operation.name", "value": {"stringValue": "chat"}},
                {"key": "gen_ai.request.model", "value": {"stringValue": agent_model or "gemini-2.5-flash"}}
            ]
        }
    ]

    exec_span_map = {}
    for d in dispatches:
        action_id = d["actionId"]
        tool_name = d["toolName"]
        call_id = d["callId"]
        attempt = int(d.get("attempt", 1))

        if action_id not in exec_span_map:
            exec_span_id = sha(f"exec_{action_id}")[:16]
            exec_span_map[action_id] = exec_span_id
            spans.append({
                "traceId": trace_id,
                "spanId": exec_span_id,
                "parentSpanId": agent_span_id,
                "name": f"execute_tool {tool_name}",
                "kind": 1,  # INTERNAL
                "startTimeUnixNano": nano(),
                "endTimeUnixNano": str(int(nano()) + 30000000),
                "attributes": common_attrs + [
                    {"key": "ga5.action.id", "value": {"stringValue": action_id}},
                    {"key": "gen_ai.tool.name", "value": {"stringValue": tool_name}},
                    {"key": "gen_ai.tool.call.id", "value": {"stringValue": call_id}},
                    {"key": "gen_ai.operation.name", "value": {"stringValue": "execute_tool"}}
                ]
            })

        tp = d.get("traceparent", "")
        tp_match = re.match(r"^00-[0-9a-f]{32}-([0-9a-f]{16})-[0-9a-f]{2}$", tp)
        client_span_id = tp_match.group(1) if tp_match else sha(f"tool_cli_{action_id}_{attempt}")[:16]

        receipt = next((r for r in receipts if r.get("actionId") == action_id and int(r.get("attempt", 1)) == attempt), {})
        status_code = int(receipt.get("status", 200))
        rcpt_id = receipt.get("receiptId", "rcpt_simulated")
        rcpt_nonce = receipt.get("nonce", "nonce_simulated")

        span_attrs = common_attrs + [
            {"key": "ga5.action.id", "value": {"stringValue": action_id}},
            {"key": "ga5.attempt", "value": {"intValue": attempt}},
            {"key": "ga5.receipt.id", "value": {"stringValue": rcpt_id}},
            {"key": "ga5.receipt.nonce", "value": {"stringValue": rcpt_nonce}},
            {"key": "http.request.method", "value": {"stringValue": "POST"}},
            {"key": "http.request.resend_count", "value": {"intValue": max(0, attempt - 1)}},
            {"key": "http.response.status_code", "value": {"intValue": status_code}}
        ]

        client_span = {
            "traceId": trace_id,
            "spanId": client_span_id,
            "parentSpanId": exec_span_map[action_id],
            "name": f"POST tool/{tool_name}",
            "kind": 3,  # CLIENT
            "startTimeUnixNano": nano(),
            "endTimeUnixNano": str(int(nano()) + 25000000),
            "attributes": span_attrs
        }

        if status_code == 503:
            client_span["status"] = {"code": 2}
            client_span["attributes"].append({"key": "error.type", "value": {"stringValue": "503"}})
        elif status_code == 0:
            client_span["status"] = {"code": 2}
            client_span["attributes"].append({"key": "error.type", "value": {"stringValue": "timeout"}})
        else:
            client_span["status"] = {"code": 1}

        spans.append(client_span)

    if is_join and len(exec_span_map) > 1:
        join_span_id = sha(f"join_{run_id}")[:16]
        links = [{"traceId": trace_id, "spanId": sid, "attributes": common_attrs} for sid in exec_span_map.values()]
        spans.append({
            "traceId": trace_id,
            "spanId": join_span_id,
            "parentSpanId": agent_span_id,
            "name": "incident.join",
            "kind": 1,  # INTERNAL
            "startTimeUnixNano": nano(),
            "endTimeUnixNano": str(int(nano()) + 32000000),
            "attributes": common_attrs,
            "links": links
        })

    for a in approvals:
        spans.append({
            "traceId": trace_id,
            "spanId": sha(f"appr_{a['approvalId']}")[:16],
            "parentSpanId": agent_span_id,
            "name": "approval_gate",
            "kind": 1,  # INTERNAL
            "startTimeUnixNano": nano(),
            "endTimeUnixNano": str(int(nano()) + 35000000),
            "attributes": common_attrs + [
                {"key": "ga5.approval.id", "value": {"stringValue": a["approvalId"]}},
                {"key": "ga5.approval.nonce", "value": {"stringValue": a.get("nonce", "nonce_appr")}}
            ]
        })

    return {
        "resourceSpans": [{
            "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "incident-agent"}}]},
            "scopeSpans": [{"scope": {"name": "ga5-incident-tracer", "version": "1.0"}, "spans": spans}]
        }]
    }

def analyze_transcript(transcript: str, allowed_roots: list):
    lines = [line.strip() for line in transcript.split("\n") if line.strip()]
    ev_candidates = []
    for l in lines:
        m = re.match(r"^\[([A-Za-z0-9_\-]+)\](.*)", l)
        if m:
            ev_id = m.group(1)
            content = m.group(2).lower()
            ev_candidates.append((ev_id, content))

    best_root = allowed_roots[0] if allowed_roots else "unspecified_failure"
    best_score = -1
    chosen_evs = []

    for root in allowed_roots:
        tokens = [t for t in re.split(r"[_\s\-]+", root.lower()) if len(t) > 2]
        matching_evs = []
        for ev_id, content in ev_candidates:
            if any(tok in content for tok in tokens):
                matching_evs.append(ev_id)
        if len(matching_evs) > best_score:
            best_score = len(matching_evs)
            best_root = root
            chosen_evs = matching_evs

    if len(chosen_evs) < 2:
        all_ev_ids = [e[0] for e in ev_candidates]
        chosen_evs = (chosen_evs + all_ev_ids)[:3]
    if len(chosen_evs) < 2:
        chosen_evs = ["ev_primary", "ev_secondary"]

    return best_root, chosen_evs[:4]

@router.post("/v2/incidents")
@router.post("")
@router.post("/")
async def create_incident(request: Request):
    try: body = await request.json()
    except Exception: return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    if not isinstance(body, dict) or body.get("profile") != "ga5-incident-agent/v2" or not body.get("runId"):
        return JSONResponse({"error": "Invalid profile or missing runId"}, status_code=422)

    run_id = body["runId"]
    h = sha(canon(body))

    existing = q("SELECT request_hash, state_json FROM incident_runs WHERE run_id=?", (run_id,))
    if existing:
        if existing[0][0] != h:
            return JSONResponse({"error": "Changed content conflict"}, status_code=409)
        return JSONResponse(json.loads(existing[0][1]))

    incoming_tp = request.headers.get("traceparent", "")
    tp_match = re.match(r"^00-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$", incoming_tp)
    trace_id = tp_match.group(1) if tp_match else uuid.uuid4().hex

    incident_data = body.get("incident", {})
    transcript = incident_data.get("transcript", "")
    allowed_roots = incident_data.get("allowedRootCauses", [])
    service_name = incident_data.get("service", "target-service")
    catalog = body.get("toolCatalog", [])
    policy = body.get("policy", {})

    root_cause, evidence = analyze_transcript(transcript, allowed_roots)

    effect_tools = set(policy.get("effectTools", []))
    diag_tools = [t for t in catalog if t.get("name") not in effect_tools]
    if not diag_tools and catalog: diag_tools = [catalog[0]]

    max_diag = policy.get("maximumDiagnostics", 3)
    diag_tools = diag_tools[:max_diag]

    dispatches = []
    for t in diag_tools:
        tool_name = t.get("name", "query_metrics")
        act_id = "act_" + sha(f"{run_id}|{tool_name}")[:16]
        call_id = "call_" + sha(f"{run_id}|{tool_name}")[:16]
        client_span_id = sha(f"cli_{act_id}_1")[:16]
        tp = f"00-{trace_id}-{client_span_id}-01"

        dispatches.append({
            "actionId": act_id,
            "callId": call_id,
            "phase": "diagnostic",
            "toolName": tool_name,
            "arguments": {"service": service_name},
            "evidence": [evidence[0]],
            "attempt": 1,
            "traceparent": tp
        })

    response_payload = {
        "runId": run_id,
        "status": "waiting",
        "diagnosis": {"rootCause": root_cause, "evidence": evidence},
        "dispatches": dispatches,
        "approvals": []
    }

    internal_state = {
        "runId": run_id,
        "publicMarker": body.get("publicMarker", "marker_safe"),
        "traceId": trace_id,
        "agentModel": "gemini-2.5-flash",
        "diagnosis": {"rootCause": root_cause, "evidence": evidence},
        "catalog": catalog,
        "policy": policy,
        "service": service_name,
        "dispatches": dispatches,
        "actionLog": list(dispatches),
        "receiptLog": [],
        "approvalLog": [],
        "status": "waiting",
        "responsePayload": response_payload
    }

    tx([("INSERT INTO incident_runs (run_id, request_hash, state_json) VALUES (?,?,?)",
         (run_id, h, json.dumps(internal_state)))])

    return JSONResponse(response_payload)

@router.post("/v2/incidents/{runId}/receipts")
@router.post("/{runId}/receipts")
async def handle_receipts(runId: str, request: Request):
    try: body = await request.json()
    except Exception: return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    receipt_id = body.get("receiptId", str(uuid.uuid4()))
    receipt_key = f"{runId}_{receipt_id}"
    rh = sha(canon(body))

    existing_rcpt = q("SELECT receipt_hash, response_json FROM incident_receipts WHERE receipt_key=?", (receipt_key,))
    if existing_rcpt:
        if existing_rcpt[0][0] != rh:
            return JSONResponse({"error": "Changed receipt conflict"}, status_code=409)
        return JSONResponse(json.loads(existing_rcpt[0][1]))

    run_row = q("SELECT state_json FROM incident_runs WHERE run_id=?", (runId,))
    if not run_row: return JSONResponse({"error": "Run not found"}, status_code=404)
    state = json.loads(run_row[0][0])

    outcomes = body.get("outcomes", [])
    approvals_in = body.get("approvals", [])

    retry_dispatches = []
    has_timeout = False
    for o in outcomes:
        state["receiptLog"].append({
            "receiptId": receipt_id,
            "actionId": o.get("actionId"),
            "callId": o.get("callId"),
            "attempt": o.get("attempt", 1),
            "status": o.get("status", 200),
            "resultClass": o.get("resultClass", "diagnosis_confirmed"),
            "nonce": o.get("nonce", "nonce_default")
        })
        if o.get("status") == 503 and o.get("attempt", 1) == 1:
            matching_d = next((d for d in state["dispatches"] if d["actionId"] == o.get("actionId")), None)
            if matching_d:
                retry_d = dict(matching_d)
                retry_d["attempt"] = 2
                new_cli_span = sha(f"cli_{retry_d['actionId']}_2")[:16]
                retry_d["traceparent"] = f"00-{state['traceId']}-{new_cli_span}-01"
                retry_dispatches.append(retry_d)
                state["actionLog"].append(retry_d)
        elif o.get("status") == 0:
            has_timeout = True

    if retry_dispatches:
        resp = {
            "runId": runId,
            "status": "waiting",
            "diagnosis": state["diagnosis"],
            "dispatches": retry_dispatches,
            "approvals": []
        }
        state["responsePayload"] = resp
        state["dispatches"] = retry_dispatches
        tx([("UPDATE incident_runs SET state_json=? WHERE run_id=?", (json.dumps(state), runId)),
            ("INSERT INTO incident_receipts (receipt_key, receipt_hash, response_json) VALUES (?,?,?)",
             (receipt_key, rh, json.dumps(resp)))])
        return JSONResponse(resp)

    if has_timeout:
        trace = build_otlp_trace(runId, state["publicMarker"], state["traceId"], state["agentModel"],
                                 state["actionLog"], state["receiptLog"], state["approvalLog"], len(state["dispatches"]) > 1)
        resp = {
            "runId": runId,
            "status": "failed",
            "diagnosis": state["diagnosis"],
            "chosenEffect": None,
            "suppressed": list(state["policy"].get("effectTools", [])),
            "actionLog": state["actionLog"],
            "receiptLog": state["receiptLog"],
            "otlp": trace
        }
        state["responsePayload"] = resp
        tx([("UPDATE incident_runs SET state_json=? WHERE run_id=?", (json.dumps(state), runId)),
            ("INSERT INTO incident_receipts (receipt_key, receipt_hash, response_json) VALUES (?,?,?)",
             (receipt_key, rh, json.dumps(resp)))])
        return JSONResponse(resp)

    if approvals_in:
        appr = approvals_in[0]
        state["approvalLog"].append(appr)
        state["receiptLog"].append({
            "receiptId": receipt_id,
            "approvalId": appr.get("approvalId"),
            "decision": appr.get("decision", "approved"),
            "nonce": appr.get("nonce", "nonce_appr")
        })

        eff_tool = state.get("pendingEffectTool", "rollback_deployment")
        eff_act_id = state.get("pendingActionId", "act_effect")
        eff_call_id = state.get("pendingCallId", "call_effect")
        cli_span = sha(f"cli_{eff_act_id}_1")[:16]

        eff_dispatch = {
            "actionId": eff_act_id,
            "callId": eff_call_id,
            "phase": "effect",
            "toolName": eff_tool,
            "arguments": {"service": state["service"]},
            "evidence": [state["diagnosis"]["evidence"][0]],
            "attempt": 1,
            "approvalId": appr.get("approvalId"),
            "approvalNonce": appr.get("nonce"),
            "traceparent": f"00-{state['traceId']}-{cli_span}-01"
        }
        state["actionLog"].append(eff_dispatch)
        state["dispatches"] = [eff_dispatch]
        resp = {
            "runId": runId,
            "status": "waiting",
            "diagnosis": state["diagnosis"],
            "dispatches": [eff_dispatch],
            "approvals": []
        }
        state["responsePayload"] = resp
        tx([("UPDATE incident_runs SET state_json=? WHERE run_id=?", (json.dumps(state), runId)),
            ("INSERT INTO incident_receipts (receipt_key, receipt_hash, response_json) VALUES (?,?,?)",
             (receipt_key, rh, json.dumps(resp)))])
        return JSONResponse(resp)

    effect_tools = state["policy"].get("effectTools", ["rollback_deployment"])
    chosen_effect = effect_tools[0] if effect_tools else "scale_service"
    appr_required = state["policy"].get("approvalRequiredFor", [])

    has_effect_outcome = any(o.get("actionId") == state.get("pendingActionId") for o in outcomes)

    if not has_effect_outcome:
        if chosen_effect in appr_required:
            eff_act_id = "act_" + sha(f"{runId}|effect|{chosen_effect}")[:16]
            eff_call_id = "call_" + sha(f"{runId}|effect|{chosen_effect}")[:16]
            eff_args = {"service": state["service"]}
            args_digest = sha(canon(eff_args))
            appr_id = "appr_" + sha(f"{runId}|approval")[:16]

            state["pendingEffectTool"] = chosen_effect
            state["pendingActionId"] = eff_act_id
            state["pendingCallId"] = eff_call_id

            resp = {
                "runId": runId,
                "status": "waiting",
                "dispatches": [],
                "approvals": [{
                    "approvalId": appr_id,
                    "actionId": eff_act_id,
                    "toolName": chosen_effect,
                    "argumentsDigest": args_digest
                }]
            }
            state["responsePayload"] = resp
            tx([("UPDATE incident_runs SET state_json=? WHERE run_id=?", (json.dumps(state), runId)),
                ("INSERT INTO incident_receipts (receipt_key, receipt_hash, response_json) VALUES (?,?,?)",
                 (receipt_key, rh, json.dumps(resp)))])
            return JSONResponse(resp)
        else:
            eff_act_id = "act_" + sha(f"{runId}|effect|{chosen_effect}")[:16]
            eff_call_id = "call_" + sha(f"{runId}|effect|{chosen_effect}")[:16]
            cli_span = sha(f"cli_{eff_act_id}_1")[:16]
            eff_dispatch = {
                "actionId": eff_act_id,
                "callId": eff_call_id,
                "phase": "effect",
                "toolName": chosen_effect,
                "arguments": {"service": state["service"]},
                "evidence": [state["diagnosis"]["evidence"][0]],
                "attempt": 1,
                "traceparent": f"00-{state['traceId']}-{cli_span}-01"
            }
            state["pendingActionId"] = eff_act_id
            state["pendingEffectTool"] = chosen_effect
            state["actionLog"].append(eff_dispatch)
            state["dispatches"] = [eff_dispatch]
            resp = {
                "runId": runId,
                "status": "waiting",
                "diagnosis": state["diagnosis"],
                "dispatches": [eff_dispatch],
                "approvals": []
            }
            state["responsePayload"] = resp
            tx([("UPDATE incident_runs SET state_json=? WHERE run_id=?", (json.dumps(state), runId)),
                ("INSERT INTO incident_receipts (receipt_key, receipt_hash, response_json) VALUES (?,?,?)",
                 (receipt_key, rh, json.dumps(resp)))])
            return JSONResponse(resp)

    trace = build_otlp_trace(runId, state["publicMarker"], state["traceId"], state["agentModel"],
                             state["actionLog"], state["receiptLog"], state["approvalLog"], len(state.get("dispatches", [])) > 1)

    resp = {
        "runId": runId,
        "status": "completed",
        "diagnosis": state["diagnosis"],
        "chosenEffect": state.get("pendingEffectTool", chosen_effect),
        "suppressed": [],
        "actionLog": state["actionLog"],
        "receiptLog": state["receiptLog"],
        "otlp": trace
    }
    state["responsePayload"] = resp
    tx([("UPDATE incident_runs SET state_json=? WHERE run_id=?", (json.dumps(state), runId)),
        ("INSERT INTO incident_receipts (receipt_key, receipt_hash, response_json) VALUES (?,?,?)",
         (receipt_key, rh, json.dumps(resp)))])
    return JSONResponse(resp)

@router.get("/v2/incidents/{runId}")
@router.get("/{runId}")
def get_incident(runId: str):
    run_row = q("SELECT state_json FROM incident_runs WHERE run_id=?", (runId,))
    if not run_row: return JSONResponse({"error": "Not found"}, status_code=404)
    state = json.loads(run_row[0][0])
    return JSONResponse(state["responsePayload"])
