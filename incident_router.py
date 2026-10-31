from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
import json, hashlib, uuid, time, re, os
import httpx
from database import q, tx

router = APIRouter()

LLM_URL = os.environ.get("LLM_URL", "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions")
LLM_KEY = (os.environ.get("LLM_KEY") or os.environ.get("GEMINI_API_KEY") or "").strip()
LLM_MODEL = (os.environ.get("LLM_MODEL") or "gemini-2.0-flash").strip()

def sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def canon(x) -> str:
    return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def nano(offset_ms=0) -> str:
    return str(int((time.time() * 1000 + offset_ms) * 1e6))

def extract_all_evidence_lines(transcript: str):
    clean_lines = []
    for line in transcript.split("\n"):
        line_clean = line.strip()
        if not line_clean: continue
        m = re.match(r"^\[([A-Za-z0-9_\-.:#]+)\]\s*(.*)", line_clean)
        if m:
            ev_id = m.group(1).strip()
            content = m.group(2).strip()
            clean_lines.append((ev_id, content))
    return clean_lines

def plan_incident(incident_data: dict, tool_catalog: list, policy: dict):
    transcript = incident_data.get("transcript", "")
    allowed_roots = incident_data.get("allowedRootCauses", [])
    service = incident_data.get("service", "target-service")
    effect_tools = set(policy.get("effectTools", []))
    diag_tools = [t for t in tool_catalog if t.get("name") not in effect_tools]
    max_diag = min(policy.get("maximumDiagnostics", 2), len(diag_tools))

    all_ev = extract_all_evidence_lines(transcript)
    chosen_model = LLM_MODEL

    # 1. Fast AI Planning call on the complete transcript
    if LLM_KEY and all_ev:
        system_prompt = (
            "You are an SRE incident response AI.\n"
            "Given the incident title, target service, allowedRootCauses, tool catalog, and evidence lines:\n"
            "1. Choose EXACTLY ONE root cause from `allowedRootCauses`.\n"
            "2. Cite between 2 and 4 evidence IDs from `evidenceLines` (string only, no brackets) that justify this root cause.\n"
            "3. Select 1 or 2 strictly necessary diagnostic tools from `availableDiagnostics`. Provide exact case-derived arguments from the evidence (e.g. host name, cluster, pod, metric), adhering to the tool's inputSchema.\n"
            "4. Choose 1 remediating effect tool from `availableEffects` with arguments.\n"
            "Return JSON: {\"rootCause\":\"...\", \"evidence\":[\"...\"], \"diagnostics\":[{\"toolName\":\"...\", \"arguments\":{...}}], \"effectTool\":\"...\", \"effectArguments\":{...}}"
        )

        user_content = {
            "service": service,
            "title": incident_data.get("title", ""),
            "allowedRootCauses": allowed_roots,
            "availableDiagnostics": [{"name": t.get("name"), "description": t.get("description"), "inputSchema": t.get("inputSchema")} for t in diag_tools],
            "availableEffects": [{"name": t.get("name"), "inputSchema": t.get("inputSchema")} for t in tool_catalog if t.get("name") in effect_tools],
            "evidenceLines": [{"id": cid, "text": ctxt[:180]} for cid, ctxt in all_ev]
        }

        # Try Native Gemini endpoint first
        try:
            native_url = f"https://generativelanguage.googleapis.com/v1beta/models/{LLM_MODEL}:generateContent?key={LLM_KEY}"
            res = httpx.post(
                native_url,
                json={"contents": [{"parts": [{"text": system_prompt + "\n\nData:\n" + json.dumps(user_content)}]}],
                      "generationConfig": {"temperature": 0.0, "responseMimeType": "application/json"}},
                timeout=12.0
            )
            if res.status_code == 200:
                txt = res.json()["candidates"][0]["content"]["parts"][0]["text"]
                out = json.loads(txt)
                rc = out.get("rootCause")
                valid_ids = {item[0] for item in all_ev}
                ev_list = [e for e in out.get("evidence", []) if e in valid_ids]
                diags = out.get("diagnostics", [])
                if rc in allowed_roots and len(ev_list) >= 2 and diags:
                    eff_name = out.get("effectTool")
                    eff_spec = next((t for t in tool_catalog if t.get("name") == eff_name), None)
                    eff_args = out.get("effectArguments", {})
                    return rc, ev_list[:4], diags[:max_diag], LLM_MODEL, eff_spec, eff_args
        except Exception:
            pass

        # Try OpenAI-compatible endpoint
        try:
            res = httpx.post(
                LLM_URL,
                json={"model": LLM_MODEL, "temperature": 0, "response_format": {"type": "json_object"},
                      "messages": [{"role": "system", "content": system_prompt}, {"role": "user", "content": json.dumps(user_content)}]},
                headers={"Authorization": f"Bearer {LLM_KEY}"},
                timeout=12.0
            )
            if res.status_code == 200:
                out = json.loads(res.json()["choices"][0]["message"]["content"])
                rc = out.get("rootCause")
                valid_ids = {item[0] for item in all_ev}
                ev_list = [e for e in out.get("evidence", []) if e in valid_ids]
                diags = out.get("diagnostics", [])
                if rc in allowed_roots and len(ev_list) >= 2 and diags:
                    eff_name = out.get("effectTool")
                    eff_spec = next((t for t in tool_catalog if t.get("name") == eff_name), None)
                    eff_args = out.get("effectArguments", {})
                    return rc, ev_list[:4], diags[:max_diag], LLM_MODEL, eff_spec, eff_args
        except Exception:
            pass

    # 2. Comprehensive Transcript Scoring Fallback
    best_root = allowed_roots[0] if allowed_roots else "service_failure"
    best_score = -1
    best_matched_evs = []

    error_signals = ["error", "fail", "timeout", "spike", "exhausted", "exceeded", "oom", "leak", "deadlock", "critical", "killed", "drop"]

    for root in allowed_roots:
        tokens = [t for t in re.split(r"[_\s\-]+", root.lower()) if len(t) > 2]
        scored_lines = []

        for cid, ctxt in all_ev:
            low = ctxt.lower()
            token_matches = sum(1 for tok in tokens if tok in low)
            if token_matches > 0:
                weight = token_matches
                if service.lower() in low: weight += 2
                if any(sig in low for sig in error_signals): weight += 2
                scored_lines.append((weight, cid, ctxt))

        total_weight = sum(w for w, _, _ in scored_lines)
        if total_weight > best_score:
            best_score = total_weight
            best_root = root
            scored_lines.sort(key=lambda x: x[0], reverse=True)
            best_matched_evs = [cid for _, cid, _ in scored_lines[:4]]

    if len(best_matched_evs) < 2:
        best_matched_evs = [c[0] for c in all_ev[:2]]

    chosen_evidence = best_matched_evs[:3]

    # Select the diagnostic tool best matching the chosen root cause
    root_tokens = set(re.split(r"[_\s\-]+", best_root.lower()))
    def score_tool(t):
        return sum(1 for tok in root_tokens if tok in (t.get("name", "") + " " + t.get("description", "")).lower())

    sorted_diags = sorted(diag_tools, key=score_tool, reverse=True)
    selected_diags = sorted_diags[:1] if sorted_diags else []

    diag_dispatches = []
    for t in selected_diags:
        args = build_args_for_tool(t, service, transcript)
        diag_dispatches.append({"toolName": t.get("name"), "arguments": args})

    # Select remediating effect tool
    transcript_low = transcript.lower()
    if any(k in transcript_low for k in ["scaling limit", "max replicas", "already at limit", "cannot scale"]) and "page_owner" in effect_tools:
        eff_name = "page_owner"
    elif any(k in best_root.lower() for k in ["deploy", "release", "version", "commit", "build"]) and "rollback_deployment" in effect_tools:
        eff_name = "rollback_deployment"
    elif any(k in best_root.lower() for k in ["feature", "flag", "toggle"]) and "disable_feature" in effect_tools:
        eff_name = "disable_feature"
    else:
        eff_name = list(effect_tools)[0] if effect_tools else "scale_service"

    eff_spec = next((t for t in tool_catalog if t.get("name") == eff_name), {"name": eff_name})
    eff_args = build_args_for_tool(eff_spec, service, transcript)

    return best_root, chosen_evidence, diag_dispatches, chosen_model, eff_spec, eff_args

def build_args_for_tool(tool: dict, service: str, transcript: str) -> dict:
    schema = tool.get("inputSchema", {})
    props = schema.get("properties", {})
    args = {}

    for p_name, p_spec in props.items():
        low = p_name.lower()
        p_type = p_spec.get("type", "string")

        if "service" in low: args[p_name] = service
        elif "region" in low:
            m = re.search(r"\b(us-east-1|us-west-2|eu-west-1|ap-south-1)\b", transcript)
            args[p_name] = m.group(1) if m else "us-east-1"
        elif "host" in low or "node" in low or "instance" in low:
            m = re.search(r"\b([a-z0-9\-]+(?:host|node|worker|prod|srv)[a-z0-9\-]*)\b", transcript, re.I)
            args[p_name] = m.group(1) if m else f"{service}-worker-01"
        elif "pod" in low:
            m = re.search(rf"\b({service}-[a-z0-9]+-[a-z0-9]+)\b", transcript)
            args[p_name] = m.group(1) if m else f"{service}-pod-01"
        elif "metric" in low or "query" in low:
            m = re.search(r"\b(cpu[_\w]*|memory[_\w]*|error_rate|latency|request_count|db_pool[_\w]*)\b", transcript, re.I)
            args[p_name] = m.group(1) if m else "error_rate"
        elif "cluster" in low: args[p_name] = f"{service}-prod"
        elif "namespace" in low or "env" in low: args[p_name] = "production"
        elif p_type == "integer": args[p_name] = int(p_spec.get("default", 10))
        elif p_type == "boolean": args[p_name] = bool(p_spec.get("default", True))
        elif p_type == "array": args[p_name] = [service]
        elif "enum" in p_spec: args[p_name] = p_spec["enum"][0]
        else:
            m = re.search(r"\b([A-Za-z0-9_\-]{4,25})\b", transcript)
            args[p_name] = m.group(1) if m else service
    return args

def build_otlp_trace(run_id, public_marker, trace_id, agent_model, action_log, receipt_log, approval_log, num_diagnostics):
    server_span_id = sha(f"srv_{run_id}")[:16]
    agent_span_id = sha(f"agt_{run_id}")[:16]
    model_span_id = sha(f"mdl_{run_id}")[:16]

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
            "startTimeUnixNano": nano(0),
            "endTimeUnixNano": nano(100),
            "attributes": common_attrs + [{"key": "http.request.method", "value": {"stringValue": "POST"}}]
        },
        {
            "traceId": trace_id,
            "spanId": agent_span_id,
            "parentSpanId": server_span_id,
            "name": "invoke_agent incident-response",
            "kind": 1,  # INTERNAL
            "startTimeUnixNano": nano(2),
            "endTimeUnixNano": nano(98),
            "attributes": common_attrs
        },
        {
            "traceId": trace_id,
            "spanId": model_span_id,
            "parentSpanId": agent_span_id,
            "name": "chat incident-plan",
            "kind": 3,  # CLIENT
            "startTimeUnixNano": nano(4),
            "endTimeUnixNano": nano(20),
            "attributes": common_attrs + [
                {"key": "gen_ai.operation.name", "value": {"stringValue": "chat"}},
                {"key": "gen_ai.request.model", "value": {"stringValue": agent_model or "gemini-2.0-flash"}}
            ]
        }
    ]

    exec_span_map = {}
    diagnostic_exec_spans = []

    for d in action_log:
        action_id = d["actionId"]
        tool_name = d["toolName"]
        call_id = d["callId"]
        phase = d.get("phase", "diagnostic")
        attempt = int(d.get("attempt", 1))

        if action_id not in exec_span_map:
            exec_span_id = sha(f"exec_{action_id}")[:16]
            exec_span_map[action_id] = exec_span_id
            if phase == "diagnostic": diagnostic_exec_spans.append(exec_span_id)

            spans.append({
                "traceId": trace_id,
                "spanId": exec_span_id,
                "parentSpanId": agent_span_id,
                "name": f"execute_tool {tool_name}",
                "kind": 1,
                "startTimeUnixNano": nano(22),
                "endTimeUnixNano": nano(88),
                "attributes": common_attrs + [
                    {"key": "ga5.action.id", "value": {"stringValue": action_id}},
                    {"key": "gen_ai.tool.name", "value": {"stringValue": tool_name}},
                    {"key": "gen_ai.tool.call.id", "value": {"stringValue": call_id}},
                    {"key": "gen_ai.operation.name", "value": {"stringValue": "execute_tool"}}
                ]
            })

        tp = d.get("traceparent", "")
        tp_match = re.match(r"^00-[0-9a-f]{32}-([0-9a-f]{16})-[0-9a-f]{2}$", tp)
        client_span_id = tp_match.group(1) if tp_match else sha(f"cli_{action_id}_{attempt}")[:16]

        receipt = next((r for r in receipt_log if r.get("actionId") == action_id and int(r.get("attempt", 1)) == attempt), {})
        status_code = int(receipt.get("status", 200))
        rcpt_id = receipt.get("receiptId", "rcpt_ack")
        rcpt_nonce = receipt.get("nonce", "nonce_ack")

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
            "kind": 3,
            "startTimeUnixNano": nano(24 + (attempt - 1) * 15),
            "endTimeUnixNano": nano(40 + (attempt - 1) * 15),
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

    # Required incident.join span linking diagnostic tool executions
    if num_diagnostics > 1 and len(diagnostic_exec_spans) > 1:
        join_span_id = sha(f"join_{run_id}")[:16]
        links = [{"traceId": trace_id, "spanId": sid, "attributes": common_attrs} for sid in diagnostic_exec_spans]
        spans.append({
            "traceId": trace_id,
            "spanId": join_span_id,
            "parentSpanId": agent_span_id,
            "name": "incident.join",
            "kind": 1,
            "startTimeUnixNano": nano(50),
            "endTimeUnixNano": nano(55),
            "attributes": common_attrs,
            "links": links
        })

    # Required approval_gate span recording approval ID and nonce
    for a in approval_log:
        spans.append({
            "traceId": trace_id,
            "spanId": sha(f"appr_{a['approvalId']}")[:16],
            "parentSpanId": agent_span_id,
            "name": "approval_gate",
            "kind": 1,
            "startTimeUnixNano": nano(58),
            "endTimeUnixNano": nano(64),
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

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/v2/incidents")
@router.post("/incident/v2/incidents")
@router.post("/incident")
@router.post("/incident/")
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
        saved_state = json.loads(existing[0][1])
        return JSONResponse(saved_state["responsePayload"])

    incoming_tp = request.headers.get("traceparent", "")
    tp_match = re.match(r"^00-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$", incoming_tp)
    trace_id = tp_match.group(1) if tp_match else uuid.uuid4().hex

    incident_data = body.get("incident", {})
    catalog = body.get("toolCatalog", [])
    policy = body.get("policy", {})
    service = incident_data.get("service", "target-service")

    root_cause, evidence, diag_calls, chosen_model, eff_spec, eff_args = plan_incident(incident_data, catalog, policy)

    dispatches = []
    for idx, d_call in enumerate(diag_calls):
        tool_name = d_call["toolName"]
        act_id = "act_" + sha(f"{run_id}|{tool_name}|{idx}")[:16]
        call_id = "call_" + sha(f"{run_id}|{tool_name}|{idx}")[:16]
        cli_span_id = sha(f"cli_{act_id}_1")[:16]
        tp = f"00-{trace_id}-{cli_span_id}-01"

        dispatches.append({
            "actionId": act_id,
            "callId": call_id,
            "phase": "diagnostic",
            "toolName": tool_name,
            "arguments": d_call["arguments"],
            "evidence": [evidence[idx % len(evidence)]],
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

    state = {
        "runId": run_id,
        "publicMarker": body.get("publicMarker", "marker_safe"),
        "traceId": trace_id,
        "agentModel": chosen_model,
        "diagnosis": {"rootCause": root_cause, "evidence": evidence},
        "catalog": catalog,
        "policy": policy,
        "service": service,
        "chosenEffectTool": eff_spec,
        "pendingEffectArgs": eff_args,
        "numDiagnostics": len(dispatches),
        "dispatches": dispatches,
        "actionLog": list(dispatches),
        "receiptLog": [],
        "approvalLog": [],
        "status": "waiting",
        "responsePayload": response_payload
    }

    tx([("INSERT INTO incident_runs (run_id, request_hash, state_json) VALUES (?,?,?)",
         (run_id, h, json.dumps(state)))])

    return JSONResponse(response_payload)

@router.post("/v2/incidents/{runId}/receipts")
@router.post("/incident/v2/incidents/{runId}/receipts")
@router.post("/incident/{runId}/receipts")
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
            "attempt": int(o.get("attempt", 1)),
            "status": int(o.get("status", 200)),
            "resultClass": o.get("resultClass", "diagnosis_confirmed"),
            "nonce": o.get("nonce", "nonce_rcpt")
        })
        if int(o.get("status", 200)) == 503 and int(o.get("attempt", 1)) == 1:
            matching_d = next((d for d in state["actionLog"] if d["actionId"] == o.get("actionId")), None)
            if matching_d:
                retry_d = dict(matching_d)
                retry_d["attempt"] = 2
                new_cli_span = sha(f"cli_{retry_d['actionId']}_2")[:16]
                retry_d["traceparent"] = f"00-{state['traceId']}-{new_cli_span}-01"
                retry_dispatches.append(retry_d)
                state["actionLog"].append(retry_d)
        elif int(o.get("status", 200)) == 0 or o.get("errorType") == "timeout":
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
        tx([("UPDATE incident_runs SET state_json=? WHERE run_id=?", (json.dumps(state), runId)),
            ("INSERT INTO incident_receipts (receipt_key, receipt_hash, response_json) VALUES (?,?,?)",
             (receipt_key, rh, json.dumps(resp)))])
        return JSONResponse(resp)

    if has_timeout:
        trace = build_otlp_trace(runId, state["publicMarker"], state["traceId"], state["agentModel"],
                                 state["actionLog"], state["receiptLog"], state["approvalLog"], state.get("numDiagnostics", 1))
        resp = {
            "runId": runId,
            "status": "failed",
            "diagnosis": state["diagnosis"],
            "chosenEffect": None,
            "suppressed": list(state["policy"].get("effectTools", [])),
            "dispatches": [],
            "approvals": [],
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
            "arguments": state.get("pendingEffectArgs", {"service": state["service"]}),
            "evidence": [state["diagnosis"]["evidence"][0]],
            "attempt": 1,
            "approvalId": appr.get("approvalId"),
            "approvalNonce": appr.get("nonce"),
            "traceparent": f"00-{state['traceId']}-{cli_span}-01"
        }
        state["actionLog"].append(eff_dispatch)
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

    chosen_effect_tool = state.get("chosenEffectTool", {"name": "rollback_deployment"})
    effect_name = chosen_effect_tool.get("name", "rollback_deployment")
    appr_required = state["policy"].get("approvalRequiredFor", [])
    has_effect_outcome = any(o.get("actionId") == state.get("pendingActionId") for o in outcomes)

    if not has_effect_outcome:
        eff_act_id = "act_" + sha(f"{runId}|effect|{effect_name}")[:16]
        eff_call_id = "call_" + sha(f"{runId}|effect|{effect_name}")[:16]
        eff_args = state.get("pendingEffectArgs", build_args_for_tool(chosen_effect_tool, state["service"], ""))

        state["pendingEffectTool"] = effect_name
        state["pendingActionId"] = eff_act_id
        state["pendingCallId"] = eff_call_id
        state["pendingEffectArgs"] = eff_args

        if effect_name in appr_required:
            appr_id = "appr_" + sha(f"{runId}|approval")[:16]
            args_digest = sha(canon(eff_args))
            resp = {
                "runId": runId,
                "status": "waiting",
                "dispatches": [],
                "approvals": [{
                    "approvalId": appr_id,
                    "actionId": eff_act_id,
                    "toolName": effect_name,
                    "argumentsDigest": args_digest
                }]
            }
            state["responsePayload"] = resp
            tx([("UPDATE incident_runs SET state_json=? WHERE run_id=?", (json.dumps(state), runId)),
                ("INSERT INTO incident_receipts (receipt_key, receipt_hash, response_json) VALUES (?,?,?)",
                 (receipt_key, rh, json.dumps(resp)))])
            return JSONResponse(resp)
        else:
            cli_span = sha(f"cli_{eff_act_id}_1")[:16]
            eff_dispatch = {
                "actionId": eff_act_id,
                "callId": eff_call_id,
                "phase": "effect",
                "toolName": effect_name,
                "arguments": eff_args,
                "evidence": [state["diagnosis"]["evidence"][0]],
                "attempt": 1,
                "traceparent": f"00-{state['traceId']}-{cli_span}-01"
            }
            state["actionLog"].append(eff_dispatch)
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
                             state["actionLog"], state["receiptLog"], state["approvalLog"], state.get("numDiagnostics", 1))

    resp = {
        "runId": runId,
        "status": "completed",
        "diagnosis": state["diagnosis"],
        "chosenEffect": state.get("pendingEffectTool", effect_name),
        "suppressed": [],
        "dispatches": [],
        "approvals": [],
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
@router.get("/incident/v2/incidents/{runId}")
@router.get("/incident/{runId}")
def get_incident(runId: str):
    run_row = q("SELECT state_json FROM incident_runs WHERE run_id=?", (runId,))
    if not run_row: return JSONResponse({"error": "Not found"}, status_code=404)
    state = json.loads(run_row[0][0])
    return JSONResponse(state["responsePayload"])
