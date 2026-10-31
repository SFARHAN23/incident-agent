import os, json
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
import a2a_router, mailroom_router, incident_router

app = FastAPI(title="Unified Agent Suite")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
@app.get("/healthz")
def health(request: Request):
    host = request.headers.get("x-forwarded-host") or request.headers.get("host", "localhost")
    return {
        "status": "healthy",
        "service": "Unified Agent Suite",
        "endpoints": {
            "task2_a2a_base": f"https://{host}/a2a/",
            "task3_mailroom": f"https://{host}/mailroom",
            "task4_incident": f"https://{host}/v2/incidents"
        }
    }

@app.get("/.well-known/agent-card.json")
def agent_card(request: Request):
    host = request.headers.get("x-forwarded-host") or request.headers.get("host", "localhost")
    base = f"https://{host}/a2a/"
    card_data = {
        "name": "Invoice Action Agent",
        "description": "Reads invoice packages and proposes one safe action per invoice with cited evidence.",
        "version": "1.0.0",
        "capabilities": {"streaming": False, "pushNotifications": False},
        "supportedInterfaces": [{"url": base, "protocolBinding": "HTTP+JSON", "protocolVersion": "1.0"}],
        "defaultInputModes": ["application/vnd.ga5.invoice-claim-batch+json"],
        "defaultOutputModes": [
            "application/vnd.ga5.invoice-action-proposals+json",
            "application/vnd.ga5.invoice-action-receipts+json"
        ],
        "skills": [{
            "id": "invoice_action_agent",
            "name": "Invoice action agent",
            "description": "Decides settle, approve, hold, reject-duplicate or exception for each invoice package.",
            "tags": ["invoice", "payments", "approval"]
        }]
    }
    return Response(content=json.dumps(card_data, ensure_ascii=False), media_type="application/a2a+json")

# Mount Routers
app.include_router(a2a_router.router, prefix="/a2a", tags=["Task 2: Invoice Agent"])
app.include_router(mailroom_router.router, tags=["Task 3: Safe Mailroom"])
app.include_router(incident_router.router, tags=["Task 4: Incident Triage"])

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)
