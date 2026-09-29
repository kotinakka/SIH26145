"""
Phase 7 — FastAPI backend.

Exposes the flow-extraction + rule-based detection pipeline over
HTTP. This is the entry point that the dashboard (Phase 8) and
future streaming layer (section 6) will talk to.

Currently stateless: /analyze runs the pipeline on an uploaded
PCAP and returns results directly. No persistence yet — that
comes with the SQLite-backed /alerts and /statistics endpoints.
"""

import os
import tempfile
from datetime import datetime, timezone
from database import init_db, insert_alert, get_alerts, get_statistics
from fastapi import FastAPI, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import json
from fastapi import WebSocket, WebSocketDisconnect
from streaming import stream_detect
from flow import (
    attach_tls_aggregates,
    extract_flows,
    attach_source_aggregates,
    attach_destination_aggregates,
    attach_dns_aggregates,
    attach_tls_aggregates
)
from detector import detect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

# Serve the dashboard static files
dashboard_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "dashboard"))
app = FastAPI(
    title="SIH26145 - AI-Based Cyber Threat Detection",
    description="Passive, read-only detection of threats in unidirectional IP traffic.",
    version="0.1.0",
)
dashboard_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "dashboard"))
if os.path.exists(dashboard_path):
    app.mount("/static", StaticFiles(directory=dashboard_path), name="static")

    @app.get("/")
    def serve_dashboard():
        return FileResponse(os.path.join(dashboard_path, "index.html"))



@app.on_event("startup")
def startup():
    init_db()

# Allow the dashboard (served separately, e.g. from a different
# port/file) to call this API from the browser.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def make_flow_id(flow):
    """
    Builds a stable, human-readable identifier for a flow from its
    5-tuple, so each alert can be traced back to the exact flow
    that produced it.
    """
    return (
        f"{flow['src_ip']}:{flow['src_port']}-"
        f"{flow['dst_ip']}:{flow['dst_port']}-"
        f"{flow['protocol']}"
    )


@app.get("/")
def root():
    return {
        "project": "SIH26145",
        "title": "AI-Based Detection of Cyber Threats in Unidirectional IP Traffic",
        "status": "running",
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze")
async def analyze(
    file: UploadFile = File(...),
    include_benign: bool = Query(
        False,
        description="If true, also return flows classified as BENIGN. Default: only return non-benign alerts.",
    ),
):
    """
    Accepts a PCAP file, runs the full extraction + detection
    pipeline, and returns a list of structured alerts matching
    the schema in section 5 of the problem spec.

    This is a batch, request/response endpoint — it processes
    the whole PCAP before responding. Incremental/streaming
    analysis (section 6) will be a separate endpoint later.
    """

    # Save the uploaded file to a temp location so Scapy (which
    # reads from disk, not from memory) can process it.
    suffix = os.path.splitext(file.filename)[1] or ".pcap"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        contents = await file.read()
        tmp.write(contents)
        tmp_path = tmp.name

    try:
        results = extract_flows(tmp_path)
        results = attach_source_aggregates(results)
        results = attach_destination_aggregates(results)
        results = attach_dns_aggregates(results, tmp_path)
        results = attach_tls_aggregates(results, tmp_path)
    finally:
        # Always clean up the temp file, even if extraction fails.
        os.remove(tmp_path)

    timestamp = datetime.now(timezone.utc).isoformat()

    alerts = []

    for flow in results:
        verdict = detect(flow)

        if not include_benign and verdict["threat_class"] == "BENIGN":
            continue

        alert = {
            "timestamp": timestamp,
            "flow_id": make_flow_id(flow),
            "src_ip": flow["src_ip"],
            "src_port": flow["src_port"],
            "dst_ip": flow["dst_ip"],
            "dst_port": flow["dst_port"],
            "protocol": flow["protocol"],
            "threat_class": verdict["threat_class"],
            "confidence": verdict["confidence"],
            "severity": verdict["severity"],
            "risk_score": verdict["risk_score"],
            "evidence": verdict["evidence"],
        }

        alerts.append(alert)
        # Only persist real detections. Saving BENIGN rows (which
        # happens when include_benign=true) pollutes alerts.db and
        # /statistics with zero-severity noise that never clears
        # until the DB file is deleted by hand.
        if verdict["threat_class"] != "BENIGN":
            insert_alert(alert, source_file=file.filename)

    return {
        "source_file": file.filename,
        "total_flows": len(results),
        "total_alerts": len(alerts),
        "alerts": alerts,
    }
@app.get("/alerts")
def list_alerts(
    threat_class: str = Query(None, description="Filter by threat class, e.g. DDOS, PORT_SCAN"),
    severity: str = Query(None, description="Filter by severity, e.g. CRITICAL, HIGH"),
    limit: int = Query(100, le=1000, description="Max number of alerts to return"),
):
    alerts = get_alerts(threat_class=threat_class, severity=severity, limit=limit)
    return {"count": len(alerts), "alerts": alerts}


@app.get("/statistics")
def statistics():
    return get_statistics()
@app.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket):
    """
    Streams near-real-time alerts to a connected client.

    Protocol:
      1. Client connects.
      2. Client sends one JSON message: {"pcap_file": "...", "speed_factor": 50}
      3. Server streams back JSON events as they occur:
         {"type": "alert", ...}  - pushed the moment a flow first
                                    crosses into a non-benign verdict
         {"type": "summary", ...} - sent once, after replay finishes
      4. Server closes the socket after the summary is sent.

    stream_detect() is a blocking generator (it uses time.sleep for
    pacing), so it's run in a background thread via asyncio's
    default executor. Events are forwarded to the websocket as
    they're produced, not batched at the end.
    """

    await websocket.accept()

    try:
        request = await websocket.receive_json()
    except Exception:
        await websocket.close(code=1003, reason="Expected a JSON message with pcap_file")
        return

    pcap_file = request.get("pcap_file")
    speed_factor = request.get("speed_factor", 50.0)

    if not pcap_file:
        await websocket.send_json({"type": "error", "message": "pcap_file is required"})
        await websocket.close()
        return

    loop = asyncio.get_event_loop()
    event_queue = asyncio.Queue()

    def run_stream():
        """
        Runs in a background thread. Pushes each event from the
        blocking generator onto the asyncio queue via
        call_soon_threadsafe, so the async side can consume them
        without blocking the event loop.
        """
        try:
            for event in stream_detect(pcap_file, speed_factor=speed_factor):
                loop.call_soon_threadsafe(event_queue.put_nowait, event)
        except Exception as e:
            loop.call_soon_threadsafe(
                event_queue.put_nowait, {"type": "error", "message": str(e)}
            )
        finally:
            loop.call_soon_threadsafe(event_queue.put_nowait, None)  # sentinel: done

    loop.run_in_executor(None, run_stream)

    try:
        while True:
            event = await event_queue.get()

            if event is None:
                break

            if event.get("type") == "alert":
                insert_alert(event, source_file=pcap_file)

            await websocket.send_json(event)

    except WebSocketDisconnect:
        pass
    finally:
        await websocket.close()