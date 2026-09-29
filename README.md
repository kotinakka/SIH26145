# Network Threat Monitor (SIH26145)

A real-time, passive network threat detection dashboard and analysis tool. It ingests PCAP files, analyzes network flows for active threat indicators (such as DDoS, Botnet C2, Port Scans, and DGA/DNS Tunneling), and visualizes security alerts via an enterprise-grade web interface.

# How to Run
- download and extract the zip file
- open the backend folder `backend/`folder
- Run `pip install -re requirements.txt` 
- Run `uvicorn main:app --reload` & follow the link.
---

## Features

* **Real-Time Live Streaming:** Replay lab capture files dynamically via WebSockets with adjustable speeds ($1\times$, $10\times$, $50\times$).
* **Batch Analysis:** Upload and instantly analyze local `.pcap` or `.pcapng` files via REST endpoints.
* **Passive & Read-Only:** Operates entirely as a passive ingest monitor with no return path or active probing.
* **Intelligent Incident Aggregation:** Automatically groups repetitive or distributed alerts (e.g., volumetric DDoS) into unified, manageable incident rows.
* **Modern IBM Plex UI:** Clean, responsive design system built with CSS variables, interactive severity charts (Chart.js), timeline markers, and detailed evidence breakdown panels.

---

## Project Structure

```text
├── dashboard/
│   ├── index.html       # Main web dashboard interface
│   ├── style.css        # Enterprise design stylesheet and layout grids
│   └── app.js           # Frontend logic, WebSocket handling, and Chart.js rendering
├── data/                # Lab PCAP captures (benign, ddos, port_scan, etc.)
├── main.py              # FastAPI backend entry point
├── requirements.txt     # Project dependencies
└── README.md