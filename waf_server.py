import sqlite3
import urllib.parse
from datetime import datetime
import os
import time
import asyncio
from contextlib import asynccontextmanager
import joblib

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
import httpx


vectorizer = joblib.load("vectorizer.pkl")
model = joblib.load("sqli_model.pkl")
THRESHOLD = 0.50

##insert your target server URL here bro

TARGET_SERVER_URL = "http://127.0.0.1:5000"


TOR_NODES = set()
TOR_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"

async def sync_tor_nodes():
    global TOR_NODES
    try:
        async with httpx.AsyncClient() as client:
            res = await client.get(TOR_EXIT_LIST_URL, timeout=5.0)
            if res.status_code == 200:
                TOR_NODES = set(line.strip() for line in res.text.splitlines() if line.strip())
                print(f"[*] Synced {len(TOR_NODES)} Tor exit nodes successfully.")
    except Exception as e:
        print(f"[!] Warning: Tor exit list sync failed ({e})")


@asynccontextmanager
async def lifespan(app: FastAPI):
    asyncio.create_task(sync_tor_nodes())
    yield

app = FastAPI(title="ML-Powered WAF & Reverse Proxy", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


DB_FILE = "waf_logs.db"

def get_db_connection():
    conn = sqlite3.connect(DB_FILE, timeout=10.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            client_ip TEXT,
            ip_type TEXT,
            endpoint TEXT,
            payload TEXT,
            confidence REAL,
            status TEXT
        )
    """)
    
    cursor.execute("PRAGMA table_info(logs)")
    columns = [row["name"] for row in cursor.fetchall()]
    if "ip_type" not in columns:
        cursor.execute("ALTER TABLE logs ADD COLUMN ip_type TEXT DEFAULT 'DIRECT'")
    conn.commit()
    conn.close()

init_db()

def log_event(client_ip: str, ip_type: str, endpoint: str, payload: str, confidence: float, status: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO logs (timestamp, client_ip, ip_type, endpoint, payload, confidence, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        client_ip,
        ip_type,
        endpoint,
        payload,
        round(confidence * 100, 2),
        status
    ))
    conn.commit()
    conn.close()


def extract_real_ip(request: Request) -> str:
    
    cf_ip = request.headers.get("cf-connecting-ip")
    if cf_ip:
        return cf_ip.strip()
    x_forwarded = request.headers.get("x-forwarded-for")
    if x_forwarded:
        return x_forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"

def classify_ip(ip: str) -> str:
    if ip in ("127.0.0.1", "localhost") or ip.startswith(("10.", "192.168.", "172.16.")):
        return "LOCAL"
    if ip in TOR_NODES:
        return "TOR-EXIT"
    return "PUBLIC-IP"


SUSPICIOUS_FUNCTIONS = ["sleep(", "benchmark(", "waitfor delay", "pg_sleep("]

def inspect_text(text: str) -> tuple[bool, float]:
    if not text:
        return False, 0.0
    cleaned = urllib.parse.unquote(text).lower().strip()
    
    # Heuristics for Time-based attacks
    if any(fn in cleaned for fn in SUSPICIOUS_FUNCTIONS):
        return True, 0.99
        
    vec = vectorizer.transform([cleaned])
    prob = float(model.predict_proba(vec)[0][1])
    return (prob >= THRESHOLD), prob


@app.get("/dashboard", response_class=FileResponse)
async def serve_dashboard():
    if os.path.exists("index.html"):
        return FileResponse("index.html")
    return HTMLResponse("<h2>index.html not found</h2>", status_code=404)

@app.get("/api/dashboard/stats")
async def get_stats():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM logs")
    total = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM logs WHERE status = 'BLOCKED'")
    blocked = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM logs WHERE status = 'ALLOWED'")
    allowed = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM logs WHERE ip_type = 'TOR-EXIT'")
    tor_count = cursor.fetchone()[0]
    conn.close()
    return {
        "total_requests": total,
        "blocked_attacks": blocked,
        "allowed_requests": allowed,
        "tor_detected": tor_count
    }

@app.get("/api/dashboard/logs")
async def get_logs(limit: int = 50):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM logs ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

@app.post("/api/dashboard/clear-logs")
async def clear_logs():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM logs")
    cursor.execute("DELETE FROM sqlite_sequence WHERE name='logs'")
    conn.commit()
    conn.close()
    return {"status": "success", "message": "All logs have been cleared successfully."}

@app.get("/api/dashboard/target-health")
async def get_target_health():
    start_time = time.time()
    try:
        async with httpx.AsyncClient() as client:
            res = await client.get(TARGET_SERVER_URL, timeout=2.0)
            latency = round((time.time() - start_time) * 1000, 2)
            return {
                "target_url": TARGET_SERVER_URL,
                "status": "ONLINE" if res.status_code < 500 else "DEGRADED",
                "status_code": res.status_code,
                "latency_ms": latency
            }
    except Exception:
        return {
            "target_url": TARGET_SERVER_URL,
            "status": "OFFLINE",
            "status_code": None,
            "latency_ms": 0.0
        }

@app.get("/api/dashboard/chart-data")
async def get_chart_data():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT strftime('%H:00', timestamp) as hour,
               SUM(CASE WHEN status = 'ALLOWED' THEN 1 ELSE 0 END) as allowed_count,
               SUM(CASE WHEN status = 'BLOCKED' THEN 1 ELSE 0 END) as blocked_count
        FROM logs
        GROUP BY hour
        ORDER BY hour DESC
        LIMIT 8
    """)
    rows = cursor.fetchall()
    conn.close()

    rows.reverse()
    labels = [r["hour"] for r in rows] if rows else ["Now"]
    allowed = [r["allowed_count"] for r in rows] if rows else [0]
    blocked = [r["blocked_count"] for r in rows] if rows else [0]

    return {
        "labels": labels,
        "allowed": allowed,
        "blocked": blocked
    }


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def reverse_proxy(path: str, request: Request):
    if path == "dashboard" or path.startswith("api/dashboard"):
        raise HTTPException(status_code=404, detail="Endpoint handled by Dashboard API")

    client_ip = extract_real_ip(request)
    ip_type = classify_ip(client_ip)
    url_path = f"/{path}"
    
    query_string = request.url.query
    extracted_payloads = []
    
    if query_string:
        extracted_payloads.append(query_string)

    body_bytes = await request.body()
    if body_bytes:
        extracted_payloads.append(body_bytes.decode(errors="ignore"))

    combined_payload = " ".join(extracted_payloads)

    if combined_payload:
        is_attack, confidence = inspect_text(combined_payload)
        if is_attack:
            log_event(client_ip, ip_type, url_path, combined_payload, confidence, "BLOCKED")
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "Access Denied: SQL Injection Detected by WAF",
                    "confidence": f"{confidence * 100:.2f}%",
                    "status": "BLOCKED",
                    "origin_type": ip_type
                }
            )
        else:
            log_event(client_ip, ip_type, url_path, combined_payload, confidence, "ALLOWED")
    else:
        log_event(client_ip, ip_type, url_path, "[EMPTY]", 0.0, "ALLOWED")

    target_url = f"{TARGET_SERVER_URL}/{path}"
    if query_string:
        target_url = f"{target_url}?{query_string}"

    headers = dict(request.headers)
    headers.pop("host", None)

    async with httpx.AsyncClient() as client:
        try:
            target_response = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body_bytes,
                timeout=10.0
            )
            return Response(
                content=target_response.content,
                status_code=target_response.status_code,
                headers=dict(target_response.headers)
            )
        except httpx.RequestError as exc:
            raise HTTPException(status_code=502, detail=f"Bad Gateway: Target Server unreachable ({exc})")