# WAF-SENTINEL-X 🛡️
> Hybrid Machine Learning Web Application Firewall & Asynchronous Reverse Proxy

WAF-SENTINEL-X protects vulnerable web endpoints against SQL Injection (SQLi) attacks by running an inline reverse proxy inspection engine. It combines character-level TF-IDF analysis, logistic regression inference, and signature heuristics to reject malicious inputs before they reach target application code.

---

## Features

- **Inline Machine Learning Inspection:** Character n-gram extraction paired with Scikit-learn Logistic Regression to identify structural SQL manipulation.
- **Heuristic Guardrails:** Immediate heuristic blocking for advanced Blind/Time-based delay syntax (`sleep()`, `benchmark()`).
- **Asynchronous Reverse Proxy:** Built on FastAPI and HTTPX for low-latency header/body forwarding to upstream services.
- **Tor & Origin Tracking:** Dynamic memory caching of Tor exit nodes with support for `X-Forwarded-For` and `CF-Connecting-IP` headers.
- **SOC Analyst Console:** Terminal-styled SIEM dashboard with Chart.js telemetry, real-time log ingestion, search filtering, upstream health probes, and log-purging controls.

---

## Prerequisites

- Python 3.9+
- Linux, macOS, or Windows (WSL2 recommended)

---

## Installation

1. **Clone the Repository:**
   ```bash
   git clone [https://github.com/your-username/waf-sentinel-x.git](https://github.com/your-username/waf-sentinel-x.git)
   cd waf-sentinel-x

2. ** Set up the virtual environment **
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate