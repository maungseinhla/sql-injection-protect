import requests

BASE_URL = "http://127.0.0.1:8000/search"

test_cases = [
    # (Payload, Expected Status, Label)
    ("alice", 200, "Benign Name"),
    ("laptop charger", 200, "Benign Query"),
    ("admin' OR 1=1--", 403, "Classic Tautology"),
    ("1' UNION SELECT null, null--", 403, "UNION Query"),
    ("test' AND SLEEP(5)--", 403, "Time-based Pattern"),
]

print(f"{'Label':<25} | {'Status':<6} | {'Expected':<8} | {'Result'}")
print("-" * 55)

for payload, expected, label in test_cases:
    try:
        res = requests.get(BASE_URL, params={"q": payload}, timeout=3)
        status = res.status_code
        passed = "PASS" if status == expected else "FAIL"
        print(f"{label:<25} | {status:<6} | {expected:<8} | {passed}")
    except requests.RequestException as e:
        print(f"{label:<25} | ERROR  | {expected:<8} | {e}")