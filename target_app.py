# target_app.py
from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse
import sqlite3

target_app = FastAPI(title="Vulnerable Demo App")


conn = sqlite3.connect(":memory:", check_same_thread=False)
cursor = conn.cursor()
cursor.execute("CREATE TABLE users (id INT, username TEXT, role TEXT)")
cursor.execute("INSERT INTO users VALUES (1, 'admin', 'SuperAdmin'), (2, 'alice', 'User')")
conn.commit()

@target_app.get("/")
def home():
    return HTMLResponse("<h1>Welcome to Target App (Protected Backend)</h1>")

@target_app.get("/search")
def search(q: str = Query("")):
    
    query = f"SELECT username, role FROM users WHERE username = '{q}'"
    try:
        cursor.execute(query)
        rows = cursor.fetchall()
        return {"status": "success", "executed_query": query, "data": rows}
    except Exception as e:
        return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(target_app, host="127.0.0.1", port=5000)