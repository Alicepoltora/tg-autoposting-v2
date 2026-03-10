import subprocess
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict
import config_manager

from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import os

app = FastAPI(title="Telegram Bot Management API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ConfigUpdate(BaseModel):
    sources: List[str]
    target: str
    cleaning_rules: List[Dict[str, str]]
    auto_translate: bool

@app.get("/", response_class=HTMLResponse)
def get_gui():
    try:
        with open("index.html", "r", encoding="utf-8") as f:
            return f.read()
    except Exception:
        return "<h1>Index.html not found</h1>"

@app.get("/status")
def get_status():
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "telegram-bot"],
            capture_output=True, text=True
        )
        return {"status": result.stdout.strip()}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/config")
def get_config():
    return config_manager.load_config()

@app.post("/config")
def update_config(new_config: ConfigUpdate):
    try:
        config_manager.save_config(new_config.dict())
        return {"message": "Config updated successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/restart")
def restart_bot():
    try:
        subprocess.run(["systemctl", "restart", "telegram-bot"], check=True)
        return {"message": "Bot restarted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to restart bot: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=80)
