import subprocess
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Optional
import config_manager
from database import Database
from datetime import datetime, timedelta
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import os
import logging

# Setup logging to capture logs
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(title="Telegram Bot Management API")
db = Database()

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

@app.get("/stats")
def get_stats(hours: int = 24):
    """Get statistics about messages processed"""
    try:
        import sqlite3
        conn = sqlite3.connect(db.db_path)
        cursor = conn.cursor()
        
        # Messages processed in the specified period
        since = datetime.now() - timedelta(hours=hours)
        cursor.execute(
            "SELECT COUNT(*) FROM processed_messages WHERE timestamp > ?",
            (since.isoformat(),)
        )
        messages_processed = cursor.fetchone()[0]
        
        # Total messages
        cursor.execute("SELECT COUNT(*) FROM processed_messages")
        messages_total = cursor.fetchone()[0]
        
        # Get bot uptime (from process)
        try:
            result = subprocess.run(
                ["systemctl", "show", "telegram-bot", "-p", "ActiveEnterTimestamp"],
                capture_output=True, text=True
            )
            uptime_str = "Unknown"
        except:
            uptime_str = "Unknown"
        
        conn.close()
        
        return {
            "messages_processed_24h": messages_processed,
            "messages_total": messages_total,
            "uptime": uptime_str,
            "last_update": datetime.now().isoformat(),
            "status": "operational"
        }
    except Exception as e:
        logger.error(f"Stats error: {e}")
        return {
            "messages_processed_24h": 0,
            "messages_total": 0,
            "uptime": "Unknown",
            "last_update": datetime.now().isoformat(),
            "error": str(e)
        }

@app.get("/logs")
def get_logs(limit: int = 50):
    """Get recent bot logs"""
    try:
        result = subprocess.run(
            ["journalctl", "-u", "telegram-bot", "-n", str(limit), "--no-pager", "-o", "json"],
            capture_output=True, text=True
        )
        
        import json
        logs = []
        for line in result.stdout.strip().split('\n'):
            if line:
                try:
                    log_entry = json.loads(line)
                    logs.append({
                        "timestamp": log_entry.get("__REALTIME_TIMESTAMP", "Unknown"),
                        "message": log_entry.get("MESSAGE", ""),
                        "priority": log_entry.get("PRIORITY", "6")
                    })
                except:
                    pass
        
        return {"logs": logs[::-1]}  # Reverse to show newest first
    except Exception as e:
        logger.error(f"Logs error: {e}")
        return {"logs": [], "error": str(e)}

@app.get("/recent-messages")
def get_recent_messages(limit: int = 10):
    """Get recently processed messages"""
    try:
        import sqlite3
        conn = sqlite3.connect(db.db_path)
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT telegram_msg_id, channel_id, timestamp FROM processed_messages ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        )
        messages = [
            {
                "message_id": row[0],
                "channel_id": row[1],
                "timestamp": row[2],
                "status": "processed"
            }
            for row in cursor.fetchall()
        ]
        
        conn.close()
        return {"messages": messages}
    except Exception as e:
        logger.error(f"Recent messages error: {e}")
        return {"messages": [], "error": str(e)}

@app.get("/config")
def get_config():
    return config_manager.load_config()

@app.post("/config")
def update_config(new_config: ConfigUpdate):
    try:
        config_manager.save_config(new_config.dict())
        logger.info("Configuration updated")
        return {"message": "Config updated successfully"}
    except Exception as e:
        logger.error(f"Config update error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/restart")
def restart_bot():
    try:
        logger.info("Restarting telegram-bot service")
        subprocess.run(["systemctl", "restart", "telegram-bot"], check=True)
        return {"message": "Bot restarted successfully"}
    except Exception as e:
        logger.error(f"Restart error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to restart bot: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=80)
