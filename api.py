# Full FastAPI server — Iranium Pro
import subprocess, os, sys, logging, asyncio, hashlib, secrets, sqlite3, json, urllib.request
from datetime import datetime, timedelta
from pathlib import Path
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import io, csv

BASE_DIR = Path(__file__).parent
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])

USERS_DB = BASE_DIR / "users.db"

# ─── PER-USER HELPERS ───
def udir(uid): return BASE_DIR / "users" / str(uid)
def uenv(uid): return udir(uid) / ".env"
def usession(uid): return str(udir(uid) / "bot_session")

def read_uenv(uid) -> dict:
    env_file = uenv(uid)
    result = {}
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if '=' in line and not line.startswith('#'):
                k, _, v = line.partition('=')
                result[k.strip()] = v.strip()
    return result

def write_uenv(uid, data: dict):
    udir(uid).mkdir(parents=True, exist_ok=True)
    existing = read_uenv(uid)
    existing.update(data)
    lines = [f"{k}={v}" for k, v in existing.items()]
    uenv(uid).write_text('\n'.join(lines) + '\n')

# ─── INIT DB ───
def init_db():
    with sqlite3.connect(USERS_DB) as c:
        c.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL DEFAULT '',
            password_hash TEXT,
            google_id TEXT,
            avatar TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now'))
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires_at TEXT NOT NULL
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )""")
        c.commit()

init_db()

# ─── AUTH ───
bearer = HTTPBearer(auto_error=False)

def hash_pw(pw: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200000).hex()
    return f"{salt}:{h}"

def verify_pw(pw: str, hashed: str) -> bool:
    try:
        salt, h = hashed.split(':')
        return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200000).hex() == h
    except:
        return False

def get_user_by_token(token: str) -> dict:
    with sqlite3.connect(USERS_DB) as c:
        row = c.execute(
            "SELECT u.id, u.email, u.name FROM users u JOIN sessions s ON u.id=s.user_id "
            "WHERE s.token=? AND s.expires_at > datetime('now')",
            (token,)
        ).fetchone()
    return {"id": row[0], "email": row[1], "name": row[2]} if row else None

async def current_user(creds: HTTPAuthorizationCredentials = Depends(bearer)):
    if not creds:
        raise HTTPException(401, "Not authorized")
    user = get_user_by_token(creds.credentials)
    if not user:
        raise HTTPException(401, "Session expired")
    return user

def create_session(uid: int) -> str:
    token = secrets.token_hex(32)
    expires = (datetime.now() + timedelta(days=30)).isoformat()
    with sqlite3.connect(USERS_DB) as c:
        c.execute("INSERT OR REPLACE INTO sessions (token, user_id, expires_at) VALUES (?,?,?)", (token, uid, expires))
        c.commit()
    return token

# ─── MODELS ───
class RegisterReq(BaseModel):
    email: str
    password: str
    name: str = ""

class LoginReq(BaseModel):
    email: str
    password: str

class GoogleReq(BaseModel):
    credential: str

class CredentialsReq(BaseModel):
    api_id: str
    api_hash: str

class TGStartReq(BaseModel):
    phone: str

class TGVerifyReq(BaseModel):
    code: str = ""
    password: str = ""

class ParseRequest(BaseModel):
    group: str
    limit: int = 1000

class InviteRequest(BaseModel):
    target: str                  # Target group/channel to invite into
    users: list = []             # List of usernames (strings) from parser
    manual_ids: str = ""         # Newline-separated user IDs entered manually
    delay: float = 5.0
    resume: bool = False         # Resume from saved queue instead of users list

# ─── AUTH ENDPOINTS ───
@app.post("/api/auth/register")
def register(data: RegisterReq):
    with sqlite3.connect(USERS_DB) as c:
        try:
            cur = c.cursor()
            name = data.name or data.email.split('@')[0]
            cur.execute("INSERT INTO users (email, password_hash, name) VALUES (?,?,?)",
                       (data.email, hash_pw(data.password), name))
            uid = cur.lastrowid
            c.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(400, "Email already exists")

    udir(uid).mkdir(parents=True, exist_ok=True)
    token = create_session(uid)
    return {"token": token, "user": {"id": uid, "email": data.email, "name": name}}

@app.post("/api/auth/login")
def login(data: LoginReq):
    with sqlite3.connect(USERS_DB) as c:
        row = c.execute("SELECT id, password_hash, name FROM users WHERE email=?", (data.email,)).fetchone()
    if not row:
        raise HTTPException(401, "Invalid credentials")
    uid, pw_hash, name = row
    if not pw_hash or not verify_pw(data.password, pw_hash):
        raise HTTPException(401, "Invalid credentials")
    token = create_session(uid)
    return {"token": token, "user": {"id": uid, "email": data.email, "name": name}}

@app.post("/api/auth/google")
def google_login(data: GoogleReq):
    try:
        url = f"https://www.googleapis.com/oauth2/v3/tokeninfo?id_token={data.credential}"
        with urllib.request.urlopen(url, timeout=10) as resp:
            idinfo = json.loads(resp.read().decode())
    except Exception as e:
        raise HTTPException(400, f"Google token invalid: {e}")

    email = idinfo.get('email', '')
    name = idinfo.get('name', email.split('@')[0])
    google_id = idinfo.get('sub', '')

    if not email:
        raise HTTPException(400, "No email in Google token")

    with sqlite3.connect(USERS_DB) as c:
        row = c.execute("SELECT id, name FROM users WHERE email=?", (email,)).fetchone()
        if row:
            uid, existing_name = row
            name = existing_name or name
        else:
            try:
                cur = c.cursor()
                cur.execute("INSERT INTO users (email, password_hash, name, google_id) VALUES (?,?,?,?)",
                           (email, hash_pw(secrets.token_hex(16)), name, google_id))
                uid = cur.lastrowid
                c.commit()
                udir(uid).mkdir(parents=True, exist_ok=True)
            except Exception as e:
                raise HTTPException(400, f"Registration failed: {e}")

    token = create_session(uid)
    return {"token": token, "user": {"id": uid, "email": email, "name": name}}

@app.get("/api/auth/me")
def auth_me(user=Depends(current_user)):
    return {"user": user}

# ─── SETTINGS ───
@app.get("/api/app-settings")
def get_settings():
    with sqlite3.connect(USERS_DB) as c:
        rows = c.execute("SELECT key, value FROM settings").fetchall()
    return dict(rows)

@app.post("/api/app-settings")
def update_settings(data: dict, user=Depends(current_user)):
    with sqlite3.connect(USERS_DB) as c:
        for k, v in data.items():
            c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?,?)", (k, v))
        c.commit()
    return {"message": "Saved"}

# ─── CREDENTIALS ───
@app.get("/api/credentials")
def get_credentials(user=Depends(current_user)):
    env = read_uenv(user["id"])
    return {
        "api_id": env.get("TG_API_ID", ""),
        "api_hash": env.get("TG_API_HASH", ""),
    }

@app.post("/api/credentials")
def save_credentials(data: CredentialsReq, user=Depends(current_user)):
    write_uenv(user["id"], {
        "TG_API_ID": data.api_id.strip(),
        "TG_API_HASH": data.api_hash.strip(),
    })
    return {"message": "Credentials saved"}

# ─── TG AUTH STATE ───
auth_states = {}  # {uid: {client, phone, phone_code_hash, status, error, waiting_for_2fa}}

def get_auth_state(uid):
    if uid not in auth_states:
        auth_states[uid] = {
            "client": None,
            "phone": "",
            "phone_code_hash": None,
            "status": "idle",
            "error": None,
            "waiting_for_2fa": False,
        }
    return auth_states[uid]

# ─── TG AUTH ENDPOINTS ───
@app.post("/api/auth/tg/start")
async def tg_auth_start(data: TGStartReq, user=Depends(current_user)):
    from telethon import TelegramClient
    from telethon.errors import FloodWaitError, PhoneNumberInvalidError

    uid = user["id"]
    env = read_uenv(uid)
    api_id = env.get("TG_API_ID", "")
    api_hash = env.get("TG_API_HASH", "")

    if not api_id or not api_hash:
        raise HTTPException(400, "Сначала сохраните API credentials в Личном кабинете")

    state = get_auth_state(uid)

    # Disconnect existing client
    if state.get("client"):
        try:
            await state["client"].disconnect()
        except:
            pass
        state["client"] = None

    # Delete stale session
    session_path = udir(uid) / "bot_session.session"
    if session_path.exists():
        session_path.unlink()

    state.update({
        "phone": data.phone,
        "phone_code_hash": None,
        "status": "sending_code",
        "error": None,
        "waiting_for_2fa": False,
    })

    try:
        client = TelegramClient(usession(uid), int(api_id), api_hash)
        await asyncio.wait_for(client.connect(), timeout=30)
        state["client"] = client

        if await asyncio.wait_for(client.is_user_authorized(), timeout=10):
            state["status"] = "authenticated"
            me = await asyncio.wait_for(client.get_me(), timeout=15)
            tg_info = {}
            if me:
                tg_info = {
                    "tg_id": str(me.id),
                    "tg_username": me.username or "",
                    "tg_first_name": me.first_name or "",
                    "tg_last_name": me.last_name or "",
                    "tg_phone": me.phone or "",
                }
                write_uenv(uid, tg_info)
            return {"status": "already_authorized", "message": "Already authorized", **tg_info}

        result = await asyncio.wait_for(
            client.send_code_request(data.phone),
            timeout=30
        )
        state["phone_code_hash"] = result.phone_code_hash
        state["status"] = "code_sent"
        # Determine code type for frontend hint
        code_type = type(result.type).__name__ if hasattr(result, 'type') else "App"
        return {"status": "code_sent", "message": "Code sent to Telegram", "code_type": code_type}

    except FloodWaitError as e:
        state["status"] = "error"
        state["error"] = f"Flood wait: {e.seconds} seconds"
        raise HTTPException(429, f"Too many requests. Wait {e.seconds} seconds")
    except PhoneNumberInvalidError:
        state["status"] = "error"
        state["error"] = "Invalid phone number"
        raise HTTPException(400, "Invalid phone number format")
    except asyncio.TimeoutError:
        state["status"] = "error"
        state["error"] = "Timeout connecting to Telegram"
        raise HTTPException(504, "Timeout connecting to Telegram")
    except Exception as e:
        state["status"] = "error"
        state["error"] = str(e)
        raise HTTPException(500, str(e))

@app.post("/api/auth/tg/verify")
async def tg_auth_verify(data: TGVerifyReq, user=Depends(current_user)):
    from telethon.errors import SessionPasswordNeededError, PhoneCodeInvalidError, PhoneCodeExpiredError

    uid = user["id"]
    state = get_auth_state(uid)
    client = state.get("client")

    if not client:
        raise HTTPException(400, "Session not started. Call /api/auth/tg/start first")

    try:
        if state.get("waiting_for_2fa") or state.get("status") == "need_password" or (not data.code and data.password):
            # 2FA flow
            if not data.password:
                raise HTTPException(400, "Password required for 2FA")
            await asyncio.wait_for(
                client.sign_in(password=data.password),
                timeout=30
            )
        else:
            # Code verification flow
            if not data.code:
                raise HTTPException(400, "Code is required")
            try:
                await asyncio.wait_for(
                    client.sign_in(
                        phone=state["phone"],
                        code=data.code,
                        phone_code_hash=state["phone_code_hash"]
                    ),
                    timeout=30
                )
            except SessionPasswordNeededError:
                state["waiting_for_2fa"] = True
                state["status"] = "need_password"
                return {"status": "need_password", "message": "2FA password required"}

        # Success
        me = await asyncio.wait_for(client.get_me(), timeout=15)
        state["status"] = "authenticated"
        state["waiting_for_2fa"] = False

        tg_info = {}
        if me:
            tg_info = {
                "tg_id": str(me.id),
                "tg_username": me.username or "",
                "tg_first_name": me.first_name or "",
                "tg_last_name": me.last_name or "",
                "tg_phone": me.phone or "",
            }
            write_uenv(uid, tg_info)

        return {"status": "authenticated", **tg_info}

    except PhoneCodeInvalidError:
        raise HTTPException(400, "Invalid code")
    except PhoneCodeExpiredError:
        raise HTTPException(400, "Code expired. Request a new one")
    except asyncio.TimeoutError:
        raise HTTPException(504, "Timeout")
    except Exception as e:
        state["status"] = "error"
        state["error"] = str(e)
        raise HTTPException(500, str(e))

@app.get("/api/auth/tg/status")
async def tg_auth_status(user=Depends(current_user)):
    uid = user["id"]
    state = get_auth_state(uid)
    env = read_uenv(uid)

    client = state.get("client")
    is_authorized = False

    if client:
        try:
            is_authorized = await asyncio.wait_for(client.is_user_authorized(), timeout=10)
        except:
            is_authorized = False
    else:
        # Try to restore session from file
        session_path = udir(uid) / "bot_session.session"
        if session_path.exists() and env.get("TG_API_ID") and env.get("TG_API_HASH"):
            try:
                from telethon import TelegramClient
                c = TelegramClient(usession(uid), int(env["TG_API_ID"]), env["TG_API_HASH"])
                await asyncio.wait_for(c.connect(), timeout=15)
                is_authorized = await asyncio.wait_for(c.is_user_authorized(), timeout=10)
                if is_authorized:
                    state["client"] = c
                    state["status"] = "authenticated"
                    me = await asyncio.wait_for(c.get_me(), timeout=10)
                    if me:
                        write_uenv(uid, {
                            "tg_id": str(me.id),
                            "tg_username": me.username or "",
                            "tg_first_name": me.first_name or "",
                            "tg_last_name": me.last_name or "",
                            "tg_phone": me.phone or "",
                        })
                        env = read_uenv(uid)
                else:
                    await c.disconnect()
            except:
                is_authorized = False

    # Normalize status
    current_status = state.get("status", "idle")
    if is_authorized:
        current_status = "authenticated"

    return {
        "authorized": is_authorized,
        "session_exists": is_authorized,
        "status": current_status,
        "waiting_for_2fa": state.get("waiting_for_2fa", False),
        "error": state.get("error"),
        "tg_id": env.get("tg_id", ""),
        "tg_username": env.get("tg_username", ""),
        "tg_first_name": env.get("tg_first_name", ""),
        "tg_last_name": env.get("tg_last_name", ""),
        "tg_phone": env.get("tg_phone", ""),
    }

@app.post("/api/auth/tg/logout")
async def tg_auth_logout(user=Depends(current_user)):
    uid = user["id"]
    state = get_auth_state(uid)
    client = state.get("client")

    if client:
        try:
            await asyncio.wait_for(client.log_out(), timeout=15)
        except:
            pass
        try:
            await client.disconnect()
        except:
            pass
        state["client"] = None

    # Delete session file
    session_path = udir(uid) / "bot_session.session"
    if session_path.exists():
        session_path.unlink()

    write_uenv(uid, {
        "tg_id": "",
        "tg_username": "",
        "tg_first_name": "",
        "tg_last_name": "",
        "tg_phone": "",
    })

    state.update({"status": "idle", "error": None, "waiting_for_2fa": False, "phone_code_hash": None})
    return {"message": "Logged out"}

# ─── PARSE STATE ───
parse_states = {}

def get_parse_state(uid):
    if uid not in parse_states:
        parse_states[uid] = {
            "running": False,
            "status": "idle",
            "group": "",
            "members": [],
            "progress": 0,
            "total": 0,
            "error": None,
            "task": None,
        }
    return parse_states[uid]

def _user_to_member(u):
    return {
        "id": u.id,
        "username": getattr(u, 'username', '') or "",
        "first_name": getattr(u, 'first_name', '') or "",
        "last_name": getattr(u, 'last_name', '') or "",
        "phone": getattr(u, 'phone', '') or "",
        "is_bot": getattr(u, 'bot', False),
    }

async def _do_parse(uid: int, group: str, limit: int):
    from telethon.tl.types import ChannelParticipantsSearch, ChannelParticipantsRecent
    from telethon.tl.functions.channels import GetParticipantsRequest, GetFullChannelRequest

    ps = get_parse_state(uid)
    state = get_auth_state(uid)
    env = read_uenv(uid)

    client = state.get("client")

    if not client:
        api_id = env.get("TG_API_ID", "")
        api_hash = env.get("TG_API_HASH", "")
        if not api_id or not api_hash:
            ps.update({"status": "error", "error": "No API credentials", "running": False})
            return

        try:
            from telethon import TelegramClient
            client = TelegramClient(usession(uid), int(api_id), api_hash)
            await asyncio.wait_for(client.connect(), timeout=30)
            if not await asyncio.wait_for(client.is_user_authorized(), timeout=10):
                ps.update({"status": "error", "error": "Not authorized in Telegram", "running": False})
                await client.disconnect()
                return
            state["client"] = client
        except Exception as e:
            ps.update({"status": "error", "error": str(e), "running": False})
            return

    try:
        ps.update({"status": "running", "running": True, "members": [], "progress": 0, "total": 0, "error": None})

        entity = await asyncio.wait_for(client.get_entity(group), timeout=30)

        # Get real participant count
        real_total = 0
        try:
            full = await client(GetFullChannelRequest(entity))
            real_total = full.full_chat.participants_count or 0
            ps["total"] = min(real_total, limit) if real_total else limit
        except:
            pass

        members_dict = {}  # id -> member dict (deduplication)

        def add_user(u):
            if u and not getattr(u, 'bot', False) and not getattr(u, 'deleted', False):
                if u.id not in members_dict:
                    members_dict[u.id] = _user_to_member(u)
                    ps["progress"] = len(members_dict)
                    ps["members"] = list(members_dict.values())

        def update_progress(phase: str):
            ps["status"] = "running: " + phase
            logger.info(f"Parse uid={uid} {phase}: {len(members_dict)} unique so far")

        # ── Method 1: iter_participants (basic, gets admins + visible members) ──
        update_progress("basic scan")
        async for participant in client.iter_participants(entity, limit=limit):
            if not ps["running"]: break
            add_user(participant)

        # ── Method 2: Search by alphabet (Latin + Cyrillic + digits) ──
        # Only if we got few results relative to real count
        if ps["running"] and real_total > 50 and len(members_dict) < min(real_total * 0.1, limit):
            update_progress("alphabet scan")
            CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789абвгдеёжзийклмнопрстуфхцчшщыьэюя'
            for char in CHARS:
                if not ps["running"]: break
                if len(members_dict) >= limit: break
                try:
                    result = await client(GetParticipantsRequest(
                        entity,
                        filter=ChannelParticipantsSearch(q=char),
                        offset=0,
                        limit=200,
                        hash=0
                    ))
                    for u in result.users:
                        add_user(u)
                    await asyncio.sleep(0.3)
                except Exception as e:
                    logger.warning(f"Search '{char}' failed: {e}")
                    await asyncio.sleep(1)

        # ── Method 3: Message senders (fallback for privacy-restricted groups) ──
        if ps["running"] and real_total > 100 and len(members_dict) < min(real_total * 0.1, limit):
            update_progress("messages scan")
            msg_scan_limit = min(limit * 20, 50000)
            msg_count = 0
            async for msg in client.iter_messages(entity, limit=msg_scan_limit):
                if not ps["running"]: break
                if len(members_dict) >= limit: break
                msg_count += 1
                if msg.sender_id and msg.sender_id > 0 and msg.sender:
                    add_user(msg.sender)
            logger.info(f"Parse uid={uid} scanned {msg_count} messages")

        final = list(members_dict.values())[:limit]
        ps.update({
            "status": "done",
            "running": False,
            "members": final,
            "progress": len(final),
            "total": max(real_total, len(final)),
        })
        logger.info(f"Parse done uid={uid} group={group} found={len(final)} real_total={real_total}")

    except asyncio.CancelledError:
        ps.update({"status": "stopped", "running": False})
    except Exception as e:
        logger.error(f"Parse error uid={uid}: {e}")
        ps.update({"status": "error", "error": str(e), "running": False})

@app.post("/api/parse/start")
async def parse_start(data: ParseRequest, user=Depends(current_user)):
    uid = user["id"]
    ps = get_parse_state(uid)

    if ps.get("running"):
        raise HTTPException(400, "Parse already running")

    if ps.get("task") and not ps["task"].done():
        ps["task"].cancel()

    ps.update({"status": "starting", "group": data.group, "progress": 0,
               "total": 0, "members": [], "error": None, "running": True})

    task = asyncio.create_task(_do_parse(uid, data.group, data.limit))
    ps["task"] = task

    return {"message": "Parse started", "group": data.group}

@app.post("/api/parse/stop")
def parse_stop(user=Depends(current_user)):
    uid = user["id"]
    ps = get_parse_state(uid)
    ps["running"] = False
    if ps.get("task") and not ps["task"].done():
        ps["task"].cancel()
    ps["status"] = "stopped"
    return {"message": "Stopped"}

@app.get("/api/parse/status")
def parse_status(user=Depends(current_user)):
    ps = get_parse_state(user["id"])
    return {
        "status": ps["status"],
        "group": ps["group"],
        "progress": ps["progress"],
        "total": ps["total"],
        "count": len(ps["members"]),
        "error": ps["error"],
    }

@app.get("/api/parse/results")
def parse_results(user=Depends(current_user)):
    ps = get_parse_state(user["id"])
    return {"members": ps["members"], "count": len(ps["members"])}

@app.get("/api/parse/export")
def parse_export(user=Depends(current_user)):
    ps = get_parse_state(user["id"])
    if not ps["members"]:
        raise HTTPException(404, "No data to export")
    output = io.StringIO()
    w = csv.DictWriter(output, fieldnames=["id", "username", "first_name", "last_name", "phone", "is_bot"])
    w.writeheader()
    w.writerows(ps["members"])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=members.csv"}
    )

# ─── INVITE DAILY LIMIT ───
DAILY_INVITE_LIMIT = 40  # Safe conservative Telegram limit per day

def udaily(uid):
    return udir(uid) / "invite_daily.json"

def read_daily_stats(uid) -> dict:
    f = udaily(uid)
    today = datetime.now().strftime("%Y-%m-%d")
    if f.exists():
        try:
            data = json.loads(f.read_text())
            if data.get("date") == today:
                return data
        except:
            pass
    return {"date": today, "count": 0}

def increment_daily(uid):
    stats = read_daily_stats(uid)
    stats["count"] += 1
    udir(uid).mkdir(parents=True, exist_ok=True)
    udaily(uid).write_text(json.dumps(stats))
    return stats["count"]

def get_daily_done(uid) -> int:
    return read_daily_stats(uid).get("count", 0)

# ─── INVITE QUEUE PERSISTENCE ───
def uqueue(uid):
    return udir(uid) / "invite_queue.json"

def save_invite_queue(uid: int, target: str, remaining: list, failed: list, delay: float):
    """Save remaining queue so invite can be resumed later."""
    udir(uid).mkdir(parents=True, exist_ok=True)
    uqueue(uid).write_text(json.dumps({
        "target": target,
        "queue": remaining,
        "failed": failed,
        "delay": delay,
        "saved_at": datetime.now().isoformat(),
    }, ensure_ascii=False))

def load_invite_queue(uid: int) -> dict | None:
    f = uqueue(uid)
    if f.exists():
        try:
            return json.loads(f.read_text())
        except:
            pass
    return None

def clear_invite_queue(uid: int):
    f = uqueue(uid)
    if f.exists():
        f.unlink()

# ─── INVITE STATE ───
invite_states = {}

def get_invite_state(uid):
    if uid not in invite_states:
        invite_states[uid] = {
            "running": False,
            "status": "idle",
            "target": "",
            "done": 0,
            "failed": 0,
            "total": 0,
            "current": "",
            "error": None,
            "task": None,
        }
    return invite_states[uid]

async def _do_invite(uid: int, target: str, usernames: list, delay: float):
    from telethon.tl.functions.channels import InviteToChannelRequest
    from telethon.errors import (FloodWaitError, UserPrivacyRestrictedError,
                                  UserNotMutualContactError, PeerFloodError,
                                  UserAlreadyParticipantError, InputUserDeactivatedError,
                                  UserBannedInChannelError, ChatWriteForbiddenError)

    inv = get_invite_state(uid)
    state = get_auth_state(uid)
    env = read_uenv(uid)

    client = state.get("client")
    if not client:
        api_id = env.get("TG_API_ID", "")
        api_hash = env.get("TG_API_HASH", "")
        if not api_id or not api_hash:
            inv.update({"status": "error", "error": "No API credentials", "running": False})
            return
        try:
            from telethon import TelegramClient
            client = TelegramClient(usession(uid), int(api_id), api_hash)
            await asyncio.wait_for(client.connect(), timeout=30)
            if not await asyncio.wait_for(client.is_user_authorized(), timeout=10):
                inv.update({"status": "error", "error": "Not authorized in Telegram", "running": False})
                await client.disconnect()
                return
            state["client"] = client
        except Exception as e:
            inv.update({"status": "error", "error": str(e), "running": False})
            return

    # Work on a mutable copy — we pop items as we go so we always know what's left
    remaining = list(usernames)
    failed_list = []

    try:
        inv.update({"status": "running", "running": True, "done": 0, "failed": 0, "error": None})

        # Resolve target entity
        target_entity = await asyncio.wait_for(client.get_entity(target), timeout=30)
        inv["total"] = len(remaining)

        while remaining:
            if not inv["running"]:
                # Paused/stopped — save what's left so it can be resumed
                save_invite_queue(uid, target, remaining, failed_list, delay)
                inv.update({"status": "paused", "running": False, "current": ""})
                logger.info(f"Invite paused uid={uid}: {len(remaining)} left in queue")
                return

            # Check daily limit before each invite
            daily_done = get_daily_done(uid)
            if daily_done >= DAILY_INVITE_LIMIT:
                save_invite_queue(uid, target, remaining, failed_list, delay)
                inv.update({
                    "status": "limit_reached",
                    "running": False,
                    "current": "",
                    "error": f"Достигнут дневной лимит {DAILY_INVITE_LIMIT} инвайтов. Попробуйте завтра."
                })
                logger.warning(f"Daily limit reached uid={uid}, {len(remaining)} users saved to queue")
                return

            username = remaining[0]  # peek
            inv["current"] = str(username)

            try:
                # Resolve user entity (username or numeric ID)
                if str(username).lstrip('-').isdigit():
                    user_entity = await asyncio.wait_for(
                        client.get_entity(int(username)), timeout=15)
                else:
                    user_entity = await asyncio.wait_for(
                        client.get_entity(username), timeout=15)

                await asyncio.wait_for(
                    client(InviteToChannelRequest(target_entity, [user_entity])),
                    timeout=30
                )
                remaining.pop(0)  # success — remove from queue
                inv["done"] += 1
                increment_daily(uid)
                inv["total"] = inv["done"] + inv["failed"] + len(remaining)
                logger.info(f"Invited {username} -> {target} (daily: {get_daily_done(uid)}/{DAILY_INVITE_LIMIT})")
                await asyncio.sleep(delay)

            except UserAlreadyParticipantError:
                remaining.pop(0)
                inv["done"] += 1  # already in group = counts as success

            except PeerFloodError:
                save_invite_queue(uid, target, remaining, failed_list, delay)
                inv.update({"status": "error", "running": False, "current": "",
                            "error": "PeerFloodError — аккаунт ограничен Telegram. Очередь сохранена."})
                return

            except FloodWaitError as e:
                logger.warning(f"FloodWait {e.seconds}s for uid={uid}")
                inv["status"] = f"flood_wait ({e.seconds}s)"
                await asyncio.sleep(e.seconds + 5)
                # Don't remove from remaining — retry after wait

            except (UserPrivacyRestrictedError, UserNotMutualContactError,
                    InputUserDeactivatedError, UserBannedInChannelError):
                remaining.pop(0)
                failed_list.append(str(username))
                inv["failed"] += 1

            except ChatWriteForbiddenError:
                save_invite_queue(uid, target, remaining, failed_list, delay)
                inv.update({"status": "error", "running": False, "current": "",
                            "error": "Нет прав добавлять участников в этот канал. Очередь сохранена."})
                return

            except Exception as e:
                logger.warning(f"Invite {username} error: {e}")
                remaining.pop(0)
                failed_list.append(str(username))
                inv["failed"] += 1

        # All done — clear saved queue
        clear_invite_queue(uid)
        inv.update({"status": "done", "running": False, "current": ""})
        logger.info(f"Invite done uid={uid} done={inv['done']} failed={inv['failed']} daily={get_daily_done(uid)}")

    except asyncio.CancelledError:
        # Also save queue on task cancellation
        if remaining:
            save_invite_queue(uid, target, remaining, failed_list, delay)
            logger.info(f"Invite cancelled uid={uid}: {len(remaining)} saved to queue")
        inv.update({"status": "paused", "running": False, "current": ""})
    except Exception as e:
        if remaining:
            save_invite_queue(uid, target, remaining, failed_list, delay)
        logger.error(f"Invite error uid={uid}: {e}")
        inv.update({"status": "error", "error": str(e), "running": False, "current": ""})

@app.post("/api/invite/start")
async def invite_start(data: InviteRequest, user=Depends(current_user)):
    uid = user["id"]
    inv = get_invite_state(uid)

    if inv.get("running"):
        raise HTTPException(400, "Invite already running")

    if inv.get("task") and not inv["task"].done():
        inv["task"].cancel()

    if data.resume:
        # Resume from saved queue
        saved = load_invite_queue(uid)
        if not saved:
            raise HTTPException(400, "Нет сохранённой очереди для возобновления")
        target = saved["target"]
        all_users = saved.get("queue", [])
        delay = saved.get("delay", data.delay)
        if not all_users:
            clear_invite_queue(uid)
            raise HTTPException(400, "Сохранённая очередь пуста")
        logger.info(f"Resuming invite uid={uid} target={target} queue={len(all_users)}")
    else:
        # Normal start: combine usernames from parser + manual IDs
        target = data.target
        all_users = list(data.users)
        if data.manual_ids:
            for line in data.manual_ids.splitlines():
                line = line.strip()
                if line:
                    all_users.append(line)
        delay = data.delay

    if not all_users:
        raise HTTPException(400, "Нет участников для инвайтинга")

    if not target:
        raise HTTPException(400, "Не указан целевой канал")

    inv.update({
        "status": "starting",
        "target": target,
        "done": 0, "failed": 0,
        "total": len(all_users),
        "current": "",
        "error": None, "running": True,
    })

    task = asyncio.create_task(_do_invite(uid, target, all_users, delay))
    inv["task"] = task

    action = "возобновлён" if data.resume else "запущен"
    return {"message": f"Инвайтинг {action} для {len(all_users)} участников"}

@app.post("/api/invite/stop")
def invite_stop(user=Depends(current_user)):
    uid = user["id"]
    inv = get_invite_state(uid)
    inv["running"] = False
    if inv.get("task") and not inv["task"].done():
        inv["task"].cancel()
    # Status will be set to "paused" by _do_invite when it detects running=False
    # Set it here too in case the task was already done
    if inv["status"] not in ("done", "error"):
        inv["status"] = "paused"
    return {"message": "Paused"}

@app.get("/api/invite/queue")
def invite_queue_info(user=Depends(current_user)):
    """Check if there's a saved invite queue to resume."""
    uid = user["id"]
    saved = load_invite_queue(uid)
    if saved:
        return {
            "has_queue": True,
            "queue_size": len(saved.get("queue", [])),
            "queue_target": saved.get("target", ""),
            "saved_at": saved.get("saved_at", ""),
            "delay": saved.get("delay", 5.0),
        }
    return {"has_queue": False, "queue_size": 0, "queue_target": "", "saved_at": "", "delay": 5.0}

@app.delete("/api/invite/queue")
def invite_queue_clear(user=Depends(current_user)):
    """Discard a saved invite queue (start fresh)."""
    uid = user["id"]
    clear_invite_queue(uid)
    return {"message": "Queue cleared"}

@app.get("/api/invite/status")
def invite_status(user=Depends(current_user)):
    uid = user["id"]
    inv = get_invite_state(uid)
    daily_done = get_daily_done(uid)
    daily_remaining = max(0, DAILY_INVITE_LIMIT - daily_done)
    remaining_in_run = max(0, inv["total"] - inv["done"] - inv["failed"])
    saved = load_invite_queue(uid)
    return {
        "status": inv["status"],
        "target": inv["target"],
        "done": inv["done"],
        "failed": inv["failed"],
        "total": inv["total"],
        "remaining": remaining_in_run,
        "current": inv["current"],
        "error": inv["error"],
        "daily_done": daily_done,
        "daily_limit": DAILY_INVITE_LIMIT,
        "daily_remaining": daily_remaining,
        "has_queue": bool(saved),
        "queue_size": len(saved.get("queue", [])) if saved else 0,
        "queue_target": saved.get("target", "") if saved else "",
    }

# ─── AUTOFILL HELPERS ───
def uautofill_config(uid): return udir(uid) / "autofill_config.json"
def uautofill_state(uid):  return udir(uid) / "autofill_state.json"

def read_autofill_config(uid) -> dict:
    f = uautofill_config(uid)
    if f.exists():
        try: return json.loads(f.read_text())
        except: pass
    return {"sources": [], "target": "", "translate": False, "rules": [], "check_interval": 5, "quick_rules": {}}

def write_autofill_config(uid, data: dict):
    udir(uid).mkdir(parents=True, exist_ok=True)
    uautofill_config(uid).write_text(json.dumps(data, ensure_ascii=False, indent=2))

def read_autofill_last_ids(uid) -> dict:
    f = uautofill_state(uid)
    if f.exists():
        try: return json.loads(f.read_text()).get("last_ids", {})
        except: pass
    return {}

def write_autofill_last_ids(uid, last_ids: dict):
    udir(uid).mkdir(parents=True, exist_ok=True)
    uautofill_state(uid).write_text(json.dumps({"last_ids": last_ids}, ensure_ascii=False))

def translate_text(text: str, target_lang: str = "ru") -> str:
    if not text or not text.strip(): return text
    try:
        import urllib.parse
        url = ("https://translate.googleapis.com/translate_a/single"
               f"?client=gtx&sl=auto&tl={target_lang}&dt=t&q={urllib.parse.quote(text)}")
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode())
            return ''.join([item[0] for item in result[0] if item[0]])
    except Exception as e:
        logger.warning(f"Translation failed: {e}")
        return text

def apply_autofill_rules(text: str, rules: list) -> str:
    import re
    for rule in rules:
        try:
            pattern = rule.get("regex", "")
            replacement = rule.get("replacement", "")
            if pattern:
                text = re.sub(pattern, replacement, text)
        except re.error as e:
            logger.warning(f"Invalid regex '{pattern}': {e}")
    return text

def apply_quick_rules(text: str, quick_rules: dict) -> tuple:
    """Apply preset quick cleanup rules. Returns (cleaned_text, should_skip)."""
    import re
    if not text:
        return text, False

    # ── Rule 3: Ads filter — skip post if it contains ad words, strip referral tails ──
    if quick_rules.get("ads"):
        ad_pattern = (r'\b(реклам[аеуыийь]?|рекл\.|промо|promo|партнёр[а-я]*|партнер[а-я]*'
                      r'|advertisement|sponsored|affiliate)\b')
        if re.search(ad_pattern, text, re.IGNORECASE):
            return text, True  # Skip entire post
        # Strip referral/UTM query params from any URL in the text
        text = re.sub(
            r'(?<=[?&])(ref|referral|utm_\w+|aff|affiliate|promo|r)=[^&\s#]*(&?)',
            '', text)
        # Clean up dangling ? or & after stripping
        text = re.sub(r'\?(?=[\s\n]|$)', '', text)
        text = re.sub(r'&(?=[\s\n]|$)', '', text)

    # ── Rule 2: Remove ALL links (superset of rule 1) ──
    if quick_rules.get("all_links"):
        text = re.sub(r'https?://\S+', '', text)
        text = re.sub(r'ftp://\S+', '', text)
        text = re.sub(r'www\.\S+', '', text)

    # ── Rule 1: Remove only Telegram links and @mentions ──
    elif quick_rules.get("tg_links"):
        text = re.sub(r'https?://t\.me\S*', '', text)
        text = re.sub(r'https?://telegram\.(?:me|dog|org)\S*', '', text)
        text = re.sub(r'tg://\S+', '', text)
        # @username — only if it looks like a TG handle (letters/digits/underscore, 5+ chars)
        text = re.sub(r'@[a-zA-Z][a-zA-Z0-9_]{4,}', '', text)

    # Clean up extra whitespace left after removals
    text = re.sub(r'\n{3,}', '\n\n', text)
    text = re.sub(r' {2,}', ' ', text)
    text = text.strip()

    return text, False

# ─── AUTOFILL STATE ───
autofill_states = {}

def get_autofill_state(uid):
    if uid not in autofill_states:
        autofill_states[uid] = {
            "running": False, "status": "idle",
            "forwarded": 0, "error": None,
            "last_activity": None, "current_source": "",
            "task": None,
        }
    return autofill_states[uid]

async def _do_autofill(uid: int):
    from telethon.errors import FloodWaitError
    af = get_autofill_state(uid)
    state = get_auth_state(uid)
    env = read_uenv(uid)

    client = state.get("client")
    if not client:
        api_id = env.get("TG_API_ID", "")
        api_hash = env.get("TG_API_HASH", "")
        if not api_id or not api_hash:
            af.update({"status": "error", "error": "Нет API credentials", "running": False})
            return
        try:
            from telethon import TelegramClient
            client = TelegramClient(usession(uid), int(api_id), api_hash)
            await asyncio.wait_for(client.connect(), timeout=30)
            if not await asyncio.wait_for(client.is_user_authorized(), timeout=10):
                af.update({"status": "error", "error": "Не авторизован в Telegram", "running": False})
                await client.disconnect()
                return
            state["client"] = client
        except Exception as e:
            af.update({"status": "error", "error": str(e), "running": False})
            return

    config = read_autofill_config(uid)
    sources = config.get("sources", [])
    target = config.get("target", "")
    do_translate = config.get("translate", False)
    rules = config.get("rules", [])
    check_interval = max(1, int(config.get("check_interval", 5))) * 60  # minutes → seconds

    # Init last_ids for new sources (remember where we are so we don't re-forward old posts)
    last_ids = read_autofill_last_ids(uid)
    for source in sources:
        if source not in last_ids:
            try:
                entity = await asyncio.wait_for(client.get_entity(source), timeout=15)
                msgs = await client.get_messages(entity, limit=1)
                last_ids[source] = msgs[0].id if msgs else 0
                logger.info(f"Autofill init {source}: last_id={last_ids[source]}")
            except Exception as e:
                logger.warning(f"Could not init source {source}: {e}")
                last_ids[source] = 0
    write_autofill_last_ids(uid, last_ids)

    af.update({"status": "running", "running": True, "error": None})
    logger.info(f"Autofill started uid={uid} sources={sources} target={target} interval={check_interval}s")

    try:
        while af["running"]:
            # Reload config each cycle so live edits take effect
            config = read_autofill_config(uid)
            sources = config.get("sources", [])
            target = config.get("target", "")
            do_translate = config.get("translate", False)
            rules = config.get("rules", [])
            quick_rules = config.get("quick_rules", {})
            check_interval = max(1, int(config.get("check_interval", 5))) * 60

            if not sources or not target:
                af.update({"status": "error", "error": "Конфиг пуст — остановлено", "running": False})
                return

            for source in sources:
                if not af["running"]: break
                af["current_source"] = source
                try:
                    src_entity = await asyncio.wait_for(client.get_entity(source), timeout=15)
                    tgt_entity = await asyncio.wait_for(client.get_entity(target), timeout=15)
                    last_id = last_ids.get(source, 0)

                    new_msgs = []
                    async for msg in client.iter_messages(src_entity, min_id=last_id, limit=100):
                        if not msg.grouped_id:  # skip album parts for simplicity
                            new_msgs.append(msg)
                    new_msgs.reverse()  # oldest first

                    for msg in new_msgs:
                        if not af["running"]: break
                        try:
                            text = msg.text or ""
                            modified = bool(rules or do_translate or quick_rules)

                            # ── Quick rules (TG links / all links / ads filter) ──
                            should_skip = False
                            if quick_rules:
                                text, should_skip = apply_quick_rules(text, quick_rules)

                            if should_skip:
                                last_ids[source] = msg.id
                                write_autofill_last_ids(uid, last_ids)
                                logger.info(f"Autofill skipped ad post id={msg.id} from {source}")
                                continue

                            # ── Custom regex rules ──
                            if rules and text:
                                text = apply_autofill_rules(text, rules)

                            # ── Translation ──
                            if do_translate and text:
                                text = await asyncio.get_event_loop().run_in_executor(
                                    None, translate_text, text)

                            # Skip text-only posts that became empty after cleaning
                            if not text and not msg.media:
                                last_ids[source] = msg.id
                                write_autofill_last_ids(uid, last_ids)
                                continue

                            # ── Forward / send ──
                            if msg.media and not modified:
                                await asyncio.wait_for(
                                    client.forward_messages(tgt_entity, msg, src_entity), timeout=30)
                            elif msg.media:
                                await asyncio.wait_for(
                                    client.send_file(tgt_entity, msg.media, caption=text or None), timeout=30)
                            elif text:
                                await asyncio.wait_for(
                                    client.send_message(tgt_entity, text), timeout=30)

                            last_ids[source] = msg.id
                            af["forwarded"] += 1
                            af["last_activity"] = datetime.now().strftime("%d.%m %H:%M:%S")
                            write_autofill_last_ids(uid, last_ids)
                            await asyncio.sleep(2)

                        except FloodWaitError as e:
                            logger.warning(f"Autofill FloodWait {e.seconds}s uid={uid}")
                            await asyncio.sleep(e.seconds + 5)
                        except Exception as e:
                            logger.warning(f"Autofill msg error uid={uid}: {e}")
                            last_ids[source] = msg.id
                            write_autofill_last_ids(uid, last_ids)

                    if new_msgs:
                        logger.info(f"Autofill uid={uid}: forwarded {len(new_msgs)} from {source}")

                except Exception as e:
                    logger.warning(f"Autofill source {source} error uid={uid}: {e}")

            af["current_source"] = ""
            af["status"] = "running"

            # Wait for next check interval, second by second so we can stop cleanly
            for _ in range(check_interval):
                if not af["running"]: break
                await asyncio.sleep(1)

    except asyncio.CancelledError:
        af.update({"status": "stopped", "running": False, "current_source": ""})
    except Exception as e:
        logger.error(f"Autofill fatal error uid={uid}: {e}")
        af.update({"status": "error", "error": str(e), "running": False, "current_source": ""})

    logger.info(f"Autofill stopped uid={uid} forwarded={af['forwarded']}")

# ─── AUTOFILL MODEL ───
class AutofillConfigReq(BaseModel):
    sources: list = []
    target: str = ""
    translate: bool = False
    rules: list = []
    check_interval: int = 5  # minutes
    quick_rules: dict = {}   # {tg_links, all_links, ads}

# ─── AUTOFILL ENDPOINTS ───
@app.get("/api/autofill/config")
def get_autofill_config_endpoint(user=Depends(current_user)):
    return read_autofill_config(user["id"])

@app.post("/api/autofill/config")
def save_autofill_config_endpoint(data: AutofillConfigReq, user=Depends(current_user)):
    write_autofill_config(user["id"], data.model_dump())
    return {"message": "Конфиг сохранён"}

@app.post("/api/autofill/start")
async def autofill_start(user=Depends(current_user)):
    uid = user["id"]
    af = get_autofill_state(uid)
    if af.get("running"):
        raise HTTPException(400, "Автонаполнение уже запущено")
    config = read_autofill_config(uid)
    if not config.get("sources"):
        raise HTTPException(400, "Добавьте хотя бы один источник")
    if not config.get("target"):
        raise HTTPException(400, "Укажите целевой канал")
    if af.get("task") and not af["task"].done():
        af["task"].cancel()
    af.update({"status": "starting", "running": True, "forwarded": 0, "error": None})
    task = asyncio.create_task(_do_autofill(uid))
    af["task"] = task
    return {"message": "Автонаполнение запущено"}

@app.post("/api/autofill/stop")
def autofill_stop(user=Depends(current_user)):
    uid = user["id"]
    af = get_autofill_state(uid)
    af["running"] = False
    if af.get("task") and not af["task"].done():
        af["task"].cancel()
    af["status"] = "stopped"
    return {"message": "Остановлено"}

@app.get("/api/autofill/status")
def autofill_status_endpoint(user=Depends(current_user)):
    uid = user["id"]
    af = get_autofill_state(uid)
    return {
        "status": af["status"],
        "running": af["running"],
        "forwarded": af["forwarded"],
        "error": af["error"],
        "last_activity": af["last_activity"],
        "current_source": af.get("current_source", ""),
    }

# ─── HTML ───
@app.get("/")
async def serve_index():
    html_path = BASE_DIR / "index.html"
    if html_path.exists():
        with open(html_path, 'r', encoding='utf-8') as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>Not found</h1>", status_code=404)

@app.get("/api/health")
def health():
    return {"status": "healthy"}
