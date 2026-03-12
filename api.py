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

    try:
        inv.update({"status": "running", "running": True, "done": 0, "failed": 0, "error": None})

        # Resolve target entity
        target_entity = await asyncio.wait_for(client.get_entity(target), timeout=30)
        inv["total"] = len(usernames)

        for username in usernames:
            if not inv["running"]:
                break

            # Check daily limit before each invite
            daily_done = get_daily_done(uid)
            if daily_done >= DAILY_INVITE_LIMIT:
                inv.update({
                    "status": "limit_reached",
                    "running": False,
                    "current": "",
                    "error": f"Достигнут дневной лимит {DAILY_INVITE_LIMIT} инвайтов. Попробуйте завтра."
                })
                logger.warning(f"Daily limit {DAILY_INVITE_LIMIT} reached for uid={uid}")
                return

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
                inv["done"] += 1
                increment_daily(uid)
                logger.info(f"Invited {username} -> {target} (daily: {get_daily_done(uid)}/{DAILY_INVITE_LIMIT})")
                await asyncio.sleep(delay)

            except UserAlreadyParticipantError:
                inv["done"] += 1  # already in group = success
            except PeerFloodError:
                inv.update({"status": "error", "error": "PeerFloodError — аккаунт заблокирован Telegram за спам", "running": False})
                return
            except FloodWaitError as e:
                logger.warning(f"FloodWait {e.seconds}s")
                await asyncio.sleep(e.seconds + 5)
            except (UserPrivacyRestrictedError, UserNotMutualContactError,
                    InputUserDeactivatedError, UserBannedInChannelError):
                inv["failed"] += 1
            except ChatWriteForbiddenError:
                inv.update({"status": "error", "error": "Нет прав добавлять участников в этот канал", "running": False})
                return
            except Exception as e:
                logger.warning(f"Invite {username} error: {e}")
                inv["failed"] += 1

        inv.update({"status": "done", "running": False, "current": ""})
        logger.info(f"Invite done uid={uid} done={inv['done']} failed={inv['failed']} daily={get_daily_done(uid)}")

    except asyncio.CancelledError:
        inv.update({"status": "stopped", "running": False, "current": ""})
    except Exception as e:
        logger.error(f"Invite error uid={uid}: {e}")
        inv.update({"status": "error", "error": str(e), "running": False, "current": ""})

@app.post("/api/invite/start")
async def invite_start(data: InviteRequest, user=Depends(current_user)):
    uid = user["id"]
    inv = get_invite_state(uid)

    if inv.get("running"):
        raise HTTPException(400, "Invite already running")

    # Combine usernames from parser + manual IDs
    all_users = list(data.users)  # usernames from parser
    if data.manual_ids:
        for line in data.manual_ids.splitlines():
            line = line.strip()
            if line:
                all_users.append(line)

    if not all_users:
        raise HTTPException(400, "Нет участников для инвайтинга")

    if inv.get("task") and not inv["task"].done():
        inv["task"].cancel()

    inv.update({
        "status": "starting",
        "target": data.target,
        "done": 0, "failed": 0,
        "total": len(all_users),
        "current": "",
        "error": None, "running": True,
    })

    task = asyncio.create_task(_do_invite(uid, data.target, all_users, data.delay))
    inv["task"] = task

    return {"message": f"Invite started for {len(all_users)} users"}

@app.post("/api/invite/stop")
def invite_stop(user=Depends(current_user)):
    uid = user["id"]
    inv = get_invite_state(uid)
    inv["running"] = False
    if inv.get("task") and not inv["task"].done():
        inv["task"].cancel()
    inv["status"] = "stopped"
    return {"message": "Stopped"}

@app.get("/api/invite/status")
def invite_status(user=Depends(current_user)):
    uid = user["id"]
    inv = get_invite_state(uid)
    daily_done = get_daily_done(uid)
    daily_remaining = max(0, DAILY_INVITE_LIMIT - daily_done)
    remaining_in_run = max(0, inv["total"] - inv["done"] - inv["failed"])
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
