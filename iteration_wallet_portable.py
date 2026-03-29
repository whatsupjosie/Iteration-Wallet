"""
iteration_wallet_portable.py — Standalone Iteration Wallet Server
═════════════════════════════════════════════════════════════════
Run this file directly to get a standalone file protection vault
without PubCast. Works on any system with Python 3.10+.

Usage:
    python iteration_wallet_portable.py
    → Opens http://localhost:8765

Features:
    - OS-level file immutability (chflags/chattr/icacls)
    - Shadow backup with auto-restore
    - Three-step deletion: OPEN → REMOVE → DELETE
    - Server-side keystroke validation
    - Hash-chain audit log
    - Project cradle management
    - Version promotion with archival

Rear View Foresight LLC — Feic Mo Chroí — 2026-03-24
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import uuid
from pathlib import Path

# Add parent directory to path so we can import vault engine
# Works both standalone and when imported from PubCast
_this_dir = Path(__file__).parent
if (_this_dir / "modules").exists():
    sys.path.insert(0, str(_this_dir))
elif (_this_dir.parent / "modules").exists():
    sys.path.insert(0, str(_this_dir.parent))

try:
    from modules.vault_engine_hardened import VaultEngine, CommandEnforcer
except ImportError:
    # Standalone mode — vault engine is in same directory
    from vault_engine_hardened import VaultEngine, CommandEnforcer

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

# ─── Config ────────────────────────────────────────────────────────────────────

DEFAULT_VAULT_ROOT = Path.home() / ".iteration_wallet" / "vault"
PORT = int(os.getenv("IW_PORT", "8765"))
HOST = os.getenv("IW_HOST", "127.0.0.1")

# ─── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(title="Iteration Wallet", version="2.0.0",
              description="Hardened file protection vault")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
                   allow_headers=["*"])

vault = VaultEngine(str(DEFAULT_VAULT_ROOT))

# ─── Inline UI ─────────────────────────────────────────────────────────────────

INLINE_UI = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Iteration Wallet</title>
<link href="https://fonts.googleapis.com/css2?family=Cinzel:wght@400;700;900&family=Courier+Prime:wght@400;700&display=swap" rel="stylesheet">
<style>
:root{--bg:#0a0805;--panel:#12100a;--border:#2a2518;--brass:#d4a84b;--brass-dim:#7a5a20;--teal:#6dd6c7;--cream:#f0e8d8;--cream-dim:#8a8070;--red:#ff3333;--green:#33cc66}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--cream);font-family:'Courier Prime',monospace;min-height:100vh;padding:24px;
  background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 400 400' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.6' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='.04'/%3E%3C/svg%3E"),radial-gradient(ellipse at 50% 30%,#141210,var(--bg));background-size:300px 300px,100% 100%}
.wrap{max-width:700px;margin:0 auto}
h1{font-family:'Cinzel',serif;font-size:1.6rem;font-weight:900;letter-spacing:4px;color:var(--brass);text-align:center;margin-bottom:4px}
.sub{text-align:center;font-size:.55rem;letter-spacing:3px;color:var(--teal);opacity:.7;margin-bottom:24px}
.card{background:var(--panel);border:1px solid var(--border);padding:16px;margin-bottom:12px}
.card-title{font-family:'Cinzel',serif;font-size:.65rem;font-weight:700;letter-spacing:2px;color:var(--brass-dim);margin-bottom:10px}
.stat{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid rgba(212,168,75,.06);font-size:.75rem}
.stat-label{color:var(--cream-dim)}.stat-value{color:var(--cream);font-weight:700}
.btn{padding:8px 18px;border:1px solid var(--border);background:var(--panel);color:var(--cream);font-family:'Cinzel',serif;font-size:.6rem;font-weight:700;letter-spacing:2px;cursor:pointer;transition:all .15s}
.btn:hover{border-color:var(--brass)}.btn.p{border-color:var(--teal);color:var(--teal)}.btn.d{border-color:var(--red);color:var(--red)}
.input{width:100%;padding:8px 10px;background:rgba(0,0,0,.3);border:1px solid var(--border);color:var(--cream);font-family:'Courier Prime',monospace;font-size:.75rem;outline:none;margin-bottom:8px}
.input:focus{border-color:var(--teal)}
.log{max-height:200px;overflow-y:auto;font-size:.6rem;line-height:1.6;color:var(--cream-dim)}
.log-entry{padding:4px 0;border-bottom:1px solid rgba(212,168,75,.04)}
.lock-indicator{text-align:center;padding:12px;font-family:'Cinzel',serif;font-size:.8rem;font-weight:700;letter-spacing:2px}
.lock-indicator.locked{color:var(--red)}.lock-indicator.open{color:var(--green)}
#status{margin-bottom:16px}
.file-list{max-height:250px;overflow-y:auto}
.file-row{display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid rgba(212,168,75,.04);font-size:.7rem}
.file-name{color:var(--cream);flex:1}.file-status{color:var(--teal);font-size:.6rem;margin-left:8px}
</style>
</head>
<body>
<div class="wrap">
<h1>ITERATION WALLET</h1>
<div class="sub">◆ hardened file protection ◆</div>

<div id="status"></div>

<div class="card">
<div class="card-title">◆ Vault Control ◆</div>
<div class="lock-indicator" id="lockState">LOCKED</div>
<div style="display:flex;gap:8px;justify-content:center;margin-top:8px">
<button class="btn p" onclick="openVault()">OPEN VAULT</button>
<button class="btn" onclick="lockVault()">LOCK</button>
</div>
<div style="margin-top:12px">
<input class="input" id="cmdInput" placeholder="Type command here (OPEN / REMOVE / DELETE)..." onkeydown="handleKey(event)">
</div>
</div>

<div class="card">
<div class="card-title">◆ Add File ◆</div>
<input class="input" id="filePath" placeholder="Full file path...">
<input class="input" id="projName" placeholder="Project name...">
<button class="btn p" onclick="addFile()">PROTECT FILE</button>
</div>

<div class="card">
<div class="card-title">◆ Protected Files ◆</div>
<div class="file-list" id="fileList">Loading...</div>
</div>

<div class="card">
<div class="card-title">◆ Integrity ◆</div>
<div id="integrity">Loading...</div>
</div>

<div class="card">
<div class="card-title">◆ Audit Log ◆</div>
<div class="log" id="auditLog">Loading...</div>
</div>
</div>

<script>
let sid = null;
const API = '';

async function loadStatus() {
  try {
    const r = await fetch(API+'/api/status');
    const d = await r.json();
    document.getElementById('lockState').textContent = d.vault_open ? 'OPEN' : 'LOCKED';
    document.getElementById('lockState').className = 'lock-indicator ' + (d.vault_open ? 'open' : 'locked');
  } catch(e) { console.error(e); }
}

async function loadFiles() {
  try {
    const r = await fetch(API+'/api/files');
    const files = await r.json();
    const el = document.getElementById('fileList');
    if (!files.length) { el.innerHTML = '<div style="color:var(--cream-dim);font-size:.7rem">No files protected yet</div>'; return; }
    el.innerHTML = files.map(f => 
      '<div class="file-row"><span class="file-name">'+f.original_path.split('/').pop()+'</span><span class="file-status">'+f.status+'</span></div>'
    ).join('');
  } catch(e) { console.error(e); }
}

async function loadIntegrity() {
  try {
    const r = await fetch(API+'/api/integrity');
    const d = await r.json();
    document.getElementById('integrity').innerHTML = 
      '<div class="stat"><span class="stat-label">Protected</span><span class="stat-value">'+d.total_protected+'</span></div>'+
      '<div class="stat"><span class="stat-label">Intact</span><span class="stat-value">'+d.intact+'</span></div>'+
      '<div class="stat"><span class="stat-label">Shadow OK</span><span class="stat-value">'+d.shadow_intact+'</span></div>'+
      '<div class="stat"><span class="stat-label">Healthy</span><span class="stat-value">'+(d.healthy?'✓':'✗')+'</span></div>';
  } catch(e) { console.error(e); }
}

async function loadLog() {
  try {
    const r = await fetch(API+'/api/events');
    const events = await r.json();
    document.getElementById('auditLog').innerHTML = events.slice(0,20).map(e =>
      '<div class="log-entry">'+new Date(e.timestamp).toLocaleTimeString()+' ['+e.event_type+'] '+e.description+'</div>'
    ).join('');
  } catch(e) { console.error(e); }
}

async function startSession() {
  sid = 'ses_'+Math.random().toString(36).slice(2,10);
  await fetch(API+'/api/enforcer/start', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({session_id:sid})});
}

async function handleKey(e) {
  if (!sid) await startSession();
  if (e.key === 'Enter') return;
  await fetch(API+'/api/enforcer/keystroke', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({session_id:sid, char:e.key})});
}

async function openVault() {
  if (!sid) await startSession();
  const cmd = document.getElementById('cmdInput').value.trim();
  if (cmd !== 'OPEN') { alert('Type OPEN in the command box first'); return; }
  const r = await fetch(API+'/api/vault/open', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({session_id:sid})});
  const d = await r.json();
  alert(d.message);
  sid = null;
  document.getElementById('cmdInput').value = '';
  loadStatus();
}

async function lockVault() {
  await fetch(API+'/api/vault/lock', {method:'POST'});
  loadStatus();
}

async function addFile() {
  const path = document.getElementById('filePath').value.trim();
  const proj = document.getElementById('projName').value.trim();
  if (!path || !proj) { alert('File path and project name required'); return; }
  const r = await fetch(API+'/api/files', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({source_path:path, project_name:proj})});
  const d = await r.json();
  alert(d.message);
  loadFiles();
  loadIntegrity();
  document.getElementById('filePath').value = '';
}

loadStatus(); loadFiles(); loadIntegrity(); loadLog();
setInterval(loadStatus, 5000);
setInterval(loadIntegrity, 10000);
</script>
</body>
</html>"""

@app.get("/")
async def index():
    return HTMLResponse(INLINE_UI)

# ─── Vault API (mirrors pubcast_vault routes) ─────────────────────────────────

@app.get("/api/status")
async def status():
    return {"vault_open": vault.is_open(), "vault_root": str(vault.vault_root)}

@app.post("/api/enforcer/start")
async def start_session(request: Request):
    body = await request.json()
    vault.enforcer.start_session(body.get("session_id", ""))
    return {"ok": True}

@app.post("/api/enforcer/keystroke")
async def keystroke(request: Request):
    body = await request.json()
    ok = vault.enforcer.record_keystroke(body.get("session_id", ""), body.get("char", ""))
    return {"ok": ok}

@app.post("/api/vault/open")
async def open_vault(request: Request):
    body = await request.json()
    ok, msg = vault.open_vault(body.get("session_id", ""))
    return {"ok": ok, "message": msg}

@app.post("/api/vault/lock")
async def lock_vault():
    ok, msg = vault.lock_vault()
    return {"ok": ok, "message": msg}

@app.get("/api/files")
async def list_files(project: str = None):
    return vault.list_vault_files(project)

@app.post("/api/files")
async def add_file(request: Request):
    body = await request.json()
    source = body.get("source_path", "")
    project = body.get("project_name", "")
    if not source or not project:
        raise HTTPException(400, "source_path and project_name required")
    vault.create_cradle(project, str(Path(source).parent))
    ok, msg = vault.add_file_to_vault(source, project)
    return {"ok": ok, "message": msg}

@app.get("/api/integrity")
async def integrity():
    return vault.get_integrity_report()

@app.get("/api/events")
async def events():
    return vault.get_event_log()

@app.get("/api/projects")
async def projects():
    return vault.list_projects()

# ─── Entry ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    print("═" * 50)
    print("  ITERATION WALLET v2.0 — Hardened")
    print(f"  Vault: {DEFAULT_VAULT_ROOT}")
    print(f"  Server: http://{HOST}:{PORT}")
    print("═" * 50)
    uvicorn.run(app, host=HOST, port=PORT)
