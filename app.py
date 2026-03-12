#!/usr/bin/env python3
"""
Globex Financial — Security Dashboard Backend
app.py | Reads real system data with graceful fallback
"""

import os, json, re, subprocess
from datetime import datetime
from flask import Flask, render_template, jsonify, request

app = Flask(__name__)
app.secret_key = "globex-secure-2024"

DATA_DIR    = os.environ.get("GLOBEX_DATA_DIR", os.path.join(os.path.dirname(__file__), "data"))
LOG_DIR     = "/var/log/globex"
USERS_DB    = os.path.join(DATA_DIR, "users.db")
ACL_DB      = os.path.join(DATA_DIR, "acl_state.db")
HIST_DB     = os.path.join(DATA_DIR, "history_policy.db")
AUDIT_LOG   = os.path.join(DATA_DIR, "audit.jsonl")
REVIEWED_DB = os.path.join(DATA_DIR, "reviewed.json")
SEC_LOG     = os.path.join(LOG_DIR,  "security_events.jsonl")
AUTH_LOG    = os.path.join(LOG_DIR,  "auth.log")

os.makedirs(DATA_DIR, exist_ok=True)

# ─────────────────────────────────────────────
#  Reviewed state  (persist across restarts)
# ─────────────────────────────────────────────

def load_reviewed():
    try:
        with open(REVIEWED_DB) as f:
            return set(json.load(f))
    except Exception:
        return set()

def save_reviewed(s):
    try:
        with open(REVIEWED_DB, "w") as f:
            json.dump(list(s), f)
    except Exception:
        pass

# ─────────────────────────────────────────────
#  Readers
# ─────────────────────────────────────────────

def read_users():
    users = []
    if os.path.exists(USERS_DB):
        with open(USERS_DB) as f:
            for line in f:
                p = line.strip().split("|")
                if len(p) >= 6:
                    username, role, project, fullname, created, status = p[:6]
                    users.append({
                        "username":   username,
                        "fullname":   fullname,
                        "role":       role.title(),
                        "project":    project.upper(),
                        "status":     status,
                        "last_login": get_last_login(username),
                        "created":    created,
                    })
    return users

def get_last_login(username):
    try:
        r = subprocess.run(["last", "-n", "1", "-F", username],
                           capture_output=True, text=True, timeout=3)
        lines = [l for l in r.stdout.splitlines() if username in l and "wtmp" not in l]
        if lines and "never" not in lines[0].lower():
            parts = lines[0].split()
            if len(parts) >= 7:
                return " ".join(parts[3:7])
    except Exception:
        pass
    return "Never"

def read_acl_state():
    acls = []
    if os.path.exists(ACL_DB):
        with open(ACL_DB) as f:
            for line in f:
                p = line.strip().split("|")
                if len(p) >= 5:
                    acls.append({"directory": p[0], "state": p[1],
                                 "owner": p[2], "group": p[3], "updated": p[4]})
    return acls or [
        {"directory": "/opt/globex/secure/project-a", "state": "restricted",
         "owner": "alice_senior", "group": "project-a", "updated": "—"},
        {"directory": "/opt/globex/secure/project-b", "state": "restricted",
         "owner": "dave_senior",  "group": "project-b", "updated": "—"},
    ]

def read_history_policy():
    policies = []
    if os.path.exists(HIST_DB):
        with open(HIST_DB) as f:
            for line in f:
                p = line.strip().split("|")
                if len(p) >= 4:
                    policies.append({"group": p[0], "limit": int(p[1]),
                                     "applied": p[2], "status": p[3]})
    return policies or [
        {"group": "default",         "limit": 50, "status": "active", "applied": "—"},
        {"group": "senior-analysts", "limit": 10, "status": "active", "applied": "—"},
    ]

def classify(msg, program=""):
    m, p = msg.lower(), program.lower()
    if any(k in m for k in ["authentication failure", "failed password", "invalid user"]):
        return "auth_fail", "HIGH"
    if "preauth" in m and "connection closed" in m:
        return "auth_fail", "MEDIUM"
    if any(k in m for k in ["not in sudoers", "incorrect password attempts"]):
        return "sudo_fail", "HIGH"
    if "sudo" in p and "command" in m:
        return "sudo_fail", "MEDIUM"
    if any(k in m for k in ["permission denied", "operation not permitted"]):
        return "acl_deny", "CRITICAL"
    if any(k in m for k in ["accepted password", "accepted publickey"]):
        return "auth_success", "LOW"
    if "session opened" in m or "session closed" in m:
        return "session", "LOW"
    return "auth_warn", "MEDIUM"

def extract_user(msg):
    for pat in [
        r"for invalid user (\S+)",
        r"failed \S+ for (\S+) from",
        r"for user (\S+)",
        r"for (\S+) from",
        r"user[= ](\S+)",
    ]:
        m = re.search(pat, msg, re.IGNORECASE)
        if m:
            u = m.group(1).strip("'\"(),:")
            if u and len(u) < 32:
                return u
    return None

def read_violations():
    reviewed = load_reviewed()
    violations = []
    vid = 1

    # Try structured JSON log
    if os.path.exists(SEC_LOG) and os.path.getsize(SEC_LOG) > 0:
        try:
            with open(SEC_LOG) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        e = json.loads(line)
                        msg     = e.get("message", "").strip()
                        program = e.get("program", "")
                        ts      = e.get("timestamp", "")[:19].replace("T", " ")
                        vtype, severity = classify(msg, program)
                        if vtype in ("session", "auth_success") and severity == "LOW":
                            continue
                        user = extract_user(msg) or e.get("host", "system")
                        key  = f"{ts[:16]}-{msg[:40]}"
                        violations.append({
                            "id": vid, "timestamp": ts, "user": user,
                            "message": msg[:120], "type": vtype,
                            "severity": severity, "program": program,
                            "reviewed": key in reviewed, "_key": key,
                        })
                        vid += 1
                    except json.JSONDecodeError:
                        continue
        except Exception:
            pass

    # Fallback: plain auth.log
    if not violations and os.path.exists(AUTH_LOG):
        try:
            with open(AUTH_LOG) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    m = re.match(r'^(\w+\s+\d+\s+[\d:]+)\s+\S+\s+(\S+?)(?:\[\d+\])?:\s+(.+)$', line)
                    if not m:
                        continue
                    ts_raw, program, msg = m.groups()
                    try:
                        ts = datetime.strptime(
                            f"{datetime.now().year} {ts_raw}", "%Y %b %d %H:%M:%S"
                        ).strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        ts = ts_raw
                    vtype, severity = classify(msg, program)
                    if vtype in ("session", "auth_success") and severity == "LOW":
                        continue
                    user = extract_user(msg) or "system"
                    key  = f"{ts[:16]}-{msg[:40]}"
                    violations.append({
                        "id": vid, "timestamp": ts, "user": user,
                        "message": msg[:120], "type": vtype,
                        "severity": severity, "program": program,
                        "reviewed": key in reviewed, "_key": key,
                    })
                    vid += 1
        except Exception:
            pass

    violations.sort(key=lambda x: x["timestamp"], reverse=True)
    return violations

def read_audit_log():
    events = []
    if os.path.exists(AUDIT_LOG):
        try:
            with open(AUDIT_LOG) as f:
                for line in f:
                    try:
                        events.append(json.loads(line.strip()))
                    except Exception:
                        pass
        except Exception:
            pass
    if not events:
        events = [{"timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                   "event": "DASHBOARD_STARTED", "detail": "Globex Security Dashboard initialized"}]
    return list(reversed(events))

def log_event(event_type, detail):
    try:
        with open(AUDIT_LOG, "a") as f:
            f.write(json.dumps({
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "event": event_type, "detail": detail,
            }) + "\n")
    except Exception:
        pass

# ─────────────────────────────────────────────
#  Routes
# ─────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("dashboard.html")

@app.route("/api/users")
def api_users():
    return jsonify(read_users())

@app.route("/api/users/create", methods=["POST"])
def api_create_user():
    data = request.json
    if not all(k in data for k in ["username", "fullname", "role", "project"]):
        return jsonify({"error": "Missing fields"}), 400
    username, fullname = data["username"].strip(), data["fullname"].strip()
    role, project = data["role"], data["project"]
    try:
        with open(USERS_DB, "a") as f:
            f.write(f"{username}|{role.lower()}|{project.lower()}|{fullname}"
                    f"|{datetime.now().strftime('%Y-%m-%dT%H:%M:%S')}|active\n")
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    log_event("USER_CREATED", f"'{username}' added via dashboard ({role} / {project})")
    return jsonify({"success": True, "user": {
        "username": username, "fullname": fullname, "role": role,
        "project": project, "status": "active", "last_login": "Never"
    }})

@app.route("/api/users/delete/<username>", methods=["DELETE"])
def api_delete_user(username):
    if not os.path.exists(USERS_DB):
        return jsonify({"error": "Not found"}), 404
    with open(USERS_DB) as f:
        lines = f.readlines()
    new_lines = [l for l in lines if not l.startswith(f"{username}|")]
    if len(new_lines) == len(lines):
        return jsonify({"error": "User not found"}), 404
    with open(USERS_DB, "w") as f:
        f.writelines(new_lines)
    log_event("USER_DELETED", f"'{username}' removed via dashboard")
    return jsonify({"success": True})

@app.route("/api/acl")
def api_acl():
    return jsonify(read_acl_state())

@app.route("/api/acl/toggle", methods=["POST"])
def api_acl_toggle():
    data = request.json
    directory, new_state = data.get("directory"), data.get("state")
    acls = read_acl_state()
    entry = next((a for a in acls if a["directory"] == directory), None)
    if not entry:
        return jsonify({"error": "Not found"}), 404
    entry["state"]   = new_state
    entry["updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(ACL_DB, "w") as f:
        for a in acls:
            f.write(f"{a['directory']}|{a['state']}|{a['owner']}|{a['group']}|{a['updated']}\n")
    perm = "r-x" if new_state == "restricted" else "rwx"
    try:
        subprocess.run(["setfacl", "-m",  f"g:{entry['group']}:{perm}", directory], check=True)
        subprocess.run(["setfacl", "-dm", f"g:{entry['group']}:{perm}", directory], check=True)
    except Exception as e:
        log_event("ACL_ERROR", f"setfacl failed: {e}")
    log_event("ACL_CHANGE", f"{directory} → {new_state}")
    return jsonify({"success": True, "entry": entry})

@app.route("/api/history-policy")
def api_history_policy():
    return jsonify(read_history_policy())

@app.route("/api/history-policy/update", methods=["POST"])
def api_history_update():
    data = request.json
    group, limit = data.get("group"), int(data.get("limit", 50))
    policies = read_history_policy()
    policy = next((p for p in policies if p["group"] == group), None)
    if not policy:
        return jsonify({"error": "Not found"}), 404
    policy["limit"]   = limit
    policy["applied"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(HIST_DB, "w") as f:
        for p in policies:
            f.write(f"{p['group']}|{p['limit']}|{p['applied']}|{p['status']}\n")
    log_event("HISTORY_CHANGED", f"HISTSIZE for '{group}' → {limit}")
    return jsonify({"success": True, "policy": policy})

@app.route("/api/history-policy/toggle", methods=["POST"])
def api_history_toggle():
    data = request.json
    group = data.get("group")
    policies = read_history_policy()
    policy = next((p for p in policies if p["group"] == group), None)
    if not policy:
        return jsonify({"error": "Not found"}), 404
    policy["status"]  = "disabled" if policy["status"] == "active" else "active"
    policy["applied"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(HIST_DB, "w") as f:
        for p in policies:
            f.write(f"{p['group']}|{p['limit']}|{p['applied']}|{p['status']}\n")
    log_event("HISTORY_TOGGLED", f"'{group}' → {policy['status']}")
    return jsonify({"success": True, "policy": policy})

@app.route("/api/violations")
def api_violations():
    violations = read_violations()
    for v in violations:
        v.pop("_key", None)
    return jsonify(violations)

@app.route("/api/violations/mark-reviewed/<int:violation_id>", methods=["POST"])
def api_mark_reviewed(violation_id):
    violations = read_violations()
    v = next((x for x in violations if x["id"] == violation_id), None)
    if v:
        reviewed = load_reviewed()
        reviewed.add(v.get("_key", str(violation_id)))
        save_reviewed(reviewed)
        log_event("VIOLATION_REVIEWED", f"#{violation_id} reviewed: {v['message'][:60]}")
    return jsonify({"success": True})

@app.route("/api/command-history")
def api_command_history():
    results = []
    users = read_users()
    for u in users:
        hist_file = f"/home/{u['username']}/.bash_history"
        if not os.path.exists(hist_file):
            continue
        try:
            with open(hist_file, errors="replace") as f:
                lines = f.readlines()
            ts = None
            for line in lines[-50:]:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("#") and line[1:].isdigit():
                    try:
                        ts = datetime.fromtimestamp(int(line[1:])).strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        pass
                    continue
                results.append({"user": u["username"], "command": line[:120], "timestamp": ts or "—"})
        except Exception:
            pass
    results.sort(key=lambda x: x["timestamp"], reverse=True)
    return jsonify(results[:200])

@app.route("/api/stats")
def api_stats():
    users      = read_users()
    acls       = read_acl_state()
    violations = read_violations()
    by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in violations:
        s = v.get("severity", "LOW")
        by_sev[s] = by_sev.get(s, 0) + 1
    return jsonify({
        "total_users":      len(users),
        "active_projects":  2,
        "total_violations": len(violations),
        "unreviewed":       sum(1 for v in violations if not v["reviewed"]),
        "by_severity":      by_sev,
        "restricted_dirs":  sum(1 for a in acls if a["state"] == "restricted"),
        "relaxed_dirs":     sum(1 for a in acls if a["state"] == "relaxed"),
        "last_updated":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })

@app.route("/api/audit-log")
def api_audit_log():
    return jsonify(read_audit_log())

if __name__ == "__main__":
    log_event("DASHBOARD_STARTED", "Globex Security Dashboard started")
    app.run(host="0.0.0.0", port=5050, debug=False)
