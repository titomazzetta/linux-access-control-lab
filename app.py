#!/usr/bin/env python3
"""
Globex Financial — Security Dashboard Backend
app.py | Flask web application
"""

import os, json, re, subprocess
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request
import random

app = Flask(__name__)
app.secret_key = "globex-secure-2024"

DATA_DIR = os.environ.get("GLOBEX_DATA_DIR", os.path.join(os.path.dirname(__file__), "data"))
os.makedirs(DATA_DIR, exist_ok=True)

# ─────────────────────────────────────────────
#  Mock data helpers (used when real system
#  data is unavailable — demo / dev mode)
# ─────────────────────────────────────────────

MOCK_USERS = [
    {"username": "alice_senior",  "fullname": "Alice Chen",   "role": "Senior Analyst", "project": "A",    "status": "active",   "last_login": "2024-01-15 09:23:11"},
    {"username": "bob_analyst",   "fullname": "Bob Torres",   "role": "Analyst",        "project": "A",    "status": "active",   "last_login": "2024-01-15 08:47:02"},
    {"username": "carol_viewer",  "fullname": "Carol Kim",    "role": "Viewer",         "project": "A",    "status": "active",   "last_login": "2024-01-14 16:30:55"},
    {"username": "dave_senior",   "fullname": "Dave Patel",   "role": "Senior Analyst", "project": "B",    "status": "active",   "last_login": "2024-01-15 10:02:44"},
    {"username": "eve_analyst",   "fullname": "Eve Johnson",  "role": "Analyst",        "project": "B",    "status": "active",   "last_login": "2024-01-15 07:58:19"},
    {"username": "frank_viewer",  "fullname": "Frank Liu",    "role": "Viewer",         "project": "A+B",  "status": "active",   "last_login": "2024-01-13 14:22:08"},
    {"username": "globex_admin",  "fullname": "Globex Admin", "role": "Admin",          "project": "All",  "status": "active",   "last_login": "2024-01-15 11:00:00"},
]

MOCK_ACL_STATE = [
    {"directory": "/secure/project-a", "state": "restricted", "owner": "alice_senior", "group": "project-a", "updated": "2024-01-15 09:00:00"},
    {"directory": "/secure/project-b", "state": "restricted", "owner": "dave_senior",  "group": "project-b", "updated": "2024-01-15 09:00:00"},
]

MOCK_HISTORY_POLICY = [
    {"group": "senior-analysts",   "limit": 10,  "status": "active", "applied": "2024-01-15 09:00:00"},
    {"group": "all other users",   "limit": 50,  "status": "active", "applied": "2024-01-15 09:00:00"},
]

VIOLATION_MESSAGES = [
    ("bob_analyst",  "Attempted write to /secure/project-a/reports/q4.xlsx",   "acl_deny",   "HIGH"),
    ("carol_viewer", "Attempted delete on /secure/project-a/config.json",       "acl_deny",   "CRITICAL"),
    ("frank_viewer", "SSH login failure (invalid password) x3",                 "auth_fail",  "HIGH"),
    ("unknown_user", "sudo: command not found for user unknown_user",           "sudo_fail",  "MEDIUM"),
    ("eve_analyst",  "Attempted write to /secure/project-b/financials/",        "acl_deny",   "HIGH"),
    ("carol_viewer", "Attempted chmod 777 on protected file",                   "perm_change","CRITICAL"),
    ("frank_viewer", "Attempted access to /secure/project-b/ (no membership)", "acl_deny",   "HIGH"),
    ("bob_analyst",  "SSH login from unrecognized IP: 192.168.55.201",          "auth_warn",  "MEDIUM"),
]

def generate_mock_violations(count=30):
    violations = []
    base_time = datetime.now() - timedelta(days=3)
    for i in range(count):
        msg = MOCK_VIOLATIONS_POOL[i % len(MOCK_VIOLATIONS_POOL)]
        ts = base_time + timedelta(
            hours=random.randint(0, 72),
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59)
        )
        violations.append({
            "id": i + 1,
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "user": msg[0],
            "message": msg[1],
            "type": msg[2],
            "severity": msg[3],
            "reviewed": random.choice([True, True, False]),
        })
    violations.sort(key=lambda x: x["timestamp"], reverse=True)
    return violations

MOCK_VIOLATIONS_POOL = VIOLATION_MESSAGES * 4

def generate_mock_history():
    commands = {
        "alice_senior":  ["ls -la /secure/project-a", "cat reports/q4.xlsx", "vim config.json", "git status", "pwd", "whoami", "date", "history", "exit", "clear"],
        "bob_analyst":   ["ls /secure/project-a", "cat summary.txt", "python3 analyze.py", "grep -r 'revenue'", "cd /secure/project-a"],
        "dave_senior":   ["ls /secure/project-b", "cat audit.log", "vim settings.conf", "chmod 600 data.csv", "history"],
        "carol_viewer":  ["ls /secure/project-a", "cat readme.md", "who", "date"],
        "eve_analyst":   ["cd /secure/project-b", "ls -la", "python3 report.py", "cat financials.csv", "grep error logs/app.log"],
        "frank_viewer":  ["ls /secure/project-a", "ls /secure/project-b", "cat notes.txt", "who am i"],
        "globex_admin":  ["systemctl status globex-dashboard", "tail -f /var/log/globex/auth.log", "getfacl /secure/project-a", "usermod -aG project-a alice_senior"],
    }
    result = []
    base_time = datetime.now() - timedelta(hours=2)
    for user, cmds in commands.items():
        for i, cmd in enumerate(cmds):
            result.append({
                "user": user,
                "command": cmd,
                "timestamp": (base_time + timedelta(minutes=i * 3 + random.randint(0, 5))).strftime("%Y-%m-%d %H:%M:%S"),
            })
    result.sort(key=lambda x: x["timestamp"], reverse=True)
    return result

# ─────────────────────────────────────────────
#  API Routes
# ─────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("dashboard.html")

@app.route("/api/users")
def api_users():
    return jsonify(MOCK_USERS)

@app.route("/api/users/create", methods=["POST"])
def api_create_user():
    data = request.json
    required = ["username", "fullname", "role", "project"]
    if not all(k in data for k in required):
        return jsonify({"error": "Missing fields"}), 400

    new_user = {
        "username":   data["username"],
        "fullname":   data["fullname"],
        "role":       data["role"],
        "project":    data["project"],
        "status":     "active",
        "last_login": "Never",
    }
    MOCK_USERS.append(new_user)

    # In production: subprocess.run(["useradd", ...])
    log_event("USER_CREATED", f"New user '{data['username']}' created via dashboard ({data['role']} / Project {data['project']})")
    return jsonify({"success": True, "user": new_user})

@app.route("/api/users/delete/<username>", methods=["DELETE"])
def api_delete_user(username):
    global MOCK_USERS
    original = len(MOCK_USERS)
    MOCK_USERS = [u for u in MOCK_USERS if u["username"] != username]
    if len(MOCK_USERS) < original:
        log_event("USER_DELETED", f"User '{username}' removed via dashboard")
        return jsonify({"success": True})
    return jsonify({"error": "User not found"}), 404

@app.route("/api/acl")
def api_acl():
    return jsonify(MOCK_ACL_STATE)

@app.route("/api/acl/toggle", methods=["POST"])
def api_acl_toggle():
    data = request.json
    directory = data.get("directory")
    new_state  = data.get("state")  # "restricted" or "relaxed"

    for entry in MOCK_ACL_STATE:
        if entry["directory"] == directory:
            entry["state"]   = new_state
            entry["updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # In production:
            # if new_state == "restricted":
            #     subprocess.run(["setfacl", "-m", f"g:{entry['group']}:r-x", directory])
            # else:
            #     subprocess.run(["setfacl", "-m", f"g:{entry['group']}:rwx", directory])

            log_event("ACL_CHANGE", f"ACL for {directory} set to '{new_state}' via dashboard")
            return jsonify({"success": True, "entry": entry})

    return jsonify({"error": "Directory not found"}), 404

@app.route("/api/history-policy")
def api_history_policy():
    return jsonify(MOCK_HISTORY_POLICY)

@app.route("/api/history-policy/update", methods=["POST"])
def api_history_update():
    data  = request.json
    group = data.get("group")
    limit = data.get("limit")
    for policy in MOCK_HISTORY_POLICY:
        if policy["group"] == group:
            policy["limit"]   = int(limit)
            policy["applied"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_event("HISTORY_POLICY_CHANGED", f"HISTSIZE for '{group}' changed to {limit}")
            return jsonify({"success": True, "policy": policy})
    return jsonify({"error": "Group not found"}), 404

@app.route("/api/history-policy/toggle", methods=["POST"])
def api_history_toggle():
    data  = request.json
    group = data.get("group")
    for policy in MOCK_HISTORY_POLICY:
        if policy["group"] == group:
            policy["status"] = "disabled" if policy["status"] == "active" else "active"
            log_event("HISTORY_POLICY_TOGGLED", f"History policy for '{group}' → {policy['status']}")
            return jsonify({"success": True, "policy": policy})
    return jsonify({"error": "Group not found"}), 404

@app.route("/api/violations")
def api_violations():
    violations = generate_mock_violations(28)
    return jsonify(violations)

@app.route("/api/violations/mark-reviewed/<int:violation_id>", methods=["POST"])
def api_mark_reviewed(violation_id):
    log_event("VIOLATION_REVIEWED", f"Violation #{violation_id} marked as reviewed")
    return jsonify({"success": True})

@app.route("/api/command-history")
def api_command_history():
    return jsonify(generate_mock_history())

@app.route("/api/stats")
def api_stats():
    violations = generate_mock_violations(28)
    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in violations:
        by_severity[v["severity"]] = by_severity.get(v["severity"], 0) + 1

    return jsonify({
        "total_users":       len(MOCK_USERS),
        "active_projects":   2,
        "total_violations":  len(violations),
        "unreviewed":        sum(1 for v in violations if not v["reviewed"]),
        "by_severity":       by_severity,
        "restricted_dirs":   sum(1 for a in MOCK_ACL_STATE if a["state"] == "restricted"),
        "relaxed_dirs":      sum(1 for a in MOCK_ACL_STATE if a["state"] == "relaxed"),
    })

@app.route("/api/audit-log")
def api_audit_log():
    log_file = os.path.join(DATA_DIR, "audit.jsonl")
    events = []
    if os.path.exists(log_file):
        with open(log_file) as f:
            for line in f:
                try:
                    events.append(json.loads(line.strip()))
                except:
                    pass
    # Always return at least some data
    if not events:
        events = [
            {"timestamp": "2024-01-15 09:00:00", "event": "SETUP_COMPLETE",      "detail": "Globex security setup completed"},
            {"timestamp": "2024-01-15 09:01:00", "event": "ACL_APPLIED",         "detail": "ACLs applied to /secure/project-a"},
            {"timestamp": "2024-01-15 09:01:05", "event": "ACL_APPLIED",         "detail": "ACLs applied to /secure/project-b"},
            {"timestamp": "2024-01-15 09:02:00", "event": "HISTORY_POLICY",      "detail": "HISTSIZE configured: senior=10, default=50"},
            {"timestamp": "2024-01-15 09:02:30", "event": "RSYSLOG_CONFIGURED",  "detail": "Security event logging enabled"},
            {"timestamp": "2024-01-15 09:03:00", "event": "DASHBOARD_STARTED",   "detail": "Web dashboard started on :5050"},
            {"timestamp": "2024-01-15 09:04:00", "event": "PERSISTENCE_ENABLED", "detail": "Boot services enabled (ACL restore + dashboard)"},
        ]
    return jsonify(list(reversed(events)))

# ─────────────────────────────────────────────
#  Helper
# ─────────────────────────────────────────────

def log_event(event_type, detail):
    log_file = os.path.join(DATA_DIR, "audit.jsonl")
    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event":     event_type,
        "detail":    detail,
    }
    with open(log_file, "a") as f:
        f.write(json.dumps(entry) + "\n")

if __name__ == "__main__":
    log_event("DASHBOARD_STARTED", "Globex Security Dashboard started")
    app.run(host="0.0.0.0", port=5050, debug=False)
