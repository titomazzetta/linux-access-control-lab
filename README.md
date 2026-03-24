# Linux Access Control Lab

> Secure file storage and access management system built on Kali Linux — role-based access controls, real-time security monitoring, audit logging, and a live SOC-style dashboard.

---

## Overview

This project simulates an enterprise security hardening scenario for a financial organization (Globex Financial) that experienced a breach due to weak access controls and poor monitoring. The system enforces strict file permissions, tracks command history for auditing, logs unauthorized access attempts via rsyslog, and surfaces everything through a real-time web dashboard.

**Stack:** Bash · Linux ACLs · Rsyslog · Python 3 · Flask · Kali Linux

---

## Project Structure

```
linux-access-control-lab/
├── globex_setup.sh            ← full system setup (run as root)
├── app.py                     ← Flask dashboard backend
├── templates/
│   └── dashboard.html         ← security dashboard UI
└── README.md
```

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/titomazzetta/linux-access-control-lab.git
cd linux-access-control-lab

# 2. Run full setup (all 5 tasks)
sudo bash globex_setup.sh

# 3. Open dashboard
http://localhost:5050
```

---

## Tasks

### Task 1 — User Accounts & ACL Permissions
Creates two project groups (`project-a`, `project-b`) and seven user accounts across roles. Applies POSIX ACLs so only the file owner can modify or delete files — group members get read-only access, all others are denied.

```bash
sudo bash globex_setup.sh task1
```

Verify ACLs are applied:
```bash
getfacl /opt/globex/secure/project-a

# Test enforcement
su - bob_analyst -c "touch /opt/globex/secure/project-a/test.txt"
# → Permission denied ✔

su - alice_senior -c "touch /opt/globex/secure/project-a/test.txt"
# → Success ✔
```

---

### Task 2 — Command History Policy
Configures `HISTSIZE` limits via `/etc/profile.d/globex_history.sh`. Senior analysts retain only the last 10 commands (minimal footprint). All other users retain 50 commands for audit trail compliance. All commands are timestamped and written immediately on execution.

```bash
sudo bash globex_setup.sh task2

# Verify
su - alice_senior -c "echo \$HISTSIZE"   # → 10
su - bob_analyst  -c "echo \$HISTSIZE"   # → 50
```

---

### Task 3 — Rsyslog Security Logging
Configures rsyslog to capture all auth and access events. Structured JSON logs are written to `/var/log/globex/security_events.jsonl` for dashboard consumption. Plain-text auth logs go to `/var/log/globex/auth.log`. Log rotation is configured for 90-day retention.

```bash
sudo bash globex_setup.sh task3

# Watch live security events
tail -f /var/log/globex/security_events.jsonl

# Trigger test events
ssh wronguser@localhost          # auth failure
su - bob_analyst                 # failed su (wrong password)
sudo ls /root                    # sudo failure (non-privileged user)
```

---

### Task 4 — Security Monitoring Dashboard
Deploys a Flask web dashboard as a systemd service on port 5050. Reads real data from system files — no mock data in production. Auto-refreshes every 30 seconds. New violations flash on screen as they arrive.

```bash
sudo bash globex_setup.sh task4

# Check service status
systemctl status globex-dashboard

# View logs
journalctl -u globex-dashboard -f
```

**Dashboard sections:**

| Tab | Data Source | Refresh |
|-----|-------------|---------|
| Overview | Live counts + severity chart | 30s auto |
| Users | `users.db` — accounts, roles, last login | On nav |
| ACL Permissions | `acl_state.db` — live toggle via `setfacl` | On action |
| History Policy | `history_policy.db` — editable HISTSIZE | On action |
| Command Log | `~/.bash_history` per user | 30s auto |
| Violations | `/var/log/globex/security_events.jsonl` | 30s auto |
| Audit Log | `audit.jsonl` — all dashboard actions | On nav |

---

### Task 5 — Boot Persistence
All security settings survive reboots. A dedicated `globex-acl-restore` systemd service re-applies ACLs from `acl_state.db` at boot. The dashboard service and rsyslog are both enabled at startup.

```bash
sudo bash globex_setup.sh task5

# Verify boot services
systemctl is-enabled globex-dashboard       # → enabled
systemctl is-enabled globex-acl-restore     # → enabled
systemctl is-enabled rsyslog                # → enabled
```

---

## Default Users

| Username | Role | Project | HISTSIZE |
|----------|------|---------|---------|
| `alice_senior` | Senior Analyst | A | 10 |
| `bob_analyst` | Analyst | A | 50 |
| `carol_viewer` | Viewer | A | 50 |
| `dave_senior` | Senior Analyst | B | 10 |
| `eve_analyst` | Analyst | B | 50 |
| `frank_viewer` | Viewer | A+B | 50 |
| `globex_admin` | Admin | All | 50 |

Default password: `GlobexTemp@2024!` — forced change on first login via `chage -d 0`.

---


## Terminal Logging Check Scripts

Use these helper scripts to validate Task 3 logging from your terminal:

```bash
# 1) Validate rsyslog + Globex log files
bash scripts/check_logging_health.sh

# 2) Generate synthetic authpriv test events
bash scripts/generate_logging_test_events.sh 5   # emits test events without restarting rsyslog

# 3) Watch structured security logs live
bash scripts/watch_security_events.sh
```

> Most commands require root or `sudo` access because they read `/var/log/globex/*` and check system services.

## Utility Commands

```bash
# Check full system status
sudo bash globex_setup.sh status

# Run a single task
sudo bash globex_setup.sh task1

# Tear everything down cleanly
sudo bash globex_setup.sh reset

# Restart dashboard after updates
sudo systemctl restart globex-dashboard

# Live violation feed
sudo tail -f /var/log/globex/security_events.jsonl

# Pretty-print JSON events
sudo cat /var/log/globex/security_events.jsonl | python3 -m json.tool
```

---

## Log Files

| File | Contents |
|------|----------|
| `/var/log/globex/security_events.jsonl` | Structured JSON — all auth events (dashboard source) |
| `/var/log/globex/auth.log` | Plain-text auth log fallback |
| `/var/log/globex/kernel.log` | Kernel-level warnings |
| `/opt/globex/data/audit.jsonl` | Dashboard action audit trail |
| `/tmp/globex_setup.log` | Setup script run log |

---

## Data Files

| File | Contents |
|------|----------|
| `/opt/globex/data/users.db` | Pipe-delimited user registry |
| `/opt/globex/data/acl_state.db` | ACL state per directory (restricted/relaxed) |
| `/opt/globex/data/history_policy.db` | HISTSIZE policy per group |
| `/opt/globex/data/reviewed.json` | Violation reviewed state (persists across restarts) |

---

## Troubleshooting

**Dashboard won't start — permission denied on data dir:**
```bash
sudo chown -R globex_admin:globex_admin /opt/globex/data
sudo systemctl restart globex-dashboard
```

**setfacl not found:**
```bash
sudo apt install acl
sudo mount -o remount,acl /
```

**Port 5050 already in use:**
```bash
sudo lsof -i :5050
sudo kill -9 <PID>
```

**Check why dashboard failed:**
```bash
sudo journalctl -u globex-dashboard -n 40 --no-pager
```

**No violations showing in dashboard:**
```bash
# Confirm rsyslog is writing
sudo systemctl status rsyslog
ls -la /var/log/globex/

# Trigger a test event then check
ssh fakeuser@localhost
sudo tail -5 /var/log/globex/auth.log
```
