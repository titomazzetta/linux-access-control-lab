#!/bin/bash
# ============================================================
#  GLOBEX FINANCIAL — Secure File Storage & Access Management
#  globex_setup.sh | Kali Linux | Run as root
#
#  Usage:
#    sudo bash globex_setup.sh          # full setup
#    sudo bash globex_setup.sh task1    # single task
#    sudo bash globex_setup.sh status   # check state
#    sudo bash globex_setup.sh reset    # tear down
# ============================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

LOGFILE="/tmp/globex_setup.log"
PROJECT_A_DIR="/opt/globex/secure/project-a"
PROJECT_B_DIR="/opt/globex/secure/project-b"
DASHBOARD_DIR="/opt/globex/app"
DATA_DIR="/opt/globex/data"
LOG_DIR="/var/log/globex"

log()  { echo -e "${GREEN}[✔]${RESET} $1" | tee -a "$LOGFILE"; }
warn() { echo -e "${YELLOW}[⚠]${RESET} $1" | tee -a "$LOGFILE"; }
err()  { echo -e "${RED}[✖]${RESET} $1" | tee -a "$LOGFILE"; exit 1; }
info() { echo -e "${CYAN}[→]${RESET} $1" | tee -a "$LOGFILE"; }

print_banner() {
  echo -e "${CYAN}${BOLD}"
  echo "  ╔══════════════════════════════════════════════════════╗"
  echo "  ║     GLOBEX FINANCIAL — SECURE ACCESS SETUP v2.0     ║"
  echo "  ╚══════════════════════════════════════════════════════╝"
  echo -e "${RESET}"
}

check_root() {
  if [[ $EUID -ne 0 ]]; then
    err "Must run as root: sudo bash $0"
  fi
  log "Running as root"
}

# ─────────────────────────────────────────────
#  INIT — create all directories + log file
# ─────────────────────────────────────────────
init() {
  mkdir -p "$LOG_DIR" "$DATA_DIR" "$DASHBOARD_DIR"/templates \
           "$PROJECT_A_DIR" "$PROJECT_B_DIR"
  touch "$LOGFILE"
  info "Setup started at $(date)"
  info "Log: $LOGFILE"
}

# ─────────────────────────────────────────────
#  DEPS
# ─────────────────────────────────────────────
install_deps() {
  info "Installing dependencies..."
  apt-get update -qq
  apt-get install -y -qq acl rsyslog python3 python3-pip python3-flask 2>/dev/null
  log "Dependencies installed"
}

# ─────────────────────────────────────────────
#  TASK 1 — Users, Groups, ACLs
# ─────────────────────────────────────────────
setup_task1() {
  echo -e "\n${BOLD}── TASK 1: Users, Groups & ACLs ───────────────────────────${RESET}"

  # Create groups
  for grp in globex-users project-a project-b senior-analysts; do
    if getent group "$grp" > /dev/null 2>&1; then
      warn "Group already exists: $grp"
    else
      groupadd "$grp"
      log "Group created: $grp"
    fi
  done

  # Clear users.db for fresh run
  > "$DATA_DIR/users.db"

  # Create users  format: username role project fullname
  create_user "alice_senior" "senior"  "a"    "Alice Chen"
  create_user "bob_analyst"  "analyst" "a"    "Bob Torres"
  create_user "carol_viewer" "viewer"  "a"    "Carol Kim"
  create_user "dave_senior"  "senior"  "b"    "Dave Patel"
  create_user "eve_analyst"  "analyst" "b"    "Eve Johnson"
  create_user "frank_viewer" "viewer"  "both" "Frank Liu"
  create_user "globex_admin" "admin"   "both" "Globex Admin"

  # Directory ownership
  chown alice_senior:project-a "$PROJECT_A_DIR"
  chown dave_senior:project-b  "$PROJECT_B_DIR"
  chmod 750 "$PROJECT_A_DIR" "$PROJECT_B_DIR"

  # Apply ACLs
  apply_acl "$PROJECT_A_DIR" "alice_senior" "project-a"
  apply_acl "$PROJECT_B_DIR" "dave_senior"  "project-b"

  log "Task 1 complete"
}

create_user() {
  local username="$1"
  local role="$2"
  local project="$3"
  local fullname="$4"

  if id "$username" > /dev/null 2>&1; then
    warn "User '$username' already exists — skipping"
  else
    useradd -m -c "$fullname" -s /bin/bash -G globex-users "$username"
    echo "${username}:GlobexTemp@2024!" | chpasswd
    chage -d 0 "$username"
    log "Created user: $username ($role)"
  fi

  # Group assignments — using if/elif to avoid set -e issues with &&
  if [[ "$project" == "a" || "$project" == "both" ]]; then
    usermod -aG project-a "$username"
  fi
  if [[ "$project" == "b" || "$project" == "both" ]]; then
    usermod -aG project-b "$username"
  fi
  if [[ "$role" == "senior" ]]; then
    usermod -aG senior-analysts "$username"
  fi
  if [[ "$role" == "admin" ]]; then
    usermod -aG sudo "$username"
  fi

  echo "$username|$role|$project|$fullname|$(date +%Y-%m-%dT%H:%M:%S)|active" \
    >> "$DATA_DIR/users.db"
}

apply_acl() {
  local dir="$1"
  local owner="$2"
  local group="$3"

  setfacl -b "$dir"
  setfacl -m  u:"$owner":rwx,g:"$group":r-x,o::--- "$dir"
  setfacl -dm u:"$owner":rwx,g:"$group":r-x,o::--- "$dir"

  # Record state (overwrite existing entry for this dir)
  local tmpfile
  tmpfile=$(mktemp)
  grep -v "^$dir|" "$DATA_DIR/acl_state.db" 2>/dev/null > "$tmpfile" || true
  echo "$dir|restricted|$owner|$group|$(date +%Y-%m-%dT%H:%M:%S)" >> "$tmpfile"
  mv "$tmpfile" "$DATA_DIR/acl_state.db"

  log "ACL applied: $dir (owner=$owner group=$group read-only)"
}

# ─────────────────────────────────────────────
#  TASK 2 — Command History
# ─────────────────────────────────────────────
setup_task2() {
  echo -e "\n${BOLD}── TASK 2: Command History Policy ─────────────────────────${RESET}"

  cat > /etc/profile.d/globex_history.sh << 'EOF'
# Globex Financial — Command History Policy
export HISTTIMEFORMAT="%Y-%m-%d %H:%M:%S  "
export HISTCONTROL=""
shopt -s histappend
PROMPT_COMMAND="history -a"

# Senior analysts: 10 | everyone else: 50
if id -nG "$USER" 2>/dev/null | grep -qw "senior-analysts"; then
  export HISTSIZE=10
  export HISTFILESIZE=10
else
  export HISTSIZE=50
  export HISTFILESIZE=50
fi
EOF
  chmod 644 /etc/profile.d/globex_history.sh

  # Inject into existing user .bashrc files
  for home_dir in /home/*/; do
    local rc="${home_dir}.bashrc"
    if [[ -f "$rc" ]]; then
      if ! grep -q "globex_history" "$rc"; then
        echo "source /etc/profile.d/globex_history.sh" >> "$rc"
      fi
    fi
  done

  # Record policy for dashboard
  > "$DATA_DIR/history_policy.db"
  echo "default|50|$(date +%Y-%m-%dT%H:%M:%S)|active"         >> "$DATA_DIR/history_policy.db"
  echo "senior-analysts|10|$(date +%Y-%m-%dT%H:%M:%S)|active"  >> "$DATA_DIR/history_policy.db"

  log "Task 2 complete — senior=10 cmds, all others=50 cmds"
}

# ─────────────────────────────────────────────
#  TASK 3 — Rsyslog
# ─────────────────────────────────────────────
setup_task3() {
  echo -e "\n${BOLD}── TASK 3: Rsyslog Security Logging ───────────────────────${RESET}"

  cat > /etc/rsyslog.d/10-globex-security.conf << 'EOF'
# Globex Financial — Security Event Logging
auth,authpriv.*  /var/log/globex/auth.log
kern.warning     /var/log/globex/kernel.log

template(name="GlobexJSON" type="list") {
  constant(value="{")
  constant(value="\"timestamp\":\"")   property(name="timereported" dateFormat="rfc3339")
  constant(value="\",\"host\":\"")     property(name="hostname")
  constant(value="\",\"program\":\"")  property(name="programname")
  constant(value="\",\"severity\":\"") property(name="syslogseverity-text")
  constant(value="\",\"message\":\"")  property(name="msg" format="json")
  constant(value="\"}\n")
}

auth,authpriv.* action(type="omfile"
  file="/var/log/globex/security_events.jsonl"
  template="GlobexJSON")
EOF

  cat > /etc/logrotate.d/globex << 'EOF'
/var/log/globex/*.log /var/log/globex/*.jsonl {
  daily
  rotate 90
  compress
  delaycompress
  missingok
  notifempty
  create 640 root globex-users
  postrotate
    systemctl reload rsyslog > /dev/null 2>&1 || true
  endscript
}
EOF

  chown root:globex-users "$LOG_DIR"
  chmod 750 "$LOG_DIR"
  systemctl restart rsyslog
  log "Task 3 complete — logging to $LOG_DIR/"
}

# ─────────────────────────────────────────────
#  TASK 4 — Dashboard
# ─────────────────────────────────────────────
setup_task4() {
  echo -e "\n${BOLD}── TASK 4: Web Dashboard ───────────────────────────────────${RESET}"

  # Copy app files from repo (same directory as this script)
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

  cp "$script_dir/app.py" "$DASHBOARD_DIR/app.py"
  cp "$script_dir/templates/dashboard.html" "$DASHBOARD_DIR/templates/dashboard.html"
  mkdir -p "$DASHBOARD_DIR/data"

  pip3 install flask --quiet --break-system-packages

  cat > /etc/systemd/system/globex-dashboard.service << EOF
[Unit]
Description=Globex Financial Security Dashboard
After=network.target rsyslog.service

[Service]
Type=simple
User=globex_admin
WorkingDirectory=$DASHBOARD_DIR
ExecStart=/usr/bin/python3 $DASHBOARD_DIR/app.py
Restart=on-failure
RestartSec=5
Environment=GLOBEX_DATA_DIR=$DATA_DIR

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable globex-dashboard
  systemctl start globex-dashboard
  log "Task 4 complete — dashboard at http://localhost:5050"
}

# ─────────────────────────────────────────────
#  TASK 5 — Persistence
# ─────────────────────────────────────────────
setup_task5() {
  echo -e "\n${BOLD}── TASK 5: Boot Persistence ────────────────────────────────${RESET}"

  cat > /usr/local/bin/globex-acl-restore << EOF
#!/bin/bash
# Globex — Restore ACLs from state file on boot
while IFS='|' read -r dir state owner group ts; do
  [[ -d "\$dir" ]] || continue
  setfacl -b "\$dir"
  if [[ "\$state" == "restricted" ]]; then
    setfacl -m  u:"\$owner":rwx,g:"\$group":r-x,o::--- "\$dir"
    setfacl -dm u:"\$owner":rwx,g:"\$group":r-x,o::--- "\$dir"
  else
    setfacl -m  u:"\$owner":rwx,g:"\$group":rwx,o::--- "\$dir"
    setfacl -dm u:"\$owner":rwx,g:"\$group":rwx,o::--- "\$dir"
  fi
done < "$DATA_DIR/acl_state.db"
EOF
  chmod +x /usr/local/bin/globex-acl-restore

  cat > /etc/systemd/system/globex-acl-restore.service << 'EOF'
[Unit]
Description=Globex ACL Restore
DefaultDependencies=no
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/globex-acl-restore
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable globex-acl-restore
  systemctl enable globex-dashboard
  systemctl enable rsyslog

  log "Task 5 complete — all services persist across reboots"
}

# ─────────────────────────────────────────────
#  STATUS
# ─────────────────────────────────────────────
show_status() {
  echo -e "\n${BOLD}── Globex System Status ────────────────────────────────────${RESET}\n"

  echo -e "${CYAN}Services:${RESET}"
  for svc in globex-dashboard globex-acl-restore rsyslog; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
      echo -e "  ${GREEN}●${RESET} $svc — running"
    else
      echo -e "  ${RED}●${RESET} $svc — stopped"
    fi
  done

  echo -e "\n${CYAN}Users:${RESET}"
  if [[ -f "$DATA_DIR/users.db" ]]; then
    while IFS='|' read -r user role project name ts status; do
      echo -e "  ${GREEN}✔${RESET}  $(printf '%-18s' "$user")  $role  /  Project $project"
    done < "$DATA_DIR/users.db"
  else
    echo "  No users found — run task1 first"
  fi

  echo -e "\n${CYAN}ACL State:${RESET}"
  if [[ -f "$DATA_DIR/acl_state.db" ]]; then
    while IFS='|' read -r dir state owner group ts; do
      if [[ "$state" == "restricted" ]]; then
        echo -e "  ${GREEN}🔒${RESET}  $dir  →  $state"
      else
        echo -e "  ${YELLOW}🔓${RESET}  $dir  →  $state"
      fi
    done < "$DATA_DIR/acl_state.db"
  else
    echo "  No ACL state found — run task1 first"
  fi

  echo -e "\n${CYAN}History Policy:${RESET}"
  if [[ -f "$DATA_DIR/history_policy.db" ]]; then
    while IFS='|' read -r group limit ts active; do
      echo -e "  ${GREEN}✔${RESET}  $(printf '%-20s' "$group")  HISTSIZE=$limit  [$active]"
    done < "$DATA_DIR/history_policy.db"
  else
    echo "  No policy found — run task2 first"
  fi
  echo ""
}

# ─────────────────────────────────────────────
#  RESET
# ─────────────────────────────────────────────
reset_all() {
  warn "This removes all Globex users, config, and data."
  read -rp "  Type CONFIRM to proceed: " confirm
  if [[ "$confirm" != "CONFIRM" ]]; then
    info "Aborted."
    exit 0
  fi

  systemctl stop    globex-dashboard globex-acl-restore 2>/dev/null || true
  systemctl disable globex-dashboard globex-acl-restore 2>/dev/null || true
  rm -f /etc/systemd/system/globex-*.service
  systemctl daemon-reload

  for user in alice_senior bob_analyst carol_viewer dave_senior \
              eve_analyst frank_viewer globex_admin; do
    if id "$user" > /dev/null 2>&1; then
      userdel -r "$user" 2>/dev/null || true
      warn "Removed user: $user"
    fi
  done

  for grp in project-a project-b senior-analysts globex-users; do
    if getent group "$grp" > /dev/null 2>&1; then
      groupdel "$grp" 2>/dev/null || true
    fi
  done

  rm -rf /opt/globex /var/log/globex
  rm -f /etc/rsyslog.d/10-globex-security.conf
  rm -f /etc/logrotate.d/globex
  rm -f /etc/profile.d/globex_history.sh
  rm -f /usr/local/bin/globex-acl-restore

  systemctl restart rsyslog 2>/dev/null || true
  log "Reset complete"
}

# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
print_banner
check_root
init

case "${1:-all}" in
  all)
    install_deps
    setup_task1
    setup_task2
    setup_task3
    setup_task4
    setup_task5
    echo -e "\n${GREEN}${BOLD}══════════════════════════════════════════════════════${RESET}"
    echo -e "${GREEN}${BOLD}  SETUP COMPLETE${RESET}"
    echo -e "${GREEN}  Dashboard → http://localhost:5050${RESET}"
    echo -e "${GREEN}  Logs      → $LOG_DIR/${RESET}"
    echo -e "${GREEN}  Data      → $DATA_DIR/${RESET}"
    echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════${RESET}\n"
    ;;
  task1) install_deps; setup_task1 ;;
  task2) setup_task2 ;;
  task3) setup_task3 ;;
  task4) setup_task4 ;;
  task5) setup_task5 ;;
  status) show_status ;;
  reset)  reset_all ;;
  *)
    echo "Usage: sudo bash $0 [all|task1|task2|task3|task4|task5|status|reset]"
    exit 1
    ;;
esac
