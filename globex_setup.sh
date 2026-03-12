#!/bin/bash
# ============================================================
#  GLOBEX FINANCIAL — Secure File Storage & Access Management
#  setup.sh | Run as root
# ============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

LOGFILE="/var/log/globex/setup.log"
DASHBOARD_DIR="/opt/globex/dashboard"
DATA_DIR="/opt/globex/data"
PROJECT_A_DIR="/secure/project-a"
PROJECT_B_DIR="/secure/project-b"

log()  { echo -e "${GREEN}[✔]${RESET} $1" | tee -a "$LOGFILE"; }
warn() { echo -e "${YELLOW}[⚠]${RESET} $1" | tee -a "$LOGFILE"; }
err()  { echo -e "${RED}[✖]${RESET} $1" | tee -a "$LOGFILE"; exit 1; }
info() { echo -e "${CYAN}[→]${RESET} $1" | tee -a "$LOGFILE"; }

print_banner() {
  echo -e "${CYAN}"
  echo "  ╔══════════════════════════════════════════════════════╗"
  echo "  ║     GLOBEX FINANCIAL — SECURE ACCESS SETUP v1.0     ║"
  echo "  ╚══════════════════════════════════════════════════════╝"
  echo -e "${RESET}"
}

check_root() {
  [[ $EUID -ne 0 ]] && err "This script must be run as root. Use: sudo bash $0"
}

install_deps() {
  info "Installing required packages..."
  apt-get update -qq
  apt-get install -y -qq acl rsyslog python3 python3-pip python3-flask \
    libpam-pwquality > /dev/null 2>&1
  log "Dependencies installed"
}

create_directories() {
  info "Creating secure directory structure..."
  mkdir -p /var/log/globex
  mkdir -p "$PROJECT_A_DIR" "$PROJECT_B_DIR"
  mkdir -p "$DASHBOARD_DIR" "$DATA_DIR"
  chmod 750 "$PROJECT_A_DIR" "$PROJECT_B_DIR"

  # Enable ACL on the filesystem (mount option)
  MOUNT_POINT=$(df /secure | tail -1 | awk '{print $6}')
  FSTAB_LINE=$(grep " $MOUNT_POINT " /etc/fstab 2>/dev/null || true)
  if [[ -n "$FSTAB_LINE" ]] && ! echo "$FSTAB_LINE" | grep -q "acl"; then
    sed -i "s|\($MOUNT_POINT.*defaults\)|\1,acl|" /etc/fstab
    mount -o remount "$MOUNT_POINT" 2>/dev/null || warn "Remount may require reboot"
  fi
  log "Directories created: $PROJECT_A_DIR, $PROJECT_B_DIR"
}

# ─────────────────────────────────────────────
#  TASK 1: Create Users & Configure ACLs
# ─────────────────────────────────────────────
create_groups() {
  info "Creating project groups..."
  for group in project-a project-b senior-analysts globex-users; do
    if ! getent group "$group" > /dev/null 2>&1; then
      groupadd "$group"
      log "Group created: $group"
    else
      warn "Group already exists: $group"
    fi
  done
  # Persist group config
  cp /etc/group "$DATA_DIR/group.bak"
}

create_user() {
  local username="$1"
  local role="$2"          # senior|analyst|viewer
  local project="$3"       # a|b|both
  local fullname="${4:-$username}"

  if id "$username" &>/dev/null; then
    warn "User '$username' already exists — skipping creation"
    return
  fi

  useradd -m -c "$fullname" -s /bin/bash "$username"
  echo "${username}:GlobexTemp@2024!" | chpasswd
  chage -d 0 "$username"   # force password change on first login

  # Assign groups
  usermod -aG globex-users "$username"
  [[ "$project" == "a" || "$project" == "both" ]] && usermod -aG project-a "$username"
  [[ "$project" == "b" || "$project" == "both" ]] && usermod -aG project-b "$username"
  [[ "$role" == "senior" ]] && usermod -aG senior-analysts "$username"

  # Store metadata for dashboard
  echo "$username|$role|$project|$fullname|$(date +%Y-%m-%dT%H:%M:%S)|active" \
    >> "$DATA_DIR/users.db"

  log "User created: $username (role=$role, project=$project)"
}

apply_acls() {
  local dir="$1"
  local owner_user="$2"

  info "Applying ACLs to $dir for owner $owner_user..."

  # Remove all existing ACLs first
  setfacl -b "$dir"

  # Owner: full access
  setfacl -m u:"$owner_user":rwx "$dir"
  setfacl -m d:u:"$owner_user":rwx "$dir"

  # Group members: read-only
  local group
  [[ "$dir" == *project-a* ]] && group="project-a" || group="project-b"
  setfacl -m g:"$group":r-x "$dir"
  setfacl -m d:g:"$group":r-x "$dir"

  # Others: no access
  setfacl -m o::--- "$dir"
  setfacl -m d:o::--- "$dir"

  # Mask
  setfacl -m m::rwx "$dir"

  log "ACLs applied: $owner_user owns $dir (group read-only)"

  # Record restriction state
  echo "$dir|restricted|$owner_user|$group|$(date +%Y-%m-%dT%H:%M:%S)" \
    >> "$DATA_DIR/acl_state.db"
}

relax_acl() {
  # Allow group write access (undo restriction)
  local dir="$1"
  local group="$2"
  setfacl -m g:"$group":rwx "$dir"
  setfacl -m d:g:"$group":rwx "$dir"
  # Update state file
  sed -i "s|^$dir|$dir|" "$DATA_DIR/acl_state.db"
  sed -i "/$dir/s/restricted/relaxed/" "$DATA_DIR/acl_state.db"
  log "ACL relaxed: $group now has write access to $dir"
}

setup_task1() {
  echo -e "\n${BOLD}── TASK 1: User Accounts & ACLs ──────────────────────────${RESET}"
  create_groups

  # ── Project A Users ──
  create_user "alice_senior"  "senior"  "a"    "Alice Chen (Senior Analyst)"
  create_user "bob_analyst"   "analyst" "a"    "Bob Torres (Analyst)"
  create_user "carol_viewer"  "viewer"  "a"    "Carol Kim (Viewer)"

  # ── Project B Users ──
  create_user "dave_senior"   "senior"  "b"    "Dave Patel (Senior Analyst)"
  create_user "eve_analyst"   "analyst" "b"    "Eve Johnson (Analyst)"
  create_user "frank_viewer"  "viewer"  "both" "Frank Liu (Cross-Project Viewer)"

  # ── Admin ──
  create_user "globex_admin"  "admin"   "both" "Globex IT Admin"
  usermod -aG sudo globex_admin

  # Set directory ownership
  chown alice_senior:project-a "$PROJECT_A_DIR"
  chown dave_senior:project-b  "$PROJECT_B_DIR"

  # Apply ACLs (owner-only modify, others read-only)
  apply_acls "$PROJECT_A_DIR" "alice_senior"
  apply_acls "$PROJECT_B_DIR" "dave_senior"

  log "Task 1 complete"
}

# ─────────────────────────────────────────────
#  TASK 2: Command History Limits
# ─────────────────────────────────────────────
setup_task2() {
  echo -e "\n${BOLD}── TASK 2: Command History Configuration ─────────────────${RESET}"

  # Global defaults (applies to all users not overridden)
  cat > /etc/profile.d/globex_history.sh << 'HISTEOF'
# Globex Financial — Command History Policy
# Default: retain last 50 commands for audit trail
export HISTSIZE=50
export HISTFILESIZE=50
export HISTTIMEFORMAT="%Y-%m-%d %H:%M:%S "
export HISTCONTROL=""          # record ALL commands, no duplicates filtering
shopt -s histappend            # append to history file, don't overwrite
PROMPT_COMMAND="history -a"    # write every command immediately
HISTEOF
  chmod 644 /etc/profile.d/globex_history.sh

  # Senior analysts: 10 commands (minimal footprint / need-to-know)
  SENIOR_PROFILE="/etc/profile.d/globex_history_senior.sh"
  cat > "$SENIOR_PROFILE" << 'SENEOF'
# Globex Financial — Senior Analyst History Override
# Senior analysts retain last 10 commands only
if id -nG "$USER" 2>/dev/null | grep -qw "senior-analysts"; then
  export HISTSIZE=10
  export HISTFILESIZE=10
fi
SENEOF
  chmod 644 "$SENIOR_PROFILE"

  # Persist to /etc/environment for non-interactive sessions
  grep -q "HISTTIMEFORMAT" /etc/environment 2>/dev/null || \
    echo 'HISTTIMEFORMAT="%Y-%m-%d %H:%M:%S "' >> /etc/environment

  # Per-user .bashrc injection for existing users
  for user_home in /home/*/; do
    local username
    username=$(basename "$user_home")
    local bashrc="$user_home/.bashrc"
    if [[ -f "$bashrc" ]] && ! grep -q "GLOBEX_HIST" "$bashrc"; then
      cat >> "$bashrc" << 'BRCEOF'
# GLOBEX_HIST — sourced by profile.d
source /etc/profile.d/globex_history.sh
BRCEOF
    fi
  done

  # Record policy state for dashboard
  echo "default|50|$(date +%Y-%m-%dT%H:%M:%S)|active" >> "$DATA_DIR/history_policy.db"
  echo "senior-analysts|10|$(date +%Y-%m-%dT%H:%M:%S)|active" >> "$DATA_DIR/history_policy.db"

  log "Task 2 complete — default: 50 cmds, senior-analysts: 10 cmds"
}

# ─────────────────────────────────────────────
#  TASK 3: Rsyslog — Log Unauthorized Access
# ─────────────────────────────────────────────
setup_task3() {
  echo -e "\n${BOLD}── TASK 3: Rsyslog / Unauthorized Access Logging ─────────${RESET}"

  # Configure rsyslog to capture auth failures
  cat > /etc/rsyslog.d/10-globex-security.conf << 'RSYSEOF'
# Globex Financial — Security Event Logging
# Capture all auth/security messages
auth,authpriv.*                 /var/log/globex/auth.log
# ACL denials via kernel audit
kern.warning                    /var/log/globex/acl_deny.log
# Emergency + alert to security console
*.emerg                         :omusrmsg:globex_admin
# Structured JSON output for dashboard
module(load="mmjsonparse")
template(name="GlobexJSON" type="list") {
  constant(value="{")
  constant(value="\"timestamp\":\"")    property(name="timereported" dateFormat="rfc3339")
  constant(value="\",\"host\":\"")      property(name="hostname")
  constant(value="\",\"program\":\"")   property(name="programname")
  constant(value="\",\"facility\":\"")  property(name="syslogfacility-text")
  constant(value="\",\"severity\":\"")  property(name="syslogseverity-text")
  constant(value="\",\"message\":\"")   property(name="msg" format="json")
  constant(value="\"}\n")
}
auth,authpriv.*  action(type="omfile" file="/var/log/globex/security_events.jsonl"
                        template="GlobexJSON")
RSYSEOF

  # Set secure permissions on log directory
  chmod 750 /var/log/globex
  chown root:globex-users /var/log/globex
  chmod 640 /var/log/globex/*.log 2>/dev/null || true

  # Logrotate config
  cat > /etc/logrotate.d/globex << 'ROTEOF'
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
ROTEOF

  systemctl restart rsyslog
  log "Task 3 complete — logging to /var/log/globex/"
}

# ─────────────────────────────────────────────
#  TASK 4: Deploy Web Dashboard
# ─────────────────────────────────────────────
setup_task4() {
  echo -e "\n${BOLD}── TASK 4: Web Dashboard Deployment ──────────────────────${RESET}"

  # Copy dashboard app files (assumes they're in the same dir as this script)
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  cp -r "$SCRIPT_DIR/." "$DASHBOARD_DIR/"

  # Install Python dependencies
  pip3 install flask --quiet --break-system-packages

  # Create systemd service
  cat > /etc/systemd/system/globex-dashboard.service << SVCEOF
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
Environment=FLASK_ENV=production
Environment=GLOBEX_DATA_DIR=$DATA_DIR

[Install]
WantedBy=multi-user.target
SVCEOF

  systemctl daemon-reload
  systemctl enable globex-dashboard
  systemctl start globex-dashboard
  log "Task 4 complete — dashboard running at http://localhost:5050"
}

# ─────────────────────────────────────────────
#  TASK 5: Persistence Across Reboots
# ─────────────────────────────────────────────
setup_task5() {
  echo -e "\n${BOLD}── TASK 5: Persistence Configuration ─────────────────────${RESET}"

  # ACL persistence: rc.local re-applies ACLs on boot
  cat > /etc/globex_acl_restore.sh << 'ACLEOF'
#!/bin/bash
# Globex — Re-apply ACLs on boot
DATA_DIR="/opt/globex/data"
while IFS='|' read -r dir state owner group timestamp; do
  [[ -d "$dir" ]] || continue
  if [[ "$state" == "restricted" ]]; then
    setfacl -b "$dir"
    setfacl -m u:"$owner":rwx "$dir"
    setfacl -m d:u:"$owner":rwx "$dir"
    setfacl -m g:"$group":r-x "$dir"
    setfacl -m d:g:"$group":r-x "$dir"
    setfacl -m o::--- "$dir"
    setfacl -m d:o::--- "$dir"
  elif [[ "$state" == "relaxed" ]]; then
    setfacl -m g:"$group":rwx "$dir"
    setfacl -m d:g:"$group":rwx "$dir"
  fi
done < "$DATA_DIR/acl_state.db"
ACLEOF
  chmod +x /etc/globex_acl_restore.sh

  # Systemd service for ACL restore
  cat > /etc/systemd/system/globex-acl-restore.service << 'SVCEOF'
[Unit]
Description=Globex Financial ACL Restore
DefaultDependencies=no
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/etc/globex_acl_restore.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SVCEOF

  systemctl enable globex-acl-restore
  systemctl enable globex-dashboard

  # Ensure rsyslog starts on boot
  systemctl enable rsyslog

  # Cron job for audit summary (daily at midnight)
  (crontab -l 2>/dev/null; echo "0 0 * * * /opt/globex/dashboard/scripts/daily_audit.sh >> /var/log/globex/audit.log 2>&1") | crontab -

  log "Task 5 complete — all settings persist across reboots"
}

# ─────────────────────────────────────────────
#  MAIN ENTRYPOINT
# ─────────────────────────────────────────────
main() {
  print_banner
  check_root

  mkdir -p /var/log/globex
  touch "$LOGFILE"
  info "Setup started at $(date)"

  install_deps
  create_directories

  case "${1:-all}" in
    task1) setup_task1 ;;
    task2) setup_task2 ;;
    task3) setup_task3 ;;
    task4) setup_task4 ;;
    task5) setup_task5 ;;
    all)
      setup_task1
      setup_task2
      setup_task3
      setup_task4
      setup_task5
      ;;
    *)
      echo "Usage: $0 [all|task1|task2|task3|task4|task5]"
      exit 1
      ;;
  esac

  echo -e "\n${GREEN}${BOLD}══════════════════════════════════════════════════════${RESET}"
  echo -e "${GREEN}${BOLD}  GLOBEX SECURITY SETUP COMPLETE${RESET}"
  echo -e "${GREEN}  Dashboard: http://localhost:5050${RESET}"
  echo -e "${GREEN}  Logs:      /var/log/globex/${RESET}"
  echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════════${RESET}\n"
}

main "$@"
