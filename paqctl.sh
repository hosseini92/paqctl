#!/bin/bash
#
# ╔═══════════════════════════════════════════════════════════════════╗
# ║      PAQCTL - GFK Manager                                          ║
# ║                                                                   ║
# ║  One-click setup for GFW-knocker (GFK) tunnel                      ║
# ║                                                                   ║
# ║  * Installs Python deps (scapy, aioquic)                           ║
# ║  * Downloads GFK scripts (server/client)                           ║
# ║  * Generates QUIC TLS certs                                        ║
# ║  * Generates parameters.py                                         ║
# ║  * Optional iptables rules for server VIO port                     ║
# ║  * Auto-start on boot via systemd (if available)                   ║
# ╚═══════════════════════════════════════════════════════════════════╝
#
# Install:
# curl -fsSL https://raw.githubusercontent.com/hosseini92/paqctl/main/paqctl.sh | sudo bash
#

set -euo pipefail

if [ -z "${BASH_VERSION:-}" ]; then
  echo "Error: this script requires bash."
  exit 1
fi

VERSION="1.0.0-gfk"

INSTALL_DIR="${INSTALL_DIR:-/opt/paqctl}"
GFK_DIR="${INSTALL_DIR}/gfk"
VENV_DIR="${INSTALL_DIR}/venv"
SETTINGS_FILE="${INSTALL_DIR}/settings.conf"
SERVICE_FILE="/etc/systemd/system/paqctl.service"
PID_FILE="/run/paqctl.pid"
LOG_FILE="/var/log/gfk-backend.log"

GFK_REPO="${GFK_REPO:-hosseini92/paqctl}"
GFK_BRANCH="${GFK_BRANCH:-main}"
GFK_RAW_URL="https://raw.githubusercontent.com/${GFK_REPO}/${GFK_BRANCH}/gfk"
PAQCTL_SCRIPT_URL="${PAQCTL_SCRIPT_URL:-https://raw.githubusercontent.com/${GFK_REPO}/${GFK_BRANCH}/paqctl.sh}"

# Defaults (match README)
BACKEND="gfw-knocker"
ROLE="${ROLE:-}"
GFK_SERVER_IP="${GFK_SERVER_IP:-}"
GFK_VIO_PORT="${GFK_VIO_PORT:-45000}"            # server VIO TCP port
GFK_VIO_CLIENT_PORT="${GFK_VIO_CLIENT_PORT:-40000}"
GFK_VIO_UDP_SERVER="${GFK_VIO_UDP_SERVER:-35000}"
GFK_VIO_UDP_CLIENT="${GFK_VIO_UDP_CLIENT:-30000}"
GFK_QUIC_PORT="${GFK_QUIC_PORT:-25000}"          # server QUIC port
GFK_QUIC_CLIENT_PORT="${GFK_QUIC_CLIENT_PORT:-20000}"
GFK_AUTH_CODE="${GFK_AUTH_CODE:-}"
GFK_TCP_FLAGS="${GFK_TCP_FLAGS:-AP}"
GFK_TCP_MAPPINGS="${GFK_TCP_MAPPINGS:-}"         # client only, "l:r,l:r"
GFK_UDP_MAPPINGS="${GFK_UDP_MAPPINGS:-}"         # client only, "l:r,l:r"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

print_header() {
  echo -e "${CYAN}"
  echo "╔════════════════════════════════════════════════════════════════╗"
  echo "║                 PAQCTL - GFK Manager (${VERSION})              ║"
  echo "╚════════════════════════════════════════════════════════════════╝"
  echo -e "${NC}"
}

log_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[✓]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
log_error()   { echo -e "${RED}[✗]${NC} $*"; }

check_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    log_error "This command must be run as root (use sudo)."
    exit 1
  fi
}

has_systemd() {
  command -v systemctl &>/dev/null && [ -d /run/systemd/system ]
}

get_self_path() {
  # Best effort: returns an on-disk path to this script when available.
  # When executed via "curl ... | bash" there is no file to copy.
  local src="${BASH_SOURCE[0]:-}"
  if [ -n "$src" ] && [ -f "$src" ] && [ "$src" != "bash" ]; then
    realpath "$src" 2>/dev/null || readlink -f "$src" 2>/dev/null || echo "$src"
  else
    echo ""
  fi
}

detect_os_pkg_manager() {
  PKG_MANAGER="unknown"
  if command -v apt-get &>/dev/null; then
    PKG_MANAGER="apt"
  elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf"
  elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum"
  elif command -v pacman &>/dev/null; then
    PKG_MANAGER="pacman"
  elif command -v zypper &>/dev/null; then
    PKG_MANAGER="zypper"
  elif command -v apk &>/dev/null; then
    PKG_MANAGER="apk"
  fi
}

install_packages() {
  local pkgs=("$@")
  detect_os_pkg_manager
  case "$PKG_MANAGER" in
    apt)
      DEBIAN_FRONTEND=noninteractive apt-get update -y
      DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}"
      ;;
    dnf) dnf install -y "${pkgs[@]}" ;;
    yum) yum install -y "${pkgs[@]}" ;;
    pacman) pacman -Sy --noconfirm "${pkgs[@]}" ;;
    zypper) zypper --non-interactive install "${pkgs[@]}" ;;
    apk) apk add --no-cache "${pkgs[@]}" ;;
    *)
      log_error "Unsupported package manager. Please install: ${pkgs[*]}"
      return 1
      ;;
  esac
}

ensure_deps() {
  log_info "Installing dependencies..."
  # iptables is optional but recommended for server.
  detect_os_pkg_manager
  local iproute_pkg="iproute2"
  case "$PKG_MANAGER" in
    dnf|yum) iproute_pkg="iproute" ;;
  esac
  install_packages curl ca-certificates openssl python3 python3-venv python3-pip "$iproute_pkg" || return 1
  if ! command -v iptables &>/dev/null; then
    log_warn "iptables not found. Server firewall rules will be skipped."
  fi
  log_success "Dependencies installed"
}

ensure_dirs() {
  mkdir -p "$INSTALL_DIR" "$GFK_DIR"
  chmod 700 "$INSTALL_DIR" "$GFK_DIR" 2>/dev/null || true
}

install_python_deps() {
  log_info "Setting up Python virtualenv..."
  ensure_dirs
  if [ ! -x "${VENV_DIR}/bin/python" ]; then
    python3 -m venv "$VENV_DIR"
  fi
  "${VENV_DIR}/bin/pip" install --upgrade pip >/dev/null
  "${VENV_DIR}/bin/pip" install scapy aioquic >/dev/null
  log_success "Python deps installed (scapy, aioquic)"
}

download_gfk() {
  log_info "Downloading GFK scripts..."
  ensure_dirs

  local server_files=(mainserver.py quic_server.py vio_server.py)
  local client_files=(mainclient.py quic_client.py vio_client.py)
  local f

  for f in "${server_files[@]}"; do
    curl -fsSL "${GFK_RAW_URL}/server/${f}" -o "${GFK_DIR}/${f}"
  done
  for f in "${client_files[@]}"; do
    curl -fsSL "${GFK_RAW_URL}/client/${f}" -o "${GFK_DIR}/${f}"
  done

  chmod 600 "${GFK_DIR}/"*.py
  log_success "GFK scripts installed in ${GFK_DIR}"
}

generate_certs() {
  if [ -f "${GFK_DIR}/cert.pem" ] && [ -f "${GFK_DIR}/key.pem" ]; then
    return 0
  fi
  log_info "Generating QUIC TLS certificate..."
  openssl req -x509 -newkey rsa:2048 \
    -keyout "${GFK_DIR}/key.pem" -out "${GFK_DIR}/cert.pem" \
    -days 3650 -nodes -subj "/CN=gfk" >/dev/null 2>&1
  chmod 600 "${GFK_DIR}/key.pem" "${GFK_DIR}/cert.pem"
  log_success "Certificates generated"
}

_validate_ip() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local o1 o2 o3 o4
  IFS='.' read -r o1 o2 o3 o4 <<<"$ip"
  for o in "$o1" "$o2" "$o3" "$o4"; do
    [ "$o" -ge 0 ] 2>/dev/null && [ "$o" -le 255 ] 2>/dev/null || return 1
  done
  return 0
}

_validate_port() {
  local p="$1"
  [[ "$p" =~ ^[0-9]+$ ]] || return 1
  [ "$p" -ge 1 ] && [ "$p" -le 65535 ]
}

_escape_py_string() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//\'/\\\'}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  printf '%s' "$s"
}

_parse_mapping_to_pydict() {
  # input: "l:r,l:r"  output: "{l: r, ...}" or "{}"
  local input="${1:-}"
  local mapping_str="{"
  local first=true

  input="$(echo "$input" | tr -d ' ' )"
  if [ -z "$input" ]; then
    echo "{}"
    return 0
  fi

  local pair lport rport
  IFS=',' read -r -a pairs <<<"$input"
  for pair in "${pairs[@]}"; do
    lport="${pair%%:*}"
    rport="${pair##*:}"
    _validate_port "$lport" || { log_error "Invalid mapping local port: $lport"; return 1; }
    _validate_port "$rport" || { log_error "Invalid mapping remote port: $rport"; return 1; }
    if [ "$first" = true ]; then
      mapping_str="${mapping_str}${lport}: ${rport}"
      first=false
    else
      mapping_str="${mapping_str}, ${lport}: ${rport}"
    fi
  done
  mapping_str="${mapping_str}}"
  echo "$mapping_str"
}

generate_parameters() {
  ensure_dirs

  if [ -z "${ROLE:-}" ]; then
    log_error "ROLE is not set"
    return 1
  fi

  if [ -z "${GFK_SERVER_IP:-}" ] || ! _validate_ip "$GFK_SERVER_IP"; then
    log_error "Invalid server IP: ${GFK_SERVER_IP:-<empty>}"
    return 1
  fi

  local safe_server_ip safe_auth safe_dir
  safe_server_ip="$(_escape_py_string "$GFK_SERVER_IP")"
  safe_auth="$(_escape_py_string "$GFK_AUTH_CODE")"
  safe_dir="$(_escape_py_string "$GFK_DIR")"

  local tcp_dict udp_dict
  if [ "$ROLE" = "client" ]; then
    tcp_dict="$(_parse_mapping_to_pydict "${GFK_TCP_MAPPINGS:-}")"
    udp_dict="$(_parse_mapping_to_pydict "${GFK_UDP_MAPPINGS:-}")"
  else
    tcp_dict="{}"
    udp_dict="{}"
  fi

  local tmp
  tmp="$(mktemp "${GFK_DIR}/parameters.py.XXXXXX")"
  (
    umask 077
    cat >"$tmp" <<PYEOF
# GFW-knocker parameters - auto-generated by paqctl (GFK-only)
# Do not edit manually (except udp_port_mapping / tcp_port_mapping if you know what you're doing)

vps_ip = "${safe_server_ip}"
# Name kept for compatibility with upstream GFK code:
xray_server_ip_address = "127.0.0.1"

tcp_port_mapping = ${tcp_dict}
udp_port_mapping = ${udp_dict}

vio_tcp_server_port = ${GFK_VIO_PORT}
vio_tcp_client_port = ${GFK_VIO_CLIENT_PORT}
vio_udp_server_port = ${GFK_VIO_UDP_SERVER}
vio_udp_client_port = ${GFK_VIO_UDP_CLIENT}

quic_server_port = ${GFK_QUIC_PORT}
quic_client_port = ${GFK_QUIC_CLIENT_PORT}
quic_local_ip = "127.0.0.1"

quic_idle_timeout = 86400
udp_timeout = 300
quic_mtu = 1420
quic_verify_cert = False
quic_max_data = 1073741824
quic_max_stream_data = 1073741824

quic_auth_code = "${safe_auth}"
quic_cert_filepath = ("${safe_dir}/cert.pem", "${safe_dir}/key.pem")

tcp_flags = "${GFK_TCP_FLAGS}"
PYEOF
  )
  mv -f "$tmp" "${GFK_DIR}/parameters.py"
  chmod 600 "${GFK_DIR}/parameters.py"
  log_success "Generated ${GFK_DIR}/parameters.py"
}

save_settings() {
  ensure_dirs
  local tmp
  tmp="$(mktemp "${SETTINGS_FILE}.XXXXXX")"
  (
    umask 077
    cat >"$tmp" <<EOF
BACKEND="${BACKEND}"
ROLE="${ROLE}"
GFK_SERVER_IP="${GFK_SERVER_IP}"
GFK_VIO_PORT="${GFK_VIO_PORT}"
GFK_VIO_CLIENT_PORT="${GFK_VIO_CLIENT_PORT}"
GFK_VIO_UDP_SERVER="${GFK_VIO_UDP_SERVER}"
GFK_VIO_UDP_CLIENT="${GFK_VIO_UDP_CLIENT}"
GFK_QUIC_PORT="${GFK_QUIC_PORT}"
GFK_QUIC_CLIENT_PORT="${GFK_QUIC_CLIENT_PORT}"
GFK_AUTH_CODE="${GFK_AUTH_CODE}"
GFK_TCP_FLAGS="${GFK_TCP_FLAGS}"
GFK_TCP_MAPPINGS="${GFK_TCP_MAPPINGS}"
GFK_UDP_MAPPINGS="${GFK_UDP_MAPPINGS}"
EOF
  )
  mv -f "$tmp" "$SETTINGS_FILE"
  chmod 600 "$SETTINGS_FILE" 2>/dev/null || true
}

load_settings() {
  [ -f "$SETTINGS_FILE" ] || return 0
  while IFS='=' read -r key value; do
    [[ "$key" =~ ^[A-Z_][A-Z_0-9]*$ ]] || continue
    value="${value#\"}"; value="${value%\"}"
    # Skip values with dangerous shell characters
    [[ "$value" =~ [\`\$\(] ]] && continue
    case "$key" in
      ROLE) ROLE="$value" ;;
      GFK_SERVER_IP) GFK_SERVER_IP="$value" ;;
      GFK_VIO_PORT) GFK_VIO_PORT="$value" ;;
      GFK_VIO_CLIENT_PORT) GFK_VIO_CLIENT_PORT="$value" ;;
      GFK_VIO_UDP_SERVER) GFK_VIO_UDP_SERVER="$value" ;;
      GFK_VIO_UDP_CLIENT) GFK_VIO_UDP_CLIENT="$value" ;;
      GFK_QUIC_PORT) GFK_QUIC_PORT="$value" ;;
      GFK_QUIC_CLIENT_PORT) GFK_QUIC_CLIENT_PORT="$value" ;;
      GFK_AUTH_CODE) GFK_AUTH_CODE="$value" ;;
      GFK_TCP_FLAGS) GFK_TCP_FLAGS="$value" ;;
      GFK_TCP_MAPPINGS) GFK_TCP_MAPPINGS="$value" ;;
      GFK_UDP_MAPPINGS) GFK_UDP_MAPPINGS="$value" ;;
    esac
  done < <(grep '^[A-Z_][A-Z_0-9]*=' "$SETTINGS_FILE")
}

detect_public_ip() {
  local ip=""
  ip="$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' || true)"
  [ -z "$ip" ] && ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  echo "$ip"
}

wizard() {
  echo ""
  echo -e "${BOLD}Select role:${NC}"
  echo "  1) Server (System B)"
  echo "  2) Client (System A)"
  echo ""
  local choice input
  read -r -p "Role [1/2]: " choice < /dev/tty || true
  case "$choice" in
    1) ROLE="server" ;;
    2) ROLE="client" ;;
    *) log_error "Invalid role"; return 1 ;;
  esac

  local detected
  detected="$(detect_public_ip)"

  if [ "$ROLE" = "server" ]; then
    echo ""
    echo -e "${BOLD}This server public IP${NC} [${detected}]:"
    read -r -p "IP: " input < /dev/tty || true
    GFK_SERVER_IP="${input:-$detected}"
  else
    echo ""
    echo -e "${BOLD}GFK server IP (System B)${NC}:"
    read -r -p "IP: " input < /dev/tty || true
    GFK_SERVER_IP="$input"
  fi

  if [ -z "$GFK_SERVER_IP" ] || ! _validate_ip "$GFK_SERVER_IP"; then
    log_error "Valid IPv4 address is required."
    return 1
  fi

  echo ""
  echo -e "${BOLD}VIO TCP server port${NC} [${GFK_VIO_PORT}]:"
  read -r -p "Port: " input < /dev/tty || true
  [ -n "$input" ] && GFK_VIO_PORT="$input"
  _validate_port "$GFK_VIO_PORT" || { log_error "Invalid port"; return 1; }

  echo ""
  echo -e "${BOLD}QUIC server port${NC} [${GFK_QUIC_PORT}]:"
  read -r -p "Port: " input < /dev/tty || true
  [ -n "$input" ] && GFK_QUIC_PORT="$input"
  _validate_port "$GFK_QUIC_PORT" || { log_error "Invalid port"; return 1; }

  echo ""
  echo -e "${BOLD}Auth code${NC} [auto-generate]:"
  read -r -p "Code: " input < /dev/tty || true
  if [ -n "$input" ]; then
    GFK_AUTH_CODE="$input"
  else
    GFK_AUTH_CODE="$(openssl rand -hex 16 2>/dev/null || date +%s)"
  fi

  echo ""
  echo -e "${BOLD}Outgoing TCP flags${NC} [${GFK_TCP_FLAGS}] (default AP):"
  read -r -p "Flags: " input < /dev/tty || true
  if [ -n "$input" ]; then
    if ! [[ "$input" =~ ^[FSRPAUEC]+$ ]]; then
      log_error "Invalid flags. Use uppercase letters like AP, SA, etc."
      return 1
    fi
    GFK_TCP_FLAGS="$input"
  fi

  # Client-only ports + mappings
  if [ "$ROLE" = "client" ]; then
    echo ""
    echo -e "${BOLD}Local VIO TCP client port${NC} [${GFK_VIO_CLIENT_PORT}]:"
    read -r -p "Port: " input < /dev/tty || true
    [ -n "$input" ] && GFK_VIO_CLIENT_PORT="$input"
    _validate_port "$GFK_VIO_CLIENT_PORT" || { log_error "Invalid port"; return 1; }

    echo ""
    echo -e "${BOLD}Local QUIC client port${NC} [${GFK_QUIC_CLIENT_PORT}]:"
    read -r -p "Port: " input < /dev/tty || true
    [ -n "$input" ] && GFK_QUIC_CLIENT_PORT="$input"
    _validate_port "$GFK_QUIC_CLIENT_PORT" || { log_error "Invalid port"; return 1; }

    echo ""
    echo -e "${BOLD}TCP port mappings${NC} (local:remote comma-separated) [empty]:"
    echo -e "  ${DIM}Example: 14000:443,15000:2096${NC}"
    read -r -p "Mappings: " input < /dev/tty || true
    GFK_TCP_MAPPINGS="$input"

    echo ""
    echo -e "${BOLD}UDP port mappings${NC} (local:remote comma-separated) [empty]:"
    echo -e "  ${DIM}Example (WireGuard): 51830:51820${NC}"
    read -r -p "Mappings: " input < /dev/tty || true
    GFK_UDP_MAPPINGS="$input"
  fi
}

_apply_firewall() {
  load_settings
  [ "${ROLE:-}" = "server" ] || return 0
  command -v iptables &>/dev/null || return 0

  local vio_port="${GFK_VIO_PORT:-45000}"
  local TAG="paqctl"
  modprobe iptable_raw 2>/dev/null || true

  # Bypass conntrack for VIO traffic
  iptables -t raw -C PREROUTING -p tcp --dport "$vio_port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || \
    iptables -t raw -A PREROUTING -p tcp --dport "$vio_port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || true
  iptables -t raw -C OUTPUT -p tcp --sport "$vio_port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || \
    iptables -t raw -A OUTPUT -p tcp --sport "$vio_port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || true

  # Drop kernel-handled TCP on VIO port (scapy sniffer handles it)
  iptables -C INPUT -p tcp --dport "$vio_port" -m comment --comment "$TAG" -j DROP 2>/dev/null || \
    iptables -A INPUT -p tcp --dport "$vio_port" -m comment --comment "$TAG" -j DROP 2>/dev/null || true

  # Drop outgoing RST that kernel might emit
  iptables -C OUTPUT -p tcp --sport "$vio_port" --tcp-flags RST RST -m comment --comment "$TAG" -j DROP 2>/dev/null || \
    iptables -A OUTPUT -p tcp --sport "$vio_port" --tcp-flags RST RST -m comment --comment "$TAG" -j DROP 2>/dev/null || true

  # Best-effort IPv6 (no NOTRACK here)
  if command -v ip6tables &>/dev/null; then
    ip6tables -C INPUT -p tcp --dport "$vio_port" -m comment --comment "$TAG" -j DROP 2>/dev/null || \
      ip6tables -A INPUT -p tcp --dport "$vio_port" -m comment --comment "$TAG" -j DROP 2>/dev/null || true
    ip6tables -C OUTPUT -p tcp --sport "$vio_port" --tcp-flags RST RST -m comment --comment "$TAG" -j DROP 2>/dev/null || \
      ip6tables -A OUTPUT -p tcp --sport "$vio_port" --tcp-flags RST RST -m comment --comment "$TAG" -j DROP 2>/dev/null || true
  fi
}

_remove_firewall() {
  load_settings
  command -v iptables &>/dev/null || return 0
  local vio_port="${GFK_VIO_PORT:-45000}"
  local TAG="paqctl"

  iptables -t raw -D PREROUTING -p tcp --dport "$vio_port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || true
  iptables -t raw -D OUTPUT -p tcp --sport "$vio_port" -m comment --comment "$TAG" -j NOTRACK 2>/dev/null || true
  iptables -D INPUT -p tcp --dport "$vio_port" -m comment --comment "$TAG" -j DROP 2>/dev/null || true
  iptables -D OUTPUT -p tcp --sport "$vio_port" --tcp-flags RST RST -m comment --comment "$TAG" -j DROP 2>/dev/null || true

  if command -v ip6tables &>/dev/null; then
    ip6tables -D INPUT -p tcp --dport "$vio_port" -m comment --comment "$TAG" -j DROP 2>/dev/null || true
    ip6tables -D OUTPUT -p tcp --sport "$vio_port" --tcp-flags RST RST -m comment --comment "$TAG" -j DROP 2>/dev/null || true
  fi
}

setup_service() {
  load_settings
  if ! has_systemd; then
    log_warn "systemd not found; will run in foreground when started manually."
    return 0
  fi

  local exec_start
  if [ "${ROLE:-}" = "server" ]; then
    exec_start="${VENV_DIR}/bin/python ${GFK_DIR}/mainserver.py"
  else
    exec_start="${VENV_DIR}/bin/python ${GFK_DIR}/mainclient.py"
  fi

  cat >"$SERVICE_FILE" <<EOF
[Unit]
Description=PAQCTL GFK Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${GFK_DIR}
ExecStartPre=/usr/local/bin/paqctl _apply-firewall
ExecStart=${exec_start}
ExecStopPost=/usr/local/bin/paqctl _remove-firewall
Restart=on-failure
RestartSec=3
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal
SyslogIdentifier=paqctl

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl enable paqctl.service >/dev/null 2>&1 || true
  log_success "systemd service installed: paqctl.service"
}

start() {
  load_settings
  if has_systemd; then
    systemctl start paqctl.service
    return 0
  fi

  log_warn "No systemd; starting in background with PID file."
  _apply_firewall
  (umask 077; touch "$LOG_FILE"; chmod 600 "$LOG_FILE" 2>/dev/null || true)
  if [ "${ROLE:-}" = "server" ]; then
    nohup "${VENV_DIR}/bin/python" "${GFK_DIR}/mainserver.py" >>"$LOG_FILE" 2>&1 &
  else
    nohup "${VENV_DIR}/bin/python" "${GFK_DIR}/mainclient.py" >>"$LOG_FILE" 2>&1 &
  fi
  echo $! >"$PID_FILE"
}

stop() {
  load_settings
  if has_systemd; then
    systemctl stop paqctl.service >/dev/null 2>&1 || true
    return 0
  fi
  if [ -f "$PID_FILE" ]; then
    local pid
    pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    rm -f "$PID_FILE"
  fi
  pkill -f "${GFK_DIR}/mainserver.py" 2>/dev/null || true
  pkill -f "${GFK_DIR}/mainclient.py" 2>/dev/null || true
  pkill -f "${GFK_DIR}/quic_.*\\.py" 2>/dev/null || true
  pkill -f "${GFK_DIR}/vio_.*\\.py" 2>/dev/null || true
  _remove_firewall
}

restart() {
  stop
  sleep 1
  start
}

status() {
  load_settings
  echo -e "${BOLD}Backend:${NC} ${BACKEND}"
  echo -e "${BOLD}Role:${NC}    ${ROLE:-unknown}"
  echo -e "${BOLD}Server:${NC}  ${GFK_SERVER_IP:-unknown}"
  echo -e "${BOLD}VIO:${NC}     tcp/${GFK_VIO_PORT:-?}"
  echo -e "${BOLD}QUIC:${NC}    udp/${GFK_QUIC_PORT:-?} (inside tunnel)"
  if [ "${ROLE:-}" = "client" ]; then
    echo -e "${BOLD}TCP map:${NC} ${GFK_TCP_MAPPINGS:-<none>}"
    echo -e "${BOLD}UDP map:${NC} ${GFK_UDP_MAPPINGS:-<none>}"
  fi
  echo ""
  if has_systemd; then
    systemctl is-active --quiet paqctl.service && echo -e "${GREEN}● Running${NC}" || echo -e "${RED}● Stopped${NC}"
    systemctl --no-pager -l status paqctl.service 2>/dev/null | sed -n '1,12p' || true
  else
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE" 2>/dev/null || echo 0)" 2>/dev/null; then
      echo -e "${GREEN}● Running${NC} (pid $(cat "$PID_FILE"))"
    else
      echo -e "${RED}● Stopped${NC}"
    fi
  fi
}

logs() {
  if has_systemd; then
    journalctl -u paqctl.service -f --no-pager -n 100
  else
    echo "Logs: ${LOG_FILE}"
    tail -n 200 "$LOG_FILE"
  fi
}

show_info() {
  load_settings
  echo ""
  echo -e "${BOLD}GFK Connection Info${NC}"
  echo "  Role:        ${ROLE:-unknown}"
  echo "  Server IP:   ${GFK_SERVER_IP:-unknown}"
  echo "  VIO port:    ${GFK_VIO_PORT:-45000} (TCP)"
  echo "  QUIC port:   ${GFK_QUIC_PORT:-25000} (carried inside tunnel)"
  echo "  Auth code:   ${GFK_AUTH_CODE:-<unset>}"
  if [ "${ROLE:-}" = "client" ]; then
    echo "  TCP mapping: ${GFK_TCP_MAPPINGS:-<none>}"
    echo "  UDP mapping: ${GFK_UDP_MAPPINGS:-<none>}"
  fi
  echo ""
}

change_config() {
  check_root
  load_settings
  log_warn "This will regenerate ${GFK_DIR}/parameters.py and restart the service."
  local confirm
  read -r -p "Continue? [y/N]: " confirm < /dev/tty || true
  [[ "$confirm" =~ ^[Yy]$ ]] || return 0

  # If user runs "paqctl config" on a partially installed system, ensure components exist.
  if [ ! -x "${VENV_DIR}/bin/python" ]; then
    install_python_deps || return 1
  fi
  if [ ! -f "${GFK_DIR}/mainserver.py" ] || [ ! -f "${GFK_DIR}/mainclient.py" ]; then
    download_gfk || return 1
  fi
  generate_certs || return 1

  wizard || return 1
  save_settings
  generate_parameters
  setup_service || true
  restart || true
  log_success "Configuration updated"
}

uninstall() {
  check_root
  load_settings
  log_warn "Uninstalling paqctl (GFK-only)."
  stop || true

  if has_systemd; then
    systemctl disable paqctl.service >/dev/null 2>&1 || true
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
  rm -f /usr/local/bin/paqctl 2>/dev/null || true
  rm -rf "$INSTALL_DIR" 2>/dev/null || true
  log_success "Uninstalled"
}

install_management_script() {
  check_root
  ensure_dirs

  local src="${1:-}"
  if [ -n "$src" ] && [ -f "$src" ]; then
    cp -f "$src" "${INSTALL_DIR}/paqctl"
  else
    curl -fsSL "$PAQCTL_SCRIPT_URL" -o "${INSTALL_DIR}/paqctl"
  fi
  chmod 755 "${INSTALL_DIR}/paqctl"
  ln -sf "${INSTALL_DIR}/paqctl" /usr/local/bin/paqctl
  log_success "Installed management command: /usr/local/bin/paqctl"
}

show_menu() {
  check_root
  load_settings

  while true; do
    echo ""
    print_header
    echo -e "${BOLD}Installed config:${NC}"
    echo "  Role:   ${ROLE:-<not configured>}"
    echo "  Server: ${GFK_SERVER_IP:-<unset>}"
    echo ""
    echo -e "${BOLD}Menu:${NC}"
    echo "  1) Status"
    echo "  2) Start"
    echo "  3) Stop"
    echo "  4) Restart"
    echo "  5) Info"
    echo "  6) Logs"
    echo "  7) Configure"
    echo "  8) Uninstall"
    echo "  0) Exit"
    echo ""
    local choice
    read -r -p "Choice [0-8]: " choice < /dev/tty || true
    case "$choice" in
      1) status ;;
      2) start ;;
      3) stop ;;
      4) restart ;;
      5) show_info ;;
      6) logs ;;
      7) change_config ;;
      8) uninstall; return 0 ;;
      0) return 0 ;;
      *) log_warn "Invalid choice: $choice" ;;
    esac
    load_settings
  done
}

install_flow() {
  check_root
  print_header

  ensure_deps
  load_settings

  echo ""
  if [ -f "$SETTINGS_FILE" ]; then
    echo -e "${YELLOW}Existing install detected.${NC}"
    echo "  1) Reconfigure"
    echo "  2) Reinstall scripts/deps"
    echo "  3) Exit"
    local choice
    read -r -p "Choice [1-3]: " choice < /dev/tty || true
    case "$choice" in
      1) change_config; return 0 ;;
      2) ;;
      *) return 0 ;;
    esac
  fi

  wizard
  install_python_deps
  download_gfk
  generate_certs
  generate_parameters
  save_settings
  install_management_script "$(get_self_path)"
  setup_service || true

  echo ""
  log_info "Starting service..."
  start || true
  sleep 1
  status || true

  echo ""
  log_success "Done."
  echo -e "Run: ${BOLD}sudo paqctl info${NC} to see connection details."
}

show_help() {
  cat <<EOF
paqctl (GFK-only) - commands:
  install         Install / setup GFK
  menu            Interactive menu (status/start/stop/config/etc)
  config          Change configuration (regenerates parameters.py)
  start|stop|restart
  status
  info
  logs
  uninstall
  version

Internal:
  _apply-firewall
  _remove-firewall
EOF
}

case "${1:-install}" in
  install)         install_flow ;;
  menu)            show_menu ;;
  config)          change_config ;;
  start)           check_root; start ;;
  stop)            check_root; stop ;;
  restart)         check_root; restart ;;
  status)          status ;;
  info)            show_info ;;
  logs)            logs ;;
  uninstall)       uninstall ;;
  version)         echo "$VERSION" ;;
  help|-h|--help)  show_help ;;
  _apply-firewall) check_root; _apply_firewall ;;
  _remove-firewall) check_root; _remove_firewall ;;
  *)
    log_error "Unknown command: $1"
    show_help
    exit 1
    ;;
esac

