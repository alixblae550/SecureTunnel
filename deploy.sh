#!/usr/bin/env bash
# =============================================================================
# SecureTunnel — VPS Auto-Deploy Script
#
# Usage:
#   curl -fsSL https://your-server/deploy.sh | bash -s -- --node exit --secret YOUR_SECRET
#
# Or copy this file to the VPS and run:
#   chmod +x deploy.sh
#   ./deploy.sh --node exit   --secret "your-long-random-secret"
#   ./deploy.sh --node middle --secret "your-long-random-secret" --exit-host 1.2.3.4
#   ./deploy.sh --node entry  --secret "your-long-random-secret" --exit-host 1.2.3.4 --middle-host 5.6.7.8
#
# What it does:
#   1. Installs Python 3.12+, pip, git
#   2. Copies SecureTunnel source (or clones if --repo given)
#   3. Installs Python dependencies
#   4. Generates TLS certificate (self-signed, 10 years)
#   5. Creates /etc/securetunnel/env  — environment config
#   6. Creates systemd service securetunnel-<node>.service
#   7. Enables and starts the service
#
# Supported OS: Ubuntu 20.04+, Debian 11+
# =============================================================================

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
NODE=""
AUTH_SECRET=""
ENTRY_HOST="127.0.0.1";  ENTRY_PORT="8765"
MIDDLE_HOST="127.0.0.1"; MIDDLE_PORT="8766"
EXIT_HOST="127.0.0.1";   EXIT_PORT="8767"
PORT=""          # override listen port (default per node)
RATE_LIMIT="60"  # higher limit for VPS (external IPs, not localhost)
INSTALL_DIR="/opt/securetunnel"
REPO_URL=""      # optional git repo URL

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[deploy]${NC} $*"; }
warn()  { echo -e "${YELLOW}[deploy]${NC} $*"; }
error() { echo -e "${RED}[deploy] ERROR:${NC} $*" >&2; exit 1; }

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --node)        NODE="$2";         shift 2 ;;
        --secret)      AUTH_SECRET="$2";  shift 2 ;;
        --entry-host)  ENTRY_HOST="$2";   shift 2 ;;
        --entry-port)  ENTRY_PORT="$2";   shift 2 ;;
        --middle-host) MIDDLE_HOST="$2";  shift 2 ;;
        --middle-port) MIDDLE_PORT="$2";  shift 2 ;;
        --exit-host)   EXIT_HOST="$2";    shift 2 ;;
        --exit-port)   EXIT_PORT="$2";    shift 2 ;;
        --port)        PORT="$2";         shift 2 ;;
        --install-dir) INSTALL_DIR="$2";  shift 2 ;;
        --repo)        REPO_URL="$2";     shift 2 ;;
        --rate-limit)  RATE_LIMIT="$2";   shift 2 ;;
        -h|--help)
            sed -n '3,20p' "$0" | sed 's/^# \?//'
            exit 0 ;;
        *) error "Unknown argument: $1" ;;
    esac
done

# ── Validation ────────────────────────────────────────────────────────────────
[[ -z "$NODE" ]] && error "Required: --node <exit|middle|entry>"
[[ "$NODE" != "exit" && "$NODE" != "middle" && "$NODE" != "entry" ]] && \
    error "--node must be one of: exit, middle, entry"
[[ -z "$AUTH_SECRET" ]] && error "Required: --secret <your-long-random-secret>"
[[ ${#AUTH_SECRET} -lt 32 ]] && \
    warn "AUTH_SECRET is short (${#AUTH_SECRET} chars). Recommend 64+ random chars."

# Default listen port per node
if [[ -z "$PORT" ]]; then
    case "$NODE" in
        exit)   PORT="$EXIT_PORT" ;;
        middle) PORT="$MIDDLE_PORT" ;;
        entry)  PORT="$ENTRY_PORT" ;;
    esac
fi

# ── Step 1: System dependencies ───────────────────────────────────────────────
info "Installing system dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
    python3 python3-pip python3-venv python3-dev \
    build-essential libssl-dev git curl openssl ufw 2>/dev/null || \
    error "Failed to install system packages. Run as root."

# Check Python version
PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
if [[ "$PY_MAJOR" -lt 3 || ("$PY_MAJOR" -eq 3 && "$PY_MINOR" -lt 11) ]]; then
    warn "Python $PY_VER detected. Installing Python 3.12..."
    apt-get install -y -qq software-properties-common
    add-apt-repository -y ppa:deadsnakes/ppa
    apt-get update -qq
    apt-get install -y -qq python3.12 python3.12-venv python3.12-dev
    PYTHON="python3.12"
else
    PYTHON="python3"
    info "Python $PY_VER OK."
fi

# ── Step 2: Copy or clone source ──────────────────────────────────────────────
info "Setting up install directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

if [[ -n "$REPO_URL" ]]; then
    info "Cloning from $REPO_URL..."
    if [[ -d "$INSTALL_DIR/.git" ]]; then
        git -C "$INSTALL_DIR" pull
    else
        git clone "$REPO_URL" "$INSTALL_DIR"
    fi
elif [[ -f "$(dirname "$0")/launcher.py" ]]; then
    # Script is inside the project directory — copy everything
    SRC="$(dirname "$(realpath "$0")")"
    info "Copying source from $SRC..."
    rsync -a --exclude='chrome_profile' --exclude='__pycache__' \
          --exclude='*.pyc' --exclude='.git' \
          "$SRC/" "$INSTALL_DIR/"
else
    error "No source found. Either run from project directory or pass --repo <git-url>"
fi

# ── Step 3: Python virtual environment + dependencies ─────────────────────────
info "Creating virtualenv and installing dependencies..."
$PYTHON -m venv "$INSTALL_DIR/.venv"
source "$INSTALL_DIR/.venv/bin/activate"

pip install -q --upgrade pip
pip install -q \
    "cryptography>=43.0.0" \
    "msgpack>=1.0" \
    "keyring>=24.0" \
    "aiohttp>=3.9"

# Verify ML-KEM is available
python3 -c "
from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEMParameters
print('[deploy] ML-KEM-768 (post-quantum) available.')
" 2>/dev/null || warn "ML-KEM not available — falling back to X25519-only. cryptography >= 43.0 required."

deactivate

# ── Step 4: TLS certificate ───────────────────────────────────────────────────
CERT="$INSTALL_DIR/cert.pem"
KEY="$INSTALL_DIR/key.pem"

if [[ ! -f "$CERT" || ! -f "$KEY" ]]; then
    info "Generating self-signed TLS certificate (10 years)..."
    openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
        -keyout "$KEY" -out "$CERT" \
        -subj "/CN=localhost/O=SecureTunnel/C=US" \
        -addext "subjectAltName=IP:127.0.0.1,IP:::1" 2>/dev/null
    chmod 600 "$KEY"
    info "Certificate generated."
else
    info "Certificate already exists — skipping."
fi

# ── Step 5: Environment config ────────────────────────────────────────────────
info "Writing environment config..."
mkdir -p /etc/securetunnel
cat > /etc/securetunnel/env <<EOF
# SecureTunnel — node: $NODE
# Generated by deploy.sh on $(date -u +"%Y-%m-%d %H:%M UTC")

AUTH_SECRET=$AUTH_SECRET

ENTRY_HOST=$ENTRY_HOST
ENTRY_PORT=$ENTRY_PORT
MIDDLE_HOST=$MIDDLE_HOST
MIDDLE_PORT=$MIDDLE_PORT
EXIT_HOST=$EXIT_HOST
EXIT_PORT=$EXIT_PORT

RATE_LIMIT=$RATE_LIMIT
PROBE_TIMEOUT=4.0
CIRCUIT_TTL=300
CIRCUIT_REQS=500
COVER_SNI=
EOF
chmod 600 /etc/securetunnel/env

# ── Step 6: systemd service ───────────────────────────────────────────────────
SERVICE_NAME="securetunnel-${NODE}"
MODULE_MAP_exit="secure_tunnel.exit_node"
MODULE_MAP_middle="secure_tunnel.node1"
MODULE_MAP_entry="secure_tunnel.entry_node"
eval "MODULE=\$MODULE_MAP_${NODE}"

info "Creating systemd service: $SERVICE_NAME..."
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=SecureTunnel ${NODE} node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nobody
Group=nogroup
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=/etc/securetunnel/env
ExecStart=$INSTALL_DIR/.venv/bin/python -m $MODULE
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal
SyslogIdentifier=securetunnel-${NODE}

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=$INSTALL_DIR

[Install]
WantedBy=multi-user.target
EOF

# ── Step 7: Firewall ──────────────────────────────────────────────────────────
info "Configuring firewall (UFW)..."
ufw allow ssh    2>/dev/null || true
ufw allow "$PORT/tcp" comment "SecureTunnel ${NODE}" 2>/dev/null || true
ufw --force enable 2>/dev/null || true

# ── Step 8: Enable and start ──────────────────────────────────────────────────
info "Enabling and starting $SERVICE_NAME..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"
sleep 2

# ── Status check ──────────────────────────────────────────────────────────────
if systemctl is-active --quiet "$SERVICE_NAME"; then
    info "✅ $SERVICE_NAME is running!"
else
    warn "Service did not start. Check logs with:"
    warn "  journalctl -u $SERVICE_NAME -n 50"
    systemctl status "$SERVICE_NAME" --no-pager || true
fi

# ── Summary ───────────────────────────────────────────────────────────────────
PUBLIC_IP=$(curl -s --max-time 5 ifconfig.me 2>/dev/null || echo "unknown")

echo ""
echo "════════════════════════════════════════════════════════"
echo "  SecureTunnel deploy complete"
echo "════════════════════════════════════════════════════════"
echo "  Node:        $NODE"
echo "  Listen port: $PORT"
echo "  Public IP:   $PUBLIC_IP"
echo "  Service:     $SERVICE_NAME"
echo "  Logs:        journalctl -u $SERVICE_NAME -f"
echo "  Config:      /etc/securetunnel/env"
echo "════════════════════════════════════════════════════════"
echo ""

case "$NODE" in
    exit)
    echo "  Next step — deploy MIDDLE node:"
    echo "  ./deploy.sh --node middle \\"
    echo "    --secret \"$AUTH_SECRET\" \\"
    echo "    --exit-host $PUBLIC_IP"
    ;;
    middle)
    echo "  Next step — deploy ENTRY node:"
    echo "  ./deploy.sh --node entry \\"
    echo "    --secret \"$AUTH_SECRET\" \\"
    echo "    --exit-host $EXIT_HOST \\"
    echo "    --middle-host $PUBLIC_IP"
    ;;
    entry)
    echo "  Next step — update launcher.py on your PC:"
    echo "  Set in environment or launcher config:"
    echo "    ENTRY_HOST=$PUBLIC_IP"
    echo "    MIDDLE_HOST=$MIDDLE_HOST"
    echo "    EXIT_HOST=$EXIT_HOST"
    echo "    AUTH_SECRET=<your-secret>"
    ;;
esac
echo ""
