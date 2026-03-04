#!/bin/bash
set -euo pipefail

# =============================================================================
# dnstt / slipstream-rust + dnstt-dns-scanner + xray install script
# Supports: Linux amd64/arm64, macOS amd64/arm64
# =============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()     { error "$*"; exit 1; }

# ---------------------------------------------------------------------------
# Step 1 — Detect OS / Arch
# ---------------------------------------------------------------------------
detect_platform() {
    local os arch
    os=$(uname -s)
    arch=$(uname -m)

    case "$os" in
        Linux)  OS_NAME="linux" ;;
        Darwin) OS_NAME="darwin" ;;
        *)      die "Unsupported OS: $os. This script supports Linux and macOS only." ;;
    esac

    case "$arch" in
        x86_64)          ARCH_NAME="amd64" ;;
        aarch64 | arm64) ARCH_NAME="arm64" ;;
        *)               die "Unsupported architecture: $arch. Only amd64 and arm64 are supported." ;;
    esac

    # Xray asset names
    if [ "$OS_NAME" = "linux" ] && [ "$ARCH_NAME" = "amd64" ]; then
        XRAY_ASSET="Xray-linux-64.zip"
    elif [ "$OS_NAME" = "linux" ] && [ "$ARCH_NAME" = "arm64" ]; then
        XRAY_ASSET="Xray-linux-arm64-v8a.zip"
    elif [ "$OS_NAME" = "darwin" ] && [ "$ARCH_NAME" = "amd64" ]; then
        XRAY_ASSET="Xray-macos-64.zip"
    elif [ "$OS_NAME" = "darwin" ] && [ "$ARCH_NAME" = "arm64" ]; then
        XRAY_ASSET="Xray-macos-arm64-v8a.zip"
    fi

    DNSTT_CLIENT_ASSET="dnstt-client-${OS_NAME}-${ARCH_NAME}"
    SCANNER_ASSET="dnstt-dns-scanner-${OS_NAME}-${ARCH_NAME}"
    SLIPSTREAM_ASSET="slipstream-client-${OS_NAME}-${ARCH_NAME}"

    info "Detected platform: $OS_NAME / $ARCH_NAME"
}

# ---------------------------------------------------------------------------
# Step 2 — Ask install directory
# ---------------------------------------------------------------------------
ask_install_dir() {
    local default_dir="$HOME/dnstt-setup"
    echo ""
    echo -e "${CYAN}Enter install directory [default: $default_dir]:${NC} \c"
    read -r input_dir
    INSTALL_DIR="${input_dir:-$default_dir}"
    INSTALL_DIR="${INSTALL_DIR/#\~/$HOME}"
    mkdir -p "$INSTALL_DIR"
    success "Install directory: $INSTALL_DIR"
}

# ---------------------------------------------------------------------------
# Step 3 — Check/install dependencies
# ---------------------------------------------------------------------------
check_deps() {
    info "Checking dependencies..."

    if ! command -v curl &>/dev/null; then
        die "curl is required but not found. Please install curl and re-run."
    fi

    if ! command -v unzip &>/dev/null; then
        warn "unzip not found. Attempting to install..."
        if command -v apt-get &>/dev/null; then
            sudo apt-get install -y unzip || die "Failed to install unzip. Please install it manually and re-run."
        elif command -v brew &>/dev/null; then
            brew install unzip || die "Failed to install unzip. Please install it manually and re-run."
        else
            die "Cannot auto-install unzip. Please install it manually (e.g. 'sudo apt-get install unzip') and re-run."
        fi
    fi

    success "Dependencies OK"
}

# ---------------------------------------------------------------------------
# Step 3b — Choose tunnel mode
# ---------------------------------------------------------------------------
ask_tunnel_mode() {
    echo ""
    echo -e "${CYAN}=== Tunnel Mode ===${NC}"
    echo "  1) dnstt only"
    echo "  2) slipstream-rust only"
    echo "  3) Both (half instances dnstt, half slipstream-rust)"
    echo -e "${CYAN}Enter your choice [default: 1]:${NC} \c"
    read -r mode_choice
    TUNNEL_MODE="${mode_choice:-1}"
    case "$TUNNEL_MODE" in
        1) success "Mode: dnstt only" ;;
        2) success "Mode: slipstream-rust only" ;;
        3) success "Mode: Both (dnstt + slipstream-rust)" ;;
        *) warn "Invalid choice, defaulting to dnstt only."; TUNNEL_MODE=1 ;;
    esac
}

# ---------------------------------------------------------------------------
# Helper: get latest release download URL from GitHub API
# ---------------------------------------------------------------------------
get_latest_asset_url() {
    local repo="$1"
    local asset_name="$2"
    local api_url="https://api.github.com/repos/${repo}/releases/latest"
    local url
    url=$(curl -sf --noproxy '*' "$api_url" | grep -o '"browser_download_url": *"[^"]*'"${asset_name}"'"' | head -1 | sed 's/.*"\(https[^"]*\)".*/\1/')
    if [ -z "$url" ]; then
        return 1
    fi
    echo "$url"
}

# ---------------------------------------------------------------------------
# Helper: download a file with fallback message
# ---------------------------------------------------------------------------
download_file() {
    local url="$1"
    local dest="$2"
    local label="$3"
    local manual_url="${4:-$url}"

    info "Downloading $label..."
    if ! curl -fL --noproxy '*' --progress-bar -o "$dest" "$url"; then
        error "Failed to download $label."
        echo ""
        echo "  Please download it manually from:"
        echo "    $manual_url"
        echo "  and place it at:"
        echo "    $dest"
        echo ""
        die "Download failed for $label"
    fi
}

# ---------------------------------------------------------------------------
# Step 4 — Download tools
# ---------------------------------------------------------------------------
TMP_DIR=""
SERVICES_STARTED=0
_cleanup_tmp() { [ -n "$TMP_DIR" ] && rm -rf "$TMP_DIR"; }
trap '_cleanup_tmp' EXIT

download_tools() {
    TMP_DIR=$(mktemp -d)
    local tmp_dir="$TMP_DIR"

    # -- xray --
    if [ -f "$INSTALL_DIR/xray" ]; then
        info "xray already exists, skipping download."
    else
        local xray_url="https://github.com/XTLS/Xray-core/releases/latest/download/${XRAY_ASSET}"
        local xray_zip="$tmp_dir/$XRAY_ASSET"
        download_file "$xray_url" "$xray_zip" "xray ($XRAY_ASSET)" "https://github.com/XTLS/Xray-core/releases/latest"

        info "Extracting xray..."
        unzip -o "$xray_zip" xray -d "$tmp_dir" 2>/dev/null || \
            unzip -o "$xray_zip" -d "$tmp_dir" 2>/dev/null
        local xray_bin
        xray_bin=$(find "$tmp_dir" -maxdepth 2 -name "xray" -not -name "*.zip" | head -1)
        if [ -z "$xray_bin" ]; then
            die "Could not find xray binary after extracting $XRAY_ASSET"
        fi
        cp "$xray_bin" "$INSTALL_DIR/xray"
        chmod +x "$INSTALL_DIR/xray"
        success "xray installed → $INSTALL_DIR/xray"
    fi

    # -- dnstt-client (skip for slipstream-only mode) --
    if [ "${TUNNEL_MODE:-1}" != "2" ]; then
        if [ -f "$INSTALL_DIR/dnstt-client" ]; then
            info "dnstt-client already exists, skipping download."
        else
            local dnstt_url
            dnstt_url=$(get_latest_asset_url "net2share/dnstt" "$DNSTT_CLIENT_ASSET") || {
                warn "Could not auto-resolve dnstt-client URL. Trying direct URL..."
                dnstt_url="https://github.com/net2share/dnstt/releases/latest/download/${DNSTT_CLIENT_ASSET}"
            }
            download_file "$dnstt_url" "$INSTALL_DIR/dnstt-client" "dnstt-client" "https://github.com/net2share/dnstt/releases/latest"
            chmod +x "$INSTALL_DIR/dnstt-client"
            success "dnstt-client installed → $INSTALL_DIR/dnstt-client"
        fi
    fi

    # -- slipstream-rust client (skip for dnstt-only mode) --
    if [ "${TUNNEL_MODE:-1}" != "1" ]; then
        if [ -f "$INSTALL_DIR/slipstream-client" ]; then
            info "slipstream-client already exists, skipping download."
        else
            local slip_url
            slip_url=$(get_latest_asset_url "AliRezaBeigy/slipstream-rust-deploy" "$SLIPSTREAM_ASSET") || {
                warn "Could not auto-resolve slipstream-client URL. Trying direct URL..."
                slip_url="https://github.com/AliRezaBeigy/slipstream-rust-deploy/releases/latest/download/${SLIPSTREAM_ASSET}"
            }
            download_file "$slip_url" "$INSTALL_DIR/slipstream-client" "slipstream-client" "https://github.com/AliRezaBeigy/slipstream-rust-deploy/releases/latest"
            chmod +x "$INSTALL_DIR/slipstream-client"
            success "slipstream-client installed → $INSTALL_DIR/slipstream-client"
        fi
    fi

    # -- dnstt-dns-scanner --
    if [ -f "$INSTALL_DIR/dnstt-dns-scanner" ]; then
        info "dnstt-dns-scanner already exists, skipping download."
    else
        local scanner_url
        scanner_url=$(get_latest_asset_url "AliRezaBeigy/dnstt-dns-scanner" "$SCANNER_ASSET") || {
            warn "Could not auto-resolve dnstt-dns-scanner URL. Trying direct URL..."
            scanner_url="https://github.com/AliRezaBeigy/dnstt-dns-scanner/releases/latest/download/${SCANNER_ASSET}"
        }
        download_file "$scanner_url" "$INSTALL_DIR/dnstt-dns-scanner" "dnstt-dns-scanner" "https://github.com/AliRezaBeigy/dnstt-dns-scanner/releases/latest"
        chmod +x "$INSTALL_DIR/dnstt-dns-scanner"
        success "dnstt-dns-scanner installed → $INSTALL_DIR/dnstt-dns-scanner"
    fi
}

# ---------------------------------------------------------------------------
# Step 5 — Resolver IPs
# ---------------------------------------------------------------------------
ask_resolvers() {
    echo ""

    if [ -f "$INSTALL_DIR/dns.txt" ]; then
        DNS_COUNT=$(wc -l < "$INSTALL_DIR/dns.txt" | tr -d ' ')
        info "dns.txt already exists ($DNS_COUNT IPs), skipping download."
        return
    fi

    echo -e "${CYAN}Enter path to your IP resolvers file.${NC}"
    echo "  (press Enter to download net2share/ir-resolvers automatically)"
    echo -e "${CYAN}>:${NC} \c"
    read -r resolvers_path

    if [ -z "$resolvers_path" ]; then
        info "Downloading ir-resolvers from net2share/ir-resolvers..."
        download_file \
            "https://raw.githubusercontent.com/net2share/ir-resolvers/main/resolvers.txt" \
            "$INSTALL_DIR/dns.txt" \
            "ir-resolvers" \
            "https://github.com/net2share/ir-resolvers/blob/main/resolvers.txt"
        DNS_COUNT=$(wc -l < "$INSTALL_DIR/dns.txt" | tr -d ' ')
        success "Downloaded $DNS_COUNT resolver IPs → $INSTALL_DIR/dns.txt"
    else
        resolvers_path="${resolvers_path/#\~/$HOME}"
        if [ ! -f "$resolvers_path" ]; then
            die "File not found: $resolvers_path"
        fi
        cp "$resolvers_path" "$INSTALL_DIR/dns.txt"
        DNS_COUNT=$(wc -l < "$INSTALL_DIR/dns.txt" | tr -d ' ')
        success "Copied $DNS_COUNT resolver IPs → $INSTALL_DIR/dns.txt"
    fi
}

# ---------------------------------------------------------------------------
# Step 6 — dnstt settings
# ---------------------------------------------------------------------------
# Read domain and pubkey from existing run_dnstt.sh (for reinstall / better UX)
get_dnstt_defaults_from_script() {
    local script_path="$1"
    [ ! -f "$script_path" ] && return
    default_domain=""
    default_pubkey=""
    default_dnstt_mode=""
    default_ssh_user=""
    default_scanner_domain=""
    default_scanner_pubkey=""
    while IFS= read -r line; do
        if [[ "$line" =~ ^DOMAIN=\"(.*)\" ]]; then
            default_domain="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^PUBKEY=\"(.*)\" ]]; then
            default_pubkey="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^DNSTT_MODE=\"(.*)\" ]]; then
            default_dnstt_mode="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^SSH_USER=\"(.*)\" ]]; then
            default_ssh_user="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^SCANNER_DOMAIN=\"(.*)\" ]]; then
            default_scanner_domain="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^SCANNER_PUBKEY=\"(.*)\" ]]; then
            default_scanner_pubkey="${BASH_REMATCH[1]}"
        fi
    done < "$script_path" 2>/dev/null
}

ask_dnstt_settings() {
    echo ""
    echo -e "${CYAN}=== dnstt Settings ===${NC}"

    default_domain=""
    default_pubkey=""
    default_dnstt_mode=""
    default_ssh_user=""
    default_scanner_domain=""
    default_scanner_pubkey=""
    get_dnstt_defaults_from_script "$INSTALL_DIR/run_dnstt.sh"

    if [ -n "$default_domain" ]; then
        echo -e "${CYAN}Enter dnstt domain [default: $default_domain]:${NC} \c"
    else
        echo -e "${CYAN}Enter dnstt domain:${NC} \c"
    fi
    read -r DNSTT_DOMAIN
    DNSTT_DOMAIN="${DNSTT_DOMAIN:-$default_domain}"
    [ -z "$DNSTT_DOMAIN" ] && die "Domain cannot be empty."

    if [ -n "$default_pubkey" ]; then
        local pubkey_preview="${default_pubkey:0:20}..."
        echo -e "${CYAN}Enter dnstt server pubkey [default: $pubkey_preview]:${NC} \c"
    else
        echo -e "${CYAN}Enter dnstt server pubkey:${NC} \c"
    fi
    read -r DNSTT_PUBKEY
    DNSTT_PUBKEY="${DNSTT_PUBKEY:-$default_pubkey}"
    [ -z "$DNSTT_PUBKEY" ] && die "Pubkey cannot be empty."

    echo ""
    echo "  dnstt connection mode:"
    echo "  1) SOCKS5 (default) — dnstt-client listens locally as SOCKS5 proxy"
    echo "  2) SSH (-D) — SSH connects to dnstt SOCKS5, dynamic forwarding to xray"
    if [ -n "$default_dnstt_mode" ]; then
        local mode_display; [ "$default_dnstt_mode" = "ssh" ] && mode_display="2" || mode_display="1"
        echo -e "${CYAN}Enter your choice [default: $mode_display]:${NC} \c"
    else
        echo -e "${CYAN}Enter your choice [default: 1]:${NC} \c"
    fi
    read -r dnstt_mode_choice
    local default_mode_val; [ "$default_dnstt_mode" = "ssh" ] && default_mode_val="2" || default_mode_val="1"
    dnstt_mode_choice="${dnstt_mode_choice:-$default_mode_val}"

    case "$dnstt_mode_choice" in
        2)
            DNSTT_MODE="ssh"

            echo -e "${YELLOW}[INFO]${NC} SSH mode: dnstt-client runs as SOCKS5 on localhost; SSH connects to it with -D (dynamic forwarding) and xray uses SSH as SOCKS5."
            echo ""

            if [ -n "$default_ssh_user" ]; then
                echo -e "${CYAN}Enter SSH username [default: $default_ssh_user]:${NC} \c"
            else
                echo -e "${CYAN}Enter SSH username:${NC} \c"
            fi
            read -r DNSTT_SSH_USER
            DNSTT_SSH_USER="${DNSTT_SSH_USER:-$default_ssh_user}"
            [ -z "$DNSTT_SSH_USER" ] && die "SSH username cannot be empty."

            echo -e "${CYAN}Enter SSH password:${NC} \c"
            read -rs DNSTT_SSH_PASS; echo
            [ -z "$DNSTT_SSH_PASS" ] && die "SSH password cannot be empty."

            echo ""
            echo -e "${YELLOW}[INFO]${NC} SSH mode: the scanner needs separate dnstt SOCKS5 credentials to verify DNS tunnels."
            if [ -n "$default_scanner_domain" ]; then
                echo -e "${CYAN}Enter dnstt domain for scanner [default: $default_scanner_domain]:${NC} \c"
            else
                echo -e "${CYAN}Enter dnstt domain for scanner:${NC} \c"
            fi
            read -r DNSTT_SCANNER_DOMAIN
            DNSTT_SCANNER_DOMAIN="${DNSTT_SCANNER_DOMAIN:-$default_scanner_domain}"
            [ -z "$DNSTT_SCANNER_DOMAIN" ] && die "Scanner domain cannot be empty."

            if [ -n "$default_scanner_pubkey" ]; then
                local sp_preview="${default_scanner_pubkey:0:20}..."
                echo -e "${CYAN}Enter dnstt pubkey for scanner [default: $sp_preview]:${NC} \c"
            else
                echo -e "${CYAN}Enter dnstt pubkey for scanner:${NC} \c"
            fi
            read -r DNSTT_SCANNER_PUBKEY
            DNSTT_SCANNER_PUBKEY="${DNSTT_SCANNER_PUBKEY:-$default_scanner_pubkey}"
            [ -z "$DNSTT_SCANNER_PUBKEY" ] && die "Scanner pubkey cannot be empty."

            success "SSH -D mode configured."
            ;;
        *)
            DNSTT_MODE="socks5"
            success "SOCKS5 mode selected."
            ;;
    esac

    while true; do
        if [ "${TUNNEL_MODE:-1}" = "3" ]; then
            echo -e "${CYAN}Enter number of dnstt instances (half of total) [default: 13]:${NC} \c"
            read -r instance_input
            DNSTT_INSTANCE_COUNT="${instance_input:-13}"
            if [[ "$DNSTT_INSTANCE_COUNT" =~ ^[0-9]+$ ]] && [ "$DNSTT_INSTANCE_COUNT" -ge 1 ] && [ "$DNSTT_INSTANCE_COUNT" -le 100 ]; then
                break
            fi
        else
            echo -e "${CYAN}Enter number of dnstt instances [default: 25]:${NC} \c"
            read -r instance_input
            DNSTT_INSTANCE_COUNT="${instance_input:-25}"
            if [[ "$DNSTT_INSTANCE_COUNT" =~ ^[0-9]+$ ]] && [ "$DNSTT_INSTANCE_COUNT" -ge 1 ] && [ "$DNSTT_INSTANCE_COUNT" -le 100 ]; then
                break
            fi
        fi
        warn "Please enter a number between 1 and 100."
    done

    DNSTT_START_PORT=7001
    DNSTT_END_PORT=$((DNSTT_START_PORT + DNSTT_INSTANCE_COUNT - 1))
    success "dnstt instances: $DNSTT_INSTANCE_COUNT (ports $DNSTT_START_PORT–$DNSTT_END_PORT)"
}

# ---------------------------------------------------------------------------
# Step 6b — slipstream-rust settings
# ---------------------------------------------------------------------------
# Read domain from existing run_slipstream.sh (for reinstall)
get_slipstream_defaults_from_script() {
    local script_path="$1"
    [ ! -f "$script_path" ] && return
    default_slip_domain=""
    while IFS= read -r line; do
        if [[ "$line" =~ ^DOMAIN=\"(.*)\" ]]; then
            default_slip_domain="${BASH_REMATCH[1]}"
        fi
    done < "$script_path" 2>/dev/null
}

ask_slipstream_settings() {
    echo ""
    echo -e "${CYAN}=== slipstream-rust Settings ===${NC}"

    default_slip_domain=""
    get_slipstream_defaults_from_script "$INSTALL_DIR/run_slipstream.sh"

    if [ -n "$default_slip_domain" ]; then
        echo -e "${CYAN}Enter slipstream domain [default: $default_slip_domain]:${NC} \c"
    else
        echo -e "${CYAN}Enter slipstream domain:${NC} \c"
    fi
    read -r SLIP_DOMAIN
    SLIP_DOMAIN="${SLIP_DOMAIN:-$default_slip_domain}"
    [ -z "$SLIP_DOMAIN" ] && die "Slipstream domain cannot be empty."

    # In slipstream-only mode, still need dnstt credentials for the scanner
    if [ "${TUNNEL_MODE:-1}" = "2" ]; then
        echo ""
        echo -e "${YELLOW}[INFO]${NC} The DNS scanner requires a dnstt server to verify tunnel reachability."
        echo -e "${CYAN}Enter dnstt domain (for scanner only):${NC} \c"
        read -r DNSTT_DOMAIN
        [ -z "$DNSTT_DOMAIN" ] && die "dnstt domain cannot be empty."

        echo -e "${CYAN}Enter dnstt server pubkey (for scanner only):${NC} \c"
        read -r DNSTT_PUBKEY
        [ -z "$DNSTT_PUBKEY" ] && die "dnstt pubkey cannot be empty."
    fi

    while true; do
        if [ "${TUNNEL_MODE:-1}" = "3" ]; then
            echo -e "${CYAN}Enter number of slipstream instances (half of total) [default: 12]:${NC} \c"
            read -r instance_input
            SLIP_INSTANCE_COUNT="${instance_input:-12}"
            if [[ "$SLIP_INSTANCE_COUNT" =~ ^[0-9]+$ ]] && [ "$SLIP_INSTANCE_COUNT" -ge 1 ] && [ "$SLIP_INSTANCE_COUNT" -le 100 ]; then
                break
            fi
        else
            echo -e "${CYAN}Enter number of slipstream instances [default: 25]:${NC} \c"
            read -r instance_input
            SLIP_INSTANCE_COUNT="${instance_input:-25}"
            if [[ "$SLIP_INSTANCE_COUNT" =~ ^[0-9]+$ ]] && [ "$SLIP_INSTANCE_COUNT" -ge 1 ] && [ "$SLIP_INSTANCE_COUNT" -le 100 ]; then
                break
            fi
        fi
        warn "Please enter a number between 1 and 100."
    done

    # Slipstream ports start right after dnstt ports (or at 7001 if dnstt not used)
    if [ "${TUNNEL_MODE:-1}" = "2" ]; then
        SLIP_START_PORT=7001
    else
        SLIP_START_PORT=$((DNSTT_END_PORT + 1))
    fi
    SLIP_END_PORT=$((SLIP_START_PORT + SLIP_INSTANCE_COUNT - 1))
    success "slipstream instances: $SLIP_INSTANCE_COUNT (ports $SLIP_START_PORT–$SLIP_END_PORT)"

    echo ""
    echo -e "${CYAN}Does slipstream SOCKS require authentication? [y/N]:${NC} \c"
    read -r slip_auth_choice
    if [[ "${slip_auth_choice,,}" == "y" ]]; then
        SLIP_AUTH=1
        echo -e "${CYAN}Enter slipstream SOCKS username:${NC} \c"
        read -r SLIP_USER
        [ -z "$SLIP_USER" ] && die "SOCKS username cannot be empty."
        echo -e "${CYAN}Enter slipstream SOCKS password:${NC} \c"
        read -r SLIP_PASS
        [ -z "$SLIP_PASS" ] && die "SOCKS password cannot be empty."
        success "Slipstream SOCKS auth configured."
    else
        SLIP_AUTH=0
        SLIP_USER=""
        SLIP_PASS=""
    fi
}

# Set unified port range variables used by xray config
set_port_range() {
    # Initialize defaults for modes that don't use both tools
    DNSTT_INSTANCE_COUNT="${DNSTT_INSTANCE_COUNT:-0}"
    DNSTT_START_PORT="${DNSTT_START_PORT:-7001}"
    DNSTT_END_PORT="${DNSTT_END_PORT:-7000}"
    SLIP_INSTANCE_COUNT="${SLIP_INSTANCE_COUNT:-0}"
    SLIP_START_PORT="${SLIP_START_PORT:-7001}"
    SLIP_END_PORT="${SLIP_END_PORT:-7000}"

    case "${TUNNEL_MODE:-1}" in
        1)
            # dnstt only
            START_PORT=$DNSTT_START_PORT
            END_PORT=$DNSTT_END_PORT
            INSTANCE_COUNT=$DNSTT_INSTANCE_COUNT
            ;;
        2)
            # slipstream only
            START_PORT=$SLIP_START_PORT
            END_PORT=$SLIP_END_PORT
            INSTANCE_COUNT=$SLIP_INSTANCE_COUNT
            ;;
        3)
            # both
            START_PORT=$DNSTT_START_PORT
            END_PORT=$SLIP_END_PORT
            INSTANCE_COUNT=$((DNSTT_INSTANCE_COUNT + SLIP_INSTANCE_COUNT))
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Step 7 — xray inbound settings
# ---------------------------------------------------------------------------
generate_uuid() {
    if command -v uuidgen &>/dev/null; then
        uuidgen | tr '[:upper:]' '[:lower:]'
    elif [ -f /proc/sys/kernel/random/uuid ]; then
        cat /proc/sys/kernel/random/uuid
    elif command -v python3 &>/dev/null; then
        python3 -c "import uuid; print(uuid.uuid4())"
    else
        # fallback: generate from /dev/urandom
        od -x /dev/urandom | head -1 | awk '{print $2$3"-"$4"-"$5"-"$6"-"$7$8$9}' | head -c 36
    fi
}

ask_xray_settings() {
    echo ""
    echo -e "${CYAN}=== xray Inbound Settings ===${NC}"
    echo "  1) VLESS TCP only"
    echo "  2) SOCKS/HTTP (mixed) only"
    echo "  3) Both VLESS TCP and SOCKS/HTTP (mixed)"
    echo -e "${CYAN}Enter your choice [default: 3]:${NC} \c"
    read -r choice
    XRAY_CHOICE="${choice:-3}"

    USE_VLESS=0; USE_MIXED=0
    case "$XRAY_CHOICE" in
        1) USE_VLESS=1 ;;
        2) USE_MIXED=1 ;;
        3) USE_VLESS=1; USE_MIXED=1 ;;
        *) warn "Invalid choice, defaulting to both."; USE_VLESS=1; USE_MIXED=1 ;;
    esac

    if [ $USE_VLESS -eq 1 ]; then
        echo -e "${CYAN}Enter VLESS TCP port [default: 443]:${NC} \c"
        read -r vless_port_input
        VLESS_PORT="${vless_port_input:-443}"

        echo -e "${CYAN}Enter VLESS UUID [press Enter to generate random]:${NC} \c"
        read -r uuid_input
        if [ -z "$uuid_input" ]; then
            VLESS_UUID=$(generate_uuid)
            success "Generated UUID: $VLESS_UUID"
        else
            VLESS_UUID="$uuid_input"
        fi
    fi

    if [ $USE_MIXED -eq 1 ]; then
        echo -e "${CYAN}Enter SOCKS/HTTP mixed port [default: 1080]:${NC} \c"
        read -r mixed_port_input
        MIXED_PORT="${mixed_port_input:-1080}"
    fi

    echo ""
    echo "  xray balancer strategy:"
    echo "    1) Lowest Latency (leastPing) - default"
    echo "    2) Round Robin (roundRobin)"
    echo -e "${CYAN}Enter your choice [default: 1]:${NC} \c"
    read -r strategy_choice
    case "${strategy_choice:-1}" in
        2) XRAY_STRATEGY="roundRobin" ;;
        *) XRAY_STRATEGY="leastPing" ;;
    esac
}

# ---------------------------------------------------------------------------
# Step 8 — Generate xray-config.json
# ---------------------------------------------------------------------------
generate_xray_config() {
    info "Generating xray-config.json..."

    local inbounds=""

    if [ $USE_MIXED -eq 1 ]; then
        inbounds=$(cat <<EOF
        {
            "port": $MIXED_PORT,
            "protocol": "mixed",
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls"],
                "routeOnly": false
            },
            "settings": {
                "auth": "noauth",
                "udp": true,
                "allowTransparent": false
            }
        }
EOF
)
    fi

    if [ $USE_VLESS -eq 1 ]; then
        local vless_entry
        vless_entry=$(cat <<EOF
        {
            "port": $VLESS_PORT,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": "$VLESS_UUID"}],
                "decryption": "none"
            },
            "streamSettings": {"network": "tcp"}
        }
EOF
)
        if [ -n "$inbounds" ]; then
            inbounds="${inbounds},"$'\n'"${vless_entry}"
        else
            inbounds="$vless_entry"
        fi
    fi

    # Build outbounds (N socks proxies + direct + block)
    local outbounds=""
    local port
    local i=1
    for port in $(seq "$START_PORT" "$END_PORT"); do
        [ $i -gt 1 ] && outbounds="${outbounds},"$'\n'
        # Determine if this port belongs to the slipstream range and auth is enabled
        local slip_auth_entry=""
        if [ "${SLIP_AUTH:-0}" -eq 1 ] && [ -n "${SLIP_START_PORT:-}" ] && [ -n "${SLIP_END_PORT:-}" ] \
            && [ "$port" -ge "$SLIP_START_PORT" ] && [ "$port" -le "$SLIP_END_PORT" ]; then
            slip_auth_entry="
                    \"user\": \"${SLIP_USER}\",
                    \"pass\": \"${SLIP_PASS}\","
        fi
        outbounds="${outbounds}        {
            \"tag\": \"proxy-${i}\",
            \"protocol\": \"socks\",
            \"settings\": {
                \"servers\": [{
                    \"address\": \"127.0.0.1\",
                    \"ota\": false,
                    \"port\": ${port},${slip_auth_entry}
                    \"level\": 1
                }]
            },
            \"streamSettings\": {\"network\": \"tcp\"},
            \"mux\": {\"enabled\": false, \"concurrency\": -1}
        }"
        i=$((i + 1))
    done

    outbounds="${outbounds},"$'\n'"        {\"tag\": \"direct\", \"protocol\": \"freedom\"},"$'\n'"        {\"tag\": \"block\", \"protocol\": \"blackhole\"}"

    cat > "$INSTALL_DIR/xray-config.json" <<EOF
{
    "log": {"loglevel": "warning"},
    "dns": {
        "hosts": {"dns.google": ["8.8.8.8"]},
        "servers": ["1.1.1.1", "https://dns.google/dns-query"]
    },
    "inbounds": [
$inbounds
    ],
    "outbounds": [
$outbounds
    ],
    "routing": {
        "domainStrategy": "AsIs",
        "rules": [
            {
                "type": "field",
                "network": "tcp,udp",
                "balancerTag": "proxy-round"
            }
        ],
        "balancers": [
            {
                "selector": ["proxy"],
                "strategy": {
                    "type": "${XRAY_STRATEGY:-leastPing}",
                    "settings": {"expected": 1}
                },
                "tag": "proxy-round"
            }
        ]
    },
    "observatory": {
        "subjectSelector": ["proxy"],
        "probeUrl": "http://www.msftconnecttest.com/connecttest.txt",
        "probeInterval": "1m",
        "enableConcurrency": true
    }
}
EOF
    success "xray-config.json written → $INSTALL_DIR/xray-config.json"
}

# ---------------------------------------------------------------------------
# Step 9 — Generate runner scripts based on tunnel mode
# ---------------------------------------------------------------------------
generate_runner_scripts() {
    case "${TUNNEL_MODE:-1}" in
        1) generate_run_dnstt ;;
        2) generate_run_slipstream ;;
        3) generate_run_dnstt; generate_run_slipstream; generate_run_both ;;
    esac
}

generate_run_dnstt() {
    if [ "${DNSTT_MODE:-socks5}" = "ssh" ]; then
        generate_run_dnstt_ssh
    else
        generate_run_dnstt_socks5
    fi
}

generate_run_dnstt_socks5() {
    info "Generating run_dnstt.sh (SOCKS5 mode)..."

    cat > "$INSTALL_DIR/run_dnstt.sh" <<DNSTT_SCRIPT
#!/bin/bash

# Configuration
DNS_FILE="dns.txt"
_DNS_FILE="_dns.txt"
DNS_ASSIGNMENTS_FILE="dns_assignments.txt"
DNS_FAILURES_FILE="dns_failures.txt"
DNS_PIDS_FILE="dns_pids.txt"
PUBKEY="$DNSTT_PUBKEY"
DOMAIN="$DNSTT_DOMAIN"
START_PORT=$DNSTT_START_PORT
END_PORT=$DNSTT_END_PORT
SCAN_INTERVAL=600

# Create logs directory if it doesn't exist
mkdir -p logs

# Initialize _dns.txt from dns.txt if it doesn't exist
if [ ! -f "\$_DNS_FILE" ]; then
    if [ -f "\$DNS_FILE" ]; then
        echo "Copying \$DNS_FILE to \$_DNS_FILE for faster scanning..."
        cp "\$DNS_FILE" "\$_DNS_FILE"
    else
        echo "WARNING: \$DNS_FILE not found, creating empty \$_DNS_FILE"
        touch "\$_DNS_FILE"
    fi
fi

# Initialize dns_failures.txt if it doesn't exist
if [ ! -f "\$DNS_FAILURES_FILE" ]; then
    touch "\$DNS_FAILURES_FILE"
fi

# Initialize dns_pids.txt if it doesn't exist
if [ ! -f "\$DNS_PIDS_FILE" ]; then
    touch "\$DNS_PIDS_FILE"
fi

# Function to refill _dns.txt from dns.txt if empty
refill_dns_file() {
    if [ ! -s "\$_DNS_FILE" ]; then
        if [ -f "\$DNS_FILE" ] && [ -s "\$DNS_FILE" ]; then
            echo "WARNING: \$_DNS_FILE is empty, refilling from \$DNS_FILE..."
            cp "\$DNS_FILE" "\$_DNS_FILE"
            echo "Refilled \$_DNS_FILE with \$(wc -l < "\$_DNS_FILE") DNS entries from \$DNS_FILE"
            # Reset failure counts when refilling
            > "\$DNS_FAILURES_FILE"
            echo "Reset failure tracking"
            return 0
        else
            echo "ERROR: Cannot refill \$_DNS_FILE - \$DNS_FILE is empty or missing"
            return 1
        fi
    fi
    return 0
}

# Function to scan DNS servers and get all with tunnels
scan_and_get_all_dns() {
    local DNS_WITH_TUNNELS_FILE="dns_with_tunnels.txt"

    echo "=== Scanning DNS servers ==="
    echo "DNS file: \$_DNS_FILE"
    echo "Domain: \$DOMAIN"
    echo "Pubkey: \$PUBKEY"

    if [ ! -f "./dnstt-dns-scanner" ] && [ ! -f "./dnstt-dns-scanner.exe" ]; then
        echo "ERROR: dnstt-dns-scanner executable not found in current directory"
        ls -la ./dnstt* 2>/dev/null || echo "No dnstt files found in current directory"
        return 1
    fi

    if [ ! -f "\$_DNS_FILE" ]; then
        echo "ERROR: DNS file '\$_DNS_FILE' not found"
        return 1
    fi

    if [ ! -s "\$_DNS_FILE" ]; then
        if ! refill_dns_file; then
            echo "ERROR: Cannot proceed with empty DNS file"
            return 1
        fi
    fi

    echo "DNS file contents:"
    cat "\$_DNS_FILE" | while read ip; do echo "  - \$ip"; done

    local dns_count=\$(wc -l < "\$_DNS_FILE" | tr -d ' ')
    local cpu_cores=\$(nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || echo 1)
    local threads=\$((dns_count / 10))
    local max_threads=\$((cpu_cores * 50))
    [ \$max_threads -gt 500 ] && max_threads=500
    [ \$threads -gt \$max_threads ] && threads=\$max_threads
    [ \$threads -lt 1 ] && threads=1
    echo "DNS count: \$dns_count, CPU cores: \$cpu_cores, threads: \$threads (cap: \$max_threads)"

    local scanner_out_file=\$(mktemp)
    local scanner_cmd="./dnstt-dns-scanner -ips \$_DNS_FILE -pubkey \$PUBKEY -test-domain test.k.markop.ir -test-txt \"TEST RESULT\" -threads \$threads \$DOMAIN"

    echo "Executing command: \$scanner_cmd"
    eval "\$scanner_cmd" > "\$scanner_out_file" 2>&1
    local scanner_exit_code=\$?
    echo "Scanner exit code: \$scanner_exit_code"
    cat "\$scanner_out_file"
    if [ \$scanner_exit_code -ne 0 ]; then
        echo "ERROR: Scanner failed with exit code \$scanner_exit_code"
        rm -f "\$scanner_out_file"
        return 1
    fi

    # Extract the already-sorted IPs from the "Tunnel-capable DNS servers IPs:" section in one awk pass
    echo "--- Parsing tunnel-capable IPs from scanner output ---"
    awk '/^Tunnel-capable DNS servers IPs:/{found=1; next} found && /^[0-9]/{print} found && !/^[0-9]/{exit}' \
        "\$scanner_out_file" > "\$DNS_WITH_TUNNELS_FILE"
    local tunnel_count=\$(wc -l < "\$DNS_WITH_TUNNELS_FILE" | tr -d ' ')
    echo "Found \$tunnel_count tunnel-capable DNS servers"

    # Update failure tracking in one awk pass (O(N) instead of O(N²) nested loops)
    echo "--- Updating failure tracking ---"
    local fail_inc=1

    local new_failures_file=\$(mktemp)
    local new_dns_file=\$(mktemp)

    awk -v fail_inc="\$fail_inc" -v failures_file="\$DNS_FAILURES_FILE" \
        -v dns_file="\$_DNS_FILE" -v new_dns_file="\$new_dns_file" '
    BEGIN {
        while ((getline line < failures_file) > 0) {
            n = split(line, a, "|")
            if (n == 2) fail_count[a[1]] = a[2]+0
        }
        close(failures_file)
        while ((getline ip < dns_file) > 0) {
            if (ip != "") scanned[ip] = 1
        }
        close(dns_file)
    }
    { is_tunnel[\$1] = 1 }
    END {
        for (ip in scanned) {
            if (ip in is_tunnel) {
                printf "DNS %s: Has tunnel, resetting failure count\n", ip > "/dev/stderr"
            } else {
                cnt = (ip in fail_count ? fail_count[ip] : 0) + fail_inc
                printf "%s|%d\n", ip, cnt
                printf "DNS %s: No tunnel, failure count: %d\n", ip, cnt > "/dev/stderr"
                if (cnt < 10) print ip > new_dns_file
                else printf "DNS %s: Removed from _dns.txt (10 consecutive failures)\n", ip > "/dev/stderr"
            }
        }
    }
    ' "\$DNS_WITH_TUNNELS_FILE" > "\$new_failures_file"

    mv "\$new_failures_file" "\$DNS_FAILURES_FILE"
    # Tunnel IPs always stay in _dns.txt (append them to the surviving-failures list)
    cat "\$DNS_WITH_TUNNELS_FILE" >> "\$new_dns_file"
    sort -u "\$new_dns_file" -o "\$new_dns_file"
    mv "\$new_dns_file" "\$_DNS_FILE"

    rm -f "\$scanner_out_file"

    if [ "\$tunnel_count" -gt 0 ]; then
        echo "=== Saved \$tunnel_count DNS servers with tunnels to \$DNS_WITH_TUNNELS_FILE ==="
        return 0
    else
        echo "ERROR: No tunnel-capable DNS servers found in scanner output!"
        > "\$DNS_WITH_TUNNELS_FILE"
        return 1
    fi
}

# Function to build dnstt-client command
build_dnstt_cmd() {
    local dns_ip="\$1"
    local port="\$2"
    echo "./dnstt-client -utls Chrome_120 -udp \$dns_ip:53 -pubkey \$PUBKEY \$DOMAIN 127.0.0.1:\$port"
}

# Function to stop instance gracefully using PID
stop_instance_gracefully() {
    local port=\$1
    local pid=\$(get_instance_pid "\$port")

    if [ -n "\$pid" ] && kill -0 "\$pid" 2>/dev/null; then
        echo "Stopping instance on port \$port (PID: \$pid) gracefully..."
        kill -TERM "\$pid" 2>/dev/null
        local wait_count=0
        while [ \$wait_count -lt 50 ] && kill -0 "\$pid" 2>/dev/null; do
            sleep 0.1
            wait_count=\$((wait_count + 1))
        done
        if kill -0 "\$pid" 2>/dev/null; then
            echo "Force killing instance on port \$port (PID: \$pid)"
            kill -KILL "\$pid" 2>/dev/null
        fi
        remove_instance_pid "\$port"
        return 0
    else
        pkill -f "dnstt-client.*\$port" 2>/dev/null
        remove_instance_pid "\$port"
        return 1
    fi
}

# Function to get instance PID for a port
get_instance_pid() {
    local port=\$1
    if [ -f "\$DNS_PIDS_FILE" ]; then
        local pid=\$(grep "^\${port}|" "\$DNS_PIDS_FILE" | cut -d'|' -f2)
        if [ -n "\$pid" ] && kill -0 "\$pid" 2>/dev/null; then
            echo "\$pid"
            return 0
        else
            remove_instance_pid "\$port"
        fi
    fi
    return 1
}

# Function to save instance PID
save_instance_pid() {
    local port=\$1
    local pid=\$2
    local temp_file=\$(mktemp)
    if [ -f "\$DNS_PIDS_FILE" ]; then
        grep -v "^\${port}|" "\$DNS_PIDS_FILE" > "\$temp_file" 2>/dev/null || true
    fi
    echo "\${port}|\${pid}" >> "\$temp_file"
    mv "\$temp_file" "\$DNS_PIDS_FILE"
}

# Function to remove instance PID
remove_instance_pid() {
    local port=\$1
    if [ -f "\$DNS_PIDS_FILE" ]; then
        local temp_file=\$(mktemp)
        grep -v "^\${port}|" "\$DNS_PIDS_FILE" > "\$temp_file" 2>/dev/null || true
        mv "\$temp_file" "\$DNS_PIDS_FILE"
    fi
}

# Function to start a dnstt-client instance
start_instance() {
    local port=\$1
    local dns_ip=\$2
    local log_file="logs/client_\$port.log"

    stop_instance_gracefully "\$port"

    local cmd=\$(build_dnstt_cmd "\$dns_ip" "\$port")
    echo "Starting dnstt-client on port \$port with DNS \$dns_ip"
    nohup \$cmd > "\$log_file" 2>&1 &
    local pid=\$!

    save_instance_pid "\$port" "\$pid"
    echo "Started instance on port \$port with PID \$pid"

    sleep 0.2
    if ! kill -0 "\$pid" 2>/dev/null; then
        echo "WARNING: Process \$pid died immediately after start"
        remove_instance_pid "\$port"
        return 1
    fi
    return 0
}

# Function to get assigned DNS for a port
get_assigned_dns() {
    local port=\$1
    if [ -f "\$DNS_ASSIGNMENTS_FILE" ]; then
        local assigned_dns=\$(grep "^\${port}|" "\$DNS_ASSIGNMENTS_FILE" | cut -d'|' -f2)
        if [ -n "\$assigned_dns" ]; then
            echo "\$assigned_dns"
            return 0
        fi
    fi
    return 1
}

# Function to check if instance process is running
is_instance_running() {
    local port=\$1
    local pid=\$(get_instance_pid "\$port")
    if [ -n "\$pid" ] && kill -0 "\$pid" 2>/dev/null; then return 0; fi
    return 1
}

# Function to restart a failed instance
check_and_restart() {
    local port=\$1
    local log_file="logs/client_\$port.log"
    local needs_restart=0

    if ! is_instance_running "\$port"; then
        echo "Instance on port \$port is not running (process missing)"
        needs_restart=1
    fi

    if [ -f "\$log_file" ]; then
        if grep -q "opening stream: io: read/write on closed pipe" "\$log_file"; then
            echo "Instance on port \$port failed with pipe error"
            needs_restart=1
        fi
    elif [ \$needs_restart -eq 0 ]; then
        if ! is_instance_running "\$port"; then needs_restart=1; fi
    fi

    if [ \$needs_restart -eq 1 ]; then
        echo "Restarting dnstt-client on port \$port"
        local assigned_dns=\$(get_assigned_dns "\$port")
        if [ -n "\$assigned_dns" ]; then
            rm -f "\$log_file"
            stop_instance_gracefully "\$port"
            sleep 1
            start_instance "\$port" "\$assigned_dns"
            return 0
        else
            echo "Warning: No DNS assigned to port \$port, skipping restart"
            remove_instance_pid "\$port"
        fi
    fi
    return 1
}

# Function to distribute DNS to instances while preserving existing mappings
distribute_dns_to_instances() {
    local DNS_WITH_TUNNELS_FILE="dns_with_tunnels.txt"

    if [ ! -f "\$DNS_WITH_TUNNELS_FILE" ] || [ ! -s "\$DNS_WITH_TUNNELS_FILE" ]; then
        echo "Error: No DNS with tunnels available (file \$DNS_WITH_TUNNELS_FILE is empty or missing)"
        return 1
    fi

    local current_dns=()
    while IFS= read -r ip; do
        [ -n "\$ip" ] && current_dns+=("\$ip")
    done < "\$DNS_WITH_TUNNELS_FILE"

    if [ \${#current_dns[@]} -eq 0 ]; then
        echo "Error: No DNS with tunnels found"
        return 1
    fi

    echo "Distributing \${#current_dns[@]} DNS servers across instances (round-robin)..."

    declare -A port_assignments
    local idx=0
    for port in \$(seq \$START_PORT \$END_PORT); do
        port_assignments["\$port"]="\${current_dns[\$((idx % \${#current_dns[@]}))]}"
        idx=\$((idx + 1))
    done

    > "\$DNS_ASSIGNMENTS_FILE"
    for port in \$(seq \$START_PORT \$END_PORT); do
        echo "\${port}|\${port_assignments[\$port]}" >> "\$DNS_ASSIGNMENTS_FILE"
        echo "Assigned: DNS \${port_assignments[\$port]} -> Port \$port"
    done

    echo "Starting/restarting instances with assigned DNS..."
    for port in \$(seq \$START_PORT \$END_PORT); do
        start_instance "\$port" "\${port_assignments[\$port]}"
        sleep 0.1
    done

    echo "DNS distribution complete: \${#port_assignments[@]} instances assigned"
    return 0
}

# Initial startup
echo "=========================================="
echo "Starting dnstt-runner"
echo "Working directory: \$(pwd)"
echo "DNS file: \$DNS_FILE"
echo "Working DNS file: \$_DNS_FILE"
echo "Port range: \$START_PORT-\$END_PORT"
echo "Scan interval: 10 minutes after completion"
echo "=========================================="
echo ""

if [ -f "\$DNS_ASSIGNMENTS_FILE" ] && [ -s "\$DNS_ASSIGNMENTS_FILE" ]; then
    echo "Previous DNS assignments found, starting instances..."
    while IFS='|' read -r port dns_ip; do
        [ -n "\$port" ] && [ -n "\$dns_ip" ] && start_instance "\$port" "\$dns_ip"
    done < "\$DNS_ASSIGNMENTS_FILE"
    echo "Started instances. Periodic scanner will run first scan shortly."
else
    echo "No previous DNS assignments found, running initial scan..."
    scan_and_get_all_dns
    initial_scan_result=\$?
    echo "Initial scan exit code: \$initial_scan_result"

    if [ \$initial_scan_result -eq 0 ]; then
        echo "DNS scan completed successfully, distributing DNS to instances..."
        distribute_dns_to_instances
        if [ \$? -ne 0 ]; then
            echo "ERROR: Failed to distribute DNS to instances. Exiting."
            exit 1
        fi
    else
        echo "ERROR: Initial scan found no DNS servers with tunnels. Exiting."
        exit 1
    fi
fi

# Start background scanner job
(
    SCAN_COUNT=0
    while true; do
        SCAN_COUNT=\$((SCAN_COUNT + 1))
        scan_start_time=\$(date +%s)

        # Every 20 scans: restore all IPs from dns.txt so previously-removed IPs get another chance
        if [ \$((SCAN_COUNT % 20)) -eq 0 ]; then
            echo "=== Scan #\${SCAN_COUNT}: Full refresh — restoring all IPs from \$DNS_FILE ==="
            if [ -f "\$DNS_FILE" ] && [ -s "\$DNS_FILE" ]; then
                cp "\$DNS_FILE" "\$_DNS_FILE"
                > "\$DNS_FAILURES_FILE"
                echo "Restored \$(wc -l < "\$_DNS_FILE") IPs from \$DNS_FILE and reset failure counts"
            else
                echo "WARNING: \$DNS_FILE not found or empty, skipping full refresh"
            fi
        fi

        echo "Running periodic DNS scan (#\${SCAN_COUNT})..."
        scan_and_get_all_dns
        scan_result=\$?
        scan_end_time=\$(date +%s)
        scan_duration=\$((scan_end_time - scan_start_time))

        if [ \$scan_result -eq 0 ]; then
            echo "DNS scan completed successfully, distributing DNS to instances..."
            distribute_dns_to_instances
        else
            echo "DNS scan found no tunnels, checking if _dns.txt needs refilling..."
            refill_dns_file
            echo "Skipping distribution - no tunnels found"
        fi

        next_scan_time=\$((scan_end_time + 600))
        current_time=\$(date +%s)
        sleep_duration=\$((next_scan_time - current_time))
        if [ \$sleep_duration -lt 0 ]; then sleep_duration=0; fi

        echo "Scan completed in \${scan_duration}s. Next scan in \${sleep_duration}s (10 minutes after completion)"
        sleep \$sleep_duration
    done
) &
SCANNER_PID=\$!

# Cleanup function
cleanup() {
    echo "Shutting down gracefully..."
    kill \$SCANNER_PID 2>/dev/null

    if [ -f "\$DNS_PIDS_FILE" ]; then
        while IFS='|' read -r port pid; do
            [ -n "\$port" ] && [ -n "\$pid" ] && stop_instance_gracefully "\$port"
        done < "\$DNS_PIDS_FILE"
    fi

    pkill -f "dnstt-client" 2>/dev/null
    exit
}
trap cleanup SIGINT SIGTERM

# Continuous monitoring loop
while true; do
    echo "Checking for failed instances..."

    if [ ! -s "\$_DNS_FILE" ]; then
        echo "WARNING: \$_DNS_FILE is empty, attempting to refill..."
        if refill_dns_file; then
            echo "Refilled \$_DNS_FILE, will be used in next scan"
        fi
    fi

    for port in \$(seq \$START_PORT \$END_PORT); do
        check_and_restart \$port
    done

    echo "Sleeping for 5 seconds before next check..."
    sleep 5
done
DNSTT_SCRIPT

    chmod +x "$INSTALL_DIR/run_dnstt.sh"
    success "run_dnstt.sh written → $INSTALL_DIR/run_dnstt.sh"
}

generate_run_dnstt_ssh() {
    info "Generating run_dnstt.sh (SSH mode)..."

    # dnstt SOCKS5 intermediate ports sit just below the xray-facing SSH -D ports
    # e.g. 25 instances: dnstt on 6976-7000, SSH -D on 7001-7025 (no overlap)
    local dnstt_base_port=$((DNSTT_START_PORT - DNSTT_INSTANCE_COUNT))

    cat > "$INSTALL_DIR/run_dnstt.sh" <<DNSTT_SSH_SCRIPT
#!/bin/bash

# Configuration
DNSTT_MODE="ssh"
DNS_FILE="dns.txt"
_DNS_FILE="_dns.txt"
DNS_ASSIGNMENTS_FILE="dns_assignments.txt"
DNS_FAILURES_FILE="dns_failures.txt"
DNS_PIDS_FILE="dns_pids.txt"
DNS_START_TIMES_FILE="dns_start_times.txt"
SSH_CONNECT_GRACE=60
PUBKEY="$DNSTT_PUBKEY"
DOMAIN="$DNSTT_DOMAIN"
SCANNER_PUBKEY="$DNSTT_SCANNER_PUBKEY"
SCANNER_DOMAIN="$DNSTT_SCANNER_DOMAIN"
SSH_USER="$DNSTT_SSH_USER"
SSH_PASS="$DNSTT_SSH_PASS"
# xray-facing ports — SSH -D dynamic SOCKS5 listens here
START_PORT=$DNSTT_START_PORT
END_PORT=$DNSTT_END_PORT
# intermediate dnstt-client SOCKS5 ports (just below xray ports)
DNSTT_BASE_PORT=$dnstt_base_port
SCAN_INTERVAL=600

# Create logs directory if it doesn't exist
mkdir -p logs

# Initialize _dns.txt from dns.txt if it doesn't exist
if [ ! -f "\$_DNS_FILE" ]; then
    if [ -f "\$DNS_FILE" ]; then
        echo "Copying \$DNS_FILE to \$_DNS_FILE for faster scanning..."
        cp "\$DNS_FILE" "\$_DNS_FILE"
    else
        echo "WARNING: \$DNS_FILE not found, creating empty \$_DNS_FILE"
        touch "\$_DNS_FILE"
    fi
fi

[ ! -f "\$DNS_FAILURES_FILE" ]     && touch "\$DNS_FAILURES_FILE"
[ ! -f "\$DNS_PIDS_FILE" ]         && touch "\$DNS_PIDS_FILE"
[ ! -f "\$DNS_START_TIMES_FILE" ]  && touch "\$DNS_START_TIMES_FILE"

# Function to refill _dns.txt from dns.txt if empty
refill_dns_file() {
    if [ ! -s "\$_DNS_FILE" ]; then
        if [ -f "\$DNS_FILE" ] && [ -s "\$DNS_FILE" ]; then
            echo "WARNING: \$_DNS_FILE is empty, refilling from \$DNS_FILE..."
            cp "\$DNS_FILE" "\$_DNS_FILE"
            echo "Refilled \$_DNS_FILE with \$(wc -l < "\$_DNS_FILE") DNS entries from \$DNS_FILE"
            > "\$DNS_FAILURES_FILE"
            echo "Reset failure tracking"
            return 0
        else
            echo "ERROR: Cannot refill \$_DNS_FILE - \$DNS_FILE is empty or missing"
            return 1
        fi
    fi
    return 0
}

# Function to scan DNS servers and get all with tunnels
scan_and_get_all_dns() {
    local DNS_WITH_TUNNELS_FILE="dns_with_tunnels.txt"

    echo "=== Scanning DNS servers (SSH mode) ==="
    echo "DNS file: \$_DNS_FILE"
    echo "Scanner domain: \$SCANNER_DOMAIN"

    if [ ! -f "./dnstt-dns-scanner" ] && [ ! -f "./dnstt-dns-scanner.exe" ]; then
        echo "ERROR: dnstt-dns-scanner executable not found in current directory"
        return 1
    fi

    if [ ! -f "\$_DNS_FILE" ] || [ ! -s "\$_DNS_FILE" ]; then
        if ! refill_dns_file; then
            echo "ERROR: Cannot proceed with empty DNS file"
            return 1
        fi
    fi

    local dns_count=\$(wc -l < "\$_DNS_FILE" | tr -d ' ')
    local cpu_cores=\$(nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || echo 1)
    local threads=\$((dns_count / 10))
    local max_threads=\$((cpu_cores * 50))
    [ \$max_threads -gt 500 ] && max_threads=500
    [ \$threads -gt \$max_threads ] && threads=\$max_threads
    [ \$threads -lt 1 ] && threads=1
    echo "DNS count: \$dns_count, CPU cores: \$cpu_cores, threads: \$threads (cap: \$max_threads)"

    local scanner_out_file=\$(mktemp)
    local scanner_cmd="./dnstt-dns-scanner -ips \$_DNS_FILE -pubkey \$SCANNER_PUBKEY -test-domain test.k.markop.ir -test-txt \"TEST RESULT\" -threads \$threads \$SCANNER_DOMAIN"

    echo "Executing command: \$scanner_cmd"
    eval "\$scanner_cmd" > "\$scanner_out_file" 2>&1
    local scanner_exit_code=\$?
    echo "Scanner exit code: \$scanner_exit_code"
    cat "\$scanner_out_file"
    if [ \$scanner_exit_code -ne 0 ]; then
        echo "ERROR: Scanner failed with exit code \$scanner_exit_code"
        rm -f "\$scanner_out_file"
        return 1
    fi

    echo "--- Parsing tunnel-capable IPs from scanner output ---"
    awk '/^Tunnel-capable DNS servers IPs:/{found=1; next} found && /^[0-9]/{print} found && !/^[0-9]/{exit}' \
        "\$scanner_out_file" > "\$DNS_WITH_TUNNELS_FILE"
    local tunnel_count=\$(wc -l < "\$DNS_WITH_TUNNELS_FILE" | tr -d ' ')
    echo "Found \$tunnel_count tunnel-capable DNS servers"

    echo "--- Updating failure tracking ---"
    local fail_inc=1

    local new_failures_file=\$(mktemp)
    local new_dns_file=\$(mktemp)

    awk -v fail_inc="\$fail_inc" -v failures_file="\$DNS_FAILURES_FILE" \
        -v dns_file="\$_DNS_FILE" -v new_dns_file="\$new_dns_file" '
    BEGIN {
        while ((getline line < failures_file) > 0) {
            n = split(line, a, "|")
            if (n == 2) fail_count[a[1]] = a[2]+0
        }
        close(failures_file)
        while ((getline ip < dns_file) > 0) {
            if (ip != "") scanned[ip] = 1
        }
        close(dns_file)
    }
    { is_tunnel[\$1] = 1 }
    END {
        for (ip in scanned) {
            if (ip in is_tunnel) {
                printf "DNS %s: Has tunnel, resetting failure count\n", ip > "/dev/stderr"
            } else {
                cnt = (ip in fail_count ? fail_count[ip] : 0) + fail_inc
                printf "%s|%d\n", ip, cnt
                printf "DNS %s: No tunnel, failure count: %d\n", ip, cnt > "/dev/stderr"
                if (cnt < 10) print ip > new_dns_file
                else printf "DNS %s: Removed from _dns.txt (10 consecutive failures)\n", ip > "/dev/stderr"
            }
        }
    }
    ' "\$DNS_WITH_TUNNELS_FILE" > "\$new_failures_file"

    mv "\$new_failures_file" "\$DNS_FAILURES_FILE"
    cat "\$DNS_WITH_TUNNELS_FILE" >> "\$new_dns_file"
    sort -u "\$new_dns_file" -o "\$new_dns_file"
    mv "\$new_dns_file" "\$_DNS_FILE"
    rm -f "\$scanner_out_file"

    if [ "\$tunnel_count" -gt 0 ]; then
        echo "=== Saved \$tunnel_count DNS servers with tunnels to \$DNS_WITH_TUNNELS_FILE ==="
        return 0
    else
        echo "ERROR: No tunnel-capable DNS servers found!"
        > "\$DNS_WITH_TUNNELS_FILE"
        return 1
    fi
}

# PID file format: PORT|DNSTT_PID|SSH_PID
# dnstt-client runs SOCKS5 on DNSTT_BASE_PORT+(PORT-START_PORT)
# SSH -D PORT connects to dnstt SOCKS5 on DNSTT_BASE_PORT+(PORT-START_PORT)

dnstt_port_for() {
    local port=\$1
    echo \$((DNSTT_BASE_PORT + port - START_PORT))
}

kill_pid_gracefully() {
    local pid=\$1
    if kill -0 "\$pid" 2>/dev/null; then
        kill -TERM "\$pid" 2>/dev/null
        local w=0
        while [ \$w -lt 30 ] && kill -0 "\$pid" 2>/dev/null; do
            sleep 0.1; w=\$((w+1))
        done
        kill -0 "\$pid" 2>/dev/null && kill -KILL "\$pid" 2>/dev/null
    fi
}

save_instance_pids() {
    local port=\$1 dnstt_pid=\$2 ssh_pid=\$3
    local tmp=\$(mktemp)
    [ -f "\$DNS_PIDS_FILE" ] && grep -v "^\${port}|" "\$DNS_PIDS_FILE" > "\$tmp" 2>/dev/null || true
    echo "\${port}|\${dnstt_pid}|\${ssh_pid}" >> "\$tmp"
    mv "\$tmp" "\$DNS_PIDS_FILE"
}

save_instance_start_time() {
    local port=\$1
    local tmp=\$(mktemp)
    [ -f "\$DNS_START_TIMES_FILE" ] && grep -v "^\${port}|" "\$DNS_START_TIMES_FILE" > "\$tmp" 2>/dev/null || true
    echo "\${port}|\$(date +%s)" >> "\$tmp"
    mv "\$tmp" "\$DNS_START_TIMES_FILE"
}

is_in_grace_period() {
    local port=\$1
    [ ! -f "\$DNS_START_TIMES_FILE" ] && return 1
    local entry=\$(grep "^\${port}|" "\$DNS_START_TIMES_FILE" | head -1)
    [ -z "\$entry" ] && return 1
    local started=\$(echo "\$entry" | cut -d'|' -f2)
    local now=\$(date +%s)
    [ \$((now - started)) -lt \$SSH_CONNECT_GRACE ] && return 0
    return 1
}

remove_instance_pid() {
    local port=\$1
    if [ -f "\$DNS_PIDS_FILE" ]; then
        local tmp=\$(mktemp)
        grep -v "^\${port}|" "\$DNS_PIDS_FILE" > "\$tmp" 2>/dev/null || true
        mv "\$tmp" "\$DNS_PIDS_FILE"
    fi
}

stop_instance_gracefully() {
    local port=\$1
    if [ -f "\$DNS_PIDS_FILE" ]; then
        local entry=\$(grep "^\${port}|" "\$DNS_PIDS_FILE" | head -1)
        if [ -n "\$entry" ]; then
            local dnstt_pid=\$(echo "\$entry" | cut -d'|' -f2)
            local ssh_pid=\$(echo "\$entry" | cut -d'|' -f3)
            [ -n "\$ssh_pid" ]   && kill_pid_gracefully "\$ssh_pid"
            [ -n "\$dnstt_pid" ] && kill_pid_gracefully "\$dnstt_pid"
        fi
    fi
    pkill -f "dnstt-client.*:\$(dnstt_port_for \$port)" 2>/dev/null || true
    rm -f "logs/askpass_\$port.sh"
    remove_instance_pid "\$port"
}

is_instance_running() {
    local port=\$1
    if [ -f "\$DNS_PIDS_FILE" ]; then
        local entry=\$(grep "^\${port}|" "\$DNS_PIDS_FILE" | head -1)
        if [ -n "\$entry" ]; then
            local ssh_pid=\$(echo "\$entry" | cut -d'|' -f3)
            kill -0 "\$ssh_pid" 2>/dev/null && return 0
        fi
    fi
    return 1
}

start_instance() {
    local port=\$1
    local dns_ip=\$2
    local dnstt_port=\$(dnstt_port_for "\$port")
    local log_file="logs/client_\$port.log"

    stop_instance_gracefully "\$port"

    # Step 1: start dnstt-client in SOCKS5 mode on the intermediate port
    echo "Starting dnstt-client SOCKS5 on 127.0.0.1:\$dnstt_port via DNS \$dns_ip"
    nohup ./dnstt-client -utls Chrome_120 -udp "\$dns_ip:53" -pubkey "\$PUBKEY" "\$DOMAIN" \
        "127.0.0.1:\$dnstt_port" >> "\$log_file" 2>&1 &
    local dnstt_pid=\$!

    # Give dnstt-client a moment to bind
    sleep 0.5
    if ! kill -0 "\$dnstt_pid" 2>/dev/null; then
        echo "WARNING: dnstt-client died immediately on port \$dnstt_port"
        return 1
    fi

    # Step 2: SSH connects to dnstt SOCKS5 port directly with -D (dynamic SOCKS5 forwarding)
    # Use SSH_ASKPASS so no sshpass dependency is needed
    echo "Starting SSH -D \$port → 127.0.0.1:\$dnstt_port as \$SSH_USER"
    local askpass_script="logs/askpass_\$port.sh"
    local ssh_log_file="logs/client_ssh_\$port.log"
    printf '#!/bin/sh\nprintf "%%s" "%s"\n' "\$SSH_PASS" > "\$askpass_script"
    chmod 700 "\$askpass_script"
    nohup env DISPLAY= SSH_ASKPASS="\$askpass_script" SSH_ASKPASS_REQUIRE=force ssh \
        -v \
        -o StrictHostKeyChecking=no \
        -o ExitOnForwardFailure=yes \
        -o ServerAliveInterval=30 \
        -o ServerAliveCountMax=3 \
        -N \
        -D "127.0.0.1:\$port" \
        -p "\$dnstt_port" \
        "\${SSH_USER}@127.0.0.1" \
        >> "\$ssh_log_file" 2>&1 &
    local ssh_pid=\$!

    save_instance_pids "\$port" "\$dnstt_pid" "\$ssh_pid"
    echo "Started: dnstt PID=\$dnstt_pid SSH PID=\$ssh_pid on port \$port"
    sleep 0.5
    if ! kill -0 "\$ssh_pid" 2>/dev/null; then
        echo "WARNING: SSH process died immediately on port \$port"
        kill_pid_gracefully "\$dnstt_pid"
        remove_instance_pid "\$port"
        return 1
    fi
    save_instance_start_time "\$port"
    echo "SSH is connecting through dnstt (grace period: \${SSH_CONNECT_GRACE}s)..."
    return 0
}

get_assigned_dns() {
    local port=\$1
    if [ -f "\$DNS_ASSIGNMENTS_FILE" ]; then
        local assigned_dns=\$(grep "^\${port}|" "\$DNS_ASSIGNMENTS_FILE" | cut -d'|' -f2)
        [ -n "\$assigned_dns" ] && echo "\$assigned_dns" && return 0
    fi
    return 1
}

check_and_restart() {
    local port=\$1
    if ! is_instance_running "\$port"; then
        if is_in_grace_period "\$port"; then
            echo "SSH instance on port \$port is still connecting (within \${SSH_CONNECT_GRACE}s grace period), skipping restart"
            return 0
        fi
        echo "SSH instance on port \$port is not running, restarting..."

        # Diagnose why it's not running
        local pid_entry=\$(grep "^\${port}|" "\$DNS_PIDS_FILE" 2>/dev/null | head -1)
        if [ -z "\$pid_entry" ]; then
            echo "  [diag] port \$port: no entry in \$DNS_PIDS_FILE"
        else
            local dnstt_pid=\$(echo "\$pid_entry" | cut -d'|' -f2)
            local ssh_pid=\$(echo "\$pid_entry" | cut -d'|' -f3)
            echo "  [diag] port \$port: PID file entry: \$pid_entry"
            if kill -0 "\$dnstt_pid" 2>/dev/null; then
                echo "  [diag] port \$port: dnstt-client PID \$dnstt_pid is alive"
            else
                echo "  [diag] port \$port: dnstt-client PID \$dnstt_pid is DEAD"
            fi
            if kill -0 "\$ssh_pid" 2>/dev/null; then
                echo "  [diag] port \$port: SSH PID \$ssh_pid is alive"
            else
                echo "  [diag] port \$port: SSH PID \$ssh_pid is DEAD"
            fi
        fi
        local log_file="logs/client_\$port.log"
        local ssh_log_file="logs/client_ssh_\$port.log"
        if [ -f "\$log_file" ] && [ -s "\$log_file" ]; then
            echo "  [diag] port \$port: last 10 lines of \$log_file (dnstt-client):"
            tail -10 "\$log_file" | sed 's/^/    /'
        else
            echo "  [diag] port \$port: \$log_file is empty or missing"
        fi
        if [ -f "\$ssh_log_file" ] && [ -s "\$ssh_log_file" ]; then
            echo "  [diag] port \$port: last 30 lines of \$ssh_log_file (SSH verbose):"
            tail -30 "\$ssh_log_file" | sed 's/^/    /'
        else
            echo "  [diag] port \$port: \$ssh_log_file is empty or missing"
        fi

        local assigned_dns=\$(get_assigned_dns "\$port")
        if [ -n "\$assigned_dns" ]; then
            echo "  [diag] port \$port: assigned DNS is \$assigned_dns, attempting restart"
            rm -f "logs/client_\$port.log" "logs/client_ssh_\$port.log"
            stop_instance_gracefully "\$port"
            sleep 1
            start_instance "\$port" "\$assigned_dns"
        else
            echo "Warning: No DNS assigned to port \$port, skipping restart"
            local _af_exists=no _af_lines=0
            [ -f "\$DNS_ASSIGNMENTS_FILE" ] && _af_exists=yes && _af_lines=\$(wc -l < "\$DNS_ASSIGNMENTS_FILE")
            echo "  [diag] port \$port: DNS_ASSIGNMENTS_FILE=\$DNS_ASSIGNMENTS_FILE exists=\$_af_exists size=\$_af_lines lines"
            echo "  [diag] port \$port: assignments file contents:"
            cat "\$DNS_ASSIGNMENTS_FILE" 2>/dev/null | sed 's/^/    /' || echo "    (file not readable)"
            echo "  [diag] port \$port: scanner only found \$_af_lines DNS server(s) — not enough for all \$((END_PORT - START_PORT + 1)) ports"
            remove_instance_pid "\$port"
        fi
    fi
}

distribute_dns_to_instances() {
    local DNS_WITH_TUNNELS_FILE="dns_with_tunnels.txt"

    if [ ! -f "\$DNS_WITH_TUNNELS_FILE" ] || [ ! -s "\$DNS_WITH_TUNNELS_FILE" ]; then
        echo "Error: No DNS with tunnels available"
        return 1
    fi

    local current_dns=()
    while IFS= read -r ip; do
        [ -n "\$ip" ] && current_dns+=("\$ip")
    done < "\$DNS_WITH_TUNNELS_FILE"

    if [ \${#current_dns[@]} -eq 0 ]; then
        echo "Error: No DNS with tunnels found"
        return 1
    fi

    echo "Distributing \${#current_dns[@]} DNS servers across SSH instances (round-robin)..."

    declare -A port_assignments
    local idx=0
    for port in \$(seq \$START_PORT \$END_PORT); do
        port_assignments["\$port"]="\${current_dns[\$((idx % \${#current_dns[@]}))]}"
        idx=\$((idx + 1))
    done

    > "\$DNS_ASSIGNMENTS_FILE"
    for port in \$(seq \$START_PORT \$END_PORT); do
        echo "\${port}|\${port_assignments[\$port]}" >> "\$DNS_ASSIGNMENTS_FILE"
        echo "Assigned: DNS \${port_assignments[\$port]} -> Port \$port"
    done

    echo "Starting/restarting SSH instances with assigned DNS..."
    for port in \$(seq \$START_PORT \$END_PORT); do
        start_instance "\$port" "\${port_assignments[\$port]}"
        sleep 0.1
    done

    echo "SSH distribution complete: \${#port_assignments[@]} instances assigned"
    return 0
}

# Initial startup
echo "=========================================="
echo "Starting dnstt-runner (SSH -D mode)"
echo "Working directory: \$(pwd)"
echo "SSH user: \$SSH_USER"
echo "xray SOCKS5 ports (SSH -D): \$START_PORT-\$END_PORT"
echo "dnstt SOCKS5 ports (intermediate): \$DNSTT_BASE_PORT-\$((START_PORT - 1))"
echo "Scan interval: 10 minutes after completion"
echo "=========================================="
echo ""

if [ -f "\$DNS_ASSIGNMENTS_FILE" ] && [ -s "\$DNS_ASSIGNMENTS_FILE" ]; then
    echo "Previous DNS assignments found, starting instances..."
    while IFS='|' read -r port dns_ip; do
        [ -n "\$port" ] && [ -n "\$dns_ip" ] && start_instance "\$port" "\$dns_ip"
    done < "\$DNS_ASSIGNMENTS_FILE"
    echo "Started instances. Periodic scanner will run first scan shortly."
else
    echo "No previous DNS assignments found, running initial scan..."
    scan_and_get_all_dns
    initial_scan_result=\$?
    if [ \$initial_scan_result -eq 0 ]; then
        distribute_dns_to_instances || { echo "ERROR: Failed to distribute DNS. Exiting."; exit 1; }
    else
        echo "ERROR: Initial scan found no DNS servers with tunnels. Exiting."
        exit 1
    fi
fi

# Background periodic scanner
(
    SCAN_COUNT=0
    while true; do
        SCAN_COUNT=\$((SCAN_COUNT + 1))
        scan_start_time=\$(date +%s)

        if [ \$((SCAN_COUNT % 20)) -eq 0 ]; then
            echo "=== Scan #\${SCAN_COUNT}: Full refresh — restoring all IPs from \$DNS_FILE ==="
            if [ -f "\$DNS_FILE" ] && [ -s "\$DNS_FILE" ]; then
                cp "\$DNS_FILE" "\$_DNS_FILE"
                > "\$DNS_FAILURES_FILE"
            fi
        fi

        echo "Running periodic DNS scan (#\${SCAN_COUNT})..."
        scan_and_get_all_dns
        scan_result=\$?
        scan_end_time=\$(date +%s)
        scan_duration=\$((scan_end_time - scan_start_time))

        if [ \$scan_result -eq 0 ]; then
            distribute_dns_to_instances
        else
            refill_dns_file
            echo "Skipping distribution - no tunnels found"
        fi

        next_scan_time=\$((scan_end_time + 600))
        current_time=\$(date +%s)
        sleep_duration=\$((next_scan_time - current_time))
        [ \$sleep_duration -lt 0 ] && sleep_duration=0
        echo "Scan completed in \${scan_duration}s. Next scan in \${sleep_duration}s."
        sleep \$sleep_duration
    done
) &
SCANNER_PID=\$!

cleanup() {
    echo "Shutting down gracefully..."
    kill \$SCANNER_PID 2>/dev/null
    if [ -f "\$DNS_PIDS_FILE" ]; then
        while IFS='|' read -r port _rest; do
            [ -n "\$port" ] && stop_instance_gracefully "\$port"
        done < "\$DNS_PIDS_FILE"
    fi
    pkill -f "dnstt-client.*127.0.0.1:\$DNSTT_BASE_PORT" 2>/dev/null || true
    exit
}
trap cleanup SIGINT SIGTERM

while true; do
    echo "Checking for failed SSH instances..."

    if [ ! -s "\$_DNS_FILE" ]; then
        echo "WARNING: \$_DNS_FILE is empty, attempting to refill..."
        refill_dns_file
    fi

    for port in \$(seq \$START_PORT \$END_PORT); do
        check_and_restart \$port
    done

    echo "Sleeping for 5 seconds before next check..."
    sleep 5
done
DNSTT_SSH_SCRIPT

    chmod +x "$INSTALL_DIR/run_dnstt.sh"
    success "run_dnstt.sh written (SSH mode) → $INSTALL_DIR/run_dnstt.sh"
}

generate_run_slipstream() {
    info "Generating run_slipstream.sh..."

    cat > "$INSTALL_DIR/run_slipstream.sh" <<SLIP_SCRIPT
#!/bin/bash

# Configuration
DNS_FILE="dns.txt"
_DNS_FILE="_dns.txt"
DNS_ASSIGNMENTS_FILE="slip_dns_assignments.txt"
DNS_FAILURES_FILE="slip_dns_failures.txt"
DNS_PIDS_FILE="slip_dns_pids.txt"
DOMAIN="$SLIP_DOMAIN"
SCANNER_DOMAIN="$DNSTT_DOMAIN"
SCANNER_PUBKEY="$DNSTT_PUBKEY"
START_PORT=$SLIP_START_PORT
END_PORT=$SLIP_END_PORT
SCAN_INTERVAL=600

# Create logs directory if it doesn't exist
mkdir -p logs

# Initialize _dns.txt from dns.txt if it doesn't exist
if [ ! -f "\$_DNS_FILE" ]; then
    if [ -f "\$DNS_FILE" ]; then
        echo "Copying \$DNS_FILE to \$_DNS_FILE for faster scanning..."
        cp "\$DNS_FILE" "\$_DNS_FILE"
    else
        echo "WARNING: \$DNS_FILE not found, creating empty \$_DNS_FILE"
        touch "\$_DNS_FILE"
    fi
fi

# Initialize tracking files if they don't exist
[ ! -f "\$DNS_FAILURES_FILE" ] && touch "\$DNS_FAILURES_FILE"
[ ! -f "\$DNS_PIDS_FILE" ]     && touch "\$DNS_PIDS_FILE"

# Function to refill _dns.txt from dns.txt if empty
refill_dns_file() {
    if [ ! -s "\$_DNS_FILE" ]; then
        if [ -f "\$DNS_FILE" ] && [ -s "\$DNS_FILE" ]; then
            echo "WARNING: \$_DNS_FILE is empty, refilling from \$DNS_FILE..."
            cp "\$DNS_FILE" "\$_DNS_FILE"
            echo "Refilled \$_DNS_FILE with \$(wc -l < "\$_DNS_FILE") DNS entries from \$DNS_FILE"
            > "\$DNS_FAILURES_FILE"
            echo "Reset failure tracking"
            return 0
        else
            echo "ERROR: Cannot refill \$_DNS_FILE - \$DNS_FILE is empty or missing"
            return 1
        fi
    fi
    return 0
}

# Scan DNS servers using dnstt-dns-scanner and collect those with tunnels
scan_and_get_all_dns() {
    local DNS_WITH_TUNNELS_FILE="slip_dns_with_tunnels.txt"

    echo "=== Scanning DNS servers for slipstream ==="
    echo "DNS file: \$_DNS_FILE"
    echo "Domain: \$DOMAIN"

    if [ ! -f "./dnstt-dns-scanner" ] && [ ! -f "./dnstt-dns-scanner.exe" ]; then
        echo "ERROR: dnstt-dns-scanner executable not found in current directory"
        return 1
    fi

    if [ ! -f "\$_DNS_FILE" ] || [ ! -s "\$_DNS_FILE" ]; then
        if ! refill_dns_file; then
            echo "ERROR: Cannot proceed with empty DNS file"
            return 1
        fi
    fi

    local dns_count=\$(wc -l < "\$_DNS_FILE" | tr -d ' ')
    local cpu_cores=\$(nproc 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || echo 1)
    local threads=\$((dns_count / 10))
    local max_threads=\$((cpu_cores * 50))
    [ \$max_threads -gt 500 ] && max_threads=500
    [ \$threads -gt \$max_threads ] && threads=\$max_threads
    [ \$threads -lt 1 ] && threads=1
    echo "DNS count: \$dns_count, CPU cores: \$cpu_cores, threads: \$threads (cap: \$max_threads)"

    # Use the dnstt server credentials to scan — slipstream needs reachable DNS servers
    local scanner_out_file=\$(mktemp)
    ./dnstt-dns-scanner -ips "\$_DNS_FILE" -pubkey "\$SCANNER_PUBKEY" \
        -test-domain test.k.markop.ir -test-txt "TEST RESULT" -threads "\$threads" "\$SCANNER_DOMAIN" \
        > "\$scanner_out_file" 2>&1 || true
    cat "\$scanner_out_file"

    # Extract the already-sorted IPs from the "Tunnel-capable DNS servers IPs:" section in one awk pass
    echo "--- Parsing tunnel-capable IPs from scanner output ---"
    awk '/^Tunnel-capable DNS servers IPs:/{found=1; next} found && /^[0-9]/{print} found && !/^[0-9]/{exit}' \
        "\$scanner_out_file" > "\$DNS_WITH_TUNNELS_FILE"
    local tunnel_count=\$(wc -l < "\$DNS_WITH_TUNNELS_FILE" | tr -d ' ')
    echo "Found \$tunnel_count working DNS servers"

    # Update failure tracking in one awk pass (O(N) instead of O(N²) nested loops)
    echo "--- Updating failure tracking ---"
    local fail_inc=1

    local new_failures_file=\$(mktemp)
    local new_dns_file=\$(mktemp)

    awk -v fail_inc="\$fail_inc" -v failures_file="\$DNS_FAILURES_FILE" \
        -v dns_file="\$_DNS_FILE" -v new_dns_file="\$new_dns_file" '
    BEGIN {
        while ((getline line < failures_file) > 0) {
            n = split(line, a, "|")
            if (n == 2) fail_count[a[1]] = a[2]+0
        }
        close(failures_file)
        while ((getline ip < dns_file) > 0) {
            if (ip != "") scanned[ip] = 1
        }
        close(dns_file)
    }
    { is_tunnel[\$1] = 1 }
    END {
        for (ip in scanned) {
            if (ip in is_tunnel) {
                printf "DNS %s: Has tunnel, resetting failure count\n", ip > "/dev/stderr"
            } else {
                cnt = (ip in fail_count ? fail_count[ip] : 0) + fail_inc
                printf "%s|%d\n", ip, cnt
                printf "DNS %s: No tunnel, failure count: %d\n", ip, cnt > "/dev/stderr"
                if (cnt < 10) print ip > new_dns_file
                else printf "DNS %s: Removed from _dns.txt (10 consecutive failures)\n", ip > "/dev/stderr"
            }
        }
    }
    ' "\$DNS_WITH_TUNNELS_FILE" > "\$new_failures_file"

    mv "\$new_failures_file" "\$DNS_FAILURES_FILE"
    # Tunnel IPs always stay in _dns.txt (append them to the surviving-failures list)
    cat "\$DNS_WITH_TUNNELS_FILE" >> "\$new_dns_file"
    sort -u "\$new_dns_file" -o "\$new_dns_file"
    mv "\$new_dns_file" "\$_DNS_FILE"

    rm -f "\$scanner_out_file"

    if [ "\$tunnel_count" -gt 0 ]; then
        echo "=== Saved \$tunnel_count working DNS servers to \$DNS_WITH_TUNNELS_FILE ==="
        return 0
    else
        echo "ERROR: No working DNS servers found!"
        > "\$DNS_WITH_TUNNELS_FILE"
        return 1
    fi
}

# Build slipstream-client command
build_slip_cmd() {
    local dns_ip="\$1"
    local port="\$2"
    echo "./slipstream-client -r \$dns_ip -d \$DOMAIN -l \$port --tcp-listen-host 127.0.0.1"
}

# PID management
get_instance_pid() {
    local port=\$1
    if [ -f "\$DNS_PIDS_FILE" ]; then
        local pid=\$(grep "^\${port}|" "\$DNS_PIDS_FILE" | cut -d'|' -f2)
        if [ -n "\$pid" ] && kill -0 "\$pid" 2>/dev/null; then echo "\$pid"; return 0; fi
        remove_instance_pid "\$port"
    fi
    return 1
}

save_instance_pid() {
    local port=\$1; local pid=\$2
    local temp_file=\$(mktemp)
    [ -f "\$DNS_PIDS_FILE" ] && grep -v "^\${port}|" "\$DNS_PIDS_FILE" > "\$temp_file" 2>/dev/null || true
    echo "\${port}|\${pid}" >> "\$temp_file"
    mv "\$temp_file" "\$DNS_PIDS_FILE"
}

remove_instance_pid() {
    local port=\$1
    if [ -f "\$DNS_PIDS_FILE" ]; then
        local temp_file=\$(mktemp)
        grep -v "^\${port}|" "\$DNS_PIDS_FILE" > "\$temp_file" 2>/dev/null || true
        mv "\$temp_file" "\$DNS_PIDS_FILE"
    fi
}

stop_instance_gracefully() {
    local port=\$1
    local pid=\$(get_instance_pid "\$port")
    if [ -n "\$pid" ] && kill -0 "\$pid" 2>/dev/null; then
        kill -TERM "\$pid" 2>/dev/null
        local wait_count=0
        while [ \$wait_count -lt 50 ] && kill -0 "\$pid" 2>/dev/null; do
            sleep 0.1; wait_count=\$((wait_count + 1))
        done
        kill -0 "\$pid" 2>/dev/null && kill -KILL "\$pid" 2>/dev/null
        remove_instance_pid "\$port"; return 0
    else
        pkill -f "slipstream-client.*\$port" 2>/dev/null; remove_instance_pid "\$port"; return 1
    fi
}

get_assigned_dns() {
    local port=\$1
    [ -f "\$DNS_ASSIGNMENTS_FILE" ] && grep "^\${port}|" "\$DNS_ASSIGNMENTS_FILE" | cut -d'|' -f2
}

is_instance_running() {
    local port=\$1
    local pid=\$(get_instance_pid "\$port")
    [ -n "\$pid" ] && kill -0 "\$pid" 2>/dev/null && return 0
    return 1
}

start_instance() {
    local port=\$1; local dns_ip=\$2
    local log_file="logs/slip_client_\$port.log"
    stop_instance_gracefully "\$port"
    local cmd=\$(build_slip_cmd "\$dns_ip" "\$port")
    echo "Starting slipstream-client on port \$port with DNS \$dns_ip"
    nohup \$cmd > "\$log_file" 2>&1 &
    local pid=\$!
    save_instance_pid "\$port" "\$pid"
    sleep 0.2
    if ! kill -0 "\$pid" 2>/dev/null; then
        echo "WARNING: Process \$pid died immediately after start"
        remove_instance_pid "\$port"; return 1
    fi
    return 0
}

check_and_restart() {
    local port=\$1
    local log_file="logs/slip_client_\$port.log"
    local needs_restart=0
    is_instance_running "\$port" || needs_restart=1

    if [ \$needs_restart -eq 1 ]; then
        echo "Restarting slipstream-client on port \$port"
        local assigned_dns=\$(get_assigned_dns "\$port")
        if [ -n "\$assigned_dns" ]; then
            rm -f "\$log_file"
            stop_instance_gracefully "\$port"
            sleep 1
            start_instance "\$port" "\$assigned_dns"
        else
            echo "Warning: No DNS assigned to port \$port, skipping restart"
            remove_instance_pid "\$port"
        fi
    fi
}

distribute_dns_to_instances() {
    local DNS_WITH_TUNNELS_FILE="slip_dns_with_tunnels.txt"
    [ ! -f "\$DNS_WITH_TUNNELS_FILE" ] || [ ! -s "\$DNS_WITH_TUNNELS_FILE" ] && {
        echo "Error: No working DNS available"; return 1; }

    local current_dns=()
    while IFS= read -r ip; do [ -n "\$ip" ] && current_dns+=("\$ip"); done < "\$DNS_WITH_TUNNELS_FILE"
    [ \${#current_dns[@]} -eq 0 ] && { echo "Error: No DNS found"; return 1; }

    echo "Distributing \${#current_dns[@]} DNS servers across slipstream instances..."

    declare -A port_assignments
    local idx=0
    for port in \$(seq \$START_PORT \$END_PORT); do
        local dns_ip="\${current_dns[\$((idx % \${#current_dns[@]}))]}"
        port_assignments["\$port"]="\$dns_ip"
        idx=\$((idx + 1))
    done

    > "\$DNS_ASSIGNMENTS_FILE"
    for port in \$(seq \$START_PORT \$END_PORT); do
        echo "\${port}|\${port_assignments[\$port]}" >> "\$DNS_ASSIGNMENTS_FILE"
    done

    for port in \$(seq \$START_PORT \$END_PORT); do
        start_instance "\$port" "\${port_assignments[\$port]}"
        sleep 0.1
    done
    echo "Slipstream distribution complete: \${#port_assignments[@]} instances"
    return 0
}

echo "=========================================="
echo "Starting slipstream-runner"
echo "Working directory: \$(pwd)"
echo "Domain: \$DOMAIN"
echo "Port range: \$START_PORT-\$END_PORT"
echo "=========================================="
echo ""

if [ -f "\$DNS_ASSIGNMENTS_FILE" ] && [ -s "\$DNS_ASSIGNMENTS_FILE" ]; then
    echo "Previous assignments found, starting instances..."
    while IFS='|' read -r port dns_ip; do
        [ -n "\$port" ] && [ -n "\$dns_ip" ] && start_instance "\$port" "\$dns_ip"
    done < "\$DNS_ASSIGNMENTS_FILE"
else
    echo "Running initial DNS scan..."
    scan_and_get_all_dns && distribute_dns_to_instances || { echo "ERROR: Initial scan failed. Exiting."; exit 1; }
fi

# Background periodic scanner
(
    SCAN_COUNT=0
    while true; do
        SCAN_COUNT=\$((SCAN_COUNT + 1))
        if [ \$((SCAN_COUNT % 20)) -eq 0 ] && [ -f "\$DNS_FILE" ] && [ -s "\$DNS_FILE" ]; then
            echo "=== Scan #\${SCAN_COUNT}: Full refresh ==="
            cp "\$DNS_FILE" "\$_DNS_FILE"
            > "\$DNS_FAILURES_FILE"
        fi
        scan_start_time=\$(date +%s)
        echo "Running periodic DNS scan (#\${SCAN_COUNT})..."
        if scan_and_get_all_dns; then
            distribute_dns_to_instances
        else
            refill_dns_file
        fi
        scan_end_time=\$(date +%s)
        scan_duration=\$((scan_end_time - scan_start_time))
        sleep_duration=\$((600 - scan_duration))
        [ \$sleep_duration -lt 0 ] && sleep_duration=0
        echo "Scan done in \${scan_duration}s. Next in \${sleep_duration}s."
        sleep \$sleep_duration
    done
) &
SCANNER_PID=\$!

cleanup() {
    echo "Shutting down slipstream-runner..."
    kill \$SCANNER_PID 2>/dev/null
    if [ -f "\$DNS_PIDS_FILE" ]; then
        while IFS='|' read -r port pid; do
            [ -n "\$port" ] && stop_instance_gracefully "\$port"
        done < "\$DNS_PIDS_FILE"
    fi
    pkill -f "slipstream-client" 2>/dev/null
    exit
}
trap cleanup SIGINT SIGTERM

while true; do
    echo "Checking slipstream instances..."
    [ ! -s "\$_DNS_FILE" ] && refill_dns_file
    for port in \$(seq \$START_PORT \$END_PORT); do
        check_and_restart \$port
    done
    sleep 5
done
SLIP_SCRIPT

    chmod +x "$INSTALL_DIR/run_slipstream.sh"
    success "run_slipstream.sh written → $INSTALL_DIR/run_slipstream.sh"
}

generate_run_both() {
    info "Generating run_both.sh (dnstt + slipstream combined)..."

    cat > "$INSTALL_DIR/run_both.sh" <<BOTH_SCRIPT
#!/bin/bash
# Starts both dnstt and slipstream-rust runners side by side.
# dnstt:       ports $DNSTT_START_PORT–$DNSTT_END_PORT
# slipstream:  ports $SLIP_START_PORT–$SLIP_END_PORT

set -euo pipefail

SCRIPT_DIR="\$(cd "\$(dirname "\$0")" && pwd)"
cd "\$SCRIPT_DIR"

mkdir -p logs

echo "Starting dnstt runner (ports $DNSTT_START_PORT–$DNSTT_END_PORT)..."
bash run_dnstt.sh > logs/dnstt-runner.log 2>&1 &
DNSTT_PID=\$!
echo "dnstt runner PID: \$DNSTT_PID"

echo "Starting slipstream runner (ports $SLIP_START_PORT–$SLIP_END_PORT)..."
bash run_slipstream.sh > logs/slip-runner.log 2>&1 &
SLIP_PID=\$!
echo "slipstream runner PID: \$SLIP_PID"

cleanup() {
    echo "Stopping both runners..."
    kill \$DNSTT_PID 2>/dev/null || true
    kill \$SLIP_PID  2>/dev/null || true
    pkill -f "dnstt-client"      2>/dev/null || true
    pkill -f "slipstream-client" 2>/dev/null || true
    exit
}
trap cleanup SIGINT SIGTERM

echo "Both runners started. Logs: logs/dnstt-runner.log and logs/slip-runner.log"
wait
BOTH_SCRIPT

    chmod +x "$INSTALL_DIR/run_both.sh"
    success "run_both.sh written → $INSTALL_DIR/run_both.sh"
}

# ---------------------------------------------------------------------------
# Step 10 — Auto-start service (optional)
# ---------------------------------------------------------------------------
install_service() {
    echo ""
    echo -e "${CYAN}Install as system service (auto-start on boot)? [Y/n]:${NC} \c"
    read -r svc_choice
    [[ "${svc_choice,,}" == "n" ]] && return 0

    if [ "$OS_NAME" = "linux" ]; then
        if ! command -v systemctl &>/dev/null; then
            warn "systemctl not found. Skipping service installation."
            return 0
        fi
        if [ "$(id -u)" -ne 0 ]; then
            warn "Not running as root. Service files will be created but you may need to run:"
            warn "  sudo systemctl daemon-reload && sudo systemctl enable --now dnstt-runner xray-dnstt"
        fi

        local runner_script
        case "${TUNNEL_MODE:-1}" in
            2) runner_script="$INSTALL_DIR/run_slipstream.sh" ;;
            3) runner_script="$INSTALL_DIR/run_both.sh" ;;
            *) runner_script="$INSTALL_DIR/run_dnstt.sh" ;;
        esac

        cat > /tmp/dnstt-runner.service <<EOF
[Unit]
Description=dnstt-runner - DNS tunnel client manager
After=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=/bin/bash ${runner_script}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

        cat > /tmp/xray-dnstt.service <<EOF
[Unit]
Description=xray - dnstt proxy
After=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/xray run -c $INSTALL_DIR/xray-config.json
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

        if [ "$(id -u)" -eq 0 ]; then
            cp /tmp/dnstt-runner.service /etc/systemd/system/
            cp /tmp/xray-dnstt.service /etc/systemd/system/
            systemctl daemon-reload
            if systemctl list-unit-files dnstt-runner.service &>/dev/null 2>&1; then
                info "Restarting services to kill old processes (reinstall)..."
                systemctl restart dnstt-runner xray-dnstt 2>/dev/null || true
            else
                systemctl enable --now dnstt-runner xray-dnstt
            fi
            success "systemd services installed and started."
            SERVICES_STARTED=1
        else
            echo ""
            echo "Run these commands as root to install services:"
            echo "  sudo cp /tmp/dnstt-runner.service /etc/systemd/system/"
            echo "  sudo cp /tmp/xray-dnstt.service /etc/systemd/system/"
            echo "  sudo systemctl daemon-reload && sudo systemctl enable --now dnstt-runner xray-dnstt"
        fi

    elif [ "$OS_NAME" = "darwin" ]; then
        local launch_dir="$HOME/Library/LaunchAgents"
        mkdir -p "$launch_dir"

        local runner_script_mac
        case "${TUNNEL_MODE:-1}" in
            2) runner_script_mac="$INSTALL_DIR/run_slipstream.sh" ;;
            3) runner_script_mac="$INSTALL_DIR/run_both.sh" ;;
            *) runner_script_mac="$INSTALL_DIR/run_dnstt.sh" ;;
        esac

        cat > "$launch_dir/com.dnstt.runner.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.dnstt.runner</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>${runner_script_mac}</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$INSTALL_DIR</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$INSTALL_DIR/logs/runner.log</string>
    <key>StandardErrorPath</key>
    <string>$INSTALL_DIR/logs/runner.err</string>
</dict>
</plist>
EOF

        cat > "$launch_dir/com.dnstt.xray.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.dnstt.xray</string>
    <key>ProgramArguments</key>
    <array>
        <string>$INSTALL_DIR/xray</string>
        <string>run</string>
        <string>-c</string>
        <string>$INSTALL_DIR/xray-config.json</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$INSTALL_DIR</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$INSTALL_DIR/logs/xray.log</string>
    <key>StandardErrorPath</key>
    <string>$INSTALL_DIR/logs/xray.err</string>
</dict>
</plist>
EOF

        mkdir -p "$INSTALL_DIR/logs"
        # Restart if already loaded (reinstall) to kill old processes
        launchctl unload "$launch_dir/com.dnstt.runner.plist" 2>/dev/null || true
        launchctl unload "$launch_dir/com.dnstt.xray.plist" 2>/dev/null || true
        launchctl load "$launch_dir/com.dnstt.runner.plist" 2>/dev/null || true
        launchctl load "$launch_dir/com.dnstt.xray.plist" 2>/dev/null || true
        success "launchd agents installed and loaded."
    fi
}

# ---------------------------------------------------------------------------
# Step 11 — Summary
# ---------------------------------------------------------------------------
print_summary() {
    echo ""
    echo -e "${GREEN}============================================================${NC}"
    echo -e "${GREEN}  Setup Complete!${NC}"
    echo -e "${GREEN}============================================================${NC}"
    echo ""
    echo -e "  Install dir  : ${CYAN}$INSTALL_DIR${NC}"
    echo -e "  DNS file     : dns.txt (${DNS_COUNT:-?} entries)"
    echo -e "  Tunnel mode  : $([ "${TUNNEL_MODE:-1}" = "1" ] && echo "dnstt only" || ([ "${TUNNEL_MODE}" = "2" ] && echo "slipstream-rust only" || echo "Both (dnstt + slipstream-rust)"))"

    case "${TUNNEL_MODE:-1}" in
        1)
            echo -e "  Binaries     : xray, dnstt-client, dnstt-dns-scanner"
            echo -e "  dnstt domain : $DNSTT_DOMAIN"
            echo -e "  dnstt pubkey : ${DNSTT_PUBKEY:0:16}..."
            echo -e "  dnstt inst.  : $DNSTT_INSTANCE_COUNT (ports $DNSTT_START_PORT–$DNSTT_END_PORT)"
            if [ "${DNSTT_MODE:-socks5}" = "ssh" ]; then
                echo -e "  dnstt mode   : SSH -D (dynamic SOCKS5)"
                echo -e "  SSH user     : ${DNSTT_SSH_USER}"
                echo -e "  Scanner dom  : $DNSTT_SCANNER_DOMAIN"
            else
                echo -e "  dnstt mode   : SOCKS5"
            fi
            ;;
        2)
            echo -e "  Binaries     : xray, slipstream-client, dnstt-dns-scanner"
            echo -e "  slip domain  : $SLIP_DOMAIN"
            echo -e "  slip inst.   : $SLIP_INSTANCE_COUNT (ports $SLIP_START_PORT–$SLIP_END_PORT)"
            echo -e "  scan domain  : $DNSTT_DOMAIN (dnstt, for scanner)"
            echo -e "  scan pubkey  : ${DNSTT_PUBKEY:0:16}... (dnstt, for scanner)"
            ;;
        3)
            echo -e "  Binaries     : xray, dnstt-client, slipstream-client, dnstt-dns-scanner"
            echo -e "  dnstt domain : $DNSTT_DOMAIN"
            echo -e "  dnstt pubkey : ${DNSTT_PUBKEY:0:16}..."
            echo -e "  dnstt inst.  : $DNSTT_INSTANCE_COUNT (ports $DNSTT_START_PORT–$DNSTT_END_PORT)"
            echo -e "  slip domain  : $SLIP_DOMAIN"
            echo -e "  slip inst.   : $SLIP_INSTANCE_COUNT (ports $SLIP_START_PORT–$SLIP_END_PORT)"
            ;;
    esac
    echo -e "  Total inst.  : $INSTANCE_COUNT (ports $START_PORT–$END_PORT)"

    if [ "${USE_VLESS:-0}" -eq 1 ]; then
        echo -e "  VLESS port   : $VLESS_PORT"
        echo -e "  VLESS UUID   : $VLESS_UUID"
    fi
    if [ "${USE_MIXED:-0}" -eq 1 ]; then
        echo -e "  Mixed port   : $MIXED_PORT"
    fi
    echo ""
    echo -e "  ${YELLOW}How it works:${NC}"
    echo -e "    1. ${CYAN}dnstt-dns-scanner${NC} scans all DNS servers in ${CYAN}_dns.txt${NC} every 10 minutes."
    case "${TUNNEL_MODE:-1}" in
        1)
            echo -e "    2. Servers with working DNSTT tunnels are ranked and saved to ${CYAN}dns_with_tunnels.txt${NC}."
            echo -e "    3. ${CYAN}run_dnstt.sh${NC} distributes the best DNS servers across $INSTANCE_COUNT dnstt-client instances."
            ;;
        2)
            echo -e "    2. Reachable DNS servers are ranked by latency and saved to ${CYAN}slip_dns_with_tunnels.txt${NC}."
            echo -e "    3. ${CYAN}run_slipstream.sh${NC} distributes DNS servers across $INSTANCE_COUNT slipstream-client instances."
            ;;
        3)
            echo -e "    2. DNSTT-capable servers → ${CYAN}dns_with_tunnels.txt${NC}; reachable servers → ${CYAN}slip_dns_with_tunnels.txt${NC}."
            echo -e "    3. ${CYAN}run_both.sh${NC} launches both dnstt ($DNSTT_INSTANCE_COUNT inst.) and slipstream ($SLIP_INSTANCE_COUNT inst.) runners."
            ;;
    esac
    echo -e "    4. ${CYAN}xray${NC} load-balances your traffic across all live tunnels (strategy: ${XRAY_STRATEGY:-leastPing})."
    echo ""
    echo -e "  ${YELLOW}For now, please wait for the scanner to finish its first scan.${NC}"

    local main_runner_script
    case "${TUNNEL_MODE:-1}" in
        2) main_runner_script="run_slipstream.sh" ;;
        3) main_runner_script="run_both.sh" ;;
        *) main_runner_script="run_dnstt.sh" ;;
    esac

    echo -e "  You can watch progress with:"
    echo -e "    tail -f ${CYAN}$INSTALL_DIR/logs/dnstt-runner.log${NC}"
    echo ""
    echo -e "  To start manually:"
    echo -e "    cd ${CYAN}$INSTALL_DIR${NC}"
    echo -e "    bash $main_runner_script &"
    echo -e "    ./xray run -c xray-config.json"
    echo ""

    if [ "${SERVICES_STARTED:-0}" -eq 1 ]; then
        echo -e "  Service commands:"
        echo -e "    systemctl status dnstt-runner       # check dnstt-runner status"
        echo -e "    systemctl status xray-dnstt         # check xray status"
        echo -e "    journalctl -u dnstt-runner -f       # follow dnstt-runner logs"
        echo -e "    journalctl -u xray-dnstt -f         # follow xray logs"
        echo -e "    systemctl restart dnstt-runner      # restart dnstt-runner"
        echo -e "    systemctl restart xray-dnstt        # restart xray"
        echo ""
        echo -e "  Once the scanner finishes, check tunnel IPs:"
        echo -e "    cat ${CYAN}$INSTALL_DIR/dns_with_tunnels.txt${NC}"
        echo ""
    fi
}

# ---------------------------------------------------------------------------
# Check if our configured ports are in use; only then prompt to stop
# ---------------------------------------------------------------------------
is_port_listening() {
    local port="$1"
    if [ "$OS_NAME" = "linux" ]; then
        ss -tlnp 2>/dev/null | awk -v p="$port" '$4 ~ ":"p"$" {exit 0} END {exit 1}'
    else
        # macOS
        lsof -iTCP -sTCP:LISTEN -i ":${port}" 2>/dev/null | grep -q .
    fi
}

# Build list of ports we will use (xray + dnstt-client range)
get_our_ports() {
    our_ports=""
    [ "${USE_VLESS:-0}" -eq 1 ] && our_ports="${our_ports} ${VLESS_PORT:-}"
    [ "${USE_MIXED:-0}" -eq 1 ] && our_ports="${our_ports} ${MIXED_PORT:-}"
    local p
    for p in $(seq "${START_PORT:-7001}" "${END_PORT:-7001}"); do
        our_ports="${our_ports} ${p}"
    done
    echo "$our_ports"
}

stop_running_instances_if_our_ports_in_use() {
    local our_ports ports_in_use port
    our_ports=$(get_our_ports)
    ports_in_use=""
    for port in $our_ports; do
        [ -z "$port" ] && continue
        if is_port_listening "$port"; then
            ports_in_use="${ports_in_use} ${port}"
        fi
    done
    ports_in_use=$(echo "$ports_in_use" | tr ' ' '\n' | sort -nu | tr '\n' ' ')
    [ -z "${ports_in_use// }" ] && return 0

    echo ""
    warn "The following ports (used by this install) are already in use:${ports_in_use}"
    echo -e "${CYAN}Stop the processes using them and continue? [Y/n]:${NC} \c"
    read -r stop_choice
    if [[ "${stop_choice,,}" == "n" ]]; then
        die "Aborted by user. Free the ports above or stop the processes and re-run."
    fi

    info "Stopping tunnel runners, dnstt-client, slipstream-client, and xray..."
    pkill -f "run_dnstt.sh"      2>/dev/null || true
    pkill -f "run_slipstream.sh" 2>/dev/null || true
    pkill -f "run_both.sh"       2>/dev/null || true
    sleep 1
    pkill -f "dnstt-client"      2>/dev/null || true
    pkill -f "slipstream-client" 2>/dev/null || true
    pkill -x xray 2>/dev/null || pkill -f "xray run" 2>/dev/null || true
    sleep 1
    success "Processes stopped."
}

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------
uninstall() {
    echo ""
    echo -e "${RED}============================================================${NC}"
    echo -e "${RED}  dnstt / slipstream-rust + dnstt-dns-scanner + xray Uninstaller${NC}"
    echo -e "${RED}============================================================${NC}"
    echo ""

    local default_dir="$HOME/dnstt-setup"
    echo -e "${CYAN}Enter install directory to remove [default: $default_dir]:${NC} \c"
    read -r input_dir
    local uninstall_dir="${input_dir:-$default_dir}"
    uninstall_dir="${uninstall_dir/#\~/$HOME}"

    if [ ! -d "$uninstall_dir" ]; then
        die "Directory not found: $uninstall_dir"
    fi

    echo ""
    warn "This will:"
    echo "  - Stop all running dnstt-client, slipstream-client, xray, and runner processes"
    echo "  - Remove systemd/launchd services (if installed)"
    echo "  - Remove runner-created data: logs/, dns_* and slip_* files (tools kept)"
    echo ""
    echo -e "${CYAN}Also remove all tools and the install directory? [y/N]:${NC} \c"
    read -r remove_tools
    local do_remove_tools=false
    [[ "${remove_tools,,}" == "y" ]] && do_remove_tools=true

    echo ""
    echo -e "${RED}Are you sure? [y/N]:${NC} \c"
    read -r confirm
    [[ "${confirm,,}" != "y" ]] && { info "Uninstall cancelled."; exit 0; }

    info "Stopping running processes..."
    pkill -f "run_dnstt.sh"      2>/dev/null || true
    pkill -f "run_slipstream.sh" 2>/dev/null || true
    pkill -f "run_both.sh"       2>/dev/null || true
    sleep 1
    pkill -f "dnstt-client"      2>/dev/null || true
    pkill -f "slipstream-client" 2>/dev/null || true
    pkill -x xray 2>/dev/null || pkill -f "xray run" 2>/dev/null || true
    sleep 1

    # Remove systemd services
    if command -v systemctl &>/dev/null; then
        for svc in dnstt-runner xray-dnstt; do
            if systemctl list-unit-files "$svc.service" &>/dev/null 2>&1; then
                info "Removing systemd service: $svc"
                systemctl disable --now "$svc" 2>/dev/null || true
                rm -f "/etc/systemd/system/$svc.service"
            fi
        done
        systemctl daemon-reload 2>/dev/null || true
    fi

    # Remove launchd agents
    local launch_dir="$HOME/Library/LaunchAgents"
    for plist in com.dnstt.runner com.dnstt.xray; do
        local plist_file="$launch_dir/$plist.plist"
        if [ -f "$plist_file" ]; then
            info "Unloading launchd agent: $plist"
            launchctl unload "$plist_file" 2>/dev/null || true
            rm -f "$plist_file"
        fi
    done

    # Remove runner-created data (logs, dns_* and slip_* files)
    if [ -d "$uninstall_dir/logs" ]; then
        info "Removing logs directory"
        rm -rf "$uninstall_dir/logs"
    fi
    for f in "$uninstall_dir"/dns_* "$uninstall_dir"/slip_*; do
        [ -e "$f" ] || continue
        info "Removing $f"
        rm -f "$f"
    done
    if [ -f "$uninstall_dir/_dns.txt" ]; then
        info "Removing _dns.txt"
        rm -f "$uninstall_dir/_dns.txt"
    fi
    for f in run_dnstt.sh run_slipstream.sh run_both.sh; do
        [ -f "$uninstall_dir/$f" ] && { info "Removing $f"; rm -f "$uninstall_dir/$f"; }
    done

    if [ "$do_remove_tools" = true ]; then
        info "Removing install directory: $uninstall_dir"
        rm -rf "$uninstall_dir"
        success "Uninstall complete (tools and directory removed)."
    else
        success "Uninstall complete (runner data removed; tools kept in $uninstall_dir)."
    fi
    echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  dnstt / slipstream-rust + dnstt-dns-scanner + xray Installer${NC}"
echo -e "${GREEN}============================================================${NC}"
echo ""
echo "  1) Install"
echo "  2) Uninstall"
echo -e "${CYAN}Enter your choice [default: 1]:${NC} \c"
read -r main_choice

if [[ "${main_choice}" == "2" ]]; then
    uninstall
    exit 0
fi

detect_platform
ask_install_dir
check_deps
ask_tunnel_mode
download_tools
ask_resolvers

# Ask settings based on tunnel mode
case "${TUNNEL_MODE:-1}" in
    1)
        ask_dnstt_settings
        DNSTT_INSTANCE_COUNT="${DNSTT_INSTANCE_COUNT:-25}"
        DNSTT_START_PORT="${DNSTT_START_PORT:-7001}"
        DNSTT_END_PORT="${DNSTT_END_PORT:-$((DNSTT_START_PORT + DNSTT_INSTANCE_COUNT - 1))}"
        ;;
    2)
        # Dummy dnstt vars so set_port_range doesn't fail
        DNSTT_INSTANCE_COUNT=0; DNSTT_START_PORT=7001; DNSTT_END_PORT=7000
        ask_slipstream_settings
        ;;
    3)
        ask_dnstt_settings
        ask_slipstream_settings
        ;;
esac

set_port_range
ask_xray_settings
stop_running_instances_if_our_ports_in_use
generate_xray_config
generate_runner_scripts
install_service
print_summary

