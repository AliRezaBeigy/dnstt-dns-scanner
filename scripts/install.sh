#!/bin/bash
set -euo pipefail

# =============================================================================
# dnstt + dnstt-dns-scanner + xray install script
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

    # -- dnstt-client --
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
    while IFS= read -r line; do
        if [[ "$line" =~ ^DOMAIN=\"(.*)\" ]]; then
            default_domain="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^PUBKEY=\"(.*)\" ]]; then
            default_pubkey="${BASH_REMATCH[1]}"
        fi
    done < "$script_path" 2>/dev/null
}

ask_dnstt_settings() {
    echo ""
    echo -e "${CYAN}=== dnstt Settings ===${NC}"

    default_domain=""
    default_pubkey=""
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

    while true; do
        echo -e "${CYAN}Enter number of dnstt instances [default: 25]:${NC} \c"
        read -r instance_input
        INSTANCE_COUNT="${instance_input:-25}"
        if [[ "$INSTANCE_COUNT" =~ ^[0-9]+$ ]] && [ "$INSTANCE_COUNT" -ge 1 ] && [ "$INSTANCE_COUNT" -le 100 ]; then
            break
        fi
        warn "Please enter a number between 1 and 100."
    done

    START_PORT=7001
    END_PORT=$((7001 + INSTANCE_COUNT - 1))
    success "Instances: $INSTANCE_COUNT (ports $START_PORT–$END_PORT)"
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
        outbounds="${outbounds}        {
            \"tag\": \"proxy-${i}\",
            \"protocol\": \"socks\",
            \"settings\": {
                \"servers\": [{
                    \"address\": \"127.0.0.1\",
                    \"ota\": false,
                    \"port\": ${port},
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
# Step 9 — Generate run_dnstt.sh (fully embedded, no external template)
# ---------------------------------------------------------------------------
generate_run_dnstt() {
    info "Generating run_dnstt.sh..."

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
START_PORT=7001
END_PORT=$END_PORT
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

# Function to convert latency to a sortable numeric value (milliseconds)
latency_to_sortable() {
    local latency_str="\$1"
    latency_str=\$(echo "\$latency_str" | tr -d ' ' | tr '[:upper:]' '[:lower:]')

    if [[ "\$latency_str" =~ ([0-9.]+)(µs|ms|s) ]]; then
        local value="\${BASH_REMATCH[1]}"
        local unit="\${BASH_REMATCH[2]}"

        case "\$unit" in
            µs) echo "\$value" | awk '{printf "%.10f", \$1/1000}' ;;
            ms) echo "\$value" ;;
            s)  echo "\$value" | awk '{printf "%.10f", \$1*1000}' ;;
        esac
    else
        echo "999999.0"
    fi
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
    local threads=\$((dns_count / 10))
    if [ \$threads -lt 1 ]; then threads=1; fi
    echo "DNS count: \$dns_count, calculated threads: \$threads"

    # When scanning more than 512 DNS, use -quick to skip aggressive tests for speed (do not use quick to find a really good DNS)
    local quick_arg=""
    if [ \$dns_count -gt 512 ]; then
        quick_arg=" -quick"
        echo "Using -quick mode (DNS > 512) to speed up scan; skip aggressive tests."
    fi

    local scanner_output
    local scanner_exit_code
    local scanner_cmd="./dnstt-dns-scanner -ips \$_DNS_FILE -pubkey \$PUBKEY -test-domain test.k.markop.ir -test-txt \"TEST RESULT\" -threads \$threads\${quick_arg} \$DOMAIN"

    echo "Executing command: \$scanner_cmd"
    echo "--- Scanner output ---"
    scanner_output=\$(eval "\$scanner_cmd" 2>&1)
    scanner_exit_code=\$?
    echo "Scanner exit code: \$scanner_exit_code"
    if [ \$scanner_exit_code -ne 0 ]; then
        echo "--- Full scanner output (stderr/stdout) ---"
        echo "\$scanner_output"
        echo "--- End scanner output ---"
        echo "ERROR: Scanner failed with exit code \$scanner_exit_code"
        return 1
    fi

    echo "--- Scanner output ---"
    echo "\$scanner_output"
    echo "--- End scanner output ---"

    echo "--- Parsing scanner output for TUNNEL servers ---"
    local temp_file=\$(mktemp)
    local tunnel_count=0
    local dns_with_tunnels=()

    local scanned_dns=()
    while IFS= read -r ip; do
        [ -n "\$ip" ] && scanned_dns+=("\$ip")
    done < "\$_DNS_FILE"

    while IFS= read -r line; do
        if echo "\$line" | grep -q "TUNNEL"; then
            echo "Found TUNNEL line: \$line"
            tunnel_count=\$((tunnel_count + 1))
            local ip=\$(echo "\$line" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -n1)
            local latency=\$(echo "\$line" | sed -n 's/.*latency:[[:space:]]*\([^)]*\).*/\1/p')
            echo "  Extracted IP: '\$ip', Latency: '\$latency'"
            if [ -n "\$ip" ] && [ -n "\$latency" ]; then
                local latency_sortable=\$(latency_to_sortable "\$latency")
                echo "  Latency sortable value: \$latency_sortable"
                echo "\$latency_sortable|\$ip" >> "\$temp_file"
                dns_with_tunnels+=("\$ip")
            else
                echo "  WARNING: Failed to extract IP or latency from line"
            fi
        fi
    done <<< "\$scanner_output"

    echo "Found \$tunnel_count lines with TUNNEL tag"

    echo "--- Updating failure tracking ---"
    # Quick scan: each failure counts as 5 so we remove bad IPs faster
    local fail_inc=1
    if [ -n "\$quick_arg" ]; then fail_inc=5; fi

    local new_failures_file=\$(mktemp)

    for scanned_ip in "\${scanned_dns[@]}"; do
        local has_tunnel=0
        for tunnel_ip in "\${dns_with_tunnels[@]}"; do
            if [ "\$scanned_ip" = "\$tunnel_ip" ]; then has_tunnel=1; break; fi
        done

        local current_count=0
        if [ -f "\$DNS_FAILURES_FILE" ]; then
            local existing_count=\$(grep "^\${scanned_ip}|" "\$DNS_FAILURES_FILE" | cut -d'|' -f2)
            if [ -n "\$existing_count" ]; then current_count=\$existing_count; fi
        fi

        if [ \$has_tunnel -eq 1 ]; then
            echo "DNS \$scanned_ip: Has tunnel, resetting failure count"
        else
            current_count=\$((current_count + fail_inc))
            echo "DNS \$scanned_ip: No tunnel, failure count: \$current_count"
            echo "\${scanned_ip}|\${current_count}" >> "\$new_failures_file"
            if [ \$current_count -ge 10 ]; then
                echo "DNS \$scanned_ip: Removed from \$_DNS_FILE (10 consecutive failures)"
                local temp_dns_file=\$(mktemp)
                grep -v "^\${scanned_ip}\$" "\$_DNS_FILE" > "\$temp_dns_file"
                mv "\$temp_dns_file" "\$_DNS_FILE"
            fi
        fi
    done

    mv "\$new_failures_file" "\$DNS_FAILURES_FILE"

    if [ -s "\$temp_file" ]; then
        echo "--- Sorting DNS servers by latency ---"
        cat "\$temp_file" | while IFS='|' read latency ip; do echo "  \$ip: \$latency ms"; done
        sort -t'|' -k1 -n "\$temp_file" > "\${temp_file}.sorted"
        mv "\${temp_file}.sorted" "\$temp_file"
        echo "--- Sorted list ---"
        cat "\$temp_file" | while IFS='|' read latency ip; do echo "  \$ip: \$latency ms"; done
        cut -d'|' -f2 "\$temp_file" > "\$DNS_WITH_TUNNELS_FILE"
        echo "=== Saved \$(wc -l < "\$DNS_WITH_TUNNELS_FILE") DNS servers with tunnels to \$DNS_WITH_TUNNELS_FILE ==="
        rm -f "\$temp_file"
        return 0
    else
        echo "ERROR: No DNS servers with TUNNEL tag found in scanner output!"
        echo "Tunnel count: \$tunnel_count"
        rm -f "\$temp_file"
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

    echo "Distributing \${#current_dns[@]} DNS servers across instances..."

    declare -A prev_assignments
    if [ -f "\$DNS_ASSIGNMENTS_FILE" ]; then
        while IFS='|' read -r port dns_ip; do
            [ -n "\$port" ] && [ -n "\$dns_ip" ] && prev_assignments["\$dns_ip"]="\$port"
        done < "\$DNS_ASSIGNMENTS_FILE"
        echo "Loaded \${#prev_assignments[@]} previous DNS assignments"
    fi

    declare -A port_assignments

    for dns_ip in "\${current_dns[@]}"; do
        if [ -n "\${prev_assignments[\$dns_ip]+x}" ]; then
            local port="\${prev_assignments[\$dns_ip]}"
            if [ "\$port" -ge "\$START_PORT" ] && [ "\$port" -le "\$END_PORT" ]; then
                port_assignments["\$port"]="\$dns_ip"
                echo "Preserved assignment: DNS \$dns_ip -> Port \$port"
            fi
        fi
    done

    for dns_ip in "\${current_dns[@]}"; do
        local already_assigned=0
        for assigned_port in "\${!port_assignments[@]}"; do
            if [ "\${port_assignments[\$assigned_port]}" = "\$dns_ip" ]; then
                already_assigned=1; break
            fi
        done
        if [ \$already_assigned -eq 0 ]; then
            for port in \$(seq \$START_PORT \$END_PORT); do
                if [ -z "\${port_assignments[\$port]+x}" ]; then
                    port_assignments["\$port"]="\$dns_ip"
                    echo "New assignment: DNS \$dns_ip -> Port \$port"
                    break
                fi
            done
        fi
    done

    local remaining_dns=()
    for dns_ip in "\${current_dns[@]}"; do
        local found=0
        for assigned_port in "\${!port_assignments[@]}"; do
            if [ "\${port_assignments[\$assigned_port]}" = "\$dns_ip" ]; then found=1; break; fi
        done
        [ \$found -eq 0 ] && remaining_dns+=("\$dns_ip")
    done

    if [ \${#remaining_dns[@]} -gt 0 ]; then
        local remaining_index=0
        for port in \$(seq \$START_PORT \$END_PORT); do
            if [ -z "\${port_assignments[\$port]+x}" ] && [ \$remaining_index -lt \${#remaining_dns[@]} ]; then
                port_assignments["\$port"]="\${remaining_dns[\$remaining_index]}"
                echo "Round-robin assignment: DNS \${remaining_dns[\$remaining_index]} -> Port \$port"
                remaining_index=\$((remaining_index + 1))
            fi
        done
    fi

    > "\$DNS_ASSIGNMENTS_FILE"
    for port in \$(seq \$START_PORT \$END_PORT); do
        if [ -n "\${port_assignments[\$port]+x}" ]; then
            echo "\${port}|\${port_assignments[\$port]}" >> "\$DNS_ASSIGNMENTS_FILE"
        fi
    done

    echo "Starting/restarting instances with assigned DNS..."
    for port in \$(seq \$START_PORT \$END_PORT); do
        if [ -n "\${port_assignments[\$port]+x}" ]; then
            start_instance "\$port" "\${port_assignments[\$port]}"
            sleep 0.1
        else
            echo "No DNS assigned to port \$port, stopping instance gracefully..."
            stop_instance_gracefully "\$port"
        fi
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

        cat > /tmp/dnstt-runner.service <<EOF
[Unit]
Description=dnstt-runner - DNS tunnel client manager
After=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=/bin/bash $INSTALL_DIR/run_dnstt.sh
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
        <string>$INSTALL_DIR/run_dnstt.sh</string>
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
    echo -e "  Binaries     : xray, dnstt-client, dnstt-dns-scanner"
    echo -e "  DNS file     : dns.txt (${DNS_COUNT:-?} entries)"
    echo -e "  Instances    : $INSTANCE_COUNT (ports $START_PORT–$END_PORT)"
    echo -e "  Domain       : $DNSTT_DOMAIN"
    echo -e "  Pubkey       : ${DNSTT_PUBKEY:0:16}..."
    if [ $USE_VLESS -eq 1 ]; then
        echo -e "  VLESS port   : $VLESS_PORT"
        echo -e "  VLESS UUID   : $VLESS_UUID"
    fi
    if [ $USE_MIXED -eq 1 ]; then
        echo -e "  Mixed port   : $MIXED_PORT"
    fi
    echo ""
    echo -e "  ${YELLOW}How it works:${NC}"
    echo -e "    1. ${CYAN}dnstt-dns-scanner${NC} scans all DNS servers in ${CYAN}_dns.txt${NC} every 10 minutes,"
    echo -e "       testing each one for a working DNSTT tunnel to your domain."
    echo -e "    2. Servers with tunnels are ranked by latency and saved to ${CYAN}dns_with_tunnels.txt${NC}."
    echo -e "       Servers that fail 10 consecutive scans are removed from the working list."
    echo -e "    3. Every 20 scans, all IPs are restored from the original ${CYAN}dns.txt${NC} and failure"
    echo -e "       counts are reset — giving previously-removed servers another chance."
    echo -e "    4. ${CYAN}run_dnstt.sh${NC} distributes the best DNS servers across $INSTANCE_COUNT dnstt-client"
    echo -e "       instances, health-checks them every 5 seconds, and restarts any that drop."
    echo -e "    5. ${CYAN}xray${NC} load-balances your traffic across all live tunnels (strategy: ${XRAY_STRATEGY:-leastPing})."
    echo ""
    echo -e "  ${YELLOW}For now, please wait for the scanner to finish its first scan.${NC}"
    echo -e "  You can watch progress with:"
    echo -e "    tail -f ${CYAN}$INSTALL_DIR/logs/dnstt-runner.log${NC}"
    echo -e "  Tunnel results appear in:"
    echo -e "    cat ${CYAN}$INSTALL_DIR/dns_with_tunnels.txt${NC}"
    echo ""
    echo -e "  To start manually:"
    echo -e "    cd ${CYAN}$INSTALL_DIR${NC}"
    echo -e "    bash run_dnstt.sh &"
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

    info "Stopping run_dnstt, dnstt-client, and xray..."
    pkill -f "run_dnstt.sh" 2>/dev/null || true
    sleep 1
    pkill -f "dnstt-client" 2>/dev/null || true
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
    echo -e "${RED}  dnstt + dnstt-dns-scanner + xray Uninstaller${NC}"
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
    echo "  - Stop all running dnstt-client, xray, and run_dnstt.sh processes"
    echo "  - Remove systemd/launchd services (if installed)"
    echo "  - Remove run_dnstt-created data: logs/ and dns_* files (tools kept)"
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
    pkill -f "run_dnstt.sh" 2>/dev/null || true
    sleep 1
    pkill -f "dnstt-client" 2>/dev/null || true
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

    # Remove run_dnstt-created data (logs and dns_* files)
    if [ -d "$uninstall_dir/logs" ]; then
        info "Removing logs directory"
        rm -rf "$uninstall_dir/logs"
    fi
    for f in "$uninstall_dir"/dns_*; do
        [ -e "$f" ] || continue
        info "Removing $f"
        rm -f "$f"
    done
    if [ -f "$uninstall_dir/_dns.txt" ]; then
        info "Removing _dns.txt"
        rm -f "$uninstall_dir/_dns.txt"
    fi

    if [ "$do_remove_tools" = true ]; then
        info "Removing install directory: $uninstall_dir"
        rm -rf "$uninstall_dir"
        success "Uninstall complete (tools and directory removed)."
    else
        success "Uninstall complete (run_dnstt data removed; tools kept in $uninstall_dir)."
    fi
    echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
echo ""
echo -e "${GREEN}============================================================${NC}"
echo -e "${GREEN}  dnstt + dnstt-dns-scanner + xray Installer${NC}"
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
download_tools
ask_resolvers
ask_dnstt_settings
ask_xray_settings
stop_running_instances_if_our_ports_in_use
generate_xray_config
generate_run_dnstt
install_service
print_summary

