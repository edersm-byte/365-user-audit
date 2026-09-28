<#
.SYNOPSIS
    Full Microsoft 365 access audit for one person (one or more accounts): Entra ID and Exchange Online.

.DESCRIPTION
    ENTRA ID (Microsoft Graph), per account
      - Transitive group memberships
      - Directory roles: active, and PIM-eligible when the tenant has Entra ID P2
      - Enterprise app assignments, with the app role name
      - Delegated OAuth consents
      - Owned objects (groups, apps, service principals, policies)
      - For owned apps: API application permissions and secrets/certificates, with a risk flag

    EXCHANGE ONLINE, all accounts together
      - Exchange admin role assignments (non-default ones flagged) and role group memberships
      - Full Access on other mailboxes, found quickly using the unified audit log, shared/resource
        mailboxes and AD automapping links; -FullScan checks every remaining mailbox
      - Full Access and Send As granted through groups the user belongs to
      - Send As and Send on Behalf
      - Mail forwarding and forwarding inbox rules on the user's own mailbox
      - Audit history of permission changes and of access to other mailboxes

.OUTPUTS
    CSV detail in -OutFolder, plus an HTML report saved in the script's folder, or -ReportFolder.

.REQUIREMENTS
    Install-Module Microsoft.Graph -Scope CurrentUser
    Install-Module ExchangeOnlineManagement -Scope CurrentUser
    Roles: Global Reader plus View-Only Audit Logs (audit steps are skipped without it).

.EXAMPLE
    ./Get-M365AccessAudit.ps1                                         # prompts for the account(s)
    ./Get-M365AccessAudit.ps1 -Users jdoe@contoso.com
    ./Get-M365AccessAudit.ps1 -Users jdoe@contoso.com, jdoe@contractor.com -FullScan
    ./Get-M365AccessAudit.ps1 -Users jdoe@contoso.com -SkipExchange
#>
param(
    [string[]]$Users,
    [int]$Days = 180,                 # audit log look-back; 180 for Audit Standard, up to 365+ for Premium
    [switch]$FullScan,                # check every mailbox for Full Access (slow, but complete)
    [switch]$SkipSharedMailboxes,
    [switch]$SkipGraph,
    [switch]$SkipExchange,
    [string]$GraphVersion,            # auto-detected if omitted
    [string]$OutFolder,
    [string]$ReportFolder             # where the HTML report goes; defaults to the script's folder
)

$ErrorActionPreference = 'Stop'

# ============================================================================================
#  SETUP
# ============================================================================================
function Save($data, $folder, $name) {
    $items = @($data | Where-Object { $null -ne $_ })
    $path = Join-Path $folder "$name.csv"
    if ($items.Count) { $items | Export-Csv $path -NoTypeInformation -Encoding UTF8 } else { Set-Content $path 'None found' }
    Write-Host ("  {0,-30} {1,5} entries" -f $name, $items.Count)
    $items.Count
}

while (-not $Users) {
    $answer = Read-Host "Enter the account(s) to audit (UPN or email; separate multiple accounts with commas)"
    $Users = $answer -split '[,;\s]+' | Where-Object { $_ }
}
$Users = @($Users -split '[,;\s]+' | Where-Object { $_ } | Select-Object -Unique)

if (-not $OutFolder) { $OutFolder = "./M365Audit_$($Users[0].Split('@')[0])_$(Get-Date -Format yyyyMMdd_HHmm)" }
New-Item -ItemType Directory -Path $OutFolder -Force | Out-Null

$graphData = [ordered]@{}   # per-account Entra results, used for the report
$exchangeRan = $false
$summary = [System.Collections.Generic.List[string]]::new()
$summary.Add("Microsoft 365 access audit - $(Get-Date -Format 'yyyy-MM-dd HH:mm')")
$summary.Add("Accounts: $($Users -join ', ')")

# Group identities collected from Graph, used to catch Exchange permissions granted via groups
$groupMap = @{}    # identifier (name/mail/alias) -> @{ Name; Users }

# ============================================================================================
#  ENTRA ID (MICROSOFT GRAPH)
# ============================================================================================
if (-not $SkipGraph) {
    # --- Load all Graph modules at one matching version (avoids assembly conflicts) ---------
    $graphModules = 'Microsoft.Graph.Authentication','Microsoft.Graph.Users','Microsoft.Graph.Applications','Microsoft.Graph.Identity.Governance'
    if (-not $GraphVersion) {
        $common = [System.Collections.Generic.List[string]]::new()
        $first = $true
        foreach ($m in $graphModules) {
            [string[]]$v = @(Get-Module -ListAvailable $m | ForEach-Object { $_.Version.ToString() })
            if ($v.Count -eq 0) { throw "$m is not installed. Run: Install-Module Microsoft.Graph -Scope CurrentUser" }
            if ($first) { foreach ($x in $v) { if (-not $common.Contains($x)) { $common.Add($x) } }; $first = $false }
            else { [void]$common.RemoveAll([Predicate[string]]{ param($x) $v -notcontains $x }) }
        }
        if ($common.Count -eq 0) { throw "No single version is installed for all Graph modules. Run: Update-Module Microsoft.Graph -Force" }
        $GraphVersion = ($common | Sort-Object { [version]$_ } -Descending | Select-Object -First 1)
    }
    $loadedAuth = Get-Module Microsoft.Graph.Authentication
    if ($loadedAuth -and $loadedAuth.Version -ne [version]$GraphVersion) {
        throw "Microsoft.Graph.Authentication $($loadedAuth.Version) is already loaded. Open a NEW PowerShell window and run again."
    }
    foreach ($m in $graphModules) { Import-Module $m -RequiredVersion $GraphVersion }

    Write-Host "`n=== ENTRA ID (Graph modules $GraphVersion) ===" -ForegroundColor Cyan
    Connect-MgGraph -Scopes 'User.Read.All','Directory.Read.All','RoleManagement.Read.Directory','Application.Read.All' -NoWelcome

    # PIM needs Entra ID P2 / Governance: test once
    $pimAvailable = $true
    try { Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Top 1 -ErrorAction Stop | Out-Null }
    catch { $pimAvailable = $false; Write-Host "PIM not available (no Entra ID P2); eligible-role check skipped." -ForegroundColor DarkYellow }

    $spCache = @{}
    function Get-SpCached($id) {
        if (-not $spCache.ContainsKey($id)) {
            try   { $spCache[$id] = Get-MgServicePrincipal -ServicePrincipalId $id -Property Id,DisplayName,AppRoles }
            catch { $spCache[$id] = $null }
        }
        $spCache[$id]
    }
    $riskyPermission = 'ReadWrite\.All|Directory\.|RoleManagement|AppRoleAssignment|Mail\.|MailboxSettings|Files\.ReadWrite|Sites\.(FullControl|ReadWrite)|full_access_as_app|User\.ReadWrite|Group\.ReadWrite|Application\.ReadWrite'

    foreach ($upn in $Users) {
        Write-Host "`n--- $upn ---" -ForegroundColor Cyan
        try {
            $user = Get-MgUser -UserId $upn -Property Id,DisplayName,UserPrincipalName,AccountEnabled,OnPremisesSyncEnabled,UserType,CreatedDateTime
        } catch { Write-Warning "Not found in Entra ID: $upn"; $summary.Add("`n[$upn] NOT FOUND in Entra ID"); continue }

        $folder = Join-Path $OutFolder ($upn.Split('@')[0] + '_' + $upn.Split('@')[1].Split('.')[0])
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        Write-Host "$($user.DisplayName) | Enabled: $($user.AccountEnabled) | Synced: $([bool]$user.OnPremisesSyncEnabled) | Type: $($user.UserType) | Created: $($user.CreatedDateTime)"

        # --- Groups ---
        $groups = Get-MgUserTransitiveMemberOf -UserId $user.Id -All | ForEach-Object {
            $ap = $_.AdditionalProperties
            [pscustomobject]@{
                Name = $ap.displayName; Type = ($ap.'@odata.type' -replace '#microsoft.graph.','')
                Id = $_.Id; Mail = $ap.mail; MailNickname = $ap.mailNickname; Security = $ap.securityEnabled
                GroupType = ($ap.groupTypes -join ','); RoleAssignable = $ap.isAssignableToRole
            }
        }
        foreach ($g in $groups | Where-Object Type -eq 'group') {
            foreach ($idv in $g.Name, $g.Mail, $g.MailNickname) {
                if (-not $idv) { continue }
                if (-not $groupMap.ContainsKey($idv)) { $groupMap[$idv] = @{ Name = $g.Name; Mail = $g.Mail; Security = $g.Security; Users = [System.Collections.Generic.HashSet[string]]::new() } }
                [void]$groupMap[$idv].Users.Add($upn)
            }
        }

        # --- Directory roles ---
        $principals = @{ $user.Id = 'Direct' }
        $groups | Where-Object Type -eq 'group' | ForEach-Object { $principals[$_.Id] = "Group: $($_.Name)" }
        $roles = foreach ($principalId in $principals.Keys) {
            Get-MgRoleManagementDirectoryRoleAssignment -Filter "principalId eq '$principalId'" -ExpandProperty roleDefinition -All |
                ForEach-Object { [pscustomobject]@{ Role = $_.RoleDefinition.DisplayName; State = 'Active'; Via = $principals[$principalId]; Scope = $_.DirectoryScopeId } }
            if ($pimAvailable) {
                Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter "principalId eq '$principalId'" -ExpandProperty roleDefinition -All -ErrorAction SilentlyContinue |
                    ForEach-Object { [pscustomobject]@{ Role = $_.RoleDefinition.DisplayName; State = 'Eligible (PIM)'; Via = $principals[$principalId]; Scope = $_.DirectoryScopeId } }
            }
        }
        $groups | Where-Object Type -eq 'directoryRole' | ForEach-Object {
            if (-not ($roles | Where-Object Role -eq $_.Name)) {
                $roles = @($roles) + [pscustomobject]@{ Role = $_.Name; State = 'Active'; Via = 'directoryRole membership'; Scope = '/' }
            }
        }

        # --- App assignments (with role names) ---
        $apps = Get-MgUserAppRoleAssignment -UserId $user.Id -All | ForEach-Object {
            $sp = Get-SpCached $_.ResourceId
            $roleName = if ($_.AppRoleId -eq '00000000-0000-0000-0000-000000000000') { 'Default Access' }
                        else { ($sp.AppRoles | Where-Object Id -eq $_.AppRoleId).DisplayName }
            [pscustomobject]@{ Application = $_.ResourceDisplayName; AppRole = $roleName; AssignedVia = $_.PrincipalDisplayName
                               PrincipalType = $_.PrincipalType; Assigned = $_.CreatedDateTime }
        }

        # --- OAuth consents ---
        $oauth = Get-MgUserOauth2PermissionGrant -UserId $user.Id -All | ForEach-Object {
            [pscustomobject]@{ App = (Get-SpCached $_.ClientId).DisplayName; Resource = (Get-SpCached $_.ResourceId).DisplayName; Scopes = $_.Scope.Trim() }
        }

        # --- Owned objects + owned app detail ---
        $ownedRaw = Get-MgUserOwnedObject -UserId $user.Id -All
        $owned = $ownedRaw | ForEach-Object {
            [pscustomobject]@{ Name = $_.AdditionalProperties.displayName; Type = ($_.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.',''); Id = $_.Id }
        }
        $ownedApps = foreach ($o in $owned | Where-Object Type -in 'application','servicePrincipal') {
            if ($o.Type -eq 'application') {
                $a = Get-MgApplication -ApplicationId $o.Id -Property DisplayName,PasswordCredentials,KeyCredentials
                $expiries = @($a.PasswordCredentials.EndDateTime) + @($a.KeyCredentials.EndDateTime) | Where-Object { $_ }
                [pscustomobject]@{ Name = $o.Name; Type = 'App registration'; ApiAppPermissions = ''
                                   Secrets = @($a.PasswordCredentials).Count; Certificates = @($a.KeyCredentials).Count
                                   LatestCredentialExpiry = ($expiries | Sort-Object -Descending | Select-Object -First 1)
                                   Risk = if (@($a.PasswordCredentials).Count + @($a.KeyCredentials).Count) { 'Has credentials - review' } else { 'None' } }
            } else {
                $perms = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $o.Id -All | ForEach-Object {
                    $api = Get-SpCached $_.ResourceId
                    "$($api.DisplayName): $(($api.AppRoles | Where-Object Id -eq $_.AppRoleId).Value)"
                }
                $permText = ($perms -join '; ')
                [pscustomobject]@{ Name = $o.Name; Type = 'Service principal'; ApiAppPermissions = $permText
                                   Secrets = ''; Certificates = ''; LatestCredentialExpiry = ''
                                   Risk = if ($permText -match $riskyPermission) { 'HIGH - privileged API permission' } elseif ($permText) { 'Has API permissions - review' } else { 'None' } }
            }
        }

        Write-Host "Results:" -ForegroundColor Green
        $n = @{}
        $n.Groups    = Save $groups    $folder 'Entra_Groups'
        $n.Roles     = Save $roles     $folder 'Entra_DirectoryRoles'
        $n.Apps      = Save $apps      $folder 'Entra_AppAssignments'
        $n.OAuth     = Save $oauth     $folder 'Entra_OAuthConsents'
        $n.Owned     = Save $owned     $folder 'Entra_OwnedObjects'
        $n.OwnedApps = Save $ownedApps $folder 'Entra_OwnedAppsDetail'

        $graphData[$upn] = [pscustomobject]@{ User = $user; Groups = $groups; Roles = $roles; Apps = $apps
                                              OAuth = $oauth; Owned = $owned; OwnedApps = $ownedApps }
        if ($roles) { $roles | Format-Table Role, State, Via, Scope -AutoSize | Out-String | Write-Host }
        $risky = @($ownedApps | Where-Object Risk -ne 'None')

        $summary.Add("`n[$upn] $($user.DisplayName) | Enabled: $($user.AccountEnabled) | Synced from AD: $([bool]$user.OnPremisesSyncEnabled) | Type: $($user.UserType)")
        $summary.Add("  Entra directory roles: $(if ($roles) { ($roles | ForEach-Object { "$($_.Role) ($($_.State), $($_.Via))" }) -join '; ' } else { 'None' })")
        $summary.Add("  Groups: $($n.Groups) | App assignments: $($n.Apps) | OAuth consents: $($n.OAuth)")
        $summary.Add("  Owned objects: $($n.Owned) ($((@($owned) | Group-Object Type | ForEach-Object { "$($_.Count) $($_.Name)" }) -join ', '))")
        $summary.Add("  Owned apps needing review: $(if ($risky) { ($risky | ForEach-Object { "$($_.Name) [$($_.Risk)]" }) -join '; ' } else { 'None' })")
    }
}

# ============================================================================================
#  EXCHANGE ONLINE
# ============================================================================================
if (-not $SkipExchange) {
    Write-Host "`n=== EXCHANGE ONLINE ===" -ForegroundColor Cyan
    if (-not (Get-ConnectionInformation -ErrorAction SilentlyContinue)) { Connect-ExchangeOnline -ShowBanner:$false }

    # --- Resolve accounts and every identifier they may appear under ------------------------
    $idToUser = @{}
    $loose = [System.Collections.Generic.List[string]]::new()
    $recipients = foreach ($u in $Users) {
        try { $r = Get-EXORecipient -Identity $u -PropertySets All -ErrorAction Stop }
        catch { Write-Warning "Not found in Exchange Online: $u"; continue }
        foreach ($v in $u, $r.PrimarySmtpAddress, $r.Alias, $r.DisplayName, $r.Name, $r.ExternalDirectoryObjectId, $r.DistinguishedName, $r.Identity) {
            if ($v) { $idToUser["$v"] = $u; if ("$v".Length -ge 5) { $loose.Add("$v".ToLower()) } }
        }
        $r
    }
    foreach ($k in $groupMap.Keys) { if ($groupMap[$k].Mail) { $loose.Add($groupMap[$k].Mail.ToLower()) } }
    $exUsers = @($recipients | ForEach-Object { $idToUser["$($_.PrimarySmtpAddress)"] } | Select-Object -Unique)

    if (-not $exUsers) { Write-Warning "No accounts found in Exchange Online; Exchange section skipped." }
    else {
        $exchangeRan = $true
        # Who does a permission's grantee refer to? Returns user(s) and path, or $null
        function Resolve-Grantee($value) {
            foreach ($v in @($value)) {
                if (-not $v) { continue }; $t = "$v".Trim()
                foreach ($k in $idToUser.Keys) { if ($k -ieq $t) { return [pscustomobject]@{ Users = $idToUser[$k]; Via = 'Direct' } } }
                foreach ($k in $groupMap.Keys) { if ($k -ieq $t) { return [pscustomobject]@{ Users = ($groupMap[$k].Users -join ', '); Via = "Group: $($groupMap[$k].Name)" } } }
            }
            $null
        }
        function Test-Loose($value) {
            foreach ($v in @($value)) {
                if (-not $v) { continue }; $t = "$v".Trim().ToLower()
                if (Resolve-Grantee $t) { return $true }
                foreach ($id in $loose) { if ($t.Contains($id)) { return $true } }
            }; $false
        }
        $candidates = @{}
        function Add-Candidate($mailbox, $reason) {
            if (-not $mailbox) { return }; $k = "$mailbox".Trim()
            if (-not $candidates.ContainsKey($k)) { $candidates[$k] = [System.Collections.Generic.HashSet[string]]::new() }
            [void]$candidates[$k].Add($reason)
        }
        function Search-AuditAll([hashtable]$Params) {
            $sid = [guid]::NewGuid().ToString(); $all = [System.Collections.Generic.List[object]]::new()
            do {
                $batch = @(Search-UnifiedAuditLog @Params -SessionId $sid -SessionCommand ReturnLargeSet -ResultSize 5000)
                foreach ($b in $batch) { $all.Add($b) }
                $total = if ($batch.Count) { $batch[0].ResultCount } else { 0 }
            } while ($batch.Count -gt 0 -and $all.Count -lt $total -and $all.Count -lt 50000)
            if ($all.Count -ge 50000) { Write-Warning "Hit the 50,000-record audit limit; use a smaller -Days window for full coverage." }
            $all | Sort-Object Identity -Unique
        }

        # --- Admin roles and role groups ----------------------------------------------------
        Write-Host "[1/8] Exchange admin roles and role groups..." -ForegroundColor Cyan
        $exRoles = foreach ($u in $exUsers) {
            Get-ManagementRoleAssignment -RoleAssignee $u -Delegating $false -ErrorAction SilentlyContinue |
                Select-Object @{n='User';e={$u}}, Role, RoleAssigneeName, AssignmentMethod, RecipientWriteScope, CustomRecipientWriteScope,
                              @{n='IsDefaultEndUser';e={$_.AssignmentMethod -eq 'RoleAssignmentPolicy'}}
        }
        $roleGroups = foreach ($rg in Get-RoleGroup -ResultSize Unlimited) {
            $members = Get-RoleGroupMember -Identity $rg.Identity -ResultSize Unlimited -ErrorAction SilentlyContinue
            foreach ($m in $members) {
                $hit = Resolve-Grantee @($m.PrimarySmtpAddress, $m.Name, $m.DisplayName)
                if ($hit) { [pscustomobject]@{ RoleGroup = $rg.Name; Users = $hit.Users; Via = $hit.Via; Description = $rg.Description } }
            }
        }

        # --- Own mailbox: forwarding ----------------------------------------------------------
        Write-Host "[2/8] Forwarding on own mailboxes..." -ForegroundColor Cyan
        $forwarding = foreach ($u in $exUsers) {
            try {
                $m = Get-EXOMailbox -Identity $u -Properties ForwardingAddress, ForwardingSmtpAddress, DeliverToMailboxAndForward -ErrorAction Stop
                if ($m.ForwardingAddress -or $m.ForwardingSmtpAddress) {
                    [pscustomobject]@{ User = $u; Type = 'Mailbox forwarding'; Detail = "$($m.ForwardingAddress) $($m.ForwardingSmtpAddress)".Trim(); KeepCopy = $m.DeliverToMailboxAndForward }
                }
                Get-InboxRule -Mailbox $u -ErrorAction SilentlyContinue | Where-Object { $_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo } | ForEach-Object {
                    [pscustomobject]@{ User = $u; Type = "Inbox rule: $($_.Name) (Enabled: $($_.Enabled))"; Detail = (@($_.ForwardTo) + @($_.ForwardAsAttachmentTo) + @($_.RedirectTo) -join '; '); KeepCopy = '' }
                }
            } catch { }   # account has no mailbox
        }

        # --- Audit: permission changes ------------------------------------------------------
        $start = (Get-Date).AddDays(-$Days); $end = Get-Date
        $auditOk = $true; $changes = @(); $activitySummary = @()
        Write-Host "[3/8] Audit log: permission changes (last $Days days)..." -ForegroundColor Cyan
        try {
            $changeRecords = Search-AuditAll @{ StartDate = $start; EndDate = $end
                Operations = 'Add-MailboxPermission','Remove-MailboxPermission','Add-RecipientPermission','Remove-RecipientPermission','Set-Mailbox' }
            $changes = foreach ($rec in $changeRecords) {
                $d = $rec.AuditData | ConvertFrom-Json
                $p = @{}; foreach ($x in $d.Parameters) { $p[$x.Name] = $x.Value }
                $grantee = @($p.User, $p.Trustee, $p.GrantSendOnBehalfTo) | Where-Object { $_ }
                if ($grantee -and (Test-Loose $grantee)) {
                    Add-Candidate $p.Identity 'Audit: permission change'
                    [pscustomobject]@{ Date = $rec.CreationDate; Operation = $d.Operation; Mailbox = $p.Identity
                                       Grantee = ($grantee -join '; '); Rights = $p.AccessRights; ChangedBy = $d.UserId }
                }
            }
            $changes = $changes | Sort-Object Date
        } catch {
            $auditOk = $false
            Write-Warning "Audit log search failed ($($_.Exception.Message)). Audit steps skipped; you may need the View-Only Audit Logs role."
        }

        # --- Audit: delegate activity -------------------------------------------------------
        Write-Host "[4/8] Audit log: access to other mailboxes..." -ForegroundColor Cyan
        if ($auditOk) {
            # RecordType takes a single value, so search each type separately
            $activityRecords = foreach ($rt in 'ExchangeItem','ExchangeItemGroup','ExchangeItemAggregated') {
                try   { Search-AuditAll @{ StartDate = $start; EndDate = $end; UserIds = [string[]]$exUsers; RecordType = $rt } }
                catch { Write-Warning "Audit search for $rt failed: $($_.Exception.Message)" }
            }
            $activity = foreach ($rec in $activityRecords) {
                $d = $rec.AuditData | ConvertFrom-Json
                $targets = @()
                if ($d.MailboxOwnerUPN)        { $targets += $d.MailboxOwnerUPN }
                if ($d.SendAsUserSmtp)         { $targets += $d.SendAsUserSmtp }
                if ($d.SendOnBehalfOfUserSmtp) { $targets += $d.SendOnBehalfOfUserSmtp }
                foreach ($t in $targets | Where-Object { -not ((Resolve-Grantee $_).Via -eq 'Direct') }) {
                    Add-Candidate $t 'Audit: delegate activity'
                    [pscustomobject]@{ User = $d.UserId; Mailbox = $t; Operation = $d.Operation; Date = $rec.CreationDate }
                }
            }
            $activitySummary = $activity | Group-Object User, Mailbox, Operation | ForEach-Object {
                $f = $_.Group[0]
                [pscustomobject]@{ User = $f.User; Mailbox = $f.Mailbox; Operation = $f.Operation; Count = $_.Count
                                   FirstSeen = ($_.Group.Date | Measure-Object -Minimum).Minimum
                                   LastSeen  = ($_.Group.Date | Measure-Object -Maximum).Maximum }
            } | Sort-Object Mailbox, User, Operation
        } else { Write-Host "  skipped" -ForegroundColor DarkGray }

        # --- Other candidate sources --------------------------------------------------------
        Write-Host "[5/8] Shared/resource mailboxes and automapping links..." -ForegroundColor Cyan
        if (-not $SkipSharedMailboxes) {
            Get-EXOMailbox -RecipientTypeDetails SharedMailbox, RoomMailbox, EquipmentMailbox -ResultSize Unlimited -Properties UserPrincipalName |
                ForEach-Object { Add-Candidate $_.UserPrincipalName 'Shared/resource mailbox' }
        }
        if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {
            foreach ($u in $exUsers) {
                try {
                    $ad = Get-ADUser -Filter "UserPrincipalName -eq '$u'" -Properties msExchDelegateListBL
                    foreach ($dn in $ad.msExchDelegateListBL) { Add-Candidate $dn 'AD automapping link' }
                } catch { }
            }
        } else { Write-Host "  ActiveDirectory module not available; automapping links skipped." -ForegroundColor DarkGray }

        # --- Verify current Full Access -----------------------------------------------------
        Write-Host "[6/8] Checking current Full Access on $($candidates.Count) candidate mailboxes..." -ForegroundColor Cyan
        $checked       = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $fullAccess    = [System.Collections.Generic.List[object]]::new()
        $unresolved    = [System.Collections.Generic.List[object]]::new()
        $groupMbx      = [System.Collections.Generic.List[object]]::new()
        $folderPerms   = [System.Collections.Generic.List[object]]::new()
        $sobDirect     = [System.Collections.Generic.List[object]]::new()
        $i = 0
        foreach ($key in @($candidates.Keys)) {
            $i++; if ($i % 50 -eq 0) { Write-Host "  ...$i of $($candidates.Count)" }
            try { $mbx = Get-EXOMailbox -Identity $key -Properties UserPrincipalName, GrantSendOnBehalfTo -ErrorAction Stop }
            catch {
                # Microsoft 365 group mailboxes are not returned by Get-EXOMailbox
                $ug = $null
                try { $ug = Get-UnifiedGroup -Identity $key -ErrorAction Stop } catch { }
                if ($ug) {
                    $roles = @()
                    foreach ($lt in 'Owners','Members') {
                        $links = Get-UnifiedGroupLinks -Identity $ug.Identity -LinkType $lt -ResultSize Unlimited -ErrorAction SilentlyContinue
                        foreach ($l in $links) { if (Resolve-Grantee @($l.PrimarySmtpAddress, $l.Name, $l.DisplayName)) { $roles += $lt.TrimEnd('s') } }
                    }
                    $groupMbx.Add([pscustomobject]@{ GroupMailbox = $ug.PrimarySmtpAddress; GroupName = $ug.DisplayName
                        Access = if ($roles) { ($roles | Select-Object -Unique) -join ', ' } else { 'NOT a member or owner - review' }
                        AccessType = $ug.AccessType; FoundBy = ($candidates[$key] -join '; ') })
                } else {
                    $unresolved.Add([pscustomobject]@{ Candidate = $key; Reason = ($candidates[$key] -join '; ') })
                }
                continue
            }
            if (-not $checked.Add($mbx.UserPrincipalName)) { continue }

            # Mailboxes pointed to by audit activity or automapping: also check delegate-style access
            $reasons = $candidates[$key]
            if ($reasons.Contains('Audit: delegate activity') -or $reasons.Contains('AD automapping link')) {
                foreach ($d in $mbx.GrantSendOnBehalfTo) {
                    $hit = Resolve-Grantee $d
                    if ($hit) { $sobDirect.Add([pscustomobject]@{ Mailbox = $mbx.PrimarySmtpAddress; RecipientTypeDetails = $mbx.RecipientTypeDetails; Delegate = $hit.Users; Via = $hit.Via }) }
                }
                $folders = @([pscustomobject]@{ Name = 'Mailbox root'; Path = "$($mbx.UserPrincipalName):\" })
                foreach ($scope in 'Calendar', 'Inbox') {
                    # Collect first, then pick: Select-Object -First on EXO cmdlets can stop the whole script
                    $fsAll = @(Get-EXOMailboxFolderStatistics -Identity $mbx.UserPrincipalName -FolderScope $scope -ErrorAction SilentlyContinue)
                    $fs = @($fsAll | Where-Object { $_.FolderType -eq $scope })[0]
                    if ($fs) { $folders += [pscustomobject]@{ Name = $scope; Path = "$($mbx.UserPrincipalName):" + ($fs.FolderPath -replace '/', '\') } }
                }
                foreach ($f in $folders) {
                    Get-EXOMailboxFolderPermission -Identity $f.Path -ErrorAction SilentlyContinue | ForEach-Object {
                        $hit = Resolve-Grantee @("$($_.User)", $_.User.DisplayName)
                        if ($hit) {
                            $folderPerms.Add([pscustomobject]@{ Mailbox = $mbx.PrimarySmtpAddress; Folder = $f.Name; Users = $hit.Users; Via = $hit.Via
                                AccessRights = ($_.AccessRights -join ','); SharingPermissionFlags = ($_.SharingPermissionFlags -join ',')
                                CalendarDelegate = [bool]("$($_.SharingPermissionFlags)" -match 'Delegate') })
                        }
                    }
                }
            }
            foreach ($p in Get-EXOMailboxPermission -Identity $mbx.UserPrincipalName -ErrorAction SilentlyContinue | Where-Object { -not $_.Deny }) {
                $hit = Resolve-Grantee $p.User
                if ($hit) {
                    $fullAccess.Add([pscustomobject]@{ Mailbox = $mbx.PrimarySmtpAddress; MailboxType = $mbx.RecipientTypeDetails
                        Users = $hit.Users; Via = $hit.Via; AccessRights = ($p.AccessRights -join ','); IsInherited = $p.IsInherited
                        FoundBy = ($candidates[$key] -join '; ') })
                }
            }
        }

        # --- Optional full scan -------------------------------------------------------------
        $totalMailboxes = $null
        if ($FullScan) {
            Write-Host "[7/8] Full scan of remaining mailboxes (slow)..." -ForegroundColor Cyan
            $allMbx = Get-EXOMailbox -ResultSize Unlimited -Properties UserPrincipalName
            $totalMailboxes = $allMbx.Count
            $remaining = $allMbx | Where-Object { -not $checked.Contains($_.UserPrincipalName) }
            Write-Host "  $(@($remaining).Count) of $totalMailboxes mailboxes still to check."
            $remaining | Get-EXOMailboxPermission -ErrorAction SilentlyContinue | Where-Object { -not $_.Deny } | ForEach-Object {
                $hit = Resolve-Grantee $_.User
                if ($hit) {
                    $fullAccess.Add([pscustomobject]@{ Mailbox = $_.Identity; MailboxType = ''; Users = $hit.Users; Via = $hit.Via
                        AccessRights = ($_.AccessRights -join ','); IsInherited = $_.IsInherited; FoundBy = 'Full scan' })
                }
            }
            $remaining | ForEach-Object { [void]$checked.Add($_.UserPrincipalName) }
        } else { Write-Host "[7/8] Full scan skipped (use -FullScan for complete coverage)." -ForegroundColor DarkGray }

        # --- Send As / Send on Behalf -------------------------------------------------------
        Write-Host "[8/8] Send As and Send on Behalf..." -ForegroundColor Cyan
        $trustees = @($exUsers) + @($groupMap.Values | Where-Object { $_.Mail -and $_.Security } | ForEach-Object Mail | Select-Object -Unique)
        $sendAs = foreach ($t in $trustees) {
            Get-RecipientPermission -Trustee $t -ResultSize Unlimited -ErrorAction SilentlyContinue | ForEach-Object {
                $hit = Resolve-Grantee @($t, $_.Trustee)
                [pscustomobject]@{ Recipient = $_.Identity; Users = $hit.Users; Via = $hit.Via; AccessRights = ($_.AccessRights -join ','); IsInherited = $_.IsInherited }
            }
        }
        $sobFilter = foreach ($r in $recipients) {
            Get-EXOMailbox -ResultSize Unlimited -Filter "GrantSendOnBehalfTo -eq '$($r.DistinguishedName)'" -ErrorAction SilentlyContinue |
                Select-Object @{n='Mailbox';e={$_.PrimarySmtpAddress}}, RecipientTypeDetails, @{n='Delegate';e={$idToUser["$($r.PrimarySmtpAddress)"]}}, @{n='Via';e={'Direct'}}
        }
        $sendOnBehalf = @($sobFilter) + @($sobDirect) | Where-Object { $_ } | Sort-Object Mailbox, Delegate -Unique

        # --- Output -------------------------------------------------------------------------
        Write-Host "`nExchange results:" -ForegroundColor Green
        $e = @{}
        $e.Roles    = Save $exRoles         $OutFolder 'Exchange_AdminRoles'
        $e.RG       = Save $roleGroups      $OutFolder 'Exchange_RoleGroups'
        $e.FA       = Save $fullAccess      $OutFolder 'Exchange_FullAccess'
        $e.SendAs   = Save $sendAs          $OutFolder 'Exchange_SendAs'
        $e.SOB      = Save $sendOnBehalf    $OutFolder 'Exchange_SendOnBehalf'
        $e.Fwd      = Save $forwarding      $OutFolder 'Exchange_Forwarding'
        $e.Changes  = Save $changes         $OutFolder 'Audit_PermissionChanges'
        $e.Activity = Save $activitySummary $OutFolder 'Audit_DelegateActivity'
        $e.Folders  = Save $folderPerms     $OutFolder 'Exchange_FolderPermissions'
        $e.Groups   = Save $groupMbx        $OutFolder 'Exchange_GroupMailboxes'
        $null       = Save $unresolved      $OutFolder 'Audit_CandidatesNotFound'

        $nonDefault = @($exRoles | Where-Object { -not $_.IsDefaultEndUser })
        $coverage = if ($FullScan) { "COMPLETE - all $totalMailboxes mailboxes checked" }
                    else { "PARTIAL - $($checked.Count) candidate mailboxes checked; run with -FullScan to confirm" }

        $summary.Add("`n[Exchange Online]")
        $summary.Add("  Admin roles beyond default end-user: $(if ($nonDefault) { ($nonDefault | ForEach-Object { "$($_.User): $($_.Role)" }) -join '; ' } else { 'None' })")
        $summary.Add("  Role groups: $(if ($roleGroups) { ($roleGroups | ForEach-Object { "$($_.RoleGroup) ($($_.Users), $($_.Via))" }) -join '; ' } else { 'None' })")
        $summary.Add("  Full Access: $(if ($fullAccess.Count) { ($fullAccess | ForEach-Object { "$($_.Mailbox) ($($_.Users), $($_.Via))" }) -join '; ' } else { 'None found' })")
        $summary.Add("  Full Access coverage: $coverage")
        $summary.Add("  Send As: $(if ($sendAs) { ($sendAs | ForEach-Object { "$($_.Recipient) ($($_.Users), $($_.Via))" }) -join '; ' } else { 'None' })")
        $summary.Add("  Send on Behalf: $(if ($sendOnBehalf) { ($sendOnBehalf | ForEach-Object { "$($_.Mailbox) ($($_.Delegate), $($_.Via))" }) -join '; ' } else { 'None' })")
        $summary.Add("  Folder permissions (mailboxes seen in audit): $(if ($folderPerms.Count) { ($folderPerms | ForEach-Object { "$($_.Mailbox) $($_.Folder): $($_.AccessRights)$(if ($_.CalendarDelegate) { ' [calendar delegate]' })" }) -join '; ' } else { 'None' })")
        $review = @($groupMbx | Where-Object Access -like 'NOT*')
        $summary.Add("  Group mailboxes accessed: $($groupMbx.Count)$(if ($review) { " - review: " + (($review | ForEach-Object GroupMailbox) -join ', ') } else { ' (all as member/owner)' })")
        $summary.Add("  Forwarding: $(if ($forwarding) { ($forwarding | ForEach-Object { "$($_.User): $($_.Type) -> $($_.Detail)" }) -join '; ' } else { 'None' })")
        $summary.Add("  Audit (last $Days days): $(if ($auditOk) { "$($e.Changes) permission changes, $($e.Activity) delegate activity entries" } else { 'not available (missing role)' })")
    }
}

# ============================================================================================
#  SUMMARY
# ============================================================================================
$summary.Add("`nNot covered: on-prem AD, SharePoint/OneDrive site permissions, Teams private channels, Azure RBAC, roles inside third-party SaaS apps.")
$summaryPath = Join-Path $OutFolder 'Summary.txt'
$summary | Set-Content $summaryPath -Encoding UTF8
Write-Host "`n================ SUMMARY ================" -ForegroundColor Green
$summary | ForEach-Object { Write-Host $_ }
Write-Host "`nAll output: $((Resolve-Path $OutFolder).Path)" -ForegroundColor Green

# ============================================================================================
#  REPORT (HTML) - saved next to the script
# ============================================================================================
function ConvertTo-HtmlText($t) { [System.Net.WebUtility]::HtmlEncode("$t") }
function New-HtmlTable($data, [string[]]$Columns, [string]$Empty = 'None found') {
    $items = @($data | Where-Object { $null -ne $_ })
    if (-not $items.Count) { return "<p class='none'>$(ConvertTo-HtmlText $Empty)</p>" }
    if (-not $Columns) { $Columns = $items[0].PSObject.Properties.Name }
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('<table><thead><tr>')
    foreach ($c in $Columns) { [void]$sb.Append("<th>$(ConvertTo-HtmlText $c)</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($it in $items) {
        [void]$sb.Append('<tr>')
        foreach ($c in $Columns) {
            $v = $it.$c
            if ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) { $v = ($v | ForEach-Object { "$_" }) -join ', ' }
            if ($c -eq 'Severity') { [void]$sb.Append("<td><span class='sev sev-$("$v".ToLower())'>$(ConvertTo-HtmlText $v)</span></td>") }
            else { [void]$sb.Append("<td>$(ConvertTo-HtmlText $v)</td>") }
        }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table>')
    $sb.ToString()
}

# --- Findings ----------------------------------------------------------------------------
$findings = [System.Collections.Generic.List[object]]::new()
function Add-Finding($sev, $area, $text) { $findings.Add([pscustomobject]@{ Severity = $sev; Area = $area; Finding = $text }) }

foreach ($u in $Users) {
    if (-not $SkipGraph -and -not $graphData.Contains($u)) { Add-Finding 'Info' 'Entra ID' "$u was not found in Entra ID." ; continue }
    if (-not $graphData.Contains($u)) { continue }
    $g = $graphData[$u]
    if (-not $g.User.AccountEnabled) { Add-Finding 'Info' 'Entra ID' "$u is disabled." }
    foreach ($r in @($g.Roles)) { if ($r) { Add-Finding 'High' 'Entra ID' "$u holds directory role '$($r.Role)' ($($r.State), via $($r.Via), scope $($r.Scope))." } }
    foreach ($a in @($g.OwnedApps | Where-Object { $_ -and $_.Risk -ne 'None' })) {
        $sev = if ($a.Risk -like 'HIGH*') { 'High' } else { 'Medium' }
        Add-Finding $sev 'Entra ID' "$u owns $($a.Type.ToLower()) '$($a.Name)': $($a.Risk). $($a.ApiAppPermissions)"
    }
    $safeApps = @($g.OwnedApps | Where-Object { $_ -and $_.Risk -eq 'None' } | ForEach-Object Name | Select-Object -Unique)
    if ($safeApps) { Add-Finding 'Review' 'Entra ID' "$u owns app(s) $($safeApps -join ', ') and can manage their SSO and user assignment (no API permissions or credentials found)." }
    $ownedGroups = @($g.Owned | Where-Object { $_ -and $_.Type -eq 'group' })
    if ($ownedGroups) { Add-Finding 'Info' 'Entra ID' "$u owns $($ownedGroups.Count) group(s) and controls their membership." }
    $oa = @($g.OAuth | Where-Object { $_ })
    if ($oa) { Add-Finding 'Review' 'Entra ID' "$u has consented to $($oa.Count) app(s) acting on their behalf: $(($oa.App | Select-Object -Unique) -join ', ')." }
}
if ($exchangeRan) {
    foreach ($r in $nonDefault)       { Add-Finding 'High'   'Exchange' "$($r.User) holds Exchange role '$($r.Role)' (via $($r.RoleAssigneeName))." }
    foreach ($r in @($roleGroups))    { if ($r) { Add-Finding 'High' 'Exchange' "$($r.Users) is in Exchange role group '$($r.RoleGroup)' ($($r.Via))." } }
    foreach ($f in @($forwarding))    { if ($f) { Add-Finding 'Medium' 'Exchange' "$($f.User): $($f.Type) forwards to $($f.Detail)." } }
    foreach ($f in $fullAccess)       { Add-Finding 'Review' 'Exchange' "$($f.Users) has Full Access to $($f.Mailbox) ($($f.MailboxType), $($f.Via))." }
    foreach ($s in @($sendAs))        { if ($s) { Add-Finding 'Review' 'Exchange' "$($s.Users) can Send As $($s.Recipient) ($($s.Via))." } }
    foreach ($s in @($sendOnBehalf))  { if ($s) { Add-Finding 'Review' 'Exchange' "$($s.Delegate) can Send on Behalf of $($s.Mailbox) ($($s.Via))." } }
    foreach ($f in $folderPerms)      { Add-Finding 'Review' 'Exchange' "$($f.Users) has '$($f.AccessRights)' on $($f.Mailbox) $($f.Folder)$(if ($f.CalendarDelegate) { ' (calendar delegate)' })." }
    foreach ($m in @($groupMbx | Where-Object { $_.Access -like 'NOT*' })) { Add-Finding 'Medium' 'Exchange' "Group mailbox $($m.GroupMailbox) was accessed but the user is not a member or owner." }
    if (-not $FullScan) { Add-Finding 'Info' 'Exchange' "Full Access coverage is partial ($($checked.Count) candidate mailboxes). Run with -FullScan for complete coverage." }
    if (-not $auditOk)  { Add-Finding 'Info' 'Exchange' 'Audit log could not be searched (View-Only Audit Logs role needed); audit-based checks were skipped.' }
}
if (-not ($findings | Where-Object { $_.Severity -in 'High','Medium' })) {
    $findings.Insert(0, [pscustomobject]@{ Severity = 'OK'; Area = 'All'; Finding = 'No administrative or high-risk access was found.' })
}
$order = @{ OK = -1; High = 0; Medium = 1; Review = 2; Info = 3 }
$findingsSorted = $findings | Sort-Object { $order[$_.Severity] }

# --- Build HTML --------------------------------------------------------------------------
$runBy = try { @(Get-ConnectionInformation)[0].UserPrincipalName } catch { '' }
if (-not $runBy) { $runBy = try { (Get-MgContext).Account } catch { '' } }
$html = [System.Text.StringBuilder]::new()
[void]$html.Append(@"
<!DOCTYPE html><html><head><meta charset="utf-8"><title>Microsoft 365 Access Report - $(ConvertTo-HtmlText ($Users -join ', '))</title>
<style>
 body{font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;font-size:12px;color:#222;margin:32px;max-width:1100px}
 h1{color:#1F3A5F;font-size:24px;margin:0 0 4px} h2{color:#1F3A5F;border-bottom:2px solid #1F3A5F;padding-bottom:4px;margin-top:28px}
 h3{color:#1F3A5F;margin:18px 0 6px;font-size:14px} .sub{color:#666;margin-bottom:16px}
 table{border-collapse:collapse;width:100%;margin:4px 0 10px} th{background:#1F3A5F;color:#fff;text-align:left;padding:5px 7px;font-weight:600}
 td{border:1px solid #d5dce6;padding:4px 7px;vertical-align:top} tr:nth-child(even) td{background:#f3f6fa} tr{page-break-inside:avoid}
 .none{color:#777;font-style:italic;margin:2px 0 10px} .meta td:first-child{font-weight:600;width:170px;background:#eef2f7}
 .sev{padding:1px 7px;border-radius:3px;font-weight:600;font-size:11px}
 .sev-high{background:#f8cbad}.sev-medium{background:#ffe699}.sev-review{background:#ddebf7}.sev-info{background:#eeeeee}.sev-ok{background:#c6efce}
 .note{background:#f7f7f7;border-left:3px solid #1F3A5F;padding:6px 10px;color:#444}
 @media print{body{margin:0;max-width:none} h2{page-break-after:avoid} h3{page-break-after:avoid}}
</style></head><body>
<h1>Microsoft 365 Access Report</h1>
<div class="sub">$(ConvertTo-HtmlText ($Users -join '  |  '))</div>
<table class="meta">
<tr><td>Generated</td><td>$(ConvertTo-HtmlText (Get-Date -Format 'yyyy-MM-dd HH:mm'))</td></tr>
<tr><td>Run by</td><td>$(ConvertTo-HtmlText $runBy)</td></tr>
<tr><td>Sections</td><td>$(ConvertTo-HtmlText ((@(if (-not $SkipGraph) {'Entra ID'}) + @(if ($exchangeRan) {'Exchange Online'})) -join ', '))</td></tr>
<tr><td>Audit look-back</td><td>$(ConvertTo-HtmlText "$Days days")</td></tr>
<tr><td>Full Access coverage</td><td>$(ConvertTo-HtmlText $(if ($exchangeRan) { $coverage } else { 'Not run' }))</td></tr>
<tr><td>CSV detail</td><td>$(ConvertTo-HtmlText ((Resolve-Path $OutFolder).Path))</td></tr>
</table>
<h2>1. Findings</h2>
$(New-HtmlTable $findingsSorted 'Severity','Area','Finding')
"@)

# --- Entra per account -------------------------------------------------------------------
if (-not $SkipGraph) {
    [void]$html.Append('<h2>2. Microsoft Entra ID</h2>')
    foreach ($u in $Users) {
        if (-not $graphData.Contains($u)) { [void]$html.Append("<h3>$(ConvertTo-HtmlText $u)</h3><p class='none'>Not found in Entra ID.</p>"); continue }
        $g = $graphData[$u]; $x = $g.User
        [void]$html.Append("<h3>$(ConvertTo-HtmlText "$($x.DisplayName) <$u>")</h3>")
        [void]$html.Append((New-HtmlTable ([pscustomobject]@{ Enabled = $x.AccountEnabled; 'Synced from AD' = [bool]$x.OnPremisesSyncEnabled; Type = $x.UserType; Created = $x.CreatedDateTime })))
        [void]$html.Append('<h3>Directory roles</h3>' + (New-HtmlTable $g.Roles 'Role','State','Via','Scope' 'None'))
        [void]$html.Append("<h3>Group memberships ($(@($g.Groups).Count))</h3>" + (New-HtmlTable $g.Groups 'Name','Type','Mail','Security','GroupType'))
        [void]$html.Append("<h3>Enterprise app assignments ($(@($g.Apps).Count))</h3>" + (New-HtmlTable $g.Apps 'Application','AppRole','AssignedVia','PrincipalType','Assigned'))
        [void]$html.Append('<h3>Delegated OAuth consents</h3>' + (New-HtmlTable $g.OAuth 'App','Resource','Scopes' 'None'))
        [void]$html.Append("<h3>Owned objects ($(@($g.Owned).Count))</h3>" + (New-HtmlTable ($g.Owned | Sort-Object Type, Name) 'Name','Type'))
        [void]$html.Append('<h3>Owned applications - permissions and credentials</h3>' + (New-HtmlTable $g.OwnedApps 'Name','Type','ApiAppPermissions','Secrets','Certificates','LatestCredentialExpiry','Risk' 'No owned applications'))
    }
}

# --- Exchange ----------------------------------------------------------------------------
if ($exchangeRan) {
    $defaultCount = @($exRoles | Where-Object IsDefaultEndUser).Count
    [void]$html.Append(@"
<h2>3. Exchange Online</h2>
<h3>Admin roles</h3>
<p class="note">$defaultCount default end-user role assignment(s) from the Default Role Assignment Policy are not listed. Only roles beyond those are shown.</p>
$(New-HtmlTable $nonDefault 'User','Role','RoleAssigneeName','AssignmentMethod','RecipientWriteScope' 'None beyond default end-user roles')
<h3>Role groups</h3>$(New-HtmlTable $roleGroups 'RoleGroup','Users','Via','Description' 'None')
<h3>Full Access to other mailboxes</h3>
<p class="note">Coverage: $(ConvertTo-HtmlText $coverage)</p>
$(New-HtmlTable $fullAccess 'Mailbox','MailboxType','Users','Via','AccessRights','FoundBy')
<h3>Send As</h3>$(New-HtmlTable $sendAs 'Recipient','Users','Via','AccessRights')
<h3>Send on Behalf</h3>$(New-HtmlTable $sendOnBehalf 'Mailbox','RecipientTypeDetails','Delegate','Via')
<h3>Folder permissions (mailboxes found through audit activity)</h3>$(New-HtmlTable $folderPerms 'Mailbox','Folder','Users','Via','AccessRights','SharingPermissionFlags','CalendarDelegate')
<h3>Microsoft 365 group mailboxes accessed</h3>$(New-HtmlTable $groupMbx 'GroupMailbox','GroupName','Access','AccessType')
<h3>Forwarding on own mailbox</h3>$(New-HtmlTable $forwarding 'User','Type','Detail','KeepCopy' 'None')
<h2>4. Audit log (last $Days days)</h2>
$(if (-not $auditOk) { "<p class='none'>Audit log not available for this run.</p>" } else {
"<h3>Permission changes</h3>$(New-HtmlTable $changes 'Date','Operation','Mailbox','Grantee','Rights','ChangedBy' 'No permission changes in the audit window')
<h3>Activity in other mailboxes</h3>$(New-HtmlTable $activitySummary 'User','Mailbox','Operation','Count','FirstSeen','LastSeen' 'No activity in other mailboxes')" })
"@)
}

[void]$html.Append(@"
<h2>Scope and limitations</h2>
<ul>
<li>Not covered: on-premises Active Directory (use the AD audit script), SharePoint/OneDrive site permissions, Teams private channels, Azure RBAC, and roles inside third-party SaaS applications.</li>
<li>Audit-based results only reach back $Days days. Older permissions are found through the shared/resource mailbox check or a full scan.</li>
<li>Folder permissions are checked only on mailboxes found through audit activity or automapping (root, Calendar and Inbox).</li>
$(if (-not $FullScan) { '<li>Full Access was checked on candidate mailboxes only. Run with <b>-FullScan</b> to check every mailbox.</li>' })
</ul>
</body></html>
"@)

# --- Write HTML ----------------------------------------------------------------------------
if (-not $ReportFolder) { $ReportFolder = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path } }
$reportBase = Join-Path $ReportFolder "M365AccessReport_$($Users[0].Split('@')[0])_$(Get-Date -Format yyyyMMdd_HHmm)"
$htmlPath = "$reportBase.html"
$html.ToString() | Set-Content -Path $htmlPath -Encoding UTF8
Write-Host "Report (HTML): $htmlPath" -ForegroundColor Green
