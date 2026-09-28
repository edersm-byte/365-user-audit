# Troubleshooting

## Graph modules

**`Could not load file or assembly 'Microsoft.Graph.Authentication, Version=x.y.z' ... Assembly with same name is already loaded`**

The Graph sub-modules are installed at different versions, and one version of `Microsoft.Graph.Authentication` was loaded before another module asked for a different one. PowerShell can only hold one version per session.

1. Close the window and open a new one. The script cannot recover inside a session where a different version already loaded.
2. Check what's installed:
   ```powershell
   Get-Module -ListAvailable Microsoft.Graph* | Group-Object Version | Select-Object Count, Name
   ```
3. If there's more than one version, update everything to match:
   ```powershell
   Update-Module Microsoft.Graph -Force
   ```
   or remove the stray version, for example:
   ```powershell
   Uninstall-Module Microsoft.Graph.Users -RequiredVersion 2.39.0 -Force
   ```
4. To force a version, run with `-GraphVersion 2.38.1`.

**`Microsoft.Graph.Authentication x.y.z is already loaded in this session`**

The script's own check. Open a new window.

**`No single version is installed for all Graph modules`**

At least one of the four modules has no version in common with the others. Run `Update-Module Microsoft.Graph -Force`.

## Licensing

**`AadPremiumLicenseRequired`**

The tenant has no Entra ID P2 or Entra ID Governance license, which PIM requires. The script tests for this once and skips eligible-role checks. Without PIM, eligible assignments cannot exist, so nothing is missed.

## Audit log

**Audit steps skipped with a warning**

The account lacks **View-Only Audit Logs**. Add it to the Purview **Audit Reader** role group, or another role group that includes that role. The rest of the run is unaffected.

**`Hit the 50,000-record audit limit`**

One search returned the maximum. Use a shorter `-Days` window, or run twice with different windows.

**Delegate activity is empty but the user clearly works in other mailboxes**

Check that mailbox auditing is on for those mailboxes (`Get-EXOMailbox <mailbox> -Properties AuditEnabled`). Also, `MailItemsAccessed` coverage depends on the tenant's audit licensing.

## Exchange

**`Get-EXORecipientPermission: Trustee parameter can be used only with Identity...`**

`Get-EXORecipientPermission` can't search tenant-wide by trustee. The script uses `Get-RecipientPermission` for that reason. If you're adapting the code, keep it that way.

**`Search-UnifiedAuditLog: Cannot process argument transformation on parameter 'RecordType'`**

`-RecordType` accepts a single value. The script searches each record type separately.

**The script stops silently partway through Exchange, printing a raw object**

`Select-Object -First` placed after an Exchange Online cmdlet can terminate the entire script instead of just trimming results. The script avoids that pattern; if you modify it, collect results into an array first and index it:
```powershell
$items = @(Get-EXOMailboxFolderStatistics -Identity $m -FolderScope Calendar)
$first = $items[0]
```

**Microsoft 365 group mailboxes in `Audit_CandidatesNotFound.csv`**

`Get-EXOMailbox` doesn't return group mailboxes. The script falls back to `Get-UnifiedGroup` and lists them in `Exchange_GroupMailboxes.csv` instead. Anything still in the not-found file is usually a deleted mailbox.

**The Full Access check is slow**

With `-FullScan` it reads every mailbox, which can take hours in large tenants. Run without it for the candidate-based check, or schedule the full scan for off-hours.

## PowerShell

**`Cannot overwrite variable PID because it is read-only or constant`**

`$PID` is a built-in automatic variable. If you modify the script, don't use `$pid`, `$host`, `$input` or other automatic variable names for your own variables.
