# How it works

The script has two sections. Entra ID runs once per account. Exchange Online runs once for all accounts together, so permissions for a person's multiple accounts are matched in a single pass.

## Entra ID

| Check | Graph call | Notes |
|---|---|---|
| Account details | `Get-MgUser` | Enabled, synced from AD, member/guest, created date |
| Group memberships | `Get-MgUserTransitiveMemberOf` | Includes nested groups |
| Directory roles, active | `Get-MgRoleManagementDirectoryRoleAssignment` | Queried for the user **and** every group they belong to, so role-assignable group grants are caught. Scope `/` is tenant-wide; `/administrativeUnits/...` is limited. |
| Directory roles, eligible | `Get-MgRoleManagementDirectoryRoleEligibilitySchedule` | Tested once. Skipped when the tenant has no Entra ID P2. |
| App assignments | `Get-MgUserAppRoleAssignment` | Resolves the app role name and shows the group that grants it |
| OAuth consents | `Get-MgUserOauth2PermissionGrant` | Apps allowed to act on the user's behalf, with scopes |
| Owned objects | `Get-MgUserOwnedObject` | Groups, app registrations, service principals, policies |
| Owned app detail | `Get-MgApplication`, `Get-MgServicePrincipalAppRoleAssignment` | Secrets, certificates and API application permissions for every owned app |

### Why owned apps get extra checks

Owning an app registration lets you add a client secret or certificate and then sign in *as the app*. If that app holds Graph application permissions, the owner can use them, which can be a real privilege path for an otherwise ordinary user. The script flags:

- **High:** a service principal with privileged API permissions (anything matching `ReadWrite.All`, `Directory.*`, `RoleManagement`, `AppRoleAssignment`, `Mail.*`, `MailboxSettings`, `Files.ReadWrite`, `Sites.FullControl/ReadWrite`, `full_access_as_app`, `User.ReadWrite`, `Group.ReadWrite`, `Application.ReadWrite`)
- **Medium:** any other API permissions, or an app registration with secrets or certificates
- **Review:** owned apps with neither. Ownership still lets the user manage SSO settings and user assignment.

## Exchange Online

| Step | What it does |
|---|---|
| 1. Admin roles and role groups | `Get-ManagementRoleAssignment -RoleAssignee`; every role group's members matched against the user and their groups. Default end-user roles from the Default Role Assignment Policy are counted but not flagged. |
| 2. Forwarding | Mailbox-level forwarding and inbox rules that forward or redirect, on the user's own mailbox |
| 3. Audit: permission changes | Grants and removals naming the user or their groups |
| 4. Audit: delegate activity | The user's actions in mailboxes other than their own |
| 5. Candidate sources | All shared, room and equipment mailboxes, plus AD automapping links |
| 6. Verify | Current Full Access on every candidate; folder permissions and Send on Behalf on mailboxes found through activity; M365 group mailbox membership |
| 7. Full scan | With `-FullScan`, every remaining mailbox |
| 8. Send As / Send on Behalf | Tenant-wide, for the user and their mail-enabled security groups |

### The Full Access problem

Exchange stores Full Access on the **mailbox**, not on the user, and there is no reverse query. The only way to prove "this user has Full Access to nothing else" is to read the permissions of every mailbox in the tenant, which can take hours.

The script instead builds a candidate list from signals that point to where access is likely:

| Source | Why it's included |
|---|---|
| Audit: permission changes | Anything granted in the audit window is named directly |
| Audit: delegate activity | Mailboxes the user actually read, sent from, or changed |
| Shared, room, equipment mailboxes | Where the large majority of Full Access is granted |
| AD automapping links | `msExchDelegateListBL` lists mailboxes automapped to the user |

Every candidate is then checked against **current** permissions, so a grant that was later removed does not show up as access. Each result's `FoundBy` column records which signal found it.

What this misses: Full Access on an ordinary user mailbox, granted before the audit window, never used during it, and without automapping. `-FullScan` closes that gap by checking every mailbox the candidate pass did not. The report always states whether coverage was **COMPLETE** or **PARTIAL**.

### The two audit searches

Both use `Search-UnifiedAuditLog` with `ReturnLargeSet` paging, up to 50,000 records per search.

**Permission changes** searches these operations and keeps entries where the grantee is the user or one of their groups:

| Operation | Meaning |
|---|---|
| `Add-MailboxPermission` / `Remove-MailboxPermission` | Full Access granted or removed |
| `Add-RecipientPermission` / `Remove-RecipientPermission` | Send As granted or removed |
| `Set-Mailbox` | Send on Behalf changes |

**Delegate activity** searches three record types, one at a time (the parameter only accepts one value), and keeps actions in mailboxes other than the user's own:

| Record type | Covers |
|---|---|
| `ExchangeItem` | Single-item actions: SendAs, SendOnBehalf, Create, Update, delete |
| `ExchangeItemGroup` | Bulk actions: moving or deleting several items |
| `ExchangeItemAggregated` | `MailItemsAccessed` (reading mail) |

### Delegate-style access

Calendar delegation and folder sharing do not appear as Full Access. For every mailbox found through delegate activity or automapping, the script also reads:

- the mailbox's `GrantSendOnBehalfTo` list directly
- folder permissions on the mailbox root, Calendar and Inbox, using the mailbox's real folder names so non-English mailboxes work
- `SharingPermissionFlags`, where `Delegate` marks a formal calendar delegate

### Group-based grants

Exchange lists a permission granted to a group under the **group's** name. The script collects every group the user belongs to from Graph (display name, mail, alias) and matches permissions against those too, reporting the path as `Via: Group: <name>`. This only works when the Graph section runs, so avoid `-SkipGraph` unless you don't need it.

### Identifier matching

A user can appear in Exchange under their UPN, primary SMTP address, alias, display name, name, object ID or distinguished name. The script resolves all of them for every account and matches exactly for permission checks. For audit log parameters, which are free text, it uses a looser contains-match to build candidates. False positives there are harmless, because every candidate is verified against real permissions.
