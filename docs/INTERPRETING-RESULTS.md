# Interpreting results

## Severity

| Severity | Meaning | Examples |
|---|---|---|
| **High** | Administrative control, or a direct path to it | Entra directory role; Exchange admin role or role group; owned app with privileged API permissions |
| **Medium** | Can move data out or act beyond the user's own scope | Mail forwarding; owned app with secrets/certificates or other API permissions; M365 group mailbox accessed without membership |
| **Review** | Legitimate in most cases, but confirm it matches the user's role | Full Access, Send As, Send on Behalf, calendar delegation, owned apps without permissions, OAuth consents |
| **Info** | Context for the reviewer | Number of owned groups; partial Full Access coverage; audit log not available |
| **OK** | Shown when nothing rated High or Medium was found | |

The severity describes **what the access allows**, not whether it's wrong. A service desk analyst with Full Access to the service desk mailbox is expected; the same finding for someone in finance is worth a question.

## Output files

All CSVs contain `None found` when a check returned nothing.

### Per account (subfolder)

| File | Key columns | Look for |
|---|---|---|
| `Entra_Groups.csv` | Name, Type, Security, GroupType, RoleAssignable | Role-assignable groups; `directoryRole` rows |
| `Entra_DirectoryRoles.csv` | Role, State, Via, Scope | Any row. `Via` shows whether the role comes directly or through a group. |
| `Entra_AppAssignments.csv` | Application, AppRole, AssignedVia | Direct assignments (`PrincipalType = User`) stand out; group-based ones apply to everyone in that group |
| `Entra_OAuthConsents.csv` | App, Resource, Scopes | Mail, Files or `*.ReadWrite` scopes granted to unfamiliar apps |
| `Entra_OwnedObjects.csv` | Name, Type | Applications and service principals |
| `Entra_OwnedAppsDetail.csv` | ApiAppPermissions, Secrets, Certificates, Risk | Anything not `None` |

### Exchange (main folder)

| File | Key columns | Look for |
|---|---|---|
| `Exchange_AdminRoles.csv` | Role, AssignmentMethod, IsDefaultEndUser | Rows where `IsDefaultEndUser` is False |
| `Exchange_RoleGroups.csv` | RoleGroup, Via | Any row |
| `Exchange_FullAccess.csv` | Mailbox, MailboxType, Via, FoundBy | User mailboxes (not shared); access via broad groups |
| `Exchange_SendAs.csv` | Recipient, Via | Send As on a person's mailbox rather than a shared one |
| `Exchange_SendOnBehalf.csv` | Mailbox, Delegate, Via | Usually pairs with calendar delegation |
| `Exchange_FolderPermissions.csv` | Folder, AccessRights, CalendarDelegate | `CalendarDelegate = True` means formal delegate access, which usually includes private items |
| `Exchange_GroupMailboxes.csv` | GroupMailbox, Access | `NOT a member or owner` |
| `Exchange_Forwarding.csv` | Type, Detail | Any external address |
| `Audit_PermissionChanges.csv` | Date, Operation, ChangedBy | Who granted what, and when |
| `Audit_DelegateActivity.csv` | Mailbox, Operation, Count, LastSeen | Whether granted access is actually used; recent activity in unexpected mailboxes |
| `Audit_CandidatesNotFound.csv` | Candidate, Reason | Usually deleted mailboxes or names that couldn't be resolved |

## Reading the audit together with permissions

The two sources answer different questions:

| Permission exists | Activity in audit | Interpretation |
|---|---|---|
| Yes | Yes | Access in active use. Confirm it's still needed. |
| Yes | No | Standing access that isn't used. A candidate for removal. |
| No | Yes | Access was removed since, **or** it comes through a path the script didn't check (another folder, a group without a mail address). Investigate. |

## Common patterns

**Calendar delegate.** `SendOnBehalf` plus `Create`/`Update` activity in another person's mailbox, with a `Calendar` row showing `CalendarDelegate = True` and a matching Send on Behalf entry. Typical for executive assistants.

**Shared mailbox worker.** Full Access and Send As on a shared mailbox, with `MailItemsAccessed` and `SendAs` activity. Normal for team inboxes.

**Contractor to employee.** Two accounts for one person. Audit both together with `-Users` so group-based and duplicate access is visible in one report, then move access to the new account before disabling the old one.

**App owner.** Owns an app registration and service principal with no API permissions or credentials. The user can manage that app's SSO configuration and assignments, nothing more.
