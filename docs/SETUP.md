# Setup

## 1. Install PowerShell 7

The script runs on Windows, macOS and Linux with PowerShell 7 or later.

| Platform | Install |
|---|---|
| Windows | `winget install Microsoft.PowerShell` |
| macOS | `brew install --cask powershell` |
| Linux | See [Microsoft's install guide](https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-linux) |

## 2. Install the modules

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
Install-Module ExchangeOnlineManagement -Scope CurrentUser
```

The script loads four Graph modules (`Authentication`, `Users`, `Applications`, `Identity.Governance`) and requires them all at the **same version**. It detects the highest version installed for all four and loads that one. If versions are mixed, see [Troubleshooting](TROUBLESHOOTING.md#graph-modules).

## 3. Roles for the account running the script

| Role | Needed for |
|---|---|
| **Global Reader** (Entra ID) | Users, groups, roles, apps, owned objects, and Exchange recipient and permission data |
| **View-Only Audit Logs** (Exchange / Purview) | The two audit log searches. Included in the Purview **Audit Reader** role group. |

Without the audit role the script still runs. The audit steps are skipped with a warning and the report says so.

## 4. Graph consent

On first run, `Connect-MgGraph` requests these delegated scopes:

| Scope | Used for |
|---|---|
| `User.Read.All` | Account details, app assignments, OAuth grants, owned objects |
| `Directory.Read.All` | Group memberships, owned objects, directory roles |
| `RoleManagement.Read.Directory` | Active and PIM-eligible role assignments |
| `Application.Read.All` | Service principals, app registrations, API permissions, credentials |

If your tenant restricts user consent, an administrator must approve these once for the Microsoft Graph Command Line Tools app.

## 5. Run

Open a **new** PowerShell window (so no Graph modules are already loaded), then:

```powershell
./Get-M365AccessAudit.ps1 -Users jdoe@contoso.com
```

You will be prompted to sign in twice: once for Graph, once for Exchange Online.

On macOS, if the Graph browser sign-in hangs, sign in with a device code before running the script:

```powershell
Connect-MgGraph -Scopes 'User.Read.All','Directory.Read.All','RoleManagement.Read.Directory','Application.Read.All' -UseDeviceCode
```

## 6. Optional: AD automapping links

If the machine has the ActiveDirectory module (Windows with RSAT) and your on-premises AD has the Exchange schema, the script also reads `msExchDelegateListBL` to find mailboxes automapped to the user. On macOS and Linux this step is skipped automatically.
