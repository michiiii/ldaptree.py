# ldaptree

Enumerate Active Directory Organizational Unit structures and display them as a hierarchical tree, with GPO links, object counts, and full DNs — all in a single run.

## Installation

```bash
pipx install git+https://github.com/michiiii/ldaptree.py
```

Or clone and install locally:

```bash
git clone https://github.com/michiiii/ldaptree.py
pipx install ./ldaptree.py
```

`pycryptodome` (NTLM auth on Python 3.14+ / modern OpenSSL that no longer exposes MD4) and `impacket` (parsing the `nTSecurityDescriptor` blob for `--acl` / `--object-acls` / `--adcs` / `--takeover`) are installed automatically as dependencies.

## Usage

```bash
ldaptree.py -s <dc> -u <user> -p <password>
```

Only three arguments are required. Everything else is resolved automatically:

- **Base DN** — discovered from the rootDSE `defaultNamingContext`; override with `-b`
- **Username** — a bare sAMAccountName is auto-expanded to a UPN (`sam@dns.domain`) for simple bind
- **Protocol** — LDAPS (port 636) by default; override with `--no-ldaps`

### Options

| Flag | Description |
|------|-------------|
| `-s`, `--server` | LDAP server hostname or IP |
| `-u`, `--user` | Bind username (sAMAccountName, UPN, or `DOMAIN\user`) |
| `-p`, `--password` | Bind password (or use `-H`) |
| `-H`, `--hash` | NT hash for pass-the-hash (`32 hex`, or `LM:NT`) — forces NTLM |
| `-b`, `--base-dn` | Base DN — auto-discovered from rootDSE if omitted |
| `-d`, `--domain` | NetBIOS domain name — forces NTLM auth instead of simple bind |
| `-o`, `--output` | Save output to file |
| `-v`, `--verbose` | Verbose logging |
| `--gc` | Query the Global Catalog (port 3269/3268) for forest-wide enumeration |
| `--containers` | Include well-known containers (`CN=Users`, `CN=Computers`, …) in the tree |
| `--acl` | Flag non-default / abusable ACEs on OUs, GPOs, Sites, GPO-creation, and DCSync (requires impacket) |
| `--object-acls` | Scan every user/computer/group(/gMSA) object for non-default ACEs held by *any* principal — arbitrary delegations between two other accounts, not just yours (requires impacket) |
| `--vuln` | Kerberoast / AS-REP roast, delegation (unconstrained/constrained/RBCD), weak account flags, and secrets in description fields |
| `--groups` | *Added* (non-default) transitive members of privileged groups (Domain/Enterprise Admins, operators, DnsAdmins, …) |
| `--creds` | LAPS local-admin passwords and gMSA managed passwords readable by the current user |
| `--trusts` | Domain / forest trusts (direction, type, transitivity, SID filtering) |
| `--computers` | Computer inventory with OS, flagging end-of-life OSes and stale accounts |
| `--adcs` | AD CS CAs and certificate templates, flagging ESC1/2/3/4/9 (requires impacket) |
| `--takeover` | Scan **every object's** ACL and highlight (in **purple**) the objects the *current user* can take over — takeover-grade rights held by you, your groups, or Everyone/Authenticated Users (requires impacket) |
| `-A`, `--all` | Enable every enumeration module above |
| `--no-ldaps` | Use plain LDAP (port 389/3268) instead of LDAPS |
| `--version` | Show version |

All the enumeration modules are opt-in and composable — run `-A` for everything, or pick the ones you need. They print as labelled sections after the OU tree; findings are filtered to non-default / abusable configurations so the output is signal, not inventory (except `--computers`, which is inventory by design).

## Authentication

**Default** — bare sAMAccountName, everything auto-discovered:

```bash
ldaptree.py -s $AD_DC_FQDN -u $AD_USER_SAMACCOUNTNAME -p $AD_USER_PASS
```

The sAMAccountName is expanded to `user@dns.domain` and a simple bind is performed.

**NTLM** — use `-d` when simple bind is disabled on the DC:

```bash
ldaptree.py -s $AD_DC_FQDN -u $AD_USER_SAMACCOUNTNAME -p $AD_USER_PASS -d DOMAIN
```

**Pass-the-hash** — authenticate with the NT hash instead of a password (`-H` in place of `-p`):

```bash
ldaptree.py -s $AD_DC_FQDN -u $AD_USER_SAMACCOUNTNAME -H $AD_USER_HASH
```

`-H` takes a bare NT hash (`32 hex`) or a full `LM:NT` pair, and forces NTLM (pass-the-hash can't use simple bind, which sends a cleartext password). The `DOMAIN\user` principal is taken from `-u` if you supply it, otherwise from `-d`, otherwise the discovered DNS domain — pass `-d NETBIOS` if the DNS domain is rejected.

NTLM over LDAPS automatically uses TLS channel binding, including on domain
controllers configured with “LDAP server channel binding token requirements:
Always”.

**Global Catalog** — enumerate the entire forest (all domains) via GC port 3269/3268:

```bash
ldaptree.py -s $AD_DC_FQDN -u $AD_USER_SAMACCOUNTNAME -p $AD_USER_PASS --gc
```

The root node is labelled `forest.root (forest)` and object counts span all domains. GPO link resolution may be incomplete — `gPLink` is a partial attribute in the GC and is not always replicated.

## Output

Every run produces a full snapshot of the OU tree — no flags needed:

```
LDAP OU Tree Structure
Base DN: DC=SEVENKINGDOMS,DC=LOCAL
OUs: 9
============================================================
SEVENKINGDOMS.LOCAL [💻 3 👤 17 👥 55]
  +-- Crownlands [OU=Crownlands,DC=sevenkingdoms,DC=local] [💻 0 👤 10 👥 4]
  +-- Domain Controllers [OU=Domain Controllers,DC=sevenkingdoms,DC=local] [💻 1 👤 0 👥 0]
      > #1 Default Domain Controllers Policy [{6AC1786C-016F-11D2-945F-00C04fB984F9}]
  +-- Dorne [OU=Dorne,DC=sevenkingdoms,DC=local] [💻 0 👤 0 👥 0]
  +-- IronIslands [OU=IronIslands,DC=sevenkingdoms,DC=local] [💻 0 👤 0 👥 0]
  +-- Reach [OU=Reach,DC=sevenkingdoms,DC=local] [💻 0 👤 0 👥 0]
  +-- Riverlands [OU=Riverlands,DC=sevenkingdoms,DC=local] [💻 0 👤 0 👥 0]
  +-- Stormlands [OU=Stormlands,DC=sevenkingdoms,DC=local] [💻 0 👤 0 👥 1]
  +-- Vale [OU=Vale,DC=sevenkingdoms,DC=local] [💻 0 👤 0 👥 0]
  +-- Westerlands [OU=Westerlands,DC=sevenkingdoms,DC=local] [💻 0 👤 1 👥 1]
```

**Object counts** `[💻 C  👤 U  👥 G]` are recursive — a parent OU includes all objects beneath it.

**GPO links** are listed in precedence order and prefixed with their link order (`#1` = highest precedence, the GPO that wins on conflicting settings — matching the GPMC *Linked Group Policy Objects* tab). They are colour-coded: green = enabled, grey = disabled. Enforced links are marked `(enforced)` in yellow; disabled links are marked `(disabled)`. An enforced link overrides the normal link order, but its number is still reported as GPMC shows it.

**DNs** are shown inline in grey next to each OU name.

## Non-default ACLs (`--acl`)

`--acl` reads each OU's `nTSecurityDescriptor` (DACL + owner) and flags access-control entries that grant a principal the ability to **take over or restructure the OU** — and, through GPO linking, everything beneath it:

```bash
ldaptree.py -s $AD_DC_FQDN -u $AD_USER_SAMACCOUNTNAME -p $AD_USER_PASS --acl
```

```
  +-- Crownlands [OU=Crownlands,DC=sevenkingdoms,DC=local] [💻 0 👤 10 👥 4]
      ! GenericAll → helpdesk
      ! WriteProperty(gPLink) → jon.snow
      ! WriteOwner → backup-svc (inherited)
```

Rights surfaced: `Owner` (non-default), `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, `CreateChild`, `DeleteChild`, `DeleteTree`, `Delete`, `WriteProperty(All)`, `AllExtendedRights`, and — most importantly — **`WriteProperty(gPLink)`**, which lets the trustee link an attacker-controlled GPO to the OU and thus run code on every computer/user under it. Inherited ACEs are marked `(inherited)`.

To keep the output to genuine delegations, ACEs held by built-in principals that hold rights on every OU **by default** are not shown — both Tier-0 admins (SYSTEM, Administrators, Domain/Enterprise Admins, Domain Controllers, Enterprise Domain Controllers, Creator Owner, Schema Admins, RODCs, `SELF`) and the operator groups AD delegates object create/delete to out of the box (**Account Operators**, Server/Print/Backup Operators — their risk is group membership, not a per-OU delegation). A delegated write scoped to a single benign attribute is also skipped; only object-wide rights and writes to attack-relevant attributes (`gPLink`) are flagged.

Rights are aggregated per trustee: a principal that appears in several ACEs (AD often splits `CreateChild` into one object-scoped ACE per child class) is shown once with the union of its rights, marked `(inherited)` only if *every* one of its ACEs is inherited.

The same analysis is run against every **GPO object** and reported in a section after the tree:

```
Group Policy Objects — non-default rights
GPOs: 7  Flagged: 1
============================================================
Helpdesk Deploy [{AAAA1111-2222-3333-4444-555566667777}]
    ! GenericWrite → helpdesk
    ! WriteDacl → manuel
```

This matters because **whoever can write a GPO object owns every OU it is linked to** — modifying the GPO runs code on all affected computers and users (the SharpGPOAbuse / pyGPOAbuse path). Unlike an over-permissioned OU, an over-permissioned GPO is otherwise invisible in the tree, and the section also surfaces GPOs that aren't linked anywhere. The same default-principal filter applies, plus **Group Policy Creator Owners** (which holds full control over GPOs it creates by default).

Finally, `--acl` reports **who can create new GPOs** (non-default), in a closing section:

```
GPO creation rights — non-default
============================================================
inlanefreight.local
  Group Policy Creator Owners members:
    • manuel
    • gpo-admins (group)
  Delegated CreateChild on CN=Policies,CN=System:
    ! CreateChild → custom-svc
```

Creating a GPO requires `CreateChild` on `CN=Policies,CN=System,<domain>`, held by default only by Domain/Enterprise Admins, SYSTEM, and **Group Policy Creator Owners** (GPCO). GPCO is empty by default, so the tool reports two non-default sources: the **transitive members of GPCO** (expanded via `LDAP_MATCHING_RULE_IN_CHAIN`) and any **custom `CreateChild` delegation** on the container (unscoped, or scoped to the `groupPolicyContainer` class). A principal who can create a GPO can then link it wherever they also hold `WriteProperty(gPLink)` — the two findings chain together.

And it checks the **domain head** for non-default **DCSync** rights:

```
DCSync rights — non-default
============================================================
inlanefreight.local
    !! DCSync (GetChanges + GetChangesAll) → svc-repl
    !  GetChangesAll (partial — not enough alone) → bob
```

DCSync (replicating secrets to dump every password hash, including `krbtgt`) needs **both** the `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` control-access rights on the domain object — or `GenericAll` / all-extended-rights, which grant both. The two rights are unioned per principal even when granted by separate ACEs; anyone holding both (that isn't a default replication principal — DCs, Administrators, SYSTEM, Enterprise DCs, RODCs, DA/EA) is flagged `!!`. Holders of only one right are listed as `partial` for awareness.

> Reading the DACL is a normal authenticated read — no elevated privilege is needed. The SACL is never requested, so `SeSecurityPrivilege` is not required.

## Arbitrary object ACLs (`--object-acls`)

`--acl` only looks at OUs, GPOs, and Sites. It won't show a delegation between two
*other* accounts on a plain user/computer/group object — e.g. one low-privileged
user holding `AddKeyCredentialLink` on another, the kind of edge PowerView's
`Get-DomainObjectAcl` or BloodHound would surface:

```bash
ldaptree.py -s $AD_DC_FQDN -u $AD_USER_SAMACCOUNTNAME -p $AD_USER_PASS --object-acls
```

```
Object ACLs — non-default rights on users/computers/groups
============================================================
inlanefreight.local
  tangui (user) [CN=tangui,CN=Users,DC=inlanefreight,DC=local]
    ! AddKeyCredentialLink → restituyo
```

`--object-acls` pages every `person`/`computer`/`group`/gMSA object in the domain
(the same mechanism `--takeover` uses to sweep every object, but scoped to the
domain NC and reporting every non-default trustee rather than just the current
user's). It's a separate flag from `--acl` because it's real full-domain traffic —
expect it to take noticeably longer on a large domain.

## Attack surface (`--vuln`)

`--vuln` sweeps the domain for the most common Kerberos/delegation abuse targets and prints them in a closing section:

```bash
ldaptree.py -s $AD_DC_FQDN -u $AD_USER_SAMACCOUNTNAME -p $AD_USER_PASS --vuln
```

```
Vulnerable / abusable account configurations
============================================================
inlanefreight.local
  Kerberoastable users (SPN set):
    ◆ svc-sql [MSSQLSvc/sql01.inlanefreight.local:1433  +1 more]
  AS-REP roastable users (pre-auth not required):
    ◆ jdoe
  Unconstrained delegation (non-DC):
    ‼ WEB01$ (computer)
  Constrained delegation:
    ! svc-app (user) [+protocol transition] → cifs/dc01.inlanefreight.local
  Resource-based constrained delegation (RBCD):
    ! WS01$ (computer) ← can be acted on by: attacker-svc, helpdesk
```

What each check looks for:

| Finding | Criterion |
|---------|-----------|
| **Kerberoastable** | Enabled user accounts with a `servicePrincipalName`, excluding `krbtgt` and gMSAs (whose keys aren't crackable). Request a TGS and crack the hash offline. |
| **AS-REP roastable** | Enabled users with `DONT_REQ_PREAUTH` (`userAccountControl` bit `0x400000`). Grab the AS-REP and crack it — no credentials needed. |
| **Unconstrained delegation** | `TRUSTED_FOR_DELEGATION` (`0x80000`) set and **not** a DC (`SERVER_TRUST_ACCOUNT` clear, not in the DC/RODC primary groups). Compromising the host lets you capture any TGT sent to it. |
| **Constrained delegation** | `msDS-AllowedToDelegateTo` populated; the target SPNs are shown. `[+protocol transition]` marks `TRUSTED_TO_AUTH_FOR_DELEGATION` (`0x1000000`), which allows impersonating *any* user (S4U2Self). |
| **RBCD** | `msDS-AllowedToActOnBehalfOfOtherIdentity` populated; the SD is parsed to list the principals that can act on the resource — compromise one of them to take over the account. |
| **Secrets in fields** | `description` / `info` / `comment` containing a password keyword — a classic instant win. |
| **Weak account flags** | `PASSWD_NOTREQD` (may accept an empty password) and reversible-encryption (`0x80`, password recoverable in cleartext) — enabled accounts only, excluding the built-in Guest/krbtgt/DefaultAccount which ship with these flags. |

Delegation checks cover both **user and computer** accounts (each is labelled), since constrained delegation on a service *user* account is common; DCs are excluded because their delegation is expected. Roastable accounts that are also `adminCount=1` (privileged) are marked **⭐** — a roastable admin is a crown jewel. `--vuln` is independent of `--acl` and can be combined with it (and with `--gc` for a forest-wide sweep).

With `--vuln`, the vulnerable objects are **also placed inline in the OU tree**, under the OU that contains them, so you can see *where* each finding lives:

```
  +-- Servers [OU=Servers,DC=inlanefreight,DC=local] [💻 3 👤 0 👥 0]
      ⚠ WEB01$ (computer) [unconstrained-deleg]
      +-- DB [OU=DB,OU=Servers,DC=inlanefreight,DC=local] [💻 1 👤 2 👥 0]
          ⚠ svc-sql (user) [kerberoastable] ⭐adminCount
```

Each object is shown once with all of its labels aggregated; objects in containers that aren't displayed (e.g. `CN=Users`) attach to the nearest ancestor shown — usually the domain root. The flat section above remains the detailed view (SPNs, delegation targets, RBCD principals, secret values).

## What can I take over? (`--takeover`)

Every other module reports *non-default* configurations. `--takeover` answers a different, immediately actionable question: **which objects can the account I'm bound as take over, right now?** It resolves your effective token — your own SID plus every group in it (via the DC-computed `tokenGroups`), plus Everyone / Authenticated Users — then pages through **every object in every partition the DC exposes** (the domain NC, **Configuration**, Schema, and the DNS app partitions), parses each `nTSecurityDescriptor`, and keeps only the objects where *your* token is granted a takeover-grade right (`GenericAll`, `WriteDacl`, `WriteOwner`, `GenericWrite`, `CreateChild`, a `gPLink`/all-attribute write, all-extended-rights, or ownership).

Scanning the **Configuration** partition matters: Sites and the entire AD CS configuration live there, not under the domain head. Linking a GPO to a site — e.g. `New-GPLink -Target "Default-First-Site-Name"`, which applies it to every computer in that site (the DCs, typically) — is a `gPLink` write on a Configuration object, so a domain-NC-only scan (or the OU tree) would never show that you can do it. Findings outside the domain NC are tagged with their partition, e.g. `contoso.local (Configuration)`.

```bash
ldaptree.py -s $AD_DC_FQDN -u $AD_USER_SAMACCOUNTNAME -p $AD_USER_PASS --takeover
```

Because it's about *you*, not defaults, matches are shown **prominently in purple** — both as a closing section and inline in the OU tree:

```
Objects YOU can take over — takeover-grade rights held by j.doe
Controllable objects: 3
============================================================
inlanefreight.local
    ★ GenericAll → svc-sql (user) via Helpdesk-Admins
      CN=svc-sql,OU=Servers,DC=inlanefreight,DC=local
    ★ WriteDacl → WS01$ (computer) via Everyone
      CN=WS01,OU=Servers,DC=inlanefreight,DC=local
    ★ Owner → oldapp (group) via you (j.doe)
      CN=oldapp,OU=Groups,DC=inlanefreight,DC=local
```

`via` tells you *how* the right reaches you — directly, through a group you're in, or through Everyone/Authenticated Users (a right granted to Authenticated Users is a path for every domain user). Owning an object is reported too, since an owner holds implicit `WriteDacl`. Unlike the other ACL views this **does not** filter "default" principals — being in Domain Admins would light up the whole domain, which is the correct answer. Unlike the rest of the tool, this scan is **paged**, so a large domain won't hit the server's result-size limit and get silently truncated — though `--gc` results can be partial because object SDs are incomplete over the Global Catalog port. Requires impacket.

## More enumeration modules

| Flag | What you get |
|------|--------------|
| `--groups` | Transitive membership (via `LDAP_MATCHING_RULE_IN_CHAIN`) of Domain/Enterprise/Schema Admins, the built-in operators, Cert Publishers, Protected Users, GPCO, and **DnsAdmins** (DLL-load → RCE on a DC). Built-in default members (`Administrator`, the nested admin groups, operators) are filtered out — only *added* principals show, and a group with no added members is omitted. |
| `--creds` | **LAPS** local-admin passwords (`ms-Mcs-AdmPwd` / `msLAPS-Password`) and **gMSA** managed passwords — confidential attributes only come back when *you* can read them, so anything shown is a credential you can use. Non-readable LAPS hosts are summarised; for gMSAs you can't read, the authorised readers are listed as onward targets. |
| `--trusts` | Domain/forest trusts with direction (`← → ↔`), type, and `trustAttributes` flags (within-forest, forest-transitive, SID-filtering, non-transitive, …). |
| `--computers` | Full computer inventory (hostname, OS, last logon) flagging **EOL OSes** and **stale** accounts (>90 days). |
| `--adcs` | AD CS CAs and certificate templates, flagging **ESC1/2/3/4/9** and non-default control over the CA object (ESC7-ish). |

### AD CS (`--adcs`)

```
AD CS — certificate authorities & vulnerable templates
============================================================
CA: INLANE-CA @ dc01.inlanefreight.local (12 templates published)
Vulnerable templates: 1
  UserAuth (enabled) [ESC1]
    enrollable by: Domain Users
(ESC6/ESC8/ESC11 need CA registry / HTTP / RPC access — not checked over LDAP)
```

Each `pKICertificateTemplate` is evaluated from LDAP alone: **ESC1** (enrollee supplies the subject + an authentication EKU + no manager approval + no RA signature + a non-admin can enroll), **ESC2** (Any-Purpose EKU), **ESC3** (Enrollment-Agent EKU), **ESC4** (a **low-privileged** principal has object-wide write — GenericAll/GenericWrite/WriteDacl/WriteOwner — over the template), and **ESC9** (`CT_FLAG_NO_SECURITY_EXTENSION`). "Enrollable by" and "writable by" come from parsing each template's DACL (the `Certificate-Enrollment` extended right).

ESC4 and the ESC7 CA-object check are deliberately restricted to **low-privileged** trustees (Everyone / Authenticated Users / Domain Users / Domain Computers / Users). Admins and the CA's own host machine account hold these rights on the built-in templates *by default*, so flagging them would bury real findings in noise — a single-attribute `WriteProperty` is likewise not treated as ESC4. The trade-off: a delegation to a **custom** (non-low-priv) group won't show; run [Certipy](https://github.com/ly4k/Certipy) for exhaustive template-ACL analysis, and to confirm/exploit ESC6/ESC8/ESC11 (which depend on CA registry / HTTP / RPC state and aren't LDAP-observable).

> The modules that parse security descriptors (`--acl`, `--object-acls`, `--adcs`, `--takeover`) need impacket; the rest are pure LDAP reads.

## Save to file

```bash
ldaptree.py -s $AD_DC_FQDN -u $AD_USER_SAMACCOUNTNAME -p $AD_USER_PASS -o results.txt
```

ANSI colour codes are included in saved files. Strip them if needed:

```bash
sed 's/\x1b\[[0-9;]*m//g' results.txt
```

## Legal

Use only on systems you own or have explicit written permission to test.
