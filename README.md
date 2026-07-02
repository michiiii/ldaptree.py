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

`pycryptodome` is required for NTLM authentication (`-d`) on Python 3.14+ and modern OpenSSL builds that no longer expose MD4. It is installed automatically.

`impacket` is required only for `--acl` (parsing the `nTSecurityDescriptor` blob). It is **not** installed by default — pull it in with the `acl` extra:

```bash
pipx install 'git+https://github.com/michiiii/ldaptree.py#egg=ldaptree[acl]'
# or, for a local clone:
pipx install './ldaptree.py[acl]'
```

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
| `-p`, `--password` | Bind password |
| `-b`, `--base-dn` | Base DN — auto-discovered from rootDSE if omitted |
| `-d`, `--domain` | NetBIOS domain name — forces NTLM auth instead of simple bind |
| `-o`, `--output` | Save output to file |
| `-v`, `--verbose` | Verbose logging |
| `--gc` | Query the Global Catalog (port 3269/3268) for forest-wide enumeration |
| `--containers` | Include well-known containers (`CN=Users`, `CN=Computers`, …) in the tree |
| `--acl` | Flag non-default / abusable ACEs on each OU (requires impacket) |
| `--no-ldaps` | Use plain LDAP (port 389/3268) instead of LDAPS |
| `--version` | Show version |

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

> Reading the DACL is a normal authenticated read — no elevated privilege is needed. The SACL is never requested, so `SeSecurityPrivilege` is not required. Requires the `acl` extra (`impacket`).

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
