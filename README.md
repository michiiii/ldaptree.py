# ldaptree

**LDAP organizational unit (OU) enumeration with Group Policy Object (GPO) links.**  
Connects to an LDAP server (typically Active Directory), discovers the OU tree and domain root, resolves linked GPOs by name, and prints a readable tree with link order, enforced/disabled state, and optional verbose details.

---

## Features

- **OU tree** – Enumerates domain root and all organizational units under the base DN
- **GPO links** – Shows which GPOs are linked to each OU/domain root, with display names (resolved from `CN=Policies,CN=System`)
- **Priority** – GPOs are shown in application order; `[1]` = highest priority (applied last)
- **Enforced / disabled** – Marks enforced links (`>`) and disabled links
- **LDAPS by default** – Uses `ldaps://` with certificate verification disabled 
- **Base DN** – Can be auto-discovered from rootDSE or set explicitly with `-b`
- **Output** – Print to terminal or save to file with `-o`

---

## Requirements

- **Python** 3.8 or newer
- **ldapsearch** (OpenLDAP client), e.g.:
  - Debian/Ubuntu: `sudo apt install ldap-utils`
  - RHEL/CentOS: `sudo yum install openldap-clients`

---

## Installation

### With pipx (recommended)

```bash
pipx install "git+https://github.com/michiiii/ldaptree.py"
```

Or from inside the project directory:

```bash
cd /path/to/ldaptree.py
pipx install .
```

### With pip

```bash
pip install .
```

## Usage

```bash
python ldaptree.py -s $AD_DC_IP -u $AD_USER_UPN -p $AD_USER_PASS [options]
```

### Options

| Option | Description |
|--------|-------------|
| `-s`, `--server` | **Required.** LDAP server hostname or IP. |
| `-u`, `--user` | **Required.** Bind user (e.g. `user@DOMAIN.COM` or `DOMAIN\user`). |
| `-p`, `--password` | **Required.** Bind password. |
| `-b`, `--base-dn` | Base DN (e.g. `DC=example,DC=com`). If omitted, discovered from rootDSE. |
| `-o`, `--output` | Write the tree to a file instead of stdout. |
| `-v`, `--verbose` | Extra details (DN per OU, GPO GUIDs, debug logs on stderr). |
| `--ldap` | Use plain LDAP instead of LDAPS. |
| `--version` | Show version and exit. |

---

## Examples

Basic run (LDAPS, base DN auto-discovered):

```bash
ldaptree -s 10.10.10.10 -u "admin@EXAMPLE.COM" -p "YourPassword"
```

With explicit base DN:

```bash
ldaptree -s ldap.example.com -b "DC=example,DC=com" -u "user@EXAMPLE.COM" -p "secret"
```

Verbose output and save to file:

```bash
ldaptree -s 192.168.1.100 -u "admin@COMPANY.LOCAL" -p "P@ssw0rd" -v -o ou-tree.txt
```

Plain LDAP (no TLS):

```bash
ldaptree -s 10.10.10.10 -u "user@DOMAIN" -p "pass" --ldap
```

---

## Output

The tool prints a tree of the domain root and OUs, with GPO links under each node. Example:

```text
================================================================================
LDAP OU Tree Structure with Group Policy Links
================================================================================
Base DN: DC=example,DC=com
Total OUs found: 12
OUs with GPO links: 5
Total GPO links: 8
================================================================================

  [Domain Root] (DC=example,DC=com)
      GPO Links (2 linked):
        - [1] Default Domain Policy
        > [2] Domain Security Policy (DISABLED)

  +-- Sales
  |     GPO Links (1 linked):
  |       - [1] Sales OU Policy

  +-- IT
  ...

================================================================================
Legend:
  [1] = Highest priority (applied last, overrides others)
  - Normal link (not enforced)
  > Enforced link (cannot be blocked by child OUs)
  (DISABLED) GPO link is disabled
================================================================================
```

Log and status messages go to **stderr**; the tree itself goes to **stdout** (or the file given with `-o`).

---

## Security notes

- Use only on systems you are authorized to test.
- The password is passed on the command line and may appear in process lists and shell history; prefer a dedicated test account.
- **LDAPS** is used by default with **TLS certificate verification disabled**, so it works with typical internal AD (self-signed or internal CA). Use `--ldap` only when you explicitly want unencrypted LDAP (e.g. local lab).

