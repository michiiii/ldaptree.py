# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`ldaptree` is a single-file Python CLI that binds to an Active Directory LDAP/LDAPS
server, enumerates the Organizational Unit tree, and prints it with inline DNs,
recursive object counts (computers/users/groups), linked GPOs, and the domain's
machine-account quota. All logic lives in `_ldaptree.py` (~460 lines); everything
else is packaging.

## Commands

There is no build step, no test suite, and no linter configured — it's a script.

```bash
# Run without installing
python3 _ldaptree.py -s <dc> -u <user> -p <password>

# Editable install for development (exposes the `ldaptree.py` console script)
pipx install -e .        # or: pip install -e .

# Smoke test: argument parsing and version, no network needed
python3 _ldaptree.py --version
python3 _ldaptree.py --help
```

Exercising real behavior requires a reachable domain controller — the README's
examples target a GOAD-style lab (`SEVENKINGDOMS.LOCAL`). There are no fixtures or
mocks, so verify changes against a live DC.

## Packaging quirk

The module is `_ldaptree.py` (underscore) but the installed command is `ldaptree.py`.
`pyproject.toml` maps the script entry point `"ldaptree.py" = "_ldaptree:main"`. Keep
these in sync if you rename anything. `pycryptodome` is a dependency solely because
NTLM auth (`-d`) needs MD4, which Python 3.14+ / modern OpenSSL no longer expose.

## Architecture

`main()` runs a linear pipeline; the helper functions above it are pure/stateless and
each own one enrichment concern:

1. **Connect & discover** — `query_rootDSE()` does an anonymous BASE query to learn
   `defaultNamingContext` / `namingContexts`. The base DN is auto-derived from this
   when `-b` is omitted.
2. **Resolve auth** (three-way branch in `main`): `-d DOMAIN` → NTLM; a bare
   sAMAccountName with a discoverable domain → auto-expanded to a UPN + simple bind;
   otherwise the username is used verbatim with simple bind. If a bare-name simple
   bind fails, the tool hints to retry with `-d` (some DCs disable simple bind).
3. **Fetch OUs** — one SUBTREE search for `organizationalUnit` (plus `container` when
   `--containers` is set), pulling `gPLink`. `build_tree()` turns each entry's DN into
   a root→leaf `path`, and drops anything under a known system container
   (`_EXCLUDED_ROOTS`).
4. **Enrich** each OU in separate passes: `parse_gplinks()` (gPLink is a bitmask
   string — bit 0 = link disabled, bit 1 = enforced — resolved to display names via
   `fetch_gpo_names()`), then recursive object counts, then MAQ.

**gPLink precedence is non-obvious and easy to get backwards.** The raw gPLink
string lists links left→right from *lowest* to *highest* precedence, so the **last
(rightmost) token is link order 1** — the GPO that wins on conflicting settings
(confirmed against [MS-GPOL] and GPMC's *Linked Group Policy Objects* tab).
`parse_gplinks()` therefore **reverses** the tokens before numbering them 1..N, and
the tree prints them highest-precedence-first (`> #1 ...`). Enforced links (bit 1)
actually override this ordering, but their number is reported unchanged, as GPMC
does. Don't "simplify" the reverse — it encodes the precedence semantics.

### ACL enumeration (`--acl`)

Feature gated on **impacket** (guarded import → `HAS_IMPACKET`; `main()` errors out
early if `--acl` is passed without it). impacket is a declared dependency in
`pyproject.toml`; the guard is defensive for running `_ldaptree.py` straight from a
checkout without installing.

Data flow, layered onto the existing OU search: when `--acl` is set the main search
also requests `nTSecurityDescriptor` and passes ldap3's
`security_descriptor_control(sdflags=0x05)` — **DACL + Owner only**. Never request
the SACL (0x08); it needs `SeSecurityPrivilege` and would fail for a normal bind.
`build_tree(with_acl=True)` stashes the raw SD bytes; `enrich_acls()` then parses
each via `analyze_sd()` (impacket `SR_SECURITY_DESCRIPTOR`) and resolves trustee
SIDs with `resolve_sid()` (well-known table → `(objectSid=…)` LDAP lookup, cached).

Two deliberate filters define "non-default", and both are load-bearing — loosening
them floods the output with noise, tightening them hides real delegations:
- **`is_default_privileged(sid)`** drops ACEs held by built-in principals that
  have rights on OUs by default: Tier-0 admins (SYSTEM, Administrators, Creator
  Owner, Enterprise DCs, `SELF`, domain RIDs 512/516/518/519/521/498/500) **and
  the operator groups** (Account/Server/Print/Backup Operators, `S-1-5-32-548..551`).
  Account Operators in particular has default CreateChild/DeleteChild on user/
  group/computer classes on every OU — omitting it was the bug that made the first
  cut of `--acl` report default ACEs as findings. Everyone else is shown.
- **`enrich_acls()` aggregates per trustee.** AD splits one logical delegation into
  several object-scoped ACEs (e.g. CreateChild per child class), so findings are
  unioned per SID into a single line; `(inherited)` is shown only when *all* of a
  trustee's ACEs are inherited. Don't revert to one-line-per-ACE — it produces the
  duplicate rows that hid the real finding.
- **`interpret_access_mask()`** returns only takeover-grade rights. Full control
  collapses to `GenericAll`. Property/extended-right writes are reported only when
  *unscoped* (all attributes) or scoped to a known-dangerous attribute — the only
  entry in `KNOWN_OBJECT_GUIDS` is **gPLink** (`f30e3bbe-…`), whose write is the
  GPO-link takeover primitive. A write scoped to one benign attribute is ignored.

Only ALLOW aces are considered (DENY/audit skipped). Owner is surfaced separately
when non-default (an owner has implicit WriteDacl). The synthetic-SD round-trip in
the test harness (build with impacket → `analyze_sd`) is the way to verify changes
here without a live DC — GUID decoding via `bin_to_string` must stay lowercase to
match `KNOWN_OBJECT_GUIDS` keys.

**GPO objects get the same treatment, by design-reuse.** `fetch_gpo_acls()` returns
GPO records shaped exactly like OU items (`name`/`dn`/`_sd_raw`) so the *same*
`enrich_acls()` processes them unchanged; `print_gpo_acls()` renders them in a
section after the tree (via the `emit()` helper in `main()`, so file and stdout stay
in sync). The rationale is the attack path: write access to a GPO object = code
execution on every OU it's linked to, and an over-permissioned GPO is invisible in
the OU tree otherwise. RID 520 (Group Policy Creator Owners) is in the default set
specifically for this — it holds full control over GPOs by default.

**"Who can create GPOs" is a container-ACL question, not an object one.** Creating a
GPO needs `CreateChild` on `CN=Policies,CN=System,<nc>`, held by default only by
DA/EA/SYSTEM/GPCO. `fetch_gpo_creators()` reports two non-default sources per domain:
(1) `creators_from_sd()` scans that container's DACL for CreateChild that is unscoped
or object-scoped to `GROUP_POLICY_CONTAINER_CLASS_GUID` (`f30e3bc2-…`; a CreateChild
scoped to any *other* class is correctly ignored — GenericWrite alone doesn't grant
creation); (2) transitive members of GPCO, since GPCO is empty by default so any
member is a delegation — resolved via `LDAP_MATCHING_RULE_IN_CHAIN`
(`memberOf:1.2.840.113556.1.4.1941:=<gpco_dn>`), with `find_gpco_dn()` locating GPCO
by `<domainSID>-520`. This chains with the OU findings: create-GPO + gPLink-write =
full compromise of that OU subtree.

**DCSync is a domain-head-ACL question.** `fetch_dcsync_rights()` reads the domain
NC head's DACL and `dcsync_from_sd()` accumulates, per non-default SID, which of the
two replication control-access rights it holds — `DS_REPL_GET_CHANGES` (`1131f6aa-…`)
and `DS_REPL_GET_CHANGES_ALL` (`1131f6ad-…`). Rights from *separate* ACEs are unioned
per SID (they usually are separate); `GenericAll` and unscoped ControlAccess (all
extended rights) both grant the pair. Holding both == DCSync == full domain
compromise (dump `krbtgt`/all hashes). Every default replication holder (DCs 516, EDCs
S-1-5-9, RODCs 498/521, Administrators, SYSTEM, DA/EA via GenericAll) is already in
the default-principal set, so survivors are real delegations. These GUIDs are the
canonical DCSync ones — don't "tidy" them.

All four `--acl` sections (OU ACEs, GPO ACEs, GPO-creation, DCSync) print via the
`emit()` helper so `-o` file output and stdout stay identical; each has an
`x = []` init before the `if args.acl:` block so `emit()` never NameErrors.

### Attack surface (`--vuln`) — independent of `--acl`

`fetch_vuln()` runs five per-domain LDAP searches; `print_vuln()` renders them. It is
gated on its own flag (not `--acl`) and does **not** require impacket except for
resolving RBCD trustees — `_rbcd_principals()` swallows a NameError if impacket is
absent, so `--vuln` still lists the RBCD accounts, just without the "acted on by"
names. The searches key off `userAccountControl` via the bitwise-AND matching rule
(`LDAP_MATCHING_RULE_BIT_AND` = `1.2.840.113556.1.4.803`): AS-REP = `0x400000`,
unconstrained = `0x80000` with `SERVER_TRUST_ACCOUNT 0x2000` cleared (plus
primaryGroupID 516/521 excluded) to drop DCs/RODCs, constrained = presence of
`msDS-AllowedToDelegateTo` with `0x1000000` flagging protocol transition, RBCD =
presence of `msDS-AllowedToActOnBehalfOfOtherIdentity` (an SD blob, parsed like any
DACL). Kerberoast filters on `sAMAccountType=805306368` (user, not computer) with an
SPN, minus krbtgt and gMSAs. Delegation checks intentionally cover users **and**
computers (labelled), since constrained delegation on service *user* accounts is the
common case. Filters are assembled with f-strings — the mock-conn paren-balance test
in the harness is the guard against interpolation typos. Note: searches are not paged
(consistent with the rest of the tool), so very large result sets hit the server's
size limit — raise paging here if a domain has >1000 kerberoastable users.

### The other enumeration modules

All follow the same shape: an independent `--flag`, a `fetch_x()` returning per-domain
dicts, a `print_x()`, an `x_info = []` init before its `if args.x:` block, and a
`print_x(...)` line in `emit()`. `-A/--all` just sets every flag. Add a new module by
copying that pattern; the mock-conn filter test + a synthetic-SD/render test is the
verification recipe (no live DC needed).

- **`--groups`** (`fetch_priv_groups`) — resolves each entry of `PRIV_GROUPS` to a DN
  (by RID for domain groups, fixed SID for built-ins, sAMAccountName for DnsAdmins,
  which has no fixed RID) then expands transitively with the same in-chain rule as
  GPCO. Members are filtered through `is_default_privileged()` so built-in defaults
  (Administrator RID 500, the nested DA/EA/Administrators, operators) drop out — only
  *added* principals show, and a group left with no members is omitted. This needs the
  member `objectSid`, so the member search requests it.
- **`--creds`** (`fetch_creds`) — LAPS/gMSA passwords are *confidential* attributes:
  the DC only returns them if the caller can read them, so presence == "you can read
  this". LAPS deployment is detected via the world-readable `…ExpirationTime` so we can
  also count deployed-but-locked hosts. gMSA `msDS-GroupMSAMembership` is an SD parsed
  by the same `_rbcd_principals()` used for RBCD.
- **`--trusts` / `--computers`** — pure LDAP. `_last_logon()` must handle both a raw
  Windows FILETIME int *and* an already-parsed `datetime` (ldap3 formats it when the
  schema is loaded via `get_info=ALL`). `EOL_OS_MARKERS` is a static heuristic — update
  it as OSes age (Windows 10 is on it as of 2026).

### AD CS / ESC (`--adcs`) — needs impacket, guarded with `--acl`

`fetch_adcs()` reads the Configuration NC (`configurationNamingContext`, or derived as
`CN=Configuration,<rootDomainNamingContext>`): `pKIEnrollmentService` objects (CAs, with
their published `certificateTemplates`) and `pKICertificateTemplate` objects. Template
DACLs are parsed by `template_sd_rights()` → (enrollers, writers), keying enrollment off
the `Certificate-Enrollment` extended-right GUID (`CERT_ENROLL_GUID`) plus GenericAll.
`_evaluate_template()` maps attributes to ESC labels: ESC1 needs *all* of
enrollee-supplies-subject + auth-EKU + no-approval + no-RA-sig + a non-default enroller;
ESC2/3 by EKU; ESC4 from *low-priv* writers; ESC9 from the no-security-extension bit.
`present` is set true if either the CA or template container was readable. ESC6/8/11 are
deliberately out of scope (not LDAP-observable) and the printer says so — don't add them
as false "clear" signals.

**ESC4 and ESC7 gate on `is_low_priv()`, not `is_default_privileged()`.** This was a
real false-positive bug: the built-in default templates (User, Computer, Basic EFS, …)
grant object-wide write only to DA/EA and grant broad principals at most a scoped
`WriteProperty`, and the CA object is controlled by the CA's own host machine account
(e.g. `DC04$`). "Non-default" let all of those through. So `template_sd_rights()` counts
only object-wide writes (GenericAll/GenericWrite/WriteDacl/WriteOwner — **not**
WriteProperty), and ESC4/ESC7 fire only when the writer is a genuinely low-privileged,
attacker-reachable principal (`LOW_PRIV_SIDS`/`LOW_PRIV_RIDS`: Everyone, Auth Users,
Domain Users/Computers, Users, Guests). Cost: a delegation to a *custom* admin group is
not flagged — an accepted trade to keep the section signal-only. The synthetic-SD +
`_evaluate_template` truth-table test (default-template scenario must yield no ESC4) is
what protects this.

**Recursive counts are computed client-side, not by the server.** `fetch_counts()`
does one subtree search per object class and buckets each hit by its *immediate*
parent DN. `recursive_count()` then sums a container plus everything whose DN ends
with that container's DN. Adding a new count type means adding an entry to the
`(count_key, ldap_filter)` loop in `main()` and a line in `format_counts()`.

**stdout vs stderr split is intentional.** The tree goes to stdout (or `-o FILE`);
all `log_*` progress/status goes to stderr. This keeps piped/redirected tree output
clean. ANSI color codes are always emitted, even into `-o` files (README shows the
`sed` one-liner to strip them).

### Global Catalog mode (`--gc`) — the main source of special-casing

`--gc` queries the GC port (3269/3268) for forest-wide, cross-domain enumeration, and
several code paths fork on `args.gc`:

- Base DN defaults to empty (search the whole forest); the root node is labeled
  `... (forest)` and OUs are grouped per-domain in `print_tree()` via
  `domain_dn_from_dn()`.
- Domain NCs are derived from the *actual returned OU DNs*, not from rootDSE, so
  domains the GC returns but doesn't advertise are still covered.
- `gPLink` is a partial attribute over the GC and may be incomplete — noted in verbose
  output, not an error.
- **MAQ needs a second, regular LDAP connection.** `ms-DS-MachineAccountQuota` is not
  served on the GC port, and querying child-domain NCs over it returns referrals that
  hang. So in GC mode the tool opens a separate LDAP connection and queries MAQ only
  for the DC's own `defaultNamingContext`. Preserve this when touching MAQ logic.
