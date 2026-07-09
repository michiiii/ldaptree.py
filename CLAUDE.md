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
2. **Resolve auth** (branch in `main`): `-H/--hash` → NTLM pass-the-hash (see below);
   `-d DOMAIN` → NTLM; a bare sAMAccountName with a discoverable domain → auto-expanded
   to a UPN + simple bind; otherwise the username is used verbatim with simple bind. If
   a bare-name simple bind fails, the tool hints to retry with `-d` (some DCs disable
   simple bind). `bind_secret = args.hash or args.password` is what's passed to every
   `Connection` (including the GC-mode secondary MAQ connection).

   **Pass-the-hash** relies on ldap3's own `ntowf_v2` (utils/ntlm.py): if the password
   is `LM:NT` with both halves exactly 32 hex, it unhexlifies the NT half and skips MD4.
   `normalize_nt_hash()` produces that form (bare NT → empty-LM `aad3…` prepended). PtH
   forces NTLM (simple bind would send the hash as a cleartext password) and needs a
   `DOMAIN\user` principal, derived from `-u` / `-d` / the discovered DNS domain. Verify
   changes against `NtlmClient.ntowf_v2` directly, as the test harness does — no DC needed.
   NTLM over LDAPS also passes `channel_binding=TLS_CHANNEL_BINDING`, which is required
   when the DC's LDAP channel-binding policy is set to `Always`.
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
  **RIDs 526/527 (Key Admins / Enterprise Key Admins)** are the same category of
  bug, found later: both groups get a standing, inherited `AddKeyCredentialLink`
  ACE at the domain root by design (Windows Hello for Business / key-trust
  support) that shows up on *every* OU underneath — noise, not a delegation.
  Like Group Policy Creator Owners (520), both groups are empty by default, so
  they're *also* in `PRIV_GROUPS` (`--groups`) — the real signal is whether
  someone was added to them, not the standing ACE. Don't drop 526/527 from
  `DEFAULT_PRIVILEGED_RIDS` without keeping the `PRIV_GROUPS` entries, or a
  membership escalation into either group goes undetected everywhere.
- **`enrich_acls()` aggregates per trustee.** AD splits one logical delegation into
  several object-scoped ACEs (e.g. CreateChild per child class), so findings are
  unioned per SID into a single line; `(inherited)` is shown only when *all* of a
  trustee's ACEs are inherited. Don't revert to one-line-per-ACE — it produces the
  duplicate rows that hid the real finding.
- **`interpret_access_mask()`** returns only takeover-grade rights. Full control
  collapses to `GenericAll`. Property writes are reported only when *unscoped*
  (`WriteProperty(All)`) or scoped to a known-dangerous attribute in
  `KNOWN_OBJECT_GUIDS`, under its **canonical BloodHound/SharpHound edge name**
  (not the raw schema attribute name — a finding should read as an action, not
  send the reader to look up a GUID): **WriteGPLink** (GPO-link takeover),
  **WriteSPN** (add an SPN → targeted Kerberoasting), **AddKeyCredentialLink**
  (Shadow Credentials), **AddAllowedToAct** and **WriteAccountRestrictions**
  (two separate paths to the same RBCD primitive — the latter is a property
  *set* that also grants other account-restriction writes, commonly delegated
  to whoever joins a computer via ADUC), and **AddMember** (add a principal to
  a group). A write scoped to any other, benign attribute is ignored. These
  same primitives can show up encoded as either `WRITE_PROP` (0x20) or, for
  "validated writes" like WriteSPN (e.g. granted via the ADUC delegation
  wizard), `ADS_RIGHT_DS_SELF` (0x8) against the *same* GUID — both mask bits
  are checked and collapse to the identical label, deduplicated within one ACE,
  since the exploitation is identical regardless of which bit AD used. Don't
  drop the `SELF` branch — it's the more common real-world encoding even though
  impacket's own `dacledit` sometimes reports the `WRITE_PROP` form for the same
  right. **Unscoped `SELF`** (no GUID at all) is a distinct primitive,
  `AddSelf` — the trustee can add itself to a group's `member` attribute,
  without needing rights over arbitrary members like `AddMember` does.
  **`MEMBER_ATTRIBUTE_GUID` (the same GUID as the `member` attribute, i.e.
  `AddMember`'s entry in `KNOWN_OBJECT_GUIDS`) is the one deliberate exception
  to "both bits collapse to the identical label."** It doubles as the rightsGUID
  for the separate, DC-enforced "Self-Membership" validated write, which
  constrains the trustee to add/remove only *itself* — a materially narrower
  primitive than `WriteProperty(member)`'s "add anyone." So `SELF` scoped to
  this one GUID is special-cased to `AddSelf`, same as the unscoped case,
  *before* falling through to the generic `KNOWN_OBJECT_GUIDS` reuse that every
  other entry (WriteSPN, AddKeyCredentialLink, …) legitimately gets. Confirmed
  against SpecterOps' AddSelf/AddMember edge docs. This was a real bug found
  during review: collapsing it to `AddMember` overstates what a Self-Membership
  grant lets the trustee do.
  **`KNOWN_CONTROL_ACCESS_GUIDS`** is the same pattern one level up: extended
  rights gated by `ACE_DS_CONTROL_ACCESS` (0x100) rather than a property write.
  Its one entry, **ForceChangePassword** (`User-Force-Change-Password`), used to
  be silently dropped whenever it was scoped to that one right instead of
  granted as unscoped `AllExtendedRights` — that was a real gap, since this is
  one of the single most common ACL findings in practice. Kept as a separate
  table from `KNOWN_OBJECT_GUIDS` (different mask bit, different GUID
  namespace) and from `DS_REPL_GET_CHANGES`/`_ALL` (DCSync needs *both* of
  those rights together, a combination this flat GUID→label map can't express,
  so it stays in its own dedicated function). None of these tables are
  OU-specific: `--takeover`'s all-object scan hits them on users/computers/
  groups too (e.g. a computer account's WriteSPN ACE, or ForceChangePassword on
  a user), which is where most of these besides WriteGPLink actually fire.

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

**Sites get the same treatment, for the same reason, and were a real gap found
against an HTB lab.** `--acl`'s main search only covers `organizationalUnit`
(`+ container`) under the domain NC — it never sees `CN=Sites,CN=Configuration,…`,
so a non-default ACE on e.g. `Default-First-Site-Name` was previously invisible to
`--acl` entirely, even though `--takeover`'s Configuration-NC scan already covered
this for the *caller's own* rights (see the `--takeover` section above). A site can
carry its own `gPLink`, so write access to a site object is exactly as dangerous as
write access to an OU or GPO: link an attacker GPO to the site and it applies to
every computer AD considers part of it. `fetch_site_acls(conn, config_nc)` searches
`CN=Sites,<config_nc>` for `(objectClass=site)`, shapes records as `name`/`dn`/
`_sd_raw` (dn is used instead of a GUID — sites don't have one), and reuses
`enrich_acls()`/`print_site_acls()` unchanged, wired into the `if args.acl:` block
in `main()` and `emit()` right after the GPO ACL section. `config_nc` (rootDSE's
`configurationNamingContext`, falling back to `CN=Configuration,<rootDomainNamingContext>`)
is now computed once and shared between `--acl` and `--adcs` rather than duplicated —
Sites live in the same Configuration NC as CAs/templates. Verify with a mock-conn
test (search base must be `CN=Sites,<config_nc>`, filter `(objectClass=site)`) plus
the same synthetic-SD `enrich_acls()` round-trip used for OUs/GPOs.

### Arbitrary object ACLs (`--object-acls`) — a third gap, found the same way

`--acl` (OUs/GPOs/Sites) and `--takeover` (every object, but self-only) both scan
security descriptors — but neither can surface a plain delegation *between two
other principals* on a plain user/computer/group object, e.g. `restituyoN` holding
`AddKeyCredentialLink` on `tangui` (found via PowerView's `Get-DomainObjectAcl` on
an HTB lab; `--acl` never touches non-OU/GPO/Site objects, and `--takeover` would
only show it if bound as `restituyoN` or one of their groups). This is the
BloodHound-ACL-edge view: every non-default trustee on every principal object, not
just the caller's.

`--object-acls` is its own flag, not folded into `--acl`, because the cost profile
is different: it's a paged sweep (`_paged_search`, the same mechanism `--takeover`
uses) over every `person`/`computer`/`group`/`msDS-GroupManagedServiceAccount`
object in the domain NC(s) (`OBJECT_ACL_FILTER`) — real traffic and potentially a
lot of output on a live domain, unlike the OU/GPO/Site sweep which touches a much
smaller object count. Scope is deliberately the domain NC(s) (`naming_contexts`),
*not* the full multi-partition sweep `--takeover` needs — principals never live in
Configuration/Schema/DomainDnsZones/ForestDnsZones, so there's nothing to gain
scanning those here.

`fetch_object_acls()` reuses `analyze_sd()` for the non-default-trustee filter
(same as OUs/GPOs/Sites) and a new shared helper, **`_aggregate_trustee_aces()`**
— the per-trustee union-of-rights/owner-surfacing logic that used to live inline
in `enrich_acls()` only. `enrich_acls()` now calls the same helper; behavior for
OUs/GPOs/Sites is unchanged, this just removes what had become two copies of a
non-trivial aggregation once a second caller needed it. `print_object_acls()`
follows the flat per-domain listing shape used elsewhere (`print_gpo_acls`-style),
not the tree-inline-annotation one `--vuln`/`--takeover` use — kept consistent
with the "other enumeration modules" pattern below rather than reusing
`_host_node`, since there was no indication inline attachment was wanted here.

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

`fetch_vuln()` runs per-domain LDAP searches; `print_vuln()` renders them. It is
gated on its own flag (not `--acl`) and does **not** require impacket except for
resolving RBCD trustees and SID History — `_rbcd_principals()` swallows a NameError
if impacket is absent, so `--vuln` still lists the RBCD accounts (and SID-History
count), just without the "acted on by"/resolved-SID names. The searches key off
`userAccountControl` via the bitwise-AND matching rule (`LDAP_MATCHING_RULE_BIT_AND`
= `1.2.840.113556.1.4.803`): AS-REP = `0x400000`, unconstrained = `0x80000` with
`SERVER_TRUST_ACCOUNT 0x2000` cleared (plus primaryGroupID 516/521 excluded) to drop
DCs/RODCs, constrained = presence of `msDS-AllowedToDelegateTo` with `0x1000000`
flagging protocol transition, RBCD = presence of
`msDS-AllowedToActOnBehalfOfOtherIdentity` (an SD blob, parsed like any DACL).
Kerberoast filters on `sAMAccountType=805306368` (user, not computer) with an SPN,
minus krbtgt and gMSAs. Delegation checks intentionally cover users **and**
computers (labelled), since constrained delegation on service *user* accounts is the
common case. **SID History** (`sIDHistory=*`) is deliberately *not*
`sAMAccountType`-restricted — groups and computers can carry migration leftover SIDs
too (BloodHound's `HasSIDHistory` edge is equally class-agnostic); each raw SID is
decoded with impacket's `LDAP_SID` and run through `resolve_sid()`, which usually
just returns the SID string unresolved since it points into a *different* domain —
that's expected and still useful (it shows the origin domain). Filters are assembled
with f-strings — the mock-conn paren-balance test in the harness is the guard against
interpolation typos. Note: searches are not paged (consistent with the rest of the
tool), so very large result sets hit the server's size limit — raise paging here if a
domain has >1000 kerberoastable users.

**`--vuln` also annotates the OU tree inline.** Besides the flat per-category section,
`fetch_vuln()` builds `d["objects"]` (keyed by DN, one entry per object with all its
labels aggregated and an `admin` flag from the adminCount set). `attach_vuln_objects()`
indexes every tree node by DN (OU items + root + GC domain nodes) and hangs each object
off its **nearest ancestor** node via `_host_node()` (climb the DN, first match wins) —
so an object in a non-displayed container like `CN=Users` falls through to the domain/
root node rather than vanishing. `print_ou`/`print_tree` render them with `⚠` under the
node. It's driven off the same `objects` dict, so the tree and the flat section can't
disagree. `_host_node` relies on the node index being keyed lowercase — keep DN
comparisons case-insensitive.

### Self takeover (`--takeover`) — the inverse of the ACL filter

Every other ACL view filters *out* the caller and asks "which grants are non-default?".
`--takeover` inverts both: it keeps **only** ACEs whose trustee is the caller, and does
**not** filter default principals (being in Domain Admins *should* light up the whole
domain — that's the true answer). It answers "what can the identity I'm bound as take
over right now?", so its findings are rendered in **bold purple** (`BPURPLE`), the one
color reserved for it — a section after the tree *and* inline (`⚑ YOU`) under the
nearest node, reusing the `--vuln` placement machinery (`attach_takeover_objects` +
`_host_node`). Gated on impacket, alongside `--acl`/`--adcs`.

Three load-bearing pieces:
- **The caller's token is the match set.** `resolve_self_sids()` finds the caller's own
  object via the LDAP *whoami* extended op (`conn.extend.standard.who_am_i()` →
  `u:DOM\user` / `u:user@dom` / `dn:…`), falling back to the sAMAccountName parsed from
  the bind username, then reads `tokenGroups` — the DC-computed, fully-transitive set of
  group SIDs (binary, decoded with `LDAP_SID`) — plus `objectSid`. **Everyone (S-1-1-0)
  and Authenticated Users (S-1-5-11) are added by hand** (`_SESSION_SIDS`): they are
  session SIDs the DC never returns in `tokenGroups`, but a takeover-grade right granted
  to them is a real path for every domain user. On any failure the set still holds those
  two, so Everyone/Auth-Users grants are matched regardless.
- **`self_rights_from_sd(sd, my_sids)`** mirrors `analyze_sd` but keeps an ACE only when
  its trustee ∈ `my_sids` (no `is_default_privileged` filter), reusing
  `interpret_access_mask` so only takeover-grade rights count. It also returns
  `owner_mine` (owning an object = implicit WriteDacl). Verify with the synthetic-SD
  harness: a grant to Everyone/your-group must match; a grant to a stranger or to Domain
  Admins (when *not* in your token) must not; a benign scoped `WriteProperty` must not.
- **The scan is paged and spans every partition.** `_paged_search()` (cookie loop on
  control `1.2.840.113556.1.4.319`) is used because one `(objectClass=*)` SD sweep over a
  real domain far exceeds the server size limit — this is the *only* paged search in the
  tool. Non-GC scans **every naming context rootDSE advertises** (`namingContexts` ∪
  `configurationNamingContext`): the domain NC(s), **Configuration** (where Sites and the
  whole AD CS config live), Schema, and the DomainDnsZones/ForestDnsZones app partitions.
  This is deliberate — a right on a Configuration object (e.g. linking a GPO to a *site*
  is a `gPLink` write on `CN=…,CN=Sites,CN=Configuration,…`) is invisible to any
  domain-NC-only search, including the OU tree itself. GC mode scans the per-domain NCs +
  Configuration (SDs may be partial over the GC port — noted, not errored). `_base_label()`
  tags each partition's findings (e.g. `contoso.local (Configuration)`) so cross-partition
  hits are distinguishable. `fetch_takeover` aggregates rights per object and records `via`
  (which of your principals granted them — `resolve_sid`, with a cache pre-seeded so your
  own SID resolves to `you (<name>)`) plus `nc` (the naming context the object was found
  under, from the `scan_bases` loop var). Objects genuinely inside the domain NC but not
  shown as their own tree node (e.g. `CN=Users`) still attach inline via `_host_node`,
  falling through to the domain root — that's intentional. But `_host_node` climbs DN
  *string* suffixes with no partition awareness, and DomainDnsZones/ForestDnsZones/
  Configuration/Schema DNs (e.g. `DC=DomainDnsZones,DC=inlanefreight,DC=local`) happen to
  textually **end with** the domain's own DN despite being separate naming contexts, not
  real descendants of it — so without a boundary, a DNS zone or Configuration object
  (Sites, cert templates, …) would climb straight past its own partition head and
  misattach under the domain root, cluttering the main tree with unrelated partitions.
  `_host_node(dn, index, nc_head=...)` takes the object's own `nc` as a stop boundary:
  once the climb reaches `nc_head` without a match, it returns `None` instead of
  continuing into whatever partition happens to share that DN suffix. Real domain-NC
  objects are unaffected (their `nc_head` *is* the domain root, which *is* indexed, so
  it's found in the same step the boundary is checked). Cross-partition objects still
  appear in the flat "Objects YOU can take over" section (via `_base_label`) — they just
  don't attach inline anymore. `attach_vuln_objects` calls `_host_node` with no `nc_head`
  (unaffected/unchanged): `--vuln`'s searches never leave the real domain NCs, so it
  doesn't hit this.

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
DACLs are parsed by `template_sd_rights()` → (enrollers, writers, flag_writers), keying
enrollment off the `Certificate-Enrollment` extended-right GUID (`CERT_ENROLL_GUID`)
plus GenericAll. `_evaluate_template()` maps attributes to ESC labels: ESC1 needs *all*
of enrollee-supplies-subject + auth-EKU + no-approval + no-RA-sig + a non-default
enroller; ESC2/3 by EKU; ESC4 from *low-priv* writers; ESC9 from the no-security-extension
bit. `present` is set true if either the CA or template container was readable. ESC6/8/11
are deliberately out of scope (not LDAP-observable) and the printer says so — don't add
them as false "clear" signals.

**ESC4 and ESC7 gate on `is_low_priv()`, not `is_default_privileged()`.** This was a
real false-positive bug: the built-in default templates (User, Computer, Basic EFS, …)
grant object-wide write only to DA/EA and grant broad principals at most a scoped
`WriteProperty`, and the CA object is controlled by the CA's own host machine account
(e.g. `DC04$`). "Non-default" let all of those through. So `template_sd_rights()` counts
only object-wide writes (GenericAll/GenericWrite/WriteDacl/WriteOwner — **not** a
WriteProperty scoped to an arbitrary attribute), and ESC4/ESC7 fire only when the writer
is a genuinely low-privileged, attacker-reachable principal (`LOW_PRIV_SIDS`/
`LOW_PRIV_RIDS`: Everyone, Auth Users, Domain Users/Computers, Users, Guests). Cost: a
delegation to a *custom* admin group is not flagged — an accepted trade to keep the
section signal-only. The synthetic-SD + `_evaluate_template` truth-table test
(default-template scenario must yield no ESC4) is what protects this.

**`flag_writers` is the one deliberate exception to "WriteProperty never counts for
ESC4."** A scoped write limited to *just* `msPKI-Certificate-Name-Flag`
(`WritePKINameFlag`) or `msPKI-Enrollment-Flag` (`WritePKIEnrollmentFlag`, GUIDs in
`FLAG_ATTRIBUTE_GUIDS`) lets a low-priv principal flip exactly the bits
`_evaluate_template()` checks (enrollee-supplies-subject / manager-approval /
no-security-extension) — i.e. self-inflict ESC1/ESC9 — without needing full
GenericWrite. That's functionally ESC4 even though it's a single-attribute write, so
`fetch_adcs` merges low-priv `flag_writers` into the same list passed to
`_evaluate_template`'s `low_writers` parameter (which fires ESC4), while still
reporting the two separately in the template record (`writers` vs `flag_writers`) so
`print_adcs` shows *which* right actually enabled it. A SID already in `writers`
(object-wide) is excluded from `flag_writers` to avoid double-reporting the same
principal under two labels.

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
