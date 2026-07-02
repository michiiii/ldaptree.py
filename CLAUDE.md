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

Optional feature gated on **impacket** (guarded import → `HAS_IMPACKET`; `main()`
errors out early if `--acl` is passed without it). impacket is an *optional* extra
in `pyproject.toml` (`[acl]`), matching the "core tree needs only ldap3" stance.

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
