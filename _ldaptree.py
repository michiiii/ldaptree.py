#!/usr/bin/env python3

import argparse
import re
import sys
from collections import defaultdict

try:
    from ldap3 import Server, Connection, ALL, NONE, SUBTREE, BASE, NTLM, SIMPLE
    from ldap3.core.exceptions import LDAPException
except ImportError:
    print("ERROR: ldap3 is required. Install it with: pip install ldap3", file=sys.stderr)
    sys.exit(1)

VERSION = "2.0"

RED    = '\033[0;31m'
GREEN  = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE   = '\033[0;34m'
PURPLE = '\033[0;35m'
CYAN   = '\033[0;36m'
GREY   = '\033[0;90m'
NC     = '\033[0m'


def log_info(msg):    print(f"{CYAN}[INFO]{NC} {msg}", file=sys.stderr)
def log_error(msg):   print(f"{RED}[ERROR]{NC} {msg}", file=sys.stderr)
def log_success(msg): print(f"{GREEN}[SUCCESS]{NC} {msg}", file=sys.stderr)

def log_verbose(msg, verbose):
    if verbose:
        print(f"{PURPLE}[VERBOSE]{NC} {msg}", file=sys.stderr)


def fetch_counts(conn, base_dn, ldap_filter):
    """Return {container_dn_lower: direct_count} for objects matching ldap_filter."""
    try:
        conn.search(
            search_base=base_dn,
            search_filter=ldap_filter,
            search_scope=SUBTREE,
            attributes=[],
        )
    except LDAPException:
        return {}
    counts = {}
    for e in conn.entries:
        dn    = str(e.entry_dn)
        parts = dn.split(",", 1)
        if len(parts) < 2:
            continue
        container = parts[1].lower()
        counts[container] = counts.get(container, 0) + 1
    return counts


def recursive_count(ou_dn, direct_counts):
    """Sum objects in this container and every sub-container beneath it."""
    if not ou_dn:  # empty = forest root; count everything
        return sum(direct_counts.values())
    suffix = "," + ou_dn.lower()
    return sum(
        cnt for container, cnt in direct_counts.items()
        if container == ou_dn.lower() or container.endswith(suffix)
    )


def fetch_gpo_names(conn, domain_ncs):
    """Return {gpo_dn_lower: display_name} for all GPOs across the given domain NCs."""
    result = {}
    for nc in domain_ncs:
        try:
            conn.search(
                search_base=f"CN=Policies,CN=System,{nc}",
                search_filter="(objectClass=groupPolicyContainer)",
                search_scope=SUBTREE,
                attributes=["displayName"],
            )
            for e in conn.entries:
                result[str(e.entry_dn).lower()] = str(e["displayName"].value or e.entry_dn)
        except LDAPException:
            pass
    return result


def parse_gplinks(gplink_str, gpo_names):
    """Parse a gPLink attribute string into an ordered list of GPO-link dicts.

    Each token looks like [LDAP://cn={GUID},...;N] where N is a bitmask:
      bit 0 set  → link is disabled
      bit 1 set  → link is enforced (still enabled)

    gPLink lists links left-to-right from LOWEST to HIGHEST precedence, so the
    last token in the string is link order 1 — the GPO that wins on conflicting
    settings. We reverse and number the links 1..N so order 1 (highest
    precedence) is first, matching the GPMC "Linked Group Policy Objects" tab.
    Enforced links (bit 1) actually override this ordering, but their link-order
    number is reported unchanged, as GPMC does.
    """
    if not gplink_str:
        return []
    links = []
    for match in re.finditer(r'\[LDAP://([^\]]+?);(\d+)\]', gplink_str, re.IGNORECASE):
        gpo_dn  = match.group(1)
        options = int(match.group(2))
        name    = gpo_names.get(gpo_dn.lower(), gpo_dn)
        guid    = gpo_dn.split(",")[0][3:]  # CN={GUID} → {GUID}
        links.append({
            "name":     name,
            "guid":     guid,
            "enabled":  not bool(options & 1),
            "enforced": bool(options & 2),
        })
    links.reverse()  # last token in the string = link order 1 = highest precedence
    for order, link in enumerate(links, start=1):
        link["order"] = order
    return links


def query_rootdse(server):
    """Return rootDSE attributes from an anonymous query, or {}."""
    try:
        conn = Connection(server)
        conn.open()
        conn.search("", "(objectClass=*)", search_scope=BASE,
                    attributes=["defaultNamingContext", "rootDomainNamingContext",
                                "namingContexts", "schemaNamingContext"])
        result = {}
        if conn.entries:
            e = conn.entries[0]
            for attr in ["defaultNamingContext", "rootDomainNamingContext", "schemaNamingContext"]:
                try:
                    result[attr] = str(e[attr].value)
                except Exception:
                    pass
            try:
                val = e["namingContexts"].value
                result["namingContexts"] = val if isinstance(val, list) else [val]
            except Exception:
                pass
        conn.unbind()
        return result
    except Exception:
        return {}


def domain_from_base_dn(base_dn):
    parts = [p.strip() for p in base_dn.split(",")]
    return ".".join(p[3:] for p in parts if p.upper().startswith("DC="))


def domain_dn_from_dn(dn):
    """Extract the domain DN (DC= components only) from any object DN."""
    parts = [p.strip() for p in dn.split(",")]
    return ",".join(p for p in parts if p.upper().startswith("DC="))


def format_counts(item):
    counts = []
    if "computer_count" in item: counts.append(f"💻 {item['computer_count']}")
    if "user_count"     in item: counts.append(f"👤 {item['user_count']}")
    if "group_count"    in item: counts.append(f"👥 {item['group_count']}")
    return f" {YELLOW}[{' '.join(counts)}]{NC}" if counts else ""


def format_maq(item):
    val = item.get("maq")
    if val is None:
        return ""
    color = GREEN if val == 0 else RED
    return f" {GREY}[MAQ: {color}{val}{NC}{GREY}]{NC}"


def fetch_maq(conn, domain_ncs):
    """Return {domain_nc_lower: maq_int_or_None} for each domain NC."""
    result = {}
    for nc in domain_ncs:
        val = None
        try:
            conn.search(nc, "(objectClass=*)", search_scope=BASE,
                        attributes=["ms-DS-MachineAccountQuota"])
            if conn.entries:
                attrs = conn.entries[0].entry_attributes_as_dict
                for k, v in attrs.items():
                    if k.lower() == "ms-ds-machineaccountquota":
                        val = int(v[0]) if v else None
                        break
        except Exception:
            pass
        result[nc.lower()] = val
    return result


# Root-level CN containers that are pure AD infrastructure noise
_EXCLUDED_ROOTS = {
    "configuration", "system", "lostandfound", "infrastructure",
    "ntds quotas", "tpm devices", "keys",
}


def build_tree(entries, with_gplink=False):
    ou_data = []
    for e in entries:
        dn    = str(e.entry_dn)
        parts = [p.strip() for p in dn.split(",")]
        # Path = all non-DC components from root to leaf
        non_dc = [p for p in reversed(parts) if not p.upper().startswith("DC=")]
        if not non_dc:
            continue
        # non_dc[0] is the component closest to the domain root.
        # Skip anything rooted under a known system container.
        root_rdn = non_dc[0]
        if root_rdn.upper().startswith("CN=") and root_rdn[3:].lower() in _EXCLUDED_ROOTS:
            continue
        path         = [p.split("=", 1)[1] for p in non_dc]
        is_container = parts[0].upper().startswith("CN=")
        item = {"path": path, "name": path[-1], "dn": dn, "gplinks": [],
                "is_container": is_container}
        if with_gplink:
            try:
                item["_gplink_raw"] = str(e["gPLink"].value or "")
            except Exception:
                item["_gplink_raw"] = ""
        ou_data.append(item)
    return ou_data


def print_ou(item, depth, extra_indent, out):
    indent = "  " * (depth + extra_indent)
    if item.get("is_container"):
        prefix = "+·· " if depth == 0 else "|·· "
        name   = f"{GREY}{item['name']}{NC}"
    else:
        prefix = "+-- " if depth == 0 else "|-- "
        name   = item['name']
    print(f"{indent}{prefix}{name} {GREY}[{item['dn']}]{NC}{format_counts(item)}", file=out)
    for link in item.get("gplinks", []):
        color = GREEN if link["enabled"] else GREY
        tag   = f" {YELLOW}(enforced){NC}{color}" if link["enforced"] else ""
        state = "" if link["enabled"] else " (disabled)"
        print(f"{indent}    {color}> #{link['order']} {link['name']} "
              f"[{link['guid']}]{tag}{state}{NC}", file=out)


def print_tree(ou_data, base_dn, root_item=None, domains=None, out=None):
    out = out or sys.stdout
    if not ou_data:
        print("No organizational units found.", file=out)
        return
    print("LDAP OU Tree Structure", file=out)
    print(f"Base DN: {base_dn or root_item['name']}", file=out)
    n_ous  = sum(1 for i in ou_data if not i.get("is_container"))
    n_cons = sum(1 for i in ou_data if i.get("is_container"))
    count_line = f"OUs: {n_ous}" + (f"  Containers: {n_cons}" if n_cons else "")
    print(count_line, file=out)
    print("=" * 60, file=out)

    if root_item:
        print(f"{root_item['name']}{format_counts(root_item)}{format_maq(root_item)}", file=out)

    if domains:
        # GC mode: group OUs by domain, each domain is its own subtree
        by_domain = defaultdict(list)
        for item in ou_data:
            by_domain[domain_dn_from_dn(item["dn"]).lower()].append(item)

        domain_list = sorted(domains.items(), key=lambda x: (x[0].count(","), x[1]["name"]))
        for i, (domain_dn, domain_item) in enumerate(domain_list):
            if i > 0:
                print("\n" * 1, file=out)  # 1 newline + the implicit one = 2 blank lines
            print(f"  +-- {domain_item['name']} {GREY}[{domain_item['dn']}]{NC}{format_counts(domain_item)}{format_maq(domain_item)}", file=out)
            for item in sorted(by_domain.get(domain_dn, []), key=lambda x: [p.lower() for p in x["path"]]):
                print_ou(item, len(item["path"]) - 1, extra_indent=2, out=out)
    else:
        for item in sorted(ou_data, key=lambda x: [p.lower() for p in x["path"]]):
            print_ou(item, len(item["path"]) - 1, extra_indent=1 if root_item else 0, out=out)


def main():
    parser = argparse.ArgumentParser(
        prog="ldaptree",
        description="Enumerate and display LDAP Organizational Unit structure as a hierarchical tree.",
        epilog="Use only on systems you own or have explicit permission to test.",
    )
    parser.add_argument("-s", "--server",   required=True, metavar="HOST",   help="LDAP server hostname or IP")
    parser.add_argument("-b", "--base-dn",  metavar="DN",                    help="Base DN — auto-discovered from rootDSE if omitted")
    parser.add_argument("-u", "--user",     required=True, metavar="USER",   help="Bind username (sAMAccountName, UPN, or DOMAIN\\user)")
    parser.add_argument("-p", "--password", required=True, metavar="PASS",   help="Bind password")
    parser.add_argument("-d", "--domain",   metavar="DOMAIN",                help="NetBIOS domain name — forces NTLM auth")
    parser.add_argument("-o", "--output",   metavar="FILE",                  help="Save output to file")
    parser.add_argument("-v", "--verbose",  action="store_true",             help="Verbose logging")
    parser.add_argument("--gc",             action="store_true",             help="Query the Global Catalog (port 3269/3268) for forest-wide enumeration")
    parser.add_argument("--containers",     action="store_true",             help="Include well-known containers (CN=Users, CN=Computers, etc.) in the tree")
    parser.add_argument("--no-ldaps",       action="store_true",             help="Use plain LDAP (port 389/3268) instead of LDAPS")
    parser.add_argument("--version",        action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args()

    if args.verbose:
        print(f"{BLUE}╔═══════════════════════════════════╗")
        print(f"║   LDAP OU Enumeration Tool v{VERSION}   ║")
        print(f"╚═══════════════════════════════════╝{NC}")

    use_ssl = not args.no_ldaps
    if args.gc:
        port   = 3269 if use_ssl else 3268
        scheme = "ldaps" if use_ssl else "ldap"
        log_verbose(f"GC mode: connecting to {scheme}://{args.server}:{port}", args.verbose)
        server = Server(args.server, port=port, use_ssl=use_ssl, get_info=ALL)
    else:
        scheme = "ldaps" if use_ssl else "ldap"
        log_verbose(f"Connecting to {scheme}://{args.server}", args.verbose)
        server = Server(args.server, use_ssl=use_ssl, get_info=ALL)

    rootdse = query_rootdse(server)

    # Resolve base DN
    if not args.base_dn:
        if args.gc:
            args.base_dn = ""
            log_verbose("GC mode: using empty base DN for forest-wide search", args.verbose)
        else:
            args.base_dn = rootdse.get("defaultNamingContext")
            if not args.base_dn:
                log_error("Could not discover base DN from rootDSE — please specify -b/--base-dn")
                sys.exit(1)
            log_verbose(f"Discovered base DN: {args.base_dn}", args.verbose)

    # Domain NCs for GPO queries (DC= NCs only, excludes Configuration/Schema)
    naming_contexts = [
        nc for nc in rootdse.get("namingContexts", [])
        if nc.upper().startswith("DC=")
    ]
    if not naming_contexts and args.base_dn:
        naming_contexts = [args.base_dn]

    # Determine bind user
    bare_sam   = "@" not in args.user and "\\" not in args.user
    upn_domain = domain_from_base_dn(
        args.base_dn or rootdse.get("rootDomainNamingContext", "")
    )

    if args.domain:
        bind_user   = f"{args.domain}\\{args.user}"
        bind_method = NTLM
        log_verbose(f"Using NTLM auth as {bind_user}", args.verbose)
    elif bare_sam and upn_domain:
        bind_user   = f"{args.user}@{upn_domain}"
        bind_method = SIMPLE
        log_verbose(f"Auto-constructed UPN: {bind_user}", args.verbose)
    else:
        bind_user   = args.user
        bind_method = SIMPLE
        log_verbose(f"Using simple bind as {bind_user}", args.verbose)

    try:
        conn = Connection(server, user=bind_user, password=args.password,
                          authentication=bind_method, auto_bind=True,
                          receive_timeout=30)
    except LDAPException as e:
        log_error(f"Connection/auth failed: {e}")
        if bare_sam and not args.domain:
            log_info("Tip: if simple bind is disabled on this DC, pass -d DOMAIN to use NTLM")
        sys.exit(1)

    log_success("LDAP connection established")
    log_verbose(f"Searching {'forest' if args.gc else args.base_dn} for organizationalUnit objects", args.verbose)

    ldap_filter = (
        "(|(objectClass=organizationalUnit)(objectClass=container))"
        if args.containers else
        "(objectClass=organizationalUnit)"
    )
    try:
        conn.search(
            search_base=args.base_dn,
            search_filter=ldap_filter,
            search_scope=SUBTREE,
            attributes=["gPLink"],
        )
    except LDAPException as e:
        log_error(f"LDAP search failed: {e}")
        sys.exit(1)

    ou_data = build_tree(conn.entries, with_gplink=True)
    log_verbose(f"Found {len(ou_data)} organizational units", args.verbose)

    # Root node
    root_dn   = rootdse.get("rootDomainNamingContext") if args.gc else args.base_dn
    root_name = domain_from_base_dn(root_dn or args.base_dn)
    if args.gc:
        root_name += " (forest)"
    root = {"name": root_name, "dn": args.base_dn}

    # Domain nodes for GC mode — derive NCs from the actual OU DNs so we
    # catch every domain the GC returned, not just what rootDSE advertised
    domains = None
    if args.gc:
        seen_ncs = sorted({domain_dn_from_dn(item["dn"]) for item in ou_data})
        naming_contexts = seen_ncs  # also used for GPO queries below
        domains = {
            nc.lower(): {"name": domain_from_base_dn(nc), "dn": nc}
            for nc in seen_ncs
        }

    if args.gc:
        log_verbose("GC mode: gPLink is a partial attribute — GPO links may be incomplete", args.verbose)

    log_verbose("Fetching GPO display names", args.verbose)
    gpo_names = fetch_gpo_names(conn, naming_contexts)
    log_verbose(f"Found {len(gpo_names)} GPOs", args.verbose)
    for item in ou_data:
        item["gplinks"] = parse_gplinks(item.pop("_gplink_raw", ""), gpo_names)

    for count_key, ldap_filter in [
        ("computer_count", "(objectClass=computer)"),
        ("user_count",     "(&(objectClass=user)(!(objectClass=computer)))"),
        ("group_count",    "(objectClass=group)"),
    ]:
        log_verbose(f"Fetching {count_key.replace('_count', '')} counts", args.verbose)
        dc = fetch_counts(conn, args.base_dn, ldap_filter)
        for item in ou_data:
            item[count_key] = recursive_count(item["dn"], dc)
        root[count_key] = recursive_count(args.base_dn, dc)
        if domains:
            for domain_item in domains.values():
                domain_item[count_key] = recursive_count(domain_item["dn"], dc)

    # MAQ — ms-DS-MachineAccountQuota is not served by the GC port (3269).
    # In GC mode, only query the NC the target DC is authoritative for (defaultNamingContext).
    # Querying child domain NCs causes the server to return a referral → hang.
    if args.gc:
        local_nc = rootdse.get("defaultNamingContext", "").lower()
        maq_ncs  = [local_nc] if local_nc else []
        ldap_conn = None
        try:
            _ldap_srv = Server(args.server, use_ssl=use_ssl, get_info=NONE)
            ldap_conn = Connection(_ldap_srv, user=bind_user, password=args.password,
                                   authentication=bind_method, auto_bind=True,
                                   receive_timeout=10)
            log_verbose(f"Opened regular LDAP connection for MAQ query ({local_nc})", args.verbose)
        except Exception as _e:
            log_verbose(f"Could not open regular LDAP connection: {_e}", args.verbose)
    else:
        maq_ncs   = [args.base_dn] if args.base_dn else naming_contexts
        ldap_conn = conn

    maq = fetch_maq(ldap_conn, maq_ncs) if ldap_conn else {nc: None for nc in maq_ncs}
    log_verbose(f"MAQ results: {maq}", args.verbose)

    if args.gc and ldap_conn:
        try:
            ldap_conn.unbind()
        except Exception:
            pass

    root["maq"] = maq.get(args.base_dn.lower()) if args.base_dn else None
    if domains:
        for nc, domain_item in domains.items():
            domain_item["maq"] = maq.get(nc)

    conn.unbind()

    if args.output:
        try:
            with open(args.output, "w") as f:
                print_tree(ou_data, args.base_dn, root_item=root, domains=domains, out=f)
            log_success(f"Results saved to: {args.output}")
        except OSError as e:
            log_error(f"Could not write {args.output}: {e}")
            sys.exit(1)
    else:
        print_tree(ou_data, args.base_dn, root_item=root, domains=domains)

    log_success("Done")


if __name__ == "__main__":
    main()
