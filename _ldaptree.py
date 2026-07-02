#!/usr/bin/env python3

import argparse
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone

try:
    from ldap3 import Server, Connection, ALL, NONE, SUBTREE, BASE, NTLM, SIMPLE
    from ldap3.core.exceptions import LDAPException
    from ldap3.protocol.microsoft import security_descriptor_control
except ImportError:
    print("ERROR: ldap3 is required. Install it with: pip install ldap3", file=sys.stderr)
    sys.exit(1)

# impacket is only needed for --acl (parsing the nTSecurityDescriptor blob).
try:
    from impacket.ldap.ldaptypes import (
        SR_SECURITY_DESCRIPTOR, ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_OBJECT_ACE,
        LDAP_SID)
    from impacket.uuid import bin_to_string
    HAS_IMPACKET = True
except ImportError:
    HAS_IMPACKET = False

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


def fetch_gpo_acls(conn, domain_ncs):
    """Return a GPO record per groupPolicyContainer, each carrying its raw SD.

    Records are shaped like the OU items (name/dn/_sd_raw) so enrich_acls() can
    process them unchanged. Whoever can write a GPO object owns every OU it is
    linked to, so its DACL is exactly as interesting as an OU's.
    """
    gpos = []
    controls = security_descriptor_control(sdflags=0x05)  # DACL + Owner, no SACL
    for nc in domain_ncs:
        try:
            conn.search(
                search_base=f"CN=Policies,CN=System,{nc}",
                search_filter="(objectClass=groupPolicyContainer)",
                search_scope=SUBTREE,
                attributes=["displayName", "nTSecurityDescriptor"],
                controls=controls,
            )
        except LDAPException:
            continue
        for e in conn.entries:
            dn = str(e.entry_dn)
            try:
                name = str(e["displayName"].value or dn)
            except Exception:
                name = dn
            try:
                sd = e["nTSecurityDescriptor"].raw_values[0]
            except Exception:
                sd = None
            gpos.append({"name": name, "dn": dn,
                         "guid": dn.split(",")[0][3:],  # CN={GUID} → {GUID}
                         "_sd_raw": sd})
    return gpos


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


# --- ACL enumeration -------------------------------------------------------
#
# Active Directory access-right bits (ADS_RIGHT_*). We only care about the
# rights that let a principal take over or restructure an OU (and everything
# beneath it), not read/list rights.
ACE_DS_CREATE_CHILD   = 0x00000001
ACE_DS_DELETE_CHILD   = 0x00000002
ACE_DS_SELF           = 0x00000008
ACE_DS_WRITE_PROP     = 0x00000020
ACE_DS_DELETE_TREE    = 0x00000040
ACE_DS_CONTROL_ACCESS = 0x00000100
ACE_DELETE            = 0x00010000
ACE_WRITE_DACL        = 0x00040000
ACE_WRITE_OWNER       = 0x00080000
ACE_GENERIC_ALL       = 0x10000000
ACE_GENERIC_WRITE     = 0x40000000
ACE_FULL_CONTROL      = 0x000F01FF  # all specific+standard rights set (== GenericAll)

ACE_INHERITED = 0x10  # AceFlags bit: this ACE was inherited from a parent

# schemaIDGUIDs of attributes whose write is itself an attack primitive on an
# OU. gPLink is the big one: writing it links an attacker-controlled GPO to the
# OU and thus code-execs every computer/user beneath it.
KNOWN_OBJECT_GUIDS = {
    "f30e3bbe-9ff0-11d1-b603-0000f80367c1": "gPLink",
}

# schemaIDGUID of the groupPolicyContainer class — the child-object type in a
# CreateChild ACE on CN=Policies,CN=System that means "can create GPOs".
GROUP_POLICY_CONTAINER_CLASS_GUID = "f30e3bc2-9ff0-11d1-b603-0000f80367c1"

# Control-access-right GUIDs whose combination on the domain head grants DCSync
# (replicate + replicate secrets → dump every password hash, incl. krbtgt).
DS_REPL_GET_CHANGES     = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
DS_REPL_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"

# userAccountControl bits used by --vuln, and the bitwise-AND matching rule OID.
UAC_ACCOUNTDISABLE                 = 0x00000002
UAC_SERVER_TRUST_ACCOUNT           = 0x00002000   # account is a (writable) DC
UAC_TRUSTED_FOR_DELEGATION         = 0x00080000   # unconstrained delegation
UAC_DONT_REQ_PREAUTH               = 0x00400000   # AS-REP roastable
UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x01000000   # constrained deleg w/ protocol transition
LDAP_MATCHING_RULE_BIT_AND         = "1.2.840.113556.1.4.803"
SAM_USER_OBJECT                    = 805306368     # sAMAccountType of a normal user

# Built-in principals that hold these rights on OUs by *default* — either Tier-0
# admins or the operator groups AD delegates object create/delete to out of the
# box (this is why Account Operators shows CreateChild/DeleteChild on every OU).
# Their per-OU ACEs are noise; their risk is group membership, not a delegation.
# Everything else with a dangerous right is surfaced.
DEFAULT_PRIVILEGED_SIDS = {
    "S-1-5-18",      # Local System
    "S-1-5-10",      # SELF (principal self)
    "S-1-3-0",       # Creator Owner
    "S-1-5-9",       # Enterprise Domain Controllers
    "S-1-5-32-544",  # Administrators
    "S-1-5-32-548",  # Account Operators (default create/delete of users/groups/computers)
    "S-1-5-32-549",  # Server Operators
    "S-1-5-32-550",  # Print Operators   (default create/delete of printQueue objects)
    "S-1-5-32-551",  # Backup Operators
}
# Domain-relative RIDs of default Tier-0 groups/accounts.
DEFAULT_PRIVILEGED_RIDS = {
    500,  # Administrator
    512,  # Domain Admins
    516,  # Domain Controllers
    518,  # Schema Admins
    519,  # Enterprise Admins
    520,  # Group Policy Creator Owners (default full control over GPOs it creates)
    521,  # Read-only Domain Controllers
    498,  # Enterprise Read-only Domain Controllers
}

# "Unsafe" principals a normal attacker is a member of or can leverage. A
# dangerous right held by one of these is what makes ESC4/ESC7 exploitable —
# the same right held by an admin or the CA's own host machine account is the
# default, expected configuration and must not be flagged.
LOW_PRIV_SIDS = {"S-1-1-0", "S-1-5-11", "S-1-5-7"}   # Everyone, Authenticated Users, Anonymous
LOW_PRIV_RIDS = {513, 515, 545, 546}                  # Domain Users, Domain Computers, Users, Guests


def is_low_priv(sid):
    """True if sid is a broad, attacker-reachable principal (not an admin/machine)."""
    if sid in LOW_PRIV_SIDS:
        return True
    rid = sid.rsplit("-", 1)[-1]
    return rid.isdigit() and int(rid) in LOW_PRIV_RIDS

WELL_KNOWN_SIDS = {
    "S-1-1-0":        "Everyone",
    "S-1-3-0":        "Creator Owner",
    "S-1-5-7":        "Anonymous",
    "S-1-5-9":        "Enterprise Domain Controllers",
    "S-1-5-10":       "SELF",
    "S-1-5-11":       "Authenticated Users",
    "S-1-5-18":       "Local System",
    "S-1-5-32-544":   "Administrators",
    "S-1-5-32-545":   "Users",
    "S-1-5-32-548":   "Account Operators",
    "S-1-5-32-549":   "Server Operators",
    "S-1-5-32-550":   "Print Operators",
    "S-1-5-32-551":   "Backup Operators",
    "S-1-5-32-554":   "Pre-Windows 2000 Compatible Access",
    "S-1-5-32-555":   "Remote Desktop Users",
}


def is_default_privileged(sid):
    """True if sid is a built-in Tier-0 principal that owns OUs by default."""
    if sid in DEFAULT_PRIVILEGED_SIDS:
        return True
    rid = sid.rsplit("-", 1)[-1]
    return rid.isdigit() and int(rid) in DEFAULT_PRIVILEGED_RIDS


def interpret_access_mask(mask, obj_guid, obj_label):
    """Return the list of *dangerous* right labels present in an access mask.

    obj_guid/obj_label describe an object-scoped ACE's target attribute or
    extended right (None for ACEs that cover the whole object). Property/
    extended-right writes are only reported when unscoped (all attributes) or
    scoped to a known-dangerous attribute — a delegated write to one benign
    attribute is not flagged.
    """
    if mask & ACE_GENERIC_ALL or (mask & ACE_FULL_CONTROL) == ACE_FULL_CONTROL:
        return ["GenericAll"]
    rights = []
    if mask & ACE_WRITE_DACL:      rights.append("WriteDacl")
    if mask & ACE_WRITE_OWNER:     rights.append("WriteOwner")
    if mask & ACE_GENERIC_WRITE:   rights.append("GenericWrite")
    if mask & ACE_DS_CREATE_CHILD: rights.append("CreateChild")
    if mask & ACE_DS_DELETE_CHILD: rights.append("DeleteChild")
    if mask & ACE_DS_DELETE_TREE:  rights.append("DeleteTree")
    if mask & ACE_DELETE:          rights.append("Delete")
    if mask & ACE_DS_WRITE_PROP:
        if obj_guid is None:
            rights.append("WriteProperty(All)")
        elif obj_guid in KNOWN_OBJECT_GUIDS:
            rights.append(f"WriteProperty({obj_label})")
        # scoped to a benign single attribute → not a takeover primitive, skip
    if mask & ACE_DS_CONTROL_ACCESS and obj_guid is None:
        rights.append("AllExtendedRights")
    return rights


def analyze_sd(sd_bytes):
    """Parse an nTSecurityDescriptor blob → (owner_sid, [(sid, rights, inherited)]).

    Only ALLOW aces granting a dangerous right to a non-default principal are
    returned. owner_sid is included so the caller can flag a non-default owner
    (an owner holds implicit WriteDacl).
    """
    sd = SR_SECURITY_DESCRIPTOR(data=sd_bytes)
    owner_sid = None
    try:
        owner_sid = sd["OwnerSid"].formatCanonical()
    except Exception:
        pass

    results = []
    dacl = sd["Dacl"]
    if not dacl:
        return owner_sid, results

    for ace in dacl["Data"]:
        if ace["AceType"] not in (ACCESS_ALLOWED_ACE.ACE_TYPE,
                                  ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE):
            continue  # skip DENY aces and audit aces
        body = ace["Ace"]
        sid  = body["Sid"].formatCanonical()
        if is_default_privileged(sid):
            continue

        obj_guid = None
        if ace["AceType"] == ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE:
            if body["Flags"] & ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT:
                obj_guid = bin_to_string(body["ObjectType"]).lower()
        obj_label = KNOWN_OBJECT_GUIDS.get(obj_guid,
                                           obj_guid[:8] if obj_guid else None)

        rights = interpret_access_mask(body["Mask"]["Mask"], obj_guid, obj_label)
        if not rights:
            continue
        results.append((sid, rights, bool(ace["AceFlags"] & ACE_INHERITED)))

    return owner_sid, results


def resolve_sid(conn, sid, search_base, cache):
    """Resolve a SID to a readable name (well-known table, then LDAP lookup)."""
    if sid in cache:
        return cache[sid]
    name = WELL_KNOWN_SIDS.get(sid)
    if not name and search_base:
        try:
            conn.search(search_base, f"(objectSid={sid})",
                        search_scope=SUBTREE, attributes=["sAMAccountName"])
            if conn.entries:
                val = conn.entries[0]["sAMAccountName"].value
                if val:
                    name = str(val)
        except LDAPException:
            pass
    name = name or sid
    cache[sid] = name
    return name


def enrich_acls(conn, ou_data, search_base):
    """Attach an "acl" list of interesting-ACE dicts to each OU item.

    ACEs are aggregated per trustee: a principal that appears in several ACEs
    (e.g. object-scoped CreateChild for user/group/computer as separate ACEs) is
    shown once with the union of its rights. A trustee is marked (inherited) only
    if *every* one of its dangerous ACEs is inherited.
    """
    cache = {}
    for item in ou_data:
        raw = item.pop("_sd_raw", None)
        item["acl"] = []
        if not raw:
            continue
        try:
            owner_sid, aces = analyze_sd(raw)
        except Exception:
            continue

        if owner_sid and not is_default_privileged(owner_sid):
            item["acl"].append({
                "who":       resolve_sid(conn, owner_sid, search_base, cache),
                "rights":    ["Owner"],
                "inherited": False,
            })

        agg   = {}   # sid -> {"rights": [...], "inherited": bool}
        order = []   # preserve first-seen order
        for sid, rights, inherited in aces:
            if sid not in agg:
                agg[sid] = {"rights": [], "inherited": True}
                order.append(sid)
            for r in rights:
                if r not in agg[sid]["rights"]:
                    agg[sid]["rights"].append(r)
            agg[sid]["inherited"] &= inherited
        for sid in order:
            item["acl"].append({
                "who":       resolve_sid(conn, sid, search_base, cache),
                "rights":    agg[sid]["rights"],
                "inherited": agg[sid]["inherited"],
            })


def creators_from_sd(sd_bytes):
    """SIDs (non-default) that can create GPOs given the Policies-container SD.

    "Can create" = CreateChild (unscoped, or object-scoped to the
    groupPolicyContainer class) or full control / GenericAll. GenericWrite alone
    does not grant child creation and is intentionally excluded.
    """
    sd = SR_SECURITY_DESCRIPTOR(data=sd_bytes)
    out  = []
    dacl = sd["Dacl"]
    if not dacl:
        return out
    for ace in dacl["Data"]:
        if ace["AceType"] not in (ACCESS_ALLOWED_ACE.ACE_TYPE,
                                  ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE):
            continue
        body = ace["Ace"]
        mask = body["Mask"]["Mask"]
        can_create = bool(mask & ACE_DS_CREATE_CHILD) or bool(mask & ACE_GENERIC_ALL) \
            or (mask & ACE_FULL_CONTROL) == ACE_FULL_CONTROL
        if not can_create:
            continue
        # An object-scoped CreateChild only counts if it targets the GPO class.
        if ace["AceType"] == ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE and \
           (body["Flags"] & ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT):
            if bin_to_string(body["ObjectType"]).lower() != GROUP_POLICY_CONTAINER_CLASS_GUID:
                continue
        sid = body["Sid"].formatCanonical()
        if is_default_privileged(sid) or sid in out:
            continue
        out.append(sid)
    return out


def _entry_sid(entry):
    """Best-effort SID string from an ldap3 entry's objectSid (str or bytes)."""
    try:
        val = entry["objectSid"].value
    except Exception:
        return None
    if isinstance(val, bytes):
        try:
            return LDAP_SID(data=val).formatCanonical()
        except Exception:
            return None
    return str(val) if val else None


def find_gpco_dn(conn, nc):
    """DN of this domain's Group Policy Creator Owners group (RID 520), or None."""
    try:
        conn.search(nc, "(objectClass=*)", search_scope=BASE, attributes=["objectSid"])
        dom_sid = _entry_sid(conn.entries[0]) if conn.entries else None
    except LDAPException:
        dom_sid = None
    if not dom_sid:
        return None
    try:
        conn.search(nc, f"(objectSid={dom_sid}-520)", search_scope=SUBTREE, attributes=[])
        if conn.entries:
            return str(conn.entries[0].entry_dn)
    except LDAPException:
        pass
    return None


def fetch_gpo_creators(conn, domain_ncs, cache):
    """Per-domain list of non-default principals who can create GPOs.

    Two sources, both excluding built-in/default holders (DA/EA/SYSTEM/GPCO):
      - members: transitive members of Group Policy Creator Owners (empty by
        default, so any member is a delegation), via LDAP_MATCHING_RULE_IN_CHAIN.
      - delegations: custom CreateChild ACEs on CN=Policies,CN=System,<nc>.
    """
    sd_ctrl = security_descriptor_control(sdflags=0x04)  # DACL only
    out = []
    for nc in domain_ncs:
        info = {"domain": domain_from_base_dn(nc), "members": [], "delegations": []}

        gpco_dn = find_gpco_dn(conn, nc)
        if gpco_dn:
            try:
                conn.search(nc,
                            f"(memberOf:1.2.840.113556.1.4.1941:={gpco_dn})",
                            search_scope=SUBTREE,
                            attributes=["sAMAccountName", "objectSid", "objectClass"])
                for e in conn.entries:
                    sid = _entry_sid(e)
                    if sid and is_default_privileged(sid):
                        continue
                    classes  = [str(c).lower() for c in e["objectClass"].values]
                    is_group = "group" in classes
                    try:
                        name = str(e["sAMAccountName"].value or e.entry_dn)
                    except Exception:
                        name = str(e.entry_dn)
                    info["members"].append((name, is_group))
            except LDAPException:
                pass

        policies_dn = f"CN=Policies,CN=System,{nc}"
        try:
            conn.search(policies_dn, "(objectClass=*)", search_scope=BASE,
                        attributes=["nTSecurityDescriptor"], controls=sd_ctrl)
            if conn.entries:
                raw = conn.entries[0]["nTSecurityDescriptor"].raw_values[0]
                for sid in creators_from_sd(raw):
                    info["delegations"].append(resolve_sid(conn, sid, nc, cache))
        except (LDAPException, IndexError):
            pass

        out.append(info)
    return out


def dcsync_from_sd(sd_bytes):
    """Return {sid: {repl rights}} for non-default principals on the domain head.

    Rights are 'GetChanges' / 'GetChangesAll'; holding both (or GenericAll / all
    extended rights) == DCSync. Rights from separate ACEs are unioned per SID.
    """
    sd = SR_SECURITY_DESCRIPTOR(data=sd_bytes)
    acc  = {}
    dacl = sd["Dacl"]
    if not dacl:
        return acc
    for ace in dacl["Data"]:
        if ace["AceType"] not in (ACCESS_ALLOWED_ACE.ACE_TYPE,
                                  ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE):
            continue
        body = ace["Ace"]
        mask = body["Mask"]["Mask"]
        sid  = body["Sid"].formatCanonical()
        if is_default_privileged(sid):
            continue

        grants = set()
        if bool(mask & ACE_GENERIC_ALL) or (mask & ACE_FULL_CONTROL) == ACE_FULL_CONTROL:
            grants.update(("GetChanges", "GetChangesAll"))
        if mask & ACE_DS_CONTROL_ACCESS:
            obj_guid = None
            if ace["AceType"] == ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE and \
               (body["Flags"] & ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT):
                obj_guid = bin_to_string(body["ObjectType"]).lower()
            if obj_guid is None:                       # all extended rights
                grants.update(("GetChanges", "GetChangesAll"))
            elif obj_guid == DS_REPL_GET_CHANGES:
                grants.add("GetChanges")
            elif obj_guid == DS_REPL_GET_CHANGES_ALL:
                grants.add("GetChangesAll")

        if grants:
            acc.setdefault(sid, set()).update(grants)
    return acc


def fetch_dcsync_rights(conn, domain_ncs, cache):
    """Per-domain list of non-default principals holding replication rights on
    the domain head; those with both Get-Changes and Get-Changes-All can DCSync.
    """
    sd_ctrl = security_descriptor_control(sdflags=0x04)  # DACL only
    out = []
    for nc in domain_ncs:
        info = {"domain": domain_from_base_dn(nc), "principals": []}
        try:
            conn.search(nc, "(objectClass=*)", search_scope=BASE,
                        attributes=["nTSecurityDescriptor"], controls=sd_ctrl)
            if conn.entries:
                raw = conn.entries[0]["nTSecurityDescriptor"].raw_values[0]
                for sid, rights in dcsync_from_sd(raw).items():
                    info["principals"].append({
                        "who":    resolve_sid(conn, sid, nc, cache),
                        "rights": rights,
                        "dcsync": {"GetChanges", "GetChangesAll"}.issubset(rights),
                    })
        except (LDAPException, IndexError):
            pass
        out.append(info)
    return out


# --- vulnerable / abusable account configurations (--vuln) -----------------

def _acct_kind(entry):
    """'computer' or 'user' from an ldap3 entry's objectClass."""
    try:
        classes = [str(c).lower() for c in entry["objectClass"].values]
    except Exception:
        return "account"
    return "computer" if "computer" in classes else "user"


# Built-in accounts that ship with these weak flags by default → not findings.
DEFAULT_ACCOUNT_NOISE_RIDS = {501, 502, 503}  # Guest, krbtgt, DefaultAccount


def _rid(sid):
    """Trailing RID of a SID as an int, or -1."""
    tail = sid.rsplit("-", 1)[-1] if sid else ""
    return int(tail) if tail.isdigit() else -1


def _attr_str(entry, attr):
    """String value of an ldap3 attribute, or None if absent/empty."""
    try:
        v = entry[attr].value
    except Exception:
        return None
    return str(v) if v else None


def _attr_raw(entry, attr):
    """First raw (bytes) value of an ldap3 attribute, or None."""
    try:
        return entry[attr].raw_values[0]
    except Exception:
        return None


_SECRET_KEYWORDS = ("pass", "pwd", "cred", "secret")


def _secret_hit(entry):
    """(field, value) of the first description/info/comment holding a password
    keyword, value truncated. None if nothing matches."""
    for field in ("description", "info", "comment"):
        try:
            val = entry[field].value
        except Exception:
            val = None
        if val:
            v = str(val)
            if any(k in v.lower() for k in _SECRET_KEYWORDS):
                value = (v[:100] + "…") if len(v) > 100 else v
                return field, value
    return None


def _rbcd_principals(sd_bytes):
    """SIDs allowed to act, from an msDS-AllowedToActOnBehalfOfOtherIdentity SD."""
    sids = []
    try:
        dacl = SR_SECURITY_DESCRIPTOR(data=sd_bytes)["Dacl"]
    except Exception:
        return sids
    if not dacl:
        return sids
    for ace in dacl["Data"]:
        if ace["AceType"] != ACCESS_ALLOWED_ACE.ACE_TYPE:
            continue
        try:
            sid = ace["Ace"]["Sid"].formatCanonical()
        except Exception:
            continue
        if sid not in sids:
            sids.append(sid)
    return sids


def fetch_vuln(conn, domain_ncs, cache):
    """Per-domain attack surface: kerberoastable / AS-REP-roastable users,
    non-DC unconstrained & constrained delegation, and RBCD.
    """
    bitand   = LDAP_MATCHING_RULE_BIT_AND
    disabled = f"(userAccountControl:{bitand}:={UAC_ACCOUNTDISABLE})"
    not_dc   = (f"(!(userAccountControl:{bitand}:={UAC_SERVER_TRUST_ACCOUNT}))"
                "(!(primaryGroupID=516))(!(primaryGroupID=521))")
    out = []
    for nc in domain_ncs:
        d = {"domain": domain_from_base_dn(nc), "kerberoastable": [], "asrep": [],
             "unconstrained": [], "constrained": [], "rbcd": [],
             "secrets": [], "passwd_notreqd": [], "reversible": [], "admincount": set()}

        def _search(flt, attrs):
            try:
                conn.search(nc, flt, search_scope=SUBTREE, attributes=attrs)
                return list(conn.entries)
            except LDAPException:
                return []

        # Kerberoastable: enabled user accounts (not gMSA/krbtgt) with an SPN
        for e in _search(
                f"(&(sAMAccountType={SAM_USER_OBJECT})(servicePrincipalName=*)"
                f"(!(sAMAccountName=krbtgt))"
                f"(!(objectClass=msDS-GroupManagedServiceAccount)){'(!' + disabled + ')'})",
                ["sAMAccountName", "servicePrincipalName"]):
            d["kerberoastable"].append((str(e["sAMAccountName"].value),
                                        [str(s) for s in e["servicePrincipalName"].values]))

        # AS-REP roastable: enabled users with DONT_REQ_PREAUTH
        for e in _search(
                f"(&(sAMAccountType={SAM_USER_OBJECT})"
                f"(userAccountControl:{bitand}:={UAC_DONT_REQ_PREAUTH})(!{disabled}))",
                ["sAMAccountName"]):
            d["asrep"].append(str(e["sAMAccountName"].value))

        # Unconstrained delegation, excluding DCs / RODCs
        for e in _search(
                f"(&(userAccountControl:{bitand}:={UAC_TRUSTED_FOR_DELEGATION}){not_dc})",
                ["sAMAccountName", "objectClass"]):
            d["unconstrained"].append((str(e["sAMAccountName"].value), _acct_kind(e)))

        # Constrained delegation (classic + protocol transition), excluding DCs
        for e in _search(
                f"(&(msDS-AllowedToDelegateTo=*){not_dc})",
                ["sAMAccountName", "objectClass", "msDS-AllowedToDelegateTo",
                 "userAccountControl"]):
            try:
                uac = int(e["userAccountControl"].value or 0)
            except Exception:
                uac = 0
            d["constrained"].append((
                str(e["sAMAccountName"].value), _acct_kind(e),
                bool(uac & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION),
                [str(s) for s in e["msDS-AllowedToDelegateTo"].values]))

        # RBCD: accounts configured as a delegation target
        for e in _search(
                "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
                ["sAMAccountName", "objectClass",
                 "msDS-AllowedToActOnBehalfOfOtherIdentity"]):
            try:
                raw = e["msDS-AllowedToActOnBehalfOfOtherIdentity"].raw_values[0]
            except Exception:
                raw = None
            who = [resolve_sid(conn, s, nc, cache) for s in _rbcd_principals(raw)] if raw else []
            d["rbcd"].append((str(e["sAMAccountName"].value), _acct_kind(e), who))

        # adminCount=1 principals (AdminSDHolder-protected / privileged) — a set,
        # used to star kerberoastable/AS-REP accounts that are also privileged.
        for e in _search(f"(&(sAMAccountType={SAM_USER_OBJECT})(adminCount=1))",
                         ["sAMAccountName"]):
            d["admincount"].add(str(e["sAMAccountName"].value))

        # Passwords hidden in description / info / comment fields
        for e in _search(
                f"(&(sAMAccountType={SAM_USER_OBJECT})"
                "(|(description=*pass*)(description=*pwd*)(description=*cred*)"
                "(description=*secret*)(info=*pass*)(info=*pwd*)(info=*cred*)))",
                ["sAMAccountName", "description", "info", "comment"]):
            hit = _secret_hit(e)
            if hit:
                d["secrets"].append((str(e["sAMAccountName"].value), *hit))

        # PASSWD_NOTREQD — enabled account that may allow an empty password
        # (skip disabled and the built-in Guest/DefaultAccount, which ship this way)
        for e in _search(
                f"(&(sAMAccountType={SAM_USER_OBJECT})"
                f"(userAccountControl:{bitand}:=32)(!{disabled}))",
                ["sAMAccountName", "objectSid"]):
            if _rid(_entry_sid(e)) in DEFAULT_ACCOUNT_NOISE_RIDS:
                continue
            d["passwd_notreqd"].append(str(e["sAMAccountName"].value))

        # Reversible encryption — password is recoverable in cleartext
        for e in _search(
                f"(&(sAMAccountType={SAM_USER_OBJECT})"
                f"(userAccountControl:{bitand}:=128)(!{disabled}))",
                ["sAMAccountName", "objectSid"]):
            if _rid(_entry_sid(e)) in DEFAULT_ACCOUNT_NOISE_RIDS:
                continue
            d["reversible"].append(str(e["sAMAccountName"].value))

        out.append(d)
    return out


# Privileged / interesting groups to expand. kind: "rid" (domain-relative),
# "sid" (fixed built-in), "name" (sAMAccountName — for groups with no fixed RID).
PRIV_GROUPS = [
    ("Domain Admins",               "rid",  512),
    ("Enterprise Admins",           "rid",  519),
    ("Schema Admins",               "rid",  518),
    ("Administrators",              "sid",  "S-1-5-32-544"),
    ("Account Operators",          "sid",  "S-1-5-32-548"),
    ("Backup Operators",           "sid",  "S-1-5-32-551"),   # can back up SAM/NTDS
    ("Server Operators",           "sid",  "S-1-5-32-549"),
    ("Print Operators",            "sid",  "S-1-5-32-550"),
    ("Cert Publishers",             "rid",  517),
    ("Group Policy Creator Owners", "rid",  520),
    ("Protected Users",             "rid",  525),
    ("DnsAdmins",                   "name", "DnsAdmins"),      # DLL load → RCE on the DC
]


def _find_group_dn(conn, nc, kind, key, dom_sid):
    if kind == "rid":
        flt = f"(objectSid={dom_sid}-{key})" if dom_sid else None
    elif kind == "sid":
        flt = f"(objectSid={key})"
    else:
        flt = f"(&(objectClass=group)(sAMAccountName={key}))"
    if not flt:
        return None
    try:
        conn.search(nc, flt, search_scope=SUBTREE, attributes=[])
        if conn.entries:
            return str(conn.entries[0].entry_dn)
    except LDAPException:
        pass
    return None


def _member_kind(entry):
    try:
        classes = [str(c).lower() for c in entry["objectClass"].values]
    except Exception:
        return "user"
    if "group" in classes:
        return "group"
    return "computer" if "computer" in classes else "user"


def fetch_priv_groups(conn, domain_ncs, cache):
    """Per-domain transitive membership of privileged/interesting groups."""
    out = []
    for nc in domain_ncs:
        info = {"domain": domain_from_base_dn(nc), "groups": []}
        dom_sid = None
        try:
            conn.search(nc, "(objectClass=*)", search_scope=BASE, attributes=["objectSid"])
            if conn.entries:
                dom_sid = _entry_sid(conn.entries[0])
        except LDAPException:
            pass

        for label, kind, key in PRIV_GROUPS:
            dn = _find_group_dn(conn, nc, kind, key, dom_sid)
            if not dn:
                continue
            members = []
            try:
                conn.search(nc, f"(memberOf:1.2.840.113556.1.4.1941:={dn})",
                            search_scope=SUBTREE,
                            attributes=["sAMAccountName", "objectClass", "objectSid"])
                for e in conn.entries:
                    # Skip built-in/default members (Administrator RID 500, the
                    # nested admin groups, operators, …) — only added principals
                    # are interesting.
                    sid = _entry_sid(e)
                    if sid and is_default_privileged(sid):
                        continue
                    try:
                        name = str(e["sAMAccountName"].value or e.entry_dn)
                    except Exception:
                        name = str(e.entry_dn)
                    members.append((name, _member_kind(e)))
            except LDAPException:
                pass
            if members:
                info["groups"].append((label, sorted(members)))
        out.append(info)
    return out


def fetch_creds(conn, domain_ncs, cache):
    """Per-domain LAPS local-admin passwords and gMSA managed accounts.

    A confidential attribute (ms-Mcs-AdmPwd, msLAPS-Password, msDS-ManagedPassword)
    is only returned when the caller has read access, so its presence in a result
    directly means "you can read this credential". LAPS presence is detected via
    the world-readable expiration-time attribute so we can also report deployed-
    but-not-readable hosts.
    """
    out = []
    for nc in domain_ncs:
        d = {"domain": domain_from_base_dn(nc), "laps": [], "gmsa": []}

        try:
            conn.search(nc,
                "(|(ms-Mcs-AdmPwdExpirationTime=*)(msLAPS-PasswordExpirationTime=*)"
                "(msLAPS-EncryptedPassword=*))",
                search_scope=SUBTREE,
                attributes=["sAMAccountName", "ms-Mcs-AdmPwd", "msLAPS-Password",
                            "msLAPS-EncryptedPassword"])
            for e in conn.entries:
                sam    = _attr_str(e, "sAMAccountName") or str(e.entry_dn)
                legacy = _attr_str(e, "ms-Mcs-AdmPwd")
                newpw  = _attr_str(e, "msLAPS-Password")
                if legacy:
                    d["laps"].append((sam, "legacy", legacy))
                elif newpw:
                    d["laps"].append((sam, "windows", newpw))
                elif _attr_raw(e, "msLAPS-EncryptedPassword") is not None:
                    d["laps"].append((sam, "encrypted", None))
                else:
                    d["laps"].append((sam, "deployed", None))
        except LDAPException:
            pass

        try:
            conn.search(nc, "(objectClass=msDS-GroupManagedServiceAccount)",
                        search_scope=SUBTREE,
                        attributes=["sAMAccountName", "msDS-GroupMSAMembership",
                                    "msDS-ManagedPassword"])
            for e in conn.entries:
                sam      = _attr_str(e, "sAMAccountName") or str(e.entry_dn)
                readable = _attr_raw(e, "msDS-ManagedPassword") is not None
                raw      = _attr_raw(e, "msDS-GroupMSAMembership")
                readers  = [resolve_sid(conn, s, nc, cache)
                            for s in _rbcd_principals(raw)] if raw else []
                d["gmsa"].append((sam, readable, readers))
        except LDAPException:
            pass

        out.append(d)
    return out


TRUST_DIRECTION = {0: "disabled", 1: "inbound", 2: "outbound", 3: "bidirectional"}
TRUST_TYPE      = {1: "NT/downlevel", 2: "AD/uplevel", 3: "MIT/Kerberos", 4: "DCE"}
# trustAttributes bits worth surfacing.
TRUST_ATTR_FLAGS = [
    (0x00000001, "non-transitive"),
    (0x00000004, "SID-filtering (quarantined)"),
    (0x00000008, "forest-transitive"),
    (0x00000010, "cross-organization"),
    (0x00000020, "within-forest"),
    (0x00000040, "treat-as-external"),
    (0x00000200, "uses-RC4"),
    (0x00000800, "no-TGT-delegation"),
]


def fetch_trusts(conn, domain_ncs):
    """Per-domain trust relationships from the trustedDomain objects."""
    out = []
    for nc in domain_ncs:
        info = {"domain": domain_from_base_dn(nc), "trusts": []}
        try:
            conn.search(f"CN=System,{nc}", "(objectClass=trustedDomain)",
                        search_scope=SUBTREE,
                        attributes=["trustPartner", "trustDirection", "trustType",
                                    "trustAttributes", "flatName"])
        except LDAPException:
            out.append(info)
            continue
        for e in conn.entries:
            def _int(a):
                try:
                    return int(e[a].value or 0)
                except Exception:
                    return 0
            info["trusts"].append({
                "partner":   _attr_str(e, "trustPartner") or str(e.entry_dn),
                "direction": _int("trustDirection"),
                "type":      _int("trustType"),
                "attrs":     _int("trustAttributes"),
            })
        out.append(info)
    return out


# Static heuristic: OS strings that are past (or near) end-of-support.
EOL_OS_MARKERS = ["2000", "2003", "2008", "2012", "Windows XP", "Windows Vista",
                  "Windows 7", "Windows 8", "Windows 10"]


def _last_logon(entry):
    """lastLogonTimestamp as an aware datetime, or None. Handles both ldap3's
    formatted datetime and a raw Windows FILETIME int."""
    try:
        v = entry["lastLogonTimestamp"].value
    except Exception:
        return None
    if not v or v in ("0", 0):
        return None
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    try:
        ft = int(v)
    except Exception:
        return None
    if ft <= 0:
        return None
    return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ft // 10)


def fetch_computers(conn, domain_ncs):
    """Per-domain computer inventory with OS and last-logon for staleness/EOL."""
    out = []
    for nc in domain_ncs:
        info = {"domain": domain_from_base_dn(nc), "computers": []}
        try:
            conn.search(nc, "(objectClass=computer)", search_scope=SUBTREE,
                        attributes=["sAMAccountName", "dNSHostName", "operatingSystem",
                                    "lastLogonTimestamp", "userAccountControl"])
        except LDAPException:
            out.append(info)
            continue
        for e in conn.entries:
            try:
                uac = int(e["userAccountControl"].value or 0)
            except Exception:
                uac = 0
            info["computers"].append({
                "name": _attr_str(e, "dNSHostName") or _attr_str(e, "sAMAccountName")
                        or str(e.entry_dn),
                "os":   _attr_str(e, "operatingSystem") or "unknown",
                "llt":  _last_logon(e),
                "uac":  uac,
            })
        out.append(info)
    return out


# --- AD CS / ESC (--adcs) --------------------------------------------------
CERT_ENROLL_GUID     = "0e10c968-78fb-11d2-90d4-00c04f79dc55"  # Certificate-Enrollment
CERT_AUTOENROLL_GUID = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"  # Certificate-AutoEnrollment

# EKU OIDs that let a cert be used to authenticate as its subject.
AUTH_EKUS = {
    "1.3.6.1.5.5.7.3.2":       "Client Authentication",
    "1.3.6.1.4.1.311.20.2.2":  "Smart Card Logon",
    "1.3.6.1.5.2.3.4":         "PKINIT Client Authentication",
    "2.5.29.37.0":             "Any Purpose",
}
ANY_PURPOSE_EKU      = "2.5.29.37.0"
ENROLLMENT_AGENT_EKU = "1.3.6.1.4.1.311.20.2.1"

# msPKI-Certificate-Name-Flag / msPKI-Enrollment-Flag bits
CT_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001   # name flag  → requester picks the SAN
CT_PEND_ALL_REQUESTS         = 0x00000002   # enroll flag → CA-manager approval required
CT_NO_SECURITY_EXTENSION     = 0x00080000   # enroll flag → no SID security ext (ESC9)


def template_sd_rights(sd_bytes):
    """(enroller_sids, writer_sids) — non-default principals that can enroll in,
    or take object-wide control of, a certificate template (or CA object).

    "writers" means GenericAll/GenericWrite/WriteDacl/WriteOwner — the rights that
    let you reconfigure the template into ESC1. A WriteProperty scoped to a single
    attribute is NOT ESC4 and is deliberately excluded (it is what made default
    templates show up as false positives)."""
    enrollers, writers = [], []
    try:
        dacl = SR_SECURITY_DESCRIPTOR(data=sd_bytes)["Dacl"]
    except Exception:
        return enrollers, writers
    if not dacl:
        return enrollers, writers
    write_bits = (ACE_WRITE_DACL | ACE_WRITE_OWNER | ACE_GENERIC_WRITE)
    for ace in dacl["Data"]:
        if ace["AceType"] not in (ACCESS_ALLOWED_ACE.ACE_TYPE,
                                  ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE):
            continue
        body = ace["Ace"]
        mask = body["Mask"]["Mask"]
        sid  = body["Sid"].formatCanonical()
        if is_default_privileged(sid):
            continue
        full = bool(mask & ACE_GENERIC_ALL) or (mask & ACE_FULL_CONTROL) == ACE_FULL_CONTROL
        if (full or (mask & write_bits)) and sid not in writers:
            writers.append(sid)
        enroll = full
        if mask & ACE_DS_CONTROL_ACCESS:
            obj = None
            if ace["AceType"] == ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE and \
               (body["Flags"] & ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT):
                obj = bin_to_string(body["ObjectType"]).lower()
            if obj is None or obj in (CERT_ENROLL_GUID, CERT_AUTOENROLL_GUID):
                enroll = True
        if enroll and sid not in enrollers:
            enrollers.append(sid)
    return enrollers, writers


def _evaluate_template(name_flag, enroll_flag, ra_sigs, ekus, enrollers, low_writers):
    """Return the list of ESC labels a template qualifies for. `enrollers` are
    non-default principals that can enroll; `low_writers` are LOW-PRIVILEGED
    principals with object-wide write (already filtered — an admin writer is the
    expected default and is not ESC4)."""
    supplies_subject = bool(name_flag & CT_ENROLLEE_SUPPLIES_SUBJECT)
    manager_approval = bool(enroll_flag & CT_PEND_ALL_REQUESTS)
    no_sec_ext       = bool(enroll_flag & CT_NO_SECURITY_EXTENSION)
    can_auth     = (not ekus) or any(o in AUTH_EKUS for o in ekus)
    any_purpose  = ANY_PURPOSE_EKU in ekus
    enroll_agent = ENROLLMENT_AGENT_EKU in ekus
    can_enroll   = bool(enrollers)

    escs = []
    if supplies_subject and can_auth and not manager_approval and ra_sigs == 0 and can_enroll:
        escs.append("ESC1")
    if any_purpose and not manager_approval and can_enroll:
        escs.append("ESC2")
    if enroll_agent and not manager_approval and can_enroll:
        escs.append("ESC3")
    if low_writers:
        escs.append("ESC4")
    if no_sec_ext and can_enroll:
        escs.append("ESC9")
    return escs


def fetch_adcs(conn, config_nc, resolve_base, cache):
    """Enumerate CAs and certificate templates from the Configuration NC and flag
    LDAP-detectable ESC misconfigurations (ESC1/2/3/4/9, plus ESC7-ish CA control)."""
    result = {"cas": [], "templates": [], "present": False}
    if not config_nc:
        return result
    pks     = f"CN=Public Key Services,CN=Services,{config_nc}"
    sd_ctrl = security_descriptor_control(sdflags=0x04)

    published = set()
    try:
        conn.search(f"CN=Enrollment Services,{pks}",
                    "(objectClass=pKIEnrollmentService)", search_scope=SUBTREE,
                    attributes=["cn", "dNSHostName", "certificateTemplates",
                                "nTSecurityDescriptor"], controls=sd_ctrl)
        result["present"] = True
        for e in conn.entries:
            templates = []
            try:
                templates = [str(t) for t in e["certificateTemplates"].values]
            except Exception:
                pass
            published.update(t.lower() for t in templates)
            _, writers = template_sd_rights(_attr_raw(e, "nTSecurityDescriptor") or b"")
            low_writers = [w for w in writers if is_low_priv(w)]  # ESC7: skip the CA's own host / admins
            result["cas"].append({
                "name":      _attr_str(e, "cn") or str(e.entry_dn),
                "host":      _attr_str(e, "dNSHostName"),
                "published": len(templates),
                "writers":   [resolve_sid(conn, s, resolve_base, cache) for s in low_writers],
            })
    except LDAPException:
        pass

    try:
        conn.search(f"CN=Certificate Templates,{pks}",
                    "(objectClass=pKICertificateTemplate)", search_scope=SUBTREE,
                    attributes=["cn", "displayName", "pKIExtendedKeyUsage",
                                "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
                                "msPKI-RA-Signature", "nTSecurityDescriptor"],
                    controls=sd_ctrl)
        result["present"] = True
        for e in conn.entries:
            cn = _attr_str(e, "cn") or ""
            def _int(a):
                try:
                    return int(e[a].value or 0)
                except Exception:
                    return 0
            try:
                ekus = [str(o) for o in e["pKIExtendedKeyUsage"].values]
            except Exception:
                ekus = []
            enrollers, writers = template_sd_rights(_attr_raw(e, "nTSecurityDescriptor") or b"")
            low_writers = [w for w in writers if is_low_priv(w)]  # ESC4 only for low-priv writers
            escs = _evaluate_template(_int("msPKI-Certificate-Name-Flag"),
                                      _int("msPKI-Enrollment-Flag"),
                                      _int("msPKI-RA-Signature"),
                                      ekus, enrollers, low_writers)
            if not escs:
                continue
            result["templates"].append({
                "name":      _attr_str(e, "displayName") or cn,
                "enabled":   cn.lower() in published,
                "escs":      escs,
                "enrollers": [resolve_sid(conn, s, resolve_base, cache) for s in enrollers],
                "writers":   [resolve_sid(conn, s, resolve_base, cache) for s in low_writers],
            })
    except LDAPException:
        pass

    return result


def query_rootdse(server):
    """Return rootDSE attributes from an anonymous query, or {}."""
    try:
        conn = Connection(server)
        conn.open()
        conn.search("", "(objectClass=*)", search_scope=BASE,
                    attributes=["defaultNamingContext", "rootDomainNamingContext",
                                "namingContexts", "schemaNamingContext",
                                "configurationNamingContext"])
        result = {}
        if conn.entries:
            e = conn.entries[0]
            for attr in ["defaultNamingContext", "rootDomainNamingContext",
                         "schemaNamingContext", "configurationNamingContext"]:
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


def build_tree(entries, with_gplink=False, with_acl=False):
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
        if with_acl:
            try:
                item["_sd_raw"] = e["nTSecurityDescriptor"].raw_values[0]
            except Exception:
                item["_sd_raw"] = None
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
    for ace in item.get("acl", []):
        rights = ", ".join(ace["rights"])
        inh    = f" {GREY}(inherited){NC}{RED}" if ace["inherited"] else ""
        print(f"{indent}    {RED}! {rights} → {ace['who']}{inh}{NC}", file=out)


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


def print_gpo_acls(gpo_items, out=None):
    """Print the GPO objects that carry non-default/abusable rights."""
    out = out or sys.stdout
    flagged = sorted((g for g in gpo_items if g.get("acl")),
                     key=lambda x: x["name"].lower())
    print("", file=out)
    print("Group Policy Objects — non-default rights", file=out)
    print(f"GPOs: {len(gpo_items)}  Flagged: {len(flagged)}", file=out)
    print("=" * 60, file=out)
    if not flagged:
        print("No non-default rights found on GPO objects.", file=out)
        return
    for g in flagged:
        print(f"{g['name']} {GREY}[{g['guid']}]{NC}", file=out)
        for ace in g["acl"]:
            rights = ", ".join(ace["rights"])
            inh    = f" {GREY}(inherited){NC}{RED}" if ace["inherited"] else ""
            print(f"    {RED}! {rights} → {ace['who']}{inh}{NC}", file=out)


def print_gpo_creators(creator_info, out=None):
    """Print who (non-default) can create GPOs, per domain."""
    out = out or sys.stdout
    print("", file=out)
    print("GPO creation rights — non-default", file=out)
    print("=" * 60, file=out)
    if not any(c["members"] or c["delegations"] for c in creator_info):
        print("No non-default GPO-creation rights found "
              "(only built-in admins can create GPOs).", file=out)
        return
    for c in creator_info:
        if not (c["members"] or c["delegations"]):
            continue
        print(c["domain"], file=out)
        if c["members"]:
            print(f"  {GREY}Group Policy Creator Owners members:{NC}", file=out)
            for name, is_group in c["members"]:
                tag = f" {GREY}(group){NC}" if is_group else ""
                print(f"    {RED}• {name}{tag}{NC}", file=out)
        if c["delegations"]:
            print(f"  {GREY}Delegated CreateChild on CN=Policies,CN=System:{NC}", file=out)
            for name in c["delegations"]:
                print(f"    {RED}! CreateChild → {name}{NC}", file=out)


def print_dcsync(dcsync_info, out=None):
    """Print who (non-default) can DCSync, per domain."""
    out = out or sys.stdout
    print("", file=out)
    print("DCSync rights — non-default", file=out)
    print("=" * 60, file=out)
    if not any(d["principals"] for d in dcsync_info):
        print("No non-default replication rights found on the domain head.", file=out)
        return
    for d in dcsync_info:
        if not d["principals"]:
            continue
        print(d["domain"], file=out)
        # full DCSync first, then partial holders
        for p in sorted(d["principals"], key=lambda x: (not x["dcsync"], x["who"].lower())):
            if p["dcsync"]:
                print(f"    {RED}!! DCSync (GetChanges + GetChangesAll) → {p['who']}{NC}", file=out)
            else:
                have = " + ".join(sorted(p["rights"]))
                print(f"    {YELLOW}!  {have} (partial — not enough alone) → {p['who']}{NC}", file=out)


def print_vuln(vuln_info, out=None):
    """Print kerberoastable/AS-REP users and delegation misconfigurations."""
    out = out or sys.stdout
    print("", file=out)
    print("Vulnerable / abusable account configurations", file=out)
    print("=" * 60, file=out)
    def _sections(d):
        return (d["kerberoastable"] or d["asrep"] or d["unconstrained"] or
                d["constrained"] or d["rbcd"] or d["secrets"] or
                d["passwd_notreqd"] or d["reversible"])

    if not any(_sections(d) for d in vuln_info):
        print("None found.", file=out)
        return
    for d in vuln_info:
        if not _sections(d):
            continue
        print(d["domain"], file=out)
        admins = d["admincount"]

        def _star(sam):
            # highlight roastable/abusable accounts that are also privileged
            return f" {RED}⭐ adminCount=1{NC}" if sam in admins else ""

        if d["secrets"]:
            print(f"  {GREY}Possible passwords in description/info:{NC}", file=out)
            for sam, field, value in d["secrets"]:
                print(f"    {RED}★ {sam}{NC} {GREY}({field}){NC} {YELLOW}{value}{NC}", file=out)

        if d["kerberoastable"]:
            print(f"  {GREY}Kerberoastable users (SPN set):{NC}", file=out)
            for sam, spns in d["kerberoastable"]:
                extra = f"  +{len(spns) - 1} more" if len(spns) > 1 else ""
                print(f"    {YELLOW}◆ {sam}{NC} {GREY}[{spns[0]}{extra}]{NC}{_star(sam)}", file=out)

        if d["asrep"]:
            print(f"  {GREY}AS-REP roastable users (pre-auth not required):{NC}", file=out)
            for sam in d["asrep"]:
                print(f"    {YELLOW}◆ {sam}{NC}{_star(sam)}", file=out)

        if d["unconstrained"]:
            print(f"  {GREY}Unconstrained delegation (non-DC):{NC}", file=out)
            for sam, kind in d["unconstrained"]:
                print(f"    {RED}‼ {sam} {GREY}({kind}){NC}", file=out)

        if d["constrained"]:
            print(f"  {GREY}Constrained delegation:{NC}", file=out)
            for sam, kind, prot, targets in d["constrained"]:
                pt = f" {RED}[+protocol transition]{NC}" if prot else ""
                print(f"    {RED}! {sam} {GREY}({kind}){NC}{pt}"
                      f"{GREY} → {', '.join(targets)}{NC}", file=out)

        if d["rbcd"]:
            print(f"  {GREY}Resource-based constrained delegation (RBCD):{NC}", file=out)
            for sam, kind, who in d["rbcd"]:
                wholist = ", ".join(who) if who else "(could not resolve principals)"
                print(f"    {RED}! {sam} {GREY}({kind}) ← can be acted on by: {wholist}{NC}",
                      file=out)

        if d["passwd_notreqd"]:
            print(f"  {GREY}PASSWD_NOTREQD (may accept an empty password):{NC}", file=out)
            for sam in d["passwd_notreqd"]:
                print(f"    {YELLOW}◆ {sam}{NC}{_star(sam)}", file=out)

        if d["reversible"]:
            print(f"  {GREY}Reversible encryption (password recoverable):{NC}", file=out)
            for sam in d["reversible"]:
                print(f"    {YELLOW}◆ {sam}{NC}{_star(sam)}", file=out)


def print_priv_groups(group_info, out=None):
    """Print transitive membership of privileged/interesting groups."""
    out = out or sys.stdout
    print("", file=out)
    print("Privileged group members", file=out)
    print("=" * 60, file=out)
    if not any(d["groups"] for d in group_info):
        print("No members found in the enumerated privileged groups.", file=out)
        return
    for d in group_info:
        if not d["groups"]:
            continue
        print(d["domain"], file=out)
        for label, members in d["groups"]:
            print(f"  {GREY}{label} ({len(members)}):{NC}", file=out)
            for name, typ in members:
                tag = f" {GREY}({typ}){NC}" if typ != "user" else ""
                print(f"    {RED}• {name}{NC}{tag}", file=out)


def print_creds(creds_info, out=None):
    """Print readable LAPS passwords and gMSA managed-account access."""
    out = out or sys.stdout
    print("", file=out)
    print("Readable credentials (LAPS / gMSA)", file=out)
    print("=" * 60, file=out)
    if not any(d["laps"] or d["gmsa"] for d in creds_info):
        print("No LAPS or gMSA objects found.", file=out)
        return
    for d in creds_info:
        if not (d["laps"] or d["gmsa"]):
            continue
        print(d["domain"], file=out)

        if d["laps"]:
            readable = [x for x in d["laps"] if x[2] is not None]
            enc      = [x for x in d["laps"] if x[1] == "encrypted"]
            locked   = [x for x in d["laps"] if x[2] is None and x[1] != "encrypted"]
            print(f"  {GREY}LAPS local-admin passwords "
                  f"({len(d['laps'])} host(s), {len(readable)} readable):{NC}", file=out)
            for sam, typ, val in readable:
                print(f"    {RED}! {sam}{NC} {GREY}({typ}){NC} {YELLOW}{val}{NC}", file=out)
            if enc:
                print(f"    {GREY}· {len(enc)} host(s) have an encrypted password "
                      f"(need the LAPS decryption key){NC}", file=out)
            if locked:
                print(f"    {GREY}· {len(locked)} host(s) LAPS-enabled but not readable "
                      f"by you{NC}", file=out)

        if d["gmsa"]:
            print(f"  {GREY}Group Managed Service Accounts:{NC}", file=out)
            for sam, readable, readers in d["gmsa"]:
                if readable:
                    print(f"    {RED}! {sam} — managed password READABLE by you "
                          f"(dump the hash){NC}", file=out)
                else:
                    who = ", ".join(readers) if readers else "(none resolved)"
                    print(f"    {GREY}· {sam} — readable by: {who}{NC}", file=out)


def print_trusts(trust_info, out=None):
    """Print domain/forest trust relationships."""
    out = out or sys.stdout
    arrows = {0: "·", 1: "←", 2: "→", 3: "↔"}
    print("", file=out)
    print("Domain / forest trusts", file=out)
    print("=" * 60, file=out)
    if not any(d["trusts"] for d in trust_info):
        print("No trust relationships found.", file=out)
        return
    for d in trust_info:
        if not d["trusts"]:
            continue
        print(d["domain"], file=out)
        for t in d["trusts"]:
            arrow = arrows.get(t["direction"], "?")
            direction = TRUST_DIRECTION.get(t["direction"], str(t["direction"]))
            ttype = TRUST_TYPE.get(t["type"], str(t["type"]))
            flags = [lbl for bit, lbl in TRUST_ATTR_FLAGS if t["attrs"] & bit]
            flagstr = f" {GREY}[{', '.join(flags)}]{NC}" if flags else ""
            print(f"    {YELLOW}{arrow} {t['partner']}{NC} "
                  f"{GREY}({direction}, {ttype}){NC}{flagstr}", file=out)


def print_computers(comp_info, out=None):
    """Print the computer inventory, flagging EOL OSes and stale accounts."""
    out = out or sys.stdout
    total = sum(len(d["computers"]) for d in comp_info)
    print("", file=out)
    print("Computers — inventory (EOL / stale flags)", file=out)
    print(f"Computers: {total}", file=out)
    print("=" * 60, file=out)
    if not total:
        print("No computer accounts found.", file=out)
        return
    now = datetime.now(timezone.utc)
    for d in comp_info:
        if not d["computers"]:
            continue
        print(d["domain"], file=out)
        for c in sorted(d["computers"], key=lambda x: x["name"].lower()):
            flags = []
            if any(m.lower() in c["os"].lower() for m in EOL_OS_MARKERS):
                flags.append("EOL-OS")
            if c["uac"] & UAC_ACCOUNTDISABLE:
                flags.append("disabled")
            if c["llt"]:
                days = (now - c["llt"]).days
                last = c["llt"].strftime("%Y-%m-%d")
                if days > 90:
                    flags.append(f"stale {days}d")
            else:
                last = "never"
            flagstr = f" {RED}[{', '.join(flags)}]{NC}" if flags else ""
            print(f"    {GREY}{c['name']} ({c['os']}, last {last}){NC}{flagstr}", file=out)


def print_adcs(adcs, out=None):
    """Print AD CS CAs and templates with detectable ESC misconfigurations."""
    out = out or sys.stdout
    print("", file=out)
    print("AD CS — certificate authorities & vulnerable templates", file=out)
    print("=" * 60, file=out)
    if not adcs["present"]:
        print("No AD CS found (no Enrollment Services in the Configuration NC).", file=out)
        return

    for ca in adcs["cas"]:
        loc = f" @ {ca['host']}" if ca["host"] else ""
        print(f"{YELLOW}CA: {ca['name']}{loc}{NC} "
              f"{GREY}({ca['published']} templates published){NC}", file=out)
        for w in ca["writers"]:
            print(f"    {RED}! ESC7: low-priv control over the CA object → {w}{NC}", file=out)

    vuln = sorted(adcs["templates"], key=lambda x: x["name"].lower())
    print(f"{GREY}Vulnerable templates: {len(vuln)}{NC}", file=out)
    for t in vuln:
        state = "enabled" if t["enabled"] else "not published"
        print(f"  {RED}{t['name']}{NC} {GREY}({state}){NC} {RED}[{', '.join(t['escs'])}]{NC}",
              file=out)
        if t["enrollers"]:
            print(f"    {GREY}enrollable by: {', '.join(t['enrollers'])}{NC}", file=out)
        if t.get("writers"):
            print(f"    {GREY}writable by: {', '.join(t['writers'])}{NC}", file=out)
    print(f"{GREY}(ESC6/ESC8/ESC11 need CA registry / HTTP / RPC access — not checked over LDAP){NC}",
          file=out)


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
    parser.add_argument("--acl",            action="store_true",             help="Flag non-default/abusable rights: ACEs on each OU and GPO object, who can create GPOs, and who can DCSync the domain. Requires impacket")
    parser.add_argument("--vuln",           action="store_true",             help="Enumerate attack surface: kerberoastable & AS-REP-roastable users, delegation, RBCD, weak account flags, and secrets in description fields")
    parser.add_argument("--groups",         action="store_true",             help="Dump transitive membership of privileged groups (Domain/Enterprise Admins, operators, DnsAdmins, ...)")
    parser.add_argument("--creds",          action="store_true",             help="Show LAPS local-admin passwords and gMSA managed passwords readable by the current user")
    parser.add_argument("--trusts",         action="store_true",             help="Enumerate domain/forest trusts (direction, type, transitivity, SID filtering)")
    parser.add_argument("--computers",      action="store_true",             help="List computer accounts with OS, flagging end-of-life OSes and stale accounts")
    parser.add_argument("--adcs",           action="store_true",             help="Enumerate AD CS CAs and certificate templates, flagging ESC1/2/3/4/9 misconfigurations. Requires impacket")
    parser.add_argument("-A", "--all",      action="store_true",             help="Enable every enumeration module (--acl --vuln --groups --creds --trusts --computers --adcs)")
    parser.add_argument("--no-ldaps",       action="store_true",             help="Use plain LDAP (port 389/3268) instead of LDAPS")
    parser.add_argument("--version",        action="version", version=f"%(prog)s {VERSION}")
    args = parser.parse_args()

    if args.all:
        args.acl = args.vuln = args.groups = args.creds = True
        args.trusts = args.computers = args.adcs = True

    if (args.acl or args.adcs) and not HAS_IMPACKET:
        log_error("--acl/--adcs require impacket. Install it with: pip install impacket")
        sys.exit(1)

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
    ou_attrs = ["gPLink"]
    # Request DACL + Owner only (SD flags 0x05); asking for the SACL would need
    # SeSecurityPrivilege and fail for a normal user.
    sd_controls = None
    if args.acl:
        ou_attrs.append("nTSecurityDescriptor")
        sd_controls = security_descriptor_control(sdflags=0x05)
    try:
        conn.search(
            search_base=args.base_dn,
            search_filter=ldap_filter,
            search_scope=SUBTREE,
            attributes=ou_attrs,
            controls=sd_controls,
        )
    except LDAPException as e:
        log_error(f"LDAP search failed: {e}")
        sys.exit(1)

    ou_data = build_tree(conn.entries, with_gplink=True, with_acl=args.acl)
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

    gpo_items = []
    gpo_creators = []
    dcsync_info = []
    vuln_info = []
    group_info = []
    creds_info = []
    trust_info = []
    comp_info = []
    adcs_info = None
    if args.acl:
        # Resolve trustee SIDs against the DC's own domain NC (rootDSE default).
        acl_base = rootdse.get("defaultNamingContext") or args.base_dn or (
            naming_contexts[0] if naming_contexts else "")

        log_verbose("Analyzing OU security descriptors for non-default ACEs", args.verbose)
        enrich_acls(conn, ou_data, acl_base)
        log_verbose(f"Flagged interesting ACEs on "
                    f"{sum(1 for i in ou_data if i.get('acl'))} OUs", args.verbose)

        if args.gc:
            log_verbose("GC mode: GPO security descriptors may be incomplete over the GC port", args.verbose)
        log_verbose("Analyzing GPO security descriptors for non-default ACEs", args.verbose)
        gpo_items = fetch_gpo_acls(conn, naming_contexts)
        enrich_acls(conn, gpo_items, acl_base)
        log_verbose(f"Flagged non-default rights on "
                    f"{sum(1 for g in gpo_items if g.get('acl'))} of {len(gpo_items)} GPOs",
                    args.verbose)

        log_verbose("Enumerating non-default GPO-creation rights", args.verbose)
        gpo_creators = fetch_gpo_creators(conn, naming_contexts, {})
        log_verbose(f"Found non-default GPO creators in "
                    f"{sum(1 for c in gpo_creators if c['members'] or c['delegations'])} domain(s)",
                    args.verbose)

        log_verbose("Checking the domain head for non-default DCSync rights", args.verbose)
        dcsync_info = fetch_dcsync_rights(conn, naming_contexts, {})
        log_verbose(f"Found non-default replication rights in "
                    f"{sum(1 for d in dcsync_info if d['principals'])} domain(s)", args.verbose)

    if args.vuln:
        log_verbose("Enumerating kerberoast/AS-REP/delegation attack surface", args.verbose)
        vuln_info = fetch_vuln(conn, naming_contexts, {})

    if args.groups:
        log_verbose("Enumerating privileged group membership", args.verbose)
        group_info = fetch_priv_groups(conn, naming_contexts, {})

    if args.creds:
        log_verbose("Looking for readable LAPS / gMSA passwords", args.verbose)
        creds_info = fetch_creds(conn, naming_contexts, {})

    if args.trusts:
        log_verbose("Enumerating domain/forest trusts", args.verbose)
        trust_info = fetch_trusts(conn, naming_contexts)

    if args.computers:
        log_verbose("Enumerating computer accounts", args.verbose)
        comp_info = fetch_computers(conn, naming_contexts)

    if args.adcs:
        config_nc = rootdse.get("configurationNamingContext") or (
            "CN=Configuration," + rootdse["rootDomainNamingContext"]
            if rootdse.get("rootDomainNamingContext") else "")
        adcs_base = rootdse.get("defaultNamingContext") or args.base_dn or (
            naming_contexts[0] if naming_contexts else "")
        log_verbose(f"Enumerating AD CS under {config_nc or '(unknown config NC)'}", args.verbose)
        adcs_info = fetch_adcs(conn, config_nc, adcs_base, {})

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

    def emit(out):
        print_tree(ou_data, args.base_dn, root_item=root, domains=domains, out=out)
        if args.acl:
            print_gpo_acls(gpo_items, out=out)
            print_gpo_creators(gpo_creators, out=out)
            print_dcsync(dcsync_info, out=out)
        if args.vuln:
            print_vuln(vuln_info, out=out)
        if args.groups:
            print_priv_groups(group_info, out=out)
        if args.creds:
            print_creds(creds_info, out=out)
        if args.trusts:
            print_trusts(trust_info, out=out)
        if args.computers:
            print_computers(comp_info, out=out)
        if args.adcs and adcs_info is not None:
            print_adcs(adcs_info, out=out)

    if args.output:
        try:
            with open(args.output, "w") as f:
                emit(f)
            log_success(f"Results saved to: {args.output}")
        except OSError as e:
            log_error(f"Could not write {args.output}: {e}")
            sys.exit(1)
    else:
        emit(sys.stdout)

    log_success("Done")


if __name__ == "__main__":
    main()
