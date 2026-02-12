#!/usr/bin/env python3
"""
LDAP Organizational Unit Enumeration Script with GPO Links
Description: Enumerates and displays LDAP OU structure with Group Policy Links
Author: Security Enumeration Tool
Version: 3.0
"""

import argparse
import os
import sys
import re
from typing import List, Dict, Optional
import subprocess
import json
import base64


class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    PURPLE = '\033[0;35m'
    CYAN = '\033[0;36m'
    NC = '\033[0m'


class Logger:
    """Simple logging class with colored output"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
    
    def info(self, msg: str):
        print(f"{Colors.CYAN}[INFO]{Colors.NC} {msg}", file=sys.stderr)
    
    def warn(self, msg: str):
        print(f"{Colors.YELLOW}[WARN]{Colors.NC} {msg}", file=sys.stderr)
    
    def error(self, msg: str):
        print(f"{Colors.RED}[ERROR]{Colors.NC} {msg}", file=sys.stderr)
    
    def success(self, msg: str):
        print(f"{Colors.GREEN}[SUCCESS]{Colors.NC} {msg}", file=sys.stderr)
    
    def debug(self, msg: str):
        if self.verbose:
            print(f"{Colors.PURPLE}[DEBUG]{Colors.NC} {msg}", file=sys.stderr)


class LDAPEnumerator:
    """LDAP enumeration class"""
    
    def __init__(self, server: str, base_dn: Optional[str], bind_user: str, bind_pass: str, logger: Logger, use_ldaps: bool = True):
        self.server = server
        self.bind_user = bind_user
        self.bind_pass = bind_pass
        self.logger = logger
        self.use_ldaps = use_ldaps
        scheme = "ldaps" if use_ldaps else "ldap"
        self.ldap_url = f"{scheme}://{server}"
        
        # Auto-discover base DN if not provided
        if not base_dn:
            self.logger.debug("Base DN not provided, querying rootDSE")
            self.base_dn = self._get_base_dn_from_rootdse()
            self.logger.info(f"Auto-discovered Base DN: {self.base_dn}")
        else:
            self.base_dn = base_dn
    
    def _ldap_env(self) -> dict:
        """Environment for ldapsearch; skip TLS cert verification for LDAPS (typical for internal AD)."""
        env = os.environ.copy()
        if self.use_ldaps:
            env["LDAPTLS_REQCERT"] = "never"
        return env
    
    def _get_base_dn_from_rootdse(self) -> str:
        """Query rootDSE to get default naming context (base DN)"""
        try:
            cmd = [
                'ldapsearch',
                '-LLL',
                '-x',
                '-H', self.ldap_url,
                '-D', self.bind_user,
                '-w', self.bind_pass,
                '-b', '',
                '-s', 'base',
                '(objectClass=*)',
                'defaultNamingContext'
            ]
            
            env = self._ldap_env()
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, env=env)
            
            # Parse the defaultNamingContext from output
            for line in result.stdout.split('\n'):
                if line.startswith('defaultNamingContext:'):
                    return line.split(':', 1)[1].strip()
            
            raise ValueError("Could not find defaultNamingContext in rootDSE")
            
        except Exception as e:
            self.logger.error(f"Failed to query rootDSE: {e}")
            raise
    
    def _run_ldapsearch(self, base: str, scope: str, filter_str: str, attributes: List[str]) -> str:
        """Execute ldapsearch command and return output"""
        cmd = [
            'ldapsearch',
            '-LLL',  # LDIF format without comments
            '-x',    # Simple authentication
            '-H', self.ldap_url,
            '-D', self.bind_user,
            '-w', self.bind_pass,
            '-b', base,
            '-s', scope,
            filter_str
        ] + attributes
        
        self.logger.debug(f"Running: ldapsearch -H {self.ldap_url} -D {self.bind_user} -b {base} -s {scope} {filter_str} {' '.join(attributes)}")
        
        try:
            env = self._ldap_env()
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, env=env)
            return result.stdout
        except subprocess.CalledProcessError as e:
            self.logger.error(f"LDAP search failed: {e}")
            self.logger.debug(f"stderr: {e.stderr}")
            raise
    
    def test_connection(self) -> bool:
        """Test LDAP connection"""
        self.logger.debug(f"Testing LDAP connection to {self.server}")
        try:
            self._run_ldapsearch(self.base_dn, 'base', '(objectClass=*)', ['dn'])
            self.logger.success("LDAP connection established")
            return True
        except Exception as e:
            self.logger.error("Failed to connect to LDAP server or authenticate")
            self.logger.info(f"  - Server address: {self.server}")
            self.logger.info(f"  - Base DN: {self.base_dn}")
            self.logger.info("  - Please verify credentials and connectivity")
            return False
    
    def get_domain_root(self) -> Dict:
        """Get domain root information including gPLink"""
        self.logger.debug("Querying domain root")
        output = self._run_ldapsearch(self.base_dn, 'base', '(objectClass=*)', ['dn', 'gPLink'])
        return self._parse_ldif(output)[0] if output else {}
    
    def get_organizational_units(self) -> List[Dict]:
        """Get all organizational units with gPLink"""
        self.logger.debug("Querying organizational units")
        output = self._run_ldapsearch(
            self.base_dn, 
            'sub', 
            '(objectClass=organizationalUnit)', 
            ['dn', 'gPLink']
        )
        return self._parse_ldif(output)
    
    def get_gpo_details(self) -> Dict[str, str]:
        """Get GPO GUID to name mapping"""
        self.logger.debug("Fetching GPO details")
        try:
            output = self._run_ldapsearch(
                f"CN=Policies,CN=System,{self.base_dn}",
                'sub',
                '(objectClass=groupPolicyContainer)',
                ['cn', 'displayName']
            )
            
            gpo_map = {}
            entries = self._parse_ldif(output)
            
            for entry in entries:
                cn = entry.get('cn', [''])[0]
                display_name = entry.get('displayName', [cn])[0]
                if cn:
                    # Strip braces and normalize to lowercase for matching
                    guid = cn.strip('{}').lower()
                    gpo_map[guid] = display_name
                    self.logger.debug(f"GPO: {guid} -> {display_name}")
            
            self.logger.debug(f"Found {len(gpo_map)} GPOs")
            return gpo_map
            
        except Exception as e:
            self.logger.warn(f"Could not fetch GPO details: {e}")
            return {}
    
    def _parse_ldif(self, ldif_output: str) -> List[Dict]:
        """Parse LDIF output into list of dictionaries"""
        entries = []
        current_entry = {}
        current_attr = None
        
        for line in ldif_output.split('\n'):
            # Handle line continuations (leading space)
            if line.startswith(' ') and current_attr:
                current_entry[current_attr][-1] += line[1:]
                continue
            
            line = line.strip()
            
            if not line:
                # Empty line = end of entry
                if current_entry:
                    entries.append(current_entry)
                    current_entry = {}
                    current_attr = None
                continue
            
            if ':' in line:
                # Check if it's base64 encoded (:: instead of :)
                if '::' in line:
                    attr, value = line.split('::', 1)
                    attr = attr.strip()
                    value = value.strip()
                    
                    # Decode base64
                    try:
                        decoded_value = base64.b64decode(value).decode('utf-8')
                        value = decoded_value
                    except Exception as e:
                        # If decoding fails, keep original value
                        self.logger.debug(f"Failed to decode base64 for {attr}: {e}")
                else:
                    attr, value = line.split(':', 1)
                    attr = attr.strip()
                    value = value.strip()
                
                current_attr = attr
                
                if attr not in current_entry:
                    current_entry[attr] = []
                current_entry[attr].append(value)
        
        # Add last entry if exists
        if current_entry:
            entries.append(current_entry)
        
        return entries


class GPOParser:
    """Parse and process GPO link information"""
    
    @staticmethod
    def parse_gplink(gplink_str: str) -> List[Dict]:
        """Parse gPLink attribute to extract GPO GUIDs and options
        
        Note: GPOs in gPLink are processed right-to-left in AD.
        We reverse the list so they're displayed in application order (lowest to highest priority).
        """
        if not gplink_str:
            return []
        
        # Format: [LDAP://cn={GUID},cn=policies,cn=system,DC=...;Options]
        pattern = r'\[LDAP://cn=\{([^}]+)\}[^;]*;(\d+)\]'
        matches = re.findall(pattern, gplink_str, re.IGNORECASE)
        
        gpos = []
        for guid, options in matches:
            options = int(options)
            # Options: 0=Enabled, 1=Disabled, 2=Enforced, 3=Disabled+Enforced
            enforced = bool(options & 2)
            disabled = bool(options & 1)
            
            # Normalize GUID: strip braces, lowercase
            guid_normalized = guid.strip('{}').lower()
            
            gpos.append({
                'guid': guid_normalized,
                'enforced': enforced,
                'disabled': disabled,
                'options': options
            })
        
        # Reverse the list: In AD, gPLink is processed right-to-left
        # The rightmost GPO is applied first (lowest priority)
        # The leftmost GPO is applied last (highest priority)
        # We reverse so index 1 = highest priority (applied last)
        return list(reversed(gpos))


class OUTree:
    """Build and display OU tree structure"""
    
    def __init__(self, base_dn: str, gpo_map: Dict[str, str], verbose: bool = False):
        self.base_dn = base_dn
        self.gpo_map = gpo_map
        self.verbose = verbose
        self.tree_data = []
    
    def add_domain_root(self, root_entry: Dict):
        """Add domain root to tree"""
        gplink = root_entry.get('gPLink', [''])[0]
        gpos = GPOParser.parse_gplink(gplink)
        
        self.tree_data.append({
            'path': ['[Domain Root]'],
            'depth': 1,
            'name': '[Domain Root]',
            'full_dn': root_entry.get('dn', [''])[0],
            'gpos': self._process_gpos(gpos),
            'is_root': True
        })
    
    def add_ous(self, ou_entries: List[Dict]):
        """Add OUs to tree"""
        for entry in ou_entries:
            dn = entry.get('dn', [''])[0]
            gplink = entry.get('gPLink', [''])[0]
            
            # Extract OU path from DN
            parts = [p.strip() for p in dn.split(',')]
            ou_path = []
            
            for part in reversed(parts):
                if part.upper().startswith('OU='):
                    ou_path.append(part[3:])
            
            if not ou_path:
                continue
            
            gpos = GPOParser.parse_gplink(gplink)
            
            self.tree_data.append({
                'path': ou_path,
                'depth': len(ou_path),
                'name': ou_path[-1],
                'full_dn': dn,
                'gpos': self._process_gpos(gpos),
                'is_root': False
            })
    
    def _process_gpos(self, gpos: List[Dict]) -> List[Dict]:
        """Process GPO list with names from map"""
        processed = []
        for gpo in gpos:
            guid = gpo['guid']
            name = self.gpo_map.get(guid)
            
            # If no name found, show GUID with braces
            if not name:
                name = f"{{{guid}}}"
            
            processed.append({
                'name': name,
                'guid': guid,
                'enforced': gpo['enforced'],
                'disabled': gpo['disabled']
            })
        
        return processed
    
    def sort(self):
        """Sort tree maintaining hierarchy"""
        def sort_key(item):
            if item.get('is_root'):
                return [(0, '', '')]
            
            path_key = []
            for i, component in enumerate(item['path']):
                parent = '/'.join(item['path'][:i]) if i > 0 else ''
                path_key.append((1, parent, component.lower()))
            return path_key
        
        self.tree_data.sort(key=sort_key)
    
    def display(self):
        """Display the tree structure"""
        if not self.tree_data:
            print("No organizational units found.")
            return
        
        total_gpos = sum(len(item['gpos']) for item in self.tree_data)
        ous_with_gpos = sum(1 for item in self.tree_data if item['gpos'])
        
        print("=" * 80)
        print("LDAP OU Tree Structure with Group Policy Links")
        print("=" * 80)
        print(f"Base DN: {self.base_dn}")
        print(f"Total OUs found: {len(self.tree_data)}")
        print(f"OUs with GPO links: {ous_with_gpos}")
        print(f"Total GPO links: {total_gpos}")
        print("=" * 80)
        print()
        
        for item in self.tree_data:
            self._print_item(item)
        
        print("=" * 80)
        print("Legend:")
        print("  [1] = Highest priority (applied last, overrides others)")
        print("  - Normal link (not enforced)")
        print("  > Enforced link (cannot be blocked by child OUs)")
        print("  (DISABLED) GPO link is disabled")
        print("=" * 80)
    
    def _print_item(self, item: Dict):
        """Print a single tree item"""
        if item.get('is_root'):
            depth = 0
            prefix = ''
            # Show DN next to domain root for clarity
            display_name = f"{item['name']} ({item['full_dn']})"
            gpo_indent = '    '  # Indent GPO links under domain root
        else:
            # Add 1 to depth to indent everything under domain root
            depth = item['depth']
            prefix = '+-- ' if depth == 1 else '|-- '
            display_name = item['name']
            gpo_indent = '  ' * depth + '    '
        
        indent = '  ' * depth
        
        # Print OU name
        print(f"{indent}{prefix}{display_name}")
        
        # Print DN if verbose
        if self.verbose and not item.get('is_root'):
            print(f"{indent}    DN: {item['full_dn']}")
        
        # Print GPO links
        if item['gpos']:
            print(f"{gpo_indent}GPO Links ({len(item['gpos'])} linked):")
            
            for i, gpo in enumerate(item['gpos'], 1):
                marker = '>' if gpo['enforced'] else '-'
                disabled_mark = ' (DISABLED)' if gpo['disabled'] else ''
                print(f"{gpo_indent}  {marker} [{i}] {gpo['name']}{disabled_mark}")
                
                if self.verbose:
                    print(f"{gpo_indent}      GUID: {{{gpo['guid']}}}")
            
            # Only add blank line after items with GPO links for readability
            print()
        elif self.verbose:
            print(f"{gpo_indent}GPO Links: None")


def check_dependencies():
    """Check if required tools are available"""
    try:
        subprocess.run(['ldapsearch', '-VV'], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"{Colors.RED}[ERROR]{Colors.NC} ldapsearch not found", file=sys.stderr)
        print(f"{Colors.CYAN}[INFO]{Colors.NC} Please install ldap-utils:", file=sys.stderr)
        print("  Ubuntu/Debian: sudo apt-get install ldap-utils", file=sys.stderr)
        print("  RHEL/CentOS:   sudo yum install openldap-clients", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(
        description='LDAP OU Enumeration Tool with GPO Links',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic enumeration (auto-discover Base DN)
  %(prog)s -s 10.10.10.10 -u "user@EXAMPLE.COM" -p "password123"

  # With explicit Base DN
  %(prog)s -s 10.10.10.10 -b "DC=example,DC=com" -u "user@EXAMPLE.COM" -p "password123"

  # Verbose mode with debug information
  %(prog)s -s ldap.example.com -u "user@EXAMPLE.COM" -p "password" -v

  # Save output to file
  %(prog)s -s 192.168.1.100 -u "admin@COMPANY.LOCAL" -p "P@ssw0rd" -o results.txt

  # Use plain LDAP instead of LDAPS (default is LDAPS)
  %(prog)s -s 10.10.10.10 -u "user@DOMAIN" -p "pass" --ldap

Security Notes:
  - Use this tool only on systems you own or have explicit permission to test
  - Passwords may be visible in process lists
  - LDAPS is used by default (certificate verification disabled); use --ldap for plain LDAP
        """
    )
    
    parser.add_argument('-s', '--server', required=True, help='LDAP server hostname or IP address')
    parser.add_argument('-b', '--base-dn', help='Base Distinguished Name (e.g., "DC=example,DC=com"). If not provided, will be auto-discovered from rootDSE')
    parser.add_argument('-u', '--user', required=True, help='Bind username (e.g., "user@DOMAIN.COM")')
    parser.add_argument('-p', '--password', required=True, help='Bind password')
    parser.add_argument('-o', '--output', help='Save output to file (default: stdout)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--ldap', action='store_true', help='Use plain LDAP instead of LDAPS (default: LDAPS)')
    parser.add_argument('--version', action='version', version='%(prog)s 3.0')
    
    args = parser.parse_args()
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Initialize logger
    logger = Logger(verbose=args.verbose)
    
    # Display banner
    if args.verbose:
        print(f"{Colors.BLUE}", file=sys.stderr)
        print("╔═══════════════════════════════════════════════════════════════╗", file=sys.stderr)
        print("║          LDAP OU Enumeration Tool with GPO Links v3.0        ║", file=sys.stderr)
        print("╚═══════════════════════════════════════════════════════════════╝", file=sys.stderr)
        print(f"{Colors.NC}", file=sys.stderr)
    
    # Initialize enumerator (LDAPS by default; use --ldap for plain LDAP)
    use_ldaps = not args.ldap
    enumerator = LDAPEnumerator(args.server, args.base_dn, args.user, args.password, logger, use_ldaps=use_ldaps)
    
    # Test connection
    if not enumerator.test_connection():
        sys.exit(1)
    
    logger.info("Starting LDAP OU enumeration with GPO links")
    
    # Always fetch GPO details for readable names
    gpo_map = enumerator.get_gpo_details()
    
    # Get domain root
    domain_root = enumerator.get_domain_root()
    
    # Get OUs
    ous = enumerator.get_organizational_units()
    logger.debug(f"Found {len(ous)} organizational units")
    
    # Build tree
    tree = OUTree(args.base_dn, gpo_map, args.verbose)
    if domain_root:
        tree.add_domain_root(domain_root)
    tree.add_ous(ous)
    tree.sort()
    
    # Output results
    if args.output:
        import io
        output_buffer = io.StringIO()
        sys.stdout = output_buffer
        tree.display()
        sys.stdout = sys.__stdout__
        
        with open(args.output, 'w') as f:
            f.write(output_buffer.getvalue())
        
        logger.success(f"Results saved to: {args.output}")
    else:
        tree.display()
    
    logger.success("OU enumeration with GPO links completed")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.CYAN}[INFO]{Colors.NC} Script interrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.NC} {e}", file=sys.stderr)
        sys.exit(1)