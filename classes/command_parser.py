from typing import Dict, List
import re

class CommandParser:
    @staticmethod
    def parse_interface_status(output: str) -> List[Dict[str, str]]:
        """Parse 'show interface | include connected' output"""
        interfaces = []
        pattern = r"(\S+) is up, line protocol is up"
        
        for line in output.splitlines():
            match = re.match(pattern, line)
            if match:
                interfaces.append({
                    'interface': match.group(1),
                    'status': 'up',
                    'protocol': 'up'
                })
        return interfaces

    @staticmethod
    def parse_ip_interface_brief(output: str) -> List[Dict[str, str]]:
        """Parse 'show ip interface brief' output"""
        interfaces = []
        for line in output.splitlines():
            # Skip header line
            if "Interface" in line or not line.strip():
                continue
            
            parts = line.split()
            if len(parts) >= 6:
                interfaces.append({
                    'interface': parts[0],
                    'ip_address': parts[1],
                    'status': parts[4],
                    'protocol': parts[5]
                })
        return interfaces

    @staticmethod
    def parse_vlan_brief(output: str) -> List[Dict[str, str]]:
        """Parse 'show vlan brief' output"""
        vlans = []
        for line in output.splitlines():
            # Skip headers and footers
            if not line.strip() or "VLAN" in line or "----" in line:
                continue
            
            parts = line.split()
            if len(parts) >= 2:
                vlans.append({
                    'vlan_id': parts[0],
                    'name': parts[1],
                    'status': parts[2] if len(parts) > 2 else 'active'
                })
        return vlans

    @staticmethod
    def parse_mac_address_table(output: str) -> List[Dict[str, str]]:
        """Parse 'show mac address-table' output"""
        mac_entries = []
        for line in output.splitlines():
            # Skip headers
            if "Mac Address Table" in line or "----" in line or not line.strip():
                continue
            
            parts = line.split()
            if len(parts) >= 4:
                mac_entries.append({
                    'vlan': parts[0],
                    'mac_address': parts[1],
                    'type': parts[2],
                    'port': parts[3]
                })
        return mac_entries

    @staticmethod
    def parse_cdp_neighbors_detail(output: str) -> List[Dict[str, str]]:
        """Parse 'show cdp neighbors detail' output"""
        neighbors = []
        current_neighbor = {}
        
        for line in output.splitlines():
            if "Device ID:" in line:
                if current_neighbor:
                    neighbors.append(current_neighbor)
                current_neighbor = {'device_id': line.split("Device ID:")[1].strip()}
            elif "IP address:" in line:
                current_neighbor['ip_address'] = line.split("IP address:")[1].strip()
            elif "Platform:" in line:
                platform_parts = line.split("Platform:")[1].split(",")
                current_neighbor['platform'] = platform_parts[0].strip()
            elif "Interface:" in line and "Port ID" in line:
                interface_parts = line.split(",")
                current_neighbor['local_interface'] = interface_parts[0].split(":")[1].strip()
                current_neighbor['remote_interface'] = interface_parts[1].split(":")[1].strip()
                
        if current_neighbor:
            neighbors.append(current_neighbor)
        return neighbors

    @staticmethod
    def parse_inventory(output: str) -> List[Dict[str, str]]:
        """Parse 'show inventory' output"""
        inventory = []
        current_item = {}
        
        for line in output.splitlines():
            if "NAME:" in line:
                if current_item:
                    inventory.append(current_item)
                current_item = {}
                parts = line.split('"')
                if len(parts) >= 2:
                    current_item['name'] = parts[1]
            elif "DESCR:" in line:
                parts = line.split('"')
                if len(parts) >= 2:
                    current_item['description'] = parts[1]
            elif "SN:" in line:
                current_item['serial'] = line.split("SN:")[1].strip()
                
        if current_item:
            inventory.append(current_item)
        return inventory

    @staticmethod
    def parse_interface_status_detailed(output: str) -> List[Dict[str, str]]:
        """Parse 'show interface status' output"""
        interfaces = []
        
        # Skip header lines
        lines = [line for line in output.splitlines() if line.strip() and 'Port' not in line and '----' not in line]
        
        for line in lines:
            # Split line while preserving spaces in description
            # This handles variable-width fields better
            try:
                # First, handle the fixed-width fields from the end
                parts = line.rstrip().split()
                if len(parts) < 7:
                    continue
                    
                # Work backwards from the end for fixed fields
                type_ = parts[-1]
                speed = parts[-2]
                duplex = parts[-3]
                vlan = parts[-4]
                status = parts[-5]
                
                # Handle interface name (always first field)
                interface = parts[0]
                
                # Description might contain spaces, so join remaining parts
                description = ' '.join(parts[1:-5]).strip()
                if description == '--':
                    description = ''
                
                # Only include if status contains 'connected'
                if 'connected' in status.lower():
                    interfaces.append({
                        'interface': interface[:30],  # Limit field lengths
                        'description': description[:50],
                        'status': status[:15],
                        'vlan': vlan[:10],
                        'duplex': duplex[:10],
                        'speed': speed[:10],
                        'type': type_[:20]
                    })
            except Exception as e:
                print(f"Error parsing line: {line} - {str(e)}")
                continue
                
        return interfaces

    @staticmethod
    def parse_running_config(output: str) -> Dict[str, str]:
        """Parse 'show running-config' output"""
        sections = {
            'interfaces': [],
            'vlans': [],
            'routing': [],
            'acls': [],
            'snmp': []
        }
        
        current_section = None
        
        for line in output.splitlines():
            if line.startswith('interface '):
                current_section = 'interfaces'
                sections['interfaces'].append(line)
            elif line.startswith('vlan '):
                current_section = 'vlans'
                sections['vlans'].append(line)
            elif line.startswith('router '):
                current_section = 'routing'
                sections['routing'].append(line)
            elif line.startswith('ip access-list '):
                current_section = 'acls'
                sections['acls'].append(line)
            elif line.startswith('snmp-server '):
                current_section = 'snmp'
                sections['snmp'].append(line)
            elif current_section and line.strip():
                sections[current_section].append(line)
                
        return sections

    @staticmethod
    def parse_version(output: str) -> Dict[str, str]:
        """Parse 'show version' output"""
        version_info = {
            'version': '',
            'uptime': '',
            'serial': '',
            'model': '',
            'memory': '',
            'flash': ''
        }
        
        patterns = {
            'version': r'Version\s+(\S+)',
            'uptime': r'uptime is\s+(.+)',
            'serial': r'Serial Number\s*:\s*(\S+)',
            'model': r'Model\s*:\s*(\S+)',
            'memory': r'with\s+(\d+[KMG]?\s*bytes)\s+of\s+memory',
            'flash': r'with\s+(\d+[KMG]?\s*bytes)\s+of\s+flash'
        }
        
        for line in output.splitlines():
            for key, pattern in patterns.items():
                match = re.search(pattern, line, re.IGNORECASE)
                if match and not version_info[key]:
                    version_info[key] = match.group(1)
                    
        return version_info

    @staticmethod
    def parse_snmp(output: str) -> Dict[str, List[str]]:
        """Parse 'show snmp' output"""
        snmp_info = {
            'communities': [],
            'locations': [],
            'contacts': [],
            'hosts': []
        }
        
        for line in output.splitlines():
            if 'Community' in line:
                community = re.search(r'Community\s+(\S+)', line)
                if community:
                    snmp_info['communities'].append(community.group(1))
            elif 'Location' in line:
                location = re.search(r'Location\s+(.+)', line)
                if location:
                    snmp_info['locations'].append(location.group(1))
            elif 'Contact' in line:
                contact = re.search(r'Contact\s+(.+)', line)
                if contact:
                    snmp_info['contacts'].append(contact.group(1))
            elif 'Host' in line:
                host = re.search(r'Host\s+(\S+)', line)
                if host:
                    snmp_info['hosts'].append(host.group(1))
                    
        return snmp_info

    @staticmethod
    def parse_interface_errors(output: str) -> List[Dict[str, str]]:
        """Parse 'show interfaces | include error|CRC|collision|abort' output"""
        interfaces = []
        current_interface = None
        error_data = {}
        
        for line in output.splitlines():
            if 'line protocol' in line:
                if current_interface and error_data:
                    interfaces.append(error_data)
                current_interface = re.match(r'(\S+) is', line)
                if current_interface:
                    error_data = {'interface': current_interface.group(1)}
            elif current_interface:
                # Extract error counters
                crc_errors = re.search(r'(\d+) CRC', line)
                input_errors = re.search(r'(\d+) input errors', line)
                output_errors = re.search(r'(\d+) output errors', line)
                collisions = re.search(r'(\d+) collisions', line)
                
                if crc_errors:
                    error_data['crc_errors'] = crc_errors.group(1)
                if input_errors:
                    error_data['input_errors'] = input_errors.group(1)
                if output_errors:
                    error_data['output_errors'] = output_errors.group(1)
                if collisions:
                    error_data['collisions'] = collisions.group(1)
        
        if current_interface and error_data:
            interfaces.append(error_data)
        return interfaces

    @staticmethod
    def parse_interface_counters(output: str) -> List[Dict[str, str]]:
        """Parse 'show interface counters' output"""
        counters = []
        for line in output.splitlines():
            if not line.strip() or 'Port' in line or '---------' in line:
                continue
            
            parts = line.split()
            if len(parts) >= 5:
                counters.append({
                    'interface': parts[0],
                    'inOctets': parts[1],
                    'inUcastPkts': parts[2],
                    'outOctets': parts[3],
                    'outUcastPkts': parts[4]
                })
        return counters

    @staticmethod
    def parse_spanning_tree(output: str) -> List[Dict[str, str]]:
        """Parse 'show spanning-tree' output"""
        stp_info = []
        current_vlan = None
        
        for line in output.splitlines():
            vlan_match = re.match(r'VLAN(\d+)', line)
            if vlan_match:
                current_vlan = vlan_match.group(1)
            elif current_vlan and 'Root ID' in line:
                root_match = re.search(r'Priority\s+(\d+).*Address\s+([0-9a-fA-F\.]+)', line)
                if root_match:
                    stp_info.append({
                        'vlan': current_vlan,
                        'root_priority': root_match.group(1),
                        'root_address': root_match.group(2)
                    })
        return stp_info

    @staticmethod
    def parse_interface_description(output: str) -> List[Dict[str, str]]:
        """Parse 'show interfaces description' output"""
        interfaces = []
        for line in output.splitlines():
            if 'Interface' in line or '---------' in line:
                continue
            parts = line.split()
            if len(parts) >= 3:
                interface = {
                    'interface': parts[0],
                    'status': parts[1],
                    'protocol': parts[2],
                    'description': ' '.join(parts[3:]) if len(parts) > 3 else ''
                }
                interfaces.append(interface)
        return interfaces

    @staticmethod
    def parse_ip_arp(output: str) -> List[Dict[str, str]]:
        """Parse 'show ip arp' output"""
        arp_entries = []
        for line in output.splitlines():
            if 'Protocol' in line or '---------' in line:
                continue
            parts = line.split()
            if len(parts) >= 6:
                entry = {
                    'protocol': parts[0],
                    'address': parts[1],
                    'age': parts[2],
                    'mac_address': parts[3],
                    'type': parts[4],
                    'interface': parts[5]
                }
                arp_entries.append(entry)
        return arp_entries

    @staticmethod
    def parse_port_security(output: str) -> List[Dict[str, str]]:
        """Parse 'show port-security' output"""
        security_entries = []
        current_interface = None
        
        for line in output.splitlines():
            if 'Port Security' in line:
                continue
            if 'Port' in line and 'MaxSecureAddr' in line:
                continue
            
            interface_match = re.match(r'(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)', line)
            if interface_match:
                security_entries.append({
                    'interface': interface_match.group(1),
                    'max_addr': interface_match.group(2),
                    'current_addr': interface_match.group(3),
                    'security_violation': interface_match.group(4),
                    'action': interface_match.group(5)
                })
        return security_entries

    @staticmethod
    def parse_spanning_tree_summary(output: str) -> List[Dict[str, str]]:
        """Parse 'show spanning-tree summary' output"""
        summary = []
        mode = ""
        instances = 0
        root_bridges = 0
        forwarding = 0
        blocking = 0
        
        for line in output.splitlines():
            if 'Switch is in' in line:
                mode = line.split('Switch is in')[-1].strip()
            elif 'spanning tree instances' in line:
                instances = re.search(r'(\d+)', line).group(1)
            elif 'root bridge for' in line:
                root_bridges = len(re.findall(r'VL\S+', line))
            elif 'ports are in forwarding state' in line:
                forwarding = re.search(r'(\d+)', line).group(1)
            elif 'ports are in blocking state' in line:
                blocking = re.search(r'(\d+)', line).group(1)
        
        summary.append({
            'mode': mode,
            'instances': instances,
            'root_bridges': str(root_bridges),
            'forwarding_ports': forwarding,
            'blocked_ports': blocking
        })
        return summary

# Define common commands with their parsers and CSV headers
COMMON_COMMANDS = {
    "Show Interfaces Status": {
        "command": "show interface status | include connected",
        "parser": CommandParser.parse_interface_status_detailed,
        "headers": ["interface", "description", "status", "vlan", "duplex", "speed", "type"]
    },
    "Show IP Interface Brief": {
        "command": "show ip interface brief",
        "parser": CommandParser.parse_ip_interface_brief,
        "headers": ["interface", "ip_address", "status", "protocol"]
    },
    "Show VLAN Brief": {
        "command": "show vlan brief",
        "parser": CommandParser.parse_vlan_brief,
        "headers": ["vlan_id", "name", "status"]
    },
    "Show MAC Address-Table": {
        "command": "show mac address-table",
        "parser": CommandParser.parse_mac_address_table,
        "headers": ["vlan", "mac_address", "type", "port"]
    },
    "Show CDP Neighbors Detail": {
        "command": "show cdp neighbors detail",
        "parser": CommandParser.parse_cdp_neighbors_detail,
        "headers": ["device_id", "ip_address", "platform", "local_interface", "remote_interface"]
    },
    "Show Inventory": {
        "command": "show inventory",
        "parser": CommandParser.parse_inventory,
        "headers": ["name", "description", "serial"]
    },
    "Show Running Config": {
        "command": "show running-config",
        "parser": CommandParser.parse_running_config,
        "headers": ["section", "config"]
    },
    "Show Version": {
        "command": "show version",
        "parser": CommandParser.parse_version,
        "headers": ["version", "uptime", "serial", "model", "memory", "flash"]
    },
    "Show SNMP": {
        "command": "show snmp",
        "parser": CommandParser.parse_snmp,
        "headers": ["type", "value"]
    },
    "Show Environment": {
        "command": "show environment all",
        "parser": None,  # Add parser if needed
        "headers": ["sensor", "status", "value"]
    },
    "Show Logging": {
        "command": "show logging",
        "parser": None,  # Add parser if needed
        "headers": ["timestamp", "facility", "severity", "message"]
    },
    "Show Tech-Support": {
        "command": "show tech-support",
        "parser": None,
        "headers": ["section", "output"]
    },
    "Show Interface Errors": {
        "command": "show interfaces | include errors|CRC|collision|abort",
        "parser": CommandParser.parse_interface_errors,
        "headers": ["interface", "input_errors", "crc_errors", "output_errors", "collisions"]
    },
    "Show Interface Counters": {
        "command": "show interfaces counters",
        "parser": CommandParser.parse_interface_counters,
        "headers": ["interface", "inOctets", "inUcastPkts", "outOctets", "outUcastPkts"]
    },
    "Show Spanning Tree Status": {
        "command": "show spanning-tree summary",
        "parser": CommandParser.parse_spanning_tree_summary,
        "headers": ["mode", "instances", "root_bridges", "forwarding_ports", "blocked_ports"]
    },
    "Show Interface Description": {
        "command": "show interfaces description",
        "parser": CommandParser.parse_interface_description,
        "headers": ["interface", "status", "protocol", "description"]
    },
    "Show IP ARP": {
        "command": "show ip arp",
        "parser": CommandParser.parse_ip_arp,
        "headers": ["protocol", "address", "age", "mac_address", "type", "interface"]
    },
    "Show Port-Security Summary": {
        "command": "show port-security",
        "parser": CommandParser.parse_port_security,
        "headers": ["interface", "max_addr", "current_addr", "security_violation", "action"]
    }
}

# Add these constants at the end of the file
DEFAULT_DEVICE_TYPE = 'cisco_ios'
REQUIRED_CSV_HEADERS = ['hostname']  # IP address is no longer required 