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
    }
}

# Add these constants at the end of the file
DEFAULT_DEVICE_TYPE = 'cisco_ios'
REQUIRED_CSV_HEADERS = ['hostname']  # IP address is no longer required 