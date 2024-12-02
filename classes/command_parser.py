from typing import Dict, List
import re

class CommandParser:
    def __init__(self):
        self.parsers = {
            # ... existing parsers ...
            'show fex': self.parse_show_fex,
        }

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
            # Skip header lines and empty lines more robustly
            if not line.strip() or any(header in line for header in ['Interface', 'Protocol', '----']):
                continue
            
            try:
                # Handle variable spacing in output
                parts = line.split()
                if len(parts) >= 4:  # Need at least interface, ip, status, protocol
                    # Some devices might show "unassigned" or "not set" for IP
                    ip_address = parts[1] if parts[1] not in ['unassigned', 'not', 'none'] else ''
                    
                    # Normalize status and protocol
                    status = parts[-2].lower()
                    protocol = parts[-1].lower()
                    
                    interfaces.append({
                        'interface': parts[0][:30],
                        'ip_address': ip_address[:15],
                        'status': status[:15],
                        'protocol': protocol[:15]
                    })
            except Exception as e:
                print(f"Error parsing line: {line} - {str(e)}")
                continue
                
        return interfaces

    @staticmethod
    def parse_vlan_brief(output: str) -> List[Dict[str, str]]:
        """Parse 'show vlan brief' output"""
        vlans = []
        for line in output.splitlines():
            # Skip headers, footers, and empty lines more robustly
            if not line.strip() or any(skip in line for skip in ['VLAN', '----', 'active', 'VLAN Type']):
                continue
            
            try:
                parts = line.split()
                if len(parts) >= 2:
                    vlan_id = parts[0]
                    # Handle cases where name might contain spaces
                    name_parts = parts[1:-1] if len(parts) > 2 else [parts[1]]
                    name = ' '.join(name_parts)
                    # Normalize status
                    status = parts[-1].lower() if len(parts) > 2 else 'active'
                    
                    # Validate VLAN ID is numeric
                    if vlan_id.isdigit() and 1 <= int(vlan_id) <= 4094:
                        vlans.append({
                            'vlan_id': vlan_id[:4],
                            'name': name[:32],
                            'status': status[:10]
                        })
            except Exception as e:
                print(f"Error parsing line: {line} - {str(e)}")
                continue
                
        return vlans

    @staticmethod
    def parse_mac_address_table(output: str) -> List[Dict[str, str]]:
        """Parse 'show mac address-table' output"""
        mac_entries = []
        for line in output.splitlines():
            # Skip headers and empty lines more robustly
            if not line.strip() or any(header in line for header in [
                'Mac Address Table', 'Vlan', '----', 'Total', 'Multicast'
            ]):
                continue
            
            try:
                parts = line.split()
                if len(parts) >= 4:
                    # Normalize MAC address format
                    mac = parts[1].lower().replace('.', '').replace(':', '')
                    mac = ':'.join([mac[i:i+2] for i in range(0, 12, 2)])
                    
                    # Normalize type field
                    type_ = parts[2].lower()
                    if 'dynamic' in type_:
                        type_ = 'dynamic'
                    elif 'static' in type_:
                        type_ = 'static'
                    
                    mac_entries.append({
                        'vlan': parts[0][:4],
                        'mac_address': mac[:17],  # xx:xx:xx:xx:xx:xx
                        'type': type_[:8],
                        'port': parts[3][:20]
                    })
            except Exception as e:
                print(f"Error parsing line: {line} - {str(e)}")
                continue
                
        return mac_entries

    @staticmethod
    def parse_cdp_neighbors_detail(output: str) -> List[Dict[str, str]]:
        """Parse 'show cdp neighbors detail' output"""
        neighbors = []
        current_neighbor = {}
        
        for line in output.splitlines():
            try:
                line = line.strip()
                if "Device ID:" in line:
                    if current_neighbor:
                        neighbors.append(current_neighbor)
                    current_neighbor = {'device_id': line.split("Device ID:", 1)[1].strip()}
                elif "IP address:" in line:
                    # Handle multiple IP addresses
                    ips = re.findall(r'IP address:\s*(\S+)', line)
                    if ips:
                        current_neighbor['ip_address'] = ips[0]  # Take first IP if multiple
                elif "Platform:" in line:
                    # Handle platform and capabilities
                    platform_match = re.search(r'Platform:\s+([^,]+),\s*Capabilities:', line)
                    if platform_match:
                        current_neighbor['platform'] = platform_match.group(1).strip()
                elif "Interface:" in line and "Port ID" in line:
                    # Handle interface information more robustly
                    local_match = re.search(r'Interface:\s*([^,]+)', line)
                    remote_match = re.search(r'Port ID \(outgoing port\):\s*([^,]+)', line)
                    if local_match:
                        current_neighbor['local_interface'] = local_match.group(1).strip()
                    if remote_match:
                        current_neighbor['remote_interface'] = remote_match.group(1).strip()
                
            except Exception as e:
                print(f"Error parsing CDP line: {line} - {str(e)}")
                continue
        
        # Don't forget the last neighbor
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
        
        # Skip header lines and empty lines more robustly
        lines = [
            line for line in output.splitlines() 
            if line.strip() 
            and not any(header in line for header in ['Port', 'Name', '----'])
        ]
        
        for line in lines:
            try:
                # Split the line into parts
                parts = line.rstrip().split()
                if len(parts) < 6:  # Need at least interface, status, vlan, duplex, speed, type
                    continue
                    
                # Handle interface name (always first field)
                interface = parts[0]
                
                # Work backwards from the end for fixed fields
                type_ = parts[-1]
                speed = parts[-2]
                duplex = parts[-3]
                vlan = parts[-4]
                status = parts[-5]
                
                # Everything between interface and status is the description (might be empty)
                description_parts = parts[1:-5] if len(parts) > 6 else []
                description = ' '.join(description_parts).strip()
                
                # Handle various forms of empty/default description
                if description in ['--', 'none', 'None', ''] or not description:
                    description = ''
                
                # Normalize status field
                status = status.lower()
                
                # Only include if status contains 'connected'
                if 'connected' in status:
                    # Clean and normalize fields
                    interface = interface.strip()
                    vlan = 'trunk' if vlan.lower() in ['trunk', 'routed'] else vlan
                    duplex = duplex.lower().replace('a-', 'auto-')  # Normalize auto-duplex
                    speed = speed.lower().replace('a-', 'auto-')    # Normalize auto-speed
                    
                    interfaces.append({
                        'interface': interface[:30],      # Limit field lengths
                        'description': description[:50],  # Limit description length
                        'status': status[:15],           # Usually 'connected'
                        'vlan': vlan[:10],               # VLAN or 'trunk'
                        'duplex': duplex[:10],           # full/half/auto
                        'speed': speed[:10],             # 10/100/1000/auto
                        'type': type_[:20]               # Interface type
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

    @staticmethod
    def parse_interface_transceiver(output: str) -> List[Dict[str, str]]:
        """Parse 'show interface transceiver' output"""
        transceivers = []
        current_interface = None
        
        for line in output.splitlines():
            try:
                if 'Temperature' not in line and 'current' not in line:
                    # This is an interface line
                    interface_match = re.match(r'^(\S+)', line)
                    if interface_match:
                        current_interface = interface_match.group(1)
                elif current_interface and any(x in line.lower() for x in ['temperature', 'voltage', 'current', 'power']):
                    parts = line.split()
                    if len(parts) >= 3:
                        transceivers.append({
                            'interface': current_interface,
                            'parameter': parts[0].lower(),
                            'value': parts[1],
                            'status': parts[2].lower()
                        })
            except Exception as e:
                print(f"Error parsing transceiver line: {line} - {str(e)}")
                continue
        
        return transceivers

    @staticmethod
    def parse_power_inline(output: str) -> List[Dict[str, str]]:
        """Parse 'show power inline' output"""
        poe_ports = []
        
        for line in output.splitlines():
            try:
                if not line.strip() or any(x in line for x in ['Interface', '----']):
                    continue
                
                parts = line.split()
                if len(parts) >= 6:
                    poe_ports.append({
                        'interface': parts[0],
                        'admin': parts[1].lower(),
                        'oper': parts[2].lower(),
                        'power_draw': parts[3],
                        'device': ' '.join(parts[4:-1]),
                        'class': parts[-1]
                    })
            except Exception as e:
                print(f"Error parsing PoE line: {line} - {str(e)}")
                continue
        
        return poe_ports

    @staticmethod
    def parse_interface_counters_errors(output: str) -> List[Dict[str, str]]:
        """Parse 'show interface counters errors' output"""
        error_counters = []
        
        for line in output.splitlines():
            try:
                if not line.strip() or any(x in line for x in ['Port', '----']):
                    continue
                
                parts = line.split()
                if len(parts) >= 5:
                    error_counters.append({
                        'interface': parts[0],
                        'align_errors': parts[1],
                        'fcs_errors': parts[2],
                        'xmit_errors': parts[3],
                        'rcv_errors': parts[4],
                        'undersize': parts[5] if len(parts) > 5 else '0',
                        'oversize': parts[6] if len(parts) > 6 else '0'
                    })
            except Exception as e:
                print(f"Error parsing error counters line: {line} - {str(e)}")
                continue
        
        return error_counters

    @staticmethod
    def parse_interface_storm_control(output: str) -> List[Dict[str, str]]:
        """Parse 'show interface storm-control' output"""
        storm_control = []
        
        for line in output.splitlines():
            try:
                if not line.strip() or 'Interface' in line or '----' in line:
                    continue
                
                parts = line.split()
                if len(parts) >= 4:
                    storm_control.append({
                        'interface': parts[0],
                        'broadcast_level': parts[1],
                        'multicast_level': parts[2],
                        'unicast_level': parts[3]
                    })
            except Exception as e:
                print(f"Error parsing storm control line: {line} - {str(e)}")
                continue
        
        return storm_control

    @staticmethod
    def parse_interface_trunk(output: str) -> List[Dict[str, str]]:
        """Parse 'show interface trunk' output"""
        trunks = []
        current_interface = None
        mode = None
        native_vlan = None
        allowed_vlans = None
        
        for line in output.splitlines():
            try:
                if 'Port' in line or '----' in line:
                    continue
                    
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 5:  # Mode line
                        current_interface = parts[0]
                        mode = parts[1].lower()
                        encapsulation = parts[2].lower()
                        status = parts[3].lower()
                        native_vlan = parts[4]
                    elif current_interface and 'allowed' in line.lower():
                        # This line contains allowed VLANs
                        allowed_vlans = line.split(':')[1].strip()
                        trunks.append({
                            'interface': current_interface,
                            'mode': mode,
                            'encapsulation': encapsulation,
                            'status': status,
                            'native_vlan': native_vlan,
                            'allowed_vlans': allowed_vlans
                        })
            except Exception as e:
                print(f"Error parsing trunk line: {line} - {str(e)}")
                continue
        
        return trunks

    @staticmethod
    def parse_authentication_sessions(output: str) -> List[Dict[str, str]]:
        """Parse 'show authentication sessions' output"""
        sessions = []
        current_interface = None
        
        for line in output.splitlines():
            try:
                if not line.strip() or 'Interface' in line or '----' in line:
                    continue
                    
                parts = line.split()
                if len(parts) >= 6:
                    sessions.append({
                        'interface': parts[0],
                        'mac': parts[1],
                        'method': parts[2],
                        'domain': parts[3],
                        'status': parts[4],
                        'session': parts[5]
                    })
            except Exception as e:
                print(f"Error parsing auth session line: {line} - {str(e)}")
                continue
        
        return sessions

    @staticmethod
    def parse_environment(output: str) -> List[Dict[str, str]]:
        """Parse 'show environment all' output"""
        sensors = []
        current_section = None
        
        for line in output.splitlines():
            try:
                if not line.strip() or '----' in line:
                    continue
                    
                if 'Temperature' in line or 'Power' in line or 'Fan' in line:
                    current_section = line.split()[0].lower()
                    continue
                    
                parts = line.split()
                if len(parts) >= 3:
                    sensor_name = parts[0]
                    # Handle different output formats
                    if 'normal' in line.lower() or 'ok' in line.lower():
                        status = 'normal'
                        value = parts[-2] if len(parts) > 2 else 'N/A'
                    else:
                        status = parts[-1].lower()
                        value = parts[-2] if len(parts) > 2 else 'N/A'
                    
                    sensors.append({
                        'section': current_section,
                        'sensor': sensor_name,
                        'value': value,
                        'status': status
                    })
            except Exception as e:
                print(f"Error parsing environment line: {line} - {str(e)}")
                continue
        
        return sensors

    @staticmethod
    def parse_logging(output: str) -> List[Dict[str, str]]:
        """Parse 'show logging' output"""
        logs = []
        
        # Regular expression for common syslog format
        syslog_pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+)(?:\.\d+)?\s+(\w+):\s+%(\w+)-\d-(\w+):\s+(.+)'
        
        for line in output.splitlines():
            try:
                if 'Log Buffer' in line or not line.strip():
                    continue
                    
                match = re.match(syslog_pattern, line)
                if match:
                    timestamp, facility, severity, mnemonic, message = match.groups()
                    logs.append({
                        'timestamp': timestamp,
                        'facility': facility,
                        'severity': severity,
                        'mnemonic': mnemonic,
                        'message': message.strip()
                    })
            except Exception as e:
                print(f"Error parsing log line: {line} - {str(e)}")
                continue
        
        return logs

    @staticmethod
    def parse_spanning_tree_blocked(output: str) -> List[Dict[str, str]]:
        """Parse 'show spanning-tree blockedports' output"""
        blocked_ports = []
        current_vlan = None
        
        for line in output.splitlines():
            try:
                if not line.strip() or 'Name' in line or '----' in line:
                    continue
                    
                if line.startswith('VLAN'):
                    current_vlan = line.split()[1]
                elif current_vlan and 'BLK' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        blocked_ports.append({
                            'interface': parts[0],
                            'vlan': current_vlan,
                            'status': 'blocking',
                            'cost': parts[3],
                            'priority': parts[4]
                        })
            except Exception as e:
                print(f"Error parsing blocked port line: {line} - {str(e)}")
                continue
        
        return blocked_ports

    @staticmethod
    def parse_show_fex(output: str) -> List[Dict[str, str]]:
        """Parse 'show fex' output from Nexus switches
        
        Example output:
        FEX         Description                       State       Model            Serial
        --------------------------------------------------------------------------------
        101         FEX0101                           Online      N2K-C2248TP-E   SSI1234567
        102         FEX0102                           Online      N2K-C2248TP-1E  SSI7654321
        """
        fex_list = []
        
        # Skip if empty output or error
        if not output or "Invalid command" in output:
            return fex_list
        
        lines = output.splitlines()
        header_found = False
        
        for line in lines:
            # Look for the header line
            if "FEX" in line and "Description" in line and "State" in line:
                header_found = True
                continue
            # Skip separator line
            if header_found and "-----------------" in line:
                continue
            # Parse FEX entries
            if header_found and line.strip():
                # Split line and handle variable spacing
                parts = [part for part in line.split() if part]
                if len(parts) >= 5:
                    fex_list.append({
                        'fex_id': parts[0],
                        'description': parts[1],
                        'state': parts[2],
                        'model': parts[3],
                        'serial': parts[4]
                    })
        
        return fex_list

# Define common commands with their parsers and CSV headers
COMMON_COMMANDS = {
    "Show Interfaces Status": {
        "command": "show interface status",
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
        "parser": CommandParser.parse_environment,
        "headers": ["section", "sensor", "value", "status"]
    },
    "Show Logging": {
        "command": "show logging",
        "parser": CommandParser.parse_logging,
        "headers": ["timestamp", "facility", "severity", "mnemonic", "message"]
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
    },
    "Show Interface Transceiver": {
        "command": "show interface transceiver",
        "parser": CommandParser.parse_interface_transceiver,
        "headers": ["interface", "parameter", "value", "status"]
    },
    "Show Power Inline": {
        "command": "show power inline",
        "parser": CommandParser.parse_power_inline,
        "headers": ["interface", "admin", "oper", "power_draw", "device", "class"]
    },
    "Show Interface Counters Errors": {
        "command": "show interface counters errors",
        "parser": CommandParser.parse_interface_counters_errors,
        "headers": ["interface", "align_errors", "fcs_errors", "xmit_errors", "rcv_errors", "undersize", "oversize"]
    },
    "Show Interface Storm-Control": {
        "command": "show interface storm-control",
        "parser": CommandParser.parse_interface_storm_control,
        "headers": ["interface", "broadcast_level", "multicast_level", "unicast_level"]
    },
    "Show Authentication Sessions": {
        "command": "show authentication sessions",
        "parser": CommandParser.parse_authentication_sessions,
        "headers": ["interface", "mac", "method", "domain", "status", "session"]
    },
    "Show Port-Security": {
        "command": "show port-security",
        "parser": CommandParser.parse_port_security,
        "headers": ["interface", "max_addr", "current_addr", "security_violation", "action"]
    },
    "Show Interface Trunk": {
        "command": "show interface trunk",
        "parser": CommandParser.parse_interface_trunk,
        "headers": ["interface", "mode", "encapsulation", "status", "native_vlan", "allowed_vlans"]
    },
    "Show Spanning-Tree Blocked Ports": {
        "command": "show spanning-tree blockedports",
        "parser": CommandParser.parse_spanning_tree_blocked,
        "headers": ["interface", "vlan", "status", "cost", "priority"]
    },
    "Show FEX": {
        "command": "show fex",
        "parser": CommandParser.parse_show_fex,
        "headers": ["fex_id", "description", "state", "model", "serial"]
    }
}

# Add these constants at the end of the file
DEFAULT_DEVICE_TYPE = 'cisco_ios'
REQUIRED_CSV_HEADERS = ['hostname']  # IP address is no longer required 