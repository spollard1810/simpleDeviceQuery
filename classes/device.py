from dataclasses import dataclass
from typing import Optional, Dict
import re
from netmiko import ConnectHandler

@dataclass
class Device:
    hostname: str
    ip: str
    model_id: Optional[str] = None
    connection_status: bool = False
    _connection = None

    DEVICE_TYPE_MAPPING = {
        # Catalyst IOS/IOS-XE Switches
        r'[Ww][Ss]-?[Cc]': 'cisco_ios',        # WS-C3750, WS-C4500, etc.
        r'[Cc](?:3|4|6|9)\d{3}': 'cisco_ios',  # C3750, C3850, C9300, etc.
        
        # Nexus Switches
        r'[Nn][Xx]-': 'cisco_nxos',            # NX-5000, NX-7000, etc.
        r'[Nn]\d[Kk]': 'cisco_nxos',           # N5K, N7K, etc.
        r'[Nn][Xx]\d{4}': 'cisco_nxos',        # NX9400, etc.
        
        # ASR Routers
        r'[Aa][Ss][Rr]\d{4}': 'cisco_ios',     # ASR1000, ASR9000, etc.
        
        # ISR Routers
        r'[Ii][Ss][Rr]\d{4}': 'cisco_ios',     # ISR4000, etc.
        
        # Cisco IOS-XR
        r'[Nn][Cc][Ss]\d{4}': 'cisco_xr',      # NCS series
        r'[Aa][Ss][Rr]-?9[Kk]': 'cisco_xr',    # ASR9K series
        
        # Cisco SD-WAN
        r'[Vv][Ee][Dd][Gg][Ee]': 'cisco_ios',  # vEdge devices
        
        # Firepower / ASA
        r'[Ff][Pp][Rr]': 'cisco_ftd',          # Firepower
        r'[Aa][Ss][Aa]': 'cisco_asa',          # ASA devices
    }

    def detect_device_type(self, model: str = None) -> str:
        """Detect Netmiko device type based on model ID"""
        if not model and not self.model_id:
            return 'cisco_ios'  # Default to IOS if no model info available
        
        model_str = model or self.model_id
        model_str = model_str.strip()

        for pattern, device_type in self.DEVICE_TYPE_MAPPING.items():
            if re.search(pattern, model_str, re.IGNORECASE):
                return device_type
        
        return 'cisco_ios'  # Default to IOS if no match found

    def detect_model(self, show_version_output: str) -> str:
        """Detect Cisco model from show version output"""
        patterns = [
            r'cisco\s+(\S+(?:-\S+)*)\s+(?:chassis|processor|adaptive security appliance)',
            r'cisco\s+(\S+(?:-\S+)*)\s+(?:Series|Software)',
            r'Hardware:\s+(\S+(?:-\S+)*),',
            r'Model\s+number\s*:\s*(\S+(?:-\S+)*)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, show_version_output, re.IGNORECASE)
            if match:
                return match.group(1)
        return "unknown"

    def connect(self, username: str, password: str) -> bool:
        """Establish SSH connection to device"""
        try:
            device_type = self.detect_device_type()
            device_params = {
                'device_type': device_type,
                'ip': self.ip,
                'username': username,
                'password': password,
            }
            
            self._connection = ConnectHandler(**device_params)
            
            # Detect model if not provided
            if not self.model_id:
                show_version = self._connection.send_command("show version")
                self.model_id = self.detect_model(show_version)
            
            self.connection_status = True
            return True
            
        except Exception as e:
            print(f"Connection failed for {self.hostname}: {str(e)}")
            self.connection_status = False
            return False

    def disconnect(self) -> None:
        """Disconnect from device"""
        if self._connection:
            self._connection.disconnect()
            self.connection_status = False
            self._connection = None

    def execute_command(self, command: str) -> str:
        """Execute command on device and return output"""
        if not self.connection_status or not self._connection:
            raise ConnectionError(f"Device {self.hostname} is not connected")
        
        try:
            return self._connection.send_command(command)
        except Exception as e:
            print(f"Command execution failed on {self.hostname}: {str(e)}")
            return "" 