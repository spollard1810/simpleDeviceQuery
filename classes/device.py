from dataclasses import dataclass
from typing import Optional, Dict
import re
from netmiko import ConnectHandler
import platform
import subprocess
import asyncio
from concurrent.futures import ThreadPoolExecutor
import socket

@dataclass
class Device:
    hostname: str
    ip: Optional[str] = None
    model_id: Optional[str] = None
    connection_status: bool = False
    _connection = None
    _device_type: Optional[str] = None
    is_online: bool = False
    PING_TIMEOUT = 1  # 1 second timeout for ping
    
    DEVICE_TYPE_MAPPING = {
        # Catalyst IOS-XE Switches
        r'[Cc]9[0-9]{3}': 'cisco_xe',           # C9200, C9300, C9400, C9500, C9600
        r'[Cc]3[89][0-9]{2}': 'cisco_xe',       # C3850, C3650, etc.
        r'[Cc]4[0-9]{3}': 'cisco_xe',           # C4500-X, etc.
        
        # Traditional IOS Switches
        r'[Ww][Ss]-[Cc]': 'cisco_ios',          # WS-C3750, WS-C4500, etc.
        r'[Cc]2[0-9]{3}': 'cisco_ios',          # C2960, C2950, etc.
        r'[Cc]3[0-7][0-9]{2}': 'cisco_ios',     # C3750, C3560, etc.
        
        # Nexus Switches
        r'[Nn][Xx]-': 'cisco_nxos',             # NX-5000, NX-7000, etc.
        r'[Nn]\d[Kk]': 'cisco_nxos',            # N5K, N7K, etc.
        r'[Nn][Xx]\d{4}': 'cisco_nxos',         # NX9400, etc.
        
        # ASR Routers
        r'[Aa][Ss][Rr]-?1[0-9]{3}': 'cisco_xe', # ASR1000 series (IOS-XE)
        r'[Aa][Ss][Rr]-?9[0-9]{3}': 'cisco_xr', # ASR9000 series (IOS-XR)
        
        # ISR Routers
        r'[Ii][Ss][Rr]4[0-9]{3}': 'cisco_xe',   # ISR4000 series (IOS-XE)
        r'[Ii][Ss][Rr][0-9]{4}': 'cisco_ios',   # Older ISR series
        
        # Cisco IOS-XR
        r'[Nn][Cc][Ss]\d{4}': 'cisco_xr',       # NCS series
        r'[Aa][Ss][Rr]-?9[Kk]': 'cisco_xr',     # ASR9K series
        
        # Cisco SD-WAN
        r'[Vv][Ee][Dd][Gg][Ee]': 'cisco_xe',    # vEdge devices (IOS-XE)
        
        # Firepower / ASA
        r'[Ff][Pp][Rr]': 'cisco_ftd',           # Firepower
        r'[Aa][Ss][Aa]': 'cisco_asa',           # ASA devices
    }

    def detect_device_type(self, model: str = None) -> str:
        """Detect Netmiko device type based on model ID"""
        if not model and not self.model_id:
            return 'cisco_xe'  # Default to IOS-XE for newer devices
        
        model_str = model or self.model_id
        model_str = model_str.strip()

        for pattern, device_type in self.DEVICE_TYPE_MAPPING.items():
            if re.search(pattern, model_str, re.IGNORECASE):
                return device_type
        
        # If no match found, try to make an educated guess based on model number
        if re.search(r'[Cc]9|[Cc]3[89]|[Ii][Ss][Rr]4', model_str):
            return 'cisco_xe'  # Newer platforms typically run IOS-XE
        
        return 'cisco_ios'  # Fall back to IOS for older/unknown devices

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
        """Connect to device with fallback mechanism"""
        try:
            # First attempt - try detected device type
            device_type = self.detect_device_type()
            device_params = {
                'device_type': device_type,
                'host': self.ip if self.ip else self.hostname,
                'username': username,
                'password': password,
            }
            
            try:
                self._connection = ConnectHandler(**device_params)
                self.connection_status = True
                return True
            except Exception as first_error:
                print(f"First connection attempt failed for {self.hostname} with {device_type}: {str(first_error)}")
                
                # If first attempt was with cisco_xe, try cisco_ios
                if device_type == 'cisco_xe':
                    try:
                        device_params['device_type'] = 'cisco_ios'
                        self._connection = ConnectHandler(**device_params)
                        self.connection_status = True
                        return True
                    except Exception as second_error:
                        print(f"Second connection attempt failed for {self.hostname} with cisco_ios: {str(second_error)}")
                
                # If first attempt was with cisco_ios, try cisco_xe
                elif device_type == 'cisco_ios':
                    try:
                        device_params['device_type'] = 'cisco_xe'
                        self._connection = ConnectHandler(**device_params)
                        self.connection_status = True
                        return True
                    except Exception as second_error:
                        print(f"Second connection attempt failed for {self.hostname} with cisco_xe: {str(second_error)}")
                
                # If both attempts failed or different device type, raise the original error
                raise first_error
                
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

    async def async_ping(self) -> bool:
        """Asynchronous ping with fast timeout"""
        try:
            # Get the host to ping (prefer IP if available)
            host = self.ip if self.ip else self.hostname
            
            # Create a socket connection with timeout
            loop = asyncio.get_event_loop()
            
            # Use ThreadPoolExecutor for the blocking socket operation
            with ThreadPoolExecutor() as pool:
                try:
                    result = await loop.run_in_executor(
                        pool,
                        self._check_host_port,
                        host,
                        22,  # Check SSH port
                        self.PING_TIMEOUT
                    )
                    self.is_online = result
                    return result
                except (socket.timeout, socket.error, ConnectionRefusedError):
                    # Try ICMP ping as fallback
                    result = await loop.run_in_executor(
                        pool,
                        self._icmp_ping,
                        host
                    )
                    self.is_online = result
                    return result
                    
        except Exception as e:
            print(f"Ping failed for {self.hostname}: {str(e)}")
            self.is_online = False
            return False

    def _check_host_port(self, host: str, port: int, timeout: float) -> bool:
        """Check if a host's port is open"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            return result == 0

    def _icmp_ping(self, host: str) -> bool:
        """Perform ICMP ping with timeout"""
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
            command = ['ping', param, '1', timeout_param, str(self.PING_TIMEOUT), host]
            
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.PING_TIMEOUT + 0.5  # Add small buffer to subprocess timeout
            )
            return result.returncode == 0
            
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            return False

    # For backward compatibility
    def ping(self) -> bool:
        """Synchronous wrapper for async_ping"""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        return loop.run_until_complete(self.async_ping()) 