from dataclasses import dataclass
from typing import Optional
import re
from netmiko import ConnectHandler

@dataclass
class Device:
    hostname: str
    ip: str
    model_id: Optional[str] = None
    connection_status: bool = False
    _connection = None

    def detect_model(self, show_version_output: str) -> str:
        """Detect Cisco model from show version output"""
        # Basic regex pattern for Cisco model detection
        pattern = r"cisco\s+(\S+).*?processor"
        match = re.search(pattern, show_version_output, re.IGNORECASE)
        if match:
            return match.group(1)
        return "unknown"

    def connect(self, username: str, password: str) -> bool:
        """Establish SSH connection to device"""
        try:
            device_params = {
                'device_type': 'cisco_ios',  # Default to IOS, will be updated after model detection
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