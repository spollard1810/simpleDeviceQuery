from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from .connection import Connection
from .device import Device

class ConnectionManager:
    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers
        self.connection: Optional[Connection] = None

    def set_credentials(self, username: str, password: str) -> None:
        """Set credentials for all connections"""
        self.connection = Connection(username=username, password=password)

    def connect_devices(self, devices: List[Device], callback=None) -> Dict[str, bool]:
        """Connect to multiple devices concurrently"""
        if not self.connection:
            raise ValueError("Credentials not set. Call set_credentials first.")

        results = {}

        def connect_single_device(device: Device) -> tuple:
            success = device.connect(self.connection.username, self.connection.password)
            return device.hostname, success

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_device = {
                executor.submit(connect_single_device, device): device 
                for device in devices
            }

            for future in as_completed(future_to_device):
                hostname, success = future.result()
                results[hostname] = success
                if callback:
                    callback()  # Update GUI if callback provided

        return results

    def execute_command_on_devices(self, devices: List[Device], command: str, 
                                 callback=None) -> Dict[str, str]:
        """Execute command on multiple devices concurrently"""
        results = {}

        def execute_single_command(device: Device) -> tuple:
            try:
                output = device.execute_command(command)
                return device.hostname, output
            except Exception as e:
                return device.hostname, f"Error: {str(e)}"

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_device = {
                executor.submit(execute_single_command, device): device 
                for device in devices if device.connection_status
            }

            for future in as_completed(future_to_device):
                hostname, output = future.result()
                results[hostname] = output
                if callback:
                    callback()  # Update GUI if callback provided

        return results

    def disconnect_all(self, devices: List[Device]) -> None:
        """Disconnect all devices"""
        for device in devices:
            if device.connection_status:
                device.disconnect() 