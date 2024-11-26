import pandas as pd
from typing import List, Dict
from .device import Device
import csv
import os

class DeviceManager:
    def __init__(self):
        self.devices: Dict[str, Device] = {}  # hostname -> Device mapping
        self.selected_devices: set = set()    # Set of selected hostnames

    def load_devices_from_csv(self, filepath: str) -> None:
        """Load devices from CSV file"""
        try:
            df = pd.read_csv(filepath)
            required_columns = ['hostname', 'ip']
            if not all(col in df.columns for col in required_columns):
                raise ValueError("CSV must contain 'hostname' and 'ip' columns")

            for _, row in df.iterrows():
                device = Device(
                    hostname=row['hostname'],
                    ip=row['ip'],
                    model_id=row.get('model_id', None)
                )
                self.devices[device.hostname] = device

        except Exception as e:
            print(f"Error loading CSV: {str(e)}")

    def export_command_output(self, hostname: str, command: str, output: str) -> None:
        """Export command output to CSV for a specific device"""
        filename = f"{hostname}_output.csv"
        
        # Create 'outputs' directory if it doesn't exist
        os.makedirs('outputs', exist_ok=True)
        filepath = os.path.join('outputs', filename)
        
        # Write output to CSV
        with open(filepath, 'a', newline='') as f:
            writer = csv.writer(f)
            if os.path.getsize(filepath) == 0:
                writer.writerow(['Command', 'Output'])
            writer.writerow([command, output])

    def select_all_devices(self) -> None:
        """Select all devices"""
        self.selected_devices = set(self.devices.keys())

    def deselect_all_devices(self) -> None:
        """Deselect all devices"""
        self.selected_devices.clear()

    def toggle_device_selection(self, hostname: str) -> None:
        """Toggle selection status of a device"""
        if hostname in self.selected_devices:
            self.selected_devices.remove(hostname)
        else:
            self.selected_devices.add(hostname)

    def get_selected_devices(self) -> List[Device]:
        """Return list of selected Device objects"""
        return [self.devices[hostname] for hostname in self.selected_devices] 

    def export_parsed_output(self, hostname: str, command_name: str, parsed_data: List[Dict[str, str]], 
                            headers: List[str]) -> None:
        """Export parsed command output to CSV"""
        filename = f"{hostname}_{command_name.lower().replace(' ', '_')}.csv"
        
        os.makedirs('outputs', exist_ok=True)
        filepath = os.path.join('outputs', filename)
        
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(parsed_data)