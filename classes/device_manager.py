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
            required_columns = ['hostname']  # Only hostname is required
            if not all(col in df.columns for col in required_columns):
                raise ValueError("CSV must contain 'hostname' column")

            for _, row in df.iterrows():
                # Get optional fields with default values
                ip = row.get('ip', None)
                model_id = row.get('model_id', None)

                device = Device(
                    hostname=row['hostname'],
                    ip=ip,
                    model_id=model_id
                )
                
                # Detect device type immediately and store it
                device._device_type = device.detect_device_type()
                print(f"Detected device type for {device.hostname}: {device._device_type}")
                
                self.devices[device.hostname] = device

        except Exception as e:
            print(f"Error loading CSV: {str(e)}")

    def export_command_output(self, hostname: str, command: str, output: str) -> None:
        """Export command output to a single CSV file for all devices"""
        # Use command name as filename (sanitized)
        safe_command = command.replace('|', '').replace('/', '_').strip()
        filename = f"command_output_{safe_command[:30]}.csv"
        
        os.makedirs('outputs', exist_ok=True)
        filepath = os.path.join('outputs', filename)
        
        # Write output to CSV with hostname column
        with open(filepath, 'a', newline='') as f:
            writer = csv.writer(f)
            if os.path.getsize(filepath) == 0:
                writer.writerow(['Hostname', 'Command', 'Output'])
            writer.writerow([hostname, command, output])

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
        """Export parsed command output to a single CSV file for all devices"""
        filename = f"{command_name.lower().replace(' ', '_')}_all_devices.csv"
        
        os.makedirs('outputs', exist_ok=True)
        filepath = os.path.join('outputs', filename)
        
        # Add hostname to each row of parsed data
        for row in parsed_data:
            row['hostname'] = hostname
        
        # Add hostname as first header
        all_headers = ['hostname'] + headers
        
        # Append to existing file or create new one
        file_exists = os.path.exists(filepath)
        with open(filepath, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=all_headers)
            if not file_exists:
                writer.writeheader()
            writer.writerows(parsed_data)