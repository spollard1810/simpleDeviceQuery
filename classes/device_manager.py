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
            # Read CSV file
            df = pd.read_csv(filepath)
            
            # Verify required columns
            required_columns = ['hostname']
            if not all(col in df.columns for col in required_columns):
                raise ValueError("CSV must contain 'hostname' column")

            # Count total devices before loading
            total_devices = len(df)
            loaded_devices = 0
            errors = []

            # Clear existing devices
            self.devices.clear()

            for index, row in df.iterrows():
                try:
                    # Skip empty rows
                    if pd.isna(row['hostname']) or str(row['hostname']).strip() == '':
                        errors.append(f"Row {index + 2}: Empty hostname")
                        continue

                    # Clean hostname
                    hostname = str(row['hostname']).strip()
                    
                    # Get optional fields with default values
                    ip = str(row.get('ip', '')).strip() or None
                    model_id = str(row.get('model_id', '')).strip() or None

                    device = Device(
                        hostname=hostname,
                        ip=ip,
                        model_id=model_id
                    )
                    
                    # Detect device type immediately and store it
                    device._device_type = device.detect_device_type()
                    print(f"Detected device type for {device.hostname}: {device._device_type}")
                    
                    self.devices[device.hostname] = device
                    loaded_devices += 1

                except Exception as e:
                    errors.append(f"Row {index + 2}: {str(e)}")

            # Print summary
            print(f"\nDevice Loading Summary:")
            print(f"Total devices in CSV: {total_devices}")
            print(f"Successfully loaded: {loaded_devices}")
            print(f"Failed to load: {total_devices - loaded_devices}")
            
            if errors:
                print("\nErrors encountered:")
                for error in errors[:10]:  # Show first 10 errors
                    print(error)
                if len(errors) > 10:
                    print(f"...and {len(errors) - 10} more errors")

            if loaded_devices == 0:
                raise ValueError("No devices were successfully loaded from the CSV file")

        except Exception as e:
            print(f"Error loading CSV: {str(e)}")
            raise

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