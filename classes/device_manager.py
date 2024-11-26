import pandas as pd
from typing import List, Dict
from .device import Device
import csv
import os
import asyncio
from concurrent.futures import ThreadPoolExecutor

class DeviceManager:
    def __init__(self):
        self.devices: Dict[str, Device] = {}  # hostname -> Device mapping
        self.selected_devices: set = set()    # Set of selected hostnames

    async def async_load_devices_from_csv(self, filepath: str, progress_callback=None) -> None:
        """Load devices from CSV file with async ping checks"""
        try:
            df = pd.read_csv(filepath)
            total_devices = len(df)
            loaded_devices = 0
            errors = []
            status_report = []  # List to store device status information

            if progress_callback:
                progress_callback("start", total_devices)

            # Clear existing devices
            self.devices.clear()

            # Create tasks for all devices
            tasks = []
            devices = []
            
            for index, row in df.iterrows():
                try:
                    if pd.isna(row['hostname']) or str(row['hostname']).strip() == '':
                        errors.append(f"Row {index + 2}: Empty hostname")
                        continue

                    hostname = str(row['hostname']).strip()
                    ip = str(row.get('ip', '')).strip() or None
                    model_id = str(row.get('model_id', '')).strip() or None

                    device = Device(
                        hostname=hostname,
                        ip=ip,
                        model_id=model_id
                    )
                    
                    if progress_callback:
                        progress_callback("update", f"Checking {hostname}...")
                    
                    devices.append(device)
                    tasks.append(device.async_ping())
                    
                except Exception as e:
                    errors.append(f"Row {index + 2}: {str(e)}")

            # Wait for all ping results
            results = await asyncio.gather(*tasks)
            
            # Process results and create status report
            for device, is_online in zip(devices, results):
                if is_online:
                    device._device_type = device.detect_device_type()
                self.devices[device.hostname] = device
                loaded_devices += 1
                
                # Add device status to report
                status_report.append({
                    'hostname': device.hostname,
                    'ip_address': device.ip or 'N/A',
                    'model': device.model_id or 'Unknown',
                    'status': 'Online' if is_online else 'Offline',
                    'device_type': device._device_type if is_online else 'N/A'
                })
                
                if progress_callback:
                    progress_callback("progress")

            # Export status report to CSV
            self._export_status_report(status_report, filepath)

            # Final status update
            if progress_callback:
                progress_callback("finish", f"Loaded {loaded_devices} of {total_devices} devices")

            if errors:
                error_msg = "\n".join(errors[:10])
                if len(errors) > 10:
                    error_msg += f"\n...and {len(errors) - 10} more errors"
                if progress_callback:
                    progress_callback("error", error_msg)

        except Exception as e:
            if progress_callback:
                progress_callback("error", f"Error loading CSV: {str(e)}")
            raise

    def _export_status_report(self, status_report: List[Dict[str, str]], source_filepath: str) -> None:
        """Export device status report to CSV"""
        # Create outputs directory if it doesn't exist
        os.makedirs('outputs', exist_ok=True)
        
        # Generate report filename based on source file
        source_filename = os.path.splitext(os.path.basename(source_filepath))[0]
        report_filename = f"{source_filename}_status_report.csv"
        report_filepath = os.path.join('outputs', report_filename)
        
        # Write report to CSV
        headers = ['hostname', 'ip_address', 'model', 'status', 'device_type']
        with open(report_filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(status_report)

    # For backward compatibility
    def load_devices_from_csv(self, filepath: str, progress_callback=None) -> None:
        """Synchronous wrapper for async_load_devices_from_csv"""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
        loop.run_until_complete(
            self.async_load_devices_from_csv(filepath, progress_callback)
        )

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