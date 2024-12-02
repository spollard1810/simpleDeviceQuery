import pandas as pd
from typing import List, Dict, Any
from .device import Device
import csv
import os
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import json
from classes.command_parser import COMMON_COMMANDS

class DeviceManager:
    def __init__(self):
        self.devices: Dict[str, Device] = {}  # hostname -> Device mapping
        self.selected_devices: set = set()    # Set of selected hostnames
        self.batch_prefix: str = ""           # Store the prefix for CSV files
        
        # Create necessary directories
        self._create_directories()

    def _create_directories(self) -> None:
        """Create necessary directories if they don't exist"""
        os.makedirs('outputs', exist_ok=True)
        os.makedirs('logs', exist_ok=True)

    def _set_batch_prefix(self, first_hostname: str) -> None:
        """Set the batch prefix from the first device hostname"""
        # Take first 3 characters, remove any non-alphanumeric chars, and convert to uppercase
        self.batch_prefix = ''.join(c for c in first_hostname[:3] if c.isalnum()).upper()
        if not self.batch_prefix:
            self.batch_prefix = "DEV"  # Default prefix if no valid characters found

    def _get_output_filename(self, base_filename: str) -> str:
        """Generate filename with batch prefix"""
        # Split the filename and extension
        name, ext = os.path.splitext(base_filename)
        # Add prefix to the filename
        return f"{self.batch_prefix}_{name}{ext}"

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

            # Set batch prefix from first valid hostname
            for _, row in df.iterrows():
                if not pd.isna(row['hostname']) and str(row['hostname']).strip():
                    self._set_batch_prefix(str(row['hostname']).strip())
                    break

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
        os.makedirs('outputs', exist_ok=True)
        
        # Generate report filename based on source file
        source_filename = os.path.splitext(os.path.basename(source_filepath))[0]
        report_filename = self._get_output_filename(f"{source_filename}_status_report.csv")
        report_filepath = os.path.join('outputs', report_filename)
        
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
        safe_command = command.replace('|', '').replace('/', '_').strip()
        filename = self._get_output_filename(f"command_output_{safe_command[:30]}.csv")
        
        os.makedirs('outputs', exist_ok=True)
        filepath = os.path.join('outputs', filename)
        
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
        filename = self._get_output_filename(f"{command_name.lower().replace(' ', '_')}_all_devices.csv")
        
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

    def _get_log_filename(self, hostname: str) -> str:
        """Generate log filename for a specific device"""
        return f"{hostname}_command_history.log"

    def log_command_execution(self, hostname: str, command: str, output: str, status: str = "SUCCESS") -> None:
        """Log command execution details to device-specific log file"""
        # Ensure logs directory exists (redundant but safe)
        os.makedirs('logs', exist_ok=True)
        log_file = os.path.join('logs', self._get_log_filename(hostname))
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(f"\n{'='*50}\n")
            f.write(f"Timestamp: {timestamp}\n")
            f.write(f"Status: {status}\n")
            f.write(f"Command: {command}\n")
            f.write(f"Output:\n{output}\n")
            f.write(f"{'='*50}\n")

    def get_device_outputs(self, hostname: str) -> Dict[str, Any]:
        """Get all command outputs for a device"""
        outputs = {}
        device_dir = os.path.join(self.output_dir, hostname)
        
        if not os.path.exists(device_dir):
            return outputs
        
        for command_name in COMMON_COMMANDS:
            command_file = os.path.join(device_dir, f"{command_name}.json")
            if os.path.exists(command_file):
                try:
                    with open(command_file, 'r') as f:
                        outputs[command_name] = json.load(f)
                except Exception as e:
                    print(f"Error loading output for {command_name}: {str(e)}")
                
        return outputs