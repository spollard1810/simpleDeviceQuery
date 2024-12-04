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

    def connect_devices(self, devices: List[Device], callback=None, progress_dialog=None) -> Dict[str, bool]:
        """Connect to multiple devices concurrently"""
        if not self.connection:
            raise ValueError("Credentials not set. Call set_credentials first.")

        results = {}
        online_devices = [device for device in devices if device.is_online]
        offline_devices = [device for device in devices if not device.is_online]

        # Log offline devices in progress dialog
        if progress_dialog:
            for device in offline_devices:
                progress_dialog.add_message(f"Skipping {device.hostname}: Device is offline")
                progress_dialog.update_progress()

        def connect_single_device(device: Device) -> tuple:
            if progress_dialog:
                progress_dialog.add_message(f"Connecting to {device.hostname}...")
            success = device.connect(self.connection.username, self.connection.password)
            if progress_dialog:
                status = "Success" if success else "Failed"
                progress_dialog.add_message(f"{device.hostname}: Connection {status}")
                progress_dialog.update_progress()
            return device.hostname, success

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_device = {
                executor.submit(connect_single_device, device): device 
                for device in online_devices  # Only attempt to connect to online devices
            }

            for future in as_completed(future_to_device):
                hostname, success = future.result()
                results[hostname] = success
                if callback:
                    callback()

        # Add offline devices to results with False status
        for device in offline_devices:
            results[device.hostname] = False

        return results

    def execute_command_on_devices(self, devices: List[Device], command: str, 
                                 callback=None) -> Dict[str, str]:
        """Execute command on multiple devices concurrently"""
        results = {}
        
        # Handle command lists (for commands that need multiple outputs)
        if isinstance(command, list):
            # Execute each command and combine outputs with a separator
            for device in devices:
                if device.is_online and device.connection_status:
                    try:
                        combined_output = []
                        for cmd in command:
                            output = device.execute_command(cmd)
                            if output:  # Only append if we got output
                                combined_output.append(output)
                            else:
                                print(f"Warning: No output for command '{cmd}' on {device.hostname}")
                        
                        if len(combined_output) == len(command):  # Only if we got all outputs
                            results[device.hostname] = "\n===COMMAND_SEPARATOR===\n".join(combined_output)
                        else:
                            results[device.hostname] = f"Error: Missing output for some commands"
                    except Exception as e:
                        results[device.hostname] = f"Error: {str(e)}"
                else:
                    status = "Offline" if not device.is_online else "Not Connected"
                    results[device.hostname] = f"Skipped: Device is {status}"
            return results

        # Filter out offline and disconnected devices
        available_devices = [
            device for device in devices 
            if device.is_online and device.connection_status
        ]
        
        skipped_devices = [
            device for device in devices 
            if not device.is_online or not device.connection_status
        ]

        # Add skipped devices to results
        for device in skipped_devices:
            status = "Offline" if not device.is_online else "Not Connected"
            results[device.hostname] = f"Skipped: Device is {status}"

        def execute_single_command(device: Device) -> tuple:
            try:
                output = device.execute_command(command)
                if callback:
                    callback()
                return device.hostname, output
            except Exception as e:
                return device.hostname, f"Error: {str(e)}"

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_device = {
                executor.submit(execute_single_command, device): device 
                for device in available_devices
            }

            for future in as_completed(future_to_device):
                hostname, output = future.result()
                results[hostname] = output

        return results

    def disconnect_all(self, devices: List[Device]) -> None:
        """Disconnect all devices"""
        for device in devices:
            if device.connection_status:
                device.disconnect()

    def execute_chained_commands(self, devices: List[Device], 
                               first_command: str,
                               first_parser: callable,
                               second_command_generator: callable,
                               second_parser: callable,
                               callback=None) -> List[Dict[str, str]]:
        """Execute a chain of commands where second command depends on first command's output
        
        Args:
            devices: List of devices to execute on
            first_command: Initial command to execute
            first_parser: Parser for first command output
            second_command_generator: Function that takes first command results and returns next command
            second_parser: Parser for second command output
            callback: Optional callback for progress updates
        
        Returns:
            List of combined results from both commands
        """
        all_results = []
        
        # Step 1: Execute first command on all devices
        first_results = self.execute_command_on_devices(devices, first_command)
        
        # Process each device's results
        for hostname, output in first_results.items():
            if output.startswith("Error") or output.startswith("Skipped"):
                continue
                
            try:
                # Parse first command output
                first_parsed = first_parser(output)
                
                # For each result from first command, generate and execute second command
                for item in first_parsed:
                    # Generate second command based on first results
                    second_command = second_command_generator(item)
                    
                    # Execute second command on this device
                    second_results = self.execute_command_on_devices(
                        [self.devices[hostname]], 
                        second_command
                    )
                    
                    if hostname in second_results:
                        second_output = second_results[hostname]
                        if not second_output.startswith("Error"):
                            # Parse second command output
                            second_parsed = second_parser(second_output)
                            
                            # Combine the results
                            combined_data = {
                                'device': hostname,
                                **item,  # Include data from first command
                                **second_parsed  # Include data from second command
                            }
                            all_results.append(combined_data)
                            
                            if callback:
                                callback()
                                
            except Exception as e:
                print(f"Error processing chain for {hostname}: {str(e)}")
                continue
                
        return all_results 