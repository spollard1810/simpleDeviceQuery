# Device Query Maker

A Python-based GUI application for bulk querying Cisco network devices and collecting their outputs in CSV format.

## Features

- GUI interface built with Tkinter
- Bulk device management and polling using Netmiko
- CSV-based device import and export
- Automated Cisco model detection and driver selection
- Concurrent device connections
- Bulk command execution with CSV output per device

## Application Structure

### Core Classes

- `Device`: Represents individual network devices
  - Properties: hostname, IP, model_ID, connection status
  - Methods: connect, disconnect, execute_command

- `DeviceManager`: Handles multiple device instances
  - CSV import/export
  - Bulk operations
  - Device filtering and selection

- `Connection`: Manages Netmiko SSH connections
  - Credential management
  - Connection retry logic
  - Model detection

- `ConnectionManager`: Orchestrates multiple connections
  - Concurrent connection handling
  - Connection pool management

### GUI Features

- Device list with select/deselect all functionality
- Connection status indicators
- Command input interface
- CSV export options
- Credential prompt dialog

## Usage

1. Import your devices using a CSV with headers:
   - hostname
   - ip
   - model_id (optional, auto-detected if not provided)

2. Select target devices from the list

3. Click Connect to establish SSH sessions
   - Enter credentials when prompted
   - Application will auto-detect device models

4. Execute commands across all selected devices
   - Results automatically exported to CSV
   - One CSV file per device with command outputs

## Requirements

- Python 3.x
- Netmiko
- tkinter
- pandas


