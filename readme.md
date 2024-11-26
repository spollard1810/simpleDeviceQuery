# Device Query Maker

A Python-based GUI application for bulk querying Cisco network devices and collecting their outputs in CSV format.

## Features

- GUI interface built with Tkinter
- Bulk device management and polling using Netmiko
- CSV-based device import and export
- Automated device online status checking
- Concurrent device connections
- Pre-configured Cisco commands with structured output parsing
- Custom command support
- Batch output files with device-specific prefixes

## Application Structure

### Core Classes

- `Device`: Represents individual network devices
  - Properties: hostname, IP, model_ID, connection status, online status
  - Methods: connect, disconnect, execute_command, ping

- `DeviceManager`: Handles multiple device instances
  - CSV import/export with status reporting
  - Batch file naming with device prefixes
  - Device selection management
  - Parsed command output handling

- `CommandParser`: Parses Cisco command outputs
  - Structured parsing for common commands
  - CSV-friendly data formatting
  - Supported commands:
    - Show Interfaces Status
    - Show IP Interface Brief
    - Show VLAN Brief
    - Show MAC Address-Table
    - Show CDP Neighbors Detail
    - Show Inventory

- `ConnectionManager`: Orchestrates multiple connections
  - Concurrent connection handling
  - Command execution across multiple devices
  - Connection status tracking

### GUI Components

- `MainWindow`: Primary application interface
  - Device list with status indicators
  - Command selection dropdown
  - Custom command input
  - Bulk operation controls

- `LoadingDialog`: Device loading progress
  - Progress bar
  - Status updates
  - Error reporting

- `ProgressDialog`: Operation progress tracking
  - Real-time status updates
  - Detailed operation logging
  - Progress visualization

## Usage

1. Import devices using a CSV with required headers:
   - hostname (required)
   - ip (optional)
   - model_id (optional)

2. Application will:
   - Check online status of all devices
   - Generate a status report CSV
   - Display device status in the GUI

3. Select target devices and connect:
   - Enter credentials when prompted
   - View connection progress in real-time
   - Monitor connection status per device

4. Execute commands:
   - Choose from pre-configured commands
   - Enter custom commands as needed
   - Results automatically exported to CSV
   - Outputs prefixed with device batch identifier

## Requirements

- Python 3.x
- Required packages:
  - netmiko
  - tkinter
  - pandas
  - asyncio

## Output Files

All outputs are saved in the `outputs` directory:
- Status reports: `{PREFIX}_devicelist_status_report.csv`
- Command outputs: `{PREFIX}_command_name_all_devices.csv`
- Custom command outputs: `{PREFIX}_command_output_{command}.csv`

Where `{PREFIX}` is automatically generated from the first device's hostname.


