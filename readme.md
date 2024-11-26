# Device Query Maker

A Python-based GUI application for bulk querying Cisco network devices and collecting their outputs in CSV format.

## Installation

1. Install Python 3.x from [python.org](https://www.python.org/downloads/)
2. Download or clone this repository
3. Run the appropriate launcher for your platform:
   - Windows: Double-click `run.bat`
   - Linux/Mac: Open terminal and run `./run.sh`

The launcher will:
- Check for Python installation
- Install required dependencies
- Start the application

## Manual Installation

If you prefer to install manually:

1. Install Python 3.x
2. Open terminal/command prompt in project directory
3. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the application:
   ```bash
   python main.py
   ```

## Features

- GUI interface built with Tkinter
- Bulk device management and polling using Netmiko
- CSV-based device import and export
- Automated device online status checking
- Concurrent device connections
- Pre-configured Cisco commands with structured output parsing
- Custom command support
- Batch output files with device-specific prefixes

### Supported Commands

#### Interface Information
- Show Interfaces Status
- Show IP Interface Brief
- Show Interface Errors
- Show Interface Counters
- Show Interface Description

#### Layer 2 Information
- Show VLAN Brief
- Show MAC Address-Table
- Show Spanning Tree Status
- Show Port-Security Summary

#### Network Information
- Show CDP Neighbors Detail
- Show IP ARP

#### System Information
- Show Inventory
- Show Version
- Show Running Config
- Show Environment
- Show Logging
- Show Tech-Support

All commands support structured output parsing and CSV export, with the following features:
- Automatic error detection and handling
- Consistent CSV formatting
- Device-specific prefixing
- Batch processing support

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

All outputs are saved in the following directories:
- `outputs/`: Contains all CSV output files
  - Status reports: `{PREFIX}_devicelist_status_report.csv`
  - Command outputs: `{PREFIX}_command_name_all_devices.csv`
  - Custom command outputs: `{PREFIX}_command_output_{command}.csv`
- `logs/`: Contains device-specific command history
  - Command logs: `{hostname}_command_history.log`

Where `{PREFIX}` is automatically generated from the first device's hostname.

### Log Format
Each command execution is logged with:
- Timestamp
- Command executed
- Execution status
- Command output
- Any errors encountered


