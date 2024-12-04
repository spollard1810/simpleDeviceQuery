import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from classes.device_manager import DeviceManager
from classes.connection_manager import ConnectionManager
from classes.command_parser import CommandParser, COMMON_COMMANDS
from classes.exceptions import CommandError, ConnectionError, ParserError
from typing import Optional, Dict, List
import threading
from gui.progress_dialog import ProgressDialog
from gui.loading_dialog import LoadingDialog

class CredentialsDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.username = tk.StringVar()
        self.password = tk.StringVar()
        self.result = None
        
        self.title("Enter Credentials")
        self.create_widgets()

    def create_widgets(self):
        # Username
        tk.Label(self, text="Username:").grid(row=0, column=0, padx=5, pady=5)
        tk.Entry(self, textvariable=self.username).grid(row=0, column=1, padx=5, pady=5)
        
        # Password
        tk.Label(self, text="Password:").grid(row=1, column=0, padx=5, pady=5)
        tk.Entry(self, textvariable=self.password, show="*").grid(row=1, column=1, padx=5, pady=5)
        
        # OK button
        tk.Button(self, text="OK", command=self.ok_clicked).grid(row=2, column=0, columnspan=2, pady=10)
        
        self.grab_set()  # Make the dialog modal
        
    def ok_clicked(self):
        self.result = (self.username.get(), self.password.get())
        self.destroy()

class MainWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("Device Query Maker")
        self.device_manager = DeviceManager()
        self.connection_manager = ConnectionManager()
        self.command_parser = CommandParser()
        self.credentials: Optional[tuple] = None
        
        self.create_widgets()

    def create_widgets(self):
        # Top frame for buttons
        button_frame = ttk.Frame(self.root)
        button_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Button(button_frame, text="Load Devices", command=self.load_devices).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Select All", command=self.select_all).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Deselect All", command=self.deselect_all).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Connect", command=self.connect_devices).pack(side=tk.LEFT, padx=5)

        # Command frame
        command_frame = ttk.Frame(self.root)
        command_frame.pack(fill=tk.X, padx=5, pady=5)

        # Left side: Regular commands
        self.left_frame = ttk.LabelFrame(command_frame, text="Regular Commands")
        self.left_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        # Regular command dropdown
        command_choices = [cmd for cmd in COMMON_COMMANDS.keys() 
                         if not isinstance(COMMON_COMMANDS[cmd]["command"], list)]
        command_choices.append("Custom Command")
        
        self.command_var = tk.StringVar()
        self.command_dropdown = ttk.Combobox(
            self.left_frame, 
            textvariable=self.command_var,
            values=command_choices,
            state="readonly",
            width=30
        )
        self.command_dropdown.pack(side=tk.LEFT, padx=5)
        self.command_dropdown.set("Show Interfaces Status")
        self.command_dropdown.bind('<<ComboboxSelected>>', self.on_regular_command_selected)

        # Custom command entry
        self.custom_label = ttk.Label(self.left_frame, text="Custom Command:")
        self.custom_label.pack(side=tk.LEFT)
        self.command_entry = ttk.Entry(self.left_frame)
        self.command_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.command_entry.configure(state='disabled')

        self.regular_execute_btn = ttk.Button(self.left_frame, text="Execute", command=self.execute_command)
        self.regular_execute_btn.pack(side=tk.LEFT, padx=5)

        # Right side: Chained commands
        self.right_frame = ttk.LabelFrame(command_frame, text="Chained Commands")
        self.right_frame.pack(side=tk.RIGHT, padx=5)

        # Chained commands dropdown
        chained_commands = [cmd for cmd in COMMON_COMMANDS.keys() 
                          if isinstance(COMMON_COMMANDS[cmd]["command"], list)]
        
        self.chained_command_var = tk.StringVar()
        self.chained_command_dropdown = ttk.Combobox(
            self.right_frame,
            textvariable=self.chained_command_var,
            values=chained_commands,
            state="readonly",
            width=30
        )
        self.chained_command_dropdown.pack(side=tk.LEFT, padx=5)
        if chained_commands:
            self.chained_command_dropdown.set(chained_commands[0])
        self.chained_command_dropdown.bind('<<ComboboxSelected>>', self.on_chained_command_selected)

        self.chain_execute_btn = ttk.Button(
            self.right_frame,
            text="Execute Chain",
            command=self.execute_chained_command
        )
        self.chain_execute_btn.pack(side=tk.LEFT, padx=5)

        # Device list
        self.device_list = ttk.Treeview(self.root, columns=("IP", "Model", "Status"))
        self.device_list.heading("#0", text="Hostname")
        self.device_list.heading("IP", text="IP")
        self.device_list.heading("Model", text="Model")
        self.device_list.heading("Status", text="Status")
        self.device_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def load_devices(self):
        filepath = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
        if not filepath:
            return

        loading_dialog = LoadingDialog(self.root, "Loading Devices")
        
        def load_thread():
            try:
                self.device_manager.load_devices_from_csv(
                    filepath,
                    progress_callback=lambda action, data=None: 
                        self.root.after(0, loading_dialog.update, action, data)
                )
                # Update device list after successful load
                self.root.after(0, self.update_device_list)
            except Exception as e:
                self.root.after(0, loading_dialog.update, "error", str(e))
            finally:
                if not loading_dialog.success:
                    self.root.after(2000, loading_dialog.destroy)

        thread = threading.Thread(target=load_thread)
        thread.start()

    def update_device_list(self):
        """Update the device list with current status"""
        self.device_list.delete(*self.device_list.get_children())
        for hostname, device in self.device_manager.devices.items():
            # Set status based on connection and online state
            if device.connection_status:
                status = "Connected"
            elif not device.is_online:
                status = "Offline"
            else:
                status = "Disconnected"
            
            # Update the treeview with device information
            ip_address = device.ip or "N/A"
            model = device.model_id or "Unknown"
            self.device_list.insert("", tk.END, text=hostname, 
                                  values=(ip_address, model, status),
                                  tags=('offline',) if not device.is_online else ())

        # Optional: Add color coding for offline devices
        self.device_list.tag_configure('offline', foreground='red')

    def select_all(self):
        self.device_manager.select_all_devices()
        for item in self.device_list.get_children():
            self.device_list.selection_add(item)

    def deselect_all(self):
        self.device_manager.deselect_all_devices()
        self.device_list.selection_remove(*self.device_list.get_children())

    def get_credentials(self):
        dialog = CredentialsDialog(self.root)
        self.root.wait_window(dialog)
        return dialog.result

    def connect_devices(self):
        if not self.credentials:
            self.credentials = self.get_credentials()
            if not self.credentials:
                return

        username, password = self.credentials
        self.connection_manager.set_credentials(username, password)
        
        selected_items = self.device_list.selection()
        selected_devices = [
            self.device_manager.devices[self.device_list.item(item)["text"]]
            for item in selected_items
        ]
        
        if not selected_devices:
            messagebox.showwarning("Warning", "No devices selected")
            return
        
        # Check if any selected devices are online
        online_devices = [d for d in selected_devices if d.is_online]
        if not online_devices:
            messagebox.showwarning("Warning", "None of the selected devices are online")
            return
        
        progress = ProgressDialog(
            self.root,
            "Connecting to Devices",
            len(selected_devices)  # Keep total count for progress bar
        )
        progress.update_status(f"Connecting to {len(online_devices)} devices...")
        progress.start()
        
        def connect_thread():
            try:
                self.connection_manager.connect_devices(
                    selected_devices,
                    callback=lambda: self.root.after(0, self.update_device_list),
                    progress_dialog=progress
                )
            finally:
                self.root.after(0, progress.finish)

        thread = threading.Thread(target=connect_thread)
        thread.start()

    def on_regular_command_selected(self, event=None):
        """Handle regular command selection"""
        # Disable chained commands section
        self.chained_command_dropdown.configure(state='disabled')
        self.chain_execute_btn.configure(state='disabled')
        
        # Enable regular commands section
        self.command_dropdown.configure(state='readonly')
        self.regular_execute_btn.configure(state='normal')
        
        # Handle custom command entry
        if self.command_var.get() == "Custom Command":
            self.command_entry.configure(state='normal')
        else:
            self.command_entry.configure(state='disabled')

    def on_chained_command_selected(self, event=None):
        """Handle chained command selection"""
        # Disable regular commands section
        self.command_dropdown.configure(state='disabled')
        self.command_entry.configure(state='disabled')
        self.regular_execute_btn.configure(state='disabled')
        
        # Enable chained commands section
        self.chained_command_dropdown.configure(state='readonly')
        self.chain_execute_btn.configure(state='normal')

    def execute_command(self):
        try:
            selected_command = self.command_var.get()
            
            # Get command info
            if selected_command == "Custom Command":
                command = self.command_entry.get().strip()
                if not command:
                    messagebox.showwarning("Warning", "Please enter a custom command")
                    return
                parser = None
                headers = ["hostname", "command", "output"]
            else:
                command_info = COMMON_COMMANDS[selected_command]
                command = command_info["command"]
                parser = command_info.get("parser")
                headers = command_info.get("headers", ["hostname", "command", "output"])

            # Execute commands and handle results
            results = self.connection_manager.execute_command_on_devices(
                self.device_manager.get_selected_devices(), 
                command
            )

            for hostname, output in results.items():
                if output.startswith("Error") or output.startswith("Skipped"):
                    continue
                    
                try:
                    # For multi-command outputs, the parser will handle splitting and combining
                    parsed_data = parser(output) if parser else [{"output": output}]
                    
                    # Only export if we got valid parsed data
                    if parsed_data:
                        self.device_manager.export_parsed_output(
                            hostname, 
                            selected_command, 
                            parsed_data,
                            headers
                        )
                except Exception as e:
                    print(f"Error parsing output for {hostname}: {str(e)}")

        except Exception as e:
            messagebox.showerror("Error", f"Command execution failed: {str(e)}")

    def get_cdp_interface_details(self):
        """Get interface details for all CDP neighbors using chained commands"""
        try:
            # Define command chain
            def generate_interface_command(cdp_data: Dict[str, str]) -> str:
                return f"show interface {cdp_data['interface']}"
            
            # Execute chained commands
            results = self.connection_manager.execute_chained_commands(
                devices=self.device_manager.get_selected_devices(),
                first_command="show cdp neighbors detail",
                first_parser=self.command_parser.parse_cdp_neighbors,
                second_command_generator=generate_interface_command,
                second_parser=self.command_parser.parse_single_interface
            )
            
            # Export results
            if results:
                headers = ['device', 'interface', 'neighbor', 'platform', 'speed', 
                          'duplex', 'status', 'input_rate', 'output_rate']
                self.device_manager.export_parsed_output(
                    "CDP_Interfaces",
                    "CDP Interface Details",
                    results,
                    headers
                )
                messagebox.showinfo("Success", "CDP interface details have been exported")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get interface details: {str(e)}")

    def execute_chained_command(self):
        """Execute the selected chained command"""
        selected_command = self.chained_command_var.get()
        if selected_command == "CDP Interface Details":
            self.get_cdp_interface_details()
        # Add other chained commands here as elif statements