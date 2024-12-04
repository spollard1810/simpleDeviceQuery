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
from gui.chain_dialog import ChainDialog

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
        command_frame = ttk.LabelFrame(self.root, text="Commands")
        command_frame.pack(fill=tk.X, padx=5, pady=5)

        # Left side for command selection
        command_select_frame = ttk.Frame(command_frame)
        command_select_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)

        # Command type selector
        type_frame = ttk.Frame(command_select_frame)
        type_frame.pack(fill=tk.X)
        
        ttk.Label(type_frame, text="Command Type:").pack(side=tk.LEFT, padx=5)
        self.command_type_var = tk.StringVar(value="Regular")
        self.command_type = ttk.Combobox(
            type_frame,
            textvariable=self.command_type_var,
            values=["Regular", "Chained"],
            state="readonly",
            width=10
        )
        self.command_type.pack(side=tk.LEFT, padx=5)
        self.command_type.bind('<<ComboboxSelected>>', self.on_command_type_changed)

        # Command selector
        command_frame = ttk.Frame(command_select_frame)
        command_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(command_frame, text="Command:").pack(side=tk.LEFT, padx=5)
        self.command_var = tk.StringVar()
        self.command_dropdown = ttk.Combobox(
            command_frame,
            textvariable=self.command_var,
            state="readonly",
            width=40
        )
        self.command_dropdown.pack(side=tk.LEFT, padx=5)
        self.command_dropdown.bind('<<ComboboxSelected>>', self.on_command_selected)

        # Custom command entry
        custom_frame = ttk.Frame(command_select_frame)
        custom_frame.pack(fill=tk.X)
        
        self.custom_label = ttk.Label(custom_frame, text="Custom Command:")
        self.custom_label.pack(side=tk.LEFT, padx=5)
        self.command_entry = ttk.Entry(custom_frame)
        self.command_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.command_entry.configure(state='disabled')

        # Execute button - now in its own frame at the bottom
        execute_frame = ttk.Frame(command_frame)
        execute_frame.pack(fill=tk.X, pady=5)
        
        self.execute_btn = ttk.Button(
            execute_frame,
            text="Execute Command",
            command=self.execute_selected_command,
            width=20
        )
        self.execute_btn.pack(side=tk.RIGHT, padx=5)

        # Initialize regular commands
        self.update_command_list()

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

    def on_command_type_changed(self, event=None):
        """Handle command type selection change"""
        self.update_command_list()
        self.command_entry.configure(state='disabled')
        self.command_entry.delete(0, tk.END)

    def update_command_list(self):
        """Update command dropdown based on selected type"""
        if self.command_type_var.get() == "Regular":
            commands = [cmd for cmd in COMMON_COMMANDS.keys() 
                       if not isinstance(COMMON_COMMANDS[cmd]["command"], list)]
            commands.append("Custom Command")
        else:
            commands = [cmd for cmd in COMMON_COMMANDS.keys() 
                       if isinstance(COMMON_COMMANDS[cmd]["command"], list)]

        self.command_dropdown['values'] = commands
        if commands:
            self.command_dropdown.set(commands[0])

    def on_command_selected(self, event=None):
        """Handle command selection"""
        if self.command_type_var.get() == "Regular" and self.command_var.get() == "Custom Command":
            self.command_entry.configure(state='normal')
        else:
            self.command_entry.configure(state='disabled')
            self.command_entry.delete(0, tk.END)

    def execute_selected_command(self):
        """Execute the selected command based on type"""
        if self.command_type_var.get() == "Regular":
            self.execute_command()
        else:
            self.execute_chained_command()

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

    def execute_chained_command(self):
        """Execute the selected chained command"""
        try:
            first_command = self.command_var.get()
            if not first_command:
                messagebox.showwarning("Warning", "Please select first command")
                return

            # Execute first command
            command_info = COMMON_COMMANDS[first_command]
            first_results = self.connection_manager.execute_command_on_devices(
                self.device_manager.get_selected_devices(),
                command_info["command"]
            )
            
            # Parse first results
            parsed_results = []
            for hostname, output in first_results.items():
                if not output.startswith("Error"):
                    parsed = command_info["parser"](output)
                    if isinstance(parsed, list):
                        parsed_results.extend(parsed)
            
            # Show chain dialog
            dialog = ChainDialog(self.root, COMMON_COMMANDS, parsed_results)
            self.root.wait_window(dialog)
            
            if dialog.result:
                # Execute chained command
                attr = dialog.result['attribute']
                second_command = dialog.result['command']
                
                results = self.connection_manager.execute_chained_commands(
                    devices=self.device_manager.get_selected_devices(),
                    first_command=command_info["command"],
                    first_parser=command_info["parser"],
                    second_command_generator=lambda x: f"{COMMON_COMMANDS[second_command]['command']} {x[attr]}",
                    second_parser=COMMON_COMMANDS[second_command]["parser"]
                )
                
                if results:
                    self.device_manager.export_parsed_output(
                        f"Chained_{first_command}_{second_command}",
                        "Chained Command Results",
                        results,
                        COMMON_COMMANDS[second_command]["headers"]
                    )
                    messagebox.showinfo("Success", "Chained command results exported")
                    
        except Exception as e:
            messagebox.showerror("Error", f"Failed to execute chained command: {str(e)}")
            print(f"Error details: {str(e)}")