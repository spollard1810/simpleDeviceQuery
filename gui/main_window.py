import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from classes.device_manager import DeviceManager
from classes.connection_manager import ConnectionManager
from classes.command_parser import CommandParser, COMMON_COMMANDS, CHAINABLE_COMMANDS
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

        # Regular command frame
        regular_frame = ttk.Frame(command_frame)
        regular_frame.pack(fill=tk.X, padx=5, pady=5)

        # Command selector
        ttk.Label(regular_frame, text="Command:").pack(side=tk.LEFT, padx=5)
        self.command_var = tk.StringVar()
        self.command_dropdown = ttk.Combobox(
            regular_frame,
            textvariable=self.command_var,
            values=[cmd for cmd in COMMON_COMMANDS.keys()],
            state="readonly",
            width=40
        )
        self.command_dropdown.pack(side=tk.LEFT, padx=5)
        self.command_dropdown.bind('<<ComboboxSelected>>', self.on_command_selected)

        # Custom command entry
        self.custom_label = ttk.Label(regular_frame, text="Custom Command:")
        self.custom_label.pack(side=tk.LEFT, padx=5)
        self.command_entry = ttk.Entry(regular_frame)
        self.command_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.command_entry.configure(state='disabled')

        # Button frame for execute options
        execute_frame = ttk.Frame(command_frame)
        execute_frame.pack(fill=tk.X, padx=5, pady=5)

        # Regular execute button
        self.execute_btn = ttk.Button(
            execute_frame,
            text="Execute Command",
            command=self.execute_command,
            width=20
        )
        self.execute_btn.pack(side=tk.LEFT, padx=5)

        # Chain command button
        self.chain_btn = ttk.Button(
            execute_frame,
            text="Chain Command",
            command=self.start_command_chain,
            width=20
        )
        self.chain_btn.pack(side=tk.RIGHT, padx=5)

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

    def on_command_selected(self, event=None):
        """Handle command selection"""
        if self.command_var.get() == "Custom Command":
            self.command_entry.configure(state='normal')
        else:
            self.command_entry.configure(state='disabled')
            self.command_entry.delete(0, tk.END)

    def execute_command(self):
        try:
            selected_command = self.command_var.get()
            if not selected_command:
                messagebox.showwarning("Warning", "Please select a command")
                return
            
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

            # Check if any devices are selected
            selected_devices = self.device_manager.get_selected_devices()
            if not selected_devices:
                messagebox.showwarning("Warning", "No devices selected")
                return

            # Execute commands and handle results
            results = self.connection_manager.execute_command_on_devices(
                selected_devices, 
                command
            )

            # Track if we successfully processed any results
            success_count = 0

            for hostname, output in results.items():
                if output.startswith("Error") or output.startswith("Skipped"):
                    print(f"Failed for {hostname}: {output}")
                    continue
                    
                try:
                    if parser:
                        parsed_data = parser(output)
                        if not isinstance(parsed_data, list):
                            parsed_data = [parsed_data]
                    else:
                        parsed_data = [{"output": output}]
                    
                    # Only export if we got valid parsed data
                    if parsed_data:
                        self.device_manager.export_parsed_output(
                            hostname, 
                            selected_command, 
                            parsed_data,
                            headers
                        )
                        success_count += 1
                except Exception as e:
                    print(f"Error parsing output for {hostname}: {str(e)}")

            # Show result message
            if success_count > 0:
                messagebox.showinfo("Success", f"Command executed successfully on {success_count} device(s)")
            else:
                messagebox.showwarning("Warning", "Command execution failed on all devices")

        except Exception as e:
            messagebox.showerror("Error", f"Command execution failed: {str(e)}")
            print(f"Error details: {str(e)}")

    def start_command_chain(self):
        """Start the command chaining process"""
        try:
            selected_command = self.command_var.get()
            if not selected_command:
                messagebox.showwarning("Warning", "Please select a command to chain")
                return

            # Execute first command
            command_info = COMMON_COMMANDS[selected_command]
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
            
            if not parsed_results:
                messagebox.showwarning("Warning", "No results to chain from first command")
                return

            # Show chain dialog
            dialog = ChainDialog(self.root, parsed_results)
            self.root.wait_window(dialog)
            
            if dialog.result:
                # Execute chained command
                attr = dialog.result['attribute']
                second_command = dialog.result['command']
                chainable_cmd = CHAINABLE_COMMANDS[second_command]
                
                # Build the second command using the chainable command format
                def generate_second_command(x):
                    value = x[attr]
                    if chainable_cmd["value_prefix"]:
                        value = f"{chainable_cmd['value_prefix']}{value}"
                    return f"{chainable_cmd['base_command']} {value}"
                
                results = self.connection_manager.execute_chained_commands(
                    devices=self.device_manager.get_selected_devices(),
                    first_command=command_info["command"],
                    first_parser=command_info["parser"],
                    second_command_generator=generate_second_command,
                    second_parser=chainable_cmd["parser"]
                )
                
                if results:
                    self.device_manager.export_parsed_output(
                        f"Chained_{selected_command}_{second_command}",
                        "Chained Command Results",
                        results,
                        CHAINABLE_COMMANDS[second_command]["headers"]
                    )
                    messagebox.showinfo("Success", "Chained command results exported")
                    
        except Exception as e:
            messagebox.showerror("Error", f"Failed to execute chained command: {str(e)}")
            print(f"Error details: {str(e)}")