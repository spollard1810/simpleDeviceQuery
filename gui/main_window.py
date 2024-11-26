import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from classes.device_manager import DeviceManager
from classes.connection_manager import ConnectionManager
from typing import Optional
import threading
from classes.command_parser import COMMON_COMMANDS
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

        # Device list
        self.device_list = ttk.Treeview(self.root, columns=("IP", "Model", "Status"))
        self.device_list.heading("#0", text="Hostname")
        self.device_list.heading("IP", text="IP")
        self.device_list.heading("Model", text="Model")
        self.device_list.heading("Status", text="Status")
        self.device_list.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Command frame
        command_frame = ttk.Frame(self.root)
        command_frame.pack(fill=tk.X, padx=5, pady=5)

        # Add "Custom Command" to the list of commands
        command_choices = list(COMMON_COMMANDS.keys()) + ["Custom Command"]
        
        # Command dropdown
        self.command_var = tk.StringVar()
        self.command_dropdown = ttk.Combobox(
            command_frame, 
            textvariable=self.command_var,
            values=command_choices,
            state="readonly"  # Make it readonly to prevent custom input
        )
        self.command_dropdown.pack(side=tk.LEFT, padx=5)
        self.command_dropdown.set("Show Interfaces Status")  # Default selection
        self.command_dropdown.bind('<<ComboboxSelected>>', self.on_command_selected)

        # Custom command entry
        ttk.Label(command_frame, text="Custom Command:").pack(side=tk.LEFT)
        self.command_entry = ttk.Entry(command_frame)
        self.command_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.command_entry.configure(state='disabled')  # Initially disabled

        # Execute button
        ttk.Button(command_frame, text="Execute", command=self.execute_command).pack(side=tk.LEFT)

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
        """Handle command selection change"""
        if self.command_var.get() == "Custom Command":
            self.command_entry.configure(state='normal')
            self.command_entry.focus()
        else:
            self.command_entry.configure(state='disabled')
            self.command_entry.delete(0, tk.END)

    def execute_command(self):
        try:
            selected_command = self.command_var.get()
            
            # Get selected devices that are online and connected
            selected_devices = self.device_manager.get_selected_devices()
            available_devices = [
                d for d in selected_devices 
                if d.is_online and d.connection_status
            ]
            
            if not available_devices:
                messagebox.showwarning(
                    "Warning", 
                    "No selected devices are both online and connected"
                )
                return
            
            # Handle custom command vs predefined command
            if selected_command == "Custom Command":
                command = self.command_entry.get().strip()
                if not command:
                    messagebox.showwarning("Warning", "Please enter a custom command")
                    return
                parser = None
                headers = ["hostname", "command", "output"]  # Added hostname
            else:
                if selected_command not in COMMON_COMMANDS:
                    messagebox.showwarning("Warning", f"Command '{selected_command}' not found in COMMON_COMMANDS")
                    return
                command_info = COMMON_COMMANDS[selected_command]
                command = command_info["command"]
                parser = command_info.get("parser")  # Use get() to handle missing parser
                headers = command_info.get("headers", ["hostname", "command", "output"])  # Default headers if missing

            progress = ProgressDialog(
                self.root,
                f"Executing {selected_command}",
                len(available_devices)
            )
            progress.update_status(f"Executing on {len(available_devices)} devices...")
            progress.start()

            def execute_thread():
                try:
                    results = self.connection_manager.execute_command_on_devices(
                        available_devices, 
                        command,
                        callback=lambda: progress.add_message("Command execution in progress...")
                    )

                    for hostname, output in results.items():
                        status = "ERROR" if isinstance(output, str) and ("Error:" in output or "Failed:" in output) else "SUCCESS"
                        
                        # Log the command execution
                        self.device_manager.log_command_execution(
                            hostname,
                            command,
                            output,
                            status
                        )

                        if status == "ERROR":
                            progress.add_message(f"Error on {hostname}: {output}")
                            continue
                        
                        try:
                            if parser:
                                parsed_data = parser(output)
                                if isinstance(parsed_data, (list, dict)):
                                    # Handle both list and dict outputs
                                    if isinstance(parsed_data, dict):
                                        parsed_data = [parsed_data]
                                    # Add hostname to each row
                                    for row in parsed_data:
                                        row['hostname'] = hostname
                                    self.device_manager.export_parsed_output(
                                        hostname, 
                                        selected_command, 
                                        parsed_data,
                                        headers
                                    )
                                else:
                                    raise ValueError("Parser output must be a list of dictionaries or a dictionary")
                            else:
                                # For custom commands or commands without parsers
                                self.device_manager.export_command_output(hostname, command, output)
                            progress.add_message(f"Successfully processed output from {hostname}")
                        except Exception as e:
                            error_msg = f"Failed to process output from {hostname}: {str(e)}"
                            progress.add_message(error_msg)
                            # Log parsing failure
                            self.device_manager.log_command_execution(
                                hostname,
                                command,
                                error_msg,
                                "PARSE_ERROR"
                            )
                    
                    self.root.after(0, lambda: messagebox.showinfo("Success", "Command execution completed"))
                except Exception as e:
                    error_msg = f"Command execution failed: {str(e)}"
                    self.root.after(0, lambda: messagebox.showerror("Error", error_msg))
                    # Log execution failure
                    for device in available_devices:
                        self.device_manager.log_command_execution(
                            device.hostname,
                            command,
                            error_msg,
                            "EXECUTION_ERROR"
                        )
                finally:
                    self.root.after(0, progress.finish)

            thread = threading.Thread(target=execute_thread)
            thread.start()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start command execution: {str(e)}")