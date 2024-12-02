import tkinter as tk
from tkinter import ttk
from typing import Dict, Any

class DeviceDetailsWindow(tk.Toplevel):
    def __init__(self, parent, device, command_outputs: Dict[str, Any]):
        super().__init__(parent)
        self.device = device
        self.command_outputs = command_outputs
        
        # Window setup
        self.title(f"Device Details - {device.hostname}")
        self.geometry("800x600")
        
        self.create_widgets()
        
    def create_widgets(self):
        # Create notebook for tabbed interface
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Device Info Tab
        device_info_frame = ttk.Frame(notebook)
        notebook.add(device_info_frame, text="Device Info")
        self.create_device_info_tab(device_info_frame)
        
        # Interface Status Tab
        interface_frame = ttk.Frame(notebook)
        notebook.add(interface_frame, text="Interfaces")
        self.create_interface_tab(interface_frame)
        
        # VLAN Info Tab
        vlan_frame = ttk.Frame(notebook)
        notebook.add(vlan_frame, text="VLANs")
        self.create_vlan_tab(vlan_frame)
        
        # CDP Neighbors Tab
        cdp_frame = ttk.Frame(notebook)
        notebook.add(cdp_frame, text="CDP Neighbors")
        self.create_cdp_tab(cdp_frame)
        
        # Environment Tab
        env_frame = ttk.Frame(notebook)
        notebook.add(env_frame, text="Environment")
        self.create_environment_tab(env_frame)
        
        # Logs Tab
        logs_frame = ttk.Frame(notebook)
        notebook.add(logs_frame, text="Logs")
        self.create_logs_tab(logs_frame)

    def create_device_info_tab(self, parent):
        # Basic device information
        info_frame = ttk.LabelFrame(parent, text="Basic Information")
        info_frame.pack(fill=tk.X, padx=5, pady=5)
        
        labels = [
            ("Hostname:", self.device.hostname),
            ("IP Address:", self.device.ip or "N/A"),
            ("Model:", self.device.model_id or "Unknown"),
            ("Status:", "Connected" if self.device.connection_status else "Disconnected"),
            ("Online:", "Yes" if self.device.is_online else "No")
        ]
        
        for row, (label, value) in enumerate(labels):
            ttk.Label(info_frame, text=label).grid(row=row, column=0, padx=5, pady=2, sticky="e")
            ttk.Label(info_frame, text=value).grid(row=row, column=1, padx=5, pady=2, sticky="w")
            
        # Version information if available
        if "Show Version" in self.command_outputs:
            version_frame = ttk.LabelFrame(parent, text="Version Information")
            version_frame.pack(fill=tk.X, padx=5, pady=5)
            
            version_info = self.command_outputs["Show Version"]
            if isinstance(version_info, dict):
                for row, (key, value) in enumerate(version_info.items()):
                    ttk.Label(version_frame, text=f"{key.title()}:").grid(
                        row=row, column=0, padx=5, pady=2, sticky="e"
                    )
                    ttk.Label(version_frame, text=value).grid(
                        row=row, column=1, padx=5, pady=2, sticky="w"
                    )

    def create_interface_tab(self, parent):
        # Create treeview for interfaces
        tree = ttk.Treeview(parent, columns=["desc", "status", "vlan", "duplex", "speed", "type"])
        tree.heading("#0", text="Interface")
        tree.heading("desc", text="Description")
        tree.heading("status", text="Status")
        tree.heading("vlan", text="VLAN")
        tree.heading("duplex", text="Duplex")
        tree.heading("speed", text="Speed")
        tree.heading("type", text="Type")
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack widgets
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Populate interface data if available
        if "Show Interfaces Status" in self.command_outputs:
            for interface in self.command_outputs["Show Interfaces Status"]:
                tree.insert("", tk.END, text=interface["interface"],
                          values=(interface.get("description", ""),
                                interface.get("status", ""),
                                interface.get("vlan", ""),
                                interface.get("duplex", ""),
                                interface.get("speed", ""),
                                interface.get("type", "")))

    def create_vlan_tab(self, parent):
        # Similar structure to interface tab but for VLANs
        tree = ttk.Treeview(parent, columns=["name", "status"])
        tree.heading("#0", text="VLAN ID")
        tree.heading("name", text="Name")
        tree.heading("status", text="Status")
        
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        if "Show VLAN Brief" in self.command_outputs:
            for vlan in self.command_outputs["Show VLAN Brief"]:
                tree.insert("", tk.END, text=vlan["vlan_id"],
                          values=(vlan.get("name", ""),
                                vlan.get("status", "")))

    def create_cdp_tab(self, parent):
        tree = ttk.Treeview(parent, columns=["ip", "platform", "local_int", "remote_int"])
        tree.heading("#0", text="Device ID")
        tree.heading("ip", text="IP Address")
        tree.heading("platform", text="Platform")
        tree.heading("local_int", text="Local Interface")
        tree.heading("remote_int", text="Remote Interface")
        
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        if "Show CDP Neighbors Detail" in self.command_outputs:
            for neighbor in self.command_outputs["Show CDP Neighbors Detail"]:
                tree.insert("", tk.END, text=neighbor["device_id"],
                          values=(neighbor.get("ip_address", ""),
                                neighbor.get("platform", ""),
                                neighbor.get("local_interface", ""),
                                neighbor.get("remote_interface", "")))

    def create_environment_tab(self, parent):
        tree = ttk.Treeview(parent, columns=["section", "value", "status"])
        tree.heading("#0", text="Sensor")
        tree.heading("section", text="Section")
        tree.heading("value", text="Value")
        tree.heading("status", text="Status")
        
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        if "Show Environment" in self.command_outputs:
            for sensor in self.command_outputs["Show Environment"]:
                tree.insert("", tk.END, text=sensor["sensor"],
                          values=(sensor.get("section", ""),
                                sensor.get("value", ""),
                                sensor.get("status", "")))

    def create_logs_tab(self, parent):
        tree = ttk.Treeview(parent, columns=["facility", "severity", "message"])
        tree.heading("#0", text="Timestamp")
        tree.heading("facility", text="Facility")
        tree.heading("severity", text="Severity")
        tree.heading("message", text="Message")
        
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        if "Show Logging" in self.command_outputs:
            for log in self.command_outputs["Show Logging"]:
                tree.insert("", tk.END, text=log["timestamp"],
                          values=(log.get("facility", ""),
                                log.get("severity", ""),
                                log.get("message", ""))) 