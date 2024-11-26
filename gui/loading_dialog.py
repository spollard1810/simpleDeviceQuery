import tkinter as tk
from tkinter import ttk
import queue
import threading

class LoadingDialog(tk.Toplevel):
    def __init__(self, parent, title: str):
        super().__init__(parent)
        self.title(title)
        self.message_queue = queue.Queue()
        self.after_id = None
        self.success = False
        
        # Make dialog modal
        self.transient(parent)
        self.grab_set()
        
        # Prevent closing with X button
        self.protocol("WM_DELETE_WINDOW", lambda: None)
        
        self.create_widgets()
        
        # Center the dialog
        self.geometry("400x200")
        self.resizable(False, False)
        
    def create_widgets(self):
        # Progress bar
        self.progress = ttk.Progressbar(
            self, 
            orient="horizontal",
            length=350,
            mode="determinate"
        )
        self.progress.pack(pady=20, padx=10)
        
        # Status label
        self.status_label = ttk.Label(self, text="Loading devices...")
        self.status_label.pack(pady=10)
        
        # Error display
        self.error_text = tk.Text(self, height=5, width=45)
        self.error_text.pack(pady=10, padx=10)
        self.error_text.pack_forget()  # Hidden by default
        
    def update(self, action: str, data=None):
        if action == "start":
            self.progress["maximum"] = data  # Set total number of devices
        elif action == "progress":
            self.progress["value"] += 1
        elif action == "update":
            self.status_label["text"] = data
        elif action == "error":
            self.error_text.pack(pady=10, padx=10)  # Show error text
            self.error_text.insert(tk.END, data)
            self.error_text.see(tk.END)
        elif action == "finish":
            self.status_label["text"] = data
            self.success = True
            self.after(2000, self.destroy)  # Close after 2 seconds 