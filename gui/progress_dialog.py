import tkinter as tk
from tkinter import ttk
from typing import Optional, Callable
import queue
import threading

class ProgressDialog(tk.Toplevel):
    def __init__(self, parent, title: str, maximum: int):
        super().__init__(parent)
        self.title(title)
        self.maximum = maximum
        self.current = 0
        self.message_queue = queue.Queue()
        self.after_id: Optional[str] = None
        
        # Make dialog modal
        self.transient(parent)
        self.grab_set()
        
        # Prevent closing with X button
        self.protocol("WM_DELETE_WINDOW", lambda: None)
        
        self.create_widgets()
        
        # Center the dialog
        self.geometry("400x300")
        self.resizable(False, False)
        
    def create_widgets(self):
        # Progress bar
        self.progress = ttk.Progressbar(
            self, 
            orient="horizontal", 
            length=350, 
            mode="determinate",
            maximum=self.maximum
        )
        self.progress.pack(pady=10, padx=10)
        
        # Status label
        self.status_label = ttk.Label(self, text="Initializing...")
        self.status_label.pack(pady=5)
        
        # Text widget for verbose output
        self.text = tk.Text(self, height=10, width=45)
        self.text.pack(pady=10, padx=10)
        
        # Scrollbar for text widget
        scrollbar = ttk.Scrollbar(self, command=self.text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.text.config(yscrollcommand=scrollbar.set)
        
    def update_progress(self, amount: int = 1):
        """Update progress bar"""
        self.current += amount
        self.progress["value"] = self.current
        
    def update_status(self, status: str):
        """Update status label"""
        self.status_label["text"] = status
        
    def add_message(self, message: str):
        """Add message to queue for processing"""
        self.message_queue.put(message)
        
    def process_messages(self):
        """Process any pending messages in the queue"""
        try:
            while True:
                message = self.message_queue.get_nowait()
                self.text.insert(tk.END, message + "\n")
                self.text.see(tk.END)
                self.message_queue.task_done()
        except queue.Empty:
            pass
        finally:
            self.after_id = self.after(100, self.process_messages)
            
    def start(self):
        """Start processing messages"""
        self.process_messages()
        
    def finish(self):
        """Clean up and close dialog"""
        if self.after_id:
            self.after_cancel(self.after_id)
        self.destroy() 