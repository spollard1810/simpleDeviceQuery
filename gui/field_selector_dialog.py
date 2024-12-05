import tkinter as tk
from tkinter import ttk
from typing import List, Dict

class FieldSelectorDialog(tk.Toplevel):
    def __init__(self, parent, available_fields: List[str], sample_data: List[Dict]):
        super().__init__(parent)
        self.title("Select Fields to Export")
        self.available_fields = available_fields
        self.sample_data = sample_data
        self.selected_fields = []
        
        self.geometry("800x600")
        self.transient(parent)
        self.grab_set()
        
        self.create_widgets()
        
    def create_widgets(self):
        # Field selection frame
        select_frame = ttk.LabelFrame(self, text="Available Fields")
        select_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create checkboxes for each field
        self.field_vars = {}
        for field in self.available_fields:
            var = tk.BooleanVar(value=True)  # Default all selected
            self.field_vars[field] = var
            ttk.Checkbutton(
                select_frame, 
                text=field,
                variable=var,
                command=self.update_preview
            ).pack(anchor=tk.W, padx=5)
            
        # Preview frame
        preview_frame = ttk.LabelFrame(self, text="Data Preview")
        preview_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Preview tree
        self.preview_tree = ttk.Treeview(preview_frame)
        self.preview_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Button frame
        button_frame = ttk.Frame(self)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(
            button_frame, 
            text="Select All",
            command=self.select_all
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            button_frame, 
            text="Deselect All",
            command=self.deselect_all
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            button_frame,
            text="Export",
            command=self.on_export
        ).pack(side=tk.RIGHT, padx=5)
        
        ttk.Button(
            button_frame,
            text="Cancel",
            command=self.destroy
        ).pack(side=tk.RIGHT, padx=5)
        
        self.update_preview()
        
    def update_preview(self):
        """Update the preview with selected fields"""
        # Clear existing preview
        for item in self.preview_tree.get_children():
            self.preview_tree.delete(item)
            
        # Get selected fields
        selected_fields = [
            field for field, var in self.field_vars.items() 
            if var.get()
        ]
        
        # Configure columns
        self.preview_tree['columns'] = selected_fields
        for col in selected_fields:
            self.preview_tree.heading(col, text=col)
            self.preview_tree.column(col, width=100)
        
        # Add sample data (first 5 rows)
        for item in self.sample_data[:5]:
            values = [item.get(field, '') for field in selected_fields]
            self.preview_tree.insert('', 'end', values=values)
            
    def select_all(self):
        """Select all fields"""
        for var in self.field_vars.values():
            var.set(True)
        self.update_preview()
        
    def deselect_all(self):
        """Deselect all fields"""
        for var in self.field_vars.values():
            var.set(False)
        self.update_preview()
        
    def on_export(self):
        """Return selected fields"""
        self.selected_fields = [
            field for field, var in self.field_vars.items() 
            if var.get()
        ]
        self.destroy() 