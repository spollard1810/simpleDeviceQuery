import tkinter as tk
from tkinter import ttk, messagebox
from typing import Dict, List
from classes.command_parser import CHAINABLE_COMMANDS
from classes.command_parser import CommandParser

class ChainDialog(tk.Toplevel):
    def __init__(self, parent, first_command_output: List[Dict]):
        super().__init__(parent)
        self.title("Chain Commands")
        self.first_output = first_command_output
        self.result = None
        
        self.geometry("800x600")
        self.transient(parent)
        self.grab_set()
        
        self.create_widgets()
        
    def create_widgets(self):
        # First output display
        output_frame = ttk.LabelFrame(self, text="Step 1: Review First Command Results")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Add scrollbar to treeview
        tree_frame = ttk.Frame(output_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        tree_scroll = ttk.Scrollbar(tree_frame)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.output_tree = ttk.Treeview(tree_frame, yscrollcommand=tree_scroll.set)
        self.output_tree.pack(fill=tk.BOTH, expand=True)
        tree_scroll.config(command=self.output_tree.yview)
        
        # Get columns from first result
        if self.first_output:
            columns = list(self.first_output[0].keys())
            self.output_tree['columns'] = columns
            
            # Configure columns
            self.output_tree.column('#0', width=0, stretch=tk.NO)  # Hide first column
            for col in columns:
                self.output_tree.heading(col, text=col)
                self.output_tree.column(col, width=100)  # Set default width
                
            # Add data
            for item in self.first_output:
                self.output_tree.insert('', 'end', values=[item.get(col, '') for col in columns])
        
        # Chain configuration
        chain_frame = ttk.LabelFrame(self, text="Step 2: Configure Command Chain")
        chain_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Select attribute to pass
        attr_frame = ttk.Frame(chain_frame)
        attr_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(attr_frame, text="Select field to use:").pack(side=tk.LEFT, padx=5)
        self.attr_var = tk.StringVar()
        if self.first_output:
            self.attr_combo = ttk.Combobox(
                attr_frame, 
                textvariable=self.attr_var,
                values=list(self.first_output[0].keys()),
                state='readonly',
                width=30
            )
            self.attr_combo.pack(side=tk.LEFT, padx=5)
            self.attr_combo.bind('<<ComboboxSelected>>', self.preview_selection)
            
        # Preview frame
        preview_frame = ttk.LabelFrame(chain_frame, text="Preview Selected Values")
        preview_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.preview_text = tk.Text(preview_frame, height=3, width=50)
        self.preview_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Command selection
        cmd_frame = ttk.Frame(chain_frame)
        cmd_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(cmd_frame, text="Select command to run:").pack(side=tk.LEFT, padx=5)
        self.command_var = tk.StringVar()
        self.command_combo = ttk.Combobox(
            cmd_frame,
            textvariable=self.command_var,
            values=list(CHAINABLE_COMMANDS.keys()),
            state='readonly',
            width=40
        )
        self.command_combo.pack(side=tk.LEFT, padx=5)
        
        # Add command description label
        self.desc_label = ttk.Label(cmd_frame, text="", wraplength=300)
        self.desc_label.pack(side=tk.LEFT, padx=5)
        
        # Show command description when selected
        self.command_combo.bind('<<ComboboxSelected>>', self.show_command_description)
        
        # Buttons
        button_frame = ttk.Frame(self)
        button_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(button_frame, text="Execute Chain", command=self.on_chain).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.destroy).pack(side=tk.RIGHT, padx=5)

    def preview_selection(self, event=None):
        """Show preview of selected values"""
        if not self.attr_var.get():
            return
            
        selected_field = self.attr_var.get()
        preview_values = [item[selected_field] for item in self.first_output[:5]]  # Show first 5
        
        self.preview_text.delete('1.0', tk.END)
        self.preview_text.insert('1.0', f"Selected field: {selected_field}\n")
        self.preview_text.insert(tk.END, f"Sample values: {', '.join(preview_values[:5])}\n")
        if len(preview_values) > 5:
            self.preview_text.insert(tk.END, f"... and {len(self.first_output) - 5} more")
        
    def on_chain(self):
        if not self.attr_var.get() or not self.command_var.get():
            messagebox.showwarning("Warning", "Please select both field and command")
            return
            
        self.result = {
            'attribute': self.attr_var.get(),
            'command': self.command_var.get()
        }
        self.destroy() 

    def show_command_description(self, event=None):
        """Show the description of the selected command"""
        selected = self.command_var.get()
        if selected in CHAINABLE_COMMANDS:
            self.desc_label.config(text=CHAINABLE_COMMANDS[selected]["description"]) 