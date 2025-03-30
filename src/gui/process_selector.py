"""
Process selector dialog module for the IL2CPP Inspector.
"""

import os
import logging
from typing import Dict, List, Optional
import tkinter as tk
from tkinter import ttk, messagebox
import psutil

class ProcessSelector(tk.Toplevel):
    """Dialog for selecting a process to attach to."""
    
    def __init__(self, parent: tk.Tk):
        super().__init__(parent)
        
        self.logger = logging.getLogger(__name__)
        self.selected_process = None
        
        self.title("Select Process")
        self.geometry("600x400")
        self.resizable(False, False)
        
        self._create_widgets()
        self._setup_layout()
        self._refresh_processes()
        
    def _create_widgets(self) -> None:
        """Create GUI widgets."""
        # Create main frame
        self.main_frame = ttk.Frame(self)
        
        # Create process list
        self.process_list = ttk.Treeview(
            self.main_frame,
            columns=("PID", "Name", "Path"),
            show="headings"
        )
        
        # Configure columns
        self.process_list.heading("PID", text="PID")
        self.process_list.heading("Name", text="Name")
        self.process_list.heading("Path", text="Path")
        
        # Set column widths
        self.process_list.column("PID", width=80)
        self.process_list.column("Name", width=150)
        self.process_list.column("Path", width=350)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(
            self.main_frame,
            orient=tk.VERTICAL,
            command=self.process_list.yview
        )
        self.process_list.configure(yscrollcommand=scrollbar.set)
        
        # Create buttons
        self.refresh_button = ttk.Button(
            self.main_frame,
            text="Refresh",
            command=self._refresh_processes
        )
        
        self.attach_button = ttk.Button(
            self.main_frame,
            text="Attach",
            command=self._attach_process
        )
        
        self.cancel_button = ttk.Button(
            self.main_frame,
            text="Cancel",
            command=self.destroy
        )
        
    def _setup_layout(self) -> None:
        """Setup widget layout."""
        # Pack main frame
        self.main_frame.pack(
            fill=tk.BOTH,
            expand=True,
            padx=5,
            pady=5
        )
        
        # Pack process list and scrollbar
        self.process_list.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True
        )
        scrollbar.pack(
            side=tk.RIGHT,
            fill=tk.Y
        )
        
        # Create button frame
        button_frame = ttk.Frame(self.main_frame)
        button_frame.pack(
            fill=tk.X,
            pady=5
        )
        
        # Pack buttons
        self.refresh_button.pack(
            side=tk.LEFT,
            padx=5
        )
        self.attach_button.pack(
            side=tk.RIGHT,
            padx=5
        )
        self.cancel_button.pack(
            side=tk.RIGHT,
            padx=5
        )
        
    def _refresh_processes(self) -> None:
        """Refresh process list."""
        try:
            # Clear existing items
            for item in self.process_list.get_children():
                self.process_list.delete(item)
                
            # Get processes
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    # Get process info
                    info = proc.info()
                    
                    # Skip processes without executable path
                    if not info['exe']:
                        continue
                        
                    # Add to list
                    self.process_list.insert(
                        "",
                        tk.END,
                        values=(
                            info['pid'],
                            info['name'],
                            info['exe']
                        )
                    )
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            self.logger.error(f"Error refreshing processes: {e}")
            messagebox.showerror(
                "Error",
                f"Failed to refresh processes: {str(e)}"
            )
            
    def _attach_process(self) -> None:
        """Attach to selected process."""
        try:
            # Get selected item
            selection = self.process_list.selection()
            if not selection:
                messagebox.showwarning(
                    "Warning",
                    "Please select a process"
                )
                return
                
            # Get process info
            values = self.process_list.item(selection[0])['values']
            pid = values[0]
            name = values[1]
            path = values[2]
            
            # Store selected process
            self.selected_process = {
                'pid': pid,
                'name': name,
                'path': path
            }
            
            # Close dialog
            self.destroy()
            
        except Exception as e:
            self.logger.error(f"Error attaching to process: {e}")
            messagebox.showerror(
                "Error",
                f"Failed to attach to process: {str(e)}"
            )
            
    def get_selected_process(self) -> Optional[Dict]:
        """Get selected process information.
        
        Returns:
            Optional[Dict]: Selected process information
        """
        return self.selected_process 