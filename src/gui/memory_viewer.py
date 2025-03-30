"""
Memory viewer dialog module for the IL2CPP Inspector.
"""

import os
import logging
from typing import Dict, List, Optional
import tkinter as tk
from tkinter import ttk, messagebox

from core.memory_manager import MemoryManager

class MemoryViewer(tk.Toplevel):
    """Dialog for viewing and editing memory."""
    
    def __init__(self, parent: tk.Tk, memory_manager: MemoryManager):
        super().__init__(parent)
        
        self.logger = logging.getLogger(__name__)
        self.memory_manager = memory_manager
        
        self.title("Memory Viewer")
        self.geometry("800x600")
        self.resizable(True, True)
        
        self._create_widgets()
        self._setup_layout()
        
    def _create_widgets(self) -> None:
        """Create GUI widgets."""
        # Create main frame
        self.main_frame = ttk.Frame(self)
        
        # Create controls frame
        controls_frame = ttk.Frame(self.main_frame)
        
        # Add address entry
        ttk.Label(controls_frame, text="Address:").pack(side=tk.LEFT)
        self.address_entry = ttk.Entry(controls_frame, width=16)
        self.address_entry.pack(side=tk.LEFT, padx=5)
        
        # Add size entry
        ttk.Label(controls_frame, text="Size:").pack(side=tk.LEFT)
        self.size_entry = ttk.Entry(controls_frame, width=8)
        self.size_entry.pack(side=tk.LEFT, padx=5)
        
        # Add refresh button
        ttk.Button(
            controls_frame,
            text="Refresh",
            command=self._refresh_memory
        ).pack(side=tk.LEFT, padx=5)
        
        # Add edit button
        ttk.Button(
            controls_frame,
            text="Edit",
            command=self._edit_memory
        ).pack(side=tk.LEFT, padx=5)
        
        # Create memory view
        self.memory_text = tk.Text(
            self.main_frame,
            wrap=tk.NONE,
            font=("Courier", 10)
        )
        
        # Add scrollbars
        scrollbar_y = ttk.Scrollbar(
            self.main_frame,
            orient=tk.VERTICAL,
            command=self.memory_text.yview
        )
        scrollbar_x = ttk.Scrollbar(
            self.main_frame,
            orient=tk.HORIZONTAL,
            command=self.memory_text.xview
        )
        
        # Configure text widget
        self.memory_text.configure(
            yscrollcommand=scrollbar_y.set,
            xscrollcommand=scrollbar_x.set
        )
        
        # Create status bar
        self.status_bar = ttk.Label(
            self.main_frame,
            text="Ready",
            relief=tk.SUNKEN,
            anchor=tk.W
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
        
        # Pack controls frame
        controls_frame.pack(
            fill=tk.X,
            pady=5
        )
        
        # Pack memory view and scrollbars
        self.memory_text.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True
        )
        scrollbar_y.pack(
            side=tk.RIGHT,
            fill=tk.Y
        )
        scrollbar_x.pack(
            side=tk.BOTTOM,
            fill=tk.X
        )
        
        # Pack status bar
        self.status_bar.pack(
            fill=tk.X,
            side=tk.BOTTOM
        )
        
    def _refresh_memory(self) -> None:
        """Refresh memory view."""
        try:
            # Get address and size
            address = int(self.address_entry.get(), 16)
            size = int(self.size_entry.get())
            
            # Read memory
            data = self.memory_manager.read_memory(address, size)
            
            # Clear text widget
            self.memory_text.delete(1.0, tk.END)
            
            # Format and display memory
            for i in range(0, len(data), 16):
                # Address
                self.memory_text.insert(
                    tk.END,
                    f"{address + i:08x}  "
                )
                
                # Hex dump
                hex_dump = ""
                for j in range(16):
                    if i + j < len(data):
                        hex_dump += f"{data[i + j]:02x} "
                    else:
                        hex_dump += "   "
                self.memory_text.insert(tk.END, hex_dump)
                
                # ASCII dump
                ascii_dump = "  "
                for j in range(16):
                    if i + j < len(data):
                        byte = data[i + j]
                        if 32 <= byte <= 126:
                            ascii_dump += chr(byte)
                        else:
                            ascii_dump += "."
                    else:
                        ascii_dump += " "
                self.memory_text.insert(tk.END, ascii_dump + "\n")
                
            # Update status
            self.status_bar.config(
                text=f"Memory view refreshed at {hex(address)}"
            )
            
        except ValueError:
            messagebox.showerror(
                "Error",
                "Invalid address or size"
            )
        except Exception as e:
            self.logger.error(f"Error refreshing memory view: {e}")
            messagebox.showerror(
                "Error",
                f"Failed to refresh memory view: {str(e)}"
            )
            
    def _edit_memory(self) -> None:
        """Edit memory at current position."""
        try:
            # Get current position
            pos = self.memory_text.index(tk.INSERT)
            line = int(float(pos))
            
            # Get line content
            line_content = self.memory_text.get(f"{line}.0", f"{line}.end")
            
            # Parse address and hex values
            parts = line_content.split()
            if len(parts) < 18:  # Address + 16 bytes + ASCII
                return
                
            address = int(parts[0], 16)
            hex_values = parts[1:17]
            
            # Create edit dialog
            dialog = MemoryEditDialog(self, address, hex_values)
            if not dialog.result:
                return
                
            # Write new values
            new_data = bytes.fromhex("".join(dialog.result))
            self.memory_manager.write_memory(address, new_data)
            
            # Refresh view
            self._refresh_memory()
            
            # Update status
            self.status_bar.config(
                text=f"Memory edited at {hex(address)}"
            )
            
        except Exception as e:
            self.logger.error(f"Error editing memory: {e}")
            messagebox.showerror(
                "Error",
                f"Failed to edit memory: {str(e)}"
            )
            
class MemoryEditDialog(tk.Toplevel):
    """Dialog for editing memory values."""
    
    def __init__(
        self,
        parent: tk.Toplevel,
        address: int,
        hex_values: List[str]
    ):
        super().__init__(parent)
        
        self.result = None
        self.address = address
        self.hex_values = hex_values
        
        self.title(f"Edit Memory at {hex(address)}")
        self.geometry("400x200")
        self.resizable(False, False)
        
        self._create_widgets()
        self._setup_layout()
        
    def _create_widgets(self) -> None:
        """Create GUI widgets."""
        # Create main frame
        self.main_frame = ttk.Frame(self)
        
        # Create hex value entries
        self.entries = []
        for i in range(16):
            entry = ttk.Entry(
                self.main_frame,
                width=3,
                justify=tk.CENTER
            )
            entry.insert(0, self.hex_values[i])
            self.entries.append(entry)
            
        # Create buttons
        self.ok_button = ttk.Button(
            self.main_frame,
            text="OK",
            command=self._on_ok
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
        
        # Pack hex value entries
        for i, entry in enumerate(self.entries):
            entry.pack(
                side=tk.LEFT,
                padx=2
            )
            
        # Create button frame
        button_frame = ttk.Frame(self.main_frame)
        button_frame.pack(
            fill=tk.X,
            pady=5
        )
        
        # Pack buttons
        self.ok_button.pack(
            side=tk.RIGHT,
            padx=5
        )
        self.cancel_button.pack(
            side=tk.RIGHT,
            padx=5
        )
        
    def _on_ok(self) -> None:
        """Handle OK button click."""
        try:
            # Get hex values
            hex_values = []
            for entry in self.entries:
                value = entry.get().strip()
                if not value:
                    value = "00"
                hex_values.append(value.zfill(2))
                
            # Store result
            self.result = hex_values
            
            # Close dialog
            self.destroy()
            
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Invalid hex value: {str(e)}"
            ) 