"""
Type inspector dialog module for the IL2CPP Inspector.
"""

import os
import logging
from typing import Dict, List, Optional
import tkinter as tk
from tkinter import ttk, messagebox

from core.metadata_parser import MetadataParser
from core.memory_manager import MemoryManager

class TypeInspector(tk.Toplevel):
    """Dialog for inspecting IL2CPP types."""
    
    def __init__(
        self,
        parent: tk.Tk,
        metadata_parser: MetadataParser,
        memory_manager: MemoryManager
    ):
        super().__init__(parent)
        
        self.logger = logging.getLogger(__name__)
        self.metadata_parser = metadata_parser
        self.memory_manager = memory_manager
        
        self.title("Type Inspector")
        self.geometry("800x600")
        self.resizable(True, True)
        
        self._create_widgets()
        self._setup_layout()
        
    def _create_widgets(self) -> None:
        """Create GUI widgets."""
        # Create main frame
        self.main_frame = ttk.Frame(self)
        
        # Create type list
        self.type_list = ttk.Treeview(
            self.main_frame,
            columns=("Name", "Namespace", "Size", "Flags"),
            show="headings"
        )
        
        # Configure columns
        self.type_list.heading("Name", text="Name")
        self.type_list.heading("Namespace", text="Namespace")
        self.type_list.heading("Size", text="Size")
        self.type_list.heading("Flags", text="Flags")
        
        # Set column widths
        self.type_list.column("Name", width=200)
        self.type_list.column("Namespace", width=200)
        self.type_list.column("Size", width=80)
        self.type_list.column("Flags", width=80)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(
            self.main_frame,
            orient=tk.VERTICAL,
            command=self.type_list.yview
        )
        self.type_list.configure(yscrollcommand=scrollbar.set)
        
        # Create type info frame
        info_frame = ttk.LabelFrame(self.main_frame, text="Type Information")
        
        # Add fields list
        self.fields_list = ttk.Treeview(
            info_frame,
            columns=("Name", "Type", "Offset", "Size"),
            show="headings"
        )
        
        # Configure columns
        self.fields_list.heading("Name", text="Name")
        self.fields_list.heading("Type", text="Type")
        self.fields_list.heading("Offset", text="Offset")
        self.fields_list.heading("Size", text="Size")
        
        # Set column widths
        self.fields_list.column("Name", width=150)
        self.fields_list.column("Type", width=150)
        self.fields_list.column("Offset", width=80)
        self.fields_list.column("Size", width=80)
        
        # Add fields scrollbar
        fields_scrollbar = ttk.Scrollbar(
            info_frame,
            orient=tk.VERTICAL,
            command=self.fields_list.yview
        )
        self.fields_list.configure(yscrollcommand=fields_scrollbar.set)
        
        # Create buttons
        self.inspect_button = ttk.Button(
            info_frame,
            text="Inspect Instance",
            command=self._inspect_instance
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
        
        # Create paned window
        paned = ttk.PanedWindow(
            self.main_frame,
            orient=tk.HORIZONTAL
        )
        paned.pack(fill=tk.BOTH, expand=True)
        
        # Add type list frame
        list_frame = ttk.Frame(paned)
        paned.add(list_frame)
        
        # Pack type list and scrollbar
        self.type_list.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True
        )
        scrollbar.pack(
            side=tk.RIGHT,
            fill=tk.Y
        )
        
        # Add info frame
        info_frame = ttk.Frame(paned)
        paned.add(info_frame)
        
        # Pack fields list and scrollbar
        self.fields_list.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True
        )
        fields_scrollbar.pack(
            side=tk.RIGHT,
            fill=tk.Y
        )
        
        # Pack inspect button
        self.inspect_button.pack(
            fill=tk.X,
            pady=5
        )
        
        # Pack status bar
        self.status_bar.pack(
            fill=tk.X,
            side=tk.BOTTOM
        )
        
        # Bind type selection event
        self.type_list.bind(
            '<<TreeviewSelect>>',
            self._on_type_selected
        )
        
    def _on_type_selected(self, event) -> None:
        """Handle type selection."""
        try:
            # Get selected type
            selection = self.type_list.selection()
            if not selection:
                return
                
            # Get type index
            type_index = int(self.type_list.item(selection[0])['text'])
            
            # Get type definition
            type_def = self.metadata_parser.get_type_definition(type_index)
            if not type_def:
                return
                
            # Clear fields list
            for item in self.fields_list.get_children():
                self.fields_list.delete(item)
                
            # Add fields
            for field in type_def.get('fields', []):
                self.fields_list.insert(
                    "",
                    tk.END,
                    values=(
                        field['name'],
                        field['type'],
                        hex(field['offset']),
                        hex(field['size'])
                    )
                )
                
            # Update status
            self.status_bar.config(
                text=f"Selected type: {type_def['name']}"
            )
            
        except Exception as e:
            self.logger.error(f"Error handling type selection: {e}")
            messagebox.showerror(
                "Error",
                f"Failed to handle type selection: {str(e)}"
            )
            
    def _inspect_instance(self) -> None:
        """Show instance inspector dialog."""
        try:
            # Get selected type
            selection = self.type_list.selection()
            if not selection:
                messagebox.showwarning(
                    "Warning",
                    "Please select a type"
                )
                return
                
            # Get type index
            type_index = int(self.type_list.item(selection[0])['text'])
            
            # Get type definition
            type_def = self.metadata_parser.get_type_definition(type_index)
            if not type_def:
                return
                
            # Show instance inspector dialog
            dialog = InstanceInspectorDialog(
                self,
                type_def,
                self.memory_manager
            )
            
        except Exception as e:
            self.logger.error(f"Error showing instance inspector: {e}")
            messagebox.showerror(
                "Error",
                f"Failed to show instance inspector: {str(e)}"
            )
            
class InstanceInspectorDialog(tk.Toplevel):
    """Dialog for inspecting type instances."""
    
    def __init__(
        self,
        parent: tk.Toplevel,
        type_def: Dict,
        memory_manager: MemoryManager
    ):
        super().__init__(parent)
        
        self.logger = logging.getLogger(__name__)
        self.type_def = type_def
        self.memory_manager = memory_manager
        
        self.title(f"Inspect {type_def['name']}")
        self.geometry("600x400")
        self.resizable(True, True)
        
        self._create_widgets()
        self._setup_layout()
        
    def _create_widgets(self) -> None:
        """Create GUI widgets."""
        # Create main frame
        self.main_frame = ttk.Frame(self)
        
        # Create address entry
        address_frame = ttk.Frame(self.main_frame)
        ttk.Label(address_frame, text="Instance Address:").pack(side=tk.LEFT)
        self.address_entry = ttk.Entry(address_frame, width=16)
        self.address_entry.pack(side=tk.LEFT, padx=5)
        
        # Create refresh button
        ttk.Button(
            address_frame,
            text="Refresh",
            command=self._refresh_instance
        ).pack(side=tk.LEFT)
        
        # Create fields list
        self.fields_list = ttk.Treeview(
            self.main_frame,
            columns=("Name", "Value"),
            show="headings"
        )
        
        # Configure columns
        self.fields_list.heading("Name", text="Name")
        self.fields_list.heading("Value", text="Value")
        
        # Set column widths
        self.fields_list.column("Name", width=200)
        self.fields_list.column("Value", width=350)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(
            self.main_frame,
            orient=tk.VERTICAL,
            command=self.fields_list.yview
        )
        self.fields_list.configure(yscrollcommand=scrollbar.set)
        
        # Create edit button
        self.edit_button = ttk.Button(
            self.main_frame,
            text="Edit Field",
            command=self._edit_field
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
        
        # Pack address frame
        address_frame.pack(
            fill=tk.X,
            pady=5
        )
        
        # Pack fields list and scrollbar
        self.fields_list.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True
        )
        scrollbar.pack(
            side=tk.RIGHT,
            fill=tk.Y
        )
        
        # Pack edit button
        self.edit_button.pack(
            fill=tk.X,
            pady=5
        )
        
        # Pack status bar
        self.status_bar.pack(
            fill=tk.X,
            side=tk.BOTTOM
        )
        
    def _refresh_instance(self) -> None:
        """Refresh instance view."""
        try:
            # Get instance address
            address = int(self.address_entry.get(), 16)
            
            # Clear fields list
            for item in self.fields_list.get_children():
                self.fields_list.delete(item)
                
            # Read instance data
            data = self.memory_manager.read_memory(
                address,
                self.type_def['size']
            )
            
            # Add fields
            for field in self.type_def.get('fields', []):
                # Get field value
                field_data = data[field['offset']:field['offset'] + field['size']]
                value = self._format_field_value(field, field_data)
                
                self.fields_list.insert(
                    "",
                    tk.END,
                    values=(field['name'], value)
                )
                
            # Update status
            self.status_bar.config(
                text=f"Instance refreshed at {hex(address)}"
            )
            
        except ValueError:
            messagebox.showerror(
                "Error",
                "Invalid address"
            )
        except Exception as e:
            self.logger.error(f"Error refreshing instance: {e}")
            messagebox.showerror(
                "Error",
                f"Failed to refresh instance: {str(e)}"
            )
            
    def _edit_field(self) -> None:
        """Edit selected field."""
        try:
            # Get selected field
            selection = self.fields_list.selection()
            if not selection:
                messagebox.showwarning(
                    "Warning",
                    "Please select a field"
                )
                return
                
            # Get field info
            field_name = self.fields_list.item(selection[0])['values'][0]
            field_def = next(
                (f for f in self.type_def['fields'] if f['name'] == field_name),
                None
            )
            if not field_def:
                return
                
            # Show edit dialog
            dialog = FieldEditDialog(
                self,
                field_def,
                self.memory_manager
            )
            if not dialog.result:
                return
                
            # Refresh instance
            self._refresh_instance()
            
        except Exception as e:
            self.logger.error(f"Error editing field: {e}")
            messagebox.showerror(
                "Error",
                f"Failed to edit field: {str(e)}"
            )
            
    def _format_field_value(self, field: Dict, data: bytes) -> str:
        """Format field value for display.
        
        Args:
            field: Field definition
            data: Field data
            
        Returns:
            str: Formatted value
        """
        try:
            # Handle different field types
            if field['type'] == 'int32':
                return str(int.from_bytes(data, 'little'))
            elif field['type'] == 'uint32':
                return str(int.from_bytes(data, 'little'))
            elif field['type'] == 'int64':
                return str(int.from_bytes(data, 'little'))
            elif field['type'] == 'uint64':
                return str(int.from_bytes(data, 'little'))
            elif field['type'] == 'float':
                return str(struct.unpack('<f', data)[0])
            elif field['type'] == 'double':
                return str(struct.unpack('<d', data)[0])
            elif field['type'] == 'bool':
                return str(bool(data[0]))
            elif field['type'] == 'string':
                return data.decode('utf-8')
            else:
                return data.hex()
                
        except Exception as e:
            self.logger.error(f"Error formatting field value: {e}")
            return data.hex()
            
class FieldEditDialog(tk.Toplevel):
    """Dialog for editing field values."""
    
    def __init__(
        self,
        parent: tk.Toplevel,
        field: Dict,
        memory_manager: MemoryManager
    ):
        super().__init__(parent)
        
        self.logger = logging.getLogger(__name__)
        self.field = field
        self.memory_manager = memory_manager
        self.result = None
        
        self.title(f"Edit {field['name']}")
        self.geometry("400x150")
        self.resizable(False, False)
        
        self._create_widgets()
        self._setup_layout()
        
    def _create_widgets(self) -> None:
        """Create GUI widgets."""
        # Create main frame
        self.main_frame = ttk.Frame(self)
        
        # Create value entry
        ttk.Label(
            self.main_frame,
            text=f"Value ({self.field['type']}):"
        ).pack(pady=5)
        
        self.value_entry = ttk.Entry(self.main_frame)
        self.value_entry.pack(
            fill=tk.X,
            padx=5,
            pady=5
        )
        
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
            # Get value
            value = self.value_entry.get()
            
            # Convert value based on type
            if self.field['type'] == 'int32':
                data = int(value).to_bytes(4, 'little')
            elif self.field['type'] == 'uint32':
                data = int(value).to_bytes(4, 'little')
            elif self.field['type'] == 'int64':
                data = int(value).to_bytes(8, 'little')
            elif self.field['type'] == 'uint64':
                data = int(value).to_bytes(8, 'little')
            elif self.field['type'] == 'float':
                data = struct.pack('<f', float(value))
            elif self.field['type'] == 'double':
                data = struct.pack('<d', float(value))
            elif self.field['type'] == 'bool':
                data = bytes([bool(value)])
            elif self.field['type'] == 'string':
                data = value.encode('utf-8')
            else:
                data = bytes.fromhex(value)
                
            # Store result
            self.result = data
            
            # Close dialog
            self.destroy()
            
        except Exception as e:
            messagebox.showerror(
                "Error",
                f"Invalid value: {str(e)}"
            ) 