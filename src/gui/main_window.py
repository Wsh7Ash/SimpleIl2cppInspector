"""
Main window GUI module for the IL2CPP Inspector.
"""

import os
import logging
from typing import Optional
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from core.binary_parser import BinaryParser
from core.metadata_parser import MetadataParser
from core.memory_manager import MemoryManager

class MainWindow:
    """Main window class for the IL2CPP Inspector."""
    
    def __init__(
        self,
        root: tk.Tk,
        binary_parser: BinaryParser,
        metadata_parser: MetadataParser,
        memory_manager: MemoryManager
    ):
        self.logger = logging.getLogger(__name__)
        self.root = root
        self.binary_parser = binary_parser
        self.metadata_parser = metadata_parser
        self.memory_manager = memory_manager
        
        self._create_widgets()
        self._setup_layout()
        
    def _create_widgets(self) -> None:
        """Create GUI widgets."""
        # Create menu bar
        self.menu_bar = tk.Menu(self.root)
        self.root.config(menu=self.menu_bar)
        
        # File menu
        self.file_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="File", menu=self.file_menu)
        self.file_menu.add_command(label="Open Binary", command=self._open_binary)
        self.file_menu.add_command(label="Open Metadata", command=self._open_metadata)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Tools menu
        self.tools_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Tools", menu=self.tools_menu)
        self.tools_menu.add_command(label="Process Selector", command=self._show_process_selector)
        self.tools_menu.add_command(label="Memory Viewer", command=self._show_memory_viewer)
        self.tools_menu.add_command(label="Type Inspector", command=self._show_type_inspector)
        
        # Create main frame
        self.main_frame = ttk.Frame(self.root)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.main_frame)
        
        # Create tabs
        self.binary_tab = ttk.Frame(self.notebook)
        self.metadata_tab = ttk.Frame(self.notebook)
        self.memory_tab = ttk.Frame(self.notebook)
        
        # Add tabs to notebook
        self.notebook.add(self.binary_tab, text="Binary")
        self.notebook.add(self.metadata_tab, text="Metadata")
        self.notebook.add(self.memory_tab, text="Memory")
        
        # Create binary tab content
        self._create_binary_tab()
        
        # Create metadata tab content
        self._create_metadata_tab()
        
        # Create memory tab content
        self._create_memory_tab()
        
        # Create status bar
        self.status_bar = ttk.Label(
            self.root,
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
        
        # Pack notebook
        self.notebook.pack(
            fill=tk.BOTH,
            expand=True
        )
        
        # Pack status bar
        self.status_bar.pack(
            fill=tk.X,
            side=tk.BOTTOM
        )
        
    def _create_binary_tab(self) -> None:
        """Create binary tab content."""
        # Create treeview for sections
        self.sections_tree = ttk.Treeview(
            self.binary_tab,
            columns=("Address", "Size", "Characteristics"),
            show="headings"
        )
        
        # Configure columns
        self.sections_tree.heading("Address", text="Address")
        self.sections_tree.heading("Size", text="Size")
        self.sections_tree.heading("Characteristics", text="Characteristics")
        
        # Add scrollbar
        sections_scrollbar = ttk.Scrollbar(
            self.binary_tab,
            orient=tk.VERTICAL,
            command=self.sections_tree.yview
        )
        self.sections_tree.configure(yscrollcommand=sections_scrollbar.set)
        
        # Pack widgets
        self.sections_tree.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True
        )
        sections_scrollbar.pack(
            side=tk.RIGHT,
            fill=tk.Y
        )
        
    def _create_metadata_tab(self) -> None:
        """Create metadata tab content."""
        # Create treeview for types
        self.types_tree = ttk.Treeview(
            self.metadata_tab,
            columns=("Name", "Namespace", "Size", "Flags"),
            show="headings"
        )
        
        # Configure columns
        self.types_tree.heading("Name", text="Name")
        self.types_tree.heading("Namespace", text="Namespace")
        self.types_tree.heading("Size", text="Size")
        self.types_tree.heading("Flags", text="Flags")
        
        # Add scrollbar
        types_scrollbar = ttk.Scrollbar(
            self.metadata_tab,
            orient=tk.VERTICAL,
            command=self.types_tree.yview
        )
        self.types_tree.configure(yscrollcommand=types_scrollbar.set)
        
        # Pack widgets
        self.types_tree.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True
        )
        types_scrollbar.pack(
            side=tk.RIGHT,
            fill=tk.Y
        )
        
    def _create_memory_tab(self) -> None:
        """Create memory tab content."""
        # Create frame for controls
        controls_frame = ttk.Frame(self.memory_tab)
        controls_frame.pack(fill=tk.X, padx=5, pady=5)
        
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
            command=self._refresh_memory_view
        ).pack(side=tk.LEFT, padx=5)
        
        # Create text widget for memory view
        self.memory_text = tk.Text(
            self.memory_tab,
            wrap=tk.NONE,
            font=("Courier", 10)
        )
        
        # Add scrollbars
        memory_scrollbar_y = ttk.Scrollbar(
            self.memory_tab,
            orient=tk.VERTICAL,
            command=self.memory_text.yview
        )
        memory_scrollbar_x = ttk.Scrollbar(
            self.memory_tab,
            orient=tk.HORIZONTAL,
            command=self.memory_text.xview
        )
        
        # Configure text widget
        self.memory_text.configure(
            yscrollcommand=memory_scrollbar_y.set,
            xscrollcommand=memory_scrollbar_x.set
        )
        
        # Pack widgets
        self.memory_text.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True
        )
        memory_scrollbar_y.pack(
            side=tk.RIGHT,
            fill=tk.Y
        )
        memory_scrollbar_x.pack(
            side=tk.BOTTOM,
            fill=tk.X
        )
        
    def _open_binary(self) -> None:
        """Open binary file."""
        file_path = filedialog.askopenfilename(
            title="Open Binary File",
            filetypes=[
                ("Executable files", "*.exe"),
                ("All files", "*.*")
            ]
        )
        
        if file_path:
            try:
                if self.binary_parser.parse_binary(file_path):
                    self._update_binary_view()
                    self.status_bar.config(text=f"Loaded binary: {file_path}")
                else:
                    messagebox.showerror(
                        "Error",
                        "Failed to parse binary file"
                    )
            except Exception as e:
                self.logger.error(f"Error opening binary: {e}")
                messagebox.showerror(
                    "Error",
                    f"Failed to open binary: {str(e)}"
                )
                
    def _open_metadata(self) -> None:
        """Open metadata file."""
        file_path = filedialog.askopenfilename(
            title="Open Metadata File",
            filetypes=[
                ("Metadata files", "*.dat"),
                ("All files", "*.*")
            ]
        )
        
        if file_path:
            try:
                if self.metadata_parser.parse_metadata(file_path):
                    self._update_metadata_view()
                    self.status_bar.config(text=f"Loaded metadata: {file_path}")
                else:
                    messagebox.showerror(
                        "Error",
                        "Failed to parse metadata file"
                    )
            except Exception as e:
                self.logger.error(f"Error opening metadata: {e}")
                messagebox.showerror(
                    "Error",
                    f"Failed to open metadata: {str(e)}"
                )
                
    def _show_process_selector(self) -> None:
        """Show process selector dialog."""
        # Implementation will be added
        pass
        
    def _show_memory_viewer(self) -> None:
        """Show memory viewer dialog."""
        # Implementation will be added
        pass
        
    def _show_type_inspector(self) -> None:
        """Show type inspector dialog."""
        # Implementation will be added
        pass
        
    def _update_binary_view(self) -> None:
        """Update binary tab view."""
        # Clear existing items
        for item in self.sections_tree.get_children():
            self.sections_tree.delete(item)
            
        # Add sections
        for name, info in self.binary_parser.sections.items():
            self.sections_tree.insert(
                "",
                tk.END,
                values=(
                    hex(info['virtual_address']),
                    hex(info['size']),
                    hex(info['characteristics'])
                ),
                text=name
            )
            
    def _update_metadata_view(self) -> None:
        """Update metadata tab view."""
        # Clear existing items
        for item in self.types_tree.get_children():
            self.types_tree.delete(item)
            
        # Add types
        for index, info in self.metadata_parser.type_definitions.items():
            self.types_tree.insert(
                "",
                tk.END,
                values=(
                    info['name'],
                    info['namespace'],
                    hex(info['size']),
                    hex(info['flags'])
                ),
                text=str(index)
            )
            
    def _refresh_memory_view(self) -> None:
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