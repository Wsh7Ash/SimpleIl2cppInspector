"""
Method inspector dialog module for the IL2CPP Inspector.
"""

import os
import logging
from typing import Dict, List, Optional
import tkinter as tk
from tkinter import ttk, messagebox

from core.metadata_parser import MetadataParser
from core.memory_manager import MemoryManager

class MethodInspector(tk.Toplevel):
    """Dialog for inspecting IL2CPP methods."""
    
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
        
        self.title("Method Inspector")
        self.geometry("800x600")
        self.resizable(True, True)
        
        self._create_widgets()
        self._setup_layout()
        
    def _create_widgets(self) -> None:
        """Create GUI widgets."""
        # Create main frame
        self.main_frame = ttk.Frame(self)
        
        # Create method list
        self.method_list = ttk.Treeview(
            self.main_frame,
            columns=("Name", "Return Type", "Parameters"),
            show="headings"
        )
        
        # Configure columns
        self.method_list.heading("Name", text="Name")
        self.method_list.heading("Return Type", text="Return Type")
        self.method_list.heading("Parameters", text="Parameters")
        
        # Set column widths
        self.method_list.column("Name", width=200)
        self.method_list.column("Return Type", width=100)
        self.method_list.column("Parameters", width=450)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(
            self.main_frame,
            orient=tk.VERTICAL,
            command=self.method_list.yview
        )
        self.method_list.configure(yscrollcommand=scrollbar.set)
        
        # Create method info frame
        info_frame = ttk.LabelFrame(self.main_frame, text="Method Information")
        
        # Add address entry
        address_frame = ttk.Frame(info_frame)
        ttk.Label(address_frame, text="Method Address:").pack(side=tk.LEFT)
        self.address_entry = ttk.Entry(address_frame, width=16)
        self.address_entry.pack(side=tk.LEFT, padx=5)
        
        # Add disassembly view
        self.disassembly_text = tk.Text(
            info_frame,
            wrap=tk.NONE,
            font=("Courier", 10)
        )
        
        # Add disassembly scrollbars
        disasm_scrollbar_y = ttk.Scrollbar(
            info_frame,
            orient=tk.VERTICAL,
            command=self.disassembly_text.yview
        )
        disasm_scrollbar_x = ttk.Scrollbar(
            info_frame,
            orient=tk.HORIZONTAL,
            command=self.disassembly_text.xview
        )
        
        # Configure disassembly text widget
        self.disassembly_text.configure(
            yscrollcommand=disasm_scrollbar_y.set,
            xscrollcommand=disasm_scrollbar_x.set
        )
        
        # Create buttons
        self.disassemble_button = ttk.Button(
            info_frame,
            text="Disassemble",
            command=self._disassemble_method
        )
        
        self.hook_button = ttk.Button(
            info_frame,
            text="Hook Method",
            command=self._hook_method
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
        
        # Add method list frame
        list_frame = ttk.Frame(paned)
        paned.add(list_frame)
        
        # Pack method list and scrollbar
        self.method_list.pack(
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
        
        # Pack address frame
        address_frame.pack(
            fill=tk.X,
            pady=5
        )
        
        # Pack disassembly view and scrollbars
        self.disassembly_text.pack(
            side=tk.LEFT,
            fill=tk.BOTH,
            expand=True
        )
        disasm_scrollbar_y.pack(
            side=tk.RIGHT,
            fill=tk.Y
        )
        disasm_scrollbar_x.pack(
            side=tk.BOTTOM,
            fill=tk.X
        )
        
        # Create button frame
        button_frame = ttk.Frame(info_frame)
        button_frame.pack(
            fill=tk.X,
            pady=5
        )
        
        # Pack buttons
        self.disassemble_button.pack(
            side=tk.LEFT,
            padx=5
        )
        self.hook_button.pack(
            side=tk.LEFT,
            padx=5
        )
        
        # Pack status bar
        self.status_bar.pack(
            fill=tk.X,
            side=tk.BOTTOM
        )
        
        # Bind method selection event
        self.method_list.bind(
            '<<TreeviewSelect>>',
            self._on_method_selected
        )
        
    def _on_method_selected(self, event) -> None:
        """Handle method selection."""
        try:
            # Get selected method
            selection = self.method_list.selection()
            if not selection:
                return
                
            # Get method index
            method_index = int(self.method_list.item(selection[0])['text'])
            
            # Get method definition
            method_def = self.metadata_parser.get_method_definition(method_index)
            if not method_def:
                return
                
            # Update status
            self.status_bar.config(
                text=f"Selected method: {method_def['name']}"
            )
            
        except Exception as e:
            self.logger.error(f"Error handling method selection: {e}")
            messagebox.showerror(
                "Error",
                f"Failed to handle method selection: {str(e)}"
            )
            
    def _disassemble_method(self) -> None:
        """Disassemble selected method."""
        try:
            # Get method address
            address = int(self.address_entry.get(), 16)
            
            # Get selected method
            selection = self.method_list.selection()
            if not selection:
                messagebox.showwarning(
                    "Warning",
                    "Please select a method"
                )
                return
                
            # Get method definition
            method_index = int(self.method_list.item(selection[0])['text'])
            method_def = self.metadata_parser.get_method_definition(method_index)
            if not method_def:
                return
                
            # Clear disassembly view
            self.disassembly_text.delete(1.0, tk.END)
            
            # Disassemble method
            instructions = self.memory_manager.disassemble(address, 1000)
            
            # Display instructions
            for insn in instructions:
                self.disassembly_text.insert(
                    tk.END,
                    f"{insn['address']:08x}  {insn['mnemonic']} {insn['op_str']}\n"
                )
                
            # Update status
            self.status_bar.config(
                text=f"Disassembled method at {hex(address)}"
            )
            
        except ValueError:
            messagebox.showerror(
                "Error",
                "Invalid address"
            )
        except Exception as e:
            self.logger.error(f"Error disassembling method: {e}")
            messagebox.showerror(
                "Error",
                f"Failed to disassemble method: {str(e)}"
            )
            
    def _hook_method(self) -> None:
        """Show method hook dialog."""
        try:
            # Get method address
            address = int(self.address_entry.get(), 16)
            
            # Get selected method
            selection = self.method_list.selection()
            if not selection:
                messagebox.showwarning(
                    "Warning",
                    "Please select a method"
                )
                return
                
            # Get method definition
            method_index = int(self.method_list.item(selection[0])['text'])
            method_def = self.metadata_parser.get_method_definition(method_index)
            if not method_def:
                return
                
            # Show hook dialog
            dialog = MethodHookDialog(
                self,
                method_def,
                address,
                self.memory_manager
            )
            
        except ValueError:
            messagebox.showerror(
                "Error",
                "Invalid address"
            )
        except Exception as e:
            self.logger.error(f"Error showing hook dialog: {e}")
            messagebox.showerror(
                "Error",
                f"Failed to show hook dialog: {str(e)}"
            )
            
class MethodHookDialog(tk.Toplevel):
    """Dialog for hooking methods."""
    
    def __init__(
        self,
        parent: tk.Toplevel,
        method_def: Dict,
        address: int,
        memory_manager: MemoryManager
    ):
        super().__init__(parent)
        
        self.logger = logging.getLogger(__name__)
        self.method_def = method_def
        self.address = address
        self.memory_manager = memory_manager
        
        self.title(f"Hook {method_def['name']}")
        self.geometry("600x400")
        self.resizable(True, True)
        
        self._create_widgets()
        self._setup_layout()
        
    def _create_widgets(self) -> None:
        """Create GUI widgets."""
        # Create main frame
        self.main_frame = ttk.Frame(self)
        
        # Create hook type selector
        hook_frame = ttk.Frame(self.main_frame)
        ttk.Label(hook_frame, text="Hook Type:").pack(side=tk.LEFT)
        self.hook_type = tk.StringVar(value="pre")
        ttk.Radiobutton(
            hook_frame,
            text="Pre-Hook",
            variable=self.hook_type,
            value="pre"
        ).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(
            hook_frame,
            text="Post-Hook",
            variable=self.hook_type,
            value="post"
        ).pack(side=tk.LEFT, padx=5)
        
        # Create hook code editor
        ttk.Label(
            self.main_frame,
            text="Hook Code (Assembly):"
        ).pack(pady=5)
        
        self.code_text = tk.Text(
            self.main_frame,
            wrap=tk.NONE,
            font=("Courier", 10)
        )
        
        # Add scrollbars
        scrollbar_y = ttk.Scrollbar(
            self.main_frame,
            orient=tk.VERTICAL,
            command=self.code_text.yview
        )
        scrollbar_x = ttk.Scrollbar(
            self.main_frame,
            orient=tk.HORIZONTAL,
            command=self.code_text.xview
        )
        
        # Configure text widget
        self.code_text.configure(
            yscrollcommand=scrollbar_y.set,
            xscrollcommand=scrollbar_x.set
        )
        
        # Create buttons
        self.apply_button = ttk.Button(
            self.main_frame,
            text="Apply Hook",
            command=self._apply_hook
        )
        
        self.cancel_button = ttk.Button(
            self.main_frame,
            text="Cancel",
            command=self.destroy
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
        
        # Pack hook frame
        hook_frame.pack(
            fill=tk.X,
            pady=5
        )
        
        # Pack code editor and scrollbars
        self.code_text.pack(
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
        
        # Create button frame
        button_frame = ttk.Frame(self.main_frame)
        button_frame.pack(
            fill=tk.X,
            pady=5
        )
        
        # Pack buttons
        self.apply_button.pack(
            side=tk.RIGHT,
            padx=5
        )
        self.cancel_button.pack(
            side=tk.RIGHT,
            padx=5
        )
        
        # Pack status bar
        self.status_bar.pack(
            fill=tk.X,
            side=tk.BOTTOM
        )
        
    def _apply_hook(self) -> None:
        """Apply method hook."""
        try:
            # Get hook code
            code = self.code_text.get(1.0, tk.END).strip()
            
            # Get hook type
            hook_type = self.hook_type.get()
            
            # Create hook
            if hook_type == "pre":
                # Create pre-hook
                if not self.memory_manager.patch_instruction(
                    self.address,
                    code
                ):
                    raise Exception("Failed to patch instruction")
            else:
                # Create post-hook
                # First, save original bytes
                original_bytes = self.memory_manager.read_memory(
                    self.address,
                    5  # Size of jump instruction
                )
                
                # Create jump to hook code
                if not self.memory_manager.patch_jump(
                    self.address,
                    self.address + len(code)
                ):
                    raise Exception("Failed to patch jump")
                    
                # Add hook code
                if not self.memory_manager.patch_instruction(
                    self.address + len(code),
                    code
                ):
                    raise Exception("Failed to patch hook code")
                    
                # Add jump back
                if not self.memory_manager.patch_jump(
                    self.address + len(code) + 5,
                    self.address + 5
                ):
                    raise Exception("Failed to patch return jump")
                    
            # Update status
            self.status_bar.config(
                text=f"Hook applied at {hex(self.address)}"
            )
            
            # Close dialog
            self.destroy()
            
        except Exception as e:
            self.logger.error(f"Error applying hook: {e}")
            messagebox.showerror(
                "Error",
                f"Failed to apply hook: {str(e)}"
            ) 