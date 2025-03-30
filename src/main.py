"""
Main entry point for the IL2CPP Inspector application.
"""

import os
import sys
import logging
from typing import Optional
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from core.binary_parser import BinaryParser
from core.metadata_parser import MetadataParser
from core.memory_manager import MemoryManager
from gui.main_window import MainWindow

class Application:
    """Main application class."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.root = None
        self.main_window = None
        self.binary_parser = BinaryParser()
        self.metadata_parser = MetadataParser()
        self.memory_manager = MemoryManager()
        
    def initialize(self) -> bool:
        """Initialize the application.
        
        Returns:
            bool: True if initialization was successful
        """
        try:
            # Initialize logging
            self._setup_logging()
            
            # Initialize memory manager
            if not self.memory_manager.initialize():
                self.logger.error("Failed to initialize memory manager")
                return False
                
            # Initialize GUI
            self.root = tk.Tk()
            self.root.title("IL2CPP Inspector")
            self.root.geometry("1024x768")
            
            # Create main window
            self.main_window = MainWindow(
                self.root,
                self.binary_parser,
                self.metadata_parser,
                self.memory_manager
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error initializing application: {e}")
            return False
            
    def run(self) -> None:
        """Run the application."""
        try:
            if not self.initialize():
                messagebox.showerror(
                    "Error",
                    "Failed to initialize application"
                )
                return
                
            self.root.mainloop()
            
        except Exception as e:
            self.logger.error(f"Error running application: {e}")
            messagebox.showerror(
                "Error",
                f"Application error: {str(e)}"
            )
            
    def _setup_logging(self) -> None:
        """Setup logging configuration."""
        # Create logs directory if it doesn't exist
        if not os.path.exists('logs'):
            os.makedirs('logs')
            
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('logs/app.log'),
                logging.StreamHandler()
            ]
        )
        
def main():
    """Main entry point."""
    app = Application()
    app.run()
    
if __name__ == '__main__':
    main() 