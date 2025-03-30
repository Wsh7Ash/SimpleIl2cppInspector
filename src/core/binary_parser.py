"""
Binary parser module for handling PE and ELF binaries.
"""

import os
import struct
import logging
from typing import Dict, List, Optional, Tuple, Union
from elftools.elf.elffile import ELFFile
import pefile

class BinaryParser:
    """Parser for PE and ELF binaries."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.binary_type = None
        self.sections = {}
        self.symbols = {}
        self.imports = {}
        
    def parse_binary(self, file_path: str) -> bool:
        """Parse a binary file and determine its type.
        
        Args:
            file_path: Path to the binary file
            
        Returns:
            bool: True if parsing was successful
        """
        try:
            with open(file_path, 'rb') as f:
                # Read file header
                header = f.read(4)
                
                # Check for PE signature
                if header.startswith(b'MZ'):
                    self.binary_type = 'PE'
                    return self._parse_pe(f)
                # Check for ELF signature
                elif header.startswith(b'\x7fELF'):
                    self.binary_type = 'ELF'
                    return self._parse_elf(f)
                else:
                    self.logger.error(f"Unknown binary format: {file_path}")
                    return False
                    
        except Exception as e:
            self.logger.error(f"Error parsing binary: {e}")
            return False
            
    def _parse_pe(self, file: 'BinaryIO') -> bool:
        """Parse PE binary format.
        
        Args:
            file: File object opened in binary mode
            
        Returns:
            bool: True if parsing was successful
        """
        try:
            # Skip DOS header
            file.seek(0x3C)
            pe_offset = struct.unpack('<I', file.read(4))[0]
            file.seek(pe_offset)
            
            # Read PE signature
            if file.read(4) != b'PE\x00\x00':
                return False
                
            # Read file header
            file_header = file.read(20)
            num_sections = struct.unpack('<H', file_header[2:4])[0]
            
            # Read section headers
            for _ in range(num_sections):
                section_header = file.read(40)
                name = section_header[:8].decode('ascii').strip('\x00')
                virtual_address = struct.unpack('<I', section_header[12:16])[0]
                size = struct.unpack('<I', section_header[16:20])[0]
                characteristics = struct.unpack('<I', section_header[36:40])[0]
                
                self.sections[name] = {
                    'virtual_address': virtual_address,
                    'size': size,
                    'characteristics': characteristics
                }
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error parsing PE binary: {e}")
            return False
            
    def _parse_elf(self, file: 'BinaryIO') -> bool:
        """Parse ELF binary format.
        
        Args:
            file: File object opened in binary mode
            
        Returns:
            bool: True if parsing was successful
        """
        try:
            # Skip ELF header
            file.seek(52)
            section_header_offset = struct.unpack('<I', file.read(4))[0]
            num_sections = struct.unpack('<H', file.read(2))[0]
            section_header_size = struct.unpack('<H', file.read(2))[0]
            
            # Read section headers
            file.seek(section_header_offset)
            for _ in range(num_sections):
                section_header = file.read(section_header_size)
                name_offset = struct.unpack('<I', section_header[0:4])[0]
                section_type = struct.unpack('<I', section_header[4:8])[0]
                flags = struct.unpack('<I', section_header[8:12])[0]
                address = struct.unpack('<I', section_header[12:16])[0]
                offset = struct.unpack('<I', section_header[16:20])[0]
                size = struct.unpack('<I', section_header[20:24])[0]
                
                # Read section name
                current_pos = file.tell()
                file.seek(name_offset)
                name = file.read(32).decode('ascii').strip('\x00')
                file.seek(current_pos)
                
                self.sections[name] = {
                    'type': section_type,
                    'flags': flags,
                    'address': address,
                    'offset': offset,
                    'size': size
                }
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error parsing ELF binary: {e}")
            return False
            
    def get_section(self, name: str) -> Optional[Dict]:
        """Get section information by name.
        
        Args:
            name: Section name
            
        Returns:
            Optional[Dict]: Section information if found
        """
        return self.sections.get(name)
        
    def get_symbol(self, name: str) -> Optional[Dict]:
        """Get symbol information by name.
        
        Args:
            name: Symbol name
            
        Returns:
            Optional[Dict]: Symbol information if found
        """
        return self.symbols.get(name)
        
    def get_import(self, name: str) -> Optional[Dict]:
        """Get import information by name.
        
        Args:
            name: Import name
            
        Returns:
            Optional[Dict]: Import information if found
        """
        return self.imports.get(name)
        
    def get_binary_type(self) -> Optional[str]:
        """Get the binary type.
        
        Returns:
            Optional[str]: Binary type ('PE' or 'ELF')
        """
        return self.binary_type 