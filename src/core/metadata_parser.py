"""
Metadata parser module for handling IL2CPP metadata.
"""

import os
import struct
import logging
from typing import Dict, List, Optional, Union

class MetadataParser:
    """Parser for IL2CPP metadata files."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.metadata = {}
        self.string_literal = {}
        self.method_definitions = {}
        self.type_definitions = {}
        
    def parse_metadata(self, file_path: str) -> bool:
        """Parse an IL2CPP metadata file.
        
        Args:
            file_path: Path to the metadata file
            
        Returns:
            bool: True if parsing was successful
        """
        try:
            with open(file_path, 'rb') as f:
                # Read metadata header
                header = f.read(16)
                if not self._validate_metadata_header(header):
                    self.logger.error("Invalid metadata header")
                    return False
                    
                # Parse version
                version = struct.unpack('<I', header[4:8])[0]
                self.metadata['version'] = version
                
                # Parse offsets
                string_literal_offset = struct.unpack('<I', header[8:12])[0]
                method_definitions_offset = struct.unpack('<I', header[12:16])[0]
                
                # Parse string literals
                if not self._parse_string_literals(f, string_literal_offset):
                    return False
                    
                # Parse method definitions
                if not self._parse_method_definitions(f, method_definitions_offset):
                    return False
                    
                # Parse type definitions
                if not self._parse_type_definitions(f):
                    return False
                    
                return True
                
        except Exception as e:
            self.logger.error(f"Error parsing metadata: {e}")
            return False
            
    def _validate_metadata_header(self, header: bytes) -> bool:
        """Validate the metadata header.
        
        Args:
            header: Raw header bytes
            
        Returns:
            bool: True if header is valid
        """
        # Check magic number
        if header[:4] != b'IL2C':
            return False
            
        # Check version range
        version = struct.unpack('<I', header[4:8])[0]
        if version < 1 or version > 100:  # Arbitrary version range
            return False
            
        return True
        
    def _parse_string_literals(self, file: 'BinaryIO', offset: int) -> bool:
        """Parse string literals from metadata.
        
        Args:
            file: File object opened in binary mode
            offset: Offset to string literals section
            
        Returns:
            bool: True if parsing was successful
        """
        try:
            file.seek(offset)
            
            # Read number of strings
            num_strings = struct.unpack('<I', file.read(4))[0]
            
            # Read string offsets
            string_offsets = []
            for _ in range(num_strings):
                string_offsets.append(struct.unpack('<I', file.read(4))[0])
                
            # Read strings
            for i, string_offset in enumerate(string_offsets):
                file.seek(string_offset)
                string_length = struct.unpack('<I', file.read(4))[0]
                string_data = file.read(string_length)
                
                try:
                    string = string_data.decode('utf-8')
                    self.string_literal[i] = string
                except UnicodeDecodeError:
                    self.logger.warning(f"Failed to decode string at offset {string_offset}")
                    self.string_literal[i] = None
                    
            return True
            
        except Exception as e:
            self.logger.error(f"Error parsing string literals: {e}")
            return False
            
    def _parse_method_definitions(self, file: 'BinaryIO', offset: int) -> bool:
        """Parse method definitions from metadata.
        
        Args:
            file: File object opened in binary mode
            offset: Offset to method definitions section
            
        Returns:
            bool: True if parsing was successful
        """
        try:
            file.seek(offset)
            
            # Read number of methods
            num_methods = struct.unpack('<I', file.read(4))[0]
            
            # Read method definitions
            for i in range(num_methods):
                method_header = file.read(16)
                name_index = struct.unpack('<I', method_header[0:4])[0]
                return_type = struct.unpack('<I', method_header[4:8])[0]
                parameter_count = struct.unpack('<I', method_header[8:12])[0]
                flags = struct.unpack('<I', method_header[12:16])[0]
                
                # Read parameters
                parameters = []
                for _ in range(parameter_count):
                    param_type = struct.unpack('<I', file.read(4))[0]
                    parameters.append(param_type)
                    
                self.method_definitions[i] = {
                    'name': self.string_literal.get(name_index),
                    'return_type': return_type,
                    'parameters': parameters,
                    'flags': flags
                }
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error parsing method definitions: {e}")
            return False
            
    def _parse_type_definitions(self, file: 'BinaryIO') -> bool:
        """Parse type definitions from metadata.
        
        Args:
            file: File object opened in binary mode
            
        Returns:
            bool: True if parsing was successful
        """
        try:
            # Read number of types
            num_types = struct.unpack('<I', file.read(4))[0]
            
            # Read type definitions
            for i in range(num_types):
                type_header = file.read(20)
                name_index = struct.unpack('<I', type_header[0:4])[0]
                namespace_index = struct.unpack('<I', type_header[4:8])[0]
                size = struct.unpack('<I', type_header[8:12])[0]
                flags = struct.unpack('<I', type_header[12:16])[0]
                parent_type = struct.unpack('<I', type_header[16:20])[0]
                
                self.type_definitions[i] = {
                    'name': self.string_literal.get(name_index),
                    'namespace': self.string_literal.get(namespace_index),
                    'size': size,
                    'flags': flags,
                    'parent_type': parent_type
                }
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error parsing type definitions: {e}")
            return False
            
    def get_string(self, index: int) -> Optional[str]:
        """Get string literal by index.
        
        Args:
            index: String index
            
        Returns:
            Optional[str]: String literal if found
        """
        return self.string_literal.get(index)
        
    def get_method_definition(self, index: int) -> Optional[Dict]:
        """Get method definition by index.
        
        Args:
            index: Method index
            
        Returns:
            Optional[Dict]: Method definition if found
        """
        return self.method_definitions.get(index)
        
    def get_type_definition(self, index: int) -> Optional[Dict]:
        """Get type definition by index.
        
        Args:
            index: Type index
            
        Returns:
            Optional[Dict]: Type definition if found
        """
        return self.type_definitions.get(index) 