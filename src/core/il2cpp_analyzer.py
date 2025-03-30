import struct
import logging
from typing import Dict, List, Optional, Union
from unicorn import *
from unicorn.x86_const import *
from unicorn.arm_const import *
from unicorn.arm64_const import *

class IL2CPPAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.mu = None
        self.memory_regions = {}
        self.type_info_cache = {}
        self.method_info_cache = {}
        self.all_types = []
        self.all_methods = []
        
    def initialize_emulator(self, arch: str, mode: str):
        """
        Initialize the Unicorn emulator based on architecture
        """
        try:
            if arch == 'x86':
                self.mu = Uc(UC_ARCH_X86, UC_MODE_32 if mode == '32' else UC_MODE_64)
            elif arch == 'arm':
                self.mu = Uc(UC_ARCH_ARM, UC_MODE_ARM if mode == '32' else UC_MODE_ARM64)
            elif arch == 'arm64':
                self.mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM64)
            else:
                raise ValueError(f"Unsupported architecture: {arch}")
                
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize emulator: {str(e)}")
            return False
            
    def map_memory(self, address: int, size: int, permissions: int):
        """
        Map memory region in emulator
        """
        try:
            self.mu.mem_map(address, size, permissions)
            self.memory_regions[address] = {
                'size': size,
                'permissions': permissions
            }
            return True
        except Exception as e:
            self.logger.error(f"Failed to map memory: {str(e)}")
            return False
            
    def read_memory(self, address: int, size: int) -> Optional[bytes]:
        """
        Read memory from emulator
        """
        try:
            return self.mu.mem_read(address, size)
        except Exception as e:
            self.logger.error(f"Failed to read memory: {str(e)}")
            return None
            
    def write_memory(self, address: int, data: bytes) -> bool:
        """
        Write memory to emulator
        """
        try:
            self.mu.mem_write(address, data)
            return True
        except Exception as e:
            self.logger.error(f"Failed to write memory: {str(e)}")
            return False
            
    def analyze_type(self, type_info_ptr: int) -> Optional[Dict]:
        """
        Analyze IL2CPP type information
        """
        if type_info_ptr in self.type_info_cache:
            return self.type_info_cache[type_info_ptr]
            
        try:
            # Read type information structure
            type_data = self.read_memory(type_info_ptr, 0x100)  # Adjust size as needed
            if not type_data:
                return None
                
            # Parse type information
            type_info = {
                'name': self._get_string_from_ptr(struct.unpack('<Q', type_data[0:8])[0]),
                'size': struct.unpack('<I', type_data[8:12])[0],
                'flags': struct.unpack('<I', type_data[12:16])[0],
                'fields': self._parse_fields(type_data[16:])
            }
            
            self.type_info_cache[type_info_ptr] = type_info
            return type_info
            
        except Exception as e:
            self.logger.error(f"Failed to analyze type: {str(e)}")
            return None
            
    def analyze_method(self, method_info_ptr: int) -> Optional[Dict]:
        """
        Analyze IL2CPP method information
        """
        if method_info_ptr in self.method_info_cache:
            return self.method_info_cache[method_info_ptr]
            
        try:
            # Read method information structure
            method_data = self.read_memory(method_info_ptr, 0x100)  # Adjust size as needed
            if not method_data:
                return None
                
            # Parse method information
            method_info = {
                'name': self._get_string_from_ptr(struct.unpack('<Q', method_data[0:8])[0]),
                'return_type': self.analyze_type(struct.unpack('<Q', method_data[8:16])[0]),
                'parameters': self._parse_parameters(method_data[16:]),
                'address': struct.unpack('<Q', method_data[-8:])[0]
            }
            
            self.method_info_cache[method_info_ptr] = method_info
            return method_info
            
        except Exception as e:
            self.logger.error(f"Failed to analyze method: {str(e)}")
            return None
            
    def _get_string_from_ptr(self, ptr: int) -> Optional[str]:
        """
        Get string from pointer
        """
        try:
            data = self.read_memory(ptr, 0x100)  # Adjust size as needed
            if not data:
                return None
                
            # Find null terminator
            null_pos = data.find(b'\x00')
            if null_pos == -1:
                return None
                
            return data[:null_pos].decode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Failed to get string from pointer: {str(e)}")
            return None
            
    def _parse_fields(self, data: bytes) -> List[Dict]:
        """
        Parse field information
        """
        fields = []
        offset = 0
        
        while offset < len(data):
            try:
                field_info = {
                    'name': self._get_string_from_ptr(struct.unpack('<Q', data[offset:offset+8])[0]),
                    'type': self.analyze_type(struct.unpack('<Q', data[offset+8:offset+16])[0]),
                    'offset': struct.unpack('<I', data[offset+16:offset+20])[0]
                }
                fields.append(field_info)
                offset += 24  # Adjust size based on actual structure
            except:
                break
                
        return fields
        
    def _parse_parameters(self, data: bytes) -> List[Dict]:
        """
        Parse parameter information
        """
        parameters = []
        offset = 0
        
        while offset < len(data):
            try:
                param_info = {
                    'name': self._get_string_from_ptr(struct.unpack('<Q', data[offset:offset+8])[0]),
                    'type': self.analyze_type(struct.unpack('<Q', data[offset+8:offset+16])[0])
                }
                parameters.append(param_info)
                offset += 16  # Adjust size based on actual structure
            except:
                break
                
        return parameters
        
    def get_all_types(self) -> List[Dict]:
        """
        Get all analyzed types
        """
        return self.all_types
        
    def get_all_methods(self) -> List[Dict]:
        """
        Get all analyzed methods
        """
        return self.all_methods
        
    def analyze_runtime(self, runtime_ptr: int):
        """
        Analyze IL2CPP runtime
        """
        try:
            # Read runtime information
            runtime_data = self.read_memory(runtime_ptr, 0x1000)  # Adjust size as needed
            if not runtime_data:
                return False
                
            # Parse type definitions
            type_defs_offset = struct.unpack('<I', runtime_data[0x10:0x14])[0]
            type_defs_count = struct.unpack('<I', runtime_data[0x14:0x18])[0]
            
            for i in range(type_defs_count):
                type_ptr = struct.unpack('<Q', runtime_data[type_defs_offset + i*8:type_defs_offset + (i+1)*8])[0]
                type_info = self.analyze_type(type_ptr)
                if type_info:
                    self.all_types.append(type_info)
                    
            # Parse method definitions
            method_defs_offset = struct.unpack('<I', runtime_data[0x20:0x24])[0]
            method_defs_count = struct.unpack('<I', runtime_data[0x24:0x28])[0]
            
            for i in range(method_defs_count):
                method_ptr = struct.unpack('<Q', runtime_data[method_defs_offset + i*8:method_defs_offset + (i+1)*8])[0]
                method_info = self.analyze_method(method_ptr)
                if method_info:
                    self.all_methods.append(method_info)
                    
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to analyze runtime: {str(e)}")
            return False 