import os
import logging
from typing import Dict, List, Optional, Union
from .binary_parser import BinaryParser
from .metadata_parser import MetadataParser
from .il2cpp_analyzer import IL2CPPAnalyzer

class GameAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.binary_parser = BinaryParser()
        self.metadata_parser = MetadataParser()
        self.il2cpp_analyzer = IL2CPPAnalyzer()
        self.game_info = {}
        
    def analyze_game(self, game_path: str) -> bool:
        """
        Analyze game binary and metadata
        """
        try:
            # Parse binary
            if not self.binary_parser.parse_binary(game_path):
                return False
                
            # Detect game engine
            engine = self._detect_engine()
            if not engine:
                self.logger.error("Failed to detect game engine")
                return False
                
            # Initialize IL2CPP analyzer based on architecture
            arch = self._detect_architecture()
            if not arch:
                self.logger.error("Failed to detect architecture")
                return False
                
            if not self.il2cpp_analyzer.initialize_emulator(arch['name'], arch['mode']):
                return False
                
            # Find and parse metadata
            metadata_path = self._find_metadata()
            if metadata_path and not self.metadata_parser.parse_metadata(metadata_path):
                self.logger.warning("Failed to parse metadata, continuing without it")
                
            # Store game information
            self.game_info = {
                'path': game_path,
                'engine': engine,
                'architecture': arch,
                'metadata_path': metadata_path,
                'binary_type': self.binary_parser.get_binary_type()
            }
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to analyze game: {str(e)}")
            return False
            
    def _detect_engine(self) -> Optional[str]:
        """
        Detect game engine based on binary characteristics
        """
        try:
            # Check for Unity-specific imports
            unity_imports = ['UnityEngine', 'UnityEngine.CoreModule']
            if any(imp in self.binary_parser.get_imports() for imp in unity_imports):
                return 'Unity'
                
            # Check for Unreal Engine-specific imports
            unreal_imports = ['UE4', 'UnrealEngine']
            if any(imp in self.binary_parser.get_imports() for imp in unreal_imports):
                return 'Unreal'
                
            # Check for IL2CPP runtime
            if self.binary_parser.get_section('.il2cpp'):
                return 'IL2CPP'
                
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to detect engine: {str(e)}")
            return None
            
    def _detect_architecture(self) -> Optional[Dict]:
        """
        Detect binary architecture
        """
        try:
            binary_type = self.binary_parser.get_binary_type()
            
            if binary_type == 'PE':
                # Check for x86 or x64
                if self.binary_parser.get_section('.text')['characteristics'] & 0x1000000:
                    return {'name': 'x86', 'mode': '64'}
                else:
                    return {'name': 'x86', 'mode': '32'}
                    
            elif binary_type == 'ELF':
                # Check for ARM or ARM64
                if self.binary_parser.get_section('.text')['flags'] & 0x4000000:
                    return {'name': 'arm64', 'mode': '64'}
                else:
                    return {'name': 'arm', 'mode': '32'}
                    
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to detect architecture: {str(e)}")
            return None
            
    def _find_metadata(self) -> Optional[str]:
        """
        Find metadata file in game directory
        """
        try:
            game_dir = os.path.dirname(self.game_info['path'])
            
            # Look for global-metadata.dat
            metadata_path = os.path.join(game_dir, 'global-metadata.dat')
            if os.path.exists(metadata_path):
                return metadata_path
                
            # Look for metadata in Data directory
            data_dir = os.path.join(game_dir, 'Data')
            if os.path.exists(data_dir):
                metadata_path = os.path.join(data_dir, 'global-metadata.dat')
                if os.path.exists(metadata_path):
                    return metadata_path
                    
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to find metadata: {str(e)}")
            return None
            
    def get_game_info(self) -> Dict:
        """
        Get analyzed game information
        """
        return self.game_info
        
    def get_engine_specific_features(self) -> List[str]:
        """
        Get engine-specific features available for the game
        """
        features = []
        
        if self.game_info['engine'] == 'Unity':
            features.extend([
                'Unity Component Inspection',
                'Unity GameObject Hierarchy',
                'Unity Scene Analysis'
            ])
            
        elif self.game_info['engine'] == 'Unreal':
            features.extend([
                'Unreal Actor Inspection',
                'Unreal Blueprint Analysis',
                'Unreal World Analysis'
            ])
            
        return features 