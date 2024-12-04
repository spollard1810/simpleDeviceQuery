import yaml
from typing import Dict, List, Callable
from pathlib import Path
from .exceptions import ParserError

class CommandParserYAML:
    def __init__(self):
        self.commands = {}
        self.chainable_commands = {}
        self.parser_registry = {}
        self.load_commands()
        self.register_parsers()

    def load_commands(self) -> None:
        """Load commands from YAML config files"""
        config_dir = Path("data/configs")
        
        # Load common commands
        common_commands_file = config_dir / "common_commands.yml"
        if common_commands_file.exists():
            with open(common_commands_file) as f:
                self.commands = yaml.safe_load(f)
        
        # Load chainable commands
        chainable_commands_file = config_dir / "chainable_commands.yml"
        if chainable_commands_file.exists():
            with open(chainable_commands_file) as f:
                self.chainable_commands = yaml.safe_load(f)

    def register_parsers(self) -> None:
        """Register parser functions to map to YAML definitions"""
        self.parser_registry = {
            'parse_interface_status': self.parse_interface_status,
            'parse_interface_details': self.parse_interface_details,
            'parse_cdp_neighbors': self.parse_cdp_neighbors,
            # Add more parser mappings as needed
        }

    def get_parser(self, parser_name: str) -> Callable:
        """Get parser function by name"""
        parser = self.parser_registry.get(parser_name)
        if not parser:
            raise ParserError(f"No parser found for: {parser_name}")
        return parser

    # Parser methods will be the same as in CommandParser
    @staticmethod
    def parse_interface_status(output: str) -> List[Dict[str, str]]:
        """Parse interface status output"""
        # Same implementation as current CommandParser
        pass

    @staticmethod
    def parse_interface_details(output: str) -> Dict[str, str]:
        """Parse interface details output"""
        # Same implementation as current CommandParser
        pass

    @staticmethod
    def parse_cdp_neighbors(output: str) -> List[Dict[str, str]]:
        """Parse CDP neighbors output"""
        # Same implementation as current CommandParser
        pass 