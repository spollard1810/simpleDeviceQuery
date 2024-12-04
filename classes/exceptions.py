class CommandError(Exception):
    """Exception raised for command execution errors"""
    pass

class ConnectionError(Exception):
    """Exception raised for connection errors"""
    pass

class ParserError(Exception):
    """Exception raised for parsing errors"""
    pass 