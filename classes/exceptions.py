class CommandError(Exception):
    """Exception raised when a command execution fails"""
    pass

class SNMPError(Exception):
    """Raised when SNMP operations fail"""
    pass 