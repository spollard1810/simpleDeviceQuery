class CommandError(Exception):
    """Raised when a command execution fails"""
    pass

class SNMPError(Exception):
    """Raised when SNMP operations fail"""
    pass 