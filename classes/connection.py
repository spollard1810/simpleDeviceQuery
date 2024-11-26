from dataclasses import dataclass
from typing import Optional, Dict, Any
from netmiko import ConnectHandler
import time

@dataclass
class Connection:
    username: str
    password: str
    max_retries: int = 3
    retry_interval: int = 5

    def establish(self, device_params: Dict[str, Any]) -> Optional[Any]:
        """Establish connection with retry mechanism"""
        retries = 0
        while retries < self.max_retries:
            try:
                # Add credentials to device params
                device_params.update({
                    'username': self.username,
                    'password': self.password,
                })
                
                connection = ConnectHandler(**device_params)
                return connection
                
            except Exception as e:
                retries += 1
                if retries == self.max_retries:
                    raise ConnectionError(f"Failed to connect after {self.max_retries} attempts: {str(e)}")
                print(f"Connection attempt {retries} failed. Retrying in {self.retry_interval} seconds...")
                time.sleep(self.retry_interval)
        
        return None 