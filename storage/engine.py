"""
Abstract Storage Engine Interface for AegisFlow
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

class BaseStorageEngine(ABC):
    @abstractmethod
    def insert_flows(self, records: List[Dict[str, Any]]) -> int:
        """Batch insert enriched flow records into storage."""
        pass

    @abstractmethod
    def query(self, sql: str, params: Optional[dict] = None) -> List[Dict[str, Any]]:
        """Execute analytical SQL query and return list of dictionaries."""
        pass

    @abstractmethod
    def close(self):
        """Flush buffers and safely close connections."""
        pass
