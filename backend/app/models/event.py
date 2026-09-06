from dataclasses import dataclass
from datetime import datetime
from typing import Optional

@dataclass(slots=True)
class Event:
    timestamp: Optional[datetime] = None
    source_ip: Optional[str] = None
    username: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    status_code: Optional[int] = None
    event_type: str = "unknown"
    raw_log: str = ""
