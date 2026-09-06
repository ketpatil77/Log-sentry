from dataclasses import dataclass, field
from datetime import datetime

@dataclass(slots=True)
class IncidentCandidate:
    attack_type: str
    source_ip: str
    event_count: int
    first_seen: datetime | None
    last_seen: datetime | None
    mitre_id: str
    mitre_name: str
    recommendation: str
    evidence: list[tuple[str, datetime | None]] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
