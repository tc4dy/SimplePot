import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List

from .utils import anonymize_ip


@dataclass
class AttackEvent:
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    ip_address: str = ''
    ip_anonymized: str = ''
    port: int = 0
    protocol: str = ''
    session_id: str = ''
    event_type: str = ''
    payload: str = ''
    username: str = ''
    password: str = ''
    command: str = ''
    user_agent: str = ''
    url: str = ''
    method: str = ''
    headers: Dict = field(default_factory=dict)
    threat_score: int = 0
    flags: List[str] = field(default_factory=list)
    mitre_techniques: List[Dict] = field(default_factory=list)
    country: str = 'Unknown'
    asn: str = 'Unknown'
    is_tor: bool = False
    is_vpn: bool = False
    raw_data: str = ''

    def __post_init__(self):
        if self.ip_address and not self.ip_anonymized:
            self.ip_anonymized = anonymize_ip(self.ip_address)


@dataclass
class AttackerProfile:
    ip_address: str
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    event_count: int = 0
    threat_score: int = 0
    protocols: List[str] = field(default_factory=list)
    usernames_tried: List[str] = field(default_factory=list)
    passwords_tried: List[str] = field(default_factory=list)
    commands_executed: List[str] = field(default_factory=list)
    payloads: List[str] = field(default_factory=list)
    mitre_techniques_seen: List[str] = field(default_factory=list)
    is_banned: bool = False
    ban_reason: str = ''
    flags: List[str] = field(default_factory=list)