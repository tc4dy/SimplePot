from typing import Tuple

from .intel import ThreatIntelligence
from .models import AttackEvent, AttackerProfile
from .sessions import SessionManager


def _build_event(ip, port, protocol, session_id, event_type, intel, sessions, **kwargs) -> Tuple[AttackEvent, AttackerProfile, int]:
    payload = kwargs.get('payload', '')
    flags = intel.analyze_payload(payload) if payload else []
    flags += kwargs.get('extra_flags', [])
    mitre = intel.map_mitre_techniques(flags, event_type)
    event = AttackEvent(
        ip_address=ip, port=port, protocol=protocol,
        session_id=session_id, event_type=event_type,
        flags=flags, mitre_techniques=mitre,
        **{k: v for k, v in kwargs.items() if k not in ('payload', 'extra_flags')}
    )
    if payload:
        event.payload = payload
    profile = sessions.get_or_create_profile(ip)
    score = intel.calculate_threat_score(event, profile)
    event.threat_score = score
    return event, profile, score