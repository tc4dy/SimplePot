from ..config import CONFIG
from ..events import _build_event
from ..logger import logger
from ..utils import anonymize_ip


class SNMPHoneypot:
    def __init__(self, db, intel, defense, sessions, alerts):
        self.db = db
        self.intel = intel
        self.defense = defense
        self.sessions = sessions
        self.alerts = alerts

    async def handle_udp(self, data: bytes, addr: tuple):
        ip = addr[0]
        if self.defense.is_banned(ip):
            return
        session_id = self.sessions.create_session(ip, 'SNMP')
        ev, profile, score = _build_event(
            ip, CONFIG['snmp_port'], 'SNMP', session_id, 'SNMP_REQUEST',
            self.intel, self.sessions,
            raw_data=data[:512].hex(),
            payload=data.decode('latin-1', errors='replace')[:256],
            extra_flags=['SNMP_ENUM']
        )
        self.db.log_event(ev)
        self.sessions.update_profile(ip, ev, score)
        logger.info(f'SNMP UDP | {anonymize_ip(ip)} | {len(data)} bytes | score={score}')
        if score >= CONFIG['alert_threshold']:
            import asyncio
            asyncio.ensure_future(self.alerts.send_alert(ip, 'SNMP_ENUMERATION', score, f'{len(data)} bytes'))