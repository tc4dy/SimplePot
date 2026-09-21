import asyncio

from ..config import CONFIG
from ..events import _build_event
from ..logger import logger
from ..models import AttackEvent
from ..utils import anonymize_ip, sanitize_log_input


class MySQLHoneypot:
    GREETING_PACKET = (
        b'\x4a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x33\x33\x00'
        b'\x01\x00\x00\x00\x6b\x4c\x67\x73\x73\x46\x37\x00'
        b'\xff\xf7\x08\x02\x00\xff\x81\x15\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x5b\x7e\x46\x7a\x39\x61'
        b'\x7e\x72\x53\x59\x57\x76\x00\xff\xff\xff\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00'
    )
    AUTH_ERROR = b'\x17\x00\x00\x02\xff\x15\x04\x23\x32\x38\x30\x30\x30\x41\x63\x63\x65\x73\x73\x20\x64\x65\x6e\x69\x65\x64'

    def __init__(self, db, intel, defense, sessions, alerts):
        self.db = db
        self.intel = intel
        self.defense = defense
        self.sessions = sessions
        self.alerts = alerts

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        ip = writer.get_extra_info('peername')[0]
        session_id = self.sessions.create_session(ip, 'MYSQL')
        self.defense.record_connection(ip)
        event = AttackEvent(ip_address=ip, port=CONFIG['mysql_port'], protocol='MYSQL', session_id=session_id, event_type='CONNECTION')
        self.db.log_event(event)
        logger.info(f'MySQL connection from {anonymize_ip(ip)}')
        try:
            writer.write(self.GREETING_PACKET)
            await writer.drain()
            try:
                auth_data = await asyncio.wait_for(reader.read(4096), timeout=30)
                if auth_data and len(auth_data) > 36:
                    username_start = 36
                    username_end = auth_data.find(b'\x00', username_start)
                    username = auth_data[username_start:username_end].decode('utf-8', errors='replace') if username_end > username_start else 'unknown'
                    username = sanitize_log_input(username, 64)
                    self.db.log_credentials(ip, 'MYSQL', username, '', session_id)
                    ev, profile, score = _build_event(ip, CONFIG['mysql_port'], 'MYSQL', session_id, 'AUTH_ATTEMPT',
                                                      self.intel, self.sessions, username=username, extra_flags=['MYSQL_AUTH'])
                    self.db.log_event(ev)
                    self.sessions.update_profile(ip, ev, score)
                    logger.info(f'MySQL AUTH | {anonymize_ip(ip)} | user={username} | score={score}')
                    if score >= CONFIG['alert_threshold']:
                        asyncio.ensure_future(self.alerts.send_alert(ip, 'MYSQL_BRUTE_FORCE', score, f'User: {username}'))
            except asyncio.TimeoutError:
                pass
            writer.write(self.AUTH_ERROR)
            await writer.drain()
        except Exception as e:
            logger.debug(f'MySQL session error {anonymize_ip(ip)}: {e}')
        finally:
            self.sessions.end_session(session_id, 'disconnected')
            try:
                writer.close()
            except Exception:
                pass