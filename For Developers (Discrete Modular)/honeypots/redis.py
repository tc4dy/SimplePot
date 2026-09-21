import asyncio

from ..config import CONFIG
from ..events import _build_event
from ..logger import logger
from ..models import AttackEvent
from ..utils import anonymize_ip, sanitize_log_input


class RedisHoneypot:
    def __init__(self, db, intel, defense, sessions, alerts):
        self.db = db
        self.intel = intel
        self.defense = defense
        self.sessions = sessions
        self.alerts = alerts

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        ip = writer.get_extra_info('peername')[0]
        session_id = self.sessions.create_session(ip, 'REDIS')
        self.defense.record_connection(ip)
        event = AttackEvent(ip_address=ip, port=CONFIG['redis_port'], protocol='REDIS', session_id=session_id, event_type='CONNECTION')
        self.db.log_event(event)
        logger.info(f'Redis connection from {anonymize_ip(ip)}')
        writer.write(b'+PONG\r\n')
        await writer.drain()
        try:
            while True:
                try:
                    line = await asyncio.wait_for(reader.readline(), timeout=30)
                except asyncio.TimeoutError:
                    break
                if not line:
                    break
                decoded = line.decode('utf-8', errors='replace').strip()
                if not decoded:
                    continue
                safe_cmd = sanitize_log_input(decoded, 256)
                ev, profile, score = _build_event(ip, CONFIG['redis_port'], 'REDIS', session_id, 'COMMAND',
                                                  self.intel, self.sessions,
                                                  command=decoded, payload=decoded, extra_flags=['REDIS_UNAUTH'])
                self.db.log_event(ev)
                self.sessions.update_profile(ip, ev, score)
                logger.info(f'Redis CMD | {anonymize_ip(ip)} | {safe_cmd!r} | score={score}')
                if score >= CONFIG['alert_threshold']:
                    asyncio.ensure_future(self.alerts.send_alert(ip, 'REDIS_ATTACK', score, f'CMD: {safe_cmd[:50]}'))
                cmd_upper = decoded.upper().split()[0] if decoded.split() else ''
                if cmd_upper == 'INFO':
                    writer.write(b'$472\r\n# Server\r\nredis_version:7.0.8\r\nos:Linux 5.15.0-91-generic x86_64\r\ntcp_port:6379\r\n# Replication\r\nrole:master\r\n# Keyspace\r\ndb0:keys=127,expires=14\r\n\r\n')
                elif cmd_upper == 'CONFIG':
                    writer.write(b'*2\r\n$3\r\ndir\r\n$4\r\n/var\r\n')
                elif cmd_upper == 'QUIT':
                    writer.write(b'+OK\r\n')
                    break
                else:
                    writer.write(b'+OK\r\n')
                await writer.drain()
        except Exception as e:
            logger.debug(f'Redis session error {anonymize_ip(ip)}: {e}')
        finally:
            self.sessions.end_session(session_id, 'disconnected')
            try:
                writer.close()
            except Exception:
                pass