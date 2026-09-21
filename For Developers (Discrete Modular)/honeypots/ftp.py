import asyncio

from ..config import CONFIG
from ..events import _build_event
from ..logger import logger
from ..models import AttackEvent
from ..utils import anonymize_ip, sanitize_log_input


class FTPHoneypot:
    def __init__(self, db, intel, defense, sessions, alerts):
        self.db = db
        self.intel = intel
        self.defense = defense
        self.sessions = sessions
        self.alerts = alerts

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        ip = writer.get_extra_info('peername')[0]
        if self.defense.is_banned(ip):
            writer.close()
            return
        session_id = self.sessions.create_session(ip, 'FTP')
        self.defense.record_connection(ip)
        event = AttackEvent(ip_address=ip, port=CONFIG['ftp_port'], protocol='FTP', session_id=session_id, event_type='CONNECTION')
        self.db.log_event(event)
        logger.info(f'FTP connection from {anonymize_ip(ip)}')
        await asyncio.sleep(CONFIG['banner_delay'])
        writer.write(b'220 Microsoft FTP Service\r\n')
        await writer.drain()
        username = ''
        try:
            while True:
                try:
                    line = await asyncio.wait_for(reader.readline(), timeout=30)
                except asyncio.TimeoutError:
                    break
                if not line:
                    break
                cmd_line = line.decode('utf-8', errors='replace').strip()
                if not cmd_line:
                    continue
                parts = cmd_line.split(' ', 1)
                cmd = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ''
                logger.info(f'FTP CMD | {anonymize_ip(ip)} | {sanitize_log_input(cmd_line, 100)!r}')
                if cmd == 'USER':
                    username = sanitize_log_input(arg, 64)
                    writer.write(b'331 Password required\r\n')
                elif cmd == 'PASS':
                    self.db.log_credentials(ip, 'FTP', username, arg, session_id)
                    ev, profile, score = _build_event(ip, CONFIG['ftp_port'], 'FTP', session_id, 'AUTH_PASS',
                                                      self.intel, self.sessions,
                                                      username=username, password=arg, extra_flags=['FTP_AUTH'])
                    self.db.log_event(ev)
                    self.sessions.update_profile(ip, ev, score)
                    logger.info(f'FTP AUTH | {anonymize_ip(ip)} | user={username} | score={score}')
                    if score >= CONFIG['alert_threshold']:
                        asyncio.ensure_future(self.alerts.send_alert(ip, 'FTP_BRUTE_FORCE', score, f'User: {username}'))
                    if username == 'anonymous' or (username == 'admin' and arg in ['admin', 'password', '12345']):
                        writer.write(b'230 User logged in\r\n')
                    else:
                        writer.write(b'530 Login incorrect\r\n')
                elif cmd == 'SYST':
                    writer.write(b'215 Windows_NT\r\n')
                elif cmd == 'FEAT':
                    writer.write(b'211-Extensions supported:\r\n SIZE\r\n MDTM\r\n PASV\r\n211 END\r\n')
                elif cmd == 'PWD':
                    writer.write(b'257 "/" is current directory\r\n')
                elif cmd in ('LIST', 'NLST'):
                    writer.write(b'150 Opening ASCII mode data connection\r\n226 Transfer complete\r\n')
                elif cmd == 'CWD':
                    writer.write(b'250 CWD command successful\r\n')
                elif cmd == 'TYPE':
                    writer.write(b'200 Type set\r\n')
                elif cmd == 'PASV':
                    writer.write(b'227 Entering Passive Mode (127,0,0,1,19,136)\r\n')
                elif cmd == 'RETR':
                    ev2 = AttackEvent(ip_address=ip, port=CONFIG['ftp_port'], protocol='FTP', session_id=session_id, event_type='FILE_RETR', command=sanitize_log_input(arg, 256))
                    self.db.log_event(ev2)
                    writer.write(b'550 File not found\r\n')
                elif cmd == 'STOR':
                    ev2 = AttackEvent(ip_address=ip, port=CONFIG['ftp_port'], protocol='FTP', session_id=session_id, event_type='FILE_STOR', command=sanitize_log_input(arg, 256))
                    self.db.log_event(ev2)
                    writer.write(b'550 Permission denied\r\n')
                elif cmd == 'QUIT':
                    writer.write(b'221 Goodbye\r\n')
                    break
                else:
                    writer.write(b'500 Unknown command\r\n')
                await writer.drain()
        except Exception as e:
            logger.debug(f'FTP session error {anonymize_ip(ip)}: {e}')
        finally:
            self.sessions.end_session(session_id, 'disconnected')
            try:
                writer.close()
            except Exception:
                pass