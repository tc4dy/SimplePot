import asyncio
import base64

from ..config import CONFIG
from ..events import _build_event
from ..logger import logger
from ..models import AttackEvent
from ..utils import anonymize_ip, sanitize_log_input


class SMTPHoneypot:
    def __init__(self, db, intel, defense, sessions, alerts):
        self.db = db
        self.intel = intel
        self.defense = defense
        self.sessions = sessions
        self.alerts = alerts

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        ip = writer.get_extra_info('peername')[0]
        session_id = self.sessions.create_session(ip, 'SMTP')
        self.defense.record_connection(ip)
        event = AttackEvent(ip_address=ip, port=CONFIG['smtp_port'], protocol='SMTP', session_id=session_id, event_type='CONNECTION')
        self.db.log_event(event)
        logger.info(f'SMTP connection from {anonymize_ip(ip)}')
        try:
            writer.write(b'220 mail.acmecorp.com ESMTP Postfix\r\n')
            await writer.drain()
            mail_from = ''
            data_buffer = []
            in_data = False
            while True:
                try:
                    line = await asyncio.wait_for(reader.readline(), timeout=60)
                except asyncio.TimeoutError:
                    break
                if not line:
                    break
                decoded = line.decode('utf-8', errors='replace').strip()
                if in_data:
                    if decoded == '.':
                        in_data = False
                        full_email = '\n'.join(data_buffer)
                        ev, profile, score = _build_event(ip, CONFIG['smtp_port'], 'SMTP', session_id, 'MAIL_DATA',
                                                          self.intel, self.sessions, payload=full_email[:4096])
                        self.db.log_event(ev)
                        writer.write(b'250 Message accepted\r\n')
                        data_buffer = []
                    else:
                        data_buffer.append(decoded)
                    await writer.drain()
                    continue
                cmd_upper = decoded.upper()
                if cmd_upper.startswith(('EHLO', 'HELO')):
                    writer.write(b'250-mail.acmecorp.com Hello\r\n250-SIZE 10485760\r\n250-AUTH LOGIN PLAIN\r\n250 OK\r\n')
                elif cmd_upper.startswith('AUTH'):
                    parts = decoded.split()
                    if len(parts) >= 3 and parts[1].upper() == 'PLAIN':
                        try:
                            creds = base64.b64decode(parts[2]).decode('utf-8', errors='replace')
                            cred_parts = creds.split('\x00')
                            username = sanitize_log_input(cred_parts[1] if len(cred_parts) > 1 else '', 64)
                            password = cred_parts[2] if len(cred_parts) > 2 else ''
                            self.db.log_credentials(ip, 'SMTP', username, password, session_id)
                            logger.info(f'SMTP AUTH | {anonymize_ip(ip)} | user={username}')
                        except Exception:
                            pass
                    writer.write(b'535 Authentication credentials invalid\r\n')
                elif cmd_upper.startswith('MAIL FROM'):
                    mail_from = sanitize_log_input(decoded, 256)
                    writer.write(b'250 OK\r\n')
                elif cmd_upper.startswith('RCPT TO'):
                    writer.write(b'250 OK\r\n')
                elif cmd_upper == 'DATA':
                    in_data = True
                    writer.write(b'354 Start input; end with <CRLF>.<CRLF>\r\n')
                elif cmd_upper == 'QUIT':
                    writer.write(b'221 Bye\r\n')
                    break
                elif cmd_upper in ('NOOP', 'RSET'):
                    mail_from = ''
                    writer.write(b'250 OK\r\n')
                else:
                    writer.write(b'500 Unknown command\r\n')
                await writer.drain()
        except Exception as e:
            logger.debug(f'SMTP session error {anonymize_ip(ip)}: {e}')
        finally:
            self.sessions.end_session(session_id, 'disconnected')
            try:
                writer.close()
            except Exception:
                pass