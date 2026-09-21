import asyncio
import struct

import dns.flags
import dns.message

from ..config import CONFIG
from ..events import _build_event
from ..logger import logger
from ..utils import anonymize_ip, sanitize_log_input


class DNSHoneypot:
    def __init__(self, db, intel, defense, sessions, alerts):
        self.db = db
        self.intel = intel
        self.defense = defense
        self.sessions = sessions
        self.alerts = alerts

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        ip = writer.get_extra_info('peername')[0]
        session_id = self.sessions.create_session(ip, 'DNS')
        self.defense.record_connection(ip)
        logger.info(f'DNS connection from {anonymize_ip(ip)}')
        try:
            while True:
                try:
                    length_data = await asyncio.wait_for(reader.read(2), timeout=15)
                    if len(length_data) < 2:
                        break
                    msg_len = struct.unpack('!H', length_data)[0]
                    if msg_len > 512:
                        break
                    data = await asyncio.wait_for(reader.read(msg_len), timeout=10)
                    if not data:
                        break
                except asyncio.TimeoutError:
                    break
                try:
                    query = dns.message.from_wire(data)
                    qname = str(query.question[0].name) if query.question else 'unknown'
                    flags = []
                    if len(qname) > 30 or qname.count('.') > 5:
                        flags.append('DNS_TUNNELING')
                    ev, profile, score = _build_event(
                        ip, CONFIG['dns_port'], 'DNS', session_id, 'DNS_QUERY',
                        self.intel, self.sessions,
                        command=sanitize_log_input(qname, 256),
                        payload=qname,
                        extra_flags=flags + ['SNMP_ENUM']
                    )
                    self.db.log_event(ev)
                    self.sessions.update_profile(ip, ev, score)
                    logger.info(f'DNS QUERY | {anonymize_ip(ip)} | {sanitize_log_input(qname, 100)} | score={score}')
                    if score >= CONFIG['alert_threshold']:
                        asyncio.ensure_future(self.alerts.send_alert(ip, 'DNS_TUNNELING', score, f'Query: {qname[:50]}'))
                    response = dns.message.make_response(query)
                    response.flags |= dns.flags.AA
                    response_wire = response.to_wire()
                    writer.write(struct.pack('!H', len(response_wire)) + response_wire)
                    await writer.drain()
                except Exception:
                    break
        except Exception as e:
            logger.debug(f'DNS session error {anonymize_ip(ip)}: {e}')
        finally:
            self.sessions.end_session(session_id, 'disconnected')
            try:
                writer.close()
            except Exception:
                pass

    async def handle_udp(self, data: bytes, addr: tuple):
        ip = addr[0]
        try:
            query = dns.message.from_wire(data)
            qname = str(query.question[0].name) if query.question else 'unknown'
            session_id = self.sessions.create_session(ip, 'DNS_UDP')
            flags = ['DNS_TUNNELING'] if (len(qname) > 30 or qname.count('.') > 5) else []
            ev, profile, score = _build_event(
                ip, CONFIG['dns_port'], 'DNS', session_id, 'DNS_QUERY_UDP',
                self.intel, self.sessions,
                command=sanitize_log_input(qname, 256),
                payload=qname, extra_flags=flags
            )
            self.db.log_event(ev)
            self.sessions.update_profile(ip, ev, score)
            logger.info(f'DNS UDP | {anonymize_ip(ip)} | {sanitize_log_input(qname, 100)} | score={score}')
        except Exception:
            pass    