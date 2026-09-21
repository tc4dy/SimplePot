import asyncio
import struct

from ..config import CONFIG, MITRE_ATTACK_MAP
from ..logger import logger
from ..models import AttackEvent
from ..utils import anonymize_ip


class ModbusHoneypot:
    def __init__(self, db, intel, defense, sessions, alerts):
        self.db = db
        self.intel = intel
        self.defense = defense
        self.sessions = sessions
        self.alerts = alerts

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        ip = writer.get_extra_info('peername')[0]
        session_id = self.sessions.create_session(ip, 'MODBUS')
        self.defense.record_connection(ip)
        event = AttackEvent(ip_address=ip, port=CONFIG['modbus_port'], protocol='MODBUS', session_id=session_id, event_type='CONNECTION', extra_flags=['ICS_ATTACK'])
        event.flags = ['ICS_ATTACK']
        event.mitre_techniques = MITRE_ATTACK_MAP.get('ICS_ATTACK', {}) and [MITRE_ATTACK_MAP['ICS_ATTACK']]
        event.threat_score = 80
        self.db.log_event(event)
        logger.warning(f'MODBUS/ICS connection from {anonymize_ip(ip)} - INDUSTRIAL HONEYPOT')
        asyncio.ensure_future(self.alerts.send_alert(ip, 'ICS_ATTACK', 80, 'Modbus/ICS connection attempt'))
        try:
            while True:
                try:
                    header = await asyncio.wait_for(reader.read(6), timeout=30)
                except asyncio.TimeoutError:
                    break
                if not header or len(header) < 6:
                    break
                transaction_id = header[0:2]
                protocol_id = header[2:4]
                length = struct.unpack('>H', header[4:6])[0]
                if length > 256:
                    break
                try:
                    pdu = await asyncio.wait_for(reader.read(length), timeout=10)
                except asyncio.TimeoutError:
                    break
                if not pdu:
                    break
                func_code = pdu[1] if len(pdu) > 1 else 0
                raw_hex = (header + pdu).hex()
                ev = AttackEvent(ip_address=ip, port=CONFIG['modbus_port'], protocol='MODBUS',
                                session_id=session_id, event_type='MODBUS_REQUEST',
                                command=f'FUNC_CODE={func_code}', raw_data=raw_hex,
                                flags=['ICS_ATTACK'], threat_score=80,
                                mitre_techniques=[MITRE_ATTACK_MAP['ICS_ATTACK']])
                self.db.log_event(ev)
                logger.warning(f'MODBUS | {anonymize_ip(ip)} | func_code={func_code} | data={raw_hex}')
                response = transaction_id + protocol_id + b'\x00\x03' + bytes([pdu[0], func_code + 0x80, 0x01])
                writer.write(response)
                await writer.drain()
        except Exception as e:
            logger.debug(f'Modbus session error {anonymize_ip(ip)}: {e}')
        finally:
            self.sessions.end_session(session_id, 'disconnected')
            try:
                writer.close()
            except Exception:
                pass