import asyncio
import signal
import sys
import traceback

from .alerts import AlertManager
from .config import CONFIG, DB_PATH, MITRE_ATTACK_MAP
from .dashboard import DashboardServer
from .db import DatabaseManager
from .defense import ActiveDefense
from .health import HealthMonitor
from .honeypots.dns import DNSHoneypot
from .honeypots.ftp import FTPHoneypot
from .honeypots.http import HTTPHoneypot
from .honeypots.modbus import ModbusHoneypot
from .honeypots.mysql import MySQLHoneypot
from .honeypots.redis import RedisHoneypot
from .honeypots.smtp import SMTPHoneypot
from .honeypots.snmp import SNMPHoneypot
from .honeypots.udp import UDPServer
from .intel import ThreatIntelligence
from .logger import logger
from .periodic import (
    periodic_data_retention,
    periodic_health_check,
    periodic_report,
    periodic_session_cleanup,
    periodic_threat_analysis,
)
from .servers import (
    run_dashboard,
    run_http_server,
    run_https_server,
    run_ssh_server,
    run_tcp_server,
    run_udp_server,
)
from .sessions import SessionManager


async def main():
    logger.info('=' * 60)
    logger.info('HONEYPOT SYSTEM v2.0 STARTING')
    logger.info('=' * 60)
    logger.info(f'Data directory: {BASE_DIR}')
    logger.info(f'Database: {DB_PATH}')

    db = DatabaseManager(DB_PATH)
    intel = ThreatIntelligence(db)
    alerts = AlertManager(db)
    defense = ActiveDefense(db, intel, alerts)
    sessions = SessionManager(db)
    health_monitor = HealthMonitor(db, sessions, defense)

    ftp_hp = FTPHoneypot(db, intel, defense, sessions, alerts)
    mysql_hp = MySQLHoneypot(db, intel, defense, sessions, alerts)
    smtp_hp = SMTPHoneypot(db, intel, defense, sessions, alerts)
    redis_hp = RedisHoneypot(db, intel, defense, sessions, alerts)
    modbus_hp = ModbusHoneypot(db, intel, defense, sessions, alerts)
    dns_hp = DNSHoneypot(db, intel, defense, sessions, alerts)
    snmp_hp = SNMPHoneypot(db, intel, defense, sessions, alerts)
    http_hp = HTTPHoneypot(db, intel, defense, sessions, alerts)
    dashboard = DashboardServer(db, intel, defense, sessions, alerts, health_monitor)

    host = '0.0.0.0'
    tasks = []

    ssh_srv = await run_ssh_server(db, intel, defense, sessions, alerts, host, CONFIG['ssh_port'])
    http_runner = await run_http_server(http_hp, host, CONFIG['http_port'])
    https_runner = await run_https_server(http_hp, host, CONFIG['https_port'])
    dashboard_runner = await run_dashboard(dashboard, host, CONFIG['dashboard_port'])

    ftp_srv = await run_tcp_server(host, CONFIG['ftp_port'], ftp_hp.handle_client, 'FTP')
    mysql_srv = await run_tcp_server(host, CONFIG['mysql_port'], mysql_hp.handle_client, 'MySQL')
    smtp_srv = await run_tcp_server(host, CONFIG['smtp_port'], smtp_hp.handle_client, 'SMTP')
    redis_srv = await run_tcp_server(host, CONFIG['redis_port'], redis_hp.handle_client, 'Redis')
    modbus_srv = await run_tcp_server(host, CONFIG['modbus_port'], modbus_hp.handle_client, 'Modbus/ICS')
    dns_tcp_srv = await run_tcp_server(host, CONFIG['dns_port'], dns_hp.handle_client, 'DNS-TCP')

    dns_udp_transport = await run_udp_server(
        host, CONFIG['dns_port'],
        lambda: UDPServer(dns_hp.handle_udp), 'DNS-UDP'
    )
    snmp_udp_transport = await run_udp_server(
        host, CONFIG['snmp_port'],
        lambda: UDPServer(snmp_hp.handle_udp), 'SNMP-UDP'
    )

    tasks.append(asyncio.create_task(periodic_threat_analysis(db, intel, defense, sessions, alerts)))
    tasks.append(asyncio.create_task(periodic_session_cleanup(sessions, defense)))
    tasks.append(asyncio.create_task(periodic_data_retention(db)))
    tasks.append(asyncio.create_task(periodic_health_check(health_monitor)))
    tasks.append(asyncio.create_task(periodic_report(db)))

    logger.info('=' * 60)
    logger.info('ALL HONEYPOT SERVICES STARTED')
    logger.info(f'Dashboard:  http://localhost:{CONFIG["dashboard_port"]}')
    logger.info(f'SSH Trap:   port {CONFIG["ssh_port"]}')
    logger.info(f'HTTP Trap:  port {CONFIG["http_port"]}')
    logger.info(f'HTTPS Trap: port {CONFIG["https_port"]} (TLS)')
    logger.info(f'FTP Trap:   port {CONFIG["ftp_port"]}')
    logger.info(f'MySQL Trap: port {CONFIG["mysql_port"]}')
    logger.info(f'SMTP Trap:  port {CONFIG["smtp_port"]}')
    logger.info(f'Redis Trap: port {CONFIG["redis_port"]}')
    logger.info(f'Modbus/ICS: port {CONFIG["modbus_port"]}')
    logger.info(f'DNS Trap:   port {CONFIG["dns_port"]} (TCP+UDP)')
    logger.info(f'SNMP Trap:  port {CONFIG["snmp_port"]} (UDP)')
    logger.info(f'Prometheus: http://localhost:{CONFIG["dashboard_port"]}/metrics')
    logger.info(f'MITRE ATT&CK techniques mapped: {len(MITRE_ATTACK_MAP)}')
    logger.info('=' * 60)

    stop_event = asyncio.Event()
    loop = asyncio.get_event_loop()

    def shutdown():
        logger.info('Shutdown signal received')
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, shutdown)
        except Exception:
            pass

    await stop_event.wait()

    logger.info('Shutting down honeypot...')
    for task in tasks:
        task.cancel()
    if ssh_srv:
        ssh_srv.close()
    if dns_udp_transport:
        dns_udp_transport.close()
    if snmp_udp_transport:
        snmp_udp_transport.close()
    db._write_queue.put(None)
    logger.info('Honeypot stopped.')


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info('Interrupted by user')
    except Exception as e:
        logger.error(f'Fatal error: {e}')
        traceback.print_exc()
        sys.exit(1)