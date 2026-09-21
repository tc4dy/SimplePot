import asyncio
import os
import ssl

import aiohttp.web
import asyncssh

from .config import BASE_DIR, CONFIG
from .logger import logger
from .utils import generate_self_signed_cert
from .honeypots.ssh import SSHHoneypot
from .honeypots.http import HTTPHoneypot
from .honeypots.udp import UDPServer
from .dashboard import DashboardServer


async def run_tcp_server(host, port, handler, name):
    try:
        server = await asyncio.start_server(handler, host, port)
        logger.info(f'{name} honeypot listening on {host}:{port}')
        return server
    except OSError as e:
        logger.warning(f'Cannot bind {name} on port {port}: {e}')
        return None


async def run_ssh_server(db, intel, defense, sessions, alerts, host, port):
    try:
        host_key_path = BASE_DIR / 'keys' / 'ssh_host_key'
        os.chmod(BASE_DIR / 'keys', 0o700)
        if not host_key_path.exists():
            key = asyncssh.generate_private_key('ssh-rsa')
            key.write_private_key(str(host_key_path))
            os.chmod(host_key_path, 0o600)
        else:
            key = asyncssh.read_private_key(str(host_key_path))
        server = await asyncssh.create_server(
            lambda: SSHHoneypot(db, intel, defense, sessions, alerts),
            host, port,
            server_host_keys=[key],
            server_version='SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11',
            login_timeout=60,
            auth_timeout=60,
        )
        logger.info(f'SSH honeypot listening on {host}:{port}')
        return server
    except Exception as e:
        logger.warning(f'Cannot start SSH server on port {port}: {e}')
        return None


async def run_https_server(http_honeypot: HTTPHoneypot, host: str, port: int):
    try:
        cert_path = BASE_DIR / 'certs' / 'server.crt'
        key_path = BASE_DIR / 'certs' / 'server.key'
        if not cert_path.exists() or not key_path.exists():
            logger.info('Generating self-signed TLS certificate...')
            generate_self_signed_cert(cert_path, key_path, CONFIG['fake_hostname'])
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(str(cert_path), str(key_path))
        ssl_ctx.set_ciphers('HIGH:!aNULL:!MD5')
        runner = aiohttp.web.AppRunner(http_honeypot.app)
        await runner.setup()
        site = aiohttp.web.TCPSite(runner, host, port, ssl_context=ssl_ctx)
        await site.start()
        logger.info(f'HTTPS honeypot listening on {host}:{port}')
        return runner
    except Exception as e:
        logger.warning(f'Cannot start HTTPS server on port {port}: {e}')
        return None


async def run_http_server(honeypot: HTTPHoneypot, host, port):
    try:
        runner = aiohttp.web.AppRunner(honeypot.app)
        await runner.setup()
        site = aiohttp.web.TCPSite(runner, host, port)
        await site.start()
        logger.info(f'HTTP honeypot listening on {host}:{port}')
        return runner
    except Exception as e:
        logger.warning(f'Cannot start HTTP server on port {port}: {e}')
        return None


async def run_dashboard(dashboard: DashboardServer, host, port):
    try:
        runner = aiohttp.web.AppRunner(dashboard.app)
        await runner.setup()
        site = aiohttp.web.TCPSite(runner, host, port)
        await site.start()
        logger.info(f'Dashboard running on http://{host}:{port}')
        return runner
    except Exception as e:
        logger.warning(f'Cannot start Dashboard on port {port}: {e}')
        return None


async def run_udp_server(host, port, protocol_factory, name):
    try:
        loop = asyncio.get_event_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            protocol_factory,
            local_addr=(host, port)
        )
        logger.info(f'{name} UDP honeypot listening on {host}:{port}')
        return transport
    except OSError as e:
        logger.warning(f'Cannot bind {name} UDP on port {port}: {e}')
        return None