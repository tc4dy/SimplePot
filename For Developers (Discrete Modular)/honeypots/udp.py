import asyncio

from ..logger import logger


class UDPServer(asyncio.DatagramProtocol):
    def __init__(self, handler_fn):
        self._handler = handler_fn
        self._transport = None

    def connection_made(self, transport):
        self._transport = transport

    def datagram_received(self, data: bytes, addr: tuple):
        asyncio.ensure_future(self._handler(data, addr))

    def error_received(self, exc):
        logger.debug(f'UDP error: {exc}')