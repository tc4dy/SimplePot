import asyncio
import datetime
import time
from typing import Dict

import aiohttp

from .config import CONFIG
from .db import DatabaseManager
from .logger import logger
from .utils import anonymize_ip, validate_url


class AlertManager:
    def __init__(self, db: DatabaseManager):
        self.db = db
        self._alerted_ips: Dict[str, float] = {}
        self._cooldown = 300

    def _should_alert(self, ip: str) -> bool:
        last = self._alerted_ips.get(ip, 0)
        if time.time() - last > self._cooldown:
            self._alerted_ips[ip] = time.time()
            return True
        return False

    async def send_alert(self, ip: str, alert_type: str, threat_score: int, details: str):
        if not self._should_alert(ip):
            return
        message = f'[!] HONEYPOT ALERT\nType: {alert_type}\nIP: {anonymize_ip(ip)}\nScore: {threat_score}/100\nDetails: {details[:200]}'
        self.db.log_alert(ip, alert_type, threat_score, details)
        tasks = []
        if CONFIG.get('slack_webhook'):
            tasks.append(self._send_slack(message))
        if CONFIG.get('webhook_url'):
            tasks.append(self._send_webhook(ip, alert_type, threat_score, details))
        if CONFIG.get('telegram_token') and CONFIG.get('telegram_chat_id'):
            tasks.append(self._send_telegram(message))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _send_slack(self, message: str):
        try:
            async with aiohttp.ClientSession() as session:
                payload = {'text': message, 'username': 'Honeypot', 'icon_emoji': ':honeybee:'}
                async with session.post(CONFIG['slack_webhook'], json=payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status != 200:
                        logger.warning(f'Slack alert failed: {resp.status}')
        except Exception as e:
            logger.error(f'Slack alert error: {e}')

    async def _send_webhook(self, ip: str, alert_type: str, threat_score: int, details: str):
        try:
            if not validate_url(CONFIG['webhook_url']):
                return
            payload = {
                'timestamp': datetime.datetime.utcnow().isoformat(),
                'ip_anonymized': anonymize_ip(ip),
                'alert_type': alert_type,
                'threat_score': threat_score,
                'details': details[:500],
                'source': 'honeypot'
            }
            async with aiohttp.ClientSession() as session:
                async with session.post(CONFIG['webhook_url'], json=payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status not in (200, 201, 202, 204):
                        logger.warning(f'Webhook alert failed: {resp.status}')
        except Exception as e:
            logger.error(f'Webhook alert error: {e}')

    async def _send_telegram(self, message: str):
        try:
            url = f'https://api.telegram.org/bot{CONFIG["telegram_token"]}/sendMessage'
            payload = {'chat_id': CONFIG['telegram_chat_id'], 'text': message, 'parse_mode': 'HTML'}
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status != 200:
                        logger.warning(f'Telegram alert failed: {resp.status}')
        except Exception as e:
            logger.error(f'Telegram alert error: {e}')
