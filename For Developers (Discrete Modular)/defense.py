import ipaddress
import subprocess
import time
from collections import defaultdict, deque
from typing import Dict, List, Set

from .config import CONFIG
from .logger import logger
from .metrics import prometheus_inc
from .utils import anonymize_ip, sanitize_log_input


class ActiveDefense:
    def __init__(self, db, intel, alerts):
        self.db = db
        self.intel = intel
        self.alerts = alerts
        self.banned_ips: Set[str] = set()
        self.tarpitted_ips: Set[str] = set()
        self.rate_limits: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self.connection_counts: Dict[str, int] = defaultdict(int)
        self._ipv6_ranges: List[ipaddress.IPv6Network] = []

    def is_valid_ip(self, ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def should_tarpit(self, ip: str) -> bool:
        return ip in self.tarpitted_ips or self.connection_counts[ip] > 20

    def ban_ip(self, ip: str, reason: str):
        if not self.is_valid_ip(ip):
            return
        self.banned_ips.add(ip)
        logger.warning(f'BANNED IP: {anonymize_ip(ip)} | Reason: {sanitize_log_input(reason)}')
        if CONFIG['active_defense_enabled']:
            try:
                subprocess.run(
                    ['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'],
                    capture_output=True, timeout=5, check=False
                )
            except Exception:
                pass

    def unban_ip(self, ip: str):
        self.banned_ips.discard(ip)
        if CONFIG['active_defense_enabled']:
            try:
                subprocess.run(
                    ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
                    capture_output=True, timeout=5, check=False
                )
            except Exception:
                pass

    def is_rate_limited(self, ip: str) -> bool:
        now = time.time()
        window = self.rate_limits[ip]
        window.append(now)
        recent = sum(1 for t in window if now - t < 60)
        if recent > CONFIG['max_connections_per_ip']:
            prometheus_inc('rate_limited_requests', {'ip_subnet': ip.rsplit('.', 1)[0] if '.' in ip else ip})
            return True
        return False

    def record_connection(self, ip: str):
        self.connection_counts[ip] += 1
        prometheus_inc('connections_total')

    def is_banned(self, ip: str) -> bool:
        return ip in self.banned_ips

    def cleanup_old_connections(self):
        cutoff_time = time.time() - 3600
        stale = [ip for ip, ts in self.rate_limits.items()
                 if all(t < cutoff_time for t in ts)]
        for ip in stale:
            del self.rate_limits[ip]