import asyncio
import sqlite3
import time
from typing import Dict, Tuple

from .metrics import prometheus_set


class HealthMonitor:
    def __init__(self, db, sessions, defense):
        self.db = db
        self.sessions = sessions
        self.defense = defense
        self._services: Dict[str, bool] = {}

    async def check_all(self) -> Dict:
        results = {}
        checks = [
            ('database', self._check_database),
            ('sessions', self._check_sessions),
            ('memory', self._check_memory),
        ]
        for name, fn in checks:
            start = time.time()
            try:
                ok, details = await asyncio.wait_for(fn(), timeout=5)
                latency = (time.time() - start) * 1000
                status = 'healthy' if ok else 'degraded'
                results[name] = {'status': status, 'latency_ms': round(latency, 2), 'details': details}
                self.db.log_health_check(name, status, latency, details)
                prometheus_set(f'health_{name}', 1 if ok else 0)
            except Exception as e:
                results[name] = {'status': 'error', 'error': str(e)}
                self.db.log_health_check(name, 'error', 0, str(e))
                prometheus_set(f'health_{name}', 0)
        return results

    async def _check_database(self) -> Tuple[bool, str]:
        try:
            conn = sqlite3.connect(str(self.db.db_path), timeout=5)
            count = conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]
            conn.close()
            return True, f'events={count}'
        except Exception as e:
            return False, str(e)

    async def _check_sessions(self) -> Tuple[bool, str]:
        active = len(self.sessions.active_sessions)
        profiles = len(self.sessions.profiles)
        return True, f'active_sessions={active}, profiles={profiles}'

    async def _check_memory(self) -> Tuple[bool, str]:
        try:
            with open('/proc/self/status') as f:
                for line in f:
                    if line.startswith('VmRSS:'):
                        kb = int(line.split()[1])
                        mb = kb // 1024
                        return mb < 2048, f'rss={mb}MB'
        except Exception:
            pass
        return True, 'unknown'