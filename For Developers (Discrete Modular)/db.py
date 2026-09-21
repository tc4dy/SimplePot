import json
import queue
import sqlite3
import threading
import time
from pathlib import Path
from typing import Dict

from .logger import logger
from .metrics import prometheus_inc
from .models import AttackEvent, AttackerProfile
from .utils import anonymize_ip, sanitize_log_input


class DatabaseManager:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._local = threading.local()
        self._write_queue: queue.Queue = queue.Queue(maxsize=5000)
        self._writer_thread = threading.Thread(target=self._writer_loop, daemon=True)
        self._writer_thread.start()
        self._init_db()

    def _get_conn(self):
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(str(self.db_path), check_same_thread=False, timeout=30)
            self._local.conn.execute('PRAGMA journal_mode=WAL')
            self._local.conn.execute('PRAGMA synchronous=NORMAL')
            self._local.conn.execute('PRAGMA cache_size=10000')
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _writer_loop(self):
        batch = []
        last_flush = time.time()
        while True:
            try:
                item = self._write_queue.get(timeout=1.0)
                if item is None:
                    if batch:
                        self._flush_batch(batch)
                    break
                batch.append(item)
                if len(batch) >= 50 or time.time() - last_flush > 2.0:
                    self._flush_batch(batch)
                    batch = []
                    last_flush = time.time()
            except queue.Empty:
                if batch:
                    self._flush_batch(batch)
                    batch = []
                    last_flush = time.time()

    def _flush_batch(self, batch: list):
        conn = sqlite3.connect(str(self.db_path), timeout=30)
        conn.execute('PRAGMA journal_mode=WAL')
        try:
            conn.executemany(batch[0][0], [b[1] for b in batch if b[0] == batch[0][0]])
            conn.commit()
        except Exception:
            for sql, params in batch:
                try:
                    conn.execute(sql, params)
                    conn.commit()
                except Exception as e:
                    logger.error(f'DB batch write error: {e}')
        finally:
            conn.close()

    def _init_db(self):
        conn = sqlite3.connect(str(self.db_path))
        conn.execute('PRAGMA journal_mode=WAL')
        cursor = conn.cursor()
        cursor.executescript('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL,
                timestamp REAL NOT NULL,
                ip_address TEXT NOT NULL,
                ip_anonymized TEXT,
                port INTEGER,
                protocol TEXT,
                session_id TEXT,
                event_type TEXT,
                payload TEXT,
                username TEXT,
                password TEXT,
                command TEXT,
                user_agent TEXT,
                url TEXT,
                method TEXT,
                headers TEXT,
                threat_score INTEGER DEFAULT 0,
                flags TEXT,
                mitre_techniques TEXT,
                country TEXT DEFAULT 'Unknown',
                asn TEXT DEFAULT 'Unknown',
                is_tor INTEGER DEFAULT 0,
                is_vpn INTEGER DEFAULT 0,
                raw_data TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS attacker_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                first_seen REAL,
                last_seen REAL,
                event_count INTEGER DEFAULT 0,
                threat_score INTEGER DEFAULT 0,
                protocols TEXT,
                usernames_tried TEXT,
                passwords_tried TEXT,
                commands_executed TEXT,
                payloads TEXT,
                mitre_techniques_seen TEXT,
                is_banned INTEGER DEFAULT 0,
                ban_reason TEXT,
                flags TEXT,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE NOT NULL,
                ip_address TEXT,
                protocol TEXT,
                start_time REAL,
                end_time REAL,
                duration REAL,
                event_count INTEGER DEFAULT 0,
                commands_count INTEGER DEFAULT 0,
                threat_score INTEGER DEFAULT 0,
                closed_reason TEXT
            );
            CREATE TABLE IF NOT EXISTS captured_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                ip_address TEXT,
                ip_anonymized TEXT,
                protocol TEXT,
                username TEXT,
                password TEXT,
                session_id TEXT,
                success INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS health_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                service TEXT,
                status TEXT,
                latency_ms REAL,
                details TEXT
            );
            CREATE TABLE IF NOT EXISTS alert_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                ip_address TEXT,
                alert_type TEXT,
                threat_score INTEGER,
                message TEXT,
                sent INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip_address);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_events_protocol ON events(protocol);
            CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
            CREATE INDEX IF NOT EXISTS idx_events_score ON events(threat_score);
            CREATE INDEX IF NOT EXISTS idx_profiles_score ON attacker_profiles(threat_score);
        ''')
        conn.commit()
        conn.close()

    def log_event(self, event: AttackEvent):
        sql = '''
            INSERT OR IGNORE INTO events
            (event_id, timestamp, ip_address, ip_anonymized, port, protocol, session_id, event_type,
             payload, username, password, command, user_agent, url, method, headers,
             threat_score, flags, mitre_techniques, country, asn, is_tor, is_vpn, raw_data)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        '''
        params = (
            event.event_id, event.timestamp, event.ip_address, event.ip_anonymized,
            event.port, event.protocol, event.session_id, event.event_type,
            event.payload[:4096] if event.payload else '',
            sanitize_log_input(event.username, 128),
            event.password[:256] if event.password else '',
            sanitize_log_input(event.command, 512),
            sanitize_log_input(event.user_agent, 256),
            event.url[:1024] if event.url else '',
            event.method,
            json.dumps(event.headers)[:2048],
            event.threat_score,
            json.dumps(event.flags),
            json.dumps(event.mitre_techniques),
            event.country, event.asn,
            int(event.is_tor), int(event.is_vpn),
            event.raw_data[:2048] if event.raw_data else ''
        )
        try:
            self._write_queue.put_nowait((sql, params))
        except queue.Full:
            logger.warning('Write queue full, dropping event')
        prometheus_inc('events_total', {'protocol': event.protocol or 'unknown'})

    def upsert_profile(self, profile: AttackerProfile):
        conn = self._get_conn()
        try:
            conn.execute('''
                INSERT INTO attacker_profiles
                (ip_address, first_seen, last_seen, event_count, threat_score,
                 protocols, usernames_tried, passwords_tried, commands_executed,
                 payloads, mitre_techniques_seen, is_banned, ban_reason, flags)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(ip_address) DO UPDATE SET
                last_seen=excluded.last_seen,
                event_count=excluded.event_count,
                threat_score=excluded.threat_score,
                protocols=excluded.protocols,
                usernames_tried=excluded.usernames_tried,
                passwords_tried=excluded.passwords_tried,
                commands_executed=excluded.commands_executed,
                payloads=excluded.payloads,
                mitre_techniques_seen=excluded.mitre_techniques_seen,
                is_banned=excluded.is_banned,
                ban_reason=excluded.ban_reason,
                flags=excluded.flags,
                updated_at=CURRENT_TIMESTAMP
            ''', (
                profile.ip_address, profile.first_seen, profile.last_seen,
                profile.event_count, profile.threat_score,
                json.dumps(profile.protocols[:50]),
                json.dumps(profile.usernames_tried[:100]),
                json.dumps(profile.passwords_tried[:100]),
                json.dumps(profile.commands_executed[:200]),
                json.dumps(profile.payloads[:50]),
                json.dumps(profile.mitre_techniques_seen[:100]),
                int(profile.is_banned), profile.ban_reason,
                json.dumps(profile.flags[:50])
            ))
            conn.commit()
        except Exception as e:
            logger.error(f'DB upsert_profile error: {e}')

    def log_credentials(self, ip: str, protocol: str, username: str, password: str, session_id: str):
        conn = self._get_conn()
        try:
            conn.execute('''
                INSERT INTO captured_credentials (timestamp, ip_address, ip_anonymized, protocol, username, password, session_id)
                VALUES (?,?,?,?,?,?,?)
            ''', (time.time(), ip, anonymize_ip(ip), protocol,
                  sanitize_log_input(username, 128), password[:512], session_id))
            conn.commit()
        except Exception as e:
            logger.error(f'DB credential log error: {e}')
        prometheus_inc('credentials_captured', {'protocol': protocol})

    def log_health_check(self, service: str, status: str, latency_ms: float, details: str = ''):
        conn = self._get_conn()
        try:
            conn.execute(
                'INSERT INTO health_checks (timestamp, service, status, latency_ms, details) VALUES (?,?,?,?,?)',
                (time.time(), service, status, latency_ms, details[:512])
            )
            conn.commit()
        except Exception as e:
            logger.error(f'DB health check error: {e}')

    def log_alert(self, ip: str, alert_type: str, threat_score: int, message: str):
        conn = self._get_conn()
        try:
            conn.execute(
                'INSERT INTO alert_log (timestamp, ip_address, alert_type, threat_score, message) VALUES (?,?,?,?,?)',
                (time.time(), ip, alert_type, threat_score, message[:1024])
            )
            conn.commit()
        except Exception as e:
            logger.error(f'DB alert log error: {e}')

    def purge_old_data(self, retention_days: int):
        cutoff = time.time() - retention_days * 86400
        conn = self._get_conn()
        try:
            conn.execute('DELETE FROM events WHERE timestamp < ?', (cutoff,))
            conn.execute('DELETE FROM captured_credentials WHERE timestamp < ?', (cutoff,))
            conn.execute('DELETE FROM health_checks WHERE timestamp < ?', (cutoff,))
            conn.execute('DELETE FROM alert_log WHERE timestamp < ?', (cutoff,))
            conn.execute('VACUUM')
            conn.commit()
            logger.info(f'Purged data older than {retention_days} days')
        except Exception as e:
            logger.error(f'DB purge error: {e}')

    def get_stats(self) -> Dict:
        conn = self._get_conn()
        try:
            stats = {}
            stats['total_events'] = conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]
            stats['unique_ips'] = conn.execute('SELECT COUNT(DISTINCT ip_address) FROM events').fetchone()[0]
            stats['total_credentials'] = conn.execute('SELECT COUNT(*) FROM captured_credentials').fetchone()[0]
            stats['banned_ips'] = conn.execute('SELECT COUNT(*) FROM attacker_profiles WHERE is_banned=1').fetchone()[0]
            stats['events_by_protocol'] = dict(conn.execute(
                'SELECT protocol, COUNT(*) FROM events WHERE protocol IS NOT NULL GROUP BY protocol ORDER BY COUNT(*) DESC'
            ).fetchall())
            stats['top_attackers'] = [dict(row) for row in conn.execute(
                'SELECT ip_address, event_count, threat_score, is_banned FROM attacker_profiles ORDER BY threat_score DESC LIMIT 20'
            ).fetchall()]
            stats['recent_events'] = [dict(row) for row in conn.execute(
                'SELECT timestamp, ip_address, protocol, event_type, threat_score, flags, mitre_techniques FROM events ORDER BY timestamp DESC LIMIT 50'
            ).fetchall()]
            stats['mitre_coverage'] = [dict(row) for row in conn.execute(
                '''SELECT json_each.value as technique, COUNT(*) as count
                   FROM events, json_each(mitre_techniques)
                   WHERE mitre_techniques != '[]'
                   GROUP BY technique ORDER BY count DESC LIMIT 20'''
            ).fetchall()]
            stats['hourly_events'] = [dict(row) for row in conn.execute(
                '''SELECT strftime('%H', datetime(timestamp, 'unixepoch')) as hour, COUNT(*) as count
                   FROM events WHERE timestamp > ? GROUP BY hour ORDER BY hour''',
                (time.time() - 86400,)
            ).fetchall()]
            return stats
        except Exception as e:
            logger.error(f'DB get_stats error: {e}')
            return {}