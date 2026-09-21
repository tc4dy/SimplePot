import sqlite3
import threading
import time
import uuid
from typing import Dict

from .config import CONFIG
from .logger import logger
from .metrics import prometheus_inc, prometheus_set
from .models import AttackEvent, AttackerProfile


class SessionManager:
    def __init__(self, db):
        self.db = db
        self.active_sessions: Dict[str, Dict] = {}
        self.profiles: Dict[str, AttackerProfile] = {}
        self._lock = threading.Lock()

    def create_session(self, ip: str, protocol: str) -> str:
        session_id = str(uuid.uuid4())
        with self._lock:
            if len(self.active_sessions) >= CONFIG['max_sessions_in_memory']:
                oldest = min(self.active_sessions.items(), key=lambda x: x[1]['start_time'])
                self.end_session(oldest[0], 'evicted')
            self.active_sessions[session_id] = {
                'ip': ip,
                'protocol': protocol,
                'start_time': time.time(),
                'events': [],
                'commands': [],
            }
        prometheus_inc('sessions_created', {'protocol': protocol})
        return session_id

    def end_session(self, session_id: str, reason: str = 'closed'):
        with self._lock:
            session = self.active_sessions.pop(session_id, None)
        if not session:
            return
        duration = time.time() - session['start_time']
        try:
            conn = sqlite3.connect(str(self.db.db_path), timeout=10)
            conn.execute('''
                INSERT OR IGNORE INTO sessions
                (session_id, ip_address, protocol, start_time, end_time, duration, event_count, commands_count, closed_reason)
                VALUES (?,?,?,?,?,?,?,?,?)
            ''', (session_id, session['ip'], session['protocol'], session['start_time'],
                  time.time(), duration, len(session['events']), len(session['commands']), reason))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f'Session close error: {e}')

    def get_or_create_profile(self, ip: str) -> AttackerProfile:
        with self._lock:
            if ip not in self.profiles:
                self.profiles[ip] = AttackerProfile(ip_address=ip)
            return self.profiles[ip]

    def update_profile(self, ip: str, event: AttackEvent, threat_score: int):
        profile = self.get_or_create_profile(ip)
        profile.last_seen = time.time()
        profile.event_count += 1
        profile.threat_score = max(profile.threat_score, threat_score)
        if event.protocol and event.protocol not in profile.protocols:
            profile.protocols.append(event.protocol)
        if event.username and event.username not in profile.usernames_tried:
            profile.usernames_tried.append(event.username)
        if event.password and event.password not in profile.passwords_tried:
            profile.passwords_tried.append(event.password)
        if event.command and event.command not in profile.commands_executed:
            profile.commands_executed.append(event.command)
        for flag in event.flags:
            if flag not in profile.flags:
                profile.flags.append(flag)
        for tech in event.mitre_techniques:
            tid = tech.get('technique_id', '')
            if tid and tid not in profile.mitre_techniques_seen:
                profile.mitre_techniques_seen.append(tid)
        self.db.upsert_profile(profile)
        prometheus_set('attacker_threat_score', threat_score, {'ip': ip})

    def cleanup_sessions(self):
        now = time.time()
        with self._lock:
            expired = [sid for sid, s in self.active_sessions.items()
                       if now - s['start_time'] > CONFIG['max_session_duration']]
        for sid in expired:
            self.end_session(sid, 'timeout')

    def cleanup_profiles(self, max_profiles: int = 50000):
        with self._lock:
            if len(self.profiles) > max_profiles:
                sorted_profiles = sorted(self.profiles.items(), key=lambda x: x[1].last_seen)
                to_remove = len(self.profiles) - max_profiles
                for ip, _ in sorted_profiles[:to_remove]:
                    del self.profiles[ip]