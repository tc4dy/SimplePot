import asyncio
import datetime
import re
from pathlib import Path

import asyncssh

from ..config import CONFIG, FAKE_FILES, SSH_COMMANDS
from ..events import _build_event
from ..logger import logger
from ..models import AttackEvent
from ..utils import anonymize_ip, sanitize_log_input, validate_url


class SSHHoneypot(asyncssh.SSHServer):
    def __init__(self, db, intel, defense, sessions, alerts):
        self.db = db
        self.intel = intel
        self.defense = defense
        self.sessions = sessions
        self.alerts = alerts
        self._ip = ''
        self._session_id = ''
        self._auth_attempts = 0

    def connection_made(self, conn):
        peername = conn.get_extra_info('peername')
        self._ip = peername[0] if peername else 'unknown'
        self._session_id = self.sessions.create_session(self._ip, 'SSH')
        self.defense.record_connection(self._ip)
        logger.info(f'SSH connection from {anonymize_ip(self._ip)}')
        event = AttackEvent(ip_address=self._ip, port=CONFIG['ssh_port'], protocol='SSH',
                           session_id=self._session_id, event_type='CONNECTION')
        self.db.log_event(event)

    def connection_lost(self, exc):
        self.sessions.end_session(self._session_id, 'connection_lost')

    def begin_auth(self, username):
        return True

    def password_auth_requested(self):
        return True

    def validate_password(self, username, password):
        self._auth_attempts += 1
        safe_user = sanitize_log_input(username, 64)
        self.db.log_credentials(self._ip, 'SSH', username, password, self._session_id)
        event, profile, score = _build_event(
            self._ip, CONFIG['ssh_port'], 'SSH', self._session_id, 'AUTH_ATTEMPT',
            self.intel, self.sessions,
            username=username, password=password,
            extra_flags=['SSH_AUTH_ATTEMPT', 'SSH_BRUTE_FORCE' if self._auth_attempts > 3 else '']
        )
        self.db.log_event(event)
        self.sessions.update_profile(self._ip, event, score)
        logger.info(f'SSH AUTH | {anonymize_ip(self._ip)} | user={safe_user} | attempts={self._auth_attempts} | score={score}')
        if score >= CONFIG['alert_threshold']:
            asyncio.ensure_future(self.alerts.send_alert(
                self._ip, 'SSH_BRUTE_FORCE', score,
                f'User: {safe_user}, Attempts: {self._auth_attempts}'
            ))
        return username == 'root' and password in ['toor', 'root', 'admin', '12345', 'password', '123456']

    def session_requested(self):
        return SSHSession(self.db, self.intel, self.defense, self.sessions, self.alerts, self._ip, self._session_id)


class SSHSession(asyncssh.SSHServerSession):
    def __init__(self, db, intel, defense, sessions, alerts, ip, session_id):
        self.db = db
        self.intel = intel
        self.defense = defense
        self.sessions = sessions
        self.alerts = alerts
        self._ip = ip
        self._session_id = session_id
        self._chan = None
        self._command_buffer = ''
        self._cwd = '/root'
        self._interaction_count = 0

    def connection_made(self, chan):
        self._chan = chan

    def shell_requested(self):
        return True

    def session_started(self):
        self._chan.write(f'Welcome to Ubuntu 20.04.6 LTS (GNU/Linux {CONFIG["fake_kernel"]} x86_64)\r\n\r\n')
        self._chan.write(f' * Documentation:  https://help.ubuntu.com\r\n\r\n')
        self._chan.write(f'Last login: {datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Y")} from 10.0.0.55\r\n')
        self._chan.write('root@prod-server-01:~# ')

    def data_received(self, data, datatype):
        if datatype == asyncssh.EXTENDED_DATA_STDERR:
            return
        self._command_buffer += data
        if '\n' in self._command_buffer or '\r' in self._command_buffer:
            lines = re.split(r'[\r\n]+', self._command_buffer)
            self._command_buffer = lines[-1]
            for line in lines[:-1]:
                cmd = line.strip()
                if cmd:
                    self._handle_command(cmd)

    def _handle_command(self, cmd: str):
        self._interaction_count += 1
        safe_cmd = sanitize_log_input(cmd, 512)
        event, profile, score = _build_event(
            self._ip, CONFIG['ssh_port'], 'SSH', self._session_id, 'COMMAND',
            self.intel, self.sessions,
            command=cmd, payload=cmd,
            extra_flags=['SSH_COMMAND']
        )
        self.db.log_event(event)
        self.sessions.update_profile(self._ip, event, score)
        logger.info(f'SSH CMD | {anonymize_ip(self._ip)} | cmd={safe_cmd!r} | score={score} | mitre={[t["technique_id"] for t in event.mitre_techniques]}')
        if score >= CONFIG['alert_threshold']:
            asyncio.ensure_future(self.alerts.send_alert(
                self._ip, 'SSH_COMMAND_INJECTION', score, f'CMD: {safe_cmd[:100]}'
            ))
        response = self._generate_response(cmd)
        self._chan.write(response + 'root@prod-server-01:~# ')

    def _generate_response(self, cmd: str) -> str:
        cmd_lower = cmd.lower().strip()
        for known_cmd, response in SSH_COMMANDS.items():
            if cmd_lower == known_cmd.lower() or cmd_lower.startswith(known_cmd.lower() + ' '):
                return response.replace('\n', '\r\n')
        if cmd_lower.startswith('cat '):
            path = cmd[4:].strip()
            path = re.sub(r'[;&|`$]', '', path).strip()
            if path in FAKE_FILES:
                return FAKE_FILES[path].replace('\n', '\r\n')
            return f'cat: {path}: No such file or directory\r\n'
        if cmd_lower.startswith('echo '):
            content = re.sub(r'[;&|`$]', '', cmd[5:])
            return content.replace('\\n', '\r\n') + '\r\n'
        if cmd_lower.startswith('cd '):
            target = re.sub(r'[;&|`$]', '', cmd[3:]).strip()
            if target == '..':
                self._cwd = str(Path(self._cwd).parent)
            elif target.startswith('/'):
                self._cwd = target
            else:
                self._cwd = str(Path(self._cwd) / target)
            return ''
        if cmd_lower.startswith('wget ') or cmd_lower.startswith('curl '):
            url_match = re.search(r'https?://[^\s;&|`]+', cmd)
            if url_match:
                url = url_match.group()
                if validate_url(url):
                    parsed = urlparse(url)
                    filename = parsed.path.split('/')[-1] or 'index.html'
                    return f'--{datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}--  {url}\r\nResolving {parsed.netloc}... 203.0.113.42\r\nHTTP request sent, awaiting response... 200 OK\r\nSaving to: \'{filename}\'\r\n{filename}: 100%[==================>]   4.00K  --.-KB/s\r\n'
            return 'wget: missing URL\r\n'
        if cmd_lower.startswith('chmod ') or cmd_lower.startswith('mkdir ') or cmd_lower.startswith('rm ') or cmd_lower.startswith('mv ') or cmd_lower.startswith('cp '):
            return ''
        if cmd_lower.startswith('python') or cmd_lower.startswith('perl') or cmd_lower.startswith('ruby'):
            return ''
        if cmd_lower in ('exit', 'logout', 'quit'):
            self._chan.write('logout\r\n')
            self._chan.close()
            return ''
        if cmd_lower.startswith('apt') or cmd_lower.startswith('yum') or cmd_lower.startswith('dnf'):
            return 'Reading package lists... Done\r\nBuilding dependency tree\r\n0 upgraded, 0 newly installed.\r\n'
        if cmd_lower.startswith('systemctl'):
            parts = cmd_lower.split()
            if len(parts) >= 3:
                service = parts[2]
                return f'[*] {service}.service\r\n   Loaded: loaded (/lib/systemd/system/{service}.service; enabled)\r\n   Active: active (running)\r\n'
            return ''
        first_word = cmd.split()[0] if cmd.split() else ''
        return f'-bash: {sanitize_log_input(first_word, 50)}: command not found\r\n' if first_word else ''

    def eof_received(self):
        self.sessions.end_session(self._session_id, 'eof')