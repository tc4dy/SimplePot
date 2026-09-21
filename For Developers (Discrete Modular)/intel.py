import ipaddress
import re
from typing import Dict, List, Set

from .config import KNOWN_MALICIOUS_PATTERNS, MITRE_ATTACK_MAP
from .models import AttackEvent, AttackerProfile


class ThreatIntelligence:
    def __init__(self, db):
        self.db = db
        self.local_blacklist: Set[str] = set()
        self.local_blacklist_networks: List[ipaddress.IPv4Network] = []
        self.suspicious_patterns = [re.compile(p, re.IGNORECASE) for p in KNOWN_MALICIOUS_PATTERNS]
        self._load_known_bad_ips()

    def _load_known_bad_ips(self):
        known_bad_cidrs = [
            '185.220.101.0/24', '193.32.162.0/24', '45.142.212.0/24',
            '162.247.72.0/24', '199.87.154.0/24', '94.142.241.0/24',
        ]
        for cidr in known_bad_cidrs:
            try:
                self.local_blacklist_networks.append(ipaddress.ip_network(cidr, strict=False))
            except Exception:
                pass

    def is_blacklisted(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in self.local_blacklist_networks)
        except Exception:
            return False

    def map_mitre_techniques(self, flags: List[str], event_type: str) -> List[Dict]:
        techniques = []
        seen_ids = set()
        sources = flags + ([event_type] if event_type else [])
        for source in sources:
            mapping = MITRE_ATTACK_MAP.get(source)
            if mapping and mapping['technique_id'] not in seen_ids:
                techniques.append(mapping.copy())
                seen_ids.add(mapping['technique_id'])
        return techniques

    def calculate_threat_score(self, event: AttackEvent, profile: AttackerProfile) -> int:
        score = 0
        if event.payload:
            for pattern in self.suspicious_patterns:
                if pattern.search(event.payload):
                    score += 15
                    break

        if event.username in {'root', 'admin', 'administrator', 'sa', 'postgres', 'oracle', 'test', 'guest', 'ubuntu', 'pi'}:
            score += 5

        if profile.event_count > 100:
            score += 20
        elif profile.event_count > 50:
            score += 10
        elif profile.event_count > 10:
            score += 5

        if len(set(profile.protocols)) > 2:
            score += 10

        if self.is_blacklisted(event.ip_address):
            score += 30

        if event.is_tor:
            score += 25

        if event.is_vpn:
            score += 10

        malicious_cmds = {'wget', 'curl', 'nc ', 'ncat', 'mkfifo', 'chmod', 'chattr',
                          'crontab', 'base64', 'python -c', 'perl -e', 'bash -i', 'sh -i'}
        if event.command:
            cmd_lower = event.command.lower()
            for cmd in malicious_cmds:
                if cmd in cmd_lower:
                    score += 10
                    break

        flag_scores = {
            'SQL_INJECTION': 20, 'RCE': 30, 'WEBSHELL': 30, 'COMMAND_INJECTION': 25,
            'LFI_TRAVERSAL': 15, 'XSS': 10, 'SSRF': 20, 'ICS_ATTACK': 40,
            'CRYPTO_MINING': 20, 'BOTNET': 25, 'DNS_TUNNELING': 20,
        }
        for flag in event.flags:
            score += flag_scores.get(flag, 0)

        return min(score, 100)

    def analyze_payload(self, payload: str) -> List[str]:
        flags = []
        if not payload:
            return flags
        payload_lower = payload.lower()
        checks = [
            ('SQL_INJECTION', ['union select', 'or 1=1', 'drop table', '" or "', "' or '"]),
            ('XSS', ['<script', 'javascript:', 'onerror=', 'onload=', 'alert(']),
            ('LFI_TRAVERSAL', ['../etc/passwd', '../../../etc', '..\\..\\', '%2e%2e%2f']),
            ('COMMAND_INJECTION', ['cmd.exe', 'powershell', '/bin/bash', '/bin/sh', 'wget http', 'curl http']),
            ('SSRF', ['169.254.169.254', 'localhost:80', '127.0.0.1:', 'metadata.']),
            ('NOSQL_INJECTION', ['$gt', '$ne', '$regex', '$where', '$or']),
            ('XXE', ['<!entity', '<!doctype', 'system "http', 'system "file']),
            ('RCE', ['exec(', 'eval(', 'system(', 'passthru(', 'shell_exec']),
            ('CRYPTO_MINING', ['xmrig', 'minerd', 'stratum+tcp', 'monero', 'coinhive']),
            ('BOTNET', ['mirai', 'gafgyt', 'bashlite', 'tsunami']),
            ('SCANNER', ['nmap', 'masscan', 'nikto', 'sqlmap', 'dirbuster', 'gobuster']),
            ('WEBSHELL', ['c99.php', 'r57.php', 'b374k', 'wso shell']),
            ('DNS_TUNNELING', ['iodine', 'dnscat', 'dns2tcp']),
        ]
        for flag_name, patterns in checks:
            if any(p in payload_lower for p in patterns):
                flags.append(flag_name)
        if len(payload) > 8192:
            flags.append('LARGE_PAYLOAD')
        if re.search(r'[^\x20-\x7E\n\r\t]', payload):
            flags.append('BINARY_PAYLOAD')
        return flags