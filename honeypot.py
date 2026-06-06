import asyncio
import aiohttp
import aiohttp.web
import asyncssh
import socket
import struct
import json
import sqlite3
import hashlib
import hmac
import time
import datetime
import ipaddress
import re
import os
import sys
import ssl
import signal
import logging
import logging.handlers
import threading
import queue
import random
import string
import base64
import gzip
import zlib
import uuid
import subprocess
import platform
import traceback
import statistics
import math
import http.server
import socketserver
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdata
import dns.rrset
from collections import defaultdict, deque
from typing import Optional, Dict, List, Tuple, Any, Set
from dataclasses import dataclass, field, asdict
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote
from functools import wraps
from contextlib import asynccontextmanager
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import secrets

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.handlers.RotatingFileHandler(
            '/tmp/honeypot_master.log',
            maxBytes=50*1024*1024,
            backupCount=5
        )
    ]
)

logger = logging.getLogger('HONEYPOT')

BASE_DIR = Path('/tmp/honeypot_data')
BASE_DIR.mkdir(exist_ok=True)
(BASE_DIR / 'sessions').mkdir(exist_ok=True)
(BASE_DIR / 'payloads').mkdir(exist_ok=True)
(BASE_DIR / 'reports').mkdir(exist_ok=True)
(BASE_DIR / 'captures').mkdir(exist_ok=True)
(BASE_DIR / 'keys').mkdir(exist_ok=True, mode=0o700)
(BASE_DIR / 'certs').mkdir(exist_ok=True, mode=0o700)

DB_PATH = BASE_DIR / 'honeypot.db'

CONFIG = {
    'ssh_port': 2222,
    'http_port': 8080,
    'https_port': 8443,
    'ftp_port': 2121,
    'mysql_port': 3306,
    'smtp_port': 2525,
    'telnet_port': 2323,
    'redis_port': 6379,
    'mongodb_port': 27017,
    'rdp_port': 3389,
    'vnc_port': 5900,
    'modbus_port': 502,
    'dns_port': 5353,
    'snmp_port': 1610,
    'api_port': 9090,
    'dashboard_port': 7777,
    'max_connections_per_ip': 50,
    'ban_threshold': 10,
    'session_timeout': 300,
    'fake_hostname': 'prod-server-01',
    'fake_os': 'Ubuntu 20.04.6 LTS',
    'fake_kernel': '5.15.0-91-generic',
    'organization': 'ACME Corp',
    'threat_intel_enabled': True,
    'active_defense_enabled': True,
    'geoip_enabled': False,
    'log_payloads': True,
    'max_session_duration': 600,
    'tarpit_delay': 0.5,
    'banner_delay': 2.0,
    'capture_all_traffic': True,
    'data_retention_days': 90,
    'webhook_url': os.environ.get('WEBHOOK_URL', ''),
    'slack_webhook': os.environ.get('SLACK_WEBHOOK', ''),
    'telegram_token': os.environ.get('TELEGRAM_TOKEN', ''),
    'telegram_chat_id': os.environ.get('TELEGRAM_CHAT_ID', ''),
    'alert_threshold': 70,
    'prometheus_port': 9091,
    'max_sessions_in_memory': 10000,
    'session_cleanup_interval': 300,
}

MITRE_ATTACK_MAP = {
    'SSH_BRUTE_FORCE':      {'technique_id': 'T1110.001', 'technique': 'Brute Force: Password Guessing',          'tactic': 'Credential Access'},
    'SSH_CREDENTIAL_STUFFING': {'technique_id': 'T1110.004', 'technique': 'Brute Force: Credential Stuffing',    'tactic': 'Credential Access'},
    'SSH_AUTH_ATTEMPT':     {'technique_id': 'T1078',     'technique': 'Valid Accounts',                         'tactic': 'Initial Access'},
    'SSH_COMMAND':          {'technique_id': 'T1059.004', 'technique': 'Command and Scripting Interpreter: Unix Shell', 'tactic': 'Execution'},
    'SQL_INJECTION':        {'technique_id': 'T1190',     'technique': 'Exploit Public-Facing Application',      'tactic': 'Initial Access'},
    'XSS':                  {'technique_id': 'T1059.007', 'technique': 'Command and Scripting Interpreter: JavaScript', 'tactic': 'Execution'},
    'LFI_TRAVERSAL':        {'technique_id': 'T1083',     'technique': 'File and Directory Discovery',           'tactic': 'Discovery'},
    'COMMAND_INJECTION':    {'technique_id': 'T1059',     'technique': 'Command and Scripting Interpreter',      'tactic': 'Execution'},
    'SSRF':                 {'technique_id': 'T1090',     'technique': 'Proxy',                                  'tactic': 'Command and Control'},
    'RCE':                  {'technique_id': 'T1203',     'technique': 'Exploitation for Client Execution',      'tactic': 'Execution'},
    'WEBSHELL':             {'technique_id': 'T1505.003', 'technique': 'Server Software Component: Web Shell',   'tactic': 'Persistence'},
    'SCANNER':              {'technique_id': 'T1595',     'technique': 'Active Scanning',                        'tactic': 'Reconnaissance'},
    'CRYPTO_MINING':        {'technique_id': 'T1496',     'technique': 'Resource Hijacking',                     'tactic': 'Impact'},
    'BOTNET':               {'technique_id': 'T1583',     'technique': 'Acquire Infrastructure',                 'tactic': 'Resource Development'},
    'NOSQL_INJECTION':      {'technique_id': 'T1190',     'technique': 'Exploit Public-Facing Application',      'tactic': 'Initial Access'},
    'XXE':                  {'technique_id': 'T1190',     'technique': 'Exploit Public-Facing Application',      'tactic': 'Initial Access'},
    'FTP_AUTH':             {'technique_id': 'T1110.001', 'technique': 'Brute Force: Password Guessing',          'tactic': 'Credential Access'},
    'MYSQL_AUTH':           {'technique_id': 'T1110.001', 'technique': 'Brute Force: Password Guessing',          'tactic': 'Credential Access'},
    'SMTP_AUTH':            {'technique_id': 'T1110.001', 'technique': 'Brute Force: Password Guessing',          'tactic': 'Credential Access'},
    'REDIS_UNAUTH':         {'technique_id': 'T1078.003', 'technique': 'Valid Accounts: Local Accounts',          'tactic': 'Privilege Escalation'},
    'ICS_ATTACK':           {'technique_id': 'T0855',     'technique': 'Unauthorized Command Message',            'tactic': 'Impair Process Control'},
    'DNS_TUNNELING':        {'technique_id': 'T1071.004', 'technique': 'Application Layer Protocol: DNS',         'tactic': 'Command and Control'},
    'SNMP_ENUM':            {'technique_id': 'T1046',     'technique': 'Network Service Discovery',               'tactic': 'Discovery'},
    'LARGE_PAYLOAD':        {'technique_id': 'T1499',     'technique': 'Endpoint Denial of Service',              'tactic': 'Impact'},
    'BINARY_PAYLOAD':       {'technique_id': 'T1027',     'technique': 'Obfuscated Files or Information',         'tactic': 'Defense Evasion'},
}

KNOWN_MALICIOUS_PATTERNS = [
    r'union\s+select', r'or\s+1=1', r'drop\s+table', r'insert\s+into',
    r'exec\s*\(', r'eval\s*\(', r'base64_decode', r'system\s*\(',
    r'passthru\s*\(', r'shell_exec', r'phpinfo\s*\(', r'<script',
    r'javascript:', r'vbscript:', r'onload=', r'onerror=',
    r'\.\./', r'etc/passwd', r'etc/shadow', r'proc/self',
    r'cmd\.exe', r'powershell', r'wget\s+http', r'curl\s+http',
    r'nc\s+-', r'netcat', r'chmod\s+777', r'rm\s+-rf',
    r'mkfifo', r'/bin/sh', r'/bin/bash', r'bash\s+-i',
    r'python\s+-c', r'perl\s+-e', r'ruby\s+-e',
    r'AAAAAAA{20,}', r'\x00', r'%00',
]

FAKE_FILES = {
    '/etc/passwd': 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nadmin:x:1000:1000:Admin User:/home/admin:/bin/bash\ndeployment:x:1001:1001:Deploy:/home/deployment:/bin/bash\n',
    '/etc/hostname': 'prod-server-01\n',
    '/etc/issue': 'Ubuntu 20.04.6 LTS \\n \\l\n',
    '/proc/version': 'Linux version 5.15.0-91-generic (buildd@lcy02-amd64-059) (gcc (Ubuntu 9.4.0-1ubuntu1~20.04.2) 9.4.0, GNU ld (GNU Binutils for Ubuntu) 2.34) #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023\n',
    '/proc/cpuinfo': 'processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 85\nmodel name\t: Intel(R) Xeon(R) Gold 6154 CPU @ 3.00GHz\nstepping\t: 4\nmicrocode\t: 0x2006e05\ncpu MHz\t\t: 3000.000\ncache size\t: 25344 KB\n',
    '/etc/crontab': '# /etc/crontab: system-wide crontab\nSHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n17 * * * *\troot\tcd / && run-parts --report /etc/cron.hourly\n25 6\t* * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n0 2\t* * *\tdeployment\t/opt/backup/backup.sh\n',
    '/var/www/html/config.php': '<?php\n$db_host = "localhost";\n$db_user = "webapp";\n$db_pass = "S3cur3P@ssw0rd2024!";\n$db_name = "production_db";\n$secret_key = "8f4a2b9c3d7e1f6a5b8c2d4e7f9a1b3c";\n?>\n',
    '/.env': 'APP_ENV=production\nAPP_KEY=base64:Xj8K2mN9pQ3rS6tU1vW4xY7zA0bC5dE\nDB_HOST=172.16.0.50\nDB_DATABASE=acme_prod\nDB_USERNAME=acmeuser\nDB_PASSWORD=Acm3C0rp$2024!\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nAWS_DEFAULT_REGION=us-east-1\nMAIL_PASSWORD=smtp_honey_trap_2024\nSTRIPE_SECRET=sk_live_FAKE_KEY_HONEYPOT_TRAP\n',
    '/root/.ssh/id_rsa': '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA2a2rwplBQLzHONEYPOT_FAKE_KEY_DO_NOT_USE\n-----END RSA PRIVATE KEY-----\n',
    '/backup/db_dump.sql': '-- MySQL dump 10.13  Distrib 8.0.33\n-- Host: localhost    Database: production_db\nCREATE TABLE users (\n  id int NOT NULL AUTO_INCREMENT,\n  username varchar(255) NOT NULL,\n  password_hash varchar(255) NOT NULL,\n  email varchar(255) NOT NULL,\n  role enum("admin","user") DEFAULT "user",\n  PRIMARY KEY (id)\n);\nINSERT INTO users VALUES (1,"admin","$2b$12$FAKEHASH","admin@acmecorp.com","admin");\n',
}

FAKE_PROCESSES = [
    'root         1  0.0  0.1 169432 13444 ?        Ss   Jan10   0:14 /sbin/init splash',
    'root       428  0.0  0.3  47448 26744 ?        Ss   Jan10   0:00 /lib/systemd/systemd-journald',
    'root       579  0.0  0.1  22528  5696 ?        Ss   Jan10   0:00 /usr/sbin/cron -f',
    'root       612  0.0  0.2  15844 17344 ?        Ss   Jan10   0:00 sshd: /usr/sbin/sshd -D [listener]',
    'mysql      789  0.0  2.4 1823872 198432 ?      Sl   Jan10   0:42 /usr/sbin/mysqld',
    'www-data   890  0.0  0.5 205112 44832 ?        S    Jan10   0:00 /usr/sbin/apache2 -k start',
    'deploy    1024  0.0  1.2 721344 98432 ?        Sl   09:00   0:33 node /opt/app/server.js',
    'redis     1100  0.0  0.1  61452  9876 ?        Ssl  Jan10   0:08 redis-server 127.0.0.1:6379',
]

FAKE_NETWORK = [
    'tcp  0  0 0.0.0.0:22       0.0.0.0:*    LISTEN  612/sshd',
    'tcp  0  0 0.0.0.0:80       0.0.0.0:*    LISTEN  890/apache2',
    'tcp  0  0 0.0.0.0:443      0.0.0.0:*    LISTEN  890/apache2',
    'tcp  0  0 127.0.0.1:3306   0.0.0.0:*    LISTEN  789/mysqld',
    'tcp  0  0 127.0.0.1:6379   0.0.0.0:*    LISTEN  1100/redis-server',
    'tcp  0  0 0.0.0.0:3000     0.0.0.0:*    LISTEN  1024/node',
]

SSH_COMMANDS = {
    'id': 'uid=0(root) gid=0(root) groups=0(root)\n',
    'whoami': 'root\n',
    'hostname': f'{CONFIG["fake_hostname"]}\n',
    'uname -a': f'Linux {CONFIG["fake_hostname"]} {CONFIG["fake_kernel"]} #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\n',
    'uname -r': f'{CONFIG["fake_kernel"]}\n',
    'uname': 'Linux\n',
    'pwd': '/root\n',
    'ls': 'total 48\ndrwx------  5 root root 4096 Jan 10 09:23 .\ndrwxr-xr-x 20 root root 4096 Jan 10 08:00 ..\n-rw-------  1 root root 1234 Jan 10 09:23 .bash_history\n-rw-r--r--  1 root root 3106 Dec 19 08:24 .bashrc\ndrwxr-xr-x  2 root root 4096 Jan 10 09:00 .ssh\ndrwxr-xr-x  3 root root 4096 Jan  5 14:22 backup\n-rw-r--r--  1 root root 2048 Jan  8 11:30 deploy_keys.txt\n-rw-------  1 root root 1024 Jan  9 16:45 secrets.txt\n',
    'ls -la': 'total 48\ndrwx------  5 root root 4096 Jan 10 09:23 .\ndrwxr-xr-x 20 root root 4096 Jan 10 08:00 ..\n-rw-------  1 root root 1234 Jan 10 09:23 .bash_history\n-rw-r--r--  1 root root 3106 Dec 19 08:24 .bashrc\ndrwxr-xr-x  2 root root 4096 Jan 10 09:00 .ssh\ndrwxr-xr-x  3 root root 4096 Jan  5 14:22 backup\n-rw-r--r--  1 root root 2048 Jan  8 11:30 deploy_keys.txt\n-rw-------  1 root root 1024 Jan  9 16:45 secrets.txt\n',
    'ps aux': '\n'.join(['USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND'] + FAKE_PROCESSES) + '\n',
    'ps -ef': '\n'.join(['UID        PID  PPID  C STIME TTY          TIME CMD'] + FAKE_PROCESSES) + '\n',
    'netstat -an': '\n'.join(['Active Internet connections (servers and established)', 'Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program'] + FAKE_NETWORK) + '\n',
    'netstat -tulnp': '\n'.join(['Active Internet connections (only servers)', 'Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program'] + FAKE_NETWORK[:6]) + '\n',
    'ss -tulnp': '\n'.join(['Netid  State   Recv-Q Send-Q  Local Address:Port   Peer Address:Port'] + FAKE_NETWORK[:6]) + '\n',
    'ifconfig': 'eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 172.16.0.10  netmask 255.255.0.0  broadcast 172.16.255.255\n        ether 00:16:3e:9a:12:34  txqueuelen 1000  (Ethernet)\nlo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n        inet 127.0.0.1  netmask 255.0.0.0\n',
    'ip a': '1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n    inet 127.0.0.1/8 scope host lo\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP\n    link/ether 00:16:3e:9a:12:34 brd ff:ff:ff:ff:ff:ff\n    inet 172.16.0.10/16 brd 172.16.255.255 scope global eth0\n',
    'ip route': 'default via 172.16.0.1 dev eth0 proto dhcp src 172.16.0.10 metric 100\n172.16.0.0/16 dev eth0 proto kernel scope link src 172.16.0.10\n',
    'df -h': 'Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        50G   23G   25G  48% /\ntmpfs           2.0G     0  2.0G   0% /dev/shm\n/dev/sdb1       500G  312G  188G  63% /data\n',
    'free -h': '               total        used        free      shared  buff/cache   available\nMem:            7.8G        3.2G        1.1G        234M        3.5G        4.1G\nSwap:           2.0G        128M        1.9G\n',
    'uptime': ' 09:23:45 up 30 days,  2:15,  1 user,  load average: 0.23, 0.45, 0.51\n',
    'w': ' 09:23:45 up 30 days,  2:15,  1 user,  load average: 0.23, 0.45, 0.51\nUSER     TTY      FROM             LOGIN@   IDLE JCPU   PCPU WHAT\nroot     pts/0    10.0.0.55        09:23    0.00s  0.01s  0.00s w\n',
    'last': 'root     pts/0        10.0.0.55        Thu Jan 10 09:23   still logged in\nroot     pts/1        185.220.101.12   Wed Jan  9 22:45 - 23:12  (00:27)\nadmin    pts/2        192.168.1.100    Tue Jan  8 14:22 - 14:55  (00:33)\n',
    'history': '    1  ls -la\n    2  cd /var/www\n    3  cat config.php\n    4  mysql -u root -p\n    5  cd /root\n    6  cat secrets.txt\n    7  nano deploy_keys.txt\n    8  systemctl status nginx\n    9  tail -f /var/log/syslog\n   10  w\n',
    'cat /etc/passwd': FAKE_FILES['/etc/passwd'],
    'cat /etc/hostname': FAKE_FILES['/etc/hostname'],
    'cat /proc/version': FAKE_FILES['/proc/version'],
    'cat /etc/crontab': FAKE_FILES['/etc/crontab'],
    'cat /root/secrets.txt': 'AWS_KEY=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nDB_ROOT_PASS=Acm3C0rp$2024!\nAPIKEY_PROD=sk_live_HONEYPOT_FAKE_KEY_4829x\nVPN_PASS=VpnAccess2024!\n',
    'cat /root/deploy_keys.txt': 'DEPLOYMENT KEY REGISTRY - CONFIDENTIAL\n\nStaging: deploy_staging_key_8f4a2b9c\nProduction: deploy_prod_key_3d7e1f6a\nDocker Registry: docker_reg_token_5b8c2d4e\nGitLab CI Token: glpat-HONEYPOT_FAKE_TOKEN\n',
    'cat /.env': FAKE_FILES['/.env'],
    'env': 'SHELL=/bin/bash\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nHOME=/root\nUSER=root\nDB_PASS=Acm3C0rp$2024!\nSECRET_KEY=8f4a2b9c3d7e1f6a\nAWS_KEY=AKIAIOSFODNN7EXAMPLE\n',
    'crontab -l': '# Deployment cron\n0 2 * * * /opt/backup/backup.sh >> /var/log/backup.log 2>&1\n*/5 * * * * /usr/local/bin/health_check.sh\n',
    'sudo -l': 'Matching Defaults entries for root on prod-server-01:\n    env_reset, mail_badpass\nUser root may run the following commands on prod-server-01:\n    (ALL : ALL) ALL\n',
    'lsb_release -a': 'No LSB modules are available.\nDistributor ID:\tUbuntu\nDescription:\tUbuntu 20.04.6 LTS\nRelease:\t20.04\nCodename:\tfocal\n',
    'cat /etc/os-release': 'NAME="Ubuntu"\nVERSION="20.04.6 LTS (Focal Fossa)"\nID=ubuntu\nPRETTY_NAME="Ubuntu 20.04.6 LTS"\nVERSION_ID="20.04"\n',
    'date': f'{datetime.datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y")}\n',
    'which python': '/usr/bin/python\n',
    'which python3': '/usr/bin/python3\n',
    'which perl': '/usr/bin/perl\n',
    'which nc': '/bin/nc\n',
    'which wget': '/usr/bin/wget\n',
    'which curl': '/usr/bin/curl\n',
    'dpkg -l': 'ii  apache2         2.4.41-4ubuntu3.15  amd64  Apache HTTP Server\nii  mysql-server    8.0.33-0ubuntu0.20.04.2  amd64  MySQL database server\nii  openssh-server  1:8.2p1-4ubuntu0.11  amd64  secure shell server\nii  python3         3.8.10-0ubuntu1~20.04  amd64  Python 3\n',
    'find / -perm -4000 2>/dev/null': '/usr/bin/sudo\n/usr/bin/passwd\n/usr/bin/chsh\n/usr/bin/newgrp\n/bin/su\n/bin/mount\n/bin/ping\n',
}

PROMETHEUS_METRICS = {}
PROMETHEUS_LOCK = threading.Lock()

def prometheus_inc(metric: str, labels: dict = None, value: float = 1.0):
    with PROMETHEUS_LOCK:
        key = metric + (str(sorted(labels.items())) if labels else '')
        PROMETHEUS_METRICS[key] = PROMETHEUS_METRICS.get(key, 0) + value

def prometheus_set(metric: str, value: float, labels: dict = None):
    with PROMETHEUS_LOCK:
        key = metric + (str(sorted(labels.items())) if labels else '')
        PROMETHEUS_METRICS[key] = value

def generate_prometheus_output() -> str:
    lines = []
    with PROMETHEUS_LOCK:
        for key, value in PROMETHEUS_METRICS.items():
            safe_key = re.sub(r'[^a-zA-Z0-9_]', '_', key)
            lines.append(f'honeypot_{safe_key} {value}')
    return '\n'.join(lines) + '\n'

def sanitize_log_input(text: str, max_length: int = 512) -> str:
    if not text:
        return ''
    sanitized = re.sub(r'[\r\n\t]', ' ', text)
    sanitized = re.sub(r'[^\x20-\x7E]', '?', sanitized)
    return sanitized[:max_length]

def validate_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return parsed.scheme in ('http', 'https') and bool(parsed.netloc)
    except Exception:
        return False

def anonymize_ip(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            parts = ip.split('.')
            return f'{parts[0]}.{parts[1]}.{parts[2]}.xxx'
        else:
            parts = ip.split(':')
            if len(parts) >= 4:
                return f'{parts[0]}:{parts[1]}:{parts[2]}:{parts[3]}:xxxx:xxxx:xxxx:xxxx'
            return ip[:ip.rfind(':')] + ':xxxx'
    except Exception:
        return 'xxx.xxx.xxx.xxx'

def generate_self_signed_cert(cert_path: Path, key_path: Path, hostname: str = 'prod-server-01'):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    with open(key_path, 'wb') as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    os.chmod(key_path, 0o600)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'California'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'ACME Corp'),
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname), x509.DNSName('localhost')]), critical=False)
        .sign(key, hashes.SHA256(), default_backend())
    )
    with open(cert_path, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(cert_path, 0o644)


@dataclass
class AttackEvent:
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    ip_address: str = ''
    ip_anonymized: str = ''
    port: int = 0
    protocol: str = ''
    session_id: str = ''
    event_type: str = ''
    payload: str = ''
    username: str = ''
    password: str = ''
    command: str = ''
    user_agent: str = ''
    url: str = ''
    method: str = ''
    headers: Dict = field(default_factory=dict)
    threat_score: int = 0
    flags: List[str] = field(default_factory=list)
    mitre_techniques: List[Dict] = field(default_factory=list)
    country: str = 'Unknown'
    asn: str = 'Unknown'
    is_tor: bool = False
    is_vpn: bool = False
    raw_data: str = ''

    def __post_init__(self):
        if self.ip_address and not self.ip_anonymized:
            self.ip_anonymized = anonymize_ip(self.ip_address)


@dataclass
class AttackerProfile:
    ip_address: str
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    event_count: int = 0
    threat_score: int = 0
    protocols: List[str] = field(default_factory=list)
    usernames_tried: List[str] = field(default_factory=list)
    passwords_tried: List[str] = field(default_factory=list)
    commands_executed: List[str] = field(default_factory=list)
    payloads: List[str] = field(default_factory=list)
    mitre_techniques_seen: List[str] = field(default_factory=list)
    is_banned: bool = False
    ban_reason: str = ''
    flags: List[str] = field(default_factory=list)


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
        message = f'🚨 HONEYPOT ALERT\nType: {alert_type}\nIP: {anonymize_ip(ip)}\nScore: {threat_score}/100\nDetails: {details[:200]}'
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


class ThreatIntelligence:
    def __init__(self, db: DatabaseManager):
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


class ActiveDefense:
    def __init__(self, db: DatabaseManager, intel: ThreatIntelligence, alerts: AlertManager):
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


class SessionManager:
    def __init__(self, db: DatabaseManager):
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


def _build_event(ip, port, protocol, session_id, event_type, intel, sessions, **kwargs) -> Tuple[AttackEvent, AttackerProfile, int]:
    payload = kwargs.get('payload', '')
    flags = intel.analyze_payload(payload) if payload else []
    flags += kwargs.get('extra_flags', [])
    mitre = intel.map_mitre_techniques(flags, event_type)
    event = AttackEvent(
        ip_address=ip, port=port, protocol=protocol,
        session_id=session_id, event_type=event_type,
        flags=flags, mitre_techniques=mitre,
        **{k: v for k, v in kwargs.items() if k not in ('payload', 'extra_flags')}
    )
    if payload:
        event.payload = payload
    profile = sessions.get_or_create_profile(ip)
    score = intel.calculate_threat_score(event, profile)
    event.threat_score = score
    return event, profile, score


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
                return f'● {service}.service\r\n   Loaded: loaded (/lib/systemd/system/{service}.service; enabled)\r\n   Active: active (running)\r\n'
            return ''
        first_word = cmd.split()[0] if cmd.split() else ''
        return f'-bash: {sanitize_log_input(first_word, 50)}: command not found\r\n' if first_word else ''

    def eof_received(self):
        self.sessions.end_session(self._session_id, 'eof')


class HTTPHoneypot:
    def __init__(self, db, intel, defense, sessions, alerts):
        self.db = db
        self.intel = intel
        self.defense = defense
        self.sessions = sessions
        self.alerts = alerts
        self.app = aiohttp.web.Application(middlewares=[self._logging_middleware])
        self._setup_routes()

    def _setup_routes(self):
        paths = [
            ('/admin', self._handle_admin),
            ('/admin/', self._handle_admin),
            ('/wp-admin', self._handle_wordpress),
            ('/wp-admin/', self._handle_wordpress),
            ('/wp-login.php', self._handle_wordpress_login),
            ('/wp-config.php', self._handle_config_file),
            ('/phpmyadmin', self._handle_phpmyadmin),
            ('/phpmyadmin/', self._handle_phpmyadmin),
            ('/.env', self._handle_env_file),
            ('/config.php', self._handle_config_file),
            ('/login', self._handle_login),
            ('/api/v1/users', self._handle_api_users),
            ('/api/v1/admin', self._handle_api_admin),
            ('/api/v1/config', self._handle_api_config),
            ('/api/v2/users', self._handle_api_users),
            ('/graphql', self._handle_graphql),
            ('/actuator', self._handle_actuator),
            ('/actuator/env', self._handle_actuator_env),
            ('/actuator/health', self._handle_actuator_health),
            ('/actuator/metrics', self._handle_actuator_metrics),
            ('/.git/config', self._handle_git_config),
            ('/backup.sql', self._handle_backup),
            ('/db_backup.sql', self._handle_backup),
            ('/dump.sql', self._handle_backup),
            ('/shell.php', self._handle_webshell),
            ('/c99.php', self._handle_webshell),
            ('/r57.php', self._handle_webshell),
            ('/setup.php', self._handle_setup),
            ('/install.php', self._handle_setup),
            ('/server-status', self._handle_server_status),
        ]
        for path, handler in paths:
            for method in ('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'):
                self.app.router.add_route(method, path, handler)
        self.app.router.add_get('/ws', self._handle_websocket)
        self.app.router.add_get('/socket.io/', self._handle_websocket)
        self.app.router.add_route('*', '/{path_info:.*}', self._handle_catch_all)

    async def _handle_websocket(self, request):
        ws = aiohttp.web.WebSocketResponse()
        await ws.prepare(request)
        ip = request.get('attacker_ip', request.remote)
        session_id = request.get('session_id', '')
        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                ev, prof, score = _build_event(
                    ip, CONFIG['http_port'], 'WS', session_id, 'WS_MESSAGE',
                    self.intel, self.sessions, payload=msg.data[:4096]
                )
                self.db.log_event(ev)
                self.sessions.update_profile(ip, ev, score)
            elif msg.type == aiohttp.WSMsgType.ERROR:
                break
        return ws

    @aiohttp.web.middleware
    async def _logging_middleware(self, request, handler):
        ip = request.remote
        if self.defense.is_banned(ip):
            return aiohttp.web.Response(status=403, text='Forbidden')
        if self.defense.is_rate_limited(ip):
            return aiohttp.web.Response(status=429, text='Too Many Requests')
        self.defense.record_connection(ip)
        session_id = self.sessions.create_session(ip, 'HTTP')
        body = b''
        try:
            body = await asyncio.wait_for(request.read(), timeout=10)
        except Exception:
            pass
        payload = (str(request.url) + ' ' + body.decode('utf-8', errors='replace'))[:8192]
        event, profile, score = _build_event(
            ip, CONFIG['http_port'], 'HTTP', session_id, 'HTTP_REQUEST',
            self.intel, self.sessions,
            url=str(request.url), method=request.method,
            user_agent=request.headers.get('User-Agent', ''),
            headers=dict(request.headers),
            payload=payload
        )
        self.db.log_event(event)
        self.sessions.update_profile(ip, event, score)
        logger.info(f'HTTP {request.method} {request.path} | {anonymize_ip(ip)} | score={score} | flags={event.flags}')
        if score >= CONFIG['alert_threshold']:
            asyncio.ensure_future(self.alerts.send_alert(
                ip, f'HTTP_{event.flags[0] if event.flags else "ATTACK"}', score,
                f'{request.method} {request.path}'
            ))
        request['session_id'] = session_id
        request['attacker_ip'] = ip
        response = await handler(request)
        response.headers['Server'] = 'Apache/2.4.41 (Ubuntu)'
        response.headers['X-Powered-By'] = 'PHP/7.4.3'
        self.sessions.end_session(session_id, 'completed')
        return response

    async def _handle_admin(self, request):
        html = '''<!DOCTYPE html><html><head><title>Admin Panel - ACME Corp</title></head><body><h1>Administration Panel</h1><form method="POST" action="/admin/login"><p>Username: <input type="text" name="username"></p><p>Password: <input type="password" name="password"></p><input type="submit" value="Login"></form></body></html>'''
        return aiohttp.web.Response(text=html, content_type='text/html')

    async def _handle_wordpress(self, request):
        html = '''<!DOCTYPE html><html><head><title>WordPress Admin</title></head><body id="login-page"><div id="login"><h1>ACME Corp</h1><form name="loginform" method="POST" action="/wp-login.php"><input type="text" name="log" placeholder="Username"><br><input type="password" name="pwd" placeholder="Password"><br><input type="submit" name="wp-submit" value="Log In"><input type="hidden" name="redirect_to" value="/wp-admin/"><input type="hidden" name="testcookie" value="1"></form></div></body></html>'''
        return aiohttp.web.Response(text=html, content_type='text/html')

    async def _handle_wordpress_login(self, request):
        if request.method == 'POST':
            try:
                data = await asyncio.wait_for(request.post(), timeout=5)
            except Exception:
                data = {}
            username = sanitize_log_input(data.get('log', ''), 64)
            password = data.get('pwd', '')
            ip = request.get('attacker_ip', request.remote)
            self.db.log_credentials(ip, 'HTTP_WP', username, password, request.get('session_id', ''))
            logger.info(f'WP LOGIN | {anonymize_ip(ip)} | user={username}')
            return aiohttp.web.Response(text='Invalid username.', content_type='text/html')
        return await self._handle_wordpress(request)

    async def _handle_phpmyadmin(self, request):
        if request.method == 'POST':
            try:
                data = await asyncio.wait_for(request.post(), timeout=5)
            except Exception:
                data = {}
            username = sanitize_log_input(data.get('pma_username', ''), 64)
            password = data.get('pma_password', '')
            ip = request.get('attacker_ip', request.remote)
            self.db.log_credentials(ip, 'HTTP_PMA', username, password, request.get('session_id', ''))
        html = '''<!DOCTYPE html><html><head><title>phpMyAdmin</title></head><body><h1>phpMyAdmin 5.2.1</h1><form method="POST"><p>Username: <input name="pma_username"></p><p>Password: <input type="password" name="pma_password"></p><input type="submit" value="Go"></form></body></html>'''
        return aiohttp.web.Response(text=html, content_type='text/html')

    async def _handle_env_file(self, request):
        return aiohttp.web.Response(text=FAKE_FILES['/.env'], content_type='text/plain')

    async def _handle_config_file(self, request):
        return aiohttp.web.Response(text=FAKE_FILES['/var/www/html/config.php'], content_type='text/plain')

    async def _handle_git_config(self, request):
        git_config = '[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n[remote "origin"]\n\turl = https://gitlab.acmecorp.com/backend/production.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n'
        return aiohttp.web.Response(text=git_config, content_type='text/plain')

    async def _handle_backup(self, request):
        return aiohttp.web.Response(text=FAKE_FILES['/backup/db_dump.sql'], content_type='text/plain')

    async def _handle_webshell(self, request):
        return aiohttp.web.Response(text='<html><body><p>404 Not Found</p></body></html>', content_type='text/html', status=404)

    async def _handle_setup(self, request):
        return aiohttp.web.Response(text='<html><head><title>Setup</title></head><body><h1>Installation Complete</h1><p><a href="/admin">Go to Admin Panel</a></p></body></html>', content_type='text/html')

    async def _handle_login(self, request):
        if request.method == 'POST':
            try:
                data = await asyncio.wait_for(request.post(), timeout=5)
            except Exception:
                data = {}
            username = sanitize_log_input(data.get('username', data.get('email', '')), 64)
            password = data.get('password', data.get('pass', ''))
            ip = request.get('attacker_ip', request.remote)
            self.db.log_credentials(ip, 'HTTP_LOGIN', username, password, request.get('session_id', ''))
            return aiohttp.web.Response(text='{"error":"Invalid credentials"}', content_type='application/json', status=401)
        return aiohttp.web.Response(text='<html><body><form method="POST"><input type="text" name="username" placeholder="Username"><br><input type="password" name="password" placeholder="Password"><br><button type="submit">Login</button></form></body></html>', content_type='text/html')

    async def _handle_api_users(self, request):
        fake_users = {'users': [
            {'id': 1, 'username': 'admin', 'email': 'admin@acmecorp.com', 'role': 'administrator'},
            {'id': 2, 'username': 'john.doe', 'email': 'john@acmecorp.com', 'role': 'user'},
            {'id': 4, 'username': 'deployment_bot', 'email': 'deploy@acmecorp.com', 'role': 'service', 'api_key': 'HONEYPOT_FAKE_KEY_7f3a9b2c'},
        ], 'total': 3}
        return aiohttp.web.Response(text=json.dumps(fake_users), content_type='application/json')

    async def _handle_api_admin(self, request):
        return aiohttp.web.Response(text=json.dumps({'error': 'Unauthorized', 'required_role': 'administrator'}), content_type='application/json', status=401)

    async def _handle_api_config(self, request):
        return aiohttp.web.Response(text=json.dumps({'database': {'host': '172.16.0.50', 'port': 3306, 'name': 'acme_prod'}, 'redis': {'host': '127.0.0.1', 'port': 6379}, 'version': '2.4.1'}), content_type='application/json')

    async def _handle_graphql(self, request):
        if request.method == 'POST':
            try:
                body = await asyncio.wait_for(request.read(), timeout=5)
                payload = body.decode('utf-8', errors='replace')
                ip = request.get('attacker_ip', request.remote)
                logger.info(f'GraphQL | {anonymize_ip(ip)} | {sanitize_log_input(payload[:200])}')
            except Exception:
                pass
        introspection = {'data': {'__schema': {'types': [{'name': 'User', 'fields': [{'name': 'id'}, {'name': 'username'}, {'name': 'password'}, {'name': 'apiKey'}]}]}}}
        return aiohttp.web.Response(text=json.dumps(introspection), content_type='application/json')

    async def _handle_actuator(self, request):
        data = {'_links': {'self': {'href': '/actuator'}, 'env': {'href': '/actuator/env'}, 'health': {'href': '/actuator/health'}, 'heapdump': {'href': '/actuator/heapdump'}}}
        return aiohttp.web.Response(text=json.dumps(data), content_type='application/json')

    async def _handle_actuator_env(self, request):
        data = {'propertySources': [{'name': 'applicationConfig', 'properties': {'spring.datasource.url': {'value': 'jdbc:mysql://172.16.0.50:3306/acme_prod'}, 'aws.access.key': {'value': 'AKIAIOSFODNN7EXAMPLE'}, 'aws.secret.key': {'value': '******'}}}]}
        return aiohttp.web.Response(text=json.dumps(data), content_type='application/json')

    async def _handle_actuator_health(self, request):
        return aiohttp.web.Response(text='{"status":"UP","components":{"db":{"status":"UP"},"redis":{"status":"UP"}}}', content_type='application/json')

    async def _handle_actuator_metrics(self, request):
        return aiohttp.web.Response(text=json.dumps({'names': ['jvm.memory.used', 'http.server.requests', 'process.cpu.usage']}), content_type='application/json')

    async def _handle_server_status(self, request):
        html = f'<html><head><title>Apache Status</title></head><body><h1>Apache Server Status for prod-server-01</h1><p>Server Version: Apache/2.4.41 (Ubuntu)</p><p>Current Time: {datetime.datetime.now()}</p><p>Server Uptime: 30 days 2 hours</p><p>Total Accesses: 2847651</p></body></html>'
        return aiohttp.web.Response(text=html, content_type='text/html')

    async def _handle_catch_all(self, request):
        path = request.path
        scan_paths = {
            '/robots.txt': 'User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /.env\n',
            '/sitemap.xml': '<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://acmecorp.com/</loc></url></urlset>',
            '/.htaccess': 'Options -Indexes\nServerSignature Off\n',
        }
        if path in scan_paths:
            return aiohttp.web.Response(text=scan_paths[path], content_type='text/plain')
        return aiohttp.web.Response(
            text='<html><body><h1>404 Not Found</h1><address>Apache/2.4.41 (Ubuntu) Server at prod-server-01 Port 80</address></body></html>',
            content_type='text/html', status=404)


class FTPHoneypot:
    def __init__(self, db, intel, defense, sessions, alerts):
        self.db = db
        self.intel = intel
        self.defense = defense
        self.sessions = sessions
        self.alerts = alerts

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        ip = writer.get_extra_info('peername')[0]
        if self.defense.is_banned(ip):
            writer.close()
            return
        session_id = self.sessions.create_session(ip, 'FTP')
        self.defense.record_connection(ip)
        event = AttackEvent(ip_address=ip, port=CONFIG['ftp_port'], protocol='FTP', session_id=session_id, event_type='CONNECTION')
        self.db.log_event(event)
        logger.info(f'FTP connection from {anonymize_ip(ip)}')
        await asyncio.sleep(CONFIG['banner_delay'])
        writer.write(b'220 Microsoft FTP Service\r\n')
        await writer.drain()
        username = ''
        try:
            while True:
                try:
                    line = await asyncio.wait_for(reader.readline(), timeout=30)
                except asyncio.TimeoutError:
                    break
                if not line:
                    break
                cmd_line = line.decode('utf-8', errors='replace').strip()
                if not cmd_line:
                    continue
                parts = cmd_line.split(' ', 1)
                cmd = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ''
                logger.info(f'FTP CMD | {anonymize_ip(ip)} | {sanitize_log_input(cmd_line, 100)!r}')
                if cmd == 'USER':
                    username = sanitize_log_input(arg, 64)
                    writer.write(b'331 Password required\r\n')
                elif cmd == 'PASS':
                    self.db.log_credentials(ip, 'FTP', username, arg, session_id)
                    ev, profile, score = _build_event(ip, CONFIG['ftp_port'], 'FTP', session_id, 'AUTH_PASS',
                                                      self.intel, self.sessions,
                                                      username=username, password=arg, extra_flags=['FTP_AUTH'])
                    self.db.log_event(ev)
                    self.sessions.update_profile(ip, ev, score)
                    logger.info(f'FTP AUTH | {anonymize_ip(ip)} | user={username} | score={score}')
                    if score >= CONFIG['alert_threshold']:
                        asyncio.ensure_future(self.alerts.send_alert(ip, 'FTP_BRUTE_FORCE', score, f'User: {username}'))
                    if username == 'anonymous' or (username == 'admin' and arg in ['admin', 'password', '12345']):
                        writer.write(b'230 User logged in\r\n')
                    else:
                        writer.write(b'530 Login incorrect\r\n')
                elif cmd == 'SYST':
                    writer.write(b'215 Windows_NT\r\n')
                elif cmd == 'FEAT':
                    writer.write(b'211-Extensions supported:\r\n SIZE\r\n MDTM\r\n PASV\r\n211 END\r\n')
                elif cmd == 'PWD':
                    writer.write(b'257 "/" is current directory\r\n')
                elif cmd in ('LIST', 'NLST'):
                    writer.write(b'150 Opening ASCII mode data connection\r\n226 Transfer complete\r\n')
                elif cmd == 'CWD':
                    writer.write(b'250 CWD command successful\r\n')
                elif cmd == 'TYPE':
                    writer.write(b'200 Type set\r\n')
                elif cmd == 'PASV':
                    writer.write(b'227 Entering Passive Mode (127,0,0,1,19,136)\r\n')
                elif cmd == 'RETR':
                    ev2 = AttackEvent(ip_address=ip, port=CONFIG['ftp_port'], protocol='FTP', session_id=session_id, event_type='FILE_RETR', command=sanitize_log_input(arg, 256))
                    self.db.log_event(ev2)
                    writer.write(b'550 File not found\r\n')
                elif cmd == 'STOR':
                    ev2 = AttackEvent(ip_address=ip, port=CONFIG['ftp_port'], protocol='FTP', session_id=session_id, event_type='FILE_STOR', command=sanitize_log_input(arg, 256))
                    self.db.log_event(ev2)
                    writer.write(b'550 Permission denied\r\n')
                elif cmd == 'QUIT':
                    writer.write(b'221 Goodbye\r\n')
                    break
                else:
                    writer.write(b'500 Unknown command\r\n')
                await writer.drain()
        except Exception as e:
            logger.debug(f'FTP session error {anonymize_ip(ip)}: {e}')
        finally:
            self.sessions.end_session(session_id, 'disconnected')
            try:
                writer.close()
            except Exception:
                pass


class MySQLHoneypot:
    GREETING_PACKET = (
        b'\x4a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x33\x33\x00'
        b'\x01\x00\x00\x00\x6b\x4c\x67\x73\x73\x46\x37\x00'
        b'\xff\xf7\x08\x02\x00\xff\x81\x15\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x5b\x7e\x46\x7a\x39\x61'
        b'\x7e\x72\x53\x59\x57\x76\x00\xff\xff\xff\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x00\x00\x00\x00'
    )
    AUTH_ERROR = b'\x17\x00\x00\x02\xff\x15\x04\x23\x32\x38\x30\x30\x30\x41\x63\x63\x65\x73\x73\x20\x64\x65\x6e\x69\x65\x64'

    def __init__(self, db, intel, defense, sessions, alerts):
        self.db = db
        self.intel = intel
        self.defense = defense
        self.sessions = sessions
        self.alerts = alerts

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        ip = writer.get_extra_info('peername')[0]
        session_id = self.sessions.create_session(ip, 'MYSQL')
        self.defense.record_connection(ip)
        event = AttackEvent(ip_address=ip, port=CONFIG['mysql_port'], protocol='MYSQL', session_id=session_id, event_type='CONNECTION')
        self.db.log_event(event)
        logger.info(f'MySQL connection from {anonymize_ip(ip)}')
        try:
            writer.write(self.GREETING_PACKET)
            await writer.drain()
            try:
                auth_data = await asyncio.wait_for(reader.read(4096), timeout=30)
                if auth_data and len(auth_data) > 36:
                    username_start = 36
                    username_end = auth_data.find(b'\x00', username_start)
                    username = auth_data[username_start:username_end].decode('utf-8', errors='replace') if username_end > username_start else 'unknown'
                    username = sanitize_log_input(username, 64)
                    self.db.log_credentials(ip, 'MYSQL', username, '', session_id)
                    ev, profile, score = _build_event(ip, CONFIG['mysql_port'], 'MYSQL', session_id, 'AUTH_ATTEMPT',
                                                      self.intel, self.sessions, username=username, extra_flags=['MYSQL_AUTH'])
                    self.db.log_event(ev)
                    self.sessions.update_profile(ip, ev, score)
                    logger.info(f'MySQL AUTH | {anonymize_ip(ip)} | user={username} | score={score}')
                    if score >= CONFIG['alert_threshold']:
                        asyncio.ensure_future(self.alerts.send_alert(ip, 'MYSQL_BRUTE_FORCE', score, f'User: {username}'))
            except asyncio.TimeoutError:
                pass
            writer.write(self.AUTH_ERROR)
            await writer.drain()
        except Exception as e:
            logger.debug(f'MySQL session error {anonymize_ip(ip)}: {e}')
        finally:
            self.sessions.end_session(session_id, 'disconnected')
            try:
                writer.close()
            except Exception:
                pass


class SMTPHoneypot:
    def __init__(self, db, intel, defense, sessions, alerts):
        self.db = db
        self.intel = intel
        self.defense = defense
        self.sessions = sessions
        self.alerts = alerts

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        ip = writer.get_extra_info('peername')[0]
        session_id = self.sessions.create_session(ip, 'SMTP')
        self.defense.record_connection(ip)
        event = AttackEvent(ip_address=ip, port=CONFIG['smtp_port'], protocol='SMTP', session_id=session_id, event_type='CONNECTION')
        self.db.log_event(event)
        logger.info(f'SMTP connection from {anonymize_ip(ip)}')
        try:
            writer.write(b'220 mail.acmecorp.com ESMTP Postfix\r\n')
            await writer.drain()
            mail_from = ''
            data_buffer = []
            in_data = False
            while True:
                try:
                    line = await asyncio.wait_for(reader.readline(), timeout=60)
                except asyncio.TimeoutError:
                    break
                if not line:
                    break
                decoded = line.decode('utf-8', errors='replace').strip()
                if in_data:
                    if decoded == '.':
                        in_data = False
                        full_email = '\n'.join(data_buffer)
                        ev, profile, score = _build_event(ip, CONFIG['smtp_port'], 'SMTP', session_id, 'MAIL_DATA',
                                                          self.intel, self.sessions, payload=full_email[:4096])
                        self.db.log_event(ev)
                        writer.write(b'250 Message accepted\r\n')
                        data_buffer = []
                    else:
                        data_buffer.append(decoded)
                    await writer.drain()
                    continue
                cmd_upper = decoded.upper()
                if cmd_upper.startswith(('EHLO', 'HELO')):
                    writer.write(b'250-mail.acmecorp.com Hello\r\n250-SIZE 10485760\r\n250-AUTH LOGIN PLAIN\r\n250 OK\r\n')
                elif cmd_upper.startswith('AUTH'):
                    parts = decoded.split()
                    if len(parts) >= 3 and parts[1].upper() == 'PLAIN':
                        try:
                            creds = base64.b64decode(parts[2]).decode('utf-8', errors='replace')
                            cred_parts = creds.split('\x00')
                            username = sanitize_log_input(cred_parts[1] if len(cred_parts) > 1 else '', 64)
                            password = cred_parts[2] if len(cred_parts) > 2 else ''
                            self.db.log_credentials(ip, 'SMTP', username, password, session_id)
                            logger.info(f'SMTP AUTH | {anonymize_ip(ip)} | user={username}')
                        except Exception:
                            pass
                    writer.write(b'535 Authentication credentials invalid\r\n')
                elif cmd_upper.startswith('MAIL FROM'):
                    mail_from = sanitize_log_input(decoded, 256)
                    writer.write(b'250 OK\r\n')
                elif cmd_upper.startswith('RCPT TO'):
                    writer.write(b'250 OK\r\n')
                elif cmd_upper == 'DATA':
                    in_data = True
                    writer.write(b'354 Start input; end with <CRLF>.<CRLF>\r\n')
                elif cmd_upper == 'QUIT':
                    writer.write(b'221 Bye\r\n')
                    break
                elif cmd_upper in ('NOOP', 'RSET'):
                    mail_from = ''
                    writer.write(b'250 OK\r\n')
                else:
                    writer.write(b'500 Unknown command\r\n')
                await writer.drain()
        except Exception as e:
            logger.debug(f'SMTP session error {anonymize_ip(ip)}: {e}')
        finally:
            self.sessions.end_session(session_id, 'disconnected')
            try:
                writer.close()
            except Exception:
                pass


class RedisHoneypot:
    def __init__(self, db, intel, defense, sessions, alerts):
        self.db = db
        self.intel = intel
        self.defense = defense
        self.sessions = sessions
        self.alerts = alerts

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        ip = writer.get_extra_info('peername')[0]
        session_id = self.sessions.create_session(ip, 'REDIS')
        self.defense.record_connection(ip)
        event = AttackEvent(ip_address=ip, port=CONFIG['redis_port'], protocol='REDIS', session_id=session_id, event_type='CONNECTION')
        self.db.log_event(event)
        logger.info(f'Redis connection from {anonymize_ip(ip)}')
        writer.write(b'+PONG\r\n')
        await writer.drain()
        try:
            while True:
                try:
                    line = await asyncio.wait_for(reader.readline(), timeout=30)
                except asyncio.TimeoutError:
                    break
                if not line:
                    break
                decoded = line.decode('utf-8', errors='replace').strip()
                if not decoded:
                    continue
                safe_cmd = sanitize_log_input(decoded, 256)
                ev, profile, score = _build_event(ip, CONFIG['redis_port'], 'REDIS', session_id, 'COMMAND',
                                                  self.intel, self.sessions,
                                                  command=decoded, payload=decoded, extra_flags=['REDIS_UNAUTH'])
                self.db.log_event(ev)
                self.sessions.update_profile(ip, ev, score)
                logger.info(f'Redis CMD | {anonymize_ip(ip)} | {safe_cmd!r} | score={score}')
                if score >= CONFIG['alert_threshold']:
                    asyncio.ensure_future(self.alerts.send_alert(ip, 'REDIS_ATTACK', score, f'CMD: {safe_cmd[:50]}'))
                cmd_upper = decoded.upper().split()[0] if decoded.split() else ''
                if cmd_upper == 'INFO':
                    writer.write(b'$472\r\n# Server\r\nredis_version:7.0.8\r\nos:Linux 5.15.0-91-generic x86_64\r\ntcp_port:6379\r\n# Replication\r\nrole:master\r\n# Keyspace\r\ndb0:keys=127,expires=14\r\n\r\n')
                elif cmd_upper == 'CONFIG':
                    writer.write(b'*2\r\n$3\r\ndir\r\n$4\r\n/var\r\n')
                elif cmd_upper == 'QUIT':
                    writer.write(b'+OK\r\n')
                    break
                else:
                    writer.write(b'+OK\r\n')
                await writer.drain()
        except Exception as e:
            logger.debug(f'Redis session error {anonymize_ip(ip)}: {e}')
        finally:
            self.sessions.end_session(session_id, 'disconnected')
            try:
                writer.close()
            except Exception:
                pass


class ModbusHoneypot:
    def __init__(self, db, intel, defense, sessions, alerts):
        self.db = db
        self.intel = intel
        self.defense = defense
        self.sessions = sessions
        self.alerts = alerts

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        ip = writer.get_extra_info('peername')[0]
        session_id = self.sessions.create_session(ip, 'MODBUS')
        self.defense.record_connection(ip)
        event = AttackEvent(ip_address=ip, port=CONFIG['modbus_port'], protocol='MODBUS', session_id=session_id, event_type='CONNECTION', extra_flags=['ICS_ATTACK'])
        event.flags = ['ICS_ATTACK']
        event.mitre_techniques = MITRE_ATTACK_MAP.get('ICS_ATTACK', {}) and [MITRE_ATTACK_MAP['ICS_ATTACK']]
        event.threat_score = 80
        self.db.log_event(event)
        logger.warning(f'MODBUS/ICS connection from {anonymize_ip(ip)} - INDUSTRIAL HONEYPOT')
        asyncio.ensure_future(self.alerts.send_alert(ip, 'ICS_ATTACK', 80, 'Modbus/ICS connection attempt'))
        try:
            while True:
                try:
                    header = await asyncio.wait_for(reader.read(6), timeout=30)
                except asyncio.TimeoutError:
                    break
                if not header or len(header) < 6:
                    break
                transaction_id = header[0:2]
                protocol_id = header[2:4]
                length = struct.unpack('>H', header[4:6])[0]
                if length > 256:
                    break
                try:
                    pdu = await asyncio.wait_for(reader.read(length), timeout=10)
                except asyncio.TimeoutError:
                    break
                if not pdu:
                    break
                func_code = pdu[1] if len(pdu) > 1 else 0
                raw_hex = (header + pdu).hex()
                ev = AttackEvent(ip_address=ip, port=CONFIG['modbus_port'], protocol='MODBUS',
                                session_id=session_id, event_type='MODBUS_REQUEST',
                                command=f'FUNC_CODE={func_code}', raw_data=raw_hex,
                                flags=['ICS_ATTACK'], threat_score=80,
                                mitre_techniques=[MITRE_ATTACK_MAP['ICS_ATTACK']])
                self.db.log_event(ev)
                logger.warning(f'MODBUS | {anonymize_ip(ip)} | func_code={func_code} | data={raw_hex}')
                response = transaction_id + protocol_id + b'\x00\x03' + bytes([pdu[0], func_code + 0x80, 0x01])
                writer.write(response)
                await writer.drain()
        except Exception as e:
            logger.debug(f'Modbus session error {anonymize_ip(ip)}: {e}')
        finally:
            self.sessions.end_session(session_id, 'disconnected')
            try:
                writer.close()
            except Exception:
                pass


class DNSHoneypot:
    def __init__(self, db, intel, defense, sessions, alerts):
        self.db = db
        self.intel = intel
        self.defense = defense
        self.sessions = sessions
        self.alerts = alerts

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        ip = writer.get_extra_info('peername')[0]
        session_id = self.sessions.create_session(ip, 'DNS')
        self.defense.record_connection(ip)
        logger.info(f'DNS connection from {anonymize_ip(ip)}')
        try:
            while True:
                try:
                    length_data = await asyncio.wait_for(reader.read(2), timeout=15)
                    if len(length_data) < 2:
                        break
                    msg_len = struct.unpack('!H', length_data)[0]
                    if msg_len > 512:
                        break
                    data = await asyncio.wait_for(reader.read(msg_len), timeout=10)
                    if not data:
                        break
                except asyncio.TimeoutError:
                    break
                try:
                    query = dns.message.from_wire(data)
                    qname = str(query.question[0].name) if query.question else 'unknown'
                    flags = []
                    if len(qname) > 30 or qname.count('.') > 5:
                        flags.append('DNS_TUNNELING')
                    ev, profile, score = _build_event(
                        ip, CONFIG['dns_port'], 'DNS', session_id, 'DNS_QUERY',
                        self.intel, self.sessions,
                        command=sanitize_log_input(qname, 256),
                        payload=qname,
                        extra_flags=flags + ['SNMP_ENUM']
                    )
                    self.db.log_event(ev)
                    self.sessions.update_profile(ip, ev, score)
                    logger.info(f'DNS QUERY | {anonymize_ip(ip)} | {sanitize_log_input(qname, 100)} | score={score}')
                    if score >= CONFIG['alert_threshold']:
                        asyncio.ensure_future(self.alerts.send_alert(ip, 'DNS_TUNNELING', score, f'Query: {qname[:50]}'))
                    response = dns.message.make_response(query)
                    response.flags |= dns.flags.AA
                    response_wire = response.to_wire()
                    writer.write(struct.pack('!H', len(response_wire)) + response_wire)
                    await writer.drain()
                except Exception:
                    break
        except Exception as e:
            logger.debug(f'DNS session error {anonymize_ip(ip)}: {e}')
        finally:
            self.sessions.end_session(session_id, 'disconnected')
            try:
                writer.close()
            except Exception:
                pass

    async def handle_udp(self, data: bytes, addr: tuple):
        ip = addr[0]
        try:
            query = dns.message.from_wire(data)
            qname = str(query.question[0].name) if query.question else 'unknown'
            session_id = self.sessions.create_session(ip, 'DNS_UDP')
            flags = ['DNS_TUNNELING'] if (len(qname) > 30 or qname.count('.') > 5) else []
            ev, profile, score = _build_event(
                ip, CONFIG['dns_port'], 'DNS', session_id, 'DNS_QUERY_UDP',
                self.intel, self.sessions,
                command=sanitize_log_input(qname, 256),
                payload=qname, extra_flags=flags
            )
            self.db.log_event(ev)
            self.sessions.update_profile(ip, ev, score)
            logger.info(f'DNS UDP | {anonymize_ip(ip)} | {sanitize_log_input(qname, 100)} | score={score}')
        except Exception:
            pass


class SNMPHoneypot:
    def __init__(self, db, intel, defense, sessions, alerts):
        self.db = db
        self.intel = intel
        self.defense = defense
        self.sessions = sessions
        self.alerts = alerts

    async def handle_udp(self, data: bytes, addr: tuple):
        ip = addr[0]
        if self.defense.is_banned(ip):
            return
        session_id = self.sessions.create_session(ip, 'SNMP')
        ev, profile, score = _build_event(
            ip, CONFIG['snmp_port'], 'SNMP', session_id, 'SNMP_REQUEST',
            self.intel, self.sessions,
            raw_data=data[:512].hex(),
            payload=data.decode('latin-1', errors='replace')[:256],
            extra_flags=['SNMP_ENUM']
        )
        self.db.log_event(ev)
        self.sessions.update_profile(ip, ev, score)
        logger.info(f'SNMP UDP | {anonymize_ip(ip)} | {len(data)} bytes | score={score}')
        if score >= CONFIG['alert_threshold']:
            asyncio.ensure_future(self.alerts.send_alert(ip, 'SNMP_ENUMERATION', score, f'{len(data)} bytes'))


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


class HealthMonitor:
    def __init__(self, db: DatabaseManager, sessions: SessionManager, defense: ActiveDefense):
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


class DashboardServer:
    def __init__(self, db, intel, defense, sessions, alerts, health_monitor):
        self.db = db
        self.intel = intel
        self.defense = defense
        self.sessions = sessions
        self.alerts = alerts
        self.health = health_monitor
        self.app = aiohttp.web.Application()
        self._setup_routes()

    def _setup_routes(self):
        self.app.router.add_get('/', self._handle_dashboard)
        self.app.router.add_get('/api/stats', self._handle_stats)
        self.app.router.add_get('/api/events', self._handle_events)
        self.app.router.add_get('/api/attackers', self._handle_attackers)
        self.app.router.add_get('/api/credentials', self._handle_credentials)
        self.app.router.add_get('/api/health', self._handle_health)
        self.app.router.add_get('/api/mitre', self._handle_mitre)
        self.app.router.add_get('/metrics', self._handle_prometheus)
        self.app.router.add_post('/api/ban', self._handle_ban)
        self.app.router.add_post('/api/unban', self._handle_unban)
        self.app.router.add_get('/api/export/json', self._handle_export_json)
        self.app.router.add_get('/api/export/stix', self._handle_export_stix)

    async def _handle_dashboard(self, request):
        stats = self.db.get_stats()
        active_sessions = len(self.sessions.active_sessions)
        banned_count = len(self.defense.banned_ips)
        mitre_techniques = set()
        for t in MITRE_ATTACK_MAP.values():
            mitre_techniques.add(t['tactic'])
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HONEYPOT COMMAND CENTER</title>
<style>
:root{{--bg:#0a0e1a;--surface:#111827;--border:#1e293b;--accent:#00ff88;--danger:#ff3366;--warning:#ffaa00;--text:#e2e8f0;--muted:#64748b;--font:'Courier New',monospace}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:var(--bg);color:var(--text);font-family:var(--font);overflow-x:hidden}}
.header{{background:var(--surface);border-bottom:1px solid var(--accent);padding:1rem 2rem;display:flex;align-items:center;gap:1rem}}
.header h1{{color:var(--accent);font-size:1.5rem;letter-spacing:.3rem;text-transform:uppercase}}
.status-dot{{width:12px;height:12px;background:var(--accent);border-radius:50%;animation:pulse 1s infinite}}
@keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.3}}}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;padding:2rem}}
.card{{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1.5rem}}
.card.danger{{border-color:var(--danger)}}
.card.warning{{border-color:var(--warning)}}
.card.active{{border-color:var(--accent)}}
.card h3{{color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.1rem;margin-bottom:.5rem}}
.card .value{{font-size:2.5rem;font-weight:bold;color:var(--accent)}}
.card.danger .value{{color:var(--danger)}}
.card.warning .value{{color:var(--warning)}}
.section{{padding:0 2rem 2rem}}
.section h2{{color:var(--accent);margin-bottom:1rem;font-size:1rem;letter-spacing:.2rem;text-transform:uppercase;border-bottom:1px solid var(--border);padding-bottom:.5rem}}
table{{width:100%;border-collapse:collapse;background:var(--surface);border-radius:8px;overflow:hidden;font-size:.85rem}}
th{{background:#1e293b;color:var(--muted);padding:.75rem 1rem;text-align:left;font-size:.75rem;text-transform:uppercase;letter-spacing:.1rem}}
td{{padding:.75rem 1rem;border-bottom:1px solid var(--border);word-break:break-all}}
tr:hover td{{background:#1a2235}}
.badge{{padding:2px 8px;border-radius:4px;font-size:.7rem;font-weight:bold}}
.badge.high{{background:#ff336620;color:var(--danger);border:1px solid var(--danger)}}
.badge.med{{background:#ffaa0020;color:var(--warning);border:1px solid var(--warning)}}
.badge.low{{background:#00ff8820;color:var(--accent);border:1px solid var(--accent)}}
.mitre-tag{{display:inline-block;background:#1e3a5f;color:#60a5fa;border:1px solid #3b82f6;border-radius:4px;padding:1px 6px;font-size:.65rem;margin:1px}}
.nav{{display:flex;gap:1rem;padding:1rem 2rem;background:var(--surface);border-bottom:1px solid var(--border)}}
.nav a{{color:var(--muted);text-decoration:none;font-size:.8rem;letter-spacing:.1rem;text-transform:uppercase;padding:.5rem 1rem;border-radius:4px}}
.nav a:hover{{background:var(--border);color:var(--text)}}
.refresh{{position:fixed;bottom:2rem;right:2rem;background:var(--accent);color:var(--bg);padding:.75rem 1.5rem;border:none;border-radius:4px;cursor:pointer;font-family:var(--font);font-weight:bold;font-size:.85rem;letter-spacing:.1rem}}
</style>
<script>setInterval(()=>location.reload(),15000);</script>
</head>
<body>
<div class="header">
<div class="status-dot"></div>
<h1>Honeypot Command Center</h1>
<span style="margin-left:auto;color:var(--muted);font-size:.85rem;">{datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")}</span>
</div>
<div class="nav">
<a href="/">Dashboard</a>
<a href="/api/stats">Stats JSON</a>
<a href="/api/mitre">MITRE Coverage</a>
<a href="/api/health">Health</a>
<a href="/metrics">Prometheus</a>
<a href="/api/export/json">Export JSON</a>
<a href="/api/export/stix">Export STIX 2.1</a>
</div>
<div class="grid">
<div class="card danger"><h3>Total Events</h3><div class="value">{stats.get("total_events",0):,}</div></div>
<div class="card warning"><h3>Unique Attackers</h3><div class="value">{stats.get("unique_ips",0):,}</div></div>
<div class="card danger"><h3>Captured Credentials</h3><div class="value">{stats.get("total_credentials",0):,}</div></div>
<div class="card"><h3>Banned IPs</h3><div class="value">{banned_count:,}</div></div>
<div class="card active"><h3>Active Sessions</h3><div class="value">{active_sessions:,}</div></div>
<div class="card warning"><h3>MITRE Techniques</h3><div class="value">{len(MITRE_ATTACK_MAP):,}</div></div>
</div>
<div class="section">
<h2>Top Attackers</h2>
<table>
<tr><th>IP (Anonymized)</th><th>Events</th><th>Threat Score</th><th>MITRE Techniques</th><th>Status</th></tr>
{"".join(f'<tr><td>{a["ip_address"]}</td><td>{a["event_count"]}</td><td><span class="badge {"high" if a["threat_score"]>=70 else "med" if a["threat_score"]>=40 else "low"}">{a["threat_score"]}</span></td><td>-</td><td>{"🚫 BANNED" if a["is_banned"] else "👁 Monitored"}</td></tr>' for a in stats.get("top_attackers",[])[:10])}
</table>
</div>
<div class="section">
<h2>Recent Events (with MITRE Mapping)</h2>
<table>
<tr><th>Time</th><th>IP</th><th>Protocol</th><th>Event Type</th><th>Score</th><th>MITRE</th></tr>
{"".join('<tr><td>'+datetime.datetime.fromtimestamp(e["timestamp"]).strftime("%H:%M:%S")+'</td><td>'+str(e["ip_address"])+'</td><td>'+(e["protocol"] or "-")+'</td><td>'+(e["event_type"] or "-")+'</td><td><span class="badge '+ ("high" if e["threat_score"]>=70 else "med" if e["threat_score"]>=40 else "low") +'">'+str(e["threat_score"])+'</span></td><td>'+"".join('<span class="mitre-tag">'+str(t.get("technique_id",""))+'</span>' for t in (json.loads(e["mitre_techniques"]) if e.get("mitre_techniques") else []))+'</td></tr>' for e in stats.get("recent_events",[])[:20])}
</table>
</div>
<div class="section">
<h2>Events by Protocol</h2>
<table>
<tr><th>Protocol</th><th>Event Count</th></tr>
{"".join(f'<tr><td>{proto}</td><td>{count:,}</td></tr>' for proto,count in stats.get("events_by_protocol",{}).items())}
</table>
</div>
<button class="refresh" onclick="location.reload()">↺ REFRESH</button>
</body></html>'''
        return aiohttp.web.Response(text=html, content_type='text/html')

    async def _handle_stats(self, request):
        stats = self.db.get_stats()
        stats['active_sessions'] = len(self.sessions.active_sessions)
        stats['banned_ips_count'] = len(self.defense.banned_ips)
        return aiohttp.web.Response(text=json.dumps(stats, default=str), content_type='application/json')

    async def _handle_events(self, request):
        limit = min(int(request.rel_url.query.get('limit', 100)), 1000)
        offset = max(int(request.rel_url.query.get('offset', 0)), 0)
        ip_filter = request.rel_url.query.get('ip', '')
        proto_filter = request.rel_url.query.get('protocol', '')
        conn = sqlite3.connect(str(self.db.db_path))
        conn.row_factory = sqlite3.Row
        query = 'SELECT * FROM events WHERE 1=1'
        params: list = []
        if ip_filter:
            query += ' AND ip_address=?'
            params.append(sanitize_log_input(ip_filter, 45))
        if proto_filter:
            query += ' AND protocol=?'
            params.append(sanitize_log_input(proto_filter, 20))
        query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?'
        params.extend([limit, offset])
        rows = [dict(r) for r in conn.execute(query, params).fetchall()]
        conn.close()
        return aiohttp.web.Response(text=json.dumps(rows, default=str), content_type='application/json')

    async def _handle_attackers(self, request):
        conn = sqlite3.connect(str(self.db.db_path))
        conn.row_factory = sqlite3.Row
        rows = [dict(r) for r in conn.execute('SELECT * FROM attacker_profiles ORDER BY threat_score DESC LIMIT 100').fetchall()]
        conn.close()
        return aiohttp.web.Response(text=json.dumps(rows, default=str), content_type='application/json')

    async def _handle_credentials(self, request):
        conn = sqlite3.connect(str(self.db.db_path))
        conn.row_factory = sqlite3.Row
        rows = [dict(r) for r in conn.execute('SELECT timestamp, ip_anonymized, protocol, username, LENGTH(password) as pwd_len, session_id FROM captured_credentials ORDER BY timestamp DESC LIMIT 200').fetchall()]
        conn.close()
        return aiohttp.web.Response(text=json.dumps(rows, default=str), content_type='application/json')

    async def _handle_health(self, request):
        health_data = await self.health.check_all()
        overall = 'healthy' if all(v.get('status') == 'healthy' for v in health_data.values()) else 'degraded'
        result = {'status': overall, 'timestamp': datetime.datetime.utcnow().isoformat(), 'checks': health_data}
        status_code = 200 if overall == 'healthy' else 503
        return aiohttp.web.Response(text=json.dumps(result, default=str), content_type='application/json', status=status_code)

    async def _handle_mitre(self, request):
        tactics = defaultdict(list)
        for key, mapping in MITRE_ATTACK_MAP.items():
            tactics[mapping['tactic']].append({
                'trigger_flag': key,
                'technique_id': mapping['technique_id'],
                'technique': mapping['technique'],
            })
        return aiohttp.web.Response(text=json.dumps({'tactics': dict(tactics), 'total_techniques': len(MITRE_ATTACK_MAP)}, indent=2), content_type='application/json')

    async def _handle_prometheus(self, request):
        output = generate_prometheus_output()
        return aiohttp.web.Response(text=output, content_type='text/plain')

    async def _handle_ban(self, request):
        try:
            data = await request.json()
        except Exception:
            return aiohttp.web.Response(text='{"error":"invalid json"}', content_type='application/json', status=400)
        ip = sanitize_log_input(data.get('ip', ''), 45)
        reason = sanitize_log_input(data.get('reason', 'Manual ban'), 256)
        if ip and self.defense.is_valid_ip(ip):
            self.defense.ban_ip(ip, reason)
            profile = self.sessions.get_or_create_profile(ip)
            profile.is_banned = True
            profile.ban_reason = reason
            self.db.upsert_profile(profile)
        return aiohttp.web.Response(text='{"status":"ok"}', content_type='application/json')

    async def _handle_unban(self, request):
        try:
            data = await request.json()
        except Exception:
            return aiohttp.web.Response(text='{"error":"invalid json"}', content_type='application/json', status=400)
        ip = sanitize_log_input(data.get('ip', ''), 45)
        if ip and self.defense.is_valid_ip(ip):
            self.defense.unban_ip(ip)
        return aiohttp.web.Response(text='{"status":"ok"}', content_type='application/json')

    async def _handle_export_json(self, request):
        stats = self.db.get_stats()
        conn = sqlite3.connect(str(self.db.db_path))
        conn.row_factory = sqlite3.Row
        events = [dict(r) for r in conn.execute('SELECT * FROM events ORDER BY timestamp DESC LIMIT 10000').fetchall()]
        credentials = [dict(r) for r in conn.execute('SELECT timestamp, ip_anonymized, protocol, username, session_id FROM captured_credentials ORDER BY timestamp DESC').fetchall()]
        profiles = [dict(r) for r in conn.execute('SELECT * FROM attacker_profiles ORDER BY threat_score DESC').fetchall()]
        conn.close()
        export_data = {
            'export_time': datetime.datetime.now().isoformat(),
            'schema_version': '2.0',
            'mitre_framework_version': 'ATT&CK v14',
            'stats': stats,
            'events': events,
            'credentials': credentials,
            'profiles': profiles,
        }
        filename = f'honeypot_export_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        return aiohttp.web.Response(
            text=json.dumps(export_data, default=str),
            content_type='application/json',
            headers={'Content-Disposition': f'attachment; filename="{filename}"'}
        )

    async def _handle_export_stix(self, request):
        conn = sqlite3.connect(str(self.db.db_path))
        conn.row_factory = sqlite3.Row
        profiles = [dict(r) for r in conn.execute('SELECT * FROM attacker_profiles WHERE threat_score >= 50 ORDER BY threat_score DESC LIMIT 100').fetchall()]
        conn.close()
        stix_bundle = {
            'type': 'bundle',
            'id': f'bundle--{str(uuid.uuid4())}',
            'spec_version': '2.1',
            'objects': []
        }
        for profile in profiles:
            mitre_seen = json.loads(profile.get('mitre_techniques_seen', '[]'))
            indicator = {
                'type': 'indicator',
                'spec_version': '2.1',
                'id': f'indicator--{str(uuid.uuid4())}',
                'created': datetime.datetime.fromtimestamp(profile['first_seen']).isoformat() + 'Z',
                'modified': datetime.datetime.fromtimestamp(profile['last_seen']).isoformat() + 'Z',
                'name': f'Malicious IP (anonymized): {anonymize_ip(profile["ip_address"])}',
                'description': f'Threat score: {profile["threat_score"]}. MITRE techniques observed: {", ".join(mitre_seen)}',
                'pattern': f"[ipv4-addr:value = '{profile['ip_address']}']",
                'pattern_type': 'stix',
                'valid_from': datetime.datetime.fromtimestamp(profile['first_seen']).isoformat() + 'Z',
                'labels': ['malicious-activity'],
                'confidence': min(profile['threat_score'], 100),
                'external_references': [
                    {'source_name': 'mitre-attack', 'external_id': tid}
                    for tid in mitre_seen
                ]
            }
            stix_bundle['objects'].append(indicator)
        filename = f'honeypot_stix_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        return aiohttp.web.Response(
            text=json.dumps(stix_bundle, indent=2),
            content_type='application/json',
            headers={'Content-Disposition': f'attachment; filename="{filename}"'}
        )


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


async def periodic_threat_analysis(db: DatabaseManager, intel: ThreatIntelligence,
                                   defense: ActiveDefense, sessions: SessionManager, alerts: AlertManager):
    while True:
        await asyncio.sleep(60)
        try:
            conn = sqlite3.connect(str(db.db_path))
            conn.row_factory = sqlite3.Row
            high_threat = conn.execute(
                'SELECT ip_address, threat_score, event_count FROM attacker_profiles WHERE is_banned=0 AND threat_score >= 70'
            ).fetchall()
            conn.close()
            for row in high_threat:
                ip = row['ip_address']
                if not defense.is_banned(ip):
                    reason = f'Auto-ban: threat_score={row["threat_score"]}'
                    defense.ban_ip(ip, reason)
                    profile = sessions.get_or_create_profile(ip)
                    profile.is_banned = True
                    profile.ban_reason = reason
                    db.upsert_profile(profile)
                    logger.warning(f'AUTO-BANNED: {anonymize_ip(ip)} (score={row["threat_score"]})')
                    await alerts.send_alert(ip, 'AUTO_BAN', row['threat_score'],
                                           f'Threshold exceeded: score={row["threat_score"]}, events={row["event_count"]}')
        except Exception as e:
            logger.error(f'Periodic analysis error: {e}')


async def periodic_session_cleanup(sessions: SessionManager, defense: ActiveDefense):
    while True:
        await asyncio.sleep(CONFIG['session_cleanup_interval'])
        try:
            sessions.cleanup_sessions()
            sessions.cleanup_profiles()
            defense.cleanup_old_connections()
            logger.debug('Session cleanup completed')
        except Exception as e:
            logger.error(f'Session cleanup error: {e}')


async def periodic_data_retention(db: DatabaseManager):
    while True:
        await asyncio.sleep(86400)
        try:
            db.purge_old_data(CONFIG['data_retention_days'])
        except Exception as e:
            logger.error(f'Data retention error: {e}')


async def periodic_health_check(health: HealthMonitor):
    while True:
        await asyncio.sleep(60)
        try:
            results = await health.check_all()
            all_ok = all(v.get('status') == 'healthy' for v in results.values())
            if not all_ok:
                logger.warning(f'Health check degraded: {results}')
        except Exception as e:
            logger.error(f'Health check error: {e}')


async def periodic_report(db: DatabaseManager):
    while True:
        await asyncio.sleep(3600)
        try:
            stats = db.get_stats()
            report = {
                'report_time': datetime.datetime.now().isoformat(),
                'schema_version': '2.0',
                'summary': stats,
                'mitre_techniques_mapped': len(MITRE_ATTACK_MAP),
            }
            report_path = BASE_DIR / 'reports' / f'hourly_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
            with open(report_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            logger.info(f'Hourly report saved to {report_path}')
        except Exception as e:
            logger.error(f'Report generation error: {e}')


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
