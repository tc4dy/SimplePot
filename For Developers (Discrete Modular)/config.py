import datetime
import os
from pathlib import Path


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