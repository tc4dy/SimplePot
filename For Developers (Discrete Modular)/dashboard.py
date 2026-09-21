import datetime
import json
import sqlite3
import uuid
from collections import defaultdict

import aiohttp
import aiohttp.web

from .config import MITRE_ATTACK_MAP
from .metrics import generate_prometheus_output
from .utils import anonymize_ip, sanitize_log_input


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
{"".join(f'<tr><td>{a["ip_address"]}</td><td>{a["event_count"]}</td><td><span class="badge {"high" if a["threat_score"]>=70 else "med" if a["threat_score"]>=40 else "low"}">{a["threat_score"]}</span></td><td>-</td><td>{"[-] BANNED" if a["is_banned"] else "[+] Monitored"}</td></tr>' for a in stats.get("top_attackers",[])[:10])}
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
<button class="refresh" onclick="location.reload()">[R] REFRESH</button>
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