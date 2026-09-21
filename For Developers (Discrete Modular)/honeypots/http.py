import asyncio
import datetime
import json
from urllib.parse import urlparse

import aiohttp
import aiohttp.web

from ..config import CONFIG, FAKE_FILES
from ..events import _build_event
from ..logger import logger
from ..utils import anonymize_ip, sanitize_log_input


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