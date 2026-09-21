import asyncio
import datetime
import json
import sqlite3

from .config import BASE_DIR, CONFIG, MITRE_ATTACK_MAP
from .logger import logger
from .utils import anonymize_ip


async def periodic_threat_analysis(db, intel, defense, sessions, alerts):
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


async def periodic_session_cleanup(sessions, defense):
    while True:
        await asyncio.sleep(CONFIG['session_cleanup_interval'])
        try:
            sessions.cleanup_sessions()
            sessions.cleanup_profiles()
            defense.cleanup_old_connections()
            logger.debug('Session cleanup completed')
        except Exception as e:
            logger.error(f'Session cleanup error: {e}')


async def periodic_data_retention(db):
    while True:
        await asyncio.sleep(86400)
        try:
            db.purge_old_data(CONFIG['data_retention_days'])
        except Exception as e:
            logger.error(f'Data retention error: {e}')


async def periodic_health_check(health):
    while True:
        await asyncio.sleep(60)
        try:
            results = await health.check_all()
            all_ok = all(v.get('status') == 'healthy' for v in results.values())
            if not all_ok:
                logger.warning(f'Health check degraded: {results}')
        except Exception as e:
            logger.error(f'Health check error: {e}')


async def periodic_report(db):
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