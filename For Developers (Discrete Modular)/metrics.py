import re
import threading


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