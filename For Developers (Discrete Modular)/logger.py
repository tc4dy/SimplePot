import logging
import logging.handlers
import sys


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