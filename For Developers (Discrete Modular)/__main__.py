import asyncio
import sys
import traceback

from .logger import logger
from .main import main


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info('Interrupted by user')
    except Exception as e:
        logger.error(f'Fatal error: {e}')
        traceback.print_exc()
        sys.exit(1)