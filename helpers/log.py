import logging
import concurrent.futures
import sys

executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)

fmt = '%(asctime)s | %(levelname)3s | [%(filename)s:%(lineno)3d] %(funcName)s() | %(message)s'
datefmt = '%Y-%m-%d %H:%M:%S'  # Date format without milliseconds


class CustomFormatter(logging.Formatter):

    COLOR_CODES = {
        'DEBUG': '\033[36m',  # Cyan
        'INFO': '\033[35m',  # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',  # Red
        'CRITICAL': '\033[41m',  # Red background
        'RESET': '\033[0m'  # Reset to default
    }

    def format(self, record):
        color_code = self.COLOR_CODES.get(record.levelname, self.COLOR_CODES['RESET'])
        record.msg = f"{color_code}{record.msg}{self.COLOR_CODES['RESET']}"
        return super().format(record)


logger = logging.getLogger(__name__)
#logging.basicConfig(level=logging.DEBUG, format=fmt, datefmt=datefmt)
handler = logging.StreamHandler()
handler.setFormatter(CustomFormatter(fmt, datefmt))
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)


def fast_log(msg: str, *args):
    try:
        #sys.stdout.write(f'[INFO] {msg}\n')
        executor.submit(sys.stdout.write, f'[INFO]{msg}\n')
        executor.submit(logger.info, msg, *args)
        #logging.info(msg, exc_info=exc_info)
    except:
        logger.info(str)
    return msg
