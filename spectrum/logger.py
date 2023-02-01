import logging
import os
from pathlib import Path

parent_dir = Path(__file__).parent.parent
logs_dir = os.path.join(parent_dir, 'logs')
if not os.path.exists(logs_dir): os.mkdir(logs_dir)

def setup_logger(name, log_file, level=logging.INFO):
    formatter = logging.Formatter(' %(levelname)s %(name)s: %(message)s')
    file_handler = logging.FileHandler(log_file)        
    file_handler.setFormatter(formatter)
    stream_handler = logging.StreamHandler()
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    return logger

if __name__ == '__main__':
    print(logs_dir)
