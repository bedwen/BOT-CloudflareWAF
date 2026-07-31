import logging
import sys
import os

class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    YELLOW = "\033[93m"
    RESET = "\033[0m"

LOG_FILE = "cldbot.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    encoding='utf-8'
)

class Logger:
    @staticmethod
    def success(message):
        print(f"{Colors.GREEN}[✔] {message}{Colors.RESET}")
        logging.info(f"SUCCESS: {message}")

    @staticmethod
    def error(message):
        print(f"{Colors.RED}[X] {message}{Colors.RESET}")
        logging.error(f"ERROR: {message}")

    @staticmethod
    def info(message):
        print(f"{Colors.CYAN}[i] {message}{Colors.RESET}")
        logging.info(f"INFO: {message}")

    @staticmethod
    def warning(message):
        print(f"{Colors.YELLOW}[!] {message}{Colors.RESET}")
        logging.warning(f"WARNING: {message}")

log = Logger()
