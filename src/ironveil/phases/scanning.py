# Scanning methods
from ..config import COMMON_PORTS, logger
import socket
import random

def check_open_ports(self, subdomain, ip_address, ports=COMMON_PORTS):
    # (Copy from original)
