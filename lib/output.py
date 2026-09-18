import sys

BANNER = r"""
  __  __ ____   ___  ____        ___  ____   ___
 |  \/  / ___| / _ \/ ___|      / _ \| ___| / _ \
 | |\/| \___ \| | | \___ \ ____| | | |___ \| | | |
 | |  | |___) | |_| |___) |____| |_| |___) | |_| |
 |_|  |_|____/ \___/|____/      \___/|____/ \___/

 CVE-2009-3103 — SMBv2 Remote Code Execution
 by ByteJMP
"""


def info(msg):
    print(f"[*] {msg}")


def success(msg):
    print(f"[+] {msg}")


def error(msg):
    print(f"[-] {msg}")


def warning(msg):
    print(f"[!] {msg}")


def fatal(msg):
    error(msg)
    sys.exit(1)
