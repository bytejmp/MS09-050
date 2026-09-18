import struct
from socket import socket, AF_INET, SOCK_STREAM

from lib.output import info, success, error, warning

SMB1_NEGOTIATE = (
    b"\x00\x00\x00\x90"
    b"\xff\x53\x4d\x42"
    b"\x72"
    b"\x00\x00\x00\x00"
    b"\x18"
    b"\x53\xc8"
    + b"\x00" * 12 +
    b"\xff\xff"
    b"\xfe\xca"
    b"\x00\x00"
    b"\x00\x00"
    b"\x00"
    b"\x62\x00"
    b"\x02NT LANMAN 1.0\x00"
    b"\x02NT LM 0.12\x00"
    b"\x02SMB 2.002\x00"
    b"\x02SMB 2.???\x00"
)

SMB1_SESSION_SETUP = (
    b"\x00\x00\x00\x63"
    b"\xff\x53\x4d\x42"
    b"\x73"
    b"\x00\x00\x00\x00"
    b"\x18"
    b"\x07\xc8"
    + b"\x00" * 12 +
    b"\xff\xff"
    b"\xfe\xca"
    b"\x00\x00"
    b"\x01\x00"
    b"\x0c"
    b"\xff"
    b"\x00"
    b"\x00\x00"
    b"\x04\x11"
    b"\x0a\x00"
    b"\x00\x00"
    b"\x00\x00\x00\x00"
    b"\x01\x00"
    b"\x00\x00\x00\x00"
    b"\x00\x00\x00\x00"
    b"\x20\x00"
    b"\x00"
    + b"\x00" * 15 +
    b"\x57\x00\x69\x00\x6e\x00\x64\x00"
    b"\x6f\x00\x77\x00\x73\x00\x00\x00"
)

VULNERABLE_SIGNATURES = [
    "Windows Vista",
    "Windows Server 2008",
    "Windows 6.0",
]


def _recv_smb(sock, timeout=5):
    sock.settimeout(timeout)
    header = b""
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk:
            return b""
        header += chunk

    length = struct.unpack(">I", header)[0] & 0x00FFFFFF
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            break
        data += chunk

    return header + data


def _extract_os_string(response):
    if len(response) < 40:
        return None

    raw = response[36:]
    try:
        decoded = raw.decode("utf-16-le", errors="ignore")
    except Exception:
        decoded = raw.decode("ascii", errors="ignore")

    for sig in VULNERABLE_SIGNATURES:
        idx = decoded.find(sig[:7])
        if idx != -1:
            end = decoded.find("\x00", idx)
            if end == -1:
                end = min(idx + 60, len(decoded))
            return decoded[idx:end].strip()

    return decoded[:80].strip() if decoded.strip() else None


def _detect_smb2_support(response):
    if len(response) < 8:
        return False
    if response[4:8] == b"\xfeSMB":
        return True
    if response[4:8] == b"\xffSMB" and len(response) > 37:
        dialect_index = struct.unpack("<H", response[37:39])[0]
        if dialect_index >= 2:
            return True
    return False


def _guess_arch_from_os(os_string):
    if not os_string:
        return None
    lower = os_string.lower()
    if "x64" in lower or "64-bit" in lower or "amd64" in lower:
        return "x64"
    if "x86" in lower or "32-bit" in lower or "i386" in lower:
        return "x86"
    if "server 2008" in lower:
        return "x64"
    if "vista" in lower:
        return "x86"
    return None


def check_smb_port(target, port=445, timeout=5):
    try:
        s = socket(AF_INET, SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, port))
        s.close()
        return True
    except (ConnectionRefusedError, TimeoutError, OSError):
        return False


def scan_target(target, port=445, timeout=5):
    result = {
        "reachable": False,
        "smb2": None,
        "os_string": None,
        "arch": None,
        "vulnerable": False,
    }

    info(f"Scanning {target}:{port}...")

    try:
        s = socket(AF_INET, SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, port))
        result["reachable"] = True
    except (ConnectionRefusedError, TimeoutError, OSError) as e:
        error(f"Cannot reach {target}:{port}: {e}")
        return result

    try:
        s.send(SMB1_NEGOTIATE)
        resp = _recv_smb(s, timeout)

        if not resp:
            error("No response to SMB negotiate")
            s.close()
            return result

        result["smb2"] = _detect_smb2_support(resp)

        if resp[4:8] == b"\xffSMB":
            s.send(SMB1_SESSION_SETUP)
            setup_resp = _recv_smb(s, timeout)
            if setup_resp:
                result["os_string"] = _extract_os_string(setup_resp)

        s.close()
    except (OSError, struct.error) as e:
        warning(f"Error during scan: {e}")
        try:
            s.close()
        except OSError:
            pass
        return result

    os_str = result["os_string"] or ""
    for sig in VULNERABLE_SIGNATURES:
        if sig.lower() in os_str.lower():
            result["vulnerable"] = True
            break

    if result["smb2"] and not result["os_string"]:
        result["vulnerable"] = None

    result["arch"] = _guess_arch_from_os(os_str)

    return result


def print_scan_results(result, target):
    if not result["reachable"]:
        error(f"Target {target} not reachable on SMB port")
        return

    success(f"Target {target} is reachable")

    if result["smb2"]:
        success("SMBv2 supported")
    elif result["smb2"] is False:
        warning("SMBv2 not detected, target may not be vulnerable")

    if result["os_string"]:
        info(f"OS: {result['os_string']}")
    else:
        warning("Could not fingerprint OS version")

    if result["arch"]:
        info(f"Architecture: {result['arch']}")
    else:
        warning("Could not determine architecture, use -a to specify manually")

    if result["vulnerable"] is True:
        success("Target appears VULNERABLE to MS09-050")
    elif result["vulnerable"] is False:
        error("Target does not appear vulnerable to MS09-050")
    else:
        warning("Vulnerability status unknown, proceed with caution")
