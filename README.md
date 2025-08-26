# DarkFTP: FTP Vulnerability Scanner

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

DarkFTP is a Python-based tool designed for ethical hacking and penetration testing. It scans FTP servers that allow anonymous login (e.g., bulk results downloaded from Shodan.io for FTP anonymous login OK targets) to identify vulnerabilities, detect sensitive files/directories, test for root access, privilege escalation, and FTP bounce attacks. The tool assigns a vulnerability score to each target and highlights high-value ones for further investigation.

**Note:** This tool is intended for educational and ethical purposes only. Use it responsibly and with permission on systems you own or have explicit authorization to test. Misuse may violate laws and ethical guidelines.

## Features

- **Anonymous Login Check**: Verifies if anonymous login is successful.
- **OS Detection**: Infers the operating system (Linux/Windows/Unknown) based on the FTP banner.
- **Root/Administrator Access Testing**: Attempts to access and write to privileged directories like `/etc`, `/root`, or `/Windows/System32`.
- **Privilege Escalation Testing**: Checks for writable directories (e.g., `/tmp` or `/inetpub/wwwroot`) and known vulnerable FTP versions.
- **FTP Bounce Vulnerability Detection**: Tests for PORT command exploitation potential.
- **Directory Spidering**: Recursively crawls directories (up to a configurable depth) to find sensitive files (e.g., `passwd`, `shadow`, `.pem`) and directories (e.g., `/etc`, `/root`, `config`).
- **Vulnerability Scoring**: Calculates a score based on findings; targets with score >= 5 are flagged as high-value.
- **Logging and Reporting**: Outputs colored console logs and appends results to `darkftp_report.txt`.
- **High-Value Target Summary**: Lists top-scoring targets at the end of the scan.

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/darkftp.git
   cd darkftp
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

   **requirements.txt** (create this file if needed):
   ```
   argparse
   ftplib
   colorama
   ```

## Usage

Run the script with a file containing a list of IP addresses (one per line). These can be exported from Shodan.io searches for FTP servers with anonymous login enabled (e.g., "ftp anonymous OK").

```
python darkftp.py --file ips.txt
```

- `--file`: Path to the file with IP addresses (required).

### Example

1. Prepare `ips.txt`:
   ```
   192.168.1.100
   10.0.0.5
   ```

2. Run the tool:
   ```
   python darkftp.py --file ips.txt
   ```

3. Output will include per-IP scans with colored indicators (green for success, red for alerts, yellow for info). High-value targets are summarized at the end.

## How It Works

1. **Input**: Reads IPs from the provided file.
2. **Scanning**:
   - Connects via anonymous login.
   - Detects OS from FTP banner.
   - Lists initial directory and checks for sensitive items.
   - Tests root access by attempting CWD, LIST, and STOR in privileged dirs.
   - Checks privilege escalation via writable exec dirs and vulnerable versions.
   - Tests FTP bounce with PORT command.
   - Spiders directories recursively to depth 3, alerting on sensitive finds.
3. **Scoring**: Accumulates points (e.g., +5 for root access, +4 for escalation, +3 for bounce, +2 per sensitive item).
4. **Output**: Console logs, file report, and high-value summary.

## Configuration

- **Sensitive Dirs/Files**: Customize `SENSITIVE_DIRS` and `SENSITIVE_FILES` in the script.
- **Vulnerable Versions**: Update `VULNERABLE_VERSIONS` dictionary as needed.
- **Max Spider Depth**: Adjust `max_depth` in `spider_directories` (default: 3).
- **Test Dirs**: Modify `LINUX_ROOT_TEST_DIRS`, `WINDOWS_ROOT_TEST_DIRS`, etc., for OS-specific testing.

## Requirements

- Python 3.6+
- Libraries: `ftplib` (standard), `colorama`, `argparse` (standard)
- No external packages beyond those in requirements.txt
- Tested on Linux/Windows; cross-platform compatible via colorama.

## Disclaimer

This tool is for ethical penetration testing only. The author is not responsible for any misuse or damage caused. Always obtain permission before scanning any systems. Scanning without authorization may be illegal in your jurisdiction.

## Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss.

## License

MIT License - see [LICENSE](LICENSE) for details.
