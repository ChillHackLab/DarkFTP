import argparse
import ftplib
import colorama
from colorama import Fore, Style
import sys
import io
import time
import os  # For path normalization

# Initialize colorama for cross-platform colored output
colorama.init()

# Define sensitive directories and files
SENSITIVE_DIRS = [
    '/etc', '/var', '/root', '/home', '/proc', '/sys',
    '/Windows', '/Program Files', '/inetpub', '/Windows/System32',
    '/Windows/System32/config', 'admin', 'backup', 'config', 'secrets', 'private'
]
SENSITIVE_FILES = [
    'passwd', 'shadow', 'config', 'system', 'credentials', 'passwords',
    'key', '.key', '.pem', '.conf', '.bak'
]

# Define directories to test for root access - separated by OS
LINUX_ROOT_TEST_DIRS = ['/etc', '/root']
WINDOWS_ROOT_TEST_DIRS = ['/Windows/System32', '/Windows']

# Define directories for executable file upload (privilege escalation) - separated by OS
LINUX_EXEC_TEST_DIRS = ['/tmp']
WINDOWS_EXEC_TEST_DIRS = ['/inetpub/wwwroot']

# Known vulnerable FTP versions
VULNERABLE_VERSIONS = {
    'Microsoft FTP Service 5.0': ['CVE-2009-3023', 'Potential remote code execution'],
    'Pure-FTPd 1.0.36': ['CVE-2011-0411', 'Directory traversal'],
    'ProFTPD 1.3.5e': ['CVE-2011-4130', 'Directory traversal']
}

def detect_os(version):
    """Detect OS based on FTP version banner."""
    if 'Microsoft' in version or 'Windows' in version:
        return 'windows'
    elif 'Pure-FTPd' in version or 'ProFTPD' in version or 'vsftpd' in version:
        return 'linux'
    return 'unknown'

def test_ftp_bounce(ftp, ip):
    """Test for FTP Bounce attack vulnerability."""
    bounce_vulnerable = False
    print(f"{Fore.CYAN}[*] Testing FTP Bounce for {ip}...{Style.RESET_ALL}")
    try:
        # Test if PORT command is accepted
        ftp.sendcmd('PORT 127,0,0,1,0,80')
        print(f"{Fore.RED}[!] FTP Bounce POSSIBLE: PORT command accepted{Style.RESET_ALL}")
        bounce_vulnerable = True
        # Attempt dummy bounce to a known open port (e.g., 80)
        test_file = 'bounce_test.txt'
        test_content = io.BytesIO(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        ftp.storbinary(f'STOR {test_file}', test_content)
        try:
            ftp.sendcmd('RETR bounce_test.txt')
            print(f"{Fore.RED}[!] FTP Bounce CONFIRMED: Can send arbitrary requests (server-side enabled){Style.RESET_ALL}")
        except ftplib.error_perm as e:
            if '553' in str(e) or 'Permission denied' in str(e):
                print(f"{Fore.YELLOW}[-] RETR failed for FTP Bounce test: Permission denied (likely server-side restriction){Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[-] RETR failed for FTP Bounce test: {e} (possibly firewall blocked){Style.RESET_ALL}")
        except TimeoutError:
            print(f"{Fore.YELLOW}[-] Timeout during RETR for FTP Bounce test (possibly firewall blocked){Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}[-] Error during RETR for FTP Bounce test: {e} (possibly firewall or network issue){Style.RESET_ALL}")
        ftp.delete(test_file)
    except ftplib.error_perm as e:
        if '500' in str(e) or 'Command not understood' in str(e):
            print(f"{Fore.YELLOW}[-] PORT command not supported (server-side disabled){Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[-] PORT command failed: {e} (possibly permission denied or firewall blocked){Style.RESET_ALL}")
    except TimeoutError:
        print(f"{Fore.YELLOW}[-] Timeout during FTP Bounce test (possibly firewall blocked){Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.YELLOW}[-] Error testing FTP Bounce: {e}{Style.RESET_ALL}")
    return bounce_vulnerable

def test_privilege_escalation(ftp, ip, os_type):
    """Test for potential privilege escalation vulnerabilities."""
    escalation_possible = False
    print(f"{Fore.CYAN}[*] Testing privilege escalation for {ip}...{Style.RESET_ALL}")
    try:
        version = ftp.sendcmd('HELP')
        print(f"{Fore.YELLOW}[-] Server version info: {version}{Style.RESET_ALL}")
        for vuln_version, vuln_info in VULNERABLE_VERSIONS.items():
            if vuln_version.lower() in version.lower():
                escalation_possible = True
                print(f"{Fore.RED}[!] VULNERABLE VERSION DETECTED: {vuln_version} - {vuln_info}{Style.RESET_ALL}")
    except ftplib.error_perm as e:
        print(f"{Fore.YELLOW}[-] Could not retrieve version (permission error): {e}{Style.RESET_ALL}")
    except TimeoutError:
        print(f"{Fore.YELLOW}[-] Timeout retrieving version{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.YELLOW}[-] Could not retrieve version: {e}{Style.RESET_ALL}")

    exec_test_dirs = LINUX_EXEC_TEST_DIRS if os_type == 'linux' else WINDOWS_EXEC_TEST_DIRS if os_type == 'windows' else EXEC_TEST_DIRS
    for test_dir in exec_test_dirs:
        try:
            # Separate CWD and LIST
            ftp.cwd(test_dir)
            print(f"{Fore.GREEN}[+] Successfully changed to {test_dir}{Style.RESET_ALL}")
            dir_list = []
            ftp.dir(dir_list.append)
            if dir_list:
                print(f"{Fore.RED}[!] Can list {test_dir}:{Style.RESET_ALL}")
                for line in dir_list:
                    print(f"{Fore.RED}    {line}{Style.RESET_ALL}")
            test_file = 'test_exec' + ('.asp' if 'inetpub' in test_dir else '.sh')
            test_content = io.BytesIO(b"<% Response.Write('Test') %>" if 'inetpub' in test_dir else b"#!/bin/bash\necho Test")
            try:
                ftp.storbinary(f'STOR {test_dir}/{test_file}', test_content)
                escalation_possible = True
                print(f"{Fore.RED}[!] PRIVILEGE ESCALATION POSSIBLE: Successfully wrote {test_file} to {test_dir}{Style.RESET_ALL}")
                try:
                    ftp.delete(f'{test_dir}/{test_file}')
                    print(f"{Fore.GREEN}[-] Cleaned up: Deleted {test_file} from {test_dir}{Style.RESET_ALL}")
                except ftplib.error_perm as e:
                    print(f"{Fore.YELLOW}[-] Warning: Could not delete {test_file} from {test_dir} (permission error): {e}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.YELLOW}[-] Warning: Could not delete {test_file} from {test_dir}: {e}{Style.RESET_ALL}")
            except ftplib.error_perm as e:
                print(f"{Fore.YELLOW}[-] Write test failed for {test_dir}: Permission denied ({e}){Style.RESET_ALL}")
            except TimeoutError:
                print(f"{Fore.YELLOW}[-] Timeout during write test for {test_dir}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.YELLOW}[-] Write test failed for {test_dir}: {e}{Style.RESET_ALL}")
        except ftplib.error_perm as e:
            if '550' in str(e) or 'No such file or directory' in str(e):
                print(f"{Fore.YELLOW}[-] {test_dir} does not exist{Style.RESET_ALL}")
            elif '553' in str(e) or 'Permission denied' in str(e):
                print(f"{Fore.YELLOW}[-] {test_dir} exists but permission denied ({e}){Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[-] Cannot access {test_dir}: {e}{Style.RESET_ALL}")
        except TimeoutError:
            print(f"{Fore.YELLOW}[-] Timeout accessing {test_dir}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}[-] Error testing {test_dir}: {e}{Style.RESET_ALL}")
    return escalation_possible

def spider_directories(ftp, ip, current_dir='/', depth=0, max_depth=3, visited=set()):
    """Recursively spider all directories and files."""
    sensitive_items = []
    if depth > max_depth:
        print(f"{Fore.YELLOW}[-] Max depth ({max_depth}) reached at {current_dir}{Style.RESET_ALL}")
        return sensitive_items
    try:
        normalized_dir = os.path.normpath(current_dir)
        if normalized_dir in visited:
            print(f"{Fore.YELLOW}[-] Skipping already visited: {normalized_dir}{Style.RESET_ALL}")
            return sensitive_items
        visited.add(normalized_dir)
        print(f"{Fore.YELLOW}[*] Spidering {normalized_dir} (depth {depth})...{Style.RESET_ALL}")
        ftp.cwd(normalized_dir)
        items = []
        ftp.retrlines('NLST', items.append)
        for item in items:
            item_path = os.path.normpath(os.path.join(normalized_dir, item))
            try:
                ftp.cwd(item_path)
                print(f"{Fore.YELLOW}Dir: {item_path}{Style.RESET_ALL}")
                for sensitive_dir in SENSITIVE_DIRS:
                    if sensitive_dir.lower() in item.lower():
                        sensitive_items.append(f"Dir: {item_path}")
                        print(f"{Fore.RED}[!] ALERT: Sensitive directory found: {item}{Style.RESET_ALL}")
                sensitive_items.extend(spider_directories(ftp, ip, item_path, depth + 1, max_depth, visited))
                ftp.cwd(normalized_dir)
            except ftplib.error_perm as e:
                if '550' in str(e) or 'Not a directory' in str(e) or 'No such file or directory' in str(e):
                    print(f"{Fore.YELLOW}File: {item_path}{Style.RESET_ALL}")
                    for sensitive_file in SENSITIVE_FILES:
                        if sensitive_file.lower() in item.lower():
                            sensitive_items.append(f"File: {item_path}")
                            print(f"{Fore.RED}[!] ALERT: Sensitive file found: {item}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.YELLOW}[-] Cannot access {item_path}: {e}{Style.RESET_ALL}")
            except TimeoutError:
                print(f"{Fore.YELLOW}[-] Timeout accessing {item_path}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.YELLOW}[-] Error accessing {item_path}: {e}{Style.RESET_ALL}")
    except ftplib.error_perm as e:
        if '550' in str(e) or 'No such file or directory' in str(e):
            print(f"{Fore.YELLOW}[-] {normalized_dir} does not exist{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[-] Cannot access {normalized_dir}: Permission denied ({e}){Style.RESET_ALL}")
    except TimeoutError:
        print(f"{Fore.YELLOW}[-] Timeout accessing {normalized_dir}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.YELLOW}[-] Error spidering {normalized_dir}: {e}{Style.RESET_ALL}")
    return sensitive_items

def test_root_access(ftp, ip, os_type):
    """Test for root/Administrator access."""
    root_access = False
    print(f"{Fore.CYAN}[*] Testing root access for {ip}...{Style.RESET_ALL}")
    root_test_dirs = LINUX_ROOT_TEST_DIRS if os_type == 'linux' else WINDOWS_ROOT_TEST_DIRS if os_type == 'windows' else ROOT_TEST_DIRS
    for test_dir in root_test_dirs:
        try:
            # Separate CWD and LIST
            ftp.cwd(test_dir)
            print(f"{Fore.GREEN}[+] Successfully changed to {test_dir}{Style.RESET_ALL}")
            dir_list = []
            ftp.dir(dir_list.append)
            if dir_list:
                root_access = True
                print(f"{Fore.RED}[!] ROOT/ADMIN ACCESS CONFIRMED: Can list {test_dir}:{Style.RESET_ALL}")
                for line in dir_list:
                    print(f"{Fore.RED}    {line}{Style.RESET_ALL}")
            test_file = 'test_root.txt'
            test_content = io.BytesIO(b"Test for root access")
            try:
                ftp.storbinary(f'STOR {test_dir}/{test_file}', test_content)
                root_access = True
                print(f"{Fore.RED}[!] ROOT/ADMIN ACCESS CONFIRMED: Successfully wrote {test_file} to {test_dir}{Style.RESET_ALL}")
                try:
                    ftp.delete(f'{test_dir}/{test_file}')
                    print(f"{Fore.GREEN}[-] Cleaned up: Deleted {test_file} from {test_dir}{Style.RESET_ALL}")
                except ftplib.error_perm as e:
                    print(f"{Fore.YELLOW}[-] Warning: Could not delete {test_file} from {test_dir} (permission error): {e}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.YELLOW}[-] Warning: Could not delete {test_file} from {test_dir}: {e}{Style.RESET_ALL}")
            except ftplib.error_perm as e:
                print(f"{Fore.YELLOW}[-] Write test failed for {test_dir}: Permission denied ({e}){Style.RESET_ALL}")
            except TimeoutError:
                print(f"{Fore.YELLOW}[-] Timeout during write test for {test_dir}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.YELLOW}[-] Write test failed for {test_dir}: {e}{Style.RESET_ALL}")
        except ftplib.error_perm as e:
            if '550' in str(e) or 'No such file or directory' in str(e):
                print(f"{Fore.YELLOW}[-] {test_dir} does not exist{Style.RESET_ALL}")
            elif '553' in str(e) or 'Permission denied' in str(e):
                print(f"{Fore.YELLOW}[-] {test_dir} exists but permission denied ({e}){Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[-] Cannot access {test_dir}: {e}{Style.RESET_ALL}")
        except TimeoutError:
            print(f"{Fore.YELLOW}[-] Timeout accessing {test_dir}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}[-] Error testing {test_dir}: {e}{Style.RESET_ALL}")
    return root_access

def check_ftp(ip):
    """Comprehensive FTP vulnerability assessment with scoring."""
    score = 0
    high_value = False
    sensitive_items = []
    log = [f"[*] Scanning {ip}..."]

    try:
        ftp = ftplib.FTP(ip, timeout=10)
        ftp.login(user='anonymous', passwd='root')
        score += 1  # Anonymous login successful
        log.append(f"{Fore.GREEN}[+] Connected to {ip} - Anonymous login successful{Style.RESET_ALL}")

        # Get version for OS detection
        version = ftp.getwelcome()  # Use getwelcome for banner
        os_type = detect_os(version)
        log.append(f"{Fore.YELLOW}[-] Detected OS type: {os_type}{Style.RESET_ALL}")

        # Initial directory listing
        dir_list = []
        ftp.dir(dir_list.append)
        log.append(f"{Fore.YELLOW}Initial directory listing for {ip}:{Style.RESET_ALL}")
        sensitive_found = False
        for line in dir_list:
            log.append(f"{Fore.YELLOW}{line}{Style.RESET_ALL}")
            for sensitive_dir in SENSITIVE_DIRS:
                if sensitive_dir.lower() in line.lower():
                    sensitive_found = True
                    score += 2
                    log.append(f"{Fore.RED}[!] ALERT: Sensitive directory found: {sensitive_dir}{Style.RESET_ALL}")
            for sensitive_file in SENSITIVE_FILES:
                if sensitive_file.lower() in line.lower():
                    sensitive_found = True
                    score += 2
                    log.append(f"{Fore.RED}[!] ALERT: Sensitive file found: {sensitive_file}{Style.RESET_ALL}")
        if not sensitive_found:
            log.append(f"{Fore.GREEN}[-] No sensitive directories or files detected in initial listing{Style.RESET_ALL}")

        # Test root access
        if test_root_access(ftp, ip, os_type):
            score += 5
            log.append(f"{Fore.RED}[!] High-value target: Root/Administrator access confirmed{Style.RESET_ALL}")

        # Test privilege escalation
        if test_privilege_escalation(ftp, ip, os_type):
            score += 4
            log.append(f"{Fore.RED}[!] High-value target: Privilege escalation possible{Style.RESET_ALL}")

        # Test FTP Bounce
        if test_ftp_bounce(ftp, ip):
            score += 3
            log.append(f"{Fore.RED}[!] High-value target: FTP Bounce vulnerability detected{Style.RESET_ALL}")

        # Spider directories
        sensitive_items = spider_directories(ftp, ip)
        if sensitive_items:
            score += len(sensitive_items)
            log.append(f"{Fore.RED}[!] High-value target: {len(sensitive_items)} sensitive items found in spidering{Style.RESET_ALL}")

        # Determine high-value target
        high_value = score >= 5
        log.append(f"{Fore.MAGENTA}[*] Vulnerability Score: {score} {'(High-value target)' if high_value else ''}{Style.RESET_ALL}")

        # Save to log file
        with open('darkftp_report.txt', 'a') as f:
            f.write('\n'.join(log) + '\n')

        ftp.quit()
        log.append(f"{Fore.GREEN}[-] Logged out from {ip}{Style.RESET_ALL}")

    except ftplib.error_perm as e:
        log.append(f"{Fore.RED}[-] Permission error for {ip}: {e}{Style.RESET_ALL}")
    except ftplib.error_temp as e:
        log.append(f"{Fore.RED}[-] Temporary error for {ip}: {e}{Style.RESET_ALL}")
    except TimeoutError:
        log.append(f"{Fore.RED}[-] Connection timeout for {ip}{Style.RESET_ALL}")
    except Exception as e:
        log.append(f"{Fore.RED}[-] Failed to connect to {ip}: {e}{Style.RESET_ALL}")

    return score, high_value, log

def main():
    parser = argparse.ArgumentParser(description="DarkFTP: FTP Vulnerability Scanner for Ethical Hacking")
    parser.add_argument('--file', type=str, required=True, help='File containing list of IP addresses')
    args = parser.parse_args()

    try:
        with open(args.file, 'r') as f:
            ip_list = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{Fore.RED}[-] Error: File {args.file} not found{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[-] Error reading file {args.file}: {e}{Style.RESET_ALL}")
        sys.exit(1)

    high_value_targets = []
    for ip in ip_list:
        score, high_value, log = check_ftp(ip)
        print('\n'.join(log))
        if high_value:
            high_value_targets.append((ip, score))

    # Print high-value targets summary
    if high_value_targets:
        print(f"{Fore.MAGENTA}\n[+] High-value targets summary:{Style.RESET_ALL}")
        for ip, score in sorted(high_value_targets, key=lambda x: x[1], reverse=True):
            print(f"{Fore.RED}[!] {ip} - Score: {score}{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}[+] No high-value targets found{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
