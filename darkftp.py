import argparse
import ftplib
import colorama
from colorama import Fore, Style
import sys
import io
import time

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

# Define directories to test for root access
ROOT_TEST_DIRS = [
    '/etc', '/root', '/Windows/System32', '/Windows'
]

# Define directories for executable file upload (privilege escalation)
EXEC_TEST_DIRS = [
    '/tmp', '/inetpub/wwwroot'
]

# Known vulnerable FTP versions
VULNERABLE_VERSIONS = {
    'Microsoft FTP Service 5.0': ['CVE-2009-3023', 'Potential remote code execution'],
    'Pure-FTPd 1.0.36': ['CVE-2011-0411', 'Directory traversal'],
    'ProFTPD 1.3.5e': ['CVE-2011-4130', 'Directory traversal']
}

def test_ftp_bounce(ftp, ip):
    """Test for FTP Bounce attack vulnerability."""
    bounce_vulnerable = False
    print(f"{Fore.CYAN}[*] Testing FTP Bounce for {ip}...{Style.RESET_ALL}")
    try:
        ftp.sendcmd('PORT 127,0,0,1,0,80')
        print(f"{Fore.RED}[!] FTP Bounce POSSIBLE: PORT command accepted{Style.RESET_ALL}")
        bounce_vulnerable = True
        test_file = 'bounce_test.txt'
        test_content = io.BytesIO(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        ftp.storbinary(f'STOR {test_file}', test_content)
        try:
            ftp.sendcmd('RETR bounce_test.txt')
            print(f"{Fore.RED}[!] FTP Bounce CONFIRMED: Can send arbitrary requests{Style.RESET_ALL}")
        except:
            print(f"{Fore.YELLOW}[-] RETR failed for FTP Bounce test{Style.RESET_ALL}")
        ftp.delete(test_file)
    except ftplib.error_perm:
        print(f"{Fore.YELLOW}[-] PORT command not supported or permission denied{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.YELLOW}[-] Error testing FTP Bounce: {e}{Style.RESET_ALL}")
    return bounce_vulnerable

def test_privilege_escalation(ftp, ip):
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
    except Exception as e:
        print(f"{Fore.YELLOW}[-] Could not retrieve version: {e}{Style.RESET_ALL}")

    for test_dir in EXEC_TEST_DIRS:
        try:
            ftp.cwd(test_dir)
            print(f"{Fore.GREEN}[+] Successfully changed to {test_dir}{Style.RESET_ALL}")
            test_file = 'test_exec' + ('.asp' if 'inetpub' in test_dir else '.sh')
            test_content = io.BytesIO(b"<% Response.Write('Test') %>" if 'inetpub' in test_dir else b"#!/bin/bash\necho Test")
            try:
                ftp.storbinary(f'STOR {test_dir}/{test_file}', test_content)
                escalation_possible = True
                print(f"{Fore.RED}[!] PRIVILEGE ESCALATION POSSIBLE: Successfully wrote {test_file} to {test_dir}{Style.RESET_ALL}")
                try:
                    ftp.delete(f'{test_dir}/{test_file}')
                    print(f"{Fore.GREEN}[-] Cleaned up: Deleted {test_file} from {test_dir}{Style.RESET_ALL}")
                except:
                    print(f"{Fore.YELLOW}[-] Warning: Could not delete {test_file} from {test_dir}{Style.RESET_ALL}")
            except ftplib.error_perm:
                print(f"{Fore.YELLOW}[-] Write test failed for {test_dir}: Permission denied{Style.RESET_ALL}")
        except ftplib.error_perm:
            print(f"{Fore.YELLOW}[-] Cannot access {test_dir}: Permission denied{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}[-] Error testing {test_dir}: {e}{Style.RESET_ALL}")
    return escalation_possible

def spider_directories(ftp, ip, current_dir='/', depth=0, max_depth=3):
    """Recursively spider all directories and files."""
    sensitive_items = []
    if depth > max_depth:
        print(f"{Fore.YELLOW}[-] Max depth ({max_depth}) reached at {current_dir}{Style.RESET_ALL}")
        return sensitive_items
    try:
        print(f"{Fore.YELLOW}[*] Spidering {current_dir} (depth {depth})...{Style.RESET_ALL}")
        ftp.cwd(current_dir)
        items = []
        ftp.retrlines('NLST', items.append)
        for item in items:
            try:
                ftp.cwd(f"{current_dir.rstrip('/')}/{item}")
                print(f"{Fore.YELLOW}Dir: {current_dir.rstrip('/')}/{item}{Style.RESET_ALL}")
                for sensitive_dir in SENSITIVE_DIRS:
                    if sensitive_dir.lower() in item.lower():
                        sensitive_items.append(f"Dir: {current_dir.rstrip('/')}/{item}")
                        print(f"{Fore.RED}[!] ALERT: Sensitive directory found: {item}{Style.RESET_ALL}")
                sensitive_items.extend(spider_directories(ftp, ip, f"{current_dir.rstrip('/')}/{item}", depth + 1, max_depth))
                ftp.cwd(current_dir)
            except ftplib.error_perm:
                print(f"{Fore.YELLOW}File: {current_dir.rstrip('/')}/{item}{Style.RESET_ALL}")
                for sensitive_file in SENSITIVE_FILES:
                    if sensitive_file.lower() in item.lower():
                        sensitive_items.append(f"File: {current_dir.rstrip('/')}/{item}")
                        print(f"{Fore.RED}[!] ALERT: Sensitive file found: {item}{Style.RESET_ALL}")
    except ftplib.error_perm:
        print(f"{Fore.YELLOW}[-] Cannot access {current_dir}: Permission denied{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.YELLOW}[-] Error spidering {current_dir}: {e}{Style.RESET_ALL}")
    return sensitive_items

def test_root_access(ftp, ip):
    """Test for root/Administrator access."""
    root_access = False
    print(f"{Fore.CYAN}[*] Testing root access for {ip}...{Style.RESET_ALL}")
    for test_dir in ROOT_TEST_DIRS:
        try:
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
                except:
                    print(f"{Fore.YELLOW}[-] Warning: Could not delete {test_file} from {test_dir}{Style.RESET_ALL}")
            except ftplib.error_perm:
                print(f"{Fore.YELLOW}[-] Write test failed for {test_dir}: Permission denied{Style.RESET_ALL}")
        except ftplib.error_perm:
            print(f"{Fore.YELLOW}[-] Cannot access {test_dir}: Permission denied{Style.RESET_ALL}")
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
        if test_root_access(ftp, ip):
            score += 5
            log.append(f"{Fore.RED}[!] High-value target: Root/Administrator access confirmed{Style.RESET_ALL}")

        # Test privilege escalation
        if test_privilege_escalation(ftp, ip):
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
