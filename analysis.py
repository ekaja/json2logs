import re
from collections import defaultdict

def analyze_log(log_file):
    # เก็บสถิติ
    stats = defaultdict(int)
    suspicious_requests = []
    
    # Patterns สำหรับตรวจจับการโจมตี
    patterns = {
        'SQL Injection': r'union\s+select|sleep\(|benchmark\(|select.+from|insert.+into',
        'Path Traversal': r'(\.\./){2,}|/etc/passwd|/etc/shadow|/proc/self',
        'XSS': r'<script>|alert\(|onerror=|javascript:|document\.cookie',
        'RCE': r'\?cmd=|system\(|exec\(|passthru\(|shell_exec\(',
        'Scanner Tools': r'sqlmap|nmap|nikto|wpscan|burpsuite|acunetix',
        'Sensitive Paths': r'/wp-admin|/phpmyadmin|/\.git|/\.env|/debug\.php'
    }

    with open(log_file, 'r') as f:
        for line in f:
            # ตรวจสอบทุก pattern
            for attack_type, pattern in patterns.items():
                if re.search(pattern, line, re.IGNORECASE):
                    stats[attack_type] += 1
                    suspicious_requests.append((attack_type, line.strip()))
                    break  # หยุดเมื่อพบ pattern ใด pattern หนึ่ง

            # ตรวจจับ status code 4xx/5xx จำนวนมาก
            if re.search(r'HTTP/1.\d" (4\d{2}|5\d{2})', line):
                stats['4xx/5xx Errors'] += 1

    # แสดงผล
    print("\n[+] สรุปการตรวจจับการโจมตี:")
    for attack_type, count in stats.items():
        print(f" - {attack_type}: {count} รายการ")

    print("\n[+] ตัวอย่าง request น่าสงสัย:")
    for i, (attack_type, request) in enumerate(suspicious_requests[:5], 1):
        print(f"{i}. [{attack_type}] {request}")

if __name__ == "__main__":
    analyze_log('/var/log/nginx/access.log')
