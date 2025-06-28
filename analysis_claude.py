#!/usr/bin/env python3
"""
Apache/Nginx Log Security Analyzer
วิเคราะห์ log files เพื่อตรวจจับการโจมตีและแสดงผลเป็นกราฟ
ติดตั้ง dependencies
pip install pandas matplotlib seaborn

วิเคราะห์ log file
python log_analyzer.py /var/log/apache2/access.log

ไม่แสดงกราฟ
python log_analyzer.py /var/log/nginx/access.log --no-graph

Export เป็น JSON
python log_analyzer.py access.log --export-json report.json
"""

import re
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from collections import defaultdict, Counter
from datetime import datetime
import argparse
import json
from urllib.parse import unquote
import ipaddress

# ตั้งค่า matplotlib สำหรับภาษาไทย
plt.rcParams['font.family'] = ['DejaVu Sans', 'Tahoma', 'Arial Unicode MS']

class LogSecurityAnalyzer:
    def __init__(self):
        # Attack patterns สำหรับตรวจจับ
        self.attack_patterns = {
            'SQL Injection': [
                r'union\s+select', r'insert\s+into', r'delete\s+from', r'drop\s+table',
                r'exec\s*\(', r'script\s*>', r'<\s*script', r'javascript:',
                r'vbscript:', r'onload\s*=', r'onerror\s*=', r'1=1', r'1\'=\'1',
                r'admin\'--', r'or\s+1=1', r'\'\s*or\s*\'', r'0x[0-9a-f]+',
                r'char\(\d+\)', r'waitfor\s+delay', r'benchmark\('
            ],
            'XSS': [
                r'<script[^>]*>', r'</script>', r'javascript:', r'vbscript:',
                r'onload\s*=', r'onerror\s*=', r'onmouseover\s*=', r'onclick\s*=',
                r'onfocus\s*=', r'onblur\s*=', r'alert\s*\(', r'document\.cookie',
                r'<iframe[^>]*>', r'<object[^>]*>', r'<embed[^>]*>'
            ],
            'Directory Traversal': [
                r'\.\./', r'\.\.\\', r'%2e%2e%2f', r'%2e%2e%5c',
                r'..%2f', r'..%5c', r'%252e%252e%252f'
            ],
            'Command Injection': [
                r';\s*cat\s+', r';\s*ls\s+', r';\s*id\s*;', r';\s*pwd\s*;',
                r';\s*whoami', r';\s*uname', r'`cat\s+', r'`ls\s+',
                r'\|\s*cat\s+', r'\|\s*ls\s+', r'&\s*cat\s+', r'&\s*ls\s+'
            ],
            'File Inclusion': [
                r'etc/passwd', r'etc/shadow', r'boot\.ini', r'win\.ini',
                r'php://filter', r'php://input', r'data://', r'file://',
                r'expect://', r'zip://', r'phar://'
            ],
            'Sensitive File Access': [
                r'\.env', r'\.git/', r'config\.php', r'wp-config\.php',
                r'database\.yml', r'\.htaccess', r'\.htpasswd', r'backup\.',
                r'\.sql', r'\.bak', r'\.old', r'\.orig', r'admin\.php',
                r'phpinfo\.php', r'test\.php'
            ],
            'Bot/Scanner': [
                r'nikto', r'nmap', r'sqlmap', r'dirb', r'dirbuster',
                r'gobuster', r'wpscan', r'masscan', r'zap', r'burp',
                r'acunetix', r'nessus', r'openvas', r'w3af'
            ]
        }
        
        # Suspicious user agents
        self.suspicious_agents = [
            'sqlmap', 'nikto', 'nmap', 'masscan', 'zap', 'burp',
            'acunetix', 'nessus', 'openvas', 'w3af', 'dirb', 'gobuster',
            'python-requests', 'curl', 'wget', 'libwww-perl'
        ]
        
        # Log format patterns
        self.log_patterns = {
            'combined': r'(\S+) \S+ \S+ \[(.*?)\] "(\S+) (.*?) HTTP/\S+" (\d+) (\S+) "(.*?)" "(.*?)"',
            'common': r'(\S+) \S+ \S+ \[(.*?)\] "(\S+) (.*?) HTTP/\S+" (\d+) (\S+)'
        }
        
        self.parsed_logs = []
        self.attacks = defaultdict(list)
        self.suspicious_ips = Counter()
        
    def parse_log_line(self, line):
        """Parse single log line"""
        line = line.strip()
        if not line or line.startswith('#'):
            return None
            
        # ลอง combined format ก่อน
        match = re.match(self.log_patterns['combined'], line)
        if match:
            ip, timestamp, method, url, status, size, referer, user_agent = match.groups()
            return {
                'ip': ip,
                'timestamp': timestamp,
                'method': method,
                'url': unquote(url),
                'status': int(status),
                'size': size if size != '-' else '0',
                'referer': referer,
                'user_agent': user_agent
            }
        
        # ลอง common format
        match = re.match(self.log_patterns['common'], line)
        if match:
            ip, timestamp, method, url, status, size = match.groups()
            return {
                'ip': ip,
                'timestamp': timestamp,
                'method': method,
                'url': unquote(url),
                'status': int(status),
                'size': size if size != '-' else '0',
                'referer': '-',
                'user_agent': '-'
            }
            
        return None
    
    def is_private_ip(self, ip):
        """ตรวจสอบว่าเป็น private IP หรือไม่"""
        try:
            return ipaddress.ip_address(ip).is_private
        except:
            return False
    
    def detect_attacks(self, log_entry):
        """ตรวจจับการโจมตีใน log entry"""
        url = log_entry['url'].lower()
        user_agent = log_entry['user_agent'].lower()
        referer = log_entry['referer'].lower()
        
        detected_attacks = []
        
        # ตรวจสอบ URL patterns
        for attack_type, patterns in self.attack_patterns.items():
            for pattern in patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    detected_attacks.append(attack_type)
                    break
        
        # ตรวจสอบ User Agent
        for agent in self.suspicious_agents:
            if agent in user_agent:
                detected_attacks.append('Bot/Scanner')
                break
        
        # ตรวจสอบ status codes ที่น่าสงสัย
        if log_entry['status'] in [401, 403]:
            detected_attacks.append('Unauthorized Access')
        elif log_entry['status'] == 404 and any(pattern in url for pattern in ['admin', 'wp-', 'config', '.env']):
            detected_attacks.append('Reconnaissance')
        
        return detected_attacks
    
    def analyze_log_file(self, file_path):
        """วิเคราะห์ไฟล์ log"""
        print(f"กำลังวิเคราะห์: {file_path}")
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                if line_num % 10000 == 0:
                    print(f"ประมวลผลแล้ว {line_num:,} บรรทัด...")
                
                parsed = self.parse_log_line(line)
                if not parsed:
                    continue
                
                self.parsed_logs.append(parsed)
                
                # ตรวจจับการโจมตี
                attacks = self.detect_attacks(parsed)
                if attacks:
                    for attack_type in attacks:
                        self.attacks[attack_type].append({
                            'ip': parsed['ip'],
                            'timestamp': parsed['timestamp'],
                            'url': parsed['url'],
                            'status': parsed['status'],
                            'user_agent': parsed['user_agent']
                        })
                    
                    # นับ IP ที่น่าสงสัย
                    self.suspicious_ips[parsed['ip']] += len(attacks)
        
        print(f"วิเคราะห์เสร็จแล้ว: {len(self.parsed_logs):,} entries")
    
    def generate_report(self):
        """สร้างรายงานการโจมตี"""
        print("\n" + "="*80)
        print("📊 รายงานการวิเคราะห์ความปลอดภัย")
        print("="*80)
        
        if not self.attacks:
            print("✅ ไม่พบการโจมตีที่น่าสงสัย")
            return
        
        # สรุปการโจมตีแต่ละประเภท
        print("\n🚨 ประเภทการโจมตีที่พบ:")
        total_attacks = 0
        for attack_type, incidents in self.attacks.items():
            count = len(incidents)
            total_attacks += count
            print(f"   {attack_type}: {count:,} ครั้ง")
        
        print(f"\n📈 รวมการโจมตีทั้งหมด: {total_attacks:,} ครั้ง")
        
        # IP ที่น่าสงสัยมากที่สุด
        print(f"\n🔍 IP ที่น่าสงสัยมากที่สุด (Top 10):")
        for ip, count in self.suspicious_ips.most_common(10):
            is_private = "🏠" if self.is_private_ip(ip) else "🌐"
            print(f"   {is_private} {ip}: {count} การโจมตี")
        
        # รายละเอียดการโจมตีแต่ละประเภท
        print(f"\n📋 รายละเอียดการโจมตี:")
        for attack_type, incidents in self.attacks.items():
            print(f"\n--- {attack_type} ({len(incidents)} ครั้ง) ---")
            
            # แสดง 5 cases แรก
            for i, incident in enumerate(incidents[:5]):
                print(f"  {i+1}. IP: {incident['ip']}")
                print(f"     URL: {incident['url'][:100]}...")
                print(f"     Status: {incident['status']}")
                print(f"     Time: {incident['timestamp']}")
                if incident['user_agent'] != '-':
                    print(f"     User-Agent: {incident['user_agent'][:50]}...")
                print()
            
            if len(incidents) > 5:
                print(f"     ... และอีก {len(incidents) - 5} ครั้ง")
    
    def create_visualizations(self):
        """สร้างกราฟแสดงผล"""
        if not self.attacks:
            print("ไม่มีข้อมูลการโจมตีสำหรับสร้างกราฟ")
            return
        
        # ตั้งค่า style
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
        
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        fig.suptitle('การวิเคราะห์ Log Security', fontsize=16, fontweight='bold')
        
        # 1. กราฟแท่งแสดงประเภทการโจมตี
        attack_counts = {k: len(v) for k, v in self.attacks.items()}
        attacks_df = pd.DataFrame(list(attack_counts.items()), columns=['Attack Type', 'Count'])
        
        ax1 = axes[0, 0]
        bars = ax1.bar(range(len(attacks_df)), attacks_df['Count'], color='red', alpha=0.7)
        ax1.set_title('จำนวนการโจมตีแต่ละประเภท', fontweight='bold')
        ax1.set_xlabel('ประเภทการโจมตี')
        ax1.set_ylabel('จำนวน')
        ax1.set_xticks(range(len(attacks_df)))
        ax1.set_xticklabels(attacks_df['Attack Type'], rotation=45, ha='right')
        
        # เพิ่มค่าบนแท่ง
        for bar, count in zip(bars, attacks_df['Count']):
            ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1,
                    str(count), ha='center', va='bottom', fontweight='bold')
        
        # 2. Top 10 IP ที่น่าสงสัย
        ax2 = axes[0, 1]
        top_ips = dict(self.suspicious_ips.most_common(10))
        if top_ips:
            ips = list(top_ips.keys())
            counts = list(top_ips.values())
            
            bars = ax2.barh(range(len(ips)), counts, color='orange', alpha=0.7)
            ax2.set_title('Top 10 IP ที่น่าสงสัย', fontweight='bold')
            ax2.set_xlabel('จำนวนการโจมตี')
            ax2.set_ylabel('IP Address')
            ax2.set_yticks(range(len(ips)))
            ax2.set_yticklabels([f"{ip}" for ip in ips])
            
            # เพิ่มค่าข้างแท่ง
            for bar, count in zip(bars, counts):
                ax2.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height()/2,
                        str(count), ha='left', va='center', fontweight='bold')
        
        # 3. Status Codes Distribution
        ax3 = axes[1, 0]
        all_status = []
        for incidents in self.attacks.values():
            all_status.extend([inc['status'] for inc in incidents])
        
        if all_status:
            status_counts = Counter(all_status)
            status_df = pd.DataFrame(list(status_counts.items()), columns=['Status Code', 'Count'])
            
            wedges, texts, autotexts = ax3.pie(status_df['Count'], labels=status_df['Status Code'],
                                              autopct='%1.1f%%', startangle=90)
            ax3.set_title('Status Codes ในการโจมตี', fontweight='bold')
        
        # 4. Timeline ของการโจมตี (ถ้ามีข้อมูลเวลา)
        ax4 = axes[1, 1]
        try:
            # รวบรวมข้อมูลเวลา
            timestamps = []
            for incidents in self.attacks.values():
                for inc in incidents:
                    try:
                        # แปลง timestamp (format: 01/Jan/2024:12:00:00 +0700)
                        time_str = inc['timestamp'].split()[0]
                        dt = datetime.strptime(time_str, '%d/%b/%Y:%H:%M:%S')
                        timestamps.append(dt)
                    except:
                        continue
            
            if timestamps:
                # จัดกลุ่มตามชั่วโมง
                hourly_attacks = Counter([dt.hour for dt in timestamps])
                hours = list(range(24))
                counts = [hourly_attacks.get(h, 0) for h in hours]
                
                ax4.plot(hours, counts, marker='o', linewidth=2, markersize=4, color='red')
                ax4.fill_between(hours, counts, alpha=0.3, color='red')
                ax4.set_title('การโจมตีตามช่วงเวลา (24 ชั่วโมง)', fontweight='bold')
                ax4.set_xlabel('ชั่วโมง')
                ax4.set_ylabel('จำนวนการโจมตี')
                ax4.set_xticks(range(0, 24, 2))
                ax4.grid(True, alpha=0.3)
            else:
                ax4.text(0.5, 0.5, 'ไม่สามารถแปลงข้อมูลเวลาได้', 
                        ha='center', va='center', transform=ax4.transAxes)
                ax4.set_title('Timeline การโจมตี', fontweight='bold')
        except Exception as e:
            ax4.text(0.5, 0.5, f'Error: {str(e)}', 
                    ha='center', va='center', transform=ax4.transAxes)
            ax4.set_title('Timeline การโจมตี', fontweight='bold')
        
        plt.tight_layout()
        plt.savefig('security_analysis_report.png', dpi=300, bbox_inches='tight')
        plt.show()
        
        print(f"\n💾 บันทึกกราฟแล้ว: security_analysis_report.png")
    
    def export_to_json(self, filename='security_report.json'):
        """Export ผลลัพธ์เป็น JSON"""
        report = {
            'summary': {
                'total_logs': len(self.parsed_logs),
                'total_attacks': sum(len(incidents) for incidents in self.attacks.values()),
                'attack_types': {k: len(v) for k, v in self.attacks.items()},
                'top_suspicious_ips': dict(self.suspicious_ips.most_common(20))
            },
            'detailed_attacks': {}
        }
        
        for attack_type, incidents in self.attacks.items():
            report['detailed_attacks'][attack_type] = incidents
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        
        print(f"💾 บันทึกรายงานแล้ว: {filename}")

def main():
    parser = argparse.ArgumentParser(description='Apache/Nginx Log Security Analyzer')
    parser.add_argument('logfile', help='Path to log file')
    parser.add_argument('--no-graph', action='store_true', help='ไม่แสดงกราฟ')
    parser.add_argument('--export-json', help='Export to JSON file')
    
    args = parser.parse_args()
    
    analyzer = LogSecurityAnalyzer()
    
    try:
        analyzer.analyze_log_file(args.logfile)
        analyzer.generate_report()
        
        if not args.no_graph:
            analyzer.create_visualizations()
        
        if args.export_json:
            analyzer.export_to_json(args.export_json)
    
    except FileNotFoundError:
        print(f"❌ ไม่พบไฟล์: {args.logfile}")
    except Exception as e:
        print(f"❌ เกิดข้อผิดพลาด: {str(e)}")

if __name__ == "__main__":
    main()
