#!/usr/bin/env python3
import os
import stat
import pwd
import grp
import datetime
import subprocess
import argparse
from html import escape

class PermissionAnalyzer:
    def __init__(self):
        self.total_files = 0
        self.risk_files = 0

    def get_detailed_permissions(self, mode):
        """Dosya izinlerini detaylı analiz eder"""
        return {
            'owner': {
                'read': bool(mode & stat.S_IRUSR),
                'write': bool(mode & stat.S_IWUSR),
                'execute': bool(mode & stat.S_IXUSR)
            },
            'group': {
                'read': bool(mode & stat.S_IRGRP),
                'write': bool(mode & stat.S_IWGRP),
                'execute': bool(mode & stat.S_IXGRP)
            },
            'others': {
                'read': bool(mode & stat.S_IROTH),
                'write': bool(mode & stat.S_IWOTH),
                'execute': bool(mode & stat.S_IXOTH)
            },
            'special': {
                'setuid': bool(mode & stat.S_ISUID),
                'setgid': bool(mode & stat.S_ISGID),
                'sticky': bool(mode & stat.S_ISVTX)
            }
        }

    def permission_to_octal(self, perms):
        """İzinleri octal formata çevirir"""
        return (f"{int(perms['owner']['read'])*4 + int(perms['owner']['write'])*2 + int(perms['owner']['execute'])}"
                f"{int(perms['group']['read'])*4 + int(perms['group']['write'])*2 + int(perms['group']['execute'])}"
                f"{int(perms['others']['read'])*4 + int(perms['others']['write'])*2 + int(perms['others']['execute'])}")

    def get_file_info(self, path):
        """Dosya/klasör için detaylı bilgi toplar"""
        try:
            st = os.lstat(path)
            perms = self.get_detailed_permissions(st.st_mode)

            return {
                'path': path,
                'type': 'directory' if stat.S_ISDIR(st.st_mode) else 'file',
                'mode_str': stat.filemode(st.st_mode),
                'octal_perm': self.permission_to_octal(perms),
                'owner': pwd.getpwuid(st.st_uid).pw_name,
                'group': grp.getgrgid(st.st_gid).gr_name,
                'size': st.st_size,
                'mtime': datetime.datetime.fromtimestamp(st.st_mtime),
                'perms': perms,
                'inode': st.st_ino,
                'security_risk': self.check_security_risk(perms, st.st_uid)
            }
        except Exception as e:
            return {'error': str(e), 'path': path}

    def check_security_risk(self, perms, uid):
        """Güvenlik risklerini kontrol eder"""
        risks = []

        # World-writable kontrolü
        if perms['others']['write']:
            risks.append('World-writable')

        # Root yazılabilir dosyalar
        if uid == 0 and perms['owner']['write']:
            risks.append('Root-writable')

        # Setuid/setgid programlar
        if perms['special']['setuid']:
            risks.append('SETUID')
        if perms['special']['setgid']:
            risks.append('SETGID')

        return ', '.join(risks) if risks else 'None'

    def get_acl_info(self, path):
        """ACL bilgilerini alır"""
        try:
            result = subprocess.run(
                ['getfacl', '-p', path],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except Exception as e:
            return f"ACL Error: {str(e)}"

    def format_size(self, size):
        """Dosya boyutunu okunabilir formata çevirir"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"

    def generate_html_report(self, data, output_file):
        """HTML raporu oluşturur"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Advanced Permission Analyzer</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; margin: 20px; }}
        h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; }}
        table {{
            border-collapse: collapse;
            width: 100%;
            font-size: 14px;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
            vertical-align: top;
        }}
        th {{
            background-color: #3498db;
            color: white;
            position: sticky;
            top: 0;
        }}
        tr.high-risk {{ background-color: #ffdddd !important; }}
        tr.medium-risk {{ background-color: #fff3cd !important; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        .octal {{ font-family: monospace; font-weight: bold; }}
        .acl {{ white-space: pre; font-family: monospace; font-size: 0.9em; }}
        .risk-label {{
            font-weight: bold;
            padding: 2px 5px;
            border-radius: 3px;
            font-size: 12px;
        }}
        .high {{ background-color: #ff4444; color: white; }}
        .medium {{ background-color: #ffbb33; color: black; }}
        .error {{ color: #d9534f; }}
    </style>
</head>
<body>
    <h1>Advanced Permission Analysis Report</h1>
    <p>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <table>
        <thead>
            <tr>
                <th>Path</th>
                <th>Type</th>
                <th>Permissions</th>
                <th>Octal</th>
                <th>Owner/Group</th>
                <th>Size</th>
                <th>Modified</th>
                <th>Security Risk</th>
                <th>ACL</th>
            </tr>
        </thead>
        <tbody>
            {data}
        </tbody>
    </table>
</body>
</html>"""

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)

    def scan_directory(self, path, depth=5):
        """Dizini tarar ve rapor verilerini hazırlar"""
        rows = []

        # Önce ana dizini analiz et
        main_dir_info = self.get_file_info(path)
        if 'error' not in main_dir_info:
            row_html = self.format_row(main_dir_info)
            rows.append(row_html)
            self.total_files += 1

        # Alt dizinleri tara
        for root, dirs, files in os.walk(path):
            current_depth = root[len(path):].count(os.sep)
            if current_depth >= depth:
                del dirs[:]
                continue

            for name in dirs + files:
                full_path = os.path.join(root, name)
                info = self.get_file_info(full_path)

                if 'error' in info:
                    print(f"⚠️ Error processing {full_path}: {info['error']}")
                    continue

                row_html = self.format_row(info)
                rows.append(row_html)
                self.total_files += 1

        return rows

    def format_row(self, info):
        """Tek bir satır için HTML oluşturur"""
        risk_class = ''
        risk_label = ''

        if 'World-writable' in info['security_risk']:
            risk_class = 'high-risk'
            risk_label = '<span class="risk-label high">HIGH</span>'
            self.risk_files += 1
        elif info['security_risk'] != 'None':
            risk_class = 'medium-risk'
            risk_label = '<span class="risk-label medium">MEDIUM</span>'
            self.risk_files += 1

        return f"""
<tr class="{risk_class}">
    <td>{escape(info['path'])}</td>
    <td>{info['type']}</td>
    <td>{info['mode_str']}</td>
    <td class="octal">{info['octal_perm']}</td>
    <td>{info['owner']}/{info['group']}</td>
    <td>{self.format_size(info['size'])}</td>
    <td>{info['mtime'].strftime('%Y-%m-%d %H:%M')}</td>
    <td>{risk_label} {info['security_risk']}</td>
    <td class="acl"><pre>{escape(self.get_acl_info(info['path']))}</pre></td>
</tr>"""

def main():
    parser = argparse.ArgumentParser(
        description='Advanced file permission analyzer with security risk detection',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('path', help='Directory to analyze')
    parser.add_argument('-o', '--output', default='permission_report.html',
                      help='Output HTML file')
    parser.add_argument('-d', '--depth', type=int, default=5,
                      help='Maximum directory traversal depth')

    args = parser.parse_args()

    if not os.path.isdir(args.path):
        print(f"Error: {args.path} is not a valid directory")
        exit(1)

    print(f"🔍 Analyzing {args.path}...")

    analyzer = PermissionAnalyzer()
    rows = analyzer.scan_directory(args.path, args.depth)
    analyzer.generate_html_report('\n'.join(rows), args.output)

    print(f"✅ Report generated: {args.output}")
    print(f"📊 Total items: {analyzer.total_files} | ⚠️ Security risks: {analyzer.risk_files}")

if __name__ == "__main__":
    main()
