#!/usr/bin/env python3
import os
import stat
import pwd
import grp
import datetime
import subprocess
import argparse
import threading
import time
from html import escape
from pathlib import Path
import shutil
import json

class PermissionAnalyzer:
    def __init__(self):
        self.total_files = 0
        self.risk_files = {'high': 0, 'medium': 0, 'low': 0}
        self.processed_inodes = set()  # For symlink loop prevention
        self.errors = []
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.stats = {
            'world_writable': 0,
            'setuid': 0,
            'setgid': 0,
            'root_writable': 0,
            'interesting_extensions': 0
        }
        self.interesting_extensions = ['.sh', '.py', '.pl', '.rb', '.php', '.conf', '.key', '.pem', '.crt', '.ini']
        self.exclude_paths = set()  # Paths to exclude

        # Check if getfacl is available
        self.has_getfacl = shutil.which('getfacl') is not None

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

    def permission_to_octal(self, perms, mode):
        """İzinleri octal formata çevirir (özel bitleri de dahil eder)"""
        special_bits = 0
        if perms['special']['setuid']:
            special_bits += 4
        if perms['special']['setgid']:
            special_bits += 2
        if perms['special']['sticky']:
            special_bits += 1

        standard_bits = (
            f"{int(perms['owner']['read'])*4 + int(perms['owner']['write'])*2 + int(perms['owner']['execute'])}"
            f"{int(perms['group']['read'])*4 + int(perms['group']['write'])*2 + int(perms['group']['execute'])}"
            f"{int(perms['others']['read'])*4 + int(perms['others']['write'])*2 + int(perms['others']['execute'])}"
        )

        if special_bits > 0:
            return f"{special_bits}{standard_bits}"
        return standard_bits

    def get_file_info(self, path):
        """Dosya/klasör için detaylı bilgi toplar"""
        try:
            path_obj = Path(path)
            if path_obj.is_symlink():
                st = os.lstat(path)
                target = os.readlink(path)
                file_type = 'symlink'
            else:
                st = os.lstat(path)
                target = None
                if stat.S_ISDIR(st.st_mode):
                    file_type = 'directory'
                elif stat.S_ISREG(st.st_mode):
                    file_type = 'file'
                elif stat.S_ISCHR(st.st_mode):
                    file_type = 'character_device'
                elif stat.S_ISBLK(st.st_mode):
                    file_type = 'block_device'
                elif stat.S_ISFIFO(st.st_mode):
                    file_type = 'fifo'
                elif stat.S_ISSOCK(st.st_mode):
                    file_type = 'socket'
                else:
                    file_type = 'unknown'

            perms = self.get_detailed_permissions(st.st_mode)

            # Dosya sahibi ve grup bilgisini güvenli şekilde al
            try:
                owner = pwd.getpwuid(st.st_uid).pw_name
            except KeyError:
                owner = str(st.st_uid)

            try:
                group = grp.getgrgid(st.st_gid).gr_name
            except KeyError:
                group = str(st.st_gid)

            # Risk seviyesi ve tipini belirle
            risk_level, risk_types = self.check_security_risk(perms, st.st_uid, st.st_mode, path)

            # Eğer bu dosya uzantısı ilgi çekici ise işaretle
            extension = path_obj.suffix.lower()
            has_interesting_extension = extension in self.interesting_extensions

            if has_interesting_extension:
                with self.lock:
                    self.stats['interesting_extensions'] += 1

            # Güvenlik istatistiklerini güncelle
            with self.lock:
                for risk_type in risk_types:
                    if risk_type in self.stats:
                        self.stats[risk_type] += 1

            result = {
                'path': path,
                'type': file_type,
                'mode_str': stat.filemode(st.st_mode),
                'octal_perm': self.permission_to_octal(perms, st.st_mode),
                'owner': owner,
                'group': group,
                'size': st.st_size,
                'mtime': datetime.datetime.fromtimestamp(st.st_mtime),
                'ctime': datetime.datetime.fromtimestamp(st.st_ctime),
                'perms': perms,
                'inode': st.st_ino,
                'risk_level': risk_level,
                'risk_types': risk_types,
                'has_interesting_extension': has_interesting_extension
            }

            if target:
                result['target'] = target

            if self.has_getfacl and file_type not in ['symlink', 'socket', 'fifo']:
                result['acl'] = self.get_acl_info(path)
            else:
                result['acl'] = "Not available"

            return result

        except Exception as e:
            with self.lock:
                self.errors.append({'path': path, 'error': str(e)})
            return {'error': str(e), 'path': path}

    def check_security_risk(self, perms, uid, mode, path):
        """Güvenlik risklerini kontrol eder ve risk seviyesini belirler"""
        risks = []
        risk_level = 'none'

        # World-writable kontrolü
        if perms['others']['write']:
            risks.append('world_writable')
            risk_level = 'high'  # World-writable her zaman yüksek risk

        # Root yazılabilir dosyalar
        if uid == 0 and perms['owner']['write']:
            risks.append('root_writable')
            if risk_level != 'high':
                risk_level = 'medium'

        # Setuid/setgid programlar
        is_executable = perms['owner']['execute'] or perms['group']['execute'] or perms['others']['execute']

        if perms['special']['setuid'] and is_executable:
            risks.append('setuid')
            risk_level = 'high'

        if perms['special']['setgid'] and is_executable:
            risks.append('setgid')
            if risk_level != 'high':
                risk_level = 'medium'

        # Tehlikeli olabilecek izin kombinasyonları
        if perms['group']['write'] and not perms['owner']['write']:
            risks.append('unusual_permissions')
            if risk_level == 'none':
                risk_level = 'low'

        # Dosya uzantısına göre ek kontroller
        path_lower = path.lower()
        if any(path_lower.endswith(ext) for ext in ['.key', '.pem']):
            if perms['others']['read']:
                risks.append('sensitive_file_readable')
                risk_level = 'high'

        if any(path_lower.endswith(ext) for ext in ['.sh', '.py', '.pl', '.rb']) and perms['others']['execute']:
            risks.append('script_executable')
            if risk_level == 'none':
                risk_level = 'low'

        # Risk yoksa
        if not risks:
            risk_level = 'none'

        return risk_level, risks

    def get_acl_info(self, path):
        """ACL bilgilerini alır"""
        if not self.has_getfacl:
            return "getfacl not available"

        try:
            result = subprocess.run(
                ['getfacl', '-p', path],
                capture_output=True,
                text=True,
                timeout=2  # Zaman aşımı ekleyerek takılmayı önle
            )
            if result.returncode == 0:
                return result.stdout.strip()
            return f"Error: {result.stderr.strip()}"
        except subprocess.TimeoutExpired:
            return "ACL check timed out"
        except Exception as e:
            return f"ACL Error: {str(e)}"

    def format_size(self, size):
        """Dosya boyutunu okunabilir formata çevirir"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"

    def scan_directory(self, path, follow_symlinks=False, exclude_paths=None):
        """Dizini tarar ve rapor verilerini hazırlar"""
        if exclude_paths:
            self.exclude_paths = set(os.path.abspath(p) for p in exclude_paths)

        rows = []
        errors = []

        # Progress reporting için değişkenler
        last_report_time = time.time()
        progress_report_interval = 5  # saniye

        # Önce ana dizini analiz et
        main_dir_info = self.get_file_info(path)
        if 'error' not in main_dir_info:
            row_html = self.format_row(main_dir_info)
            rows.append(row_html)
            self.total_files += 1

        print(f"🔍 Scanning {path}...")
        print("Progress will be reported every 5 seconds")

        try:
            # os.walk ile dizindeki tüm dosya ve klasörleri dolaş
            for root, dirs, files in os.walk(path, topdown=True, followlinks=follow_symlinks):
                # Hariç tutulan dizinleri kontrol et ve atlat
                if any(os.path.abspath(root).startswith(excluded) for excluded in self.exclude_paths):
                    dirs[:] = []  # Alt dizinleri temizleyerek bu klasörü atla
                    continue

                # Progress report
                current_time = time.time()
                if current_time - last_report_time > progress_report_interval:
                    elapsed = current_time - self.start_time
                    print(f"⏱ {elapsed:.1f}s: Processed {self.total_files} items, found {sum(self.risk_files.values())} risks, {len(self.errors)} errors")
                    last_report_time = current_time

                # Dizin ve dosyaları işle
                for name in dirs + files:
                    full_path = os.path.join(root, name)

                    # Hariç tutulan yolu atla
                    if any(os.path.abspath(full_path).startswith(excluded) for excluded in self.exclude_paths):
                        continue

                    info = self.get_file_info(full_path)

                    if 'error' in info:
                        with self.lock:
                            errors.append(f"⚠️ Error processing {full_path}: {info['error']}")
                        continue

                    # Sembolik bağlantıları takip ederken sonsuz döngüleri önle
                    if info['inode'] in self.processed_inodes and info['type'] != 'symlink':
                        continue

                    self.processed_inodes.add(info['inode'])

                    # Risk seviyesine göre sayaçları güncelle
                    if info['risk_level'] in self.risk_files:
                        with self.lock:
                            self.risk_files[info['risk_level']] += 1

                    row_html = self.format_row(info)
                    rows.append(row_html)

                    with self.lock:
                        self.total_files += 1

        except KeyboardInterrupt:
            print("\n🛑 Scan interrupted by user.")

        # Hatalar varsa yazdır
        if errors:
            print("\n".join(errors[:10]))
            if len(errors) > 10:
                print(f"... and {len(errors) - 10} more errors.")

        return rows

    def format_row(self, info):
        """Tek bir satır için HTML oluşturur"""
        if 'error' in info:
            return f"""
<tr class="error-row">
    <td colspan="10" class="error">
        Error processing {escape(info['path'])}: {escape(info['error'])}
    </td>
</tr>"""

        risk_class = ''
        risk_label = ''

        # Risk seviyesine göre sınıf ve etiket belirle
        if info['risk_level'] == 'high':
            risk_class = 'high-risk'
            risk_label = '<span class="risk-label high">HIGH</span>'
        elif info['risk_level'] == 'medium':
            risk_class = 'medium-risk'
            risk_label = '<span class="risk-label medium">MEDIUM</span>'
        elif info['risk_level'] == 'low':
            risk_class = 'low-risk'
            risk_label = '<span class="risk-label low">LOW</span>'

        # Özel dosya türleri için ikonlar
        type_icon = {
            'directory': '📁',
            'file': '📄',
            'symlink': '🔗',
            'character_device': '📱',
            'block_device': '💾',
            'fifo': '📬',
            'socket': '🔌',
            'unknown': '❓'
        }.get(info['type'], '❓')

        # İlgi çekici dosya uzantıları için ek simge
        interesting_marker = ' 🔍' if info.get('has_interesting_extension', False) else ''

        # Symlink hedefini göster
        symlink_target = f" → {info['target']}" if 'target' in info else ''

        # Risk türlerini göster
        risk_types_str = ', '.join(info['risk_types']) if info['risk_types'] else 'None'

        return f"""
<tr class="{risk_class}" data-path="{escape(info['path'])}" data-risk="{info['risk_level']}">
    <td>{escape(info['path'])}{symlink_target}</td>
    <td>{type_icon} {info['type']}{interesting_marker}</td>
    <td>{info['mode_str']}</td>
    <td class="octal">{info['octal_perm']}</td>
    <td>{info['owner']}/{info['group']}</td>
    <td>{self.format_size(info['size'])}</td>
    <td>{info['mtime'].strftime('%Y-%m-%d %H:%M')}</td>
    <td>{risk_label} {risk_types_str}</td>
    <td class="acl"><pre>{escape(info['acl'])}</pre></td>
</tr>"""

    def generate_html_report(self, rows_data, output_file):
        """HTML raporu oluşturur"""
        # İstatistikleri hesapla
        total_risks = sum(self.risk_files.values())
        risk_percent = (total_risks / self.total_files * 100) if self.total_files > 0 else 0
        elapsed_time = time.time() - self.start_time

        # Risk türleri istatistikleri
        risk_stats_html = ""
        for risk_name, count in self.stats.items():
            if count > 0:
                risk_stats_html += f"<div class='stat-item'><strong>{risk_name.replace('_', ' ').title()}:</strong> {count}</div>"

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Advanced Permission Analyzer</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; margin: 20px; background-color: #f5f5f5; color: #333; }}
        h1, h2 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 5px; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 5px; box-shadow: 0 1px 3px rgba(0,0,0,0.12); }}
        .summary {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 15px; }}
        .stat-box {{ background-color: white; padding: 10px; border-radius: 5px; box-shadow: 0 1px 2px rgba(0,0,0,0.05); }}
        .stat-item {{ margin-bottom: 5px; }}
        .controls {{ margin: 15px 0; display: flex; flex-wrap: wrap; gap: 10px; }}
        input[type="text"], select {{ padding: 8px; border: 1px solid #ddd; border-radius: 4px; }}
        button {{ padding: 8px 12px; background: #3498db; color: white; border: none; border-radius: 4px; cursor: pointer; }}
        button:hover {{ background: #2980b9; }}

        table {{
            border-collapse: collapse;
            width: 100%;
            font-size: 14px;
            margin-top: 15px;
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
            z-index: 10;
        }}
        tr.high-risk {{ background-color: #ffdddd !important; }}
        tr.medium-risk {{ background-color: #fff3cd !important; }}
        tr.low-risk {{ background-color: #e2f0d9 !important; }}
        tr.error-row {{ background-color: #f8d7da !important; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        .octal {{ font-family: monospace; font-weight: bold; }}
        .acl {{ white-space: pre; font-family: monospace; font-size: 0.9em; max-height: 100px; overflow-y: auto; }}
        .risk-label {{
            font-weight: bold;
            padding: 2px 5px;
            border-radius: 3px;
            font-size: 12px;
        }}
        .high {{ background-color: #ff4444; color: white; }}
        .medium {{ background-color: #ffbb33; color: black; }}
        .low {{ background-color: #99cc00; color: black; }}
        .error {{ color: #d9534f; }}

        /* Responsive tasarım */
        @media (max-width: 768px) {{
            .summary-grid {{ grid-template-columns: 1fr; }}
            table {{ font-size: 12px; }}
            th, td {{ padding: 4px; }}
        }}
    </style>
    <script>
        window.onload = function() {{
            // Filtreleme ve sıralama işlevleri
            document.getElementById('filter-input').addEventListener('input', filterTable);
            document.getElementById('risk-filter').addEventListener('change', filterTable);

            function filterTable() {{
                const filterText = document.getElementById('filter-input').value.toLowerCase();
                const riskLevel = document.getElementById('risk-filter').value;
                const rows = document.querySelectorAll('table tbody tr');

                rows.forEach(row => {{
                    const path = row.getAttribute('data-path') || '';
                    const risk = row.getAttribute('data-risk') || 'none';

                    const matchesText = path.toLowerCase().includes(filterText);
                    const matchesRisk = riskLevel === 'all' || risk === riskLevel;

                    row.style.display = (matchesText && matchesRisk) ? '' : 'none';
                }});

                updateDisplayCount();
            }}

            function updateDisplayCount() {{
                const visibleRows = document.querySelectorAll('table tbody tr[style=""]').length;
                document.getElementById('visible-count').textContent = visibleRows;
            }}

            // Export JSON verisi
            document.getElementById('export-json').addEventListener('click', function() {{
                // JSON verisi oluştur
                const tableData = [];
                const rows = document.querySelectorAll('table tbody tr');

                rows.forEach(row => {{
                    if (!row.classList.contains('error-row')) {{
                        const cells = row.querySelectorAll('td');
                        if (cells.length >= 8) {{
                            tableData.push({{
                                path: cells[0].textContent,
                                type: cells[1].textContent.trim(),
                                permissions: cells[2].textContent,
                                octal: cells[3].textContent,
                                owner_group: cells[4].textContent,
                                size: cells[5].textContent,
                                modified: cells[6].textContent,
                                risk: cells[7].textContent
                            }});
                        }}
                    }}
                }});

                // JSON dosyasını indir
                const jsonStr = JSON.stringify(tableData, null, 2);
                const blob = new Blob([jsonStr], {{ type: 'application/json' }});
                const url = URL.createObjectURL(blob);

                const a = document.createElement('a');
                a.href = url;
                a.download = 'permission_analysis.json';
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
            }});
        }};
    </script>
</head>
<body>
    <div class="container">
        <h1>Advanced Permission Analysis Report</h1>

        <div class="summary">
            <h2>Scan Summary</h2>
            <div class="summary-grid">
                <div class="stat-box">
                    <div class="stat-item"><strong>Generated:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
                    <div class="stat-item"><strong>Scan Duration:</strong> {elapsed_time:.1f} seconds</div>
                    <div class="stat-item"><strong>Total Items:</strong> {self.total_files}</div>
                    <div class="stat-item"><strong>Total Risks:</strong> {total_risks} ({risk_percent:.1f}%)</div>
                </div>

                <div class="stat-box">
                    <div class="stat-item"><strong>High Risks:</strong> {self.risk_files['high']}</div>
                    <div class="stat-item"><strong>Medium Risks:</strong> {self.risk_files['medium']}</div>
                    <div class="stat-item"><strong>Low Risks:</strong> {self.risk_files['low']}</div>
                    <div class="stat-item"><strong>Errors:</strong> {len(self.errors)}</div>
                </div>

                <div class="stat-box">
                    <h3>Risk Types</h3>
                    {risk_stats_html}
                </div>
            </div>
        </div>

        <div class="controls">
            <input type="text" id="filter-input" placeholder="Filter by path..." style="flex-grow: 1;">
            <select id="risk-filter">
                <option value="all">All Risks</option>
                <option value="high">High Risk</option>
                <option value="medium">Medium Risk</option>
                <option value="low">Low Risk</option>
                <option value="none">No Risk</option>
            </select>
            <button id="export-json">Export JSON</button>
        </div>

        <div>
            Showing <span id="visible-count">{self.total_files}</span> items
        </div>

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
                {rows_data}
            </tbody>
        </table>

        <div class="summary">
            <h2>Errors</h2>
            <pre>{json.dumps(self.errors, indent=2) if self.errors else "No errors encountered."}</pre>
        </div>
    </div>
</body>
</html>"""

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)

def main():
    parser = argparse.ArgumentParser(
        description='Advanced file permission analyzer with security risk detection',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('path', help='Directory to analyze')
    parser.add_argument('-o', '--output', default='permission_report.html',
                      help='Output HTML file')
    parser.add_argument('-f', '--follow-symlinks', action='store_true',
                      help='Follow symbolic links (be careful with loops)')
    parser.add_argument('-e', '--exclude', nargs='+', default=[],
                      help='Exclude paths (can specify multiple)')
    parser.add_argument('-j', '--json-output',
                      help='Also save results as JSON file')

    args = parser.parse_args()

    if not os.path.isdir(args.path):
        print(f"Error: {args.path} is not a valid directory")
        exit(1)

    print(f"🔍 Starting analysis of {args.path}...")
    if args.follow_symlinks:
        print("⚠️ Warning: Following symbolic links may cause infinite loops!")

    print(f"🔒 Checking if running with sufficient permissions...")
    try:
        test_path = os.path.join(args.path, ".permission_test")
        with open(test_path, "w") as f:
            f.write("test")
        os.remove(test_path)
        print("✅ Write permission test passed")
    except Exception:
        print("⚠️ Warning: You may not have sufficient permissions to access all files")
        print("💡 Consider running the script with sudo for complete analysis")

    analyzer = PermissionAnalyzer()
    rows = analyzer.scan_directory(args.path, args.follow_symlinks, args.exclude)
    analyzer.generate_html_report('\n'.join(rows), args.output)

    # JSON çıktısı üret
    if args.json_output:
        try:
            data = {
                'summary': {
                    'total_files': analyzer.total_files,
                    'risk_files': analyzer.risk_files,
                    'errors': len(analyzer.errors),
                    'stats': analyzer.stats
                },
                'errors': analyzer.errors
            }
            with open(args.json_output, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
            print(f"✅ JSON data saved to: {args.json_output}")
        except Exception as e:
            print(f"❌ Error saving JSON data: {str(e)}")

    print(f"\n✅ Report generated: {args.output}")
    print(f"📊 Summary:")
    print(f"  - Total items: {analyzer.total_files}")
    print(f"  - High risks: {analyzer.risk_files['high']}")
    print(f"  - Medium risks: {analyzer.risk_files['medium']}")
    print(f"  - Low risks: {analyzer.risk_files['low']}")
    print(f"  - Errors: {len(analyzer.errors)}")
    print(f"\n⏱ Scan completed in {time.time() - analyzer.start_time:.1f} seconds")

if __name__ == "__main__":
    main()
