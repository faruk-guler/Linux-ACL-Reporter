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
        self.risk_files = {'high': 0, 'medium': 0, 'low': 0, 'none': 0}
        self.processed_inodes = set()
        self.errors = []
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.stats = {
            'world_writable': 0,
            'setuid': 0,
            'setgid': 0,
            'root_writable': 0,
            'symlink': 0,
            'sticky_bit': 0,
            'interesting_extensions': 0
        }
        self.interesting_extensions = ['.sh', '.py', '.pl', '.rb', '.php', '.conf', '.key', '.pem', '.crt', '.ini']
        self.exclude_paths = set()
        self.has_getfacl = shutil.which('getfacl') is not None
        self.visited_real_paths = set()  # Sembolik bağlantı döngüleri için gerçek yolları takip et

    def get_detailed_permissions(self, mode):
        """Analyze file permissions in detail"""
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

    def get_permission_string(self, mode):
        """Return permissions in drwxr-xr-x format (including special bits)"""
        perms = ['-'] * 10
        file_types = {
            stat.S_IFREG: '-',
            stat.S_IFDIR: 'd',
            stat.S_IFLNK: 'l',
            stat.S_IFCHR: 'c',
            stat.S_IFBLK: 'b',
            stat.S_IFSOCK: 's',
            stat.S_IFIFO: 'p',
        }
        perms[0] = file_types.get(stat.S_IFMT(mode), '?')

        perms[1] = 'r' if mode & stat.S_IRUSR else '-'
        perms[2] = 'w' if mode & stat.S_IWUSR else '-'
        perms[3] = 'x' if mode & stat.S_IXUSR else '-'

        perms[4] = 'r' if mode & stat.S_IRGRP else '-'
        perms[5] = 'w' if mode & stat.S_IWGRP else '-'
        perms[6] = 'x' if mode & stat.S_IXGRP else '-'

        perms[7] = 'r' if mode & stat.S_IROTH else '-'
        perms[8] = 'w' if mode & stat.S_IWOTH else '-'
        perms[9] = 'x' if mode & stat.S_IXOTH else '-'

        if mode & stat.S_ISUID:
            perms[3] = 's' if perms[3] == 'x' else 'S'
        if mode & stat.S_ISGID:
            perms[6] = 's' if perms[6] == 'x' else 'S'
        if mode & stat.S_ISVTX:
            perms[9] = 't' if perms[9] == 'x' else 'T'

        return ''.join(perms)

    def permission_to_octal(self, mode):
        """Convert permissions to octal format"""
        return oct(mode & 0o777)[2:].zfill(3)

    def get_file_info(self, path):
        """Collect detailed information about a file or directory"""
        try:
            path_obj = Path(path)
            abs_path = os.path.abspath(path)
            real_path = os.path.realpath(path)  # Sembolik bağlantının gerçek yolu

            # Sembolik bağlantı döngü kontrolü
            if real_path in self.visited_real_paths:
                error_msg = f"Symlink loop detected at {path} -> {real_path}"
                with self.lock:
                    self.errors.append({'path': path, 'error': error_msg})
                return {'error': error_msg, 'path': path}
            self.visited_real_paths.add(real_path)

            if path_obj.is_symlink():
                st = os.lstat(path)
                try:
                    target = os.readlink(path)
                except OSError as e:
                    target = f"UNREADABLE: {str(e)}"
                file_type = 'symlink'
            else:
                st = os.lstat(path)
                target = ''
                if stat.S_ISDIR(st.st_mode): file_type = 'directory'
                elif stat.S_ISREG(st.st_mode): file_type = 'file'
                elif stat.S_ISCHR(st.st_mode): file_type = 'character_device'
                elif stat.S_ISBLK(st.st_mode): file_type = 'block_device'
                elif stat.S_ISFIFO(st.st_mode): file_type = 'fifo'
                elif stat.S_ISSOCK(st.st_mode): file_type = 'socket'
                else: file_type = 'unknown'

            perms = self.get_detailed_permissions(st.st_mode)
            perm_string = self.get_permission_string(st.st_mode)
            octal_perm = self.permission_to_octal(st.st_mode)

            try:
                owner = pwd.getpwuid(st.st_uid).pw_name
            except KeyError:
                owner = str(st.st_uid)

            try:
                group = grp.getgrgid(st.st_gid).gr_name
            except KeyError:
                group = str(st.st_gid)

            risk_level, risk_types = self.check_security_risk(perms, st.st_uid, path_obj.suffix.lower(), path, st.st_mode)

            extension = path_obj.suffix.lower()
            has_interesting_extension = extension in self.interesting_extensions

            if has_interesting_extension:
                with self.lock:
                    self.stats['interesting_extensions'] += 1

            with self.lock:
                for risk_type in risk_types:
                    if risk_type in self.stats:
                        self.stats[risk_type] += 1

            result = {
                'path': path,
                'type': file_type,
                'mode_str': perm_string,
                'octal_perm': octal_perm,
                'owner': owner,
                'group': group,
                'size': st.st_size,
                'mtime': datetime.datetime.fromtimestamp(st.st_mtime),
                'inode': st.st_ino,
                'risk_level': risk_level,
                'risk_types': risk_types,
                'has_interesting_extension': has_interesting_extension,
                'target': target
            }

            if self.has_getfacl and file_type not in ['symlink', 'socket', 'fifo']:
                try:
                    result['acl'] = self.get_acl_info(path)
                except Exception as e:
                    result['acl'] = f"ACL Error: {str(e)}"
            else:
                result['acl'] = "Symlink: ACL not applicable" if file_type == 'symlink' else "getfacl not available"

            return result

        except (PermissionError, FileNotFoundError) as e:
            with self.lock:
                self.errors.append({'path': path, 'error': str(e)})
            return {'error': str(e), 'path': path}
        except Exception as e:
            with self.lock:
                self.errors.append({'path': path, 'error': str(e)})
            return {'error': str(e), 'path': path}

    def check_security_risk(self, perms, uid, extension, path, mode):
        """Check for security risks"""
        risks = []
        risk_level = 'none'

        if stat.S_ISLNK(mode):
            risks.append('symlink')
            risk_level = 'low'
        else:
            if perms['others']['write']:
                risks.append('world_writable')
                risk_level = 'high'

            if uid == 0 and perms['owner']['write'] and path != '/':
                risks.append('root_writable')
                if risk_level != 'high':
                    risk_level = 'medium'

            is_executable = perms['owner']['execute'] or perms['group']['execute'] or perms['others']['execute']
            if perms['special']['setuid'] and is_executable:
                risks.append('setuid')
                risk_level = 'high'
            if perms['special']['setgid'] and is_executable:
                risks.append('setgid')
                if risk_level != 'high':
                    risk_level = 'medium'

            if perms['group']['write'] and not perms['owner']['write']:
                risks.append('unusual_permissions')
                if risk_level == 'none':
                    risk_level = 'low'

            if extension in ['.key', '.pem'] and perms['others']['read']:
                risks.append('sensitive_file_readable')
                risk_level = 'high'

            if extension in ['.sh', '.py', '.pl', '.rb'] and perms['others']['execute']:
                risks.append('script_executable')
                if risk_level == 'none':
                    risk_level = 'low'

            if mode & stat.S_ISUID and not path.startswith(('/bin', '/usr')):
                risks.append('suid_risk')
                risk_level = 'high'

            if mode & stat.S_ISVTX:
                risks.append('sticky_bit')
                if risk_level == 'none':
                    risk_level = 'medium'

        return risk_level, risks

    def get_acl_info(self, path, timeout=5):
        """Retrieve ACL information"""
        if not self.has_getfacl:
            return "getfacl not available"

        try:
            result = subprocess.run(
                ['getfacl', '-p', path],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout.strip() if result.returncode == 0 else f"Error: {result.stderr.strip()}"
        except subprocess.TimeoutExpired:
            return "ACL retrieval timed out"
        except Exception as e:
            return f"ACL Error: {str(e)}"

    def format_size(self, size):
        """Convert file size to human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0 or unit == 'TB':
                return f"{size:.1f} {unit}"
            size /= 1024.0

    def scan_directory(self, path, follow_symlinks=False, exclude_paths=None, depth=5):
        """Scan directory and prepare report data"""
        if exclude_paths:
            self.exclude_paths = set(os.path.abspath(p) for p in exclude_paths)

        temp_file = 'temp_rows.html'
        visited_paths = set()

        try:
            with open(temp_file, 'w', encoding='utf-8', errors='replace') as f:
                main_dir_info = self.get_file_info(path)
                if 'error' not in main_dir_info:
                    f.write(self.format_row(main_dir_info) + '\n')
                    self.total_files += 1
                    if main_dir_info['risk_level'] in self.risk_files:
                        self.risk_files[main_dir_info['risk_level']] += 1
                    visited_paths.add(os.path.abspath(path))

            print(f"🔍 Scanning {path} with max depth {depth}...")
            print("Progress will be reported every 5 seconds")

            last_report_time = time.time()
            progress_report_interval = 5

            def get_depth(current_path):
                try:
                    current_path = os.path.abspath(current_path)
                    base_path = os.path.abspath(path)
                    if current_path == base_path:
                        return 0
                    rel_path = os.path.relpath(current_path, base_path)
                    return rel_path.count(os.sep) + 1
                except ValueError:
                    return 0

            for root, dirs, files in os.walk(path, topdown=True, followlinks=follow_symlinks):
                abs_root = os.path.abspath(root)
                if follow_symlinks and abs_root in visited_paths:
                    print(f"Skipping loop: {root}")
                    dirs[:] = []
                    continue
                visited_paths.add(abs_root)

                if any(os.path.abspath(root).startswith(excluded) for excluded in self.exclude_paths):
                    print(f"Excluding directory: {root}")
                    dirs[:] = []
                    continue
                if get_depth(root) >= depth:
                    print(f"Depth limit reached: {root}")
                    dirs[:] = []
                    continue

                current_time = time.time()
                if current_time - last_report_time > progress_report_interval:
                    elapsed = current_time - self.start_time
                    print(f"⏱ {elapsed:.1f}s: Processed {self.total_files} items, found {sum(self.risk_files.values()) - self.risk_files.get('none', 0)} risks")
                    last_report_time = current_time

                with open(temp_file, 'a', encoding='utf-8', errors='replace') as f:
                    for name in dirs + files:
                        full_path = os.path.join(root, name)
                        if any(os.path.abspath(full_path).startswith(excluded) for excluded in self.exclude_paths):
                            continue
                        info = self.get_file_info(full_path)
                        if 'error' in info:
                            print(f"⚠️ Error processing {full_path}: {info['error']}")
                            continue
                        if info['inode'] in self.processed_inodes and info['type'] != 'symlink':
                            continue
                        self.processed_inodes.add(info['inode'])
                        if info['risk_level'] in self.risk_files:
                            with self.lock:
                                self.risk_files[info['risk_level']] += 1
                        f.write(self.format_row(info) + '\n')
                        with self.lock:
                            self.total_files += 1

        except KeyboardInterrupt:
            print("\n🛑 Scan interrupted by user.")
        except Exception as e:
            print(f"\n❌ Error during scan: {str(e)}")
        finally:
            try:
                with open(temp_file, 'r', encoding='utf-8', errors='replace') as f:
                    rows = f.read().splitlines()
                os.remove(temp_file)
                return rows
            except Exception as e:
                print(f"❌ Error reading temporary file: {str(e)}")
                return []

    def format_row(self, info):
        """Generate HTML for a single table row"""
        if 'error' in info:
            return f"""
<tr class="error-row">
    <td colspan="10" class="error">Error processing {escape(info['path'])}: {escape(info['error'])}</td>
</tr>"""

        risk_class = ''
        risk_label = ''

        if info['risk_level'] == 'high':
            risk_class = 'high-risk'
            risk_label = '<span class="risk-label high">HIGH</span>'
        elif info['risk_level'] == 'medium':
            risk_class = 'medium-risk'
            risk_label = '<span class="risk-label medium">MEDIUM</span>'
        elif info['risk_level'] == 'low':
            risk_class = 'low-risk'
            risk_label = '<span class="risk-label low">LOW</span>'

        type_icon = {
            'directory': '📁', 'file': '📄', 'symlink': '🔗',
            'character_device': '📱', 'block_device': '💾',
            'fifo': '📬', 'socket': '🔌', 'unknown': '❓'
        }.get(info['type'], '❓')

        interesting_marker = ' 🔍' if info.get('has_interesting_extension', False) else ''
        symlink_target = info['target']
        risk_types_str = ', '.join(info['risk_types']) if info['risk_types'] else 'None'
        acl_info = info.get('acl', 'Not available')

        return f"""
<tr class="{risk_class}" data-path="{escape(info['path'])}" data-risk="{info['risk_level']}">
    <td>{escape(info['path'])}</td>
    <td>{type_icon} {info['type']}{interesting_marker}</td>
    <td>{info['mode_str']}</td>
    <td class="octal">{info['octal_perm']}</td>
    <td>{info['owner']}</td>
    <td>{info['group']}</td>
    <td>{self.format_size(info['size'])}</td>
    <td>{info['mtime'].strftime('%Y-%m-%d %H:%M')}</td>
    <td>{risk_label} {risk_types_str}</td>
    <td>{escape(symlink_target)}</td>
    <td class="acl"><pre>{escape(str(acl_info))}</pre></td>
</tr>"""

    def generate_html_report(self, rows_data, output_file, scanned_directory):
        """Generate HTML report with error section"""
        total_risks = sum(value for key, value in self.risk_files.items() if key != 'none')
        elapsed_time = time.time() - self.start_time
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        risk_stats_html = ""
        for risk_name, count in self.stats.items():
            if count > 0:
                risk_stats_html += f"<div class='stat-item'><strong>{risk_name.replace('_', ' ').title()}:</strong> {count}</div>"

        # Hata tablosu oluştur
        error_rows = ""
        if self.errors:
            for error in self.errors:
                error_rows += f"""
<tr class="error-row">
    <td>{escape(error['path'])}</td>
    <td>{escape(error['error'])}</td>
</tr>"""

        error_section = ""
        if error_rows:
            error_section = f"""
<div class="errors">
    <h2>⚠️ Hata Kayıtları</h2>
    <table>
        <thead>
            <tr>
                <th>Yol</th>
                <th>Hata Mesajı</th>
            </tr>
        </thead>
        <tbody>
            {error_rows}
        </tbody>
    </table>
</div>
"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Linux File Permissions Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #f9f9f9; color: #333; }}
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
        table {{ border-collapse: collapse; width: 100%; font-size: 14px; margin-top: 15px; }}
        th, td {{ border: 1px solid #ccc; padding: 5px; text-align: left; vertical-align: top; }}
        th {{ background-color: #f2f2f2; position: sticky; top: 0; z-index: 10; }}
        tr.high-risk {{ background-color: #ffd6d6 !important; }}
        tr.medium-risk {{ background-color: #fff3cd !important; }}
        tr.low-risk {{ background-color: #e2f0d9 !important; }}
        tr.error-row {{ background-color: #f8d7da !important; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        tr:hover {{ background-color: #f5f5f5; }}
        .octal {{ font-family: monospace; font-weight: bold; }}
        .acl {{ white-space: pre; font-family: monospace; font-size: 0.9em; max-height: 100px; overflow-y: auto; }}
        .risk-label {{ font-weight: bold; padding: 2px 5px; border-radius: 3px; font-size: 12px; }}
        .high {{ background-color: #ff4444; color: white; }}
        .medium {{ background-color: #ffbb33; color: black; }}
        .low {{ background-color: #99cc00; color: black; }}
        .error {{ color: #d9534f; }}
        .errors {{ margin-top: 20px; }}
        @media (max-width: 768px) {{ .summary-grid {{ grid-template-columns: 1fr; }} table {{ font-size: 12px; }} th, td {{ padding: 4px; }} }}
    </style>
    <script>
        window.onload = function() {{
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
                const visibleRows = document.querySelectorAll('table tbody tr:not([style*="display: none"])').length;
                document.getElementById('visible-count').textContent = visibleRows;
            }}

            document.getElementById('export-json').addEventListener('click', function() {{
                const tableData = [];
                const rows = document.querySelectorAll('table tbody tr');

                rows.forEach(row => {{
                    if (!row.classList.contains('error-row')) {{
                        const cells = row.querySelectorAll('td');
                        if (cells.length >= 10) {{
                            tableData.push({{
                                path: cells[0].textContent,
                                type: cells[1].textContent.trim(),
                                permissions: cells[2].textContent,
                                octal: cells[3].textContent,
                                owner: cells[4].textContent,
                                group: cells[5].textContent,
                                size: cells[6].textContent,
                                modified: cells[7].textContent,
                                risk: cells[8].textContent,
                                symlink_target: cells[9].textContent,
                                acl: cells[10].textContent
                            }});
                        }}
                    }}
                }});

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
            updateDisplayCount();
        }};
    </script>
</head>
<body>
    <div class="container">
        <h1>📋 Linux File Permissions Report</h1>
        <p>Generated At: {now}</p>

        <div class="summary">
            <h2>Scan Summary</h2>
            <div class="summary-grid">
                <div class="stat-box">
                    <div class="stat-item"><strong>Scanned Directory:</strong> {escape(scanned_directory)}</div>
                    <div class="stat-item"><strong>Generated:</strong> {now}</div>
                    <div class="stat-item"><strong>Scan Duration:</strong> {elapsed_time:.1f} seconds</div>
                    <div class="stat-item"><strong>Total Items:</strong> {self.total_files}</div>
                    <div class="stat-item"><strong>Total Risks:</strong> {total_risks}</div>
                </div>

                <div class="stat-box">
                    <div class="stat-item"><strong>High Risks:</strong> {self.risk_files['high']}</div>
                    <div class="stat-item"><strong>Medium Risks:</strong> {self.risk_files['medium']}</div>
                    <div class="stat-item"><strong>Low Risks:</strong> {self.risk_files['low']}</div>
                    <div class="stat-item"><strong>No Risk:</strong> {self.risk_files.get('none', 0)}</div>
                    <div class="stat-item"><strong>Errors:</strong> {len(self.errors)}</div>
                </div>

                <div class="stat-box">
                    <h3>Risk Types</h3>
                    {risk_stats_html}
                </div>
            </div>
        </div>

        {error_section}

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
                    <th>Owner</th>
                    <th>Group</th>
                    <th>Size</th>
                    <th>Modified</th>
                    <th>Risk Warning</th>
                    <th>Symlink Target</th>
                    <th>ACL</th>
                </tr>
            </thead>
            <tbody>
                {rows_data}
            </tbody>
        </table>
    </div>
</body>
</html>"""

        try:
            with open(output_file, 'w', encoding='utf-8', errors='replace') as f:
                f.write(html)
        except Exception as e:
            print(f"❌ Error writing HTML report: {str(e)}")
            try:
                alt_output = f"permission_report_backup_{int(time.time())}.html"
                with open(alt_output, 'w', encoding='utf-8', errors='replace') as f:
                    f.write(html)
                print(f"✅ Backup report saved to: {alt_output}")
            except Exception:
                print("❌ Failed to write backup report")

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
    parser.add_argument('-d', '--depth', type=int, default=5,
                      help='Maximum directory traversal depth (minimum 0)')

    args = parser.parse_args()

    if not os.path.exists(args.path):
        print(f"Error: {args.path} does not exist")
        exit(1)

    if not os.path.isdir(args.path):
        print(f"Error: {args.path} is not a valid directory")
        exit(1)

    if args.depth < 0:
        print("Error: Depth cannot be negative")
        exit(1)

    if args.depth == 0:
        print("⚠️ Warning: Depth is 0, only the root directory will be scanned")

    print(f"🔍 Starting analysis of {args.path} with max depth {args.depth}...")
    if args.follow_symlinks:
        print("⚠️ Warning: Following symbolic links may cause infinite loops!")

    analyzer = PermissionAnalyzer()
    rows = analyzer.scan_directory(args.path, args.follow_symlinks, args.exclude, args.depth)
    analyzer.generate_html_report('\n'.join(rows), args.output, args.path)

    if args.json_output:
        try:
            data = {
                'summary': {
                    'scanned_directory': args.path,
                    'total_files': analyzer.total_files,
                    'risk_files': analyzer.risk_files,
                    'errors': len(analyzer.errors),
                    'stats': analyzer.stats
                },
                'errors': analyzer.errors
            }
            with open(args.json_output, 'w', encoding='utf-8', errors='replace') as f:
                json.dump(data, f, indent=2, default=str)
            print(f"✅ JSON data saved to: {args.json_output}")
        except Exception as e:
            print(f"❌ Error saving JSON data: {str(e)}")

    print(f"\n✅ Report generated: {args.output}")
    print(f"📊 Summary:")
    print(f"  - Scanned Directory: {args.path}")
    print(f"  - Total items: {analyzer.total_files}")
    print(f"  - High risks: {analyzer.risk_files['high']}")
    print(f"  - Medium risks: {analyzer.risk_files['medium']}")
    print(f"  - Low risks: {analyzer.risk_files['low']}")
    print(f"  - Errors: {len(analyzer.errors)}")
    print(f"\n⏱ Scan completed in {time.time() - analyzer.start_time:.1f} seconds")

if __name__ == "__main__":
    main()
