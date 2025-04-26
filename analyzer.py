#!/usr/bin/env python3-
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
import logging
from concurrent.futures import ThreadPoolExecutor
from collections import deque

# ANSI renk kodları
class Colors:
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    RED_BG = '\033[41;97m'  # Kırmızı zemin, beyaz metin

# Özel log formatlayıcı
class ColoredFormatter(logging.Formatter):
    def __init__(self, fmt):
        super().__init__(fmt)
        self.level_colors = {
            'DEBUG': Colors.CYAN,
            'INFO': Colors.GREEN,
            'WARNING': Colors.YELLOW,
            'ERROR': Colors.RED,
            'CRITICAL': Colors.RED_BG
        }

    def format(self, record):
        color = self.level_colors.get(record.levelname, Colors.RESET)
        message = super().format(record)
        return f"{color}{message}{Colors.RESET}"

class PermissionAnalyzer:
    def __init__(self, config=None):
        self.config = config or {
            'interesting_extensions': ['.sh', '.py', '.pl', '.rb', '.php', '.conf', '.key', '.pem', '.crt', '.ini'],
            'acl_timeout': 5
        }
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
        self.exclude_paths = set()
        self.is_posix = os.name == 'posix'
        self.has_getfacl = self.is_posix and shutil.which('getfacl') is not None
        self.visited_real_paths = set()

        # Logging yapılandırması
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        handlers = [
            logging.StreamHandler(),  # Konsol
            logging.FileHandler('permission_analyzer.log')  # Dosya
        ]

        # Konsol için renkli formatlayıcı
        colored_formatter = ColoredFormatter(log_format)
        handlers[0].setFormatter(colored_formatter)

        # Dosya için renksiz formatlayıcı
        file_formatter = logging.Formatter(log_format)
        handlers[1].setFormatter(file_formatter)

        logging.basicConfig(
            level=logging.INFO,
            handlers=handlers
        )
        self.logger = logging.getLogger(__name__)

    def get_detailed_permissions(self, mode):
        """Analyze file permissions in detail."""
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
        """Return permissions in drwxr-xr-x format (including special bits)."""
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
        """Convert permissions to octal format."""
        return oct(mode & 0o777)[2:].zfill(3)

    def get_file_info(self, path):
        """
        Collect detailed information about a file or directory.

        Args:
            path (str): Path to the file or directory.

        Returns:
            dict: File information including permissions, owner, group, risk level, etc.

        Raises:
            PermissionError: If access to the file is denied.
            FileNotFoundError: If the file does not exist.
        """
        try:
            path_obj = Path(path)
            abs_path = os.path.abspath(path)
            real_path = os.path.realpath(path)

            if real_path in self.visited_real_paths:
                self.logger.warning(f"Symlink loop detected at {path} -> {real_path}")
                return None
            self.visited_real_paths.add(real_path)

            if path_obj.is_symlink():
                st = os.lstat(path)
                try:
                    target = os.readlink(path)
                except OSError as e:
                    target = f"BROKEN SYMLINK: {str(e)}"
                    self.logger.warning(f"Broken symlink at {path}: {e}")
                    return {'error': target, 'path': path}
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
                owner = pwd.getpwuid(st.st_uid).pw_name if self.is_posix else str(st.st_uid)
            except (KeyError, AttributeError):
                owner = str(st.st_uid)

            try:
                group = grp.getgrgid(st.st_gid).gr_name if self.is_posix else str(st.st_gid)
            except (KeyError, AttributeError):
                group = str(st.st_gid)

            risk_level, risk_types = self.check_security_risk(perms, st.st_uid, path_obj.suffix.lower(), path, st.st_mode)

            extension = path_obj.suffix.lower()
            has_interesting_extension = extension in self.config['interesting_extensions']

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
                    result['acl'] = self.get_acl_info(path, timeout=self.config['acl_timeout'])
                except Exception as e:
                    result['acl'] = f"ACL Error: {str(e)}"
                    self.logger.error(f"ACL error for {path}: {e}")
            else:
                result['acl'] = "Symlink: ACL not applicable" if file_type == 'symlink' else "getfacl not available"

            return result

        except PermissionError as e:
            error_msg = f"Permission denied: {str(e)}"
            self.logger.error(error_msg)
            if len(self.errors) < 100:
                with self.lock:
                    self.errors.append({'path': path, 'error': error_msg})
            else:
                self.logger.warning("Too many errors, stopping error logging")
            return {'error': error_msg, 'path': path}
        except FileNotFoundError as e:
            error_msg = f"File not found: {str(e)}"
            self.logger.error(error_msg)
            if len(self.errors) < 100:
                with self.lock:
                    self.errors.append({'path': path, 'error': error_msg})
            else:
                self.logger.warning("Too many errors, stopping error logging")
            return {'error': error_msg, 'path': path}
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            self.logger.error(error_msg)
            if len(self.errors) < 100:
                with self.lock:
                    self.errors.append({'path': path, 'error': error_msg})
            else:
                self.logger.warning("Too many errors, stopping error logging")
            return {'error': error_msg, 'path': path}

    def check_security_risk(self, perms, uid, extension, path, mode):
        """Check for security risks."""
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
        """Retrieve ACL information."""
        if not self.has_getfacl:
            return "getfacl not available"
        try:
            result = subprocess.run(
                ['getfacl', '-p', path],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            if result.returncode != 0:
                error_msg = f"getfacl error: {result.stderr.strip()}"
                self.logger.error(error_msg)
                return error_msg
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            error_msg = "ACL retrieval timed out"
            self.logger.error(error_msg)
            return error_msg
        except subprocess.SubprocessError as e:
            error_msg = f"Subprocess error: {str(e)}"
            self.logger.error(error_msg)
            return error_msg
        except Exception as e:
            error_msg = f"Unexpected ACL error: {str(e)}"
            self.logger.error(error_msg)
            return error_msg

    def format_size(self, size):
        """Convert file size to human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0 or unit == 'TB':
                return f"{size:.1f} {unit}"
            size /= 1024.0

    def scan_directory(self, path, follow_symlinks=False, exclude_paths=None, depth=5, max_workers=4):
        """
        Scan directory and prepare report data.

        Args:
            path (str): Directory to scan.
            follow_symlinks (bool): Whether to follow symbolic links.
            exclude_paths (list): Paths to exclude.
            depth (int): Maximum directory traversal depth.
            max_workers (int): Number of worker threads.

        Returns:
            list: List of HTML row strings.
        """
        if exclude_paths:
            self.exclude_paths = set(os.path.abspath(p) for p in exclude_paths)

        rows = deque()
        visited_paths = set()

        try:
            main_dir_info = self.get_file_info(path)
            if main_dir_info and 'error' not in main_dir_info:
                rows.append(self.format_row(main_dir_info))
                with self.lock:
                    self.total_files += 1
                    self.risk_files[main_dir_info['risk_level']] += 1
                visited_paths.add(os.path.abspath(path))

            self.logger.info(f"Scanning {path} with max depth {depth}...")

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

            def process_item(full_path):
                if any(os.path.abspath(full_path).startswith(excluded) for excluded in self.exclude_paths):
                    return None
                info = self.get_file_info(full_path)
                if not info or 'error' in info:
                    return None
                if info['inode'] in self.processed_inodes and info['type'] != 'symlink':
                    return None
                self.processed_inodes.add(info['inode'])
                with self.lock:
                    self.risk_files[info['risk_level']] += 1
                    self.total_files += 1
                return self.format_row(info)

            last_report_time = time.time()
            progress_report_interval = 5

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                for root, dirs, files in os.walk(path, topdown=True, followlinks=follow_symlinks):
                    abs_root = os.path.abspath(root)
                    if follow_symlinks and abs_root in visited_paths:
                        self.logger.info(f"Skipping loop: {root}")
                        dirs[:] = []
                        continue
                    visited_paths.add(abs_root)

                    if any(os.path.abspath(root).startswith(excluded) for excluded in self.exclude_paths):
                        self.logger.info(f"Excluding directory: {root}")
                        dirs[:] = []
                        continue
                    if get_depth(root) >= depth:
                        self.logger.info(f"Depth limit reached: {root}")
                        dirs[:] = []
                        continue

                    current_time = time.time()
                    if current_time - last_report_time > progress_report_interval:
                        elapsed = current_time - self.start_time
                        self.logger.info(f"Processed {self.total_files} items, found {sum(self.risk_files.values()) - self.risk_files.get('none', 0)} risks in {elapsed:.1f}s")
                        last_report_time = current_time

                    futures = [executor.submit(process_item, os.path.join(root, name)) for name in dirs + files]
                    for future in futures:
                        result = future.result()
                        if result:
                            rows.append(result)

        except KeyboardInterrupt:
            self.logger.warning("Scan interrupted by user")
            raise
        except Exception as e:
            self.logger.error(f"Error during scan: {str(e)}")
            raise
        return list(rows)

    def format_row(self, info):
        """Generate HTML for a single table row."""
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
<tr class="{risk_class}" data-path="{escape(info['path'])}" data-risk="{info['risk_level']}" data-type="{info['type']}">
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
</tr>
"""

    def generate_html_report(self, rows_data, output_file, scanned_directory):
        """Generate HTML report without error section."""
        total_risks = sum(value for key, value in self.risk_files.items() if key != 'none')
        elapsed_time = time.time() - self.start_time
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        risk_stats_html = ""
        for risk_name, count in self.stats.items():
            if count > 0:
                risk_stats_html += f"<div class='stat-item'><strong>{risk_name.replace('_', ' ').title()}:</strong> {count}</div>"

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
        @media (max-width: 768px) {{ .summary-grid {{ grid-template-columns: 1fr; }} table {{ font-size: 12px; }} th, td {{ padding: 4px; }} }}
    </style>
    <script>
        window.onload = function() {{
            document.getElementById('filter-input').addEventListener('input', filterTable);
            document.getElementById('risk-filter').addEventListener('change', filterTable);
            document.getElementById('type-filter').addEventListener('change', filterTable);

            function filterTable() {{
                const filterText = document.getElementById('filter-input').value.toLowerCase();
                const riskLevel = document.getElementById('risk-filter').value;
                const typeFilter = document.getElementById('type-filter').value;
                const rows = document.querySelectorAll('table tbody tr');

                rows.forEach(row => {{
                    const path = row.getAttribute('data-path') || '';
                    const risk = row.getAttribute('data-risk') || 'none';
                    const type = row.getAttribute('data-type') || '';
                    const matchesText = path.toLowerCase().includes(filterText);
                    const matchesRisk = riskLevel === 'all' || risk === riskLevel;
                    const matchesType = typeFilter === 'all' || type === typeFilter;
                    row.style.display = (matchesText && matchesRisk && matchesType) ? '' : 'none';
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

                const jsonData = {{
                    summary: {{
                        scanned_directory: "{escape(scanned_directory)}",
                        total_files: {self.total_files},
                        risk_files: {json.dumps(self.risk_files)},
                        stats: {json.dumps(self.stats)}
                    }},
                    data: tableData
                }};

                const jsonStr = JSON.stringify(jsonData, null, 2);
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
        <h1>📋 Linux File Permissions Report -farukguler.com</h1>
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
            <select id="type-filter">
                <option value="all">All Types</option>
                <option value="file">File</option>
                <option value="directory">Directory</option>
                <option value="symlink">Symlink</option>
                <option value="character_device">Character Device</option>
                <option value="block_device">Block Device</option>
                <option value="fifo">FIFO</option>
                <option value="socket">Socket</option>
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
                {''.join(rows_data)}
            </tbody>
        </table>
    </div>
</body>
</html>"""

        try:
            with open(output_file, 'w', encoding='utf-8', errors='replace') as f:
                f.write(html)
            self.logger.info(f"HTML report generated: {output_file}")
        except Exception as e:
            self.logger.error(f"Error writing HTML report: {str(e)}")
            try:
                alt_output = f"permission_report_backup_{int(time.time())}.html"
                with open(alt_output, 'w', encoding='utf-8', errors='replace') as f:
                    f.write(html)
                self.logger.info(f"Backup report saved to: {alt_output}")
            except Exception as e:
                self.logger.error(f"Failed to write backup report: {str(e)}")

    def main(self):
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
                          help='Maximum directory traversal depth (minimum 1)')
        parser.add_argument('--acl-timeout', type=int, default=5,
                          help='Timeout for getfacl command in seconds')
        parser.add_argument('--max-workers', type=int, default=4,
                          help='Number of worker threads for scanning')

        args = parser.parse_args()

        if not os.path.exists(args.path):
            self.logger.error(f"Path does not exist: {args.path}")
            exit(1)

        if not os.path.isdir(args.path):
            self.logger.error(f"Not a valid directory: {args.path}")
            exit(1)

        if args.depth < 1:
            self.logger.error("Depth must be at least 1")
            exit(1)

        for exclude_path in args.exclude:
            if not os.path.exists(exclude_path):
                self.logger.warning(f"Exclude path does not exist: {exclude_path}")

        self.config['acl_timeout'] = args.acl_timeout
        self.logger.info(f"Starting analysis of {args.path} with max depth {args.depth}...")
        if args.follow_symlinks:
            self.logger.warning("Following symbolic links may cause infinite loops!")

        rows = self.scan_directory(args.path, args.follow_symlinks, args.exclude, args.depth, args.max_workers)
        self.generate_html_report(rows, args.output, args.path)

        if args.json_output:
            try:
                data = {
                    'summary': {
                        'scanned_directory': args.path,
                        'total_files': self.total_files,
                        'risk_files': self.risk_files,
                        'stats': self.stats
                    }
                }
                with open(args.json_output, 'w', encoding='utf-8', errors='replace') as f:
                    json.dump(data, f, indent=2, default=str)
                self.logger.info(f"JSON data saved to: {args.json_output}")
            except Exception as e:
                self.logger.error(f"Error saving JSON data: {str(e)}")

        self.logger.info(f"\nReport generated: {args.output}")
        self.logger.info(f"Summary:")
        self.logger.info(f"  - Scanned Directory: {args.path}")
        self.logger.info(f"  - Total items: {self.total_files}")
        self.logger.info(f"  - High risks: {self.risk_files['high']}")
        self.logger.info(f"  - Medium risks: {self.risk_files['medium']}")
        self.logger.info(f"  - Low risks: {self.risk_files['low']}")
        self.logger.info(f"Scan completed in {time.time() - self.start_time:.1f} seconds")

if __name__ == "__main__":
    analyzer = PermissionAnalyzer()
    analyzer.main()
