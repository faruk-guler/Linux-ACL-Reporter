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
import logging
from concurrent.futures import ThreadPoolExecutor
from collections import deque
from typing import Dict, List, Any, Optional, Set, Union

# TOML support
try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

# ANSI colors
class Colors:
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    RED_BG = '\033[41;97m'

class ColoredFormatter(logging.Formatter):
    def __init__(self, fmt: str):
        super().__init__(fmt)
        self.level_colors = {
            'DEBUG': Colors.CYAN, 'INFO': Colors.GREEN, 'WARNING': Colors.YELLOW,
            'ERROR': Colors.RED, 'CRITICAL': Colors.RED_BG
        }
    def format(self, record: logging.LogRecord) -> str:
        color = self.level_colors.get(record.levelname, Colors.RESET)
        return f"{color}{super().format(record)}{Colors.RESET}"

class PermissionAnalyzer:
    def print_banner(self):
        banner = f"""{Colors.CYAN}
   --------------------------------------------------
    User: faruk-guler
    Web: www.farukguler.com
    GitHub: github/faruk-guler
   --------------------------------------------------{Colors.RESET}"""
        print(banner)
        print(f"{Colors.YELLOW}   >>> Linux ACL Reporter Tool v1.3 <<<{Colors.RESET}\n")

    def __init__(self, config_path: str = 'config.toml'):
        self.config_path = config_path
        self.config = self.load_config()
        
        self.total_files = 0
        self.risk_files = {'high': 0, 'medium': 0, 'low': 0, 'none': 0}
        self.processed_inodes: Set[int] = set()
        self.errors: List[str] = []
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.stats = {
            'world_writable': 0, 'setuid': 0, 'setgid': 0, 'root_writable': 0,
            'symlink': 0, 'sticky_bit': 0, 'interesting_extensions': 0,
            'sensitive_file_readable': 0, 'orphaned_ownership': 0
        }
        
        # Excludes
        self.exclude_paths: Set[str] = set()
        file_rules = self.config.get('file_rules', {})
        if isinstance(file_rules, dict):
            excludes = file_rules.get('exclude_paths', [])
            if isinstance(excludes, list):
                self.exclude_paths = {os.path.abspath(str(p)) for p in excludes if p}
            
        self.is_posix = os.name == 'posix'
        self.has_getfacl = self.is_posix and shutil.which('getfacl') is not None
        self.visited_real_paths: Set[str] = set()

        # Cache system UIDs/GIDs
        self.system_uids = set()
        self.system_gids = set()
        if self.is_posix:
            try:
                self.system_uids = {u.pw_uid for u in pwd.getpwall()}
                self.system_gids = {g.gr_gid for g in grp.getgrall()}
            except Exception:
                pass

        # Logging
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        handlers = [logging.StreamHandler(), logging.FileHandler('permission_analyzer.log')]
        handlers[0].setFormatter(ColoredFormatter(log_format))
        handlers[1].setFormatter(logging.Formatter(log_format))
        logging.basicConfig(level=logging.INFO, handlers=handlers)
        self.logger = logging.getLogger(__name__)

    def load_config(self) -> Dict[str, Any]:
        """Loads TOML configuration."""
        defaults = {
            "scan_settings": {"target_path": "/", "depth": 5, "max_workers": 4, "follow_symlinks": False, "acl_timeout": 5},
            "file_rules": {
                "interesting_extensions": [".sh", ".py", ".pl", ".rb", ".php", ".conf", ".key", ".pem", ".crt", ".ini"],
                "exclude_paths": ["/proc", "/sys", "/dev", "/run"]
            },
            "output_settings": {"html_report": "permission_report.html", "json_report": "permission_report.json", "report_pagination": 1000}
        }

        if not tomllib:
            print("Warning: tomllib or tomli not found. Using defaults.")
            return defaults

        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'rb') as f:
                    user_config = tomllib.load(f)
                    # Simple recursive merge
                    for key in defaults:
                        if key in user_config:
                            if isinstance(defaults[key], dict) and isinstance(user_config[key], dict):
                                defaults[key].update(user_config[key])
                            else:
                                defaults[key] = user_config[key]
                    return defaults
            except Exception as e:
                print(f"Config load error ({self.config_path}): {e}")
        return defaults

    def get_detailed_permissions(self, mode: int) -> Dict[str, Dict[str, bool]]:
        return {
            'owner': {'read': bool(mode & stat.S_IRUSR), 'write': bool(mode & stat.S_IWUSR), 'execute': bool(mode & stat.S_IXUSR)},
            'group': {'read': bool(mode & stat.S_IRGRP), 'write': bool(mode & stat.S_IWGRP), 'execute': bool(mode & stat.S_IXGRP)},
            'others': {'read': bool(mode & stat.S_IROTH), 'write': bool(mode & stat.S_IWOTH), 'execute': bool(mode & stat.S_IXOTH)},
            'special': {'setuid': bool(mode & stat.S_ISUID), 'setgid': bool(mode & stat.S_ISGID), 'sticky': bool(mode & stat.S_ISVTX)}
        }

    def get_permission_string(self, mode: int) -> str:
        perms = ['-'] * 10
        ft = {
            stat.S_IFREG: '-', stat.S_IFDIR: 'd', stat.S_IFLNK: 'l', 
            stat.S_IFCHR: 'c', stat.S_IFBLK: 'b', stat.S_IFSOCK: 's', 
            stat.S_IFIFO: 'p'
        }
        perms[0] = ft.get(stat.S_IFMT(mode), '?')
        perms[1] = 'r' if mode & stat.S_IRUSR else '-'
        perms[2] = 'w' if mode & stat.S_IWUSR else '-'
        perms[3] = 'x' if mode & stat.S_IXUSR else '-'
        perms[4] = 'r' if mode & stat.S_IRGRP else '-'
        perms[5] = 'w' if mode & stat.S_IWGRP else '-'
        perms[6] = 'x' if mode & stat.S_IXGRP else '-'
        perms[7] = 'r' if mode & stat.S_IROTH else '-'
        perms[8] = 'w' if mode & stat.S_IWOTH else '-'
        perms[9] = 'x' if mode & stat.S_IXOTH else '-'
        if mode & stat.S_ISUID: perms[3] = 's' if perms[3] == 'x' else 'S'
        if mode & stat.S_ISGID: perms[6] = 's' if perms[6] == 'x' else 'S'
        if mode & stat.S_ISVTX: perms[9] = 't' if perms[9] == 'x' else 'T'
        return ''.join(perms)

    def get_file_info(self, path: str) -> Optional[Dict[str, Any]]:
        try:
            real_path = os.path.realpath(path)
            if real_path in self.visited_real_paths: return None
            self.visited_real_paths.add(real_path)

            st = os.lstat(path)
            is_lnk = stat.S_ISLNK(st.st_mode)
            target = os.readlink(path) if is_lnk else ''
            
            ft_str = 'symlink' if is_lnk else 'directory' if stat.S_ISDIR(st.st_mode) else 'file' if stat.S_ISREG(st.st_mode) else 'other'
            
            perms = self.get_detailed_permissions(st.st_mode)
            risk_level, risk_types = self.check_security_risk(perms, st.st_uid, st.st_gid, Path(path).suffix.lower(), path, st.st_mode)
            
            interesting_exts = self.config.get('file_rules', {}).get('interesting_extensions', [])
            is_interesting = Path(path).suffix.lower() in interesting_exts
            
            if is_interesting:
                with self.lock: self.stats['interesting_extensions'] += 1
            with self.lock:
                for rt in risk_types:
                    if rt in self.stats: self.stats[rt] += 1

            info = {
                'path': path, 'type': ft_str, 'mode_str': self.get_permission_string(st.st_mode),
                'octal_perm': format(st.st_mode & 0o7777, '04o'),
                'owner': pwd.getpwuid(st.st_uid).pw_name if (self.is_posix and st.st_uid in self.system_uids) else str(st.st_uid),
                'group': grp.getgrgid(st.st_gid).gr_name if (self.is_posix and st.st_gid in self.system_gids) else str(st.st_gid),
                'size': st.st_size, 'mtime': datetime.datetime.fromtimestamp(st.st_mtime),
                'risk_level': risk_level, 'risk_types': risk_types, 'has_interesting_extension': is_interesting,
                'target': target, 'inode': st.st_ino
            }

            if self.has_getfacl and ft_str not in ['symlink']:
                timeout = int(self.config.get('scan_settings', {}).get('acl_timeout', 5))
                try:
                    res = subprocess.run(['getfacl', '-p', path], capture_output=True, text=True, timeout=timeout)
                    info['acl'] = res.stdout.strip() if res.returncode == 0 else f"Error: {res.stderr.strip()}"
                except: info['acl'] = "Timeout/Error"
            else: info['acl'] = "N/A"
            return info
        except: return None

    def check_security_risk(self, perms: Dict[str, Dict[str, bool]], uid: int, gid: int, ext: str, path: str, mode: int) -> tuple[str, List[str]]:
        risks: List[str] = []; lvl = 'none'
        
        # Base risks
        if stat.S_ISLNK(mode): 
            risks.append('symlink'); lvl = 'low'
        else:
            if perms['others']['write']: 
                risks.append('world_writable'); lvl = 'high'
            
            # Check for sensitive paths
            sensitive_patterns = ['.ssh', '.bash_history', 'shadow', 'passwd', 'sudoers', '.key', '.pem', '.crt']
            if any(p in path.lower() for p in sensitive_patterns):
                if perms['others']['read']:
                    risks.append('sensitive_file_readable'); lvl = 'high'
                elif perms['group']['read']:
                    risks.append('sensitive_file_readable'); lvl = 'medium'
            
            if uid == 0 and perms['owner']['write'] and path not in ['/', '/root']: 
                risks.append('root_writable')
                if lvl == 'none': lvl = 'medium'
                
            if perms['special']['setuid']: 
                risks.append('setuid'); lvl = 'high'
            if perms['special']['setgid']: 
                risks.append('setgid'); lvl = 'medium'
                
            if perms['others']['read'] and stat.S_ISDIR(mode):
                # Only flag world-readable dirs if they are somewhat deep or sensitive
                if '/root' in path or '/etc' in path:
                    risks.append('world_readable_sensitive_dir'); lvl = 'medium'

            # Orphaned ownership check
            if self.is_posix:
                if uid not in self.system_uids or gid not in self.system_gids:
                    risks.append('orphaned_ownership'); lvl = 'medium'
        
        return lvl, risks

    def scan_directory(self, path: str) -> List[Dict[str, Any]]:
        s = self.config.get('scan_settings', {})
        try:
            depth = int(s.get('depth', 5))
            workers = int(s.get('max_workers', 4))
            follow = bool(s.get('follow_symlinks', False))
        except (ValueError, TypeError):
            depth, workers, follow = 5, 4, False

        results: deque[Dict[str, Any]] = deque()
        
        def process(p: str) -> Optional[Dict[str, Any]]:
            if any(os.path.abspath(p).startswith(ex) for ex in self.exclude_paths): return None
            info = self.get_file_info(p)
            if info:
                with self.lock:
                    self.total_files += 1
                    level = str(info['risk_level'])
                    if level in self.risk_files:
                        self.risk_files[level] += 1
                    else:
                        self.risk_files['none'] += 1
                return info
            return None

        with ThreadPoolExecutor(max_workers=workers) as executor:
            for root, dirs, files in os.walk(path, topdown=True, followlinks=follow):
                abs_root = os.path.abspath(root)
                rel = os.path.relpath(abs_root, os.path.abspath(path))
                curr_depth = 0 if rel == '.' else rel.count(os.sep) + 1
                
                if curr_depth >= depth or any(abs_root.startswith(ex) for ex in self.exclude_paths):
                    dirs.clear()
                    continue
                
                # Real-time console progress
                self.logger.info(f"Scanning: {abs_root}")

                for d in list(dirs):
                    full_d = os.path.join(root, d)
                    if any(os.path.abspath(full_d).startswith(ex) for ex in self.exclude_paths):
                        dirs.remove(d)

                futures = [executor.submit(process, os.path.join(root, n)) for n in (dirs + files)]
                for f in futures:
                    res = f.result()
                    if res: results.append(res)
        return list(results)

    def generate_html_report(self, data: List[Dict[str, Any]], outfile: str, target: str):
        elapsed = time.time() - self.start_time
        gen_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        for d in data:
            s = int(d['size'])
            if s >= 1024**3: d['size_str'] = f"{s/(1024**3):.1f} GB"
            elif s >= 1024**2: d['size_str'] = f"{s/(1024**2):.1f} MB"
            elif s >= 1024: d['size_str'] = f"{s/1024:.1f} KB"
            else: d['size_str'] = f"{s} B"
            d['mtime_str'] = d['mtime'].strftime("%Y-%m-%d %H:%M")

        json_str = json.dumps(data, default=lambda o: str(o) if isinstance(o, datetime.datetime) else o)
        
        risk_types_list = [
            ('World Writable', self.stats.get('world_writable', 0)),
            ('Setuid', self.stats.get('setuid', 0)),
            ('Setgid', self.stats.get('setgid', 0)),
            ('Root Writable', self.stats.get('root_writable', 0)),
            ('Sensitive Exposed', self.stats.get('sensitive_file_readable', 0)),
            ('Orphaned Files', self.stats.get('orphaned_ownership', 0)),
            ('Symlink', self.stats.get('symlink', 0)),
            ('Sticky Bit', self.stats.get('sticky_bit', 0)),
            ('Interesting Exts', self.stats.get('interesting_extensions', 0))
        ]
        risk_types_html = "".join([f'<p><strong>{l}:</strong> {v}</p>' for l, v in risk_types_list])

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Linux File Permissions Report -farukguler.com</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #fff; color: #333; margin: 0; padding: 20px; overflow-y: scroll; }}
        .header {{ display: flex; align-items: center; border-bottom: 2px solid #3498db; padding-bottom: 5px; margin-bottom: 5px; }}
        .header h1 {{ margin: 0; font-size: 24px; color: #2c3e50; font-weight: 600; }}
        .header-icon {{ font-size: 24px; margin-right: 10px; }}
        .gen-at {{ font-size: 13px; color: #7f8c8d; margin-bottom: 20px; }}
        .section-title {{ font-size: 18px; font-weight: bold; color: #34495e; border-bottom: 2px solid #3498db; padding-bottom: 5px; margin-bottom: 15px; margin-top: 20px; }}
        .summary-row {{ display: flex; gap: 20px; margin-bottom: 25px; align-items: flex-start; }}
        .summary-box {{ background: #fff; padding: 15px; border-radius: 3px; border: 1px solid #f0f0f0; box-shadow: 0 1px 3px rgba(0,0,0,0.05); min-width: 250px; flex: 1; }}
        .summary-box p {{ margin: 6px 0; font-size: 13px; }}
        .summary-box strong {{ min-width: 130px; display: inline-block; color: #2c3e50; }}
        .summary-box h3 {{ margin-top: 0; margin-bottom: 10px; font-size: 15px; color: #2c3e50; border-bottom: 1px solid #eee; padding-bottom: 5px; }}
        
        .controls {{ display: flex; gap: 10px; margin-bottom: 15px; align-items: center; background: #fcfcfc; padding: 10px; border-radius: 4px; border: 1px solid #eee; }}
        input, select {{ padding: 7px 10px; border: 1px solid #ddd; border-radius: 3px; font-size: 13px; background: white; }}
        .btn {{ padding: 7px 15px; background: #3498db; color: #fff; border: none; border-radius: 3px; cursor: pointer; font-size: 13px; transition: background 0.2s; }}
        .btn:hover {{ background: #2980b9; }}
        .btn:disabled {{ background: #bdc3c7; cursor: not-allowed; opacity: 0.7; }}
        .btn-export {{ background: #5dade2; }}
        
        .table-container {{ background: #fff; border: 1px solid #ddd; border-radius: 4px; overflow-x: auto; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 12px; table-layout: fixed; }}
        th {{ text-align: left; padding: 10px; border-bottom: 1px solid #ddd; background: #f8f9fa; color: #555; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; position: sticky; top: 0; }}
        td {{ padding: 8px 10px; border-bottom: 1px solid #eee; vertical-align: top; word-break: break-all; }}
        
        .row-high {{ background-color: #fff5f5 !important; }}
        .row-medium {{ background-color: #fffdf5 !important; }}
        .badge-high {{ background: #e74c3c; color: #fff; padding: 2px 5px; border-radius: 2px; font-weight: bold; font-size: 10px; }}
        .badge-medium {{ background: #f39c12; color: #fff; padding: 2px 5px; border-radius: 2px; font-weight: bold; font-size: 10px; }}
        .path-cell {{ color: #c0392b; font-weight: 500; }}
        .acl-cell {{ font-family: 'Consolas', monospace; white-space: pre-wrap; color: #444; font-size: 11px; max-height: 100px; overflow-y: auto; display: block; }}
        .folder-icon {{ margin-right: 5px; color: #f39c12; }}
        
        .pagination {{ display: flex; justify-content: center; gap: 10px; margin-top: 20px; align-items: center; font-size: 13px; padding-bottom: 40px; }}
        .page-info {{ color: #7f8c8d; }}
    </style>
</head>
<body>
    <div class="header">
        <span class="header-icon">📋</span>
        <h1>Linux File Permissions Report -farukguler.com</h1>
    </div>
    <div class="gen-at">Generated At: {gen_time}</div>
    
    <div class="section-title">Scan Summary</div>
    <div class="summary-row">
        <div class="summary-box">
            <p><strong>Scanned Directory:</strong> {escape(target)}</p>
            <p><strong>Scan Duration:</strong> {elapsed:.1f} seconds</p>
            <p><strong>Total Items:</strong> {self.total_files}</p>
            <p><strong>Total Risks:</strong> {sum(v for k, v in self.risk_files.items() if k != 'none')}</p>
        </div>
        <div class="summary-box">
            <p><strong>High Risks:</strong> {self.risk_files['high']}</p>
            <p><strong>Medium Risks:</strong> {self.risk_files['medium']}</p>
            <p><strong>Low Risks:</strong> {self.risk_files['low']}</p>
            <p><strong>No Risk:</strong> {self.risk_files['none']}</p>
        </div>
        <div class="summary-box">
            <h3>Risk Types</h3>
            {risk_types_html}
        </div>
    </div>

    <div class="controls">
        <input type="text" id="pathFilter" placeholder="Filter by path..." style="flex:1">
        <select id="riskFilter">
            <option value="all">All Risks</option>
            <option value="high">High Risk</option>
            <option value="medium">Medium Risk</option>
            <option value="low">Low Risk</option>
            <option value="none">No Risk</option>
        </select>
        <select id="typeFilter">
            <option value="all">All Types</option>
            <option value="file">File</option>
            <option value="directory">Directory</option>
            <option value="symlink">Symlink</option>
        </select>
        <button class="btn btn-export" onclick="exportJSON()">Export JSON</button>
    </div>

    <div class="table-container">
        <div id="table-wrap"></div>
    </div>

    <div class="pagination">
        <button class="btn" id="prevBtn" onclick="prevPage()">Previous</button>
        <span class="page-info" id="pageInfo">Page 1 of 1</span>
        <button class="btn" id="nextBtn" onclick="nextPage()">Next</button>
    </div>

    <script>
        const allItems = {json_str};
        let filteredItems = allItems;
        let currentPage = 1;
        const pageSize = Math.max(1, {int(self.config.get('output_settings', {}).get('report_pagination', 1000))});

        function renderTable() {{
            const start = (currentPage - 1) * pageSize;
            const end = start + pageSize;
            const pageData = filteredItems.slice(start, end);
            
            let h = '<table><colgroup><col style="width:20%"><col style="width:8%"><col style="width:10%"><col style="width:5%"><col style="width:7%"><col style="width:7%"><col style="width:7%"><col style="width:10%"><col style="width:15%"><col style="width:15%"><col style="width:20%"></colgroup><thead><tr><th>Path</th><th>Type</th><th>Permissions</th><th>Octal</th><th>Owner</th><th>Group</th><th>Size</th><th>Modified</th><th>Risk Warning</th><th>Symlink Target</th><th>ACL</th></tr></thead><tbody>';
            
            pageData.forEach(d => {{
                let rowClass = "";
                if (d.risk_level === 'high') rowClass = 'row-high';
                else if (d.risk_level === 'medium') rowClass = 'row-medium';
                
                const typeIcon = d.type === 'directory' ? '<span class="folder-icon">📁</span>' : '';
                let badge = "";
                if (d.risk_level === 'high') badge = '<span class="badge-high">HIGH</span> ';
                else if (d.risk_level === 'medium') badge = '<span class="badge-medium">MED</span> ';
                
                const riskInfo = badge + (d.risk_types || []).join(', ');
                
                h += `<tr class="${{rowClass}}">
                    <td class="path-cell">${{d.path}}</td>
                    <td>${{typeIcon}}${{d.type}}</td>
                    <td><code>${{d.mode_str}}</code></td>
                    <td>${{d.octal_perm}}</td>
                    <td>${{d.owner}}${{d.risk_types && d.risk_types.includes('orphaned_ownership') ? ' <span title="Non-existent UID/GID">(Orphan)</span>' : ''}}</td>
                    <td>${{d.group}}</td>
                    <td>${{d.size_str}}</td>
                    <td>${{d.mtime_str}}</td>
                    <td>${{riskInfo}}</td>
                    <td>${{d.target || ''}}</td>
                    <td><span class="acl-cell">${{d.acl}}</span></td>
                </tr>`;
            }});
            
            h += '</tbody></table>' + (filteredItems.length === 0 ? '<p style="text-align:center; padding:20px; color:#999;">No items found matches the filters.</p>' : '');
            document.getElementById('table-wrap').innerHTML = h;
            
            const totalPages = Math.ceil(filteredItems.length / pageSize) || 1;
            document.getElementById('pageInfo').innerText = `Page ${{currentPage}} of ${{totalPages}} (${{filteredItems.length.toLocaleString()}} total)`;
            document.getElementById('prevBtn').disabled = currentPage === 1;
            document.getElementById('nextBtn').disabled = currentPage === totalPages;
            
            // Hide pagination if only one page
            if (document.querySelector('.pagination')) {{
                document.querySelector('.pagination').style.display = totalPages > 1 ? 'flex' : 'none';
            }}
            
            window.scrollTo(0, 0);
        }}

        function applyFilters() {{
            const p = document.getElementById('pathFilter').value.toLowerCase();
            const r = document.getElementById('riskFilter').value;
            const t = document.getElementById('typeFilter').value;
            
            filteredItems = allItems.filter(i => {{
                const searchStr = p.toLowerCase();
                const pathMatch = i.path.toLowerCase().includes(searchStr);
                const riskMatch = (i.risk_types || []).some(rt => rt.toLowerCase().includes(searchStr));
                const ownerMatch = i.owner.toLowerCase().includes(searchStr);
                
                return (pathMatch || riskMatch || ownerMatch) &&
                       (r === 'all' || i.risk_level === r) &&
                       (t === 'all' || i.type === t);
            }});
            
            currentPage = 1;
            renderTable();
        }}
        function prevPage() {{ if(currentPage > 1) {{ currentPage--; renderTable(); }} }}
        function nextPage() {{ if(currentPage < Math.ceil(filteredItems.length / pageSize)) {{ currentPage++; renderTable(); }} }}

        document.getElementById('pathFilter').addEventListener('input', applyFilters);
        document.getElementById('riskFilter').addEventListener('change', applyFilters);
        document.getElementById('typeFilter').addEventListener('change', applyFilters);

        function exportJSON() {{
            const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(allItems));
            const dl = document.createElement('a');
            dl.setAttribute("href", dataStr);
            dl.setAttribute("download", "acl_report.json");
            document.body.appendChild(dl); dl.click(); dl.remove();
        }}

        renderTable();
    </script>
</body>
</html>"""
        with open(outfile, 'w', encoding='utf-8') as f:
            f.write(html)

    def main(self):
        parser = argparse.ArgumentParser(description='Linux ACL Reporter (English Version)')
        parser.add_argument('path', nargs='?', help='Target directory path')
        args = parser.parse_args()

        target_path = str(args.path or self.config.get('scan_settings', {}).get('target_path', '/'))
        if not os.path.exists(target_path):
            self.logger.error(f"Error: Path '{target_path}' not found."); return

        self.print_banner()

        if self.has_getfacl:
            self.logger.info("ACL Package check: [OK] 'getfacl' found.")
        else:
            self.logger.warning("ACL Package check: [MISSING] 'getfacl' not found. ACL details will be skipped.")
            self.logger.warning("Tip: Install 'acl' package (e.g. 'sudo apt install acl') for full analysis.")

        # 5-second countdown delay
        print(f"{Colors.CYAN}Starting scan in 5 seconds...{Colors.RESET}")
        for i in range(5, 0, -1):
            print(f"{Colors.YELLOW}{i}...{Colors.RESET}", end=" ", flush=True)
            time.sleep(1)
        print(f"\n{Colors.GREEN}Proceeding!{Colors.RESET}\n")

        self.logger.info(f"Scan started: {target_path}")
        rows = self.scan_directory(target_path)
        
        out = self.config.get('output_settings', {})
        html_file = str(out.get('html_report', 'report.html'))
        self.generate_html_report(rows, html_file, target_path)
        
        j_out = out.get('json_report')
        if j_out:
            try:
                with open(str(j_out), 'w') as f:
                    json.dump(rows, f, indent=2, default=str)
                self.logger.info(f"JSON data saved to: {j_out}")
            except Exception as e:
                self.logger.error(f"Error saving JSON: {e}")
            
        self.logger.info(f"Analysis completed. Scanned: {self.total_files} items.")

if __name__ == "__main__":
    PermissionAnalyzer().main()
