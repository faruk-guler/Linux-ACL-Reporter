# Linux ACL Reporter -farukguler.com

<img src="https://github.com/faruk-guler/Linux-ACL-Reporter/blob/main/report.jpeg" alt="ACL Logo" width="500" style="float: left;"/>

## Usage:

>+ ./analyzer.py /etc -o etc_report.html --depth 3 --exclude /etc/ssl
>+ ./analyzer.py /home --output report.html --depth 3 --follow-symlinks --exclude /proc /sys

## See Logs an Depth:
>+ default depth (5) directory
>+ cat permission_analyzer.log | grep "Symlink loop detected"


## Requirements:
-Python3

-acl package
>apt install acl
>yum install acl

## Thnx: Claude/Anthropic
