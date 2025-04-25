# Linux ACL Reporter v.1 -farukguler.com

<p>
  <img src="https://github.com/faruk-guler/Linux-ACL-Reporter/blob/main/lnx-acl.PNG" alt="ACL Logo" width="500" style="float: left;"/>
</p>

## Usage:

>+ python3 analyzer.py /etc -o etc_report.html --depth 3 --exclude /etc/ssl
>+ ./analyzer.py /etc -o etc_report.html -d 3 -e /etc/ssl

See Logs:
cat permission_analyzer.log | grep "Symlink loop detected"


## Requirements:
-Python3

-linux acl tool [apt install acl, - yum install acl]
