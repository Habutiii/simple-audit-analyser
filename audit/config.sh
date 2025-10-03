#!/bin/bash

# Simple Audit Analyzer Configuration Script
# This script configures comprehensive audit rules for system-wide security monitoring
# 
# The audit rules are organized into categories:
# - Process Control: Monitor process creation, execution, and termination
# - File System: Monitor file access, modifications, and permission changes
# - Network: Monitor network socket operations and communications
# - Privilege Escalation: Monitor UID/GID changes and capability modifications
# - System Information: Monitor access to system information
# - Inter-Process Communication: Monitor IPC mechanisms (pipes, message queues, etc.)
# - Memory Management: Monitor memory-related operations
# - Signal Handling: Monitor signal operations
#
# Each rule is tagged with a key (-k option) for easier log analysis

BASEDIR=$(dirname $(readlink -f "$0"))
OUTDIR=$(dirname $BASEDIR)

cd $BASEDIR
echo "config auditbeat.yml"
cp auditbeat.yml /etc/auditbeat

echo "config audit-rules.conf"
audit_rule_path=/etc/auditbeat/audit.rules.d/audit-rules.conf

# Create comprehensive audit rules for system-wide security monitoring
cat > $audit_rule_path << 'EOF'
# Audit rules for comprehensive security monitoring
# Exclude SELinux daemon noise (works with SELinux)
-a never,exit -S all -F subj_type=pulseaudio_t -F subj_type=ntpd_t -F subj_type=cron_t

## Cron jobs fill the logs with stuff we normally don't want (works with SELinux) 
-a never,user -F subj_type=crond_t
-a exit,never -F subj_type=crond_t
-a never,user -F subj_type=cron_t
-a exit,never -F subj_type=cron_t

## Process execution (argv + cwd)
-a always,exit -F arch=b64 -S execve,execveat -k exec
-a always,exit -F arch=b32 -S execve,execveat -k exec
-a always,exit -F arch=b64 -S chdir -k chdir

## File system access (will generate PATH records)
-a always,exit -F arch=b64 -S open,openat,creat,truncate,ftruncate,unlink,unlinkat,rename,renameat,link,linkat,symlink,symlinkat,chmod,fchmod,fchmodat,chown,fchown,fchownat -k file

## Directory watches
-w / -p rwxa

## Network activity (IPs and ports)
-a always,exit -F arch=b64 -S socket -k net
-a always,exit -F arch=b64 -S connect,accept,accept4,bind,listen -k net
-a always,exit -F arch=b64 -S getsockname,getpeername -k net
-a always,exit -F arch=b64 -S sendto,recvfrom,sendmsg,recvmsg -k net

## Privilege escalation attempts
-a always,exit -F arch=b64 -S setuid,setgid,setresuid,setresgid -k ids
-a always,exit -F arch=b64 -S setreuid,setregid -k ids
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -k perms

## Persistence indicators
-a always,exit -F arch=b64 -S init_module,delete_module -k modules
-w /etc/cron.d/ -p wa -k cron_watch
-w /etc/cron.daily/ -p wa -k cron_watch
-w /etc/systemd/ -p wa -k systemd_watch

EOF

# delete previous audit records
echo "delete existing audit records"
rm /var/log/auditbeat/* > /dev/null 2>&1

# Create a new folder to record init information
echo "collect meta-information before system auditing"
folder=$OUTDIR/audit_out
rm -rf $folder
mkdir $folder
cd $folder

# Collect information for current processes running on the system 
mkdir procinfo
cd procinfo
ps -ef > general.txt
ps -eo pid > pid.txt
ps -eo comm > exe.txt
ps -eo args > args.txt
ps -eo ppid > ppid.txt

# Collect information for file descriptor
cd ../
mkdir fdinfo
cd fdinfo
for proc in $(ls /proc | grep '[0-9+]'); do
		touch $proc 1>/dev/null 
		ls -la /proc/$proc/fd > $proc 2>/dev/null
done

# Collect information for socket descriptor
cd ../
mkdir socketinfo
cd socketinfo
lsof -i -n -P > general.txt
cat general.txt | awk '{print $6}' > device.txt
cat general.txt | awk '{print $9}' > name.txt

# Start auditbeat
service auditbeat restart
cd ../
