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

# Exclude cron jobs to reduce log noise
-a never,user -F subj_type=crond_t
-a exit,never -F subj_type=crond_t
-a never,user -F subj_type=cron_t
-a exit,never -F subj_type=cron_t

# Exclude unlogged users (auid=-1)
-a never,exit -F auid=4294967295

# Exclude noise from common system directories
-a never,exit -F dir=/sys/fs/cgroup
-a never,exit -F dir=/sys/kernel
-a never,exit -F dir=/proc
-a never,exit -F dir=/dev/pts

# === PROCESS CONTROL MONITORING ===
# Monitor process creation and termination
-a always,exit -S execve -k process_exec
-a always,exit -S clone,fork,vfork -k process_creation
-a always,exit -S exit,exit_group -k process_termination

# === FILE SYSTEM MONITORING ===
# Monitor file access and modifications
-a always,exit -S open,openat,creat -k file_access
-a always,exit -S close,read,write -k file_io
-a always,exit -S unlink,unlinkat,rmdir -k file_deletion
-a always,exit -S mkdir,mkdirat -k directory_creation
-a always,exit -S rename,renameat,renameat2 -k file_rename
-a always,exit -S link,linkat,symlink,symlinkat -k file_linking
-a always,exit -S chmod,fchmod,fchmodat -k file_permissions
-a always,exit -S chown,fchown,lchown,fchownat -k file_ownership

# === NETWORK MONITORING ===
# Monitor network operations
-a always,exit -S socket -k network_socket
-a always,exit -S connect -k network_connect
-a always,exit -S bind -k network_bind
-a always,exit -S listen -k network_listen
-a always,exit -S accept,accept4 -k network_accept
-a always,exit -S sendto,sendmsg,sendmmsg -k network_send
-a always,exit -S recvfrom,recvmsg,recvmmsg -k network_recv

# === PRIVILEGE ESCALATION MONITORING ===
# Monitor privilege changes
-a always,exit -S setuid,setreuid,setresuid -k privilege_setuid
-a always,exit -S setgid,setregid,setresgid -k privilege_setgid
-a always,exit -S setfsuid,setfsgid -k privilege_setfs
-a always,exit -S capset -k capability_change

# === SYSTEM INFORMATION MONITORING ===
# Monitor system information access
-a always,exit -S uname -k system_info
-a always,exit -S getpid,getppid,gettid -k process_info
-a always,exit -S getuid,geteuid,getgid,getegid -k identity_info

# === INTER-PROCESS COMMUNICATION ===
# Monitor IPC mechanisms
-a always,exit -S pipe,pipe2 -k ipc_pipe
-a always,exit -S mq_open,mq_unlink,mq_timedsend,mq_timedreceive -k ipc_mqueue
-a always,exit -S msgget,msgsnd,msgrcv,msgctl -k ipc_sysv_msg
-a always,exit -S semget,semop,semctl -k ipc_sysv_sem
-a always,exit -S shmget,shmat,shmdt,shmctl -k ipc_sysv_shm

# === MEMORY MANAGEMENT ===
# Monitor memory operations that could be security relevant
-a always,exit -S mmap,munmap,mprotect -k memory_management
-a always,exit -S brk,sbrk -k memory_heap

# === SIGNAL HANDLING ===
# Monitor signal operations
-a always,exit -S kill,tkill,tgkill -k signal_send
-a always,exit -S signal,sigaction,rt_sigaction -k signal_handler

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
