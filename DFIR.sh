#!/bin/bash
echo "======创建目录======"
CURRENT_PATH=$(pwd)
EXECUTION_TIME=$(date +%Y-%m-%d)
FOLDER_CREATION="$CURRENT_PATH/DFIR-$HOSTNAME-$EXECUTION_TIME"
mkdir -p "$FOLDER_CREATION" >/dev/null 2>&1
echo "创建目录完成：$FOLDER_CREATION"


echo "======备份history======"
History_Path="$FOLDER_CREATION/History"
mkdir -p "$History_Path" >/dev/null 2>&1

if [ -f "/root/.bash_history" ]; then
    cp "/root/.bash_history" "$History_Path/root_history.bak"
    echo "Backed up /root/.bash_history as $History_Path/root_history.bak"
else
    echo "/root/.bash_history not found."
fi

for dir in /home/*; do
    # Check if it's a valid user directory
    if [ -d "$dir" ]; then
        # Check if .base_history file exists
        if [ -f "$dir/.bash_history" ]; then
            # Create backup file with user name and .bak extension
            cp "$dir/.bash_history" "$History_Path/$(basename "$dir")_history.bak"
            echo "Backed up $dir/.bash_history as $History_Path/$(basename "$dir")_history.bak"
        else
            echo "$dir/.bash_history not found."
        fi
    fi
done

echo  "======收集系统信息======"
SysInfo="$FOLDER_CREATION/SystemInfo.txt"

echo "主机名：" $(hostname) >> $SysInfo
echo "当前用户：" $(whoami) >> $SysInfo
echo "运行时间：" $(uptime) >> $SysInfo
echo "系统信息：" $(cat /etc/os-release) >> $SysInfo
echo "IP信息：" $(ifconfig) >> $SysInfo

echo "======收集网络信息======"
NetContent="$FOLDER_CREATION/NetContent.txt"

echo "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name" > $NetContent
netstat -antlp |grep ESTABLISHED >> $NetContent
netstat -antlp |grep LISTEN | grep -v 127.0.0.1 >> $NetContent

echo "======收集CPU占用信息======"
CpuInfo="$FOLDER_CREATION/CpuInfo.txt"
top -b -n 1 -o %CPU | head -n 21 >> $CpuInfo 

echo "======收集进程信息======"
ProcessInfo="$FOLDER_CREATION/ProcessInfo.txt"

printf "%-10s %-10s %-20s %-20s %-20s %-10s %-10s\n" "PID" "PPID" "Name" "Command" "Executable" "User" "Elapsed Time" > $ProcessInfo
for pid in /proc/[0-9]*/ ; do
    pid=$(basename $pid)
    ppid=$(cat /proc/$pid/status | grep PPid | awk '{print $2}')
    name=$(cat /proc/$pid/status | grep Name | awk '{print $2}')
    cmd=$(cat /proc/$pid/cmdline | tr '\0' ' ')
    exe=$(readlink -f /proc/$pid/exe)
    user=$(ps -o user= -p $pid)
    etime=$(ps -o etime= -p $pid)
    printf "%-10s %-10s %-20s %-20s %-20s %-10s %-10s\n" "$pid" "$ppid" "$name" "$cmd" "$exe" "$user" "$etime" >> $ProcessInfo
done

echo "======收集账户信息======"
UserInfo="$FOLDER_CREATION/UserInfo.txt"
echo "登录账户信息\n" >> $UserInfo
w >> $UserInfo
echo "可登录用户信息\n" >> $UserInfo
cat /etc/passwd |grep -v "nologin\|sync" |grep -v /bin/false >> $UserInfo
echo "公钥信息\n" >> $UserInfo
cat /root/.ssh/authorized_keys >> $UserInfo
echo "历史登录信息\n" >> $UserInfo
last -F -n 20 >> $UserInfo

echo "======收集计划任务信息======"
CronList="$FOLDER_CREATION/CronList.txt"
for user in $(grep -v "/nologin\|/sync\|/false" /etc/passwd | cut -f1 -d ':');
do
	echo $user >> $CronList
	crontab -u $user -l >> $CronList
	echo "ENDOFUSERRON" >> $CronList
done

echo "======收集开机启动项======"
SystemStartUp="$FOLDER_CREATION/SystemStartUp.txt"
systemctl list-unit-files --type=service --state=enabled >> $SystemStartUp
echo "详细信息\n" >> $SystemStartUp
find /etc/systemd/ -name "*.service" -print0 | xargs -0 cat >> $SystemStartUp

echo "======查找24小时内修改过的web脚本文件======"
WebShellFile="$FOLDER_CREATION/WebShellFiles.txt"
find / -type f \( -iname '*.jsp' -o -iname '*.asp' -o -iname '*.php' -o -iname '*.aspx' -o -iname '*.sh' -o -iname '*.py' -o -iname '*.conf' \) -mtime 0 >> $WebShellFile

echo "======查找特定目录下的隐藏文件======"
HiddenFiles="$FOLDER_CREATION/HiddenFiles.txt"
find /root/* /tmp/* /home/* -name ".*" -print |more >> $HiddenFiles 

echo "======压缩打包所有信息======"
tar -czf $FOLDER_CREATION.tar.gz $FOLDER_CREATION
echo "打包文件到$FOLDER_CREATION.tar.gz"
