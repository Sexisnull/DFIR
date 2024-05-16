$Version = '1.0.0'
$ASCIIBanner = @"
  _____                                           _              _   _     _____    ______   _____   _____  
 |  __ \                                         | |            | | | |   |  __ \  |  ____| |_   _| |  __ \ 
 | |__) |   ___   __      __   ___   _ __   ___  | |__     ___  | | | |   | |  | | | |__      | |   | |__) |
 |  ___/   / _ \  \ \ /\ / /  / _ \ | '__| / __| | '_ \   / _ \ | | | |   | |  | | |  __|     | |   |  _  / 
 | |      | (_) |  \ V  V /  |  __/ | |    \__ \ | | | | |  __/ | | | |   | |__| | | |       _| |_  | | \ \ 
 |_|       \___/    \_/\_/    \___| |_|    |___/ |_| |_|  \___| |_| |_|   |_____/  |_|      |_____| |_|  \_\`n
"@
Write-Host $ASCIIBanner
Write-Host "Version: $Version"
Write-Host "Github: Sexisnull"
Write-Host "===========================================`n"


Write-Host "======创建目录======"
$CurrentPath = $pwd
$ExecutionTime = $(get-date -f yyyy-MM-dd)
$FolderCreation = "$CurrentPath\DFIR-$env:computername-$ExecutionTime"
mkdir -Force $FolderCreation | Out-Null
Write-Host "创建目录完成：$FolderCreation"

$currentUsername = (Get-WmiObject Win32_Process -f 'Name="explorer.exe"').GetOwner().User


function Get-EventViewerFiles {
    Write-Host "======备份日志======"
    $EventViewer = "$FolderCreation\Event Viewer"
    mkdir -Force $EventViewer | Out-Null
    $evtxPath = "C:\Windows\System32\winevt\Logs"
    $channels = @(
        "Application",
        "Security",
        "System",
        "Microsoft-Windows-Sysmon%4Operational",
        "Microsoft-Windows-TaskScheduler%4Operational",
        "Microsoft-Windows-PowerShell%4Operational",
        "Microsoft-Windows-Windows Defender%4Operational"
    )

    Get-ChildItem "$evtxPath\*.evtx" | Where-Object{$_.BaseName -in $channels} | ForEach-Object{
        Copy-Item  -Path $_.FullName -Destination "$($EventViewer)\$($_.Name)"
    }
}

function Get-SysInfo {
    Write-Host "======系统信息======"
    $output = "$FolderCreation\系统信息.txt"
    Systeminfo | Out-File -Force -FilePath $output
}

function Get-IPInfo {
    Write-Host "======IP信息======"
    $output = "$FolderCreation\ip信息.txt"
    Get-NetIPAddress | Out-File -Force -FilePath $output
}

function Get-OpenConnections {
    Write-Host "======网络信息======"
    $output = "$FolderCreation\网络连接信息.txt"
    Get-NetTCPConnection -State Established | Out-File -Force -FilePath $output
}

function Get-AutoRunInfo {
    Write-Host "======开机启动项======"
    $Output = "$FolderCreation\自启动应用.txt"
    Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | Format-List | Out-File -Force -FilePath $Output
    Get-ChildItem -Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
}

function Get-RegAutoRunInfo {
    Write-Host "======开机启动项注册表======"
    $RegKeyOutput = "$FolderCreation\后门自查-注册表.txt"
    "==========检查开机运行注册表键==========" | Out-File -Append -FilePath $RegKeyOutput
    Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | Out-File -Append -FilePath $RegKeyOutput

    "==========检查开机运行注册表键==========" | Out-File -Append -FilePath $RegKeyOutput
    Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" | Out-File -Append -FilePath $RegKeyOutput

    "==========检查开机运行注册表键==========" | Out-File -Append -FilePath $RegKeyOutput
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" | Out-File -Append -FilePath $RegKeyOutput

    "==========检查开机运行注册表键==========" | Out-File -Append -FilePath $RegKeyOutput
    Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" | Out-File -Append -FilePath $RegKeyOutput


    "==========检查BOOT启动执行注册表键==========" | Out-File -Append -FilePath $RegKeyOutput
    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "BootExecute" | Out-File -Append -FilePath $RegKeyOutput
    $SessiondefaultValue = "autocheck autochk *"
    $currentValue = (Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "BootExecute").Trim()
    if ($SessiondefaultValue -ne $currentValue) {
        "检测到注册表项与默认值不同！！！" | Out-File -Append -FilePath $RegKeyOutput
    }


    "==========检查LSA启动执行注册表键==========" | Out-File -Append -FilePath $RegKeyOutput
    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Authentication Packages" | Out-File -Append -FilePath $RegKeyOutput
    $lsadefaultValue = "msv1_0"
    $currentValue = (Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Authentication Packages").Trim()
    if ($lsadefaultValue -ne $currentValue) {
        "检测到注册表项与默认值不同！！！" | Out-File -Append -FilePath $RegKeyOutput
    }


    "==========检查LSA启动执行注册表键==========" | Out-File -Append -FilePath $RegKeyOutput
    Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Security Packages" | Out-File -Append -FilePath $RegKeyOutput
    $lsadefaultValue = '""'
    $currentValue = (Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Security Packages").Trim()
    if ($lsadefaultValue -ne $currentValue) {
        "检测到注册表项与默认值不同！！！" | Out-File -Append -FilePath $RegKeyOutput
    }


    "==========检查回收站启动执行注册表键==========" | Out-File -Append -FilePath $RegKeyOutput
    Get-ChildItem -Path "HKCR:\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell\" | Select-Object -ExpandProperty Name | Out-File -Append -FilePath $RegKeyOutput
    $currentValue = Get-ChildItem -Path "HKCR:\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell\" | Select-Object -ExpandProperty Name
    if ($currentValue -like "*open*") {
        "检测到注册表项与默认值不同！！！" | Out-File -Append -FilePath $RegKeyOutput
    }


    "==========检查系统启动目录注册表键==========" | Out-File -Append -FilePath $RegKeyOutput
    Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Common Startup" | Out-File -Append -FilePath $RegKeyOutput
    $startup = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    $currentValue = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Common Startup").Trim()
    if ($startup -ne $currentValue) {
        "检测到注册表项与默认值不同！！！" | Out-File -Append -FilePath $RegKeyOutput
    }


    "==========检查系统启动目录注册表键==========" | Out-File -Append -FilePath $RegKeyOutput
    Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Startup" | Out-File -Append -FilePath $RegKeyOutput
    $startup = "$env:AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
    $currentValue = (Get-ItemPropertyValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Startup").Trim()
    if ($startup -ne $currentValue) {
        "检测到注册表项与默认值不同！！！" | Out-File -Append -FilePath $RegKeyOutput
    }


    "==========检查系统启动脚本注册表键==========" | Out-File -Append -FilePath $RegKeyOutput
    Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Userinit" | Out-File -Append -FilePath $RegKeyOutput
    $defaultValue = "C:\Windows\system32\userinit.exe,"
    $currentValue = (Get-ItemPropertyValue -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Userinit").Trim()
    if ($defaultValue -ne $currentValue) {
        "检测到注册表项与默认值不同！！！" | Out-File -Append -FilePath $RegKeyOutput
    }


    "==========检查系统启动脚本注册表键==========" | Out-File -Append -FilePath $RegKeyOutput
    Get-ItemProperty "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Shell" | Out-File -Append -FilePath $RegKeyOutput
    $defaultValue = "explorer.exe"
    $currentValue = (Get-ItemPropertyValue -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Shell").Trim()
    if ($defaultValue -ne $currentValue) {
        "检测到注册表项与默认值不同！！！" | Out-File -Append -FilePath $RegKeyOutput
    }


    "==========检查系统启动脚本注册表键==========" | Out-File -Append -FilePath $RegKeyOutput
    Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" | Get-ItemProperty | Out-File -Append -FilePath $RegKeyOutput
    $currentValue = Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" | Select-Object -ExpandProperty Name
    if ($currentValue -ne $null) {
        "检测到注册表项与默认值不同！！！HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon应默认为空" | Out-File -Append -FilePath $RegKeyOutput
    }


    "==========检查系统时间服务注册表键==========" | Out-File -Append -FilePath $RegKeyOutput
    Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders" | Get-ItemProperty | Out-File -Append -FilePath $RegKeyOutput
    $currentValues = (Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders" | Get-ItemProperty | Select-Object -ExpandProperty dllname).Trim()
    foreach ($currentValue in $currentValues) {
    if ($currentValue -ne "C:\windows\system32\w32time.dll" -and $currentValue -ne "C:\windows\System32\vmictimeprovider.dll") {
        "检测到注册表项与默认值不同！！！" | Out-File -Append -FilePath $RegKeyOutput
        }
    }


    "==========检查打印注册表键==========" | Out-File -Append -FilePath $RegKeyOutput
    "各厂商打印DLL文件各不相同，需自行判断" | Out-File -Append -FilePath $RegKeyOutput
    Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors" | Get-ItemProperty | Out-File -Append -FilePath $RegKeyOutput

    $currentValues = (Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors" | Get-ItemProperty | Select-Object -ExpandProperty Driver).Trim()
    foreach ($currentValue in $currentValues) {
    if ($currentValue -ne "localspl.dll" -and $currentValue -ne "tcpmon.dll" -and $currentValue -ne "usbmon.dll" -and $currentValue -ne "WSDMon.dll" -and $currentValue -ne "APMon.dll") {
        "检测到注册表项与默认值不同！！！" | Out-File -Append -FilePath $RegKeyOutput
        }
    }


    "==========检查Active Setup注册表键==========" | Out-File -Append -FilePath $RegKeyOutput
    Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\" | Get-ItemProperty | Select-Object -ExpandProperty StubPath -ErrorAction SilentlyContinue | Out-File -Append -FilePath $RegKeyOutput
    Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Active Setup\Installed Components\" | Get-ItemProperty | Select-Object -ExpandProperty StubPath -ErrorAction SilentlyContinue | Out-File -Append -FilePath $RegKeyOutput
}

function Get-ActiveUsers {
    Write-Host "======当前登录账户======"
    $ActiveUserOutput = "$FolderCreation\ActiveUsers.txt"
    query user /server:$server | Out-File -Force -FilePath $ActiveUserOutput
}

function Get-LocalUsers {
    Write-Host "======本地用户======"
    $ActiveUserOutput = "$FolderCreation\LocalUsers.txt"
    Get-LocalUser | Format-Table | Out-File -Force -FilePath $ActiveUserOutput
}

function Get-ActiveProcesses {
    Write-Host "======进程信息======"
    $ProcessFolder = "$FolderCreation\ProcessInformation"
    New-Item -Path $ProcessFolder -ItemType Directory -Force | Out-Null
    $UniqueProcessHashOutput = "$ProcessFolder\UniqueProcessHash.csv"
    $ProcessListOutput = "$ProcessFolder\ProcessList.csv"
	$CSVExportLocation = "$CSVOutputFolder\Processes.csv"

    $processes_list = @()
    foreach ($process in (Get-WmiObject Win32_Process | Select-Object Name, ExecutablePath, CommandLine, ParentProcessId, ProcessId))
    {
        $process_obj = New-Object PSCustomObject
        if ($null -ne $process.ExecutablePath)
        {
            $hash = (Get-FileHash -Algorithm SHA256 -Path $process.ExecutablePath).Hash 
            $process_obj | Add-Member -NotePropertyName Proc_Hash -NotePropertyValue $hash
            $process_obj | Add-Member -NotePropertyName Proc_Name -NotePropertyValue $process.Name
            $process_obj | Add-Member -NotePropertyName Proc_Path -NotePropertyValue $process.ExecutablePath
            $process_obj | Add-Member -NotePropertyName Proc_CommandLine -NotePropertyValue $process.CommandLine
            $process_obj | Add-Member -NotePropertyName Proc_ParentProcessId -NotePropertyValue $process.ParentProcessId
            $process_obj | Add-Member -NotePropertyName Proc_ProcessId -NotePropertyValue $process.ProcessId
            $processes_list += $process_obj
        }   
    }

    ($processes_list | Select-Object Proc_Path, Proc_Hash -Unique).GetEnumerator() | Export-Csv -NoTypeInformation -Path $UniqueProcessHashOutput
	($processes_list | Select-Object Proc_Path, Proc_Hash -Unique).GetEnumerator() | Export-Csv -NoTypeInformation -Path $CSVExportLocation
    ($processes_list | Select-Object Proc_Name, Proc_Path, Proc_CommandLine, Proc_ParentProcessId, Proc_ProcessId, Proc_Hash).GetEnumerator() | Export-Csv -NoTypeInformation -Path $ProcessListOutput
	
}

function Get-PowershellHistoryCurrentUser {
    Write-Host "======导出当前用户powershell执行日志======"
    $PowershellConsoleHistory = "$FolderCreation\PowerShellHistory"
    mkdir -Force $PowershellConsoleHistory | Out-Null
    $PowershellHistoryOutput = "$PowershellConsoleHistory\PowershellHistoryCurrentUser.txt"
    history | Out-File -Force -FilePath $PowershellHistoryOutput
}

function Get-PowershellConsoleHistory-AllUsers {
    Write-Host "======导出所有用户powershell执行日志======"
    $PowershellConsoleHistory = "$FolderCreation\PowerShellHistory"
    # Specify the directory where user profiles are stored
    $usersDirectory = "C:\Users"
    # Get a list of all user directories in C:\Users
    $userDirectories = Get-ChildItem -Path $usersDirectory -Directory
    foreach ($userDir in $userDirectories) {
        $userName = $userDir.Name
        $historyFilePath = Join-Path -Path $userDir.FullName -ChildPath "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        if (Test-Path -Path $historyFilePath -PathType Leaf) {
            $outputDirectory = "$PowershellConsoleHistory\$userDir.Name"
            mkdir -Force $outputDirectory | Out-Null
            Copy-Item -Path $historyFilePath -Destination $outputDirectory -Force
            }
        }
}

function Get-RDPSessions {
    Write-Host "======RDP信息======"
    $ProcessOutput = "$FolderCreation\RDPSessions.txt"
    qwinsta /server:localhost | Out-File -Force -FilePath $ProcessOutput
}

function Get-DNSCache {
    Write-Host "======DNS服务器信息======"
    $ProcessOutput = "$FolderCreation\DNSCache.txt"
    Get-DnsClientCache | Format-List | Out-File -Force -FilePath $ProcessOutput
}

function Get-hosts {
    Write-Host "======hosts信息======"
    Copy-Item -Path C:\Windows\System32\drivers\etc\hosts -Destination "$FolderCreation\hosts.txt"
}

function Get-RunningServices {
    Write-Host "======正在运行服务信息======"
    $ProcessOutput = "$FolderCreation\运行服务.txt"
    Get-WmiObject -Class Win32_Service | Select-Object Name, DisplayName, State, PathName | Where-Object {$_.State -eq "Running"} | format-list | Out-File -Force -FilePath $ProcessOutput
}

function Get-ScheduledTasks {
    Write-Host "======计划任务信息======"
    $ProcessOutput = "$FolderCreation\计划任务.txt"
    Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | Get-ScheduledTaskInfo | Select-Object -Property LastRunTime, NextRunTime, TaskName, TaskPath, @{Name="Actions";Expression={(Get-ScheduledTask -TaskName $_.TaskName).Actions | Select-Object -ExpandProperty Execute}} | format-list | Out-File -Force -FilePath $ProcessOutput
}

function Get-ChromiumFiles {
    param(
        [Parameter(Mandatory=$true)][String]$Username
    )

    Write-Host "======收集Chromium history 和 profile文件======"
    $HistoryFolder = "$FolderCreation\Browsers\Chromium"
    New-Item -Path $HistoryFolder -ItemType Directory -Force | Out-Null

    $filesToCopy = @(
        'Preferences',
        'History'
    )

    Get-ChildItem "C:\Users\$Username\AppData\Local\*\*\User Data\*\" | Where-Object { `
        (Test-Path "$_\History") -and `
        [char[]](Get-Content "$($_.FullName)\History" -Encoding byte -TotalCount 'SQLite format'.Length) -join ''
    } | Where-Object { 
        $srcpath = $_.FullName
        $destpath = $_.FullName -replace "^C:\\Users\\$Username\\AppData\\Local",$HistoryFolder -replace "User Data\\",""
        New-Item -Path $destpath -ItemType Directory -Force | Out-Null

        $filesToCopy | ForEach-Object{
            $filesToCopy | Where-Object{ Test-Path "$srcpath\$_" } | ForEach-Object{ Copy-Item -Path "$srcpath\$_" -Destination "$destpath\$_" }
        }
    }
}

function Get-FirefoxFiles {
    param(
        [Parameter(Mandatory=$true)][String]$Username
    )

    if(Test-Path "C:\Users\$Username\AppData\Roaming\Mozilla\Firefox\Profiles\") {
        Write-Host "======收集 Firefox history 和 profile 文件======"
        $HistoryFolder = "$FolderCreation\Browsers\Firefox"
        New-Item -Path $HistoryFolder -ItemType Directory -Force | Out-Null

        $filesToCopy = @(
            'places.sqlite',
            'permissions.sqlite',
            'content-prefs.sqlite',
            'extensions'
        )

        Get-ChildItem "C:\Users\$Username\AppData\Roaming\Mozilla\Firefox\Profiles\" | Where-Object { `
            (Test-Path "$($_.FullName)\places.sqlite") -and `
            [char[]](Get-Content "$($_.FullName)\places.sqlite" -Encoding byte -TotalCount 'SQLite format'.Length) -join ''
        } | ForEach-Object {
            $srcpath = $_.FullName
            $destpath = $_.FullName -replace "^C:\\Users\\$Username\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles",$HistoryFolder
            New-Item -Path $destpath -ItemType Directory -Force | Out-Null
            $filesToCopy | Where-Object{ Test-Path "$srcpath\$_" } | ForEach-Object{ Copy-Item -Path "$srcpath\$_" -Destination "$destpath\$_" }
        }
    }
}


function Get-DefenderExclusions {
	Write-Host "======Denender信息======"
	$DefenderExclusionFolder = "$FolderCreation\DefenderExclusions"
	New-Item -Path $DefenderExclusionFolder -ItemType Directory -Force | Out-Null
	Get-MpPreference | Select-Object -ExpandProperty ExclusionPath | Out-File -Force -FilePath "$DefenderExclusionFolder\ExclusionPath.txt"
	Get-MpPreference | Select-Object -ExpandProperty ExclusionExtension | Out-File -Force -FilePath "$DefenderExclusionFolder\ExclusionExtension.txt"
	Get-MpPreference | Select-Object -ExpandProperty ExclusionIpAddress | Out-File -Force -FilePath "$DefenderExclusionFolder\ExclusionIpAddress.txt"
	Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess | Out-File -Force -FilePath "$DefenderExclusionFolder\ExclusionProcess.txt"
}

function Get-NewFile{
    Write-Host "======24小时内temp新增可执行文件信息信息======"
    Get-ChildItem -Path "C:\Windows\Temp" -Recurse -Include *.exe,*.ps1,*.bat | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-1)}
    Write-Host "建议使用此命令检索web等目录 Get-ChildItem -Path 'C:\Windows\Temp' -Recurse -Include *.exe,*.ps1,*.bat,*.php,*.asp,*.jsp | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-1)}  (也可以替换成分钟：AddMinutes(-30))"

}

function Analyzing-Log{
    Write-Host "======解析安全日志中的重要事件======"
    $output = "$FolderCreation\安全日志浅析.txt"
    Get-WinEvent -FilterHashtable @{LogName='Security';ID=@(4624, 4625, 4720, 4722, 4726, 4698, 7045, 4609)} | Select-Object TimeCreated, Id, Message | Out-File -Force -FilePath $output
}

function Get-Software{
    Write-Host "======收集已安装软件======"
    $output = "$FolderCreation\已安装软件.txt"
    Get-CimInstance -ClassName win32_product | Select-Object Name, Version, Vendor, InstallDate, InstallSource, PackageName, LocalPackag | Out-File -Force -FilePath $output
}

function Zip-Results {
    Write-Host "Write results to $FolderCreation.zip..."
    Compress-Archive -Force -LiteralPath $FolderCreation -DestinationPath "$FolderCreation.zip"
}

function Run {
    param(
        [Parameter(Mandatory=$false)][String]$Username
    )
    Get-EventViewerFiles
    Get-SysInfo
    Get-IPInfo
    Get-OpenConnections
    Get-AutoRunInfo
    Get-RegAutoRunInfo
    Get-ActiveUsers
    Get-LocalUsers
    Get-ActiveProcesses
    Get-RDPSessions
    Get-PowershellHistoryCurrentUser
    Get-PowershellConsoleHistory-AllUsers
    Get-DNSCache
    Get-hosts
    Get-RunningServices
    Get-ScheduledTasks
    if($Username) {
        Get-ChromiumFiles -Username $Username
        Get-FirefoxFiles -Username $Username
    }

	Get-DefenderExclusions
    Get-NewFile
    Analyzing-Log
    Get-Software
}


Run -Username $currentUsername -ErrorAction SilentlyContinue

Zip-Results