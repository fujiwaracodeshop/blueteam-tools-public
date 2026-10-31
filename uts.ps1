#Script Author - catwithapples/takumi
#Unified triage scripts (in progress)
$ErrorActionPreference = "Continue"

#Logfile for triage actions
$ts = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
New-Item -Path "C:\Windows\System32\ja-jq\backup\log_$ts.txt"
$logFile = "C:\Windows\System32\ja-jq\backup\log_$ts.txt"

#The following was not written by me fully, but adapted a bit for use as a standalone script
#I basically just take the output from most of these and add them to a file so I can view them easier/store them
#Also I had to change a few because the original author wrote them as a powershell module and I want to run all of them without prompting for input
#See repo: https://github.com/jsgreen90/PowerShell-BlueTeam/blob/main/BlueTeamPowerShell.psm1

#create whitelist
Add-Content -Path $logFile -Value "=== Hidden Exes Scan Start ==="
    $whitelist = '.exe', '.dll'
    #grab items in target directory
    $file_listing = Get-ChildItem -Path "C:\Windows\System32" -Recurse:$true
    Write-Host("Number of Files/Folders:")$file_listing.count
    $suspect_files = @()
    for ($i=0;$i -lt $file_listing.count; $i++)
    {
        #for each item make sure its not a directory or whitelisted
        if ((Test-Path $file_listing[$i] -PathType Leaf) -and ($file_listing[$i].Extension -notin $whitelist))
        {
            $exebytes = '{0:X2}' -f (Get-Content $file_listing[$i] -Encoding Byte -ReadCount 4)
            if($exebytes -eq '4D 5A 90 00')
            {
                Write-Host("Found atypical file:")$file_listing[$i]
                Add-Content -Path $logFile -Value $file_listing[$i]
                $suspect_files += $file_listing[$i]
            }
        }
    }
    Write-Host("Number of suspicious files found:")$suspect_files.count
    Write-Host $suspect_files
    Add-Content -Path $logFile -Value "=== Hidden Exes Scan End ==="

Add-Content -Path $logFile -Value "=== Filter Manager Scan Start ==="
$FilterEvents = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName="Microsoft-Windows-FilterManager"} | ForEach-Object {
        [PSCustomObject] @{
            TimeCreated = $_.TimeCreated
            MachineName = $_.MachineName
            UserId = $_.UserId
            FilterDriver = $_.Properties[4].Value
            Message = $_.Message
        }
    }
    Write-Output "Scanning for suspicious filter drivers. Any found will be compared against existing services:"
    $SuspectDrivers = $($FilterEvents | where-object {$_.FilterDriver -ine "FileInfo" -AND $_.FilterDriver -ine "WdFilter" -AND $_.FilterDriver -ine "storqosflt" -AND $_.FilterDriver -ine "wcifs" -AND $_.FilterDriver -ine "CldFlt" -AND $_.FilterDriver -ine "FileCrypt" -AND $_.FilterDriver -ine "luafv" -AND $_.FilterDriver -ine "npsvctrig" -AND $_.FilterDriver -ine "Wof" -AND $_.FilterDriver -ine "FileInfo" -AND $_.FilterDriver -ine "bindflt" -AND $_.FilterDriver -ine "PROCMON24" -AND $_.FilterDriver -ine "FsDepends"} | Select-Object -exp FilterDriver)
    $SuspectDrivers
    foreach ($driver in $SuspectDrivers){
    Write-Output "Checking services for relevant drivers. Any which aren't present may indicate a filter driver which has since been removed, or an active rootkit filtering service registry keys."
    Get-ChildItem REGISTRY::HKLM\SYSTEM\CurrentControlSet\Services\$driver
    Add-Content -Path $logFile -Value $driver
    }

Add-Content -Path $logFile -Value "=== Filter Manager Scan End ==="

Add-Content -Path $logFile -Value "=== User Powershell History Scan Start ==="

$users = Get-ChildItem C:\Users

    foreach($user in $users){
        if(Test-Path -Path  C:\Users\$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt){
        Add-Content -Path $logFile -Value "Powershell History for $user"
            $psHistory = Get-Content C:\Users\$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
            foreach($cmd in $psHistory){
                Add-Content -Path $logFile -Value $cmd
        }
    }
}
Add-Content -Path $logFile -Value "=== User Powershell History Scan End ==="
#(gps).Modules.FileName | get-authenticodesignature | ? Status -NE "Valid"

Add-Content -Path $logFile -Value "=== Scheduled Task Scan Start ==="
$tasks = Get-ScheduledTask | Select-Object TaskName, TaskPath, Date, Author, Actions, Triggers, Description, State |
    Where-Object Author -NotLike 'Microsoft*' | Where-Object Author -NE $null | Where-Object Author -NotLike '*@%SystemRoot%\*'

    #for each task found, export in XML which will show any commands run
    foreach ($task in $tasks)
    {
        Export-ScheduledTask -TaskName $task.TaskName
        Add-Content -Path $logFile -Value $task
    }
Add-Content -Path $logFile -Value "=== Scheduled Task Scan End ==="

Add-Content -Path $logFile -Value "=== Hidden Service Scan Start ==="
$hidsvcs = Compare-Object -ReferenceObject (Get-Service | Select-Object -ExpandProperty Name | ForEach-Object { $_ -replace "_[0-9a-f]{2,8}$" } ) -DifferenceObject (Get-ChildItem -path hklm:\system\currentcontrolset\services | ForEach-Object { $_.Name -Replace "HKEY_LOCAL_MACHINE\\","HKLM:\" } | Where-Object { Get-ItemProperty -Path "$_" -name objectname -erroraction 'ignore' } | ForEach-Object { $_.substring(40) }) -PassThru | Where-Object {$_.sideIndicator -eq "=>"}
foreach ($hidsvc in $hidsvcs)
{
    Write-Host $hidsvc
    Add-Content -Path $logFile -Value $hidsvc
}
Add-Content -Path $logFile -Value "=== Hidden Service Scan End ==="

Add-Content -Path $logFile -Value "=== DLL Signature Check Start ==="
$a = Get-ChildItem  -Path C:\Windows\* -Include *.dll | Get-AuthenticodeSignature | Where-Object Status -NE "Valid" | Format-List *
    $b = Get-ChildItem  -Path C:\Windows\System32\* -Include *.dll | Get-AuthenticodeSignature | Where-Object Status -NE "Valid" | Format-List *
    $c = $a + $b
    $c
    Add-Content -Path $logFile -Value $c
Add-Content -Path $logFile -Value "=== DLL Signature Check End ==="

Add-Content -Path $logFile -Value "=== Logon Script Check Start ==="
$logonScriptsArrayList = [System.Collections.ArrayList]@();
                 
    New-PSDrive HKU Registry HKEY_USERS -ErrorAction SilentlyContinue | Out-Null;
    Set-Location HKU: | Out-Null;

    $SIDS  += Get-ChildItem -Path HKU: | Where-Object {$_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$'} | ForEach-Object {$_.PSChildName };

    foreach($SID in $SIDS){
       $logonscriptObject = [PSCustomObject]@{
           SID =""
           HasLogonScripts = ""
    
       };
       $logonscriptObject.sid = $SID; 
       $logonscriptObject.haslogonscripts = !($null -eq (Get-ItemProperty HKU:\$SID\Environment\).userinitmprlogonscript); 
       $logonScriptsArrayList.add($logonscriptObject) | out-null
       Add-Content -Path $logFile -Value $logonScriptsObject
       }
    $logonScriptsArrayList
Add-Content -Path $logFile -Value "=== Logon Script Check End ==="

Add-Content -Path $logFile -Value "=== Driver Check Start ==="
$susdrivers = Get-ChildItem -path C:\Windows\System32\drivers -include *.sys -recurse -ea SilentlyContinue | Get-AuthenticodeSignature | Where-Object {$_.status -ne 'Valid'}
foreach ($susdriver in $susdrivers){
    Add-Content -Path $logFile -Value $susdriver
}
Add-Content -Path $logFile -Value "=== Driver Check End ==="
Add-Content -Path $logFile -Value "=== Weird Exe Check Start ==="
$Output = $logFile
   $commands = ('dir /s /b %localappdata%\*.exe | findstr /e .exe',
                'dir /s /b %appdata%\*.exe | findstr /e .exe',
                'dir /s /b %localappdata%\*.dll | findstr /e .dll',
                'dir /s /b %appdata%\*.dll | findstr /e .dll',
                'dir /s /b %localappdata%\*.bat | findstr /e .bat',
                'dir /s /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup\" | findstr /e .lnk',
                'dir /s /b "C:\Users\Public\" | findstr /e .exe',
                'dir /s /b "C:\Users\Public\" | findstr /e .lnk',
                'dir /s /b "C:\Users\Public\" | findstr /e .dll',
                'dir /s /b "C:\Users\Public\" | findstr /e .bat')
   
   foreach ($command in $commands)
   {
       Write-Output $command >> $Output
       cmd.exe /c $command >> $Output
       Write-Output "-----------------------------------------------------" >> $Output
   }
Add-Content -Path $logFile -Value "=== Weird Exe Check End ==="