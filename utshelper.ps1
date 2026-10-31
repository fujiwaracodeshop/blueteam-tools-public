## Helper script to make uts.ps1 work correctly. RUN THIS FIRST.
## RUN AS ADMIN PS FOR SYSMON CONFIG
## This also serves as a file to run stuff that should only need be run once (configs, changes etc)

$ErrorActionPreference = "Continue"

## Run sysmon config (need to be in sysmon dir to work)
## Config file is from here: https://github.com/THEVER1TAS/sysmon-config/tree/master
## Config file can be modified if necessary (We can add sus hashes or other things to it over time)
sysmon.exe -accepteula -i sysmonconfig-advanced-public-block-v3.3.xml
cmd.exe /c 'wevtutil.exe sl Microsoft-Windows-Sysmon/Operational /ca:O:BAG:SYD:(A;;0xf0005;;;SY)(A;;0x5;;;BA)(A;;0x1;;;S-1-5-32-573)(A;;0x1;;;NS)'

#Create backup path if it doesnt exist
if (-not (Test-Path -Path "C:\Windows\System32\ja-jq")) {
    $newFolder = New-Item -Path "C:\Windows\System32\ja-jq" -ItemType Directory
    $newFolder.Attributes = "Hidden, ReadOnly"
}

# Create backup folder if it doesn't exist
if (-not (Test-Path -Path "C:\Windows\System32\ja-jq\backup")) {
    $backup = New-Item -Path "C:\Windows\System32\ja-jq\backup" -ItemType Directory
    $backup.Attributes = "Hidden, ReadOnly"
}

### Hardening Section Before Scheduled Task Creation

#Backup old fw
netsh advfirewall export "C:\Windows\System32\ja-jq\default.wfw"
Get-NetFirewallRule | Export-Csv -Path "C:\Windows\System32\ja-jq\DefaultRules.csv" -NoTypeInformation

#Disable features
Disable-WindowsOptionalFeature -Online -FeatureName "TelnetClient"
Disable-WindowsOptionalFeature -Online -FeatureName "TFTP"
Set-SmbServerConfiguration -EnableSMB1Protocol $false -EnableSMB2Protocol $true –EncryptData $true –RejectUnencryptedAccess $true -RequireSecuritySignature $true -EnableSecuritySignature $true -AuditSmb1Access $true

#Set registry keys
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LMCompatibilityLevel" -Value 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\tcpip* -Name NetbiosOptions -Value 2
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name FullSecureChannelProtection -Value 1

#Stop bad services (Check if WinRM is a scored service before deploying)
$servicesToStop = @("CertPropSvc", "DiagTrack", "PlugPlay", "Spooler", "WinRM")
Get-Service -Name $servicesToStop | Stop-Service -Force -PassThru | Set-Service -StartupType Disabled
Disable-PSRemoting -Force
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 1
Disable-NetFirewallRule -DisplayGroup "Remote Desktop" 

#Firewall setup
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
netsh advfirewall import "C:\Windows\System32\ja-jq\default.wfw" Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block -NotifyOnListen True -LogAllowed True -LogBlocked True -LogFileName %SystemRoot%\System32\LogFiles\Firewall\pfirewall.log

# Disable Non-Microsoft rules
Get-NetFirewallRule | Where-Object { $_.Group -notlike "@%SystemRoot%*" } |Disable-NetFirewallRule

#--------------------------------------------------------------
# Current rule list:
# Allow: 53/88/464/389/636/445/135/5000-5100/123/80
# Block: 137/138/139/5353/22
#--------------------------------------------------------------

# DNS
New-NetFirewallRule -DisplayName "DNS TCP Inbound 53" -Direction Inbound -LocalPort 53 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "DNS TCP Outbound 53" -Direction Outbound -RemotePort 53 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "DNS UDP Inbound 53" -Direction Inbound -LocalPort 53 -Protocol UDP -Action Allow
New-NetFirewallRule -DisplayName "DNS UDP Outbound 53" -Direction Outbound -RemotePort 53 -Protocol UDP -Action Allow
New-NetFirewallRule -DisplayName "Kerberos TCP Inbound 88" -Direction Inbound -LocalPort 88 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Kerberos TCP Outbound 88" -Direction Outbound -RemotePort 88 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Kerberos UDP Inbound 88" -Direction Inbound -LocalPort 88 -Protocol UDP -Action Allow
New-NetFirewallRule -DisplayName "Kerberos UDP Outbound 88" -Direction Outbound -RemotePort 88 -Protocol UDP -Action Allow

# Kerberos Password Change
New-NetFirewallRule -DisplayName "Kerberos PW TCP Inbound 464" -Direction Inbound -LocalPort 464 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Kerberos PW TCP Outbound 464" -Direction Outbound -RemotePort 464 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Kerberos PW UDP Inbound 464" -Direction Inbound -LocalPort 464 -Protocol UDP -Action Allow
New-NetFirewallRule -DisplayName "Kerberos PW UDP Outbound 464" -Direction Outbound -RemotePort 464 -Protocol UDP -Action Allow

# LDAP
New-NetFirewallRule -DisplayName "LDAP TCP Inbound 389" -Direction Inbound -LocalPort 389 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "LDAP TCP Outbound 389" -Direction Outbound -RemotePort 389 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "LDAP UDP Inbound 389" -Direction Inbound -LocalPort 389 -Protocol UDP -Action Allow
New-NetFirewallRule -DisplayName "LDAP UDP Outbound 389" -Direction Outbound -RemotePort 389 -Protocol UDP -Action Allow

# LDAPS
New-NetFirewallRule -DisplayName "LDAPS TCP Inbound 636" -Direction Inbound -LocalPort 636 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "LDAPS TCP Outbound 636" -Direction Outbound -RemotePort 636 -Protocol TCP -Action Allow

# SMB 
New-NetFirewallRule -DisplayName "SMB TCP Inbound 445" -Direction Inbound -LocalPort 445 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "SMB TCP Outbound 445" -Direction Outbound -RemotePort 445 -Protocol TCP -Action Allow

# RPC 
New-NetFirewallRule -DisplayName "RPC TCP Inbound 135" -Direction Inbound -LocalPort 135 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "RPC TCP Outbound 135" -Direction Outbound -RemotePort 135 -Protocol TCP -Action Allow

# RPC Dynamic Range 
New-NetFirewallRule -DisplayName "RPC Dynamic TCP 49152-65535 Inbound" -Direction Inbound -LocalPort 49152-65535 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "RPC Dynamic TCP 49152-65535 Outbound" -Direction Outbound -RemotePort 49152-65535 -Protocol TCP -Action Allow

# Time Sync
New-NetFirewallRule -DisplayName "W32Time UDP Inbound 123" -Direction Inbound -LocalPort 123 -Protocol UDP -Action Allow
New-NetFirewallRule -DisplayName "W32Time UDP Outbound 123" -Direction Outbound -RemotePort 123 -Protocol UDP -Action Allow

# NetBIOS (BLOCK)
New-NetFirewallRule -DisplayName "Block NetBIOS UDP 137" -Direction Inbound -LocalPort 137 -Protocol UDP -Action Block
New-NetFirewallRule -DisplayName "Block NetBIOS UDP 138" -Direction Inbound -LocalPort 138 -Protocol UDP -Action Block
New-NetFirewallRule -DisplayName "Block NetBIOS TCP 139" -Direction Inbound -LocalPort 139 -Protocol TCP -Action Block

# ICMP 
New-NetFirewallRule -DisplayName "ICMPv4 Inbound" -Protocol ICMPv4 -Direction Inbound -Action Allow
New-NetFirewallRule -DisplayName "ICMPv4 Outbound" -Protocol ICMPv4 -Direction Outbound -Action Allow

# Block mDNS 
New-NetFirewallRule -DisplayName "Block mDNS Inbound (UDP 5353)" -Direction Inbound -LocalPort 5353 -Protocol UDP -Action Block -ErrorAction SilentlyContinue | Out-Null
New-NetFirewallRule -DisplayName "Block mDNS Outbound (UDP 5353)" -Direction Outbound -LocalPort 5353 -Protocol UDP -Action Block -ErrorAction SilentlyContinue | Out-Null

# HTTP
New-NetFirewallRule -DisplayName "HTTP UDP Inbound 80" -Direction Inbound -LocalPort 80 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "HTTP UDP Outbound 80" -Direction Outbound -RemotePort 80 -Protocol TCP -Action Allow

# Block SSH
New-NetFirewallRule -DisplayName "Block SSH Inbound 22" -Direction Inbound -LocalPort 22 -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block SSH Outbound 22" -Direction Outbound -RemotePort 22 -Protocol TCP -Action Block

netsh advfirewall export "C:\Windows\System32\ja-jq\good.wfw"

### Create scheduled task for the UTS.ps1 to run, make sure the file path in the $Action is correct otherwise will error
$NewTaskName = "WUASVC"
$User="NT AUTHORITY\SYSTEM"
$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 5) `
    -RepetitionDuration (New-TimeSpan -Hours 24)
$Action= New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -NoLogo -NonInteractive -WindowStyle hidden -ExecutionPolicy Bypass -File C:\Windows\uts.ps1"
Register-ScheduledTask -TaskName $NewTaskName -Trigger $Trigger -User $User -Action $Action -RunLevel Highest –Force

