###################################################################################
#
#    Script:    WINTri.ps1
#    Version:   1.11
#    Contact:   DFIR@nttdata.com
#    Purpose:   Windows Cyber Security Incident Response Script (PowerShell)
#    Usage:     .\WINTri.ps1
#
#    This program is free software: you can redistribute it and / or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program. If not, see <https://www.gnu.org/licenses/>.
#
###################################################################################

$script = "WINTri_"
$version = "v1.10"

########## Startup ##########


Write-Host "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Please Note:

Hi $env:USERNAME, script running on $env:ComputerName, please do not touch!

Bitte beachten Sie:

Hallo $env:USERNAME, skript läuft auf $env:ComputerName, bitte nicht berühren!

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" -ForegroundColor yellow -BackgroundColor black

# Check Priveleges
$admin=[Security.Principal.WindowsIdentity]::GetCurrent()
If ((New-Object Security.Principal.WindowsPrincipal $Admin).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) -eq $FALSE)
{
    Write-Host "`n"
    Write-Warning "You have insufficient permissions. Run this script with local Administrator priveleges."
    Write-Warning "Sie haben unzureichende Berechtigungen. Fuehren Sie dieses Skript mit lokalen Administratorrechten aus."
    Write-Host "`n"
    exit
}

########## Admin ##########

# Destination
$dst = $PSScriptRoot
# System Date/Time
$timestamp = ((Get-Date).ToString('_yyyyMMdd_HHmmss'))
# Computer Name
$endpoint = $env:ComputerName
# Triage
$name = $script+$endpoint+$timestamp
$tri = $name
# Stream Events
Start-Transcript $dst\$tri\WINTri.log -Append | Out-Null

# Exchange Install path
function Get-ExchangeInstallPath {
    $p = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue).MsiInstallPath
    if ($null -eq $p) {
        $p = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v14\Setup -ErrorAction SilentlyContinue).MsiInstallPath
    }

    return $p
}

$exchangePath = Get-ExchangeInstallPath

# Script Progress
$Activity1 = "Task / Aufgabe (1 / 13)"
$Id1 = 1
$Task1 = "Admin task running / Admin-Aufgabe laeuft."
Write-Progress -Id $Id1 -Activity $Activity1 -Status $Task1

# Directory Structure
New-Item $dst\$tri\Registry -ItemType Directory | Out-Null
New-Item $dst\$tri\Configuration -ItemType Directory | Out-Null
# User Folders
Get-ChildItem -Path C:\Users -Directory -Force | Select-Object -ExpandProperty Name | Out-File $dst\$tri\Configuration\User_Folders.txt
$UserFolders = Get-Content $dst\$tri\Configuration\User_Folders.txt
ForEach ($UserFolder in $UserFolders)
{
	New-Item $dst\$tri\Registry\$UserFolder -ItemType Directory | Out-Null
	}
	
########## Memory ##########

# Script Progress
$Activity2 = "Task / Aufgabe (2 / 13)"
$Id2 = 2
$Task2 = "Gather memory process information / Sammeln von Speicherprozessinformationen."
Write-Progress -Id $Id2 -Activity $Activity2 -Status $Task2

# Directory Structure
New-Item $dst\$tri\Memory -ItemType Directory | Out-Null
# Process + PPID + PID
Get-WmiObject -class win32_process | Select-Object -property processname, ws, parentprocessid, processid, sessionid, creationdate, commandline | Export-Csv $dst\$tri\Memory\Process_PPID_PID.txt
# Processes + Services
tasklist /svc | Out-File $dst\$tri\Memory\Process_Services.txt
# Processes + DLL
tasklist /m | Out-File $dst\$tri\Memory\Process_DLL.txt
# Processes & Owners
tasklist /v | Out-File $dst\$tri\Memory\Process_Owners.txt

########## Registry ##########

# Script Progress
$Activity3 = "Task / Aufgabe (3 / 13)"
$Id3 = 3
$Task3 = "Gather registry information / Sammeln von Registerinformationen."
Write-Progress -Id $Id3 -Activity $Activity3 -Status $Task3

# Local Groups
try
{
    Get-LocalGroup | select * | Out-File $dst\$tri\Registry\Local_Groups.txt
}
catch
{

}
# Local User Accounts
try
{
    Get-LocalUser | select * | Out-File $dst\$tri\Registry\Local_User_Accounts.txt
}
catch
{

}
# Local Admins
try
{
    net localgroup administrators | Out-File $dst\$tri\Registry\Local_Admins.txt
}
catch
{

}
# Domain Admins
try
{
    net group "domain admins" /domain | Out-File $dst\$tri\Registry\Domain_Admins.txt
}
catch
{

}
# Enterprise Admins
try
{
    net group "enterprise admins" /domain | Out-File $dst\$tri\Registry\Enterprise_Admins.txt
}
catch
{

}
# System Hives
reg save HKLM\SYSTEM $dst\$tri\Registry\SYSTEM | Out-Null
reg save HKLM\SOFTWARE $dst\$tri\Registry\SOFTWARE | Out-Null
reg save HKLM\SAM $dst\$tri\Registry\SAM | Out-Null
reg save HKLM\SECURITY $dst\$tri\Registry\SECURITY | Out-Null
# Local System Hive
reg save HKU\.DEFAULT $dst\$tri\Registry\.DEFAULT | Out-Null
# NTUSER.DAT Hives
$UserFolders = Get-Content $dst\$tri\Configuration\User_Folders.txt
ForEach ($UserFolder in $UserFolders)
{
    cmd /c "C:\ntt\rawcopy64.exe" C:\Users\$UserFolder\NTUSER.DAT  $dst\$tri\Registry\$UserFolder\NTUSER.DAT
	Copy-Item $dst\NTUSER.DAT $dst\$tri\Registry\$UserFolder\NTUSER.DAT
	Remove-Item $dst\NTUSER.DAT
	}
# UsrClass
$UserFolders = Get-Content $dst\$tri\Configuration\User_Folders.txt
ForEach ($UserFolder in $UserFolders)
{
    cmd /c "C:\ntt\rawcopy64.exe" C:\Users\$UserFolder\AppData\Local\Microsoft\Windows\UsrClass.dat  $dst\$tri\Registry\$UserFolder\UsrClass.dat
    Copy-Item $dst\UsrClass.dat $dst\$tri\Registry\$UserFolder\UsrClass.dat
	Remove-Item $dst\UsrClass.dat
	}

########## Logs ##########

# Script Progress
$Activity4 = "Task / Aufgabe (4 / 13)"
$Id4 = 4
$Task4 = "Gather log information / Sammeln von Protokollinformationen."
Write-Progress -Id $Id4 -Activity $Activity4 -Status $Task4

# Directory Structure
New-Item $dst\$tri\Logs\winevt -ItemType Directory | Out-Null
New-Item $dst\$tri\Logs\USB -ItemType Directory | Out-Null
New-Item $dst\$tri\Logs\ETW -ItemType Directory | Out-Null
New-Item $dst\$tri\Logs\PowerShell -ItemType Directory | Out-Null
# Windows Event Logs
if (Test-Path C:\Windows\System32\winevt\Logs)
{
 Copy-Item C:\Windows\System32\winevt\Logs\*.evtx $dst\$tri\Logs\winevt
}
# USB Device Connections
if (Test-Path C:\Windows\inf\setupapi.dev.log)
{
  Copy-Item C:\Windows\inf\setupapi.dev.log $dst\$tri\Logs\USB
}
# Windows Update Log
if (Test-Path C:\Windows\Logs\WindowsUpdate)
{
  Copy-Item C:\Windows\Logs\WindowsUpdate\*.etl $dst\$tri\Logs\ETW
}
# PowerShell History
$UserFolders = Get-Content $dst\$tri\Configuration\User_Folders.txt
ForEach ($UserFolder in $UserFolders)
{
        robocopy "C:\Users\$UserFolder\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine" $dst\$tri\Logs\PowerShell\ConsoleHost_history-$UserFolder ConsoleHost_history.txt /ZB /TS /r:4 /w:3 /FP /NP /log+:$dst\$tri\Logs\PowerShell\ConsoleHost_history-$UserFolder.txt | Out-Null
    }
# Firewall Logs
if (Test-Path C:\Windows\System32\LogFiles\Firewall)
{
    New-Item $dst\$tri\Logs\Firewall -ItemType Directory | Out-Null
    robocopy "C:\Windows\System32\LogFiles\Firewall" "$dst\$tri\Logs\Firewall\" /E /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:$dst\$tri\Logs\Firewall\Firewall.txt | Out-Null
}
# Internet Information Services
if (Test-Path C:\inetpub\logs\LogFiles)
{
    New-Item $dst\$tri\Logs\IIS -ItemType Directory | Out-Null
    robocopy "C:\inetpub\logs\LogFiles" "$dst\$tri\Logs\IIS\" /E /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:$dst\$tri\Logs\IIS\IIS_ID_Folders.txt | Out-Null
}
# Exchange Logging
if (Test-Path "$exchangePath\Logging\")
{
    New-Item $dst\$tri\Logs\Exchange -ItemType Directory | Out-Null
    robocopy "$exchangePath\Logging" "$dst\$tri\Logs\Exchange\" /E /copyall /ZB /TS /r:4 /w:15 /FP /NP /log+:$dst\$tri\Logs\Exchange\Exchange_ID_Folders.txt | Out-Null
}

########## Network ##########

# Script Progress
$Activity5 = "Task / Aufgabe (5 / 13)"
$Id5 = 5
$Task5 = "Gather network information / Sammeln von Netzwerkinformationen."
Write-Progress -Id $Id5 -Activity $Activity5 -Status $Task5

# Directory Structure
New-Item $dst\$tri\Network -ItemType Directory | Out-Null
# DNS Entries
Copy-Item C:\Windows\System32\drivers\etc\hosts $dst\$tri\Network
# Network Settings
Copy-Item C:\Windows\System32\drivers\etc\networks $dst\$tri\Network
# IP Configuration
ipconfig /all | Out-File $dst\$tri\Network\ipconfig_all.txt
# Local DNS
ipconfig /displaydns | Out-File $dst\$tri\Network\ipconfig_dns.txt
# DNS Client Cache
Get-DnsClientCache | Out-File $dst\$tri\Network\DNS_Client_Cache.txt
# ARP Table
arp -a | Out-File $dst\$tri\Network\ARP_Table.txt
# Netstat
netstat -naob | Out-File $dst\$tri\Network\netstat.txt
# Routing Table
netstat -rn | Out-File $dst\$tri\Network\Routing_Table.txt
# Listening Ports
netstat -an| findstr LISTENING | Out-File $dst\$tri\Network\Listening_Ports.txt
# Open Connections
netstat -ano | Out-File $dst\$tri\Network\Open_Connections.txt
# Wireless Profiles
netsh wlan show profiles | Out-File $dst\$tri\Network\Wireless_Profiles.txt
# Firewall Configuration
netsh firewall show config | Out-File $dst\$tri\Network\Firewall_Configuration.txt
# Firewall Profile Properties
netsh advfirewall show allprofiles | Out-File $dst\$tri\Network\Firewall_Profile_Properties.txt
# Firewall Rules
netsh advfirewall firewall show rule name=all | Out-File $dst\$tri\Network\Firewall_Rules.txt

########## Configuration ##########

# Script Progress
$Activity6 = "Task / Aufgabe (6 / 13)"
$Id6 = 6
$Task6 = "Gather configuration information / Sammeln von Konfigurationsinformationen."
Write-Progress -Id $Id6 -Activity $Activity6 -Status $Task6

# Screenshot (https://gallery.technet.microsoft.com/scriptcenter/eeff544a-f690-4f6b-a586-11eea6fc5eb8)
Function Take-ScreenShot {   
#Requires -Version 2 
        [cmdletbinding( 
                SupportsShouldProcess = $True, 
                DefaultParameterSetName = "screen", 
                ConfirmImpact = "low" 
        )] 
Param ( 
       [Parameter( 
            Mandatory = $False, 
            ParameterSetName = "screen", 
            ValueFromPipeline = $True)] 
            [switch]$screen, 
       [Parameter( 
            Mandatory = $False, 
            ParameterSetName = "window", 
            ValueFromPipeline = $False)] 
            [switch]$activewindow, 
       [Parameter( 
            Mandatory = $False, 
            ParameterSetName = "", 
            ValueFromPipeline = $False)] 
            [string]$file,  
       [Parameter( 
            Mandatory = $False, 
            ParameterSetName = "", 
            ValueFromPipeline = $False)] 
            [string] 
            [ValidateSet("bmp","jpeg","png")] 
            $imagetype = "bmp", 
       [Parameter( 
            Mandatory = $False, 
            ParameterSetName = "", 
            ValueFromPipeline = $False)] 
            [switch]$print                        
        
) 
# C# code 
$code = @' 
using System; 
using System.Runtime.InteropServices; 
using System.Drawing; 
using System.Drawing.Imaging; 
namespace ScreenShotDemo 
{ 
  /// <summary> 
  /// Provides functions to capture the entire screen, or a particular window, and save it to a file. 
  /// </summary> 
  public class ScreenCapture 
  { 
    /// <summary> 
    /// Creates an Image object containing a screen shot the active window 
    /// </summary> 
    /// <returns></returns> 
    public Image CaptureActiveWindow() 
    { 
      return CaptureWindow( User32.GetForegroundWindow() ); 
    } 
    /// <summary> 
    /// Creates an Image object containing a screen shot of the entire desktop 
    /// </summary> 
    /// <returns></returns> 
    public Image CaptureScreen() 
    { 
      return CaptureWindow( User32.GetDesktopWindow() ); 
    }     
    /// <summary> 
    /// Creates an Image object containing a screen shot of a specific window 
    /// </summary> 
    /// <param name="handle">The handle to the window. (In windows forms, this is obtained by the Handle property)</param> 
    /// <returns></returns> 
    private Image CaptureWindow(IntPtr handle) 
    { 
      // get te hDC of the target window 
      IntPtr hdcSrc = User32.GetWindowDC(handle); 
      // get the size 
      User32.RECT windowRect = new User32.RECT(); 
      User32.GetWindowRect(handle,ref windowRect); 
      int width = windowRect.right - windowRect.left; 
      int height = windowRect.bottom - windowRect.top; 
      // create a device context we can copy to 
      IntPtr hdcDest = GDI32.CreateCompatibleDC(hdcSrc); 
      // create a bitmap we can copy it to, 
      // using GetDeviceCaps to get the width/height 
      IntPtr hBitmap = GDI32.CreateCompatibleBitmap(hdcSrc,width,height); 
      // select the bitmap object 
      IntPtr hOld = GDI32.SelectObject(hdcDest,hBitmap); 
      // bitblt over 
      GDI32.BitBlt(hdcDest,0,0,width,height,hdcSrc,0,0,GDI32.SRCCOPY); 
      // restore selection 
      GDI32.SelectObject(hdcDest,hOld); 
      // clean up 
      GDI32.DeleteDC(hdcDest); 
      User32.ReleaseDC(handle,hdcSrc); 
      // get a .NET image object for it 
      Image img = Image.FromHbitmap(hBitmap); 
      // free up the Bitmap object 
      GDI32.DeleteObject(hBitmap); 
      return img; 
    } 
    /// <summary> 
    /// Captures a screen shot of the active window, and saves it to a file 
    /// </summary> 
    /// <param name="filename"></param> 
    /// <param name="format"></param> 
    public void CaptureActiveWindowToFile(string filename, ImageFormat format) 
    { 
      Image img = CaptureActiveWindow(); 
      img.Save(filename,format); 
    } 
    /// <summary> 
    /// Captures a screen shot of the entire desktop, and saves it to a file 
    /// </summary> 
    /// <param name="filename"></param> 
    /// <param name="format"></param> 
    public void CaptureScreenToFile(string filename, ImageFormat format) 
    { 
      Image img = CaptureScreen(); 
      img.Save(filename,format); 
    }     
    
    /// <summary> 
    /// Helper class containing Gdi32 API functions 
    /// </summary> 
    private class GDI32 
    { 
       
      public const int SRCCOPY = 0x00CC0020; // BitBlt dwRop parameter 
      [DllImport("gdi32.dll")] 
      public static extern bool BitBlt(IntPtr hObject,int nXDest,int nYDest, 
        int nWidth,int nHeight,IntPtr hObjectSource, 
        int nXSrc,int nYSrc,int dwRop); 
      [DllImport("gdi32.dll")] 
      public static extern IntPtr CreateCompatibleBitmap(IntPtr hDC,int nWidth, 
        int nHeight); 
      [DllImport("gdi32.dll")] 
      public static extern IntPtr CreateCompatibleDC(IntPtr hDC); 
      [DllImport("gdi32.dll")] 
      public static extern bool DeleteDC(IntPtr hDC); 
      [DllImport("gdi32.dll")] 
      public static extern bool DeleteObject(IntPtr hObject); 
      [DllImport("gdi32.dll")] 
      public static extern IntPtr SelectObject(IntPtr hDC,IntPtr hObject); 
    } 
 
    /// <summary> 
    /// Helper class containing User32 API functions 
    /// </summary> 
    private class User32 
    { 
      [StructLayout(LayoutKind.Sequential)] 
      public struct RECT 
      { 
        public int left; 
        public int top; 
        public int right; 
        public int bottom; 
      } 
      [DllImport("user32.dll")] 
      public static extern IntPtr GetDesktopWindow(); 
      [DllImport("user32.dll")] 
      public static extern IntPtr GetWindowDC(IntPtr hWnd); 
      [DllImport("user32.dll")] 
      public static extern IntPtr ReleaseDC(IntPtr hWnd,IntPtr hDC); 
      [DllImport("user32.dll")] 
      public static extern IntPtr GetWindowRect(IntPtr hWnd,ref RECT rect); 
      [DllImport("user32.dll")] 
      public static extern IntPtr GetForegroundWindow();       
    } 
  } 
} 
'@ 
#User Add-Type to import the code 
add-type $code -ReferencedAssemblies 'System.Windows.Forms','System.Drawing' 
#Create the object for the Function 
$capture = New-Object ScreenShotDemo.ScreenCapture 
 
#Take screenshot of the entire screen 
If ($Screen) { 
    Write-Verbose "Taking screenshot of entire desktop" 
    #Save to a file 
    If ($file) { 
        If ($file -eq "") { 
            $file = "$pwd\image.bmp" 
            } 
        Write-Verbose "Creating screen file: $file with imagetype of $imagetype" 
        $capture.CaptureScreenToFile($file,$imagetype) 
        } 
    ElseIf ($print) { 
        $img = $Capture.CaptureScreen() 
        $pd = New-Object System.Drawing.Printing.PrintDocument 
        $pd.Add_PrintPage({$_.Graphics.DrawImage(([System.Drawing.Image]$img), 0, 0)}) 
        $pd.Print() 
        }         
    Else { 
        $capture.CaptureScreen() 
        } 
    } 
}
Take-ScreenShot -screen -file $dst\$tri\Configuration\Desktop_Screenshot.png -imagetype png
# Operating System Information
systeminfo | Out-File $dst\$tri\Configuration\OS_Information.txt
# System Date/Time
Get-Date -Format "yyyyMMdd HHmmss K" | Out-File $dst\$tri\Configuration\System_Date_Time_Z.txt
# Environment Variables
Get-ChildItem ENV: | format-table @{Expression={$_.Name};Label="$ENV:ComputerName ENV:Variable"}, Value -AutoSize -Wrap | Out-File $dst\$tri\Configuration\Environment_Variables.txt
# AntiVirus Product
try
{
   Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct -ErrorAction Stop  | Out-File $dst\$tri\Configuration\AntiVirus_Product.txt
}
catch
{
   Write-Warning "[ERROR] invalid namespace [$($computer)] : $_"
   $noantivirus+=$computer
   $noantivirus | out-file -FilePath  $dst\$tri\Configuration\Noantivirus_Product.txt -Force
}
# Anti Malware Health Status
Get-WmiObject -namespace root\Microsoft\SecurityClient -Class AntimalwareHealthStatus | Out-File $dst\$tri\Configuration\Anti_Malware_Health_Status.txt
# Hotfixes
Get-HotFix | Out-File $dst\$tri\Configuration\Hotfixes.txt
# Disk Management
Get-WmiObject -class Win32_LogicalDisk | Out-File $dst\$tri\Configuration\Disk_Drives.txt
# SMB Shares
Get-SmbShare | Out-File $dst\$tri\Configuration\SMB_Shares.txt
# Scheduled Tasks
schtasks /query /fo list /v | Out-File $dst\$tri\Configuration\Scheduled_Tasks.txt
# Volume Shadow Copy Service
C:\windows\system32\vssadmin list shadows | Out-File $dst\$tri\Configuration\VSC.txt
# Group Policy Result
gpresult /R /Z | Out-File $dst\$tri\Configuration\Group_Policy_Result.txt

########## File System ##########

# Script Progress
$Activity7 = "Task / Aufgabe (7 / 13)"
$Id7 = 7
$Task7 = "Gather file system information / Sammeln von Dateisysteminformationen."
Write-Progress -Id $Id7 -Activity $Activity7 -Status $Task7

# Directory Structure
New-Item $dst\$tri\FileSystem -ItemType Directory | Out-Null
# Alternate Data Streams
try
{
   Get-ChildItem "C:\" -recurse | ForEach {Get-Item $_.FullName -stream *} | Where stream -ne ':$DATA' | Out-File $dst\$tri\FileSystem\Alternate_Data_Streams.txt
}
catch
{

}
# C:\Windows\Temp\ Directory Listing
Get-ChildItem -Force -Recurse C:\Windows\Temp\* | Format-Table Name, Length, CreationTimeUtc, LastWriteTimeUtc, LastAccessTimeUtc | Out-File $dst\$tri\FileSystem\C_Windows_Temp_Dir.txt
# C:\Users\<user>\AppData\Local\Temp\ Directory Listing
foreach($userpath in (Get-WmiObject win32_userprofile | Select-Object -ExpandProperty localpath)) {
    if (Test-Path(($userpath + "\AppData\Local\Temp\"))) {
        Get-ChildItem -Force -Recurse ($userpath + "\AppData\Local\Temp\*") | Format-Table Name, Length, CreationTimeUtc, LastWriteTimeUtc, LastAccessTimeUtc | Out-File $dst\$tri\FileSystem\C_Users_Temp_Dir.txt
    }
}
# Named Pipe Collection
if ($PSVersionTable.PSVersion.Major -ge 5) {
    # More detail with PowerShell version >= 5
    Get-ChildItem -Path "\\.\pipe\" | Out-File $dst\$tri\FileSystem\Named_PIPES.txt
}
else {
    # Any other versions
    [System.IO.Directory]::GetFiles("\\.\pipe\") | Out-File $dst\$tri\FileSystem\Named_PIPES.txt
}

########## Operating System ##########

# Script Progress
$Activity8 = "Task / Aufgabe (8 / 13)"
$Id8 = 8
$Task8 = "Gather system information / Sammeln von Systeminformationen."
Write-Progress -Id $Id8 -Activity $Activity8 -Status $Task8

# Directory Structure
New-Item $dst\$tri\OS\Jumplists -ItemType Directory | Out-Null
New-Item $dst\$tri\OS\LNK -ItemType Directory | Out-Null
New-Item $dst\$tri\OS\Programs -ItemType Directory | Out-Null
New-Item $dst\$tri\OS\Programs\StartupFiles -ItemType Directory | Out-Null
New-Item $dst\$tri\OS\BITSAdmin -ItemType Directory | Out-Null
New-Item $dst\$tri\OS\RDPCache -ItemType Directory | Out-Null
New-Item $dst\$tri\OS\SRUM -ItemType Directory | Out-Null
New-Item $dst\$tri\OS\WinNotifications -ItemType Directory | Out-Null
New-Item $dst\$tri\OS\WinTimeline -ItemType Directory | Out-Null


# Installed Programs
WMIC Product List Full /format:csv | Out-File $dst\$tri\OS\Programs\Installed_Programs.txt
# Startup Programs
Get-WmiObject -class "Win32_startupCommand" | select-object Name, Command, User, Location | Export-Csv $dst\$tri\OS\Programs\Startup_Programs.txt -NoTypeInformation
# Startup Files
if (Test-Path C:\Windows\System32\WDI\LogFiles\StartupInfo)
{
     Copy-Item C:\Windows\System32\WDI\LogFiles\StartupInfo\*.xml $dst\$tri\OS\Programs\StartupFiles
}
# SMB Sessions
if (Get-Command Get-SmbSession -ErrorAction SilentlyContinue){
    New-Item $dst\$tri\OS\SMB -ItemType Directory | Out-Null
    Get-SmbSession | format-table -AutoSize -wrap | Out-File $dst\$tri\OS\SMB\SMB_Sessions.txt
}
# BITSAdmin Job Que
bitsadmin /list | Out-File $dst\$tri\OS\\BITSAdmin\BITSAdmin_Job_Que.txt
# RDP Cache
$UserFolders = Get-Content $dst\$tri\Configuration\User_Folders.txt
ForEach ($UserFolder in $UserFolders)
{
    robocopy "C:\Users\$UserFolder\AppData\Local\Microsoft\Terminal Server Client\Cache" "$dst\$tri\OS\RDPCache\RDPCache-$UserFolder" *.bin /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:$dst\$tri\OS\RDPCache\RDPCache-$UserFolder.txt | Out-Null
    }
# System Resource Usage Monitor
if (Test-Path C:\Windows\System32\sru\SRUDB.dat)
{
    Copy-Item C:\Windows\System32\sru\SRUDB.dat $dst\$tri\OS\SRUM
}
# Windows Notifications
$UserFolders = Get-Content $dst\$tri\Configuration\User_Folders.txt
ForEach ($UserFolder in $UserFolders)
{
    robocopy "C:\Users\$UserFolder\AppData\Local\Microsoft\Windows\Notifications" "$dst\$tri\OS\WinNotifications\WinNotifications-$UserFolder" wpndatabase.* /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:$dst\$tri\OS\WinNotifications\WinNotifications-$UserFolder.txt | Out-Null
    robocopy "C:\Users\$UserFolder\AppData\Local\Microsoft\Windows\Notifications\wpnidm" "$dst\$tri\OS\WinNotifications\WinNotificationsPics-$UserFolder" *.jpg /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:$dst\$tri\OS\WinNotifications\WinNotificationsPics-$UserFolder.txt | Out-Null
}
# Prefetch
if (Test-Path C:\Windows\Prefetch)
{
    New-Item $dst\$tri\OS\Prefetch -ItemType Directory | Out-Null
    robocopy C:\Windows\Prefetch $dst\$tri\OS\Prefetch\PF /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:$dst\$tri\OS\Prefetch\Prefetch.txt | Out-Null
}
# RecentFileCache
if (Test-Path C:\Windows\appcompat\Programs\RecentFileCache.bcf)
{
    New-Item $dst\$tri\OS\RecentFileCache -ItemType Directory | Out-Null
    cmd /c "C:\ntt\rawcopy64.exe" "C:\Windows\appcompat\Programs\RecentFileCache.bcf"  $dst\$tri\OS\RecentFileCache\RecentFileCache.bcf
    Copy-Item $dst\RecentFileCache.bcf $dst\$tri\OS\RecentFileCache\RecentFileCache.bcf
	Remove-Item $dst\RecentFileCache.bcf
}
# Amcache.hve
if (Test-Path C:\Windows\appcompat\Programs\Amcache.hve)
{
    New-Item $dst\$tri\OS\AppCompat -ItemType Directory | Out-Null
    cmd /c "C:\ntt\rawcopy64.exe" "C:\Windows\appcompat\Programs\Amcache.hve"  $dst\$tri\OS\AppCompat\Amcache.hve
    Copy-Item $dst\Amcache.hve $dst\$tri\OS\AppCompat\Amcache.hve
	Remove-Item $dst\Amcache.hve
}
# LNK
$UserFolders = Get-Content $dst\$tri\Configuration\User_Folders.txt
ForEach ($UserFolder in $UserFolders)
{
    robocopy "C:\Users\$UserFolder\AppData\Roaming\Microsoft\Windows\Recent" "$dst\$tri\OS\LNK\LNK-$UserFolder" *.lnk /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:$dst\$tri\OS\LNK\LNK-$UserFolder.txt | Out-Null
    }
# Jumplists
$UserFolders = Get-Content $dst\$tri\Configuration\User_Folders.txt
ForEach ($UserFolder in $UserFolders)
{
    robocopy "C:\Users\$UserFolder\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" $dst\$tri\OS\Jumplists\Jumplists-$UserFolder /E /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:$dst\$tri\OS\Jumplists\Jumplists-$UserFolder.txt | Out-Null
    robocopy "C:\Users\$UserFolder\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations" $dst\$tri\OS\Jumplists\Jumplists-$UserFolder /E /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:$dst\$tri\OS\Jumplists\Jumplists-$UserFolder.txt | Out-Null
    }
# Windows Timeline
$UserFolders = Get-Content $dst\$tri\Configuration\User_Folders.txt
ForEach ($UserFolder in $UserFolders)
{
    robocopy "C:\Users\$UserFolder\AppData\Local\ConnectedDevicesPlatform" $dst\$tri\OS\WinTimeline\WinTimeline-$UserFolder /E /copyall /ZB /TS /r:4 /w:3 /FP /NP /log+:$dst\$tri\OS\WinTimeline\WinTimline-$UserFolder.txt | Out-Null
    }

# Script Progress
$Activity9 = "Task / Aufgabe (9 / 13)"
$Id9 = 9
$Task9 = "Gather UAL information "
Write-Progress -Id $Id9 -Activity $Activity9 -Status $Task9

# User Access Loggging
if (Test-Path C:\Windows\System32\LogFiles\SUM)
{
      New-Item $dst\$tri\OS\UAL -ItemType Directory | Out-Null 
   
      Get-UalDailyAccess | ConvertTo-Csv | Out-File $dst\$tri\OS\UAL\UAL-DailyAccess.txt
   
}

########## Internet ##########

# Script Progress
$Activity10 = "Task / Aufgabe (10 / 13)"
$Id10 = 10
$Task10 = "Gather internet information / Sammeln von Internet-Informationen."
Write-Progress -Id $Id10 -Activity $Activity10 -Status $Task10

# Directory Structure
New-Item $dst\$tri\Internet\Chrome -ItemType Directory | Out-Null
New-Item $dst\$tri\Internet\Firefox -ItemType Directory | Out-Null
New-Item $dst\$tri\Internet\IE -ItemType Directory | Out-Null
# Chrome
$UserFolders = Get-Content $dst\$tri\Configuration\User_Folders.txt
ForEach ($UserFolder in $UserFolders)
{
    robocopy "C:\Users\$UserFolder\AppData\Local\Google\Chrome\User Data\Default" $dst\$tri\Internet\Chrome\History-$UserFolder History /ZB /TS /r:4 /w:3 /FP /NP /log+:$dst\$tri\Internet\Chrome\Chrome-$UserFolder.txt | Out-Null
    }
# Firefox
$UserFolders = Get-Content $dst\$tri\Configuration\User_Folders.txt
ForEach ($UserFolder in $UserFolders)
{
    robocopy C:\Users\$UserFolder\AppData\Roaming\Mozilla\Firefox\Profiles $dst\$tri\Internet\Firefox\places-$UserFolder places.sqlite /s /ZB /TS /r:4 /w:3 /FP /NP /log+:$dst\$tri\Internet\Firefox\Firefox-$UserFolder.txt | Out-Null
    }
# IE
$UserFolders = Get-Content $dst\$tri\Configuration\User_Folders.txt
ForEach ($UserFolder in $UserFolders)
{
    cmd /c "C:\ntt\rawcopy64.exe" "C:\Users\$UserFolder\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat"  $dst\$tri\Internet\IE\WebCacheV01.dat-$UserFolder
	Copy-Item $dst\WebCacheV01.dat $dst\$tri\Internet\IE\WebCacheV01.dat-$UserFolder
	Remove-Item $dst\WebCacheV01.dat
    }
	
#### WER Forensic Artifacts #####
$Activity11 = "Task / Aufgabe (11 / 13)"
$Id11 = 11
$Task11 = "Gather WER forensic artifacts "
Write-Progress -Id $Id11 -Activity $Activity11 -Status $Task11
# Directory Structure
New-Item $dst\$tri\WER -ItemType Directory | Out-Null


if (Test-Path C:\ProgramData\Microsoft\Windows\WER\ReportArchive)
{
   robocopy C:\ProgramData\Microsoft\Windows\WER\ReportArchive $dst\$tri\WER\ReportArchive /E | Out-Null
}
if (Test-Path C:\ProgramData\Microsoft\Windows\WER\ReportQueue)
{
   robocopy C:\ProgramData\Microsoft\Windows\WER\ReportQueue $dst\$tri\WER\ReportQueue /E | Out-Null
}
$UserFolders = Get-Content $dst\$tri\Configuration\User_Folders.txt
ForEach ($UserFolder in $UserFolders)
{
     New-Item $dst\$tri\WER\WER-$UserFolder  -ItemType Directory | Out-Null
    if (Test-Path C:\Users\$UserFolder\AppData\Local\Microsoft\Windows\WER\ReportArchive) 
	{
	 
      robocopy C:\Users\$UserFolder\AppData\Local\Microsoft\Windows\WER\ReportArchive $dst\$tri\WER\WER-$UserFolder\ReportArchive /E | Out-Null
    }
	if (Test-Path C:\Users\$UserFolder\AppData\Local\Microsoft\Windows\WER\ReportQueue) 
	{
	  robocopy C:\Users\$UserFolder\AppData\Local\Microsoft\Windows\WER\ReportQueue $dst\$tri\WER\WER-$UserFolder\ReportQueue /E | Out-Null
	}
}



########## Recycle Bin  ##########

# Script Progress
$Activity12 = "Task / Aufgabe (12 / 13)"
$Id12 = 12
$Task12 = "Gather Recyle Bin information "
Write-Progress -Id $Id12 -Activity $Activity12 -Status $Task12

# Directory Structure
New-Item $dst\$tri\RecycleBin -ItemType Directory | Out-Null


ForEach ($DriveLetter in Get-PSDrive -PSProvider FileSystem) {
	$DelPath = $DriveLetter.Name + ':\$Recycle.Bin'
	Get-ChildItem $DelPath -Force -Recurse -ErrorAction SilentlyContinue -Include `$I*  |  select -ExpandProperty FullName | Out-File $dst\$tri\RecycleBin\index_file.txt -append
	$UserFolders = Get-Content $dst\$tri\RecycleBin\index_file.txt
	ForEach ($UserFolder in $UserFolders)
    {
	    Copy-Item $UserFolder $dst\$tri\RecycleBin\
	   
    }
	Get-ChildItem $DelPath -Force -Recurse -ErrorAction SilentlyContinue -Include `$R*  |  select -ExpandProperty FullName | Out-File $dst\$tri\RecycleBin\index_r_file.txt -append
	$UserFolders = Get-Content $dst\$tri\RecycleBin\index_r_file.txt
	ForEach ($UserFolder in $UserFolders)
    {
	    $outputFile = Split-Path $UserFolder -leaf
	    Copy-Item $UserFolder $dst\$tri\RecycleBin\$outputFile
	 
    }
}

########## Organise Collection ##########

# Script Progress
$Activity13 = "Task / Aufgabe (12 / 12)"
$Id13 = 13
$Task13 = "Organise Collection / Sammlung organisieren."
Write-Progress -Id $Id13 -Activity $Activity13 -Status $Task13

# Hashing
Get-ChildItem $dst\$tri -Recurse | Where-Object {!$_.psiscontainer } | Get-FileHash -ea 0 -Algorithm MD5 | Format-List  | Out-File $dst\$tri\Hashes.txt

Stop-Transcript | Out-Null

cmd /c "c:\NTT\7za.exe" a $dst\$tri.7z $dst\$tri\* 

# Compress Archive
Get-ChildItem -Path $dst\$tri | Compress-Archive -DestinationPath $dst\$tri.zip -CompressionLevel Fastest

# Delete Folder
Get-ChildItem -Path "$dst\$tri\\*" -Recurse | Remove-Item -Force -Recurse
Remove-Item "$dst\$tri"

Write-Host "`nScript completed! / Skript abgeschlossen!" -ForegroundColor yellow -BackgroundColor black


