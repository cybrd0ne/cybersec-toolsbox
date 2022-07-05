# Config
$logFileName = "Security" # Add Name of the Logfile (System, Application, etc)
$path = "C:\nttirt\" # Add Path, needs to end with a backsplash

# do not edit
$exportFileName = $logFileName + (get-date -f yyyyMMdd) + ".evt"
$logFile = Get-WmiObject Win32_NTEventlogFile | Where-Object {$_.logfilename -eq $logFileName}
$logFile.backupeventlog($path + $exportFileName)
