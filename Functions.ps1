function Get-History{
    [Cmdletbinding()]
    Param([Parameter(Mandatory = $false)] $Search)
    import-module PSSQLite
    $db = "C:\Users\%USERNAME%\AppData\Local\Google\Chrome\User Data\Default\databases "
    
    if($Search){
        Invoke-SQLiteQuery -DataSource $db -Query "SELECT url FROM ******** WHERE url LIKE '%$Search%'" 
    } else {
        Invoke-SQLiteQuery -DataSource $db -Query "SELECT url FROM ********"
    }
}

function Uninstall-Office{
    schtasks.exe /delete /tn "\Microsoft\Office\Office Automatic Updates"
    schtasks.exe /delete /tn "\Microsoft\Office\Office Subscription Maintenance"
    schtasks.exe /delete /tn "\Microsoft\Office\Office ClickToRun Service Monitor"
    schtasks.exe /delete /tn "\Microsoft\Office\OfficeTelemetryAgentLogOn2016"
    schtasks.exe /delete /tn "\Microsoft\Office\OfficeTelemetryAgentFallBack2016"
    
    Get-Process | Where-Object {$_.Name -match "OfficeClickToRun"} | Stop-Process
    Get-Process | Where-Object {$_.Name -match "OfficeC2RClient"} | Stop-Process
    Get-Process | Where-Object {$_.Name -match "AppVShNotify"} | Stop-Process
    Get-Process | Where-Object {$_.Name -match "setup*"} | Stop-Process
    Get-Process | Where-Object {$_.Name -match "outlook"} | Stop-Process
    Get-Process | Where-Object {$_.Name -match "skype"} | Stop-Process
    Get-Process | Where-Object {$_.Name -match "word"} | Stop-Process
    Get-Process | Where-Object {$_.Name -match "PowerPoint"}| Stop-Process
    Get-Process | Where-Object {$_.Name -match "Excel"} | Stop-Process
    
    sc delete ClickToRunSvc
    
    Remove-Item -Recurse -Force "C:/ProgramFiles/Microsoft Office 16"
    Remove-Item -Recurse -Force "C:/ProgramFiles/Microsoft Office"
    Remove-Item -Recurse -Force "C:/ProgramFiles(x86)/Microsoft Office"
    Remove-Item -Recurse -Force "C:/CommonProgramFiles/Microsoft Shared/ClickToRun"
    Remove-Item -Recurse -Force "C:/ProgramData/Microsoft\ClickToRun"
    Remove-Item -Recurse -Force "C:/ProgramData/Microsoft\Office\ClickToRunPackagerLocker"
    
    
    Remove-Item -Path HKLM:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun
    Remove-Item -Path HKLM:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\AppVISV
    Remove-Item -Path HKLM:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Office <Edition> - en-us
    Remove-Item -Path HKLM:HKEY_CURRENT_USER\Software\Microsoft\Office
    
    MsiExec.exe /X{90160000-008F-0000-1000-0000000FF1CE}
    MsiExec.exe /X{90160000-008C-0000-0000-0000000FF1CE}
    MsiExec.exe /X{90160000-008C-0409-0000-0000000FF1CE}
}

function Copy-ADGroupFromMirror {
    Set-ExecutionPolicy Unrestricted

    $MirrorId = Read-Host -Prompt 'Digite o DE espelho: '
    $DesiredId = Read-Host -Prompt 'Digite o DE de destino: '

    $reference = Get-ADUser -Identity $MirrorId -Properties MemberOf
    $groups = $reference.MemberOf
    $groups | Add-ADGroupMember -Members $DesiredId
}

Copy-ADGroupFromMirror

$reference =  Get-ADUser -Identity DE0181955 -Properties MemberOf 
$groups = $reference.MemberOf

$separate = $groups | Select-String -Pattern "N1"
$separate 

| Add-ADGroupMember -Members DE8900060

[AD]$groups.GetType()

$reference = Get-ADUser -Identity DE0181955 -Properties MemberOf | Where-object {$_.MemberOf -like "*N1*"}
$groups = $reference.MemberOf
$separate

function Initialize-MainPrograms {
    Invoke-Item -Path "C:\Users\de0186679\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Avaya\Avaya Aura Agent Desktop 6.0.appref-ms"
    Invoke-Item -Path "C:\Program Files (x86)\Avaya\Avaya Communicator\AvayaCommunicator.exe"
    Invoke-Item -Path "C:\Program Files\Google\Chrome\Application\chrome.exe"
    Invoke-Item -Path "C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe"
    Invoke-Item -Path "C:\Program Files (x86)\TeamViewer\TeamViewer.exe"
    Invoke-Item -Path "C:\windows\system32\dsa.msc"
    Invoke-Item -Path "C:\Program Files (x86)\Microsoft Office\root\Office16\OUTLOOK.EXE"
    C:\Users\de0186679\AppData\Local\Microsoft\Teams\Update.exe --processStart "Teams.exe"
    wt
}

Initialize-MainPrograms


function Close-AllPrograms{
    Stop-Computer -ComputerName localhost
}

Close-AllPrograms


(Get-WmiObject -Namespace root/WMI -Class WmiMonitorBrightnessMethods).WmiSetBrightness(1,100)

function hahah{
    import-module ActiveDirectory
    $users = Get-ADUser -Filter * -SearchBase "1-DEP_COMERCIAL_COMERCIAL-DIRECIONAL-ENGENHARIA-MG_G"
    $sourceUser = Get-ADUser -Identity user.a -Properties MemberOf
    $sourceGroups = $sourceUser.MemberOf

    ForEach($group in $sourceGroups){
        $thisgroup = $group.split(",")
        $thisgroup | Add-ADGroupMember -Members
    }
}

function Add-ADMultipleUsersInAGroup($Path, $Identity){
    $users = Get-Content -Path $Path
    $groups = Get-ADUser -Identity $Identity -Properties MemberOf
    $group = $groups.MemberOf[0]

    ForEach($user in $users){
        Add-ADGroupMember -Members $user -Identity $group
    }
}

Add-ADMultipleUsersInAGroup

function hihi{
    $newusers = Get-Content -Path ""

    ForEach($newuser in $newusers){
        $path = ""
        $password = Get-Random
        $firstname = $newuser.split(" ")[0]
        $lastname = $newuser.split("")[1]
        $username = "$firstname.$lastname"

        New-ADUser -Name "$newuser" `
                   -GivenName "$firstname" `
                   -Surname "$lastname" `
                   -SamAccountName $username `
                   -UserPrincipalName $username `
                   -AccountPassword $password `
                   -Enabled $True

    }
}

function Connect-office365{
    $credential = Get-Credential
    $urlOutlook = "https://ps.outlook.com/powershell"

    $Session = New-PSSession `
            -ConfigurationName Microsoft.Exchange `
            -ConnectionUri  $urlOutlook `
            -Credential $credential `
            -Authentication Basic `
            -AllowRedirection

    Import-module msonline
    Connect-MsolService -Credential $credential
}

function Get-TargetResource ($Path) {
    # TODO: Add parameters here
    # Make sure to use the same parameters for
    # Get-TargetResource, Set-TargetResource, and Test-TargetResource

    Import-Csv -Path $Path | ForEach-Object {
        New-Msoluser -UserPrincipalName $_.UserPrincipalName `
                     -FirstName $_.FirstName `
                     -LastName $_.LastName `
                     -Department $_.Department `
                     -Title $_.Title `
                     -Office $_.Office `
                     -PhoneNumber $_.PhoneNumber `
                     -Fax $_.Fax `
                     -StreetAddress $_.StreetAddress `
                     -MobilePhone $_.MobilePhone `
                     -City $_.City `
                     -State $_.State `
                     -Country $_.Country `
                     -DisplayName $_.DisplayName `
                     -PostalCode $_.PostalCode `
                     -UsageLocation ""
    }
}


function reset-password{
    $newPassword = $randomPas
    # Try to reset the user's password
    try {
        # Reset the user's password
        Set-ADAccountPassword -Identity $username -NewPassword $newPassword -Reset -ErrorAction Stop
        # Force the user to change password during the next log in
        Set-ADuser -Identity $username -ChangePasswordAtLogon $true
        # If the password reset was successfull, return the username and new password.
        [pscustomobject]@{
            Username = $username
            NewPassword = $randomPassword
        }
    }
    # If the password reset failed, show a message and exit the script.
    catch {
        Write-Host "There was an error performing the password reset. Please consult the error below."
        Write-host $_.Exception.Message
        return $null
    }
}


function clear-TeamsCache{
    ## Remove the all users' cache. This reads all user subdirectories in each user folder matching
    ## all folder names in the cache and removes them all
    Get-ChildItem -Path "C:\Users\*\AppData\Roaming\Microsoft\Teams\*" `
                  -Directory | `
                  Where-Object Name -in ('application cache','blob_storage','databases','GPUcache','IndexedDB','Local Storage','tmp') | `
                  ForEach-Object {Remove-Item $_.FullName -Recurse -Force}
    
    

    ## Remove every user's cache. This reads all subdirectories in the $env:APPDATA\Microsoft\Teams folder matching
    ## all folder names in the cache and removes them all
    Get-ChildItem -Path "$env:APPDATA\Microsoft\Teams\*" `
                  -Directory | `
                  Where-Object Name -in ('application cache','blob storage','databases','GPUcache','IndexedDB','Local Storage','tmp') | `
                  ForEach-Object {Remove-Item $_.FullName -Recurse -Force}
}

function download{
    $dest = "https://download-eu.drivers.plus/download/rUjvPcE611qSsAFvWQD-zg/1620217120/9/a/e/0/f/XPSCardPrinter_6.2.456.exe"
    $proxy = ([System.Net.WebRequest]::GetSystemWebproxy()).GetProxy($dest)
    Invoke-WebRequest https://download-eu.drivers.plus/download/rUjvPcE611qSsAFvWQD-zg/1620217120/9/a/e/0/f/XPSCardPrinter_6.2.456.exe `
                      -Proxy $proxy `
                      -ProxyUseDefaultCredentials
}


Get-ADUser -Filter * | Where-Object {$_.SamAccountName -like "tr*"} |Export-Csv C:\Users\de0186679\Desktop\tr.csv

<#
 #   Get-DnsClientCache
 #   Get-DnsClient
 #   Get-WindowsFeature -Name *DNS*
 #   Start-Process powershell.exe -Credential $Credential -ArgumentList ("-file $args")
 #>
