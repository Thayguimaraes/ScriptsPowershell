
function Copy-ADGroupFromMirror {
    param ()
    Set-ExecutionPolicy Unrestricted

    $MirrorId = Read-Host -Prompt 'Digite o DE espelho: '
    $DesiredId = Read-Host -Prompt 'Digite o DE de destino: '

    $reference = Get-ADUser -Identity $MirrorId -Properties MemberOf
    $groups = $reference.MemberOf
    $groups | Add-ADGroupMember -Members $DesiredId
}

Copy-ADGroupFromMirror

$reference =  Get-ADUser -Identity DE6400256 -Properties MemberOf
$groups = $reference.MemberOf

$separate = $groups | Select-String -Pattern "SafeDoc_431"
# $separate | Add-ADGroupMember -Members DE8900060

[AD]$groups.GetType()

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
    param ()

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
                   -AccountPassword $password
        
        
        $password -Enabled $True

    }
}

function Connect-office365{
    $credential = Get-Credential
    $urlOutlook = "https://ps.outlook.com/powershell"=

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
    param ()

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
                  ForEach {Remove-Item $_.FullName -Recurse -Force}
    
    

    ## Remove every user's cache. This reads all subdirectories in the $env:APPDATA\Microsoft\Teams folder matching
    ## all folder names in the cache and removes them all
    Get-ChildItem -Path "$env:APPDATA\Microsoft\Teams\*" `
                  -Directory | `
                  Where-Object Name -in ('application cache','blob storage','databases','GPUcache','IndexedDB','Local Storage','tmp') | `
                  ForEach {Remove-Item $_.FullName -Recurse -Force}
}

function download{
    $dest = "http://resources.kodakalaris.com/docimaging/drivers/ST_i900_v1.8.52.exe"
    $proxy = ([System.Net.WebRequest]::GetSystemWebproxy()).GetProxy($dest)
    Invoke-WebRequest http://resources.kodakalaris.com/docimaging/drivers/ST_i900_v1.8.52.exe `
                      -Proxy $proxy `
                      -ProxyUseDefaultCredentials
}

<#
 Convert the plain text password to a secure strsword | ConvertTo-SecureString -AsPlainText -Force
 ing.

@('user_a','user_b') | ForEach-Object {.\Reset-ADUserPassword.ps1 -username $PSItem}

Get-Content .\users.txt | ForEach-Object {.\Reset-ADUserPassword.ps1 -username $PSItem}


Get-DnsClientCache
Get-DnsClient

Start-Process powershell.exe -Credential $Credential -ArgumentList ("-file $args")
#>
