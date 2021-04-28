
function Copy-ADGroupFromMirror {
    param (
        $OptionalParameters
    )
    
    $MirrorId = Read-Host -Prompt 'Digite o DE espelho: '
    $DesiredId = Read-Host -Prompt 'Digite o DE de destino: '

    $reference = Get-ADUser -Identity $MirrorId -Properties MemberOf 
    $groups = $reference.MemberOf
    $groups | Add-ADGroupMember -Members $DesiredId
}

Copy-ADGroupFromMirror

function Initialize-MainPrograms {
    Invoke-Item -Path "C:\Users\de0186679\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Avaya\Avaya Aura Agent Desktop 6.0.appref-ms"
    Invoke-Item -Path "C:\Program Files (x86)\Avaya\Avaya Communicator\AvayaCommunicator.exe"
    Invoke-Item -Path "C:\Program Files\Google\Chrome\Application\chrome.exe"
    Invoke-Item -Path "C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe"
    Invoke-Item -Path "C:\Program Files (x86)\TeamViewer\TeamViewer.exe"
    Invoke-Item -Path "C:\windows\system32\dsa.msc"
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
    $users = Get-ADUser -Filter * -SearchBase ""
    $sourceUser = Get-ADUser -Identity user.a -Properties MemberOf
    $sourceGroups = $sourceUser.MemberOf
    
    ForEach($group in $sourceGroups){
        $thisgroup = $group.split(",")
        $thisgroup
    }
}


function hihi{
    $newusers = Get-Content -Path ""
    
    ForEach($newuser in $newusers){
        $path = ""
        $password = Get-Random
        $firstname = $newuser.split(" ")[0]
        $lastname = $newuser.split("")[1]
        $username = "$firstname.$lastname"
        
        New-ADUser -Name "$newuser" -GivenName "$firstname" -Surname "$lastname" -SamAccountName $username -UserPrincipalName $username -AccountPassword $password -Enabled $True
        
    }
}





<#
# Add a parameter called username.
 param (
     $username
 )

 # If the user did not provide a username value, show a message and exit the script.
 if (-not($username)) {
     Write-Host "You did not enter a username. Exiting script"
     return $null
 }

 # Check if the user exists or if the username is valid. Do not show the result on the screen.
 try {
     $null = Get-ADUser -Identity $username -ErrorAction Stop
 }
 # If the username cannot be found, show a message and exit the script.
 catch {
     Write-Host $_.Exception.Message
     return $null
 }
 
 # Generate a random password that is 12-characters long with five non-AlphaNumeric characters.
 $randomPassword = [System.Web.Security.Membership]::GeneratePassword(12, 5)
 
 # Convert the plain text password to a secure string.
 $newPassword = $randomPassword | ConvertTo-SecureString -AsPlainText -Force
 
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

@('user_a','user_b') | ForEach-Object {.\Reset-ADUserPassword.ps1 -username $PSItem}

Get-Content .\users.txt | ForEach-Object {.\Reset-ADUserPassword.ps1 -username $PSItem}

#>
