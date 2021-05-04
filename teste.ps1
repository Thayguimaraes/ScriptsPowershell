

    $MirrorId = Read-Host -Prompt 'Digite o DE espelho: '
    $DesiredId = Read-Host -Prompt 'Digite o DE de destino: '

    $reference = Get-ADUser -Identity $MirrorId -Properties MemberOf 
    $groups = $reference.MemberOf
    $groups | Add-ADGroupMember -Members $DesiredId