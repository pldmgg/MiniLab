$DomainToJoin = "beta.lab"
# Make sure we can resolve the domain
if (![bool]$(Resolve-DNSName "beta.lab")) {
    Write-Error "Unable to resolve '$DomainToJoin'! Halting!"
    $global:FunctionResult = "1"
    return
}

# Join Domain
$InvokeParallelUrl = "https://raw.githubusercontent.com/RamblingCookieMonster/Invoke-Parallel/master/Invoke-Parallel/Invoke-Parallel.ps1"
Invoke-Expression $([System.Net.WebClient]::new().DownloadString($InvokeParallelUrl))
$VagrantVMPassword = ConvertTo-SecureString 'vagrant' -AsPlainText -Force
$VagrantVMAdminCreds = [pscredential]::new("vagrant",$VagrantVMPassword)
$DomainAdminPassword = ConvertTo-SecureString 'Unsecure321!' -AsPlainText -Force
$DomainAdminCreds = [pscredential]::new("beta\betaadmin",$DomainAdminPassword)
[System.Collections.ArrayList]$CAServerInfo = @(
    [pscustomobject]@{
        HostName    = "BetaRootCA"
        IPAddress   = "192.168.2.37"
    }
    [pscustomobject]@{
        HostName    = "BetaSubCA"
        IPAddress   = "192.168.2.40"
    }
)

 # Make sure WinRM in Enabled and Running on $env:ComputerName
 try {
    $null = Enable-PSRemoting -Force -ErrorAction Stop
}
catch {
    $null = Get-NetConnectionProfile | Where-Object {$_.NetworkCategory -eq 'Public'} | Set-NetConnectionProfile -NetworkCategory 'Private'

    try {
        $null = Enable-PSRemoting -Force
    }
    catch {
        Write-Error $_
        Write-Error "Problem with Enabble-PSRemoting WinRM Quick Config! Halting!"
        $global:FunctionResult = "1"
        return
    }
}

# If $env:ComputerName is not part of a Domain, we need to add this registry entry to make sure WinRM works as expected
if (!$(Get-CimInstance Win32_Computersystem).PartOfDomain) {
    $null = reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
}

# Add the New Server's IP Addresses to $env:ComputerName's TrustedHosts
$CurrentTrustedHosts = $(Get-Item WSMan:\localhost\Client\TrustedHosts).Value
[System.Collections.ArrayList][array]$CurrentTrustedHostsAsArray = $CurrentTrustedHosts -split ','

$IPsToAddToWSMANTrustedHosts = $CAServerInfo.IPAddress
foreach ($IPAddr in $IPsToAddToWSMANTrustedHosts) {
    if ($CurrentTrustedHostsAsArray -notcontains $IPAddr) {
        $null = $CurrentTrustedHostsAsArray.Add($IPAddr)
    }
}
$UpdatedTrustedHostsString = $CurrentTrustedHostsAsArray -join ','
Set-Item WSMan:\localhost\Client\TrustedHosts $UpdatedTrustedHostsString -Force

$CAServerInfo | Invoke-Parallel {
    $PSObj = $_
    $DomainToJoin = $using:DomainToJoin
    $VagrantVMAdminCreds = $using:VagrantVMAdminCreds
    $DomainAdminCreds = $using:DomainAdminCreds

    New-PSSession -ComputerName $PSObj.IPAddress -Credential $VagrantVMAdminCreds -Name "To$($PSObj.Hostname)"

    $RenameComputerSB = {
        Rename-Computer -NewName $args[0] -LocalCredential $args[1] -Force -Restart -ErrorAction SilentlyContinue
    }
    $InvCmdRenameComputerSplatParams = @{
        Session         = Get-PSSession -Name "To$($PSObj.Hostname)"
        ScriptBlock     = $RenameComputerSB
        ArgumentList    = $PSObj.HostName,$VagrantVMAdminCreds
        ErrorAction     = "SilentlyContinue"
    }
    Invoke-Command @InvCmdRenameComputerSplatParams
}
Write-Host "Sleeping for 5 minutes to give the Servers a chance to restart after name change..."
Start-Sleep -Seconds 300
Write-Host "Joining Servers to Domain..."
$CAServerInfo | Invoke-Parallel {
    $PSObj = $_
    $DomainToJoin = $using:DomainToJoin
    $VagrantVMAdminCreds = $using:VagrantVMAdminCreds
    $DomainAdminCreds = $using:DomainAdminCreds

    # Waiting for maximum of 15 minutes for the CA Servers to accept new PSSessions Post Name Change Reboot...
    $Counter = 0
    while (![bool]$(Get-PSSession -Name "To$($PSObj.Hostname)" -ErrorAction SilentlyContinue)) {
        try {
            New-PSSession -ComputerName $PSObj.IPAddress -Credential $VagrantVMAdminCreds -Name "To$($PSObj.Hostname)" -ErrorAction SilentlyContinue
            if (![bool]$(Get-PSSession -Name "To$($PSObj.Hostname)" -ErrorAction SilentlyContinue)) {throw}
        }
        catch {
            if ($Counter -le 60) {
                Write-Warning "New-PSSession 'To$($PSObj.Hostname)' failed. Trying again in 15 seconds..."
                Start-Sleep -Seconds 15
            }
            else {
                Write-Error "Unable to create new PSSession to 'To$($PSObj.Hostname)' using Local Admin account '$($VagrantVMAdminCreds.UsersName)'! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        $Counter++
    }
    
    $JoinDomainSB = {
        # Make sure time is synchronized with NTP Servers/Domain Controllers (i.e. might be using NT5DS instead of NTP)
        # See: https://giritharan.com/time-synchronization-in-active-directory-domain/
        $null = W32tm /config /update /manualpeerlist:”0.pool.ntp.org,1.pool.ntp.org,2.pool.ntp.org” /syncfromflags:manual /reliable:yes
        $null = W32tm /resync /rediscover /nowait
        
        Add-Computer -ComputerName $args[0] -DomainName $args[1] -Credential $args[2] -Restart -Force
    }
    $InvCmdJoinDomainSplatParams = @{
        Session         = Get-PSSession -Name "To$($PSObj.Hostname)"
        ScriptBlock     = $JoinDomainSB
        ArgumentList    = $PSObj.HostName,$DomainToJoin,$DomainAdminCreds
    }
    try {
        Invoke-Command @InvCmdJoinDomainSplatParams
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }
}

if (!$?) {
    $global:FunctionResult = "1"
    return
}

Write-Host "Sleeping for 5 minutes to give the Servers a chance to restart after Domain Change..."
Start-Sleep -Seconds 300
$CAServerInfo | Invoke-Parallel {
    $PSObj = $_
    $DomainToJoin = $using:DomainToJoin
    $VagrantVMAdminCreds = $using:VagrantVMAdminCreds
    $DomainAdminCreds = $using:DomainAdminCreds

    # Waiting for maximum of 15 minutes for the CA Servers to accept new PSSessions Post Name Change Reboot...
    $Counter = 0
    while (![bool]$(Get-PSSession -Name "To$($PSObj.Hostname)" -ErrorAction SilentlyContinue)) {
        try {
            New-PSSession -ComputerName $PSObj.IPAddress -Credential $VagrantVMAdminCreds -Name "To$($PSObj.Hostname)" -ErrorAction SilentlyContinue
            if (![bool]$(Get-PSSession -Name "To$($PSObj.Hostname)" -ErrorAction SilentlyContinue)) {throw}
        }
        catch {
            if ($Counter -le 60) {
                Write-Warning "New-PSSession 'To$($PSObj.Hostname)' failed. Trying again in 15 seconds..."
                Start-Sleep -Seconds 15
            }
            else {
                Write-Error "Unable to create new PSSession to 'To$($PSObj.Hostname)' using Local Admin account '$($VagrantVMAdminCreds.UsersName)'! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        $Counter++
    }
}
Get-PSSession | Remove-PSSession
New-PSSession -ComputerName "192.168.2.37" -Credential $DomainAdminCreds -Name "ToRootCA"
New-PSSession -ComputerName "192.168.2.40" -Credential $DomainAdminCreds -Name "ToSubCA"





# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUADWTNVKD70XFmA4vTg6n83+k
# /a2gggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
# 9w0BAQsFADAwMQwwCgYDVQQGEwNMQUIxDTALBgNVBAoTBFpFUk8xETAPBgNVBAMT
# CFplcm9EQzAxMB4XDTE3MDkyMDIxMDM1OFoXDTE5MDkyMDIxMTM1OFowPTETMBEG
# CgmSJomT8ixkARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMT
# B1plcm9TQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCwqv+ROc1
# bpJmKx+8rPUUfT3kPSUYeDxY8GXU2RrWcL5TSZ6AVJsvNpj+7d94OEmPZate7h4d
# gJnhCSyh2/3v0BHBdgPzLcveLpxPiSWpTnqSWlLUW2NMFRRojZRscdA+e+9QotOB
# aZmnLDrlePQe5W7S1CxbVu+W0H5/ukte5h6gsKa0ktNJ6X9nOPiGBMn1LcZV/Ksl
# lUyuTc7KKYydYjbSSv2rQ4qmZCQHqxyNWVub1IiEP7ClqCYqeCdsTtfw4Y3WKxDI
# JaPmWzlHNs0nkEjvnAJhsRdLFbvY5C2KJIenxR0gA79U8Xd6+cZanrBUNbUC8GCN
# wYkYp4A4Jx+9AgMBAAGjggEqMIIBJjASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsG
# AQQBgjcVAgQWBBQ/0jsn2LS8aZiDw0omqt9+KWpj3DAdBgNVHQ4EFgQUicLX4r2C
# Kn0Zf5NYut8n7bkyhf4wGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwDgYDVR0P
# AQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUdpW6phL2RQNF
# 7AZBgQV4tgr7OE0wMQYDVR0fBCowKDAmoCSgIoYgaHR0cDovL3BraS9jZXJ0ZGF0
# YS9aZXJvREMwMS5jcmwwPAYIKwYBBQUHAQEEMDAuMCwGCCsGAQUFBzAChiBodHRw
# Oi8vcGtpL2NlcnRkYXRhL1plcm9EQzAxLmNydDANBgkqhkiG9w0BAQsFAAOCAQEA
# tyX7aHk8vUM2WTQKINtrHKJJi29HaxhPaHrNZ0c32H70YZoFFaryM0GMowEaDbj0
# a3ShBuQWfW7bD7Z4DmNc5Q6cp7JeDKSZHwe5JWFGrl7DlSFSab/+a0GQgtG05dXW
# YVQsrwgfTDRXkmpLQxvSxAbxKiGrnuS+kaYmzRVDYWSZHwHFNgxeZ/La9/8FdCir
# MXdJEAGzG+9TwO9JvJSyoGTzu7n93IQp6QteRlaYVemd5/fYqBhtskk1zDiv9edk
# mHHpRWf9Xo94ZPEy7BqmDuixm4LdmmzIcFWqGGMo51hvzz0EaE8K5HuNvNaUB/hq
# MTOIB5145K8bFOoKHO4LkTCCBc8wggS3oAMCAQICE1gAAAH5oOvjAv3166MAAQAA
# AfkwDQYJKoZIhvcNAQELBQAwPTETMBEGCgmSJomT8ixkARkWA0xBQjEUMBIGCgmS
# JomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EwHhcNMTcwOTIwMjE0MTIy
# WhcNMTkwOTIwMjExMzU4WjBpMQswCQYDVQQGEwJVUzELMAkGA1UECBMCUEExFTAT
# BgNVBAcTDFBoaWxhZGVscGhpYTEVMBMGA1UEChMMRGlNYWdnaW8gSW5jMQswCQYD
# VQQLEwJJVDESMBAGA1UEAxMJWmVyb0NvZGUyMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAxX0+4yas6xfiaNVVVZJB2aRK+gS3iEMLx8wMF3kLJYLJyR+l
# rcGF/x3gMxcvkKJQouLuChjh2+i7Ra1aO37ch3X3KDMZIoWrSzbbvqdBlwax7Gsm
# BdLH9HZimSMCVgux0IfkClvnOlrc7Wpv1jqgvseRku5YKnNm1JD+91JDp/hBWRxR
# 3Qg2OR667FJd1Q/5FWwAdrzoQbFUuvAyeVl7TNW0n1XUHRgq9+ZYawb+fxl1ruTj
# 3MoktaLVzFKWqeHPKvgUTTnXvEbLh9RzX1eApZfTJmnUjBcl1tCQbSzLYkfJlJO6
# eRUHZwojUK+TkidfklU2SpgvyJm2DhCtssFWiQIDAQABo4ICmjCCApYwDgYDVR0P
# AQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBS5d2bhatXq
# eUDFo9KltQWHthbPKzAfBgNVHSMEGDAWgBSJwtfivYIqfRl/k1i63yftuTKF/jCB
# 6QYDVR0fBIHhMIHeMIHboIHYoIHVhoGubGRhcDovLy9DTj1aZXJvU0NBKDEpLENO
# PVplcm9TQ0EsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
# cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y2VydGlmaWNh
# dGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlv
# blBvaW50hiJodHRwOi8vcGtpL2NlcnRkYXRhL1plcm9TQ0EoMSkuY3JsMIHmBggr
# BgEFBQcBAQSB2TCB1jCBowYIKwYBBQUHMAKGgZZsZGFwOi8vL0NOPVplcm9TQ0Es
# Q049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO
# PUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y0FDZXJ0aWZpY2F0ZT9iYXNl
# P29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwLgYIKwYBBQUHMAKG
# Imh0dHA6Ly9wa2kvY2VydGRhdGEvWmVyb1NDQSgxKS5jcnQwPQYJKwYBBAGCNxUH
# BDAwLgYmKwYBBAGCNxUIg7j0P4Sb8nmD8Y84g7C3MobRzXiBJ6HzzB+P2VUCAWQC
# AQUwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcDAzANBgkqhkiG9w0BAQsFAAOC
# AQEAszRRF+YTPhd9UbkJZy/pZQIqTjpXLpbhxWzs1ECTwtIbJPiI4dhAVAjrzkGj
# DyXYWmpnNsyk19qE82AX75G9FLESfHbtesUXnrhbnsov4/D/qmXk/1KD9CE0lQHF
# Lu2DvOsdf2mp2pjdeBgKMRuy4cZ0VCc/myO7uy7dq0CvVdXRsQC6Fqtr7yob9NbE
# OdUYDBAGrt5ZAkw5YeL8H9E3JLGXtE7ir3ksT6Ki1mont2epJfHkO5JkmOI6XVtg
# anuOGbo62885BOiXLu5+H2Fg+8ueTP40zFhfLh3e3Kj6Lm/NdovqqTBAsk04tFW9
# Hp4gWfVc0gTDwok3rHOrfIY35TGCAfUwggHxAgEBMFQwPTETMBEGCgmSJomT8ixk
# ARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EC
# E1gAAAH5oOvjAv3166MAAQAAAfkwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwx
# CjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFASU/SPHio1vHAP/
# tcPgEOLQi3BNMA0GCSqGSIb3DQEBAQUABIIBAK/4uScGGiTE1gFuX4hIRvCR2I4b
# xjiulZeob5b/7gzFPE2BAdcLaWLMZwKQdegG9OI/UQNbzATJa5TTGv0aKMnnmES1
# a1l7xkAdzyOiX8czcpKy1UNdshJCgFDF+lesNFqrHE2lvnsSAWLheZYkLucQZWuz
# HLPYAvIA9Dy1YsHwewvhfiV52tnJi3OZmGOR8i62tZS0JfZwAnBhjmZHSYAgGXkB
# hFmW5LSuwi8AhLuPdKu6TX9XqZ0pBRtKzCZHX7K59cK+IZeabAUsH1jIZEremZn/
# XPfQczfU/D7Nds7d74DMks67rQsOiPaVjiEPzirYgATXtOQJveA9nS/+uX8=
# SIG # End signature block
