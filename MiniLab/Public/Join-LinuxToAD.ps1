<#
    .SYNOPSIS
        This function joins a Linux machine to a Windows Active Directory Domain.

        Currently, this function only supports RedHat/CentOS.

        Most of this function is from:

        https://winsysblog.com/2018/01/join-linux-active-directory-powershell-core.html

    .DESCRIPTION
        See .SYNOPSIS

    .PARAMETER DomainName
        This parameter is MANDATORY.

        This parameter takes a string that represents Active Directory Domain that you would like to join.

    .PARAMETER DomainCreds
        This parameter is MANDATORY.

        This parameter takes a pscredential object that represents a UserName and Password that can join
        a host to teh Active Directory Domain.

    .EXAMPLE
        # Open an elevated PowerShell Core (pwsh) session on a Linux, import the module, and -

        [CentOS7Host] # sudo pwsh

        PS /home/testadmin> $DomainCreds = [pscredential]::new("zero\zeroadmin",$(Read-Host "Enter Password" -AsSecureString))
        PS /home/testadmin> Join-LinuxToAD -DomainName "zero.lab" -DomainCreds $DomainCreds
#>
function Join-LinuxToAD {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [string]$DomainName,

        [Parameter(Mandatory=$True)]
        [pscredential]$DomainCreds
    )

    if (!$(GetElevation)) {
        Write-Error "You must run the $($MyInvocation.MyCommand.Name) function with elevated permissions! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$IsLinux) {
        Write-Error "This host is not Linux. Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (![bool]$($PSVersionTable.OS -match 'RedHat|CentOS|\.el[0-9]\.')) {
        Write-Error "Currently, the $(MyInvocation.MyCommand.Name) function only works on RedHat/CentOS Linux Distros! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Make sure nslookup is installed
    which nslookup *>/dev/null
    if ($LASTEXITCODE -ne 0) {
        $null = yum install bind-utils -y
    }

    # Ensure you can lookup AD DNS
    $null = nslookup $DomainName
    if ($LASTEXITCODE -ne 0) {
        Write-Error 'Could not find domain in DNS. Checking settings'
        $global:FunctionResult = "1"
        return
    }

    #Ensure Samba and dependencies installed
    $DependenciesToInstall = @(
        "sssd"
        "realmd"
        "oddjob"
        "oddjob-mkhomedir"
        "adcli"
        "samba-common"
        "samba-common-tools"
        "krb5-workstation"
        "openldap-clients"
        "policycoreutils-python"
    )

    [System.Collections.ArrayList]$SuccessfullyInstalledDependencies = @()
    [System.Collections.ArrayList]$FailedInstalledDependencies = @()
    foreach ($Dependency in $DependenciesToInstall) {
        $null = yum install $Dependency -y

        if ($LASTEXITCODE -ne 0) {
            $null = $FailedInstalledDependencies.Add($Dependency)
        }
        else {
            $null = $SuccessfullyInstalledDependencies.Add($Dependency)
        }
    }

    if ($FailedInstalledDependencies.Count -gt 0) {
        Write-Error "Failed to install the following dependencies:`n$($FailedInstalledDependencies -join "`n")`nHalting!"
        $global:FunctionResult = "1"
        return
    }

    # Join domain with realm
    $DomainUserName = $DomainCreds.UserName
    if ($DomainUserName -match "\\") {$DomainUserName = $($DomainUserName -split "\\")[-1]}
    $PTPasswd = $DomainCreds.GetNetworkCredential().Password
    printf "$PTPasswd" | realm join $DomainName --user=$DomainUserName

    if ($LASTEXITCODE -ne 0) {
        Write-Error -Message "Could not join domain $DomainName. See error output"
        exit
    }
    if ($LASTEXITCODE -eq 0) {
        Write-Output 'Success'
    }
}

# SIG # Begin signature block
# MIIMaAYJKoZIhvcNAQcCoIIMWTCCDFUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUSNypzR2SeG2dXKXQU9RDtlQu
# JvegggndMIIEJjCCAw6gAwIBAgITawAAADqEP46TDmc/hQAAAAAAOjANBgkqhkiG
# 9w0BAQsFADAwMQwwCgYDVQQGEwNMQUIxDTALBgNVBAoTBFpFUk8xETAPBgNVBAMT
# CFplcm9EQzAxMB4XDTE4MTAxNzIwMTEyNVoXDTIwMTAxNzIwMjEyNVowPTETMBEG
# CgmSJomT8ixkARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMT
# B1plcm9TQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0crvKbqlk
# 77HGtaVMWpZBOKwb9eSHzZjh5JcfMJ33A9ORwelTAzpRP+N0k/rAoQkauh3qdeQI
# fsqdcrEiingjiOvxaX3lHA5+fVGe/gAnZ+Cc7iPKXJVhw8jysCCld5zIG8x8eHuV
# Z540iNXdI+g2mustl+l5q4kcWukj+iQwtCYEaCgAXB9qlkT33sX0k/07JoSYcGJx
# ++0SHnF0HBw7Gs/lHlyt4biIGtJleOw0iIN2yVD9UrVWMtKrghKPaW31mjYYeN5k
# ckYzBit/Kokxo0m54B4M3aLRPBQdXH1wL6A894BAlUlPM7vrozU2cLrZgcFuEvwM
# 0cLN8mfGKbo5AgMBAAGjggEqMIIBJjASBgkrBgEEAYI3FQEEBQIDAgACMCMGCSsG
# AQQBgjcVAgQWBBTlQTDY2HBi1snaI36s8nvJLv5ZGDAdBgNVHQ4EFgQUkNLPVlgd
# vV0pNGjQxY8gU/mxzMIwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwDgYDVR0P
# AQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUdpW6phL2RQNF
# 7AZBgQV4tgr7OE0wMQYDVR0fBCowKDAmoCSgIoYgaHR0cDovL3BraS9jZXJ0ZGF0
# YS9aZXJvREMwMS5jcmwwPAYIKwYBBQUHAQEEMDAuMCwGCCsGAQUFBzAChiBodHRw
# Oi8vcGtpL2NlcnRkYXRhL1plcm9EQzAxLmNydDANBgkqhkiG9w0BAQsFAAOCAQEA
# fgu+F49OeWIQAUO9nUN5bYBtmBwU1YOL1X1OtmFPRkwBm4zE+rjMtWOO5MU4Huv3
# f3y2K0BhVWfu12N9nOZW1kO+ENgxwz5rjwR/VtxJzopO5EALJZwwDoOqfQUDgqRN
# xyRh8qX1CM/mPpu9xPi/FeA+3xCd0goKGVRPQD9NBq24ktb9iGWu/vNb5ovGXsU5
# JzDz4drIHrnEy2SM7g9YdRo/IvshBvrQdYKiNIMeB0WxCsUAjqu/J42Nc9LGQcRj
# jJSK4baX1eotcBpy/XjVC0lHhOI+BdirfVRGvTjax7KqJWSem0ccxaw30e3jRQJE
# wnslUecNTfz07DkopxjrxDCCBa8wggSXoAMCAQICE1gAAAJQw22Yn6op/pMAAwAA
# AlAwDQYJKoZIhvcNAQELBQAwPTETMBEGCgmSJomT8ixkARkWA0xBQjEUMBIGCgmS
# JomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EwHhcNMTkxMTI4MTI1MDM2
# WhcNMjExMTI3MTI1MDM2WjBJMUcwRQYDVQQDEz5aZXJvQ29kZTEzLE9VPURldk9w
# cyxPPVRlY2ggVGFyZ2V0cywgTExDLEw9QnJ5biBNYXdyLFM9UEEsQz1VUzCCASIw
# DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPYULq1HCD/SgqTajXuWjnzVedBE
# Nc3LQwdDFmOLyrVPi9S9FF3yYDCTywA6wwgxSQGhI8MVWwF2Xdm+e6pLX+957Usk
# /lZGHCNwOMP//vodJUhxcyDZG7sgjjz+3qBl0OhUodZfqlprcVMQERxlIK4djDoP
# HhIBHBm6MZyC9oiExqytXDqbns4B1MHMMHJbCBT7KZpouonHBK4p5ObANhGL6oh5
# GnUzZ+jOTSK4DdtulWsvFTBpfz+JVw/e3IHKqHnUD4tA2CxxA8ofW2g+TkV+/lPE
# 9IryeA6PrAy/otg0MfVPC2FKaHzkaaMocnEBy5ZutpLncwbwqA3NzerGmiMCAwEA
# AaOCApowggKWMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUW0DvcuEW1X6BD+eQ
# 2AJHO2eur9UwHwYDVR0jBBgwFoAUkNLPVlgdvV0pNGjQxY8gU/mxzMIwgekGA1Ud
# HwSB4TCB3jCB26CB2KCB1YaBrmxkYXA6Ly8vQ049WmVyb1NDQSgyKSxDTj1aZXJv
# U0NBLENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNl
# cyxDTj1Db25maWd1cmF0aW9uLERDPXplcm8sREM9bGFiP2NlcnRpZmljYXRlUmV2
# b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2lu
# dIYiaHR0cDovL3BraS9jZXJ0ZGF0YS9aZXJvU0NBKDIpLmNybDCB5gYIKwYBBQUH
# AQEEgdkwgdYwgaMGCCsGAQUFBzAChoGWbGRhcDovLy9DTj1aZXJvU0NBLENOPUFJ
# QSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25m
# aWd1cmF0aW9uLERDPXplcm8sREM9bGFiP2NBQ2VydGlmaWNhdGU/YmFzZT9vYmpl
# Y3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MC4GCCsGAQUFBzAChiJodHRw
# Oi8vcGtpL2NlcnRkYXRhL1plcm9TQ0EoMykuY3J0MD0GCSsGAQQBgjcVBwQwMC4G
# JisGAQQBgjcVCIO49D+Em/J5g/GPOIOwtzKG0c14gSeh88wfj9lVAgFkAgEFMBMG
# A1UdJQQMMAoGCCsGAQUFBwMDMBsGCSsGAQQBgjcVCgQOMAwwCgYIKwYBBQUHAwMw
# DQYJKoZIhvcNAQELBQADggEBAEfjH/emq+TnlhFss6cNor/VYKPoEeqYgFwzGbul
# dzPdPEBFUNxcreN0b61kxfenAHifvI0LCr/jDa8zGPEOvo8+zB/GWp1Huw/xLMB8
# rfZHBCox3Av0ohjzO5Ac5yCHijZmrwaXV3XKpBncWdC6pfr/O0bIoRMbvV9EWkYG
# fpNaFvR8piUGJ47cLlC+NFTOQcmESOmlsy+v8JeG9OPsnvZLsD6sydajrxRnNlSm
# zbK64OrbSM9gQoA6bjuZ6lJWECCX1fEYDBeZaFrtMB/RTVQLF/btisfDQXgZJ+Tw
# Tjy+YP39D0fwWRfAPSRJ8NcnRw4Ccj3ngHz7e0wR6niCtsMxggH1MIIB8QIBATBU
# MD0xEzARBgoJkiaJk/IsZAEZFgNMQUIxFDASBgoJkiaJk/IsZAEZFgRaRVJPMRAw
# DgYDVQQDEwdaZXJvU0NBAhNYAAACUMNtmJ+qKf6TAAMAAAJQMAkGBSsOAwIaBQCg
# eDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEE
# AYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJ
# BDEWBBT5ls6Vf9b1SCFyQSf8Q9ZZDxEJiDANBgkqhkiG9w0BAQEFAASCAQDQ8sgD
# UFMLzOFsk+h8LYHkEKFm+RHwKQMhSa4gH/nsUHwjOUI99fr0mt7l6Rt616DtrafT
# TVTQux1a/a31iyfPQ7OIqlJiwN9o4X3kjdKrsGwnPx7Wz4GJPaFtHuCcUrnyJDur
# BG8aTwZyeE8+q7y87U0stkY5NwszecE2NnNu04iqtkhtEJUjNeV++rwoPNZVr3Qt
# v6UIz4DQQ+xRa37kEhw6Q1XLQr0NRLzrmOS5s4lvSdAEEb8d+Sn6P2G/8/G9Ftqo
# y6c4U7Z6KKyriBugJhvlbqbMkTDDOmJM7ceDnj6NDSZgT+ivxXkIcMs54rGxTkSq
# /vtl6f9AcVjWxE8u
# SIG # End signature block
