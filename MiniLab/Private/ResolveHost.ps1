function ResolveHost {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$HostNameOrIP
    )

    ##### BEGIN Main Body #####

    $RemoteHostNetworkInfoArray = @()
    if (!$(TestIsValidIPAddress -IPAddress $HostNameOrIP)) {
        try {
            $HostNamePrep = $HostNameOrIP
            [System.Collections.ArrayList]$RemoteHostArrayOfIPAddresses = @()
            $IPv4AddressFamily = "InterNetwork"
            $IPv6AddressFamily = "InterNetworkV6"

            $ResolutionInfo = [System.Net.Dns]::GetHostEntry($HostNamePrep)
            $ResolutionInfo.AddressList | Where-Object {
                $_.AddressFamily -eq $IPv4AddressFamily
            } | foreach {
                if ($RemoteHostArrayOfIPAddresses -notcontains $_.IPAddressToString) {
                    $null = $RemoteHostArrayOfIPAddresses.Add($_.IPAddressToString)
                }
            }
        }
        catch {
            Write-Verbose "Unable to resolve $HostNameOrIP when treated as a Host Name (as opposed to IP Address)!"
        }
    }
    if (TestIsValidIPAddress -IPAddress $HostNameOrIP) {
        try {
            $HostIPPrep = $HostNameOrIP
            [System.Collections.ArrayList]$RemoteHostArrayOfIPAddresses = @()
            $null = $RemoteHostArrayOfIPAddresses.Add($HostIPPrep)

            $ResolutionInfo = [System.Net.Dns]::GetHostEntry($HostIPPrep)

            [System.Collections.ArrayList]$RemoteHostFQDNs = @() 
            $null = $RemoteHostFQDNs.Add($ResolutionInfo.HostName)
        }
        catch {
            Write-Verbose "Unable to resolve $HostNameOrIP when treated as an IP Address (as opposed to Host Name)!"
        }
    }

    if ($RemoteHostArrayOfIPAddresses.Count -eq 0) {
        Write-Error "Unable to determine IP Address of $HostNameOrIP! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # At this point, we have $RemoteHostArrayOfIPAddresses...
    [System.Collections.ArrayList]$RemoteHostFQDNs = @()
    foreach ($HostIP in $RemoteHostArrayOfIPAddresses) {
        try {
            $FQDNPrep = [System.Net.Dns]::GetHostEntry($HostIP).HostName
        }
        catch {
            Write-Verbose "Unable to resolve $HostIP. No PTR Record? Please check your DNS config."
            continue
        }
        if ($RemoteHostFQDNs -notcontains $FQDNPrep) {
            $null = $RemoteHostFQDNs.Add($FQDNPrep)
        }
    }

    if ($RemoteHostFQDNs.Count -eq 0) {
        $null = $RemoteHostFQDNs.Add($ResolutionInfo.HostName)
    }

    [System.Collections.ArrayList]$HostNameList = @()
    [System.Collections.ArrayList]$DomainList = @()
    foreach ($fqdn in $RemoteHostFQDNs) {
        $PeriodCheck = $($fqdn | Select-String -Pattern "\.").Matches.Success
        if ($PeriodCheck) {
            $HostName = $($fqdn -split "\.")[0]
            $Domain = $($fqdn -split "\.")[1..$($($fqdn -split "\.").Count-1)] -join '.'
        }
        else {
            $HostName = $fqdn
            $Domain = "Unknown"
        }

        $null = $HostNameList.Add($HostName)
        $null = $DomainList.Add($Domain)
    }

    if ($RemoteHostFQDNs[0] -eq $null -and $HostNameList[0] -eq $null -and $DomainList -eq "Unknown" -and $RemoteHostArrayOfIPAddresses) {
        [System.Collections.ArrayList]$SuccessfullyPingedIPs = @()
        # Test to see if we can reach the IP Addresses
        foreach ($ip in $RemoteHostArrayOfIPAddresses) {
            if ([bool]$(Test-Connection $ip -Count 1 -ErrorAction SilentlyContinue)) {
                $null = $SuccessfullyPingedIPs.Add($ip)
            }
        }

        if ($SuccessfullyPingedIPs.Count -eq 0) {
            Write-Error "Unable to resolve $HostNameOrIP! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    $FQDNPrep = if ($RemoteHostFQDNs) {$RemoteHostFQDNs[0]} else {$null}
    if ($FQDNPrep -match ',') {
        $FQDN = $($FQDNPrep -split ',')[0]
    }
    else {
        $FQDN = $FQDNPrep
    }

    $DomainPrep = if ($DomainList) {$DomainList[0]} else {$null}
    if ($DomainPrep -match ',') {
        $Domain = $($DomainPrep -split ',')[0]
    }
    else {
        $Domain = $DomainPrep
    }

    [pscustomobject]@{
        IPAddressList   = [System.Collections.ArrayList]@($(if ($SuccessfullyPingedIPs) {$SuccessfullyPingedIPs} else {$RemoteHostArrayOfIPAddresses}))
        FQDN            = $FQDN
        HostName        = if ($HostNameList) {$HostNameList[0].ToLowerInvariant()} else {$null}
        Domain          = $Domain
    }

    ##### END Main Body #####

}

# SIG # Begin signature block
# MIIMaAYJKoZIhvcNAQcCoIIMWTCCDFUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUc6OSN+Fn7QUQGQCFRQBGBUek
# e+qgggndMIIEJjCCAw6gAwIBAgITawAAADqEP46TDmc/hQAAAAAAOjANBgkqhkiG
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
# BDEWBBSREJj7VV/2NQhyXQeqZtYawN3hgDANBgkqhkiG9w0BAQEFAASCAQB7HpU0
# 0umnr+Uwgnx1KM1Gh99g8jCd8m5TbF/YkyCeRRgbSMjHm9qqv+AMEOPMBkqp0XA6
# A7ESfnBEFMzePLlqnslRM/VZc3BdvBhpjcvtmpj7aHf11Qle77njzz0l7QJZZeel
# z44Fb9ZjSBw2rR+agCnIMpbGn+jdFOpz7BAypk/9j2zn78cmr2+jPWj8Y08/oOh4
# nWtMnMYJwg8443z5tYP2z6mO6cQj+kO0DHod/IYtrOrF56vQFvDWvgBBFGIc2fZK
# MIrNE3wMd1ayOPw5xwcmjcXRASuTfF6f+C6QgapYXiWjP710eGIOHca47UrdkcY3
# litwOzCEP6tAR7Lg
# SIG # End signature block
