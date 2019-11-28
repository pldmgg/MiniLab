# Example Usage: GetDomainController -Domain $(Get-CimInstance Win32_ComputerSystem).Domain
# If you don't specify -Domain, it defaults to the one you're currently on
function GetDomainController {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$False)]
        [String]$Domain,

        [Parameter(Mandatory=$False)]
        [switch]$UseLogonServer
    )

    ##### BEGIN Helper Functions #####

    function Parse-NLTest {
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$True)]
            [string]$Domain
        )

        while ($Domain -notmatch "\.") {
            Write-Warning "The provided value for the -Domain parameter is not in the correct format. Please use the entire domain name (including periods)."
            $Domain = Read-Host -Prompt "Please enter the full domain name (including periods)"
        }

        if (![bool]$(Get-Command nltest -ErrorAction SilentlyContinue)) {
            Write-Error "Unable to find nltest.exe! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $DomainPrefix = $($Domain -split '\.')[0]
        $PrimaryDomainControllerPrep = Invoke-Expression "nltest /dclist:$DomainPrefix 2>null"
        if (![bool]$($PrimaryDomainControllerPrep | Select-String -Pattern 'PDC')) {
            Write-Error "Can't find the Primary Domain Controller for domain $DomainPrefix"
            return
        }
        $PrimaryDomainControllerPrep = $($($PrimaryDomainControllerPrep -match 'PDC').Trim() -split ' ')[0]
        if ($PrimaryDomainControllerPrep -match '\\\\') {
            $PrimaryDomainController = $($PrimaryDomainControllerPrep -replace '\\\\','').ToLower() + ".$Domain"
        }
        else {
            $PrimaryDomainController = $PrimaryDomainControllerPrep.ToLower() + ".$Domain"
        }

        $PrimaryDomainController
    }

    ##### END Helper Functions #####


    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    $ComputerSystemCim = Get-CimInstance Win32_ComputerSystem
    $PartOfDomain = $ComputerSystemCim.PartOfDomain

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    if (!$PartOfDomain -and !$Domain) {
        Write-Error "$env:ComputerName is NOT part of a Domain and the -Domain parameter was not used in order to specify a domain! Halting!"
        $global:FunctionResult = "1"
        return
    }
    
    $ThisMachinesDomain = $ComputerSystemCim.Domain

    # If we're in a PSSession, [system.directoryservices.activedirectory] won't work due to Double-Hop issue
    # So just get the LogonServer if possible
    if ($Host.Name -eq "ServerRemoteHost" -or $UseLogonServer) {
        if (!$Domain -or $Domain -eq $ThisMachinesDomain) {
            $Counter = 0
            while ([string]::IsNullOrWhitespace($DomainControllerName) -or $Counter -le 20) {
                $DomainControllerName = $(Get-CimInstance win32_ntdomain).DomainControllerName
                if ([string]::IsNullOrWhitespace($DomainControllerName)) {
                    Write-Warning "The win32_ntdomain CimInstance has a null value for the 'DomainControllerName' property! Trying again in 15 seconds (will try for 5 minutes total)..."
                    Start-Sleep -Seconds 15
                }
                $Counter++
            }

            if ([string]::IsNullOrWhitespace($DomainControllerName)) {
                $IPOfDNSServerWhichIsProbablyDC = $(Resolve-DNSName $ThisMachinesDomain).IPAddress
                $DomainControllerFQDN = $(ResolveHost -HostNameOrIP $IPOfDNSServerWhichIsProbablyDC).FQDN
            }
            else {
                $LogonServer = $($DomainControllerName | Where-Object {![string]::IsNullOrWhiteSpace($_)}).Replace('\\','').Trim()
                $DomainControllerFQDN = $LogonServer + '.' + $RelevantSubCANetworkInfo.DomainName
            }

            [pscustomobject]@{
                FoundDomainControllers      = [array]$DomainControllerFQDN
                PrimaryDomainController     = $DomainControllerFQDN
            }

            return
        }
        else {
            Write-Error "Unable to determine Domain Controller(s) network location due to the Double-Hop Authentication issue! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($Domain) {
        try {
            $Forest = [system.directoryservices.activedirectory.Forest]::GetCurrentForest()
        }
        catch {
            Write-Verbose "Cannot connect to current forest."
        }

        if ($ThisMachinesDomain -eq $Domain -and $Forest.Domains -contains $Domain) {
            [System.Collections.ArrayList]$FoundDomainControllers = $Forest.Domains | Where-Object {$_.Name -eq $Domain} | foreach {$_.DomainControllers} | foreach {$_.Name}
            $PrimaryDomainController = $Forest.Domains.PdcRoleOwner.Name
        }
        if ($ThisMachinesDomain -eq $Domain -and $Forest.Domains -notcontains $Domain) {
            try {
                $GetCurrentDomain = [system.directoryservices.activedirectory.domain]::GetCurrentDomain()
                [System.Collections.ArrayList]$FoundDomainControllers = $GetCurrentDomain | foreach {$_.DomainControllers} | foreach {$_.Name}
                $PrimaryDomainController = $GetCurrentDomain.PdcRoleOwner.Name
            }
            catch {
                try {
                    Write-Warning "Only able to report the Primary Domain Controller for $Domain! Other Domain Controllers most likely exist!"
                    Write-Warning "For a more complete list, try running this function on a machine that is part of the domain $Domain!"
                    $PrimaryDomainController = Parse-NLTest -Domain $Domain
                    [System.Collections.ArrayList]$FoundDomainControllers = @($PrimaryDomainController)
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
        if ($ThisMachinesDomain -ne $Domain -and $Forest.Domains -contains $Domain) {
            [System.Collections.ArrayList]$FoundDomainControllers = $Forest.Domains | foreach {$_.DomainControllers} | foreach {$_.Name}
            $PrimaryDomainController = $Forest.Domains.PdcRoleOwner.Name
        }
        if ($ThisMachinesDomain -ne $Domain -and $Forest.Domains -notcontains $Domain) {
            try {
                Write-Warning "Only able to report the Primary Domain Controller for $Domain! Other Domain Controllers most likely exist!"
                Write-Warning "For a more complete list, try running this function on a machine that is part of the domain $Domain!"
                $PrimaryDomainController = Parse-NLTest -Domain $Domain
                [System.Collections.ArrayList]$FoundDomainControllers = @($PrimaryDomainController)
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
    }
    else {
        try {
            $Forest = [system.directoryservices.activedirectory.Forest]::GetCurrentForest()
            [System.Collections.ArrayList]$FoundDomainControllers = $Forest.Domains | foreach {$_.DomainControllers} | foreach {$_.Name}
            $PrimaryDomainController = $Forest.Domains.PdcRoleOwner.Name
        }
        catch {
            Write-Verbose "Cannot connect to current forest."

            try {
                $GetCurrentDomain = [system.directoryservices.activedirectory.domain]::GetCurrentDomain()
                [System.Collections.ArrayList]$FoundDomainControllers = $GetCurrentDomain | foreach {$_.DomainControllers} | foreach {$_.Name}
                $PrimaryDomainController = $GetCurrentDomain.PdcRoleOwner.Name
            }
            catch {
                $Domain = $ThisMachinesDomain

                try {
                    $CurrentUser = "$(whoami)"
                    Write-Warning "Only able to report the Primary Domain Controller for the domain that $env:ComputerName is joined to (i.e. $Domain)! Other Domain Controllers most likely exist!"
                    Write-Host "For a more complete list, try one of the following:" -ForegroundColor Yellow
                    if ($($CurrentUser -split '\\') -eq $env:ComputerName) {
                        Write-Host "- Try logging into $env:ComputerName with a domain account (as opposed to the current local account $CurrentUser" -ForegroundColor Yellow
                    }
                    Write-Host "- Try using the -Domain parameter" -ForegroundColor Yellow
                    Write-Host "- Run this function on a computer that is joined to the Domain you are interested in" -ForegroundColor Yellow
                    $PrimaryDomainController = Parse-NLTest -Domain $Domain
                    [System.Collections.ArrayList]$FoundDomainControllers = @($PrimaryDomainController)
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
    }

    [pscustomobject]@{
        FoundDomainControllers      = $FoundDomainControllers
        PrimaryDomainController     = $PrimaryDomainController
    }

    ##### END Main Body #####
}

# SIG # Begin signature block
# MIIMaAYJKoZIhvcNAQcCoIIMWTCCDFUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU3rJpad0TBijH7oHDRphPukyM
# Zq+gggndMIIEJjCCAw6gAwIBAgITawAAADqEP46TDmc/hQAAAAAAOjANBgkqhkiG
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
# BDEWBBR3nq5V9pr5vjB3soyyXuXIh9+UDTANBgkqhkiG9w0BAQEFAASCAQA7dB9W
# WVC7zngb0r++HxnW1/k6JlXmfGOAjX83Wp6jTj62+nL//deKvp3+0CQH/ajdiRKl
# MVG7k8uJXTkE4T2WJAVXei6yYvz5JkpPqI9eXBfll+K+uh9o3/r29+7Pnc6kFFag
# cwBkZ5h0Qf9zsJQOKMOA3iDL9VXcatoZuUPCK78yo2ENWEXmIYc3321MBGDNPEaP
# JMn3pCSkn077Jp5gFor2r8ZUhAad6tCPFoz0aPi4O6oYIgZ11zj/CPATUuWFidBI
# Y4zeF8tRLtnSUV8nh6M2nMNpH9dljiBRB9NRMW+N+iSyPFdXWOoeIF7BEo7pZY3C
# qRcXhWAquK8JlQrO
# SIG # End signature block
