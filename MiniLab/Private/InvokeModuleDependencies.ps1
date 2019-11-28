function InvokeModuleDependencies {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$False)]
        [string[]]$RequiredModules,

        [Parameter(Mandatory=$False)]
        [switch]$InstallModulesNotAvailableLocally
    )

    if ($InstallModulesNotAvailableLocally) {
        if ($PSVersionTable.PSEdition -ne "Core") {
            $null = Install-PackageProvider -Name Nuget -Force -Confirm:$False
            $null = Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        }
        else {
            $null = Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        }
    }

    if ($PSVersionTable.PSEdition -eq "Core") {
        $InvPSCompatSplatParams = @{
            ErrorAction                         = "SilentlyContinue"
            #WarningAction                       = "SilentlyContinue"
        }

        $MyInvParentScope = Get-Variable "MyInvocation" -Scope 1 -ValueOnly
        $PathToFile = $MyInvParentScope.MyCommand.Source
        $FunctionName = $MyInvParentScope.MyCommand.Name

        if ($PathToFile) {
            $InvPSCompatSplatParams.Add("InvocationMethod",$PathToFile)
        }
        elseif ($FunctionName) {
            $InvPSCompatSplatParams.Add("InvocationMethod",$FunctionName)
        }
        else {
            Write-Error "Unable to determine MyInvocation Source or Name! Halting!"
            $global:FunctionResult = "1"
            return
        }

        if ($PSBoundParameters['InstallModulesNotAvailableLocally']) {
            $InvPSCompatSplatParams.Add("InstallModulesNotAvailableLocally",$True)
        }
        if ($PSBoundParameters['RequiredModules']) {
            $InvPSCompatSplatParams.Add("RequiredModules",$RequiredModules)
        }

        $Output = InvokePSCompatibility @InvPSCompatSplatParams
    }
    else {
        [System.Collections.ArrayList]$SuccessfulModuleImports = @()
        [System.Collections.ArrayList]$FailedModuleImports = @()

        foreach ($ModuleName in $RequiredModules) {
            $ModuleInfo = [pscustomobject]@{
                ModulePSCompatibility   = "WinPS"
                ModuleName              = $ModuleName
            }

            if (![bool]$(Get-Module -ListAvailable $ModuleName) -and $InstallModulesNotAvailableLocally) {
                $searchUrl = "https://www.powershellgallery.com/api/v2/Packages?`$filter=Id eq '$ModuleName' and IsLatestVersion"
                $PSGalleryCheck = Invoke-RestMethod $searchUrl
                if (!$PSGalleryCheck -or $PSGalleryCheck.Count -eq 0) {
                    $searchUrl = "https://www.powershellgallery.com/api/v2/Packages?`$filter=Id eq '$ModuleName'"
                    $PSGalleryCheck = Invoke-RestMethod $searchUrl

                    if (!$PSGalleryCheck -or $PSGalleryCheck.Count -eq 0) {
                        Write-Warning "Unable to find Module '$ModuleName' in the PSGallery! Skipping..."
                        continue
                    }

                    $PreRelease = $True
                }

                try {
                    if ($PreRelease) {
                        ManualPSGalleryModuleInstall -ModuleName $ModuleName -DownloadDirectory "$HOME\Downloads" -PreRelease -ErrorAction Stop -WarningAction SilentlyContinue
                    }
                    else {
                        Install-Module $ModuleName -AllowClobber -Force -ErrorAction Stop -WarningAction SilentlyContinue
                    }
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }
            }

            if (![bool]$(Get-Module -ListAvailable $ModuleName)) {
                $ErrMsg = "The Module '$ModuleName' is not available on the localhost! Did you " +
                "use the -InstallModulesNotAvailableLocally switch? Halting!"
                Write-Error $ErrMsg
                continue
            }

            $ManifestFileItem = Get-Item $(Get-Module -ListAvailable $ModuleName).Path
            $ModuleInfo | Add-Member -Type NoteProperty -Name ManifestFileItem -Value $ManifestFileItem

            # Import the Module
            try {
                Import-Module $ModuleName -Scope Global -ErrorAction Stop
                $null = $SuccessfulModuleImports.Add($ModuleInfo)
            }
            catch {
                Write-Warning "Problem importing the $ModuleName Module!"
                $null = $FailedModuleImports.Add($ModuleInfo)
            }
        }

        $UnacceptableUnloadedModules = $FailedModuleImports

        $Output = [pscustomobject]@{
            SuccessfulModuleImports         = $SuccessfulModuleImports
            FailedModuleImports             = $FailedModuleImports
            UnacceptableUnloadedModules     = $UnacceptableUnloadedModules
        }
    }

    $Output
}

# SIG # Begin signature block
# MIIMaAYJKoZIhvcNAQcCoIIMWTCCDFUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUIuI5NgclVoPYJ+IBBAMJ6NCJ
# FrKgggndMIIEJjCCAw6gAwIBAgITawAAADqEP46TDmc/hQAAAAAAOjANBgkqhkiG
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
# BDEWBBR0GI/XVJUyRfA2iCKY1+bpDWLq7zANBgkqhkiG9w0BAQEFAASCAQBl6C3D
# 2NfBUh54/YBCCBiQFj8pkpPC7fizMNkSUp+PJ2W1UJCiRygsSjSpWCz4XOvBc1JR
# TRuAi3QdZfoK+aoisA3oYSSUjG4BlSyO3pOyORgJdJDQvcZ1PHF58hX8bBWARzL3
# 1Cl8+w9TESYG+rGyR/YH84Y4npGY1Fz5S1GCm805dl69PndOvgcI/a7lJjeMjMwv
# VHg1M3YZxc4yQKCGkooFiNOZG72A0U8NAELqGSqZF48bbLXRQ5QvN8Lm72j5RlgF
# 9rrl7IUUKSJxYQKi4Hjvled7l1fCuzIHkOD/wglcKOLQUI396Y0MMdCNLoRH02jD
# LRcVAo0PSbCEds0v
# SIG # End signature block
