[System.Collections.ArrayList]$script:FunctionsForSBUse = @(
    ${Function:AddWinRMTrustLocalHost}.Ast.Extent.Text
    ${Function:AddWinRMTrustedHost}.Ast.Extent.Text
    ${Function:ConfirmAWSVM}.Ast.Extent.Text
    ${Function:ConfirmAzureVM}.Ast.Extent.Text
    ${Function:ConfirmGoogleComputeVM}.Ast.Extent.Text
    ${Function:ConvertSize}.Ast.Extent.Text
    ${Function:ConvertSubnetMask}.Ast.Extent.Text
    ${Function:DoDockerInstall}.Ast.Extent.Text
    ${Function:EnableNestedVM}.Ast.Extent.Text
    ${Function:FixNTVirtualMachinesPerms}.Ast.Extent.Text 
    ${Function:FixVagrantPrivateKeyPerms}.Ast.Extent.Text
    ${Function:GetDomainController}.Ast.Extent.Text
    ${Function:GetElevation}.Ast.Extent.Text
    ${Function:GetFileLockProcess}.Ast.Extent.Text
    ${Function:GetIPRange}.Ast.Extent.Text
    ${Function:GetModuleDependencies}.Ast.Extent.Text
    ${Function:GetNativePath}.Ast.Extent.Text
    ${Function:GetNestedVirtCapabilities}.Ast.Extent.Text
    ${Function:GetPendingReboot}.Ast.Extent.Text
    ${Function:GetVSwitchAllRelatedInfo}.Ast.Extent.Text
    ${Function:GetWinPSInCore}.Ast.Extent.Text
    ${Function:GetWorkingCredentials}.Ast.Extent.Text
    ${Function:InstallFeatureDism}.Ast.Extent.Text
    ${Function:InstallHyperVFeatures}.Ast.Extent.Text
    ${Function:InvokeModuleDependencies}.Ast.Extent.Text
    ${Function:InvokePSCompatibility}.Ast.Extent.Text
    ${Function:ManualPSGalleryModuleInstall}.Ast.Extent.Text
    ${Function:MobyLinuxBetter}.Ast.Extent.Text
    ${Function:NewUniqueString}.Ast.Extent.Text
    ${Function:PauseForWarning}.Ast.Extent.Text
    ${Function:ResolveHost}.Ast.Extent.Text
    ${Function:TestHyperVExternalvSwitch}.Ast.Extent.Text
    ${Function:TestIsValidIPAddress}.Ast.Extent.Text
    ${Function:UnzipFile}.Ast.Extent.Text
    ${Function:Create-Domain}.Ast.Extent.Text
    ${Function:Create-RootCA}.Ast.Extent.Text
    ${Function:Create-SubordinateCA}.Ast.Extent.Text
    ${Function:Create-TwoTierPKI}.Ast.Extent.Text
    ${Function:Create-TwoTierPKICFSSL}.Ast.Extent.Text
    ${Function:Deploy-HyperVVagrantBoxManually}.Ast.Extent.Text
    ${Function:Generate-Certificate}.Ast.Extent.Text
    ${Function:Get-DockerInfo}.Ast.Extent.Text
    ${Function:Get-DSCEncryptionCert}.Ast.Extent.Text
    ${Function:Get-EncryptionCert}.Ast.Extent.Text
    ${Function:Get-GuestVMAndHypervisorInfo}.Ast.Extent.Text
    ${Function:Get-VagrantBoxManualDownload}.Ast.Extent.Text
    ${Function:Get-WinOpenSSL}.Ast.Extent.Text
    ${Function:Install-Docker}.Ast.Extent.Text
    ${Function:Join-LinuxToAD}.Ast.Extent.Text
    ${Function:Manage-HyperVVM}.Ast.Extent.Text
    ${Function:Move-DockerStorage}.Ast.Extent.Text
    ${Function:New-DomainController}.Ast.Extent.Text
    ${Function:New-RootCA}.Ast.Extent.Text
    ${Function:New-Runspace}.Ast.Extent.Text
    ${Function:New-SelfSignedCertificateEx}.Ast.Extent.Text
    ${Function:New-SubordinateCA}.Ast.Extent.Text
    ${Function:Recreate-MobyLinuxVM}.Ast.Extent.Text
    ${Function:Switch-DockerContainerType}.Ast.Extent.Text
)

# SIG # Begin signature block
# MIIMaAYJKoZIhvcNAQcCoIIMWTCCDFUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU1uhxOSqHlZCrYeM2Mq8pJgVD
# 1QqgggndMIIEJjCCAw6gAwIBAgITawAAADqEP46TDmc/hQAAAAAAOjANBgkqhkiG
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
# BDEWBBQcmyX/HZS3jLC2PeTQ+PxFW0J/ijANBgkqhkiG9w0BAQEFAASCAQBX4d/5
# wQox94QfgNo0hZDagNTQjTu8onpouwub3xenl+v/Tez9zyGCuQCoYD2PnTbIZrWT
# uzUqDsiyWvS5BeOHDxZF8Vwx+MGSElxVvnptjfDKNkq0CA91G6U/WW2jDsxb4RB9
# Zv0MaauwypM2q/Cvfg3pviY4voI+Eq7NtkoNUuG0vl4wtffqMi/Z8pQsLd5l2pQd
# 1EM4U9vZQaN+hAeUxRW3WPUmarrprOWsVBp1X05zrXFFDppoRk4hPJe+eDfTbGfB
# MIe0wxigLOnGa/o8PdvvJ/v+pN1KA+2wcruaHFy5vv9/CPbYg7dcToXRJHy63jI9
# cWrohVA2ogy2/G8v
# SIG # End signature block
