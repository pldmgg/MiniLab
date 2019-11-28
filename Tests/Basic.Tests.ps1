[CmdletBinding()]
param(
    [Parameter(Mandatory=$False)]
    [System.Collections.Hashtable]$TestResources
)

# NOTE: `Set-BuildEnvironment -Force -Path $PSScriptRoot` from build.ps1 makes the following $env: available:
<#
    $env:BHBuildSystem = "Unknown"
    $env:BHProjectPath = "U:\powershell\ProjectRepos\Sudo"
    $env:BHBranchName = "master"
    $env:BHCommitMessage = "!deploy"
    $env:BHBuildNumber = 0
    $env:BHProjectName = "Sudo"
    $env:BHPSModuleManifest = "U:\powershell\ProjectRepos\Sudo\Sudo\Sudo.psd1"
    $env:BHModulePath = "U:\powershell\ProjectRepos\Sudo\Sudo"
    $env:BHBuildOutput = "U:\powershell\ProjectRepos\Sudo\BuildOutput"
#>

# Verbose output for non-master builds on appveyor
# Handy for troubleshooting.
# Splat @Verbose against commands as needed (here or in pester tests)
$Verbose = @{}
if($env:BHBranchName -notlike "master" -or $env:BHCommitMessage -match "!verbose") {
    $Verbose.add("Verbose",$True)
}

# Make sure the Module is not already loaded
if ([bool]$(Get-Module -Name $env:BHProjectName -ErrorAction SilentlyContinue)) {
    Remove-Module $env:BHProjectName -Force
}

Describe -Name "General Project Validation: $env:BHProjectName" -Tag 'Validation' -Fixture {
    $Scripts = Get-ChildItem $env:BHProjectPath -Include *.ps1,*.psm1,*.psd1 -Recurse

    # TestCases are splatted to the script so we need hashtables
    $TestCasesHashTable = $Scripts | foreach {@{file=$_}}         
    It "Script <file> should be valid powershell" -TestCases $TestCasesHashTable {
        param($file)

        $file.fullname | Should Exist

        $contents = Get-Content -Path $file.fullname -ErrorAction Stop
        $errors = $null
        $null = [System.Management.Automation.PSParser]::Tokenize($contents, [ref]$errors)
        $errors.Count | Should Be 0
    }

    It "Module '$env:BHProjectName' Should Load" -Test {
        {Import-Module $env:BHPSModuleManifest -Force} | Should Not Throw
    }

    It "Module '$env:BHProjectName' Public and Not Private Functions Are Available" {
        $Module = Get-Module $env:BHProjectName
        $Module.Name -eq $env:BHProjectName | Should Be $True
        $Commands = $Module.ExportedCommands.Keys
        $Commands -contains 'AddWinRMTrustedHost' | Should Be $False
        $Commands -contains 'AddWinRMTrustLocalHost' | Should Be $False
        $Commands -contains 'ConfirmAWSVM' | Should Be $False
        $Commands -contains 'ConfirmAzureVM' | Should Be $False
        $Commands -contains 'ConfirmGoogleComputeVM' | Should Be $False
        $Commands -contains 'ConvertSize' | Should Be $False
        $Commands -contains 'ConvertSubnetMask' | Should Be $False
        $Commands -contains 'DoDockerinstall' | Should Be $False
        $Commands -contains 'EnableNestedVM' | Should Be $False
        $Commands -contains 'FixNTVirtualMachinesPerms' | Should Be $False
        $Commands -contains 'FixVagrantPrivateKeyPerms' | Should Be $False
        $Commands -contains 'GetDomainController' | Should Be $False
        $Commands -contains 'GetElevation' | Should Be $False
        $Commands -contains 'GetFileLockProcess' | Should Be $False
        $Commands -contains 'GetIPRange' | Should Be $False
        $Commands -contains 'GetModuleDependencies' | Should Be $False
        $Commands -contains 'GetNativePath' | Should Be $False
        $Commands -contains 'GetNestedVirtCapabilities' | Should Be $False
        $Commands -contains 'GetPendingReboot' | Should Be $False
        $Commands -contains 'GetVSwitchAllRelatedInfo' | Should Be $False
        $Commands -contains 'GetWinPSInCore' | Should Be $False
        $Commands -contains 'GetWorkingCredentials' | Should Be $False
        $Commands -contains 'InstallFeatureDism' | Should Be $False
        $Commands -contains 'InstallHyperVFeatures' | Should Be $False
        $Commands -contains 'InvokeModuleDependencies' | Should Be $False
        $Commands -contains 'InvokePSCompatibility' | Should Be $False
        $Commands -contains 'ManualPSGalleryModuleInstall' | Should Be $False
        $Commands -contains 'MobyLinuxBetter' | Should Be $False
        $Commands -contains 'NewUniqueString' | Should Be $False
        $Commands -contains 'PauseForWarning' | Should Be $False
        $Commands -contains 'ResolveHost' | Should Be $False
        $Commands -contains 'TestIsValidIPAddress' | Should Be $False
        $Commands -contains 'UnzipFile' | Should Be $False
        
        $Commands -contains 'Create-Domain' | Should Be $True
        $Commands -contains 'Create-RootCA' | Should Be $True
        $Commands -contains 'Create-SubordinateCA' | Should Be $True
        $Commands -contains 'Create-TwoTierPKI' | Should Be $True
        $Commands -contains 'Create-TwoTierPKICFSSL' | Should Be $True
        $Commands -contains 'Deploy-HyperVVagrantBoxManually' | Should Be $True
        $Commands -contains 'Generate-Certificate' | Should Be $True
        $Commands -contains 'Get-DockerInfo' | Should Be $True
        $Commands -contains 'Get-DSCEncryptionCert' | Should Be $True
        $Commands -contains 'Get-EncryptionCert' | Should Be $True
        $Commands -contains 'Get-GuestVMAndHypervisorInfo' | Should Be $True
        $Commands -contains 'Get-VagrantBoxManualDownload' | Should Be $True
        $Commands -contains 'Get-WinOpenSSL' | Should Be $True
        $Commands -contains 'Install-Docker' | Should Be $True
        $Commands -contains 'Join-LinuxToAD' | Should Be $True
        $Commands -contains 'Manage-HyperVVM' | Should Be $True
        $Commands -contains 'Move-DockerStorage' | Should Be $True
        $Commands -contains 'New-DomainController' | Should Be $True
        $Commands -contains 'New-RootCA' | Should Be $True
        $Commands -contains 'New-Runspace' | Should Be $True
        $Commands -contains 'New-SelfSignedCertificateEx' | Should Be $True
        $Commands -contains 'New-SubordinateCA' | Should Be $True
        $Commands -contains 'Recreate-MobyLinuxVM' | Should Be $True
        $Commands -contains 'Switch-DockerContainerType' | Should Be $True
    }

    It "Module '$env:BHProjectName' Private Functions Are Available in Internal Scope" {
        $Module = Get-Module $env:BHProjectName
        [bool]$Module.Invoke({Get-Item function:AddWinRMTrustedHost}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:AddWinRMTrustLocalHost}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:ConfirmAWSVM}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:ConfirmAzureVM}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:ConfirmGoogleComputeVM}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:ConvertSize}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:ConvertSubnetMask}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:DoDockerInstall}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:EnableNestedVM}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:FixNTVirtualMachinesPerms}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:FixVagrantPrivateKeyPerms}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:GetDomainController}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:GetElevation}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:GetFileLockProcess}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:GetIPRange}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:GetModuleDependencies}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:GetNativePath}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:GetNestedVirtCapabilities}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:GetPendingReboot}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:GetVSwitchAllRelatedInfo}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:GetWinPSInCore}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:GetWorkingCredentials}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:InstallFeatureDism}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:InstallHyperVFeatures}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:InvokeModuleDependencies}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:InvokePSCompatibility}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:ManualPSGalleryModuleInstall}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:MobyLinuxBetter}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:NewUniqueString}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:PauseForWarning}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:ResolveHost}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:TestHyperVExternalvSwitch}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:TestIsValidIPAddress}) | Should Be $True
        [bool]$Module.Invoke({Get-Item function:UnzipFile}) | Should Be $True
    }
}

# SIG # Begin signature block
# MIIMaAYJKoZIhvcNAQcCoIIMWTCCDFUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUE1VmVykRK9yoMmWZ9jtt8qmE
# ZYugggndMIIEJjCCAw6gAwIBAgITawAAADqEP46TDmc/hQAAAAAAOjANBgkqhkiG
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
# BDEWBBRHmOCRWAP5KGdrXf/UUoiUxaj9MjANBgkqhkiG9w0BAQEFAASCAQBBvptq
# cYQ/V3dRBKIW9Hka1DStti4pijRGHF8Rn5LUV6AYmZVFjzydiUn0cuFEZVdOct5S
# 7g9LHZiUXtbm7lQokkNvLDzsIHq6OkZBovbX17kR5viXSQBozzxl/1xVFxm08i9C
# bP3WuHF+y6LQlpPiXCkFHhOk85DwFdSKZ/MSweqtWQ7Qe8u8/H9rnhBFliQKzlcy
# dFsMzbDJOrSnldvu6qb34ZFr6Iz4FXBahxswYvhx+CykfZ88q+o5zYRA9XBW7Cfd
# zfp0h++xfj2Cbpn4vnm9tFfq9TwO5UoQ+9kxOEj2vdDipihx9mEvjwm549X+RHgM
# MC/XiKVBWL07hnLk
# SIG # End signature block
