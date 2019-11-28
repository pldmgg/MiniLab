function DoDockerInstall {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [int]$MobyLinuxVMMemoryInGB = 2,

        [Parameter(Mandatory=$False)]
        [switch]$AllowRestarts,

        [Parameter(Mandatory=$False)]
        [switch]$SkipHyperVInstallCheck,

        [Parameter(Mandatory=$False)]
        [switch]$RecreateMobyLinuxVM,

        [Parameter(Mandatory=$False)]
        [switch]$PreRelease,

        [Parameter(Mandatory=$False)]
        [switch]$AllowLogout
    )

    # Make sure we have the ProgramManagement Module installed and imported
    if (![bool]$(Get-Module -ListAvailable ProgramManagement)) {Install-Module ProgramManagement}
    if (![bool]$(Get-Module ProgramManagement)) {Import-Module ProgramManagement}


    try {
        $DockerForWindowsUninstallResult = Uninstall-Program -ProgramName "docker-for-windows" -ErrorAction SilentlyContinue
    }
    catch {
        if ($_.Exception.Message -match "^Unable to find an installed program matching the name") {
            Write-Verbose $($_.Exception.Message)
        }
        else {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }

    # Do some basic Memory Checks before attempting to create/start the MobyLinux VM
    $OSInfo = Get-CimInstance Win32_OperatingSystem
    $TotalMemory = $OSInfo.TotalVisibleMemorySize
    $MemoryAvailable = $OSInfo.FreePhysicalMemory
    $TotalMemoryInGB = [Math]::Round($TotalMemory / 1MB)
    $MemoryAvailableInGB = [Math]::Round($MemoryAvailable / 1MB)
    if ($TotalMemoryInGB -lt 8) {
        Write-Error "The host machine should have at least 8GB total memory installed in order to run VMs. Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($MemoryAvailableInGB -lt 4) {
        $MemoryErrorMsg = "The host machine should have at least 4GB of memory readily available in order to run a VM. " +
        "It currently only has about $MemoryAvailableInGB GB available for immediate use. Halting!"
        Write-Error $MemoryErrorMsg
        $global:FunctionResult = "1"
        return
    }

    if ([bool]$PSBoundParameters['MobyLinuxVMMemoryInGB']) {
        $MobyLinuxVMMemoryInMB = [Math]::Round($MobyLinuxVMMemoryInGB * 1KB)
    }

    if (!$SkipHyperVInstallCheck) {
        # Check to see if all Hyper-V features are installed...

        # NOTE: Below $HyperVFeaturesInstallResults contains properties 'InstallResults' (array of InstallFeatureDism
        # pscustomobjects which contiain properties contains properties [string]Path, [bool]Online, [string]WinPath,
        # [string]SysDrivePath, [bool]RestartNeeded, [string]$LogPath, [string]ScratchDirectory,
        # [string]LogLevel), and 'InstallFailures' (array of strings of Dism Feature Names that
        # failed to install).
        # NOTE: InstallHyperVFeatures returns $null if everything is already installed.
        try {
            $HyperVFeaturesInstallResults = InstallHyperVFeatures -ParentFunction $MyInvocation.MyCommand.Name
        }
        catch {
            Write-Error $_
            Write-Error "The InstallHyperVFeatures function (as executed by the $($MyInvocation.MyCommand.Name) function) failed! Halting!"
            $global:FunctionResult = "1"
            return
        }

        if ($HyperVFeaturesInstallResults.InstallFailures.Count -gt 0) {
            Write-Error "Please remedy the Hyper-V Features that failed to install before proceeding. Halting!"
            $global:FunctionResult = "1"
            return
        }

        # Check to see if Windows Containers Feature is installed...
        # NOTE: The below InstallFeatureDism returns $null if Containers is already installed
        try {
            $InstallContainersFeatureDismResult = InstallFeatureDism -Feature Containers -ParentFunction $MyInvocation.MyCommand.Name
        }
        catch {
            Write-Error $_
            Write-Error "The InstallFeatureDism function (as executed by the $($MyInvocation.MyCommand.Name) function) failed! Halting!"
            $global:FunctionResult = "1"
            return
        }
        
        if ($HyperVFeaturesInstallResults.InstallResults.RestartNeeded -notcontains $True -and 
        $($InstallContainersFeatureDismResult.RestartNeeded -eq $False -or $InstallContainersFeatureDismResult.RestartNeeded -eq $null)) {
            Write-Host "All dependencies are already installed...proceeding..." -ForegroundColor Green
        }
        else {
            if ($($HyperVFeaturesInstallResults.InstallResults.RestartNeeded -contains $True -or $InstallContainersFeatureDismResult.RestartNeeded) -and $AllowRestarts) {
                Write-Host "Restarting $env:ComputerName..."
                # NOTE: The below output "Restarting" is important when running this function via Invoke-Command
                Write-Output "Restarting"
                Restart-Computer -Confirm:$false -Force
            }
            else {
                Write-Error "You must restart $env:ComputerName before proceeding! Halting!"
                return
            }
        }
    }

    # At this point, we know that Hyper-V is installed one way or another, so import the NetNat cmdlet
    if ($PSVersionTable.PSEdition -eq "Core") {
        Import-WinModule -Name NetNat -ErrorAction SilentlyContinue
    }
    else {
        Import-Module -Name NetNat -ErrorAction SilentlyContinue
    }
    if ($(Get-Module).Name -notcontains "NetNat" -and $(Get-Module -ListAvailable).Name -notcontains "NetNat") {
        Write-Error $_
        Write-Error "Unable to import the NetNat Module! Is Hyper-V installed? Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Make sure that OpenSSH is installed and that the ssh-agent service is installed and running
    if (![bool]$(Get-Command ssh -ErrorAction SilentlyContinue)) {
        if (![bool]$(Get-Module -ListAvailable ProgramManagement)) {Install-Module ProgramManagement}
        if (![bool]$(Get-Module ProgramManagement)) {Import-Module ProgramManagement}
        $InstallOpenSSHResult = Install-Program -ProgramName openssh -CommandName ssh.exe -ExpectedInstallLocation "C:\Program Files\OpenSSH-Win64"

        if (![bool]$(Get-Service ssh-agent -ErrorAction SilentlyContinue)) {
            if (Test-Path "C:\Program Files\OpenSSH-Win64\install-sshd.ps1") {
                & "C:\Program Files\OpenSSH-Win64\install-sshd.ps1"
            }
            else {
                Write-Warning "Unable to find 'C:\Program Files\OpenSSH-Win64\install-sshd.ps1'! The services 'ssh-agent' and 'sshd' will NOT be installed."
            }
        }
    }
    
    try {
        Write-Host "Installing Docker CE (i.e. Docker For Windows)..."
        $InstallDockerSplatParams = @{
            ProgramName                 = "docker-for-windows"
            CommandName                 = "docker.exe"
            ExpectedInstallLocation     = "$env:ProgramFiles\Docker"
            ErrorAction                 = "SilentlyContinue"
            ErrorVariable               = "IPErr"
            WarningAction               = "SilentlyContinue"
            InformationAction           = "SilentlyContinue"
        }
        if ($PreRelease) {
            $InstallDockerSplatParams.Add("PreRelease",$True)
        }
        $InstallDockerCEResult = Install-Program @InstallDockerSplatParams
        if (!$InstallDockerCEResult) {throw "The Install-Program function failed while installing DockerCE! Halting!"}
    }
    catch {
        Write-Error $_
        Write-Host "Errors for the Install-Program function are as follows:"
        Write-Error $($IPErr | Out-String)
        $global:FunctionResult = "1"
        return
    }

    if ($InstallDockerCEResult.InstallAction -eq "FreshInstall") {
        Write-Host "Docker CE (i.e. Docker For Windows) has successfully been installed" -ForegroundColor Green
    }
    if ($InstallDockerCEResult.InstallAction -eq "AlreadyInstalled") {
        Write-Warning "Docker CE (i.e. Docker For Windows) is already installed!"

        if ($RecreateMobyLinuxVM) {
            $RecreateMobyLinuxVMResult = Recreate-MobyLinuxVM
        }

        $Output = [ordered]@{
            DockerCEInstallResult   = $InstallDockerCEResult
        }
        if ($RecreateMobyLinuxVMResult) {
            $Output.Add("RecreateMobyLinuxVMResult",$RecreateMobyLinuxVMResult)
        }

        [pscustomobject]$Output
        return
    }

    # Before configuring Docker CE, make sure there is NOT already an Internal vSwitch named DockerNAT or
    # a Network Adapter with IP 10.0.75.1
    $vSwitchInfoByIP = GetvSwitchAllRelatedInfo -IPAddress 10.0.75.1 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    if ($vSwitchInfoByIP) {
        Remove-VMSwitch -Name $vSwitchInfoByIP.BasicvSwitchInfo.Name -Confirm:$False -Force
    }
    if ([bool]$(Get-NetIPAddress -IPAddress 10.0.75.1 -ErrorAction SilentlyContinue)) {
        Remove-NetIPAddress -InterfaceAlias $(Get-NetIPAddress -IPAddress 10.0.75.1).InterfaceAlias -Confirm:$False
    }
    $vSwitchInfoByName = GetvSwitchAllRelatedInfo -vSwitchName "LocalNAT" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    if ($vSwitchInfoByName) {
        Remove-VMSwitch -Name $vSwitchInfoByName.BasicvSwitchInfo.Name -Confirm:$False -Force
    }
    try {
        $NetNatToRemove = Get-NetNat | Where-Object {$_.InternalIPInterfaceAddressPrefix -eq "10.0.75.0/24"}
        if ($NetNatToRemove) {
            Remove-NetNat -InputObject $NetNatToRemove -Confirm:$False
        }
    }
    catch {
        Write-Warning $_.ToString()
    }

    if ($InstallDockerCEResult.InstallAction -eq "FreshInstall") {
        Recreate-MobyLinuxVM
    }
    if ($InstallDockerCEResult.InstallAction -eq "AlreadyInstalled") {
        $RecreateMobyLinuxVMChoice = Read-Host -Prompt "Would you like to re-create the MobyLinux VM? (IMPORTANT NOTE: This could destroy existing Docker Containers.) [Yes\No]"
        while ($RecreateMobyLinuxVMChoice -notmatch "Yes|yes|Y|y|No|no|N|n") {
            Write-Host "'$RecreateMobyLinuxVMChoice' in not a valid option. Pleas enter 'Yes' or 'No'"
            $RecreateMobyLinuxVMChoice = Read-Host -Prompt "Would you like to re-create the MobyLinux VM? (IMPORTANT NOTE: This could destroy existing Docker Containers.) [Yes\No]"
        }

        if ($RecreateMobyLinuxVMChoice -match "^yes$|^y$") {
            Recreate-MobyLinuxVM
        }
    }

    # Finally, we're ready to start Docker For Windows aka DockerCE
    $DockerForWindowsEXE = $(Get-ChildItem -Path "C:\Program Files\Docker" -Recurse -File -Filter "*Docker For Windows.exe").FullName
    try {
        & $DockerForWindowsEXE
    }
    catch {
        Write-Error $_
        Write-Error "'$DockerForWindowsExe' failed! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # $Host is an Automatic Variable. Values for $Host.Name can be "ConsoleHost" (for normal local PowerShell
    # Session) or "ServerRemoteHost" (if we're within a Remote PSSession)
    if ($Host.Name -eq "ConsoleHost") {
        if (!$AllowLogout) {
            Write-Warning "Docker CE (i.e. Docker For Windows) has added the current user (i.e. $(whoami)) to the 'docker-users' security group, however, logout/login is required docker can be used by $(whoami)!"
            $LogoutChoice = Read-Host -Prompt "Would you like to logout now? [Yes/No]"
            
            while ($LogoutChoice -notmatch "Yes|yes|Y|y|No|no|N|n") {
                Write-Host "$LogoutChoice is not a valid choice! Please enter 'Yes' or 'No'"
                $LogoutChoice = Read-Host -Prompt "Would you like to logout now? [Yes/No]"
            }
        }

        if ($LogoutChoice -match "Yes|yes|Y|y" -or $AllowLogout) {
            logoff
        }
        else {
            Write-Host "Please logout/login at your discretion in order to begin using docker."
            Write-Host "Install-Docker function completed successfully!" -ForegroundColor Green
        }
    }

    $Output = [ordered]@{
        DockerCEInstallResult   = $InstallDockerCEResult
    }
    if ($MobyLinuxScriptResult) {
        $Output.Add("MobyLinuxScriptResult",$MobyLinuxScriptResult)
    }
    if ($RecreateMobyLinuxVMResult) {
        $Output.Add("RecreateMobyLinuxVMResult",$RecreateMobyLinuxVMResult)
    }

    [pscustomobject]$Output
}

# SIG # Begin signature block
# MIIMaAYJKoZIhvcNAQcCoIIMWTCCDFUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUfWfRdYhMCJgG9pVfT6RXyjsW
# us2gggndMIIEJjCCAw6gAwIBAgITawAAADqEP46TDmc/hQAAAAAAOjANBgkqhkiG
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
# BDEWBBQemkhjLrHWvSuSHuvpgHR1SxGvrjANBgkqhkiG9w0BAQEFAASCAQCoR7Su
# 66KiDTElrJb4SwcJ3OliA8gzEr9iJwGMpXjhLAm3c9HRVvOL8ae4iBq5MQfDPTi8
# qGUElh9YzpwnM8zo8BGAVgq4b/+1caTyqDSAA89ZOIFXvHOiRAHKNw1ovR75rPam
# JCSDIk1BB3LB0hPPtgaYiKbOGxO3RDkDA2hOImcQQLaE+rRvTY53mUF6t25F7rF4
# p5WwOvBwJLOEj+5d6FRCnQrd+DbhrmYty37BVciSFnivpCJKpBKDGhhG1k0j4I8e
# UzKX7BLGqqY2FYOBsc2O3SA9YoBCCgEnr7cutJZ+EaP0+hhbMeJZj8u8ch4FSXSb
# z40CEuM/V1mEs+f2
# SIG # End signature block
