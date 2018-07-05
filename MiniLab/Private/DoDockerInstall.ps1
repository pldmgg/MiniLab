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
        $DockerForWindowsUninstallResult = Uninstall-Program -ProgramName "docker-for-windows"
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
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUHY0VlaBYQJPBP8qusVdj5fUO
# Y4Sgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFJRm0q8iGAXgseZp
# 3/ApZo9abDIIMA0GCSqGSIb3DQEBAQUABIIBAE0zLXWyIOGMx53IEUbyxiIDpq8t
# 72mztRU+LYMz+K8z0THwnNYRU0Bx38UBaevK/Q4XVdX+pqP6vRxOqvm8PgC9wTk3
# E0aLzIUlx9/TvHKv7ZUvhr9TqLn7wWjrJNBJijfWAGunsR/4t3xxO3doyP8KfV8M
# RO7FekAe5OMof/YlnkYNdfQxBWZcbYpNGsi2hLvoJEnsviqWwisoJMxngvqQ0h1u
# vLCDQDVMwUgpWmJjOygsL7v6l4sb7eil5SYJqkpmxnHKVjwJFVSch4NUpNJmSkhm
# ACfng2h8aA8vi51K9rZ/TO6pyDyARxd2fWOj6rT3t5GLd2OJ7Tl469V1SQQ=
# SIG # End signature block
