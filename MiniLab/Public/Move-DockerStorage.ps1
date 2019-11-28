<#
    .SYNOPSIS
        This function moves Docker-For-Windows (DockerCE) Windows and Linux Container storage
        to the specified location(s).

    .DESCRIPTION
        See .SYNOPSIS

    .PARAMETER NewDockerDrive
        This parameter is OPTIONAL.

        This parameter takes a letter (A-Z) that represents the drive that you would like to move
        Windows and Linux Container storage to.

        If you use this parameter, do not use the -CustomWindowsImageStoragePath or -CustomLinuxImageStoragePath
        parameters.

    .PARAMETER CustomWindowsImageStoragePath
        This parameter is OPTIONAL.

        This parameter takes a string that represents a full path to a directory where you would like
        Windows Container storage moved.

        Do not use this parameter if you are using the -NewDockerDrive parameter.

    .PARAMETER CustomLinuxImageStoragePath
        This parameter is OPTIONAL.

        This parameter takes a string that represents a full path to a directory where you would like
        Linux Container storage moved.

        Do not use this parameter if you are using the -NewDockerDrive parameter.

    .PARAMETER MoveWindowsImagesOnly
        This parameter is OPTIONAL.

        This parameter is a switch. If used, only Windows Container storage will be moved.

    .PARAMETER MoveLinuxImagesOnly
        This parameter is OPTIONAL.

        This parameter is a switch. If used, only Linux Container storage will be moved.

    .PARAMETER Force
        This parameter is OPTIONAL.

        This parameter is a switch.

        Moving Windows Docker Storage to a new location causes existing Windows docker images and containers to be removed.
        Default behavior for this function is prompt the user to confirm this action before proceeding. Use the -Force
        switch to skip this prompt.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Move-DockerStorage -NewDockerDrive H -Force
        
#>
function Move-DockerStorage {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [ValidatePattern("[a-zA-Z]")]
        [string]$NewDockerDrive,

        [Parameter(Mandatory=$False)]
        [string]$CustomWindowsImageStoragePath,

        [Parameter(Mandatory=$False)]
        [string]$CustomLinuxImageStoragePath,

        [Parameter(Mandatory=$False)]
        [switch]$MoveWindowsImagesOnly,

        [Parameter(Mandatory=$False)]
        [switch]$MoveLinuxImagesOnly,

        [Parameter(Mandatory=$False)]
        [switch]$Force
    )

    # Make sure one of the parameters is used
    if (!$NewDockerDrive -and !$CustomWindowsImageStoragePath -and !$CustomLinuxImageStoragePath) {
        Write-Error "The $($MyInvocation.MyCommand.Name) function requires either the -NewDockerDrive parameter or the -CustomDockerStoragePath parameter! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($CustomWindowsImageStoragePath -and $MoveLinuxImagesOnly) {
        Write-Error "The switch -MoveLinuxImagesOnly was used in conjunction with the -CustomWindowsImageStoragePath parameter! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($CustomLinuxImageStoragePath -and $MoveWindowsImagesOnly) {
        Write-Error "The switch -MoveWindowsImagesOnly was used in conjunction with the -CustomLinuxImageStoragePath parameter! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Make sure docker is installed
    if (![bool]$(Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Error "The 'docker' command is not available! Is docker installed? Halting!"
        $global:FunctionResult = "1"
        return
    }

    $DockerInfo = Get-DockerInfo
    $LocalDrives = Get-CimInstance Win32_LogicalDisk | Where-Object {$_.Drivetype -eq 3} | foreach {Get-PSDrive $_.DeviceId[0] -ErrorAction SilentlyContinue}

    if ($NewDockerDrive) {
        while ($LocalDrives.Name -notcontains $NewDockerDrive) {
            Write-Warning "$NewDockerDrive is not a valid Local Drive!"
            $NewDockerDrive = Read-Host -Prompt "Please enter the drive letter (LETTER ONLY) that you would like to move Docker Storage to [$($LocalDrives.Name -join '|')]"
        }
    }

    if ($CustomLinuxImageStoragePath) {
        if ($NewDockerDrive) {
            if ($CustomLinuxImageStoragePath[0] -ne $NewDockerDrive) {
                Write-Error "The drive indicated by -CustomLinuxImageStoragePath (i.e. $($CustomLinuxImageStoragePath[0])) is not the same as the drive indicated by -NewDockerDrive (i.e. $NewDockerDrive)! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        $FinalLinuxImageStoragePath = $CustomLinuxImageStoragePath
    }
    else {
        $FinalLinuxImageStoragePath = "$NewDockerDrive`:\DockerStorage\LinuxContainers"
    }
    if (!$(Test-Path $FinalLinuxImageStoragePath)) {
        $null = New-Item -ItemType Directory -Path $FinalLinuxImageStoragePath -Force
    }

    if ($CustomWindowsImageStoragePath) {
        if ($NewDockerDrive) {
            if ($CustomWindowsImageStoragePath[0] -ne $NewDockerDrive) {
                Write-Error "The drive indicated by -CustomWindowsImageStoragePath (i.e. $($CustomWindowsImageStoragePath[0])) is not the same as the drive indicated by -NewDockerDrive (i.e. $NewDockerDrive)! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        $FinalWindowsImageStoragePath = $CustomWindowsImageStoragePath
    }
    else {
        $FinalWindowsImageStoragePath = "$NewDockerDrive`:\DockerStorage\WindowsContainers"
    }
    if (!$(Test-Path $FinalWindowsImageStoragePath)) {
        $null = New-Item -ItemType Directory -Path $FinalWindowsImageStoragePath -Force
    }

    if (!$MoveLinuxImagesOnly) {
        # Unfortunately, it does not seem possible to move Docker Storage along with existing Windows docker images and containers.
        # So, the docker images and containers will need to be recreated after "C:\ProgramData\Docker\config\daemon.json"
        # has been updated with the new storage location
        if (!$Force) {
            Write-Warning "Moving Windows Docker Storage to a new location will remove all existing Windows docker images and containers!"
            $MoveWinDockerStorageChoice = Read-Host -Prompt "Are you sure you want to move Windows Docker Storage? [Yes\No]"
            while ($MoveWinDockerStorageChoice -match "Yes|yes|Y|y|No|no|N|n") {
                Write-Host "'$MoveWinDockerStorageChoice' is *not* a valid choice. Please enter either 'Yes' or 'No'."
                $MoveWinDockerStorageChoice = Read-Host -Prompt "Are you sure you want to move Windows Docker Storage? [Yes\No]"
            }

            if ($MoveWinDockerStorageChoice -notmatch "Yes|yes|Y|y") {
                Write-Warning "Windows Docker Storage will NOT be moved."
            }
        }

        if ($Force -or $MoveWinDockerStorageChoice -match "Yes|yes|Y|y") {
            # If "C:\ProgramData\Docker\config" doesn't exist, that means that Docker has NEVER been switched to Windows Containers
            # on this machine, so we need to do so.
            if (!$(Test-Path "C:\ProgramData\Docker\config")) {
                $null = Switch-DockerContainerType -ContainerType Windows
                #Write-Host "Sleeping for 30 seconds to give docker time to setup for Windows Containers..."
                #Start-Sleep -Seconds 30
                
                $UpdatedDockerInfo = Get-DockerInfo
                if ($UpdatedDockerInfo.DockerServerInfo.'OS/Arch' -notmatch "windows") {
                    Write-Error "Docker did NOT successfully switch to Windows Containers within the alotted time! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }

            # Update the Docker Config File with the New Storage Location
            # Solution from:
            # https://social.technet.microsoft.com/Forums/Lync/en-US/4ac564e2-ad6d-4d32-8cb4-7fea481738a4/how-to-change-docker-images-and-containers-location-with-windows-containers?forum=ws2016
            
            $DockerConfigJsonAsPSObject = Get-Content "C:\ProgramData\Docker\config\daemon.json" | ConvertFrom-Json
            $DockerConfigJsonAsPSObject | Add-Member -Type NoteProperty -Name data-root -Value $FinalWindowsImageStoragePath -Force
            $DockerConfigJsonAsPSObject | ConvertTo-Json -Compress | Out-File "C:\ProgramData\Docker\config\daemon.json"
        }
    }

    if (!$MoveWindowsImagesOnly) {
        # We need to move the MobyLinuxVM #

        # Make sure that com.docker.service is Stopped and 'Docker For Windows.exe' and 'dockerd.exe' are not running
        try {
            $DockerService = Get-Service com.docker.service -ErrorAction Stop

            if ($DockerService.Status -ne "Stopped") {
                $DockerService | Stop-Service -Force
            }
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        try {
            $DockerForWindowsProcess = Get-Process "Docker For Windows" -ErrorAction SilentlyContinue
            if ($DockerForWindowsProcess) {
                $DockerForWindowsProcess | Stop-Process -Force
            }

            $DockerDProcess = Get-Process "dockerd" -ErrorAction SilentlyContinue
            if ($DockerDProcess) {
                $DockerDProcess | Stop-Process -Force
            }
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        # Make sure the MobyLinuxVM is Off
        $MobyLinuxVMInfo = Get-VM -Name MobyLinuxVM

        if ($MobyLinuxVMInfo.State -ne "Off") {
            try {
                Stop-VM -VMName MobyLinuxVM -TurnOff -Confirm:$False -Force -ErrorAction Stop
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }

        $DockerSettings = Get-Content "$env:APPDATA\Docker\settings.json" | ConvertFrom-Json
        $DockerSettings.MobyVhdPathOverride = "$CustomLinuxImageStoragePath\MobyLinuxVM.vhdx"
        $DockerSettings | ConvertTo-Json | Out-File "$env:APPDATA\Docker\settings.json"

        # Alternate method using symlink/junction
        <#
        try {
            # Get the current location of the VHD - It's almost definitely under
            # C:\Users\Public\Documents\Hyper-V\Virtual Hard Disks\MobyLinuxVM.vhdx, but check to make sure
            $MLVhdLocation = $(Get-VMHardDiskDrive -VMName MobyLinuxVM).Path
            $MLVhdLocationParentDir = $MLVhdLocation | Split-Path -Parent

            # Determine if there are other files in $MLVhdLocationParentDir. If there are, halt because
            # we can't safely create the symlink, so just leave everything where it is...
            $MLVhdLocationContentCheck = Get-ChildItem -Path $MLVhdLocationParentDir -File -Recurse
            if ($MLVhdLocationContentCheck.Count -gt 1 -and
            [bool]$($MLVhdLocationContentCheck.FullName -notmatch "MobyLinuxVM.*?vhdx$")
            ) {
                Write-Warning "There are files under '$MLVhdLocationParentDir' besides VHDs related to MobyLinuxVM! MobyLinuxVM storage will NOT be moved!"
            }
            else {
                Move-VMStorage -VMName MobyLinuxVM -DestinationStoragePath $FinalLinuxImageStoragePath

                Write-Host "Removing empty directory '$MLVhdLocationParentDir' in preparation for symlink ..."
                Remove-Item $MLVhdLocationParentDir -ErrorAction Stop
                
                Write-Host "Creating junction for MobyLinuxVM storage directory from original location '$MLVhdLocationParentDir' to new location '$FinalLinuxImageStoragePath\Virtual Hard Disks' ..."
                $null = cmd /c mklink /j $MLVhdLocationParentDir "$FinalLinuxImageStoragePath\Virtual Hard Disks"
            }
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
        #>

        # Turn On Docker Again
        try {
            $DockerService = Get-Service com.docker.service -ErrorAction Stop

            if ($DockerService.Status -eq "Stopped") {
                $DockerService | Start-Service
                Write-Host "Sleeping for 30 seconds to give the com.docker.service service time to become ready..."
                Start-Sleep -Seconds 30
            }

            $MobyLinuxVMInfo = Get-VM -Name MobyLinuxVM
            if ($MobyLinuxVMInfo.State -ne "Running") {
                Write-Host "Manually starting MobyLinuxVM..."
                Start-VM -Name MobyLinuxVM
            }

            & "C:\Program Files\Docker\Docker\Docker For Windows.exe"
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        # Make sure we switch to Linuc Container Mode to ensure MobyLinuxVM is recreated in he new Storage Location
        $null = Switch-DockerContainerType -ContainerType Linux
    }

    
    # Create Output
    if ($FinalLinuxImageStoragePath) {
        $LinuxStorage = $FinalLinuxImageStoragePath
    }
    if ($FinalWindowsImageStoragePath) {
        $WindowsStorage = $FinalWindowsImageStoragePath
    }
    if ($CustomLinuxImageStoragePath) {
        $LinuxStorage = $CustomLinuxImageStoragePath
    }
    if ($CustomWindowsImageStoragePath) {
        $WindowsStorage = $CustomWindowsImageStoragePath
    }

    $Output = @{}

    if ($LinuxStorage) {
        $Output.Add("LinuxStorage",$LinuxStorage)
    }
    if ($WindowsStorage) {
        $Output.Add("WindowsStorage",$WindowsStorage)
    }

    [pscustomobject]$Output
}

# SIG # Begin signature block
# MIIMaAYJKoZIhvcNAQcCoIIMWTCCDFUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUn5z4y96U45qpIKxg1EGErgM5
# uYKgggndMIIEJjCCAw6gAwIBAgITawAAADqEP46TDmc/hQAAAAAAOjANBgkqhkiG
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
# BDEWBBQopmBIGZMyQHfNjUOqwCZ8WGI+kjANBgkqhkiG9w0BAQEFAASCAQB89Kxs
# YGORO2a26KW3Xkc0u9HuFtcoFNG1ysj+PhV4V872IkCiWswbRoBANfyHYo01E8dA
# GXDF9E1soLtlTTSQevCPonMj6c99YHfsUMaRAlKc4AwAM3mf/OQJTaaEiT/fXR7F
# Y8FgQWqv+4daZ5AjIEre2TUFPI/PWm4tULUBtXgKCtksJSAayBSdPA6Hf6Dhp9De
# Q9/wnf2h8EuYrr0be01xF9KB7aoayaEBP8CmEESmLlJ7NauycdQWZsI1M5Myjl4k
# AjJqsTAxhAeTgLa1rgDBWw/nG3nPS5WmEP7m8OvsDPJaEuz1KdCBq99lX0getzso
# bBIHnQc/cqcjLwJY
# SIG # End signature block
