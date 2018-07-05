# Example: Move-DockerStorage -NewDockerDrive <DriveLetter>
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

    # Make sure docker is installed
    if (![bool]$(Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Error "The 'docker' command is not available! Is docker installed? Halting!"
        $global:FunctionResult = "1"
        return
    }

    $DockerInfo = Get-DockerInfo
    $LocalDrives = Get-WmiObject Win32_LogicalDisk | Where-Object {$_.Drivetype -eq 3} | foreach {Get-PSDrive $_.DeviceId[0] -ErrorAction SilentlyContinue}

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
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUjWEu170hrnokhcgqGi3dgFJV
# 3HOgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFHMlGYyCOusrbq+a
# iXB+eBf/MGG7MA0GCSqGSIb3DQEBAQUABIIBACw3PW0Gvf57oYoo7PdIoDu1d5nQ
# sUaqdslX4Oy8EzdjWTRX9BhG4VZwjRcL59cbE2TM0YDSe30Rb5oyhpv3vjbauALp
# FrXpOA6dlaBvHdZsYVNUQ+tpUmrl4Oqd6GzxDwxFT/5uxo5V9XV7GS2eYGPgJClM
# kyxOteqt6PQaOKi2c0e5NItwnh9wBaOk9PcVgkemM4BcVB1AZ+8HlhzeKOQNJ7Ox
# 4D5JMMNuVKhOmB2tXWLuIVbD4jfXCwGEW7QidrKjW53Kw62V2fBDu6YujewJq031
# sapiH4BQExS7uLSvioD5Ae1mDg4deXuOy7jvCjzn+bSFxh13Sdk+Od4s9u0=
# SIG # End signature block
