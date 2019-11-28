function MobyLinuxBetter {
    Param(
        [string] $VmName = "MobyLinuxVM",
        [string] $IsoFile = $($(Get-ChildItem -Path "C:\Program Files\Docker" -Recurse -File -Filter "docker-for-win.iso").FullName),
        [string] $SwitchName = "DockerNAT",
        [string] $VhdPathOverride = $null,
        [long] $VhdSize = 64*1000*1000*1000,
        [string] $confIsoFile = $null,
        [Parameter(ParameterSetName='Create',Mandatory=$false)][switch] $Create,
        [Parameter(ParameterSetName='Create',Mandatory=$false)][int] $CPUs = 2,
        [Parameter(ParameterSetName='Create',Mandatory=$false)][long] $Memory = 2048,
        [Parameter(ParameterSetName='Create',Mandatory=$false)][string] $SwitchSubnetAddress = "10.0.75.0",
        [Parameter(ParameterSetName='Create',Mandatory=$false)][int] $SwitchSubnetMaskSize = 24,
        [Parameter(ParameterSetName='Destroy',Mandatory=$false)][switch] $Destroy,
        [Parameter(ParameterSetName='Destroy',Mandatory=$false)][switch] $KeepVolume,
        [Parameter(ParameterSetName='Start',Mandatory=$false)][switch] $Start,
        [Parameter(ParameterSetName='Stop',Mandatory=$false)][switch] $Stop
    )

    Write-Host "Script started at $(Get-Date -Format "HH:mm:ss.fff")"

    # Make sure we stop at Errors unless otherwise explicitly specified
    $ErrorActionPreference = "Stop"
    $ProgressPreference = "SilentlyContinue"

    # Explicitly disable Module autoloading and explicitly import the
    # Modules this script relies on. This is not strictly necessary but
    # good practise as it prevents arbitrary errors
    $PSModuleAutoloadingPreference = 'None'

    # Check to see if Hyper-V is installed:
    if ($(Get-Module).Name -notcontains "Dism") {
        # Using full path to Dism Module Manifest because sometimes there are issues with just 'Import-Module Dism'
        $DismModuleManifestPaths = $(Get-Module -ListAvailable -Name Dism).Path

        foreach ($MMPath in $DismModuleManifestPaths) {
            try {
                Import-Module $MMPath -ErrorAction Stop
                break
            }
            catch {
                continue
            }
        }
    }
    if ($(Get-Module).Name -notcontains "Dism") {
        Write-Error "Problem importing the Dism PowerShell Module! Halting!"
        $global:FunctionResult = "1"
        return
    }
    
    $HyperVCheck = Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online
    if ($HyperVCheck.State -ne "Enabled") {
        Write-Error "Please install Hyper-V before proceeding! Halting!"
        $global:FunctionResult = "1"
        return
    }

    function Get-Vhd-Root {
        if($VhdPathOverride){
            return $VhdPathOverride
        }
        # Default location for VHDs
        $VhdRoot = "$((Hyper-V\Get-VMHost -ComputerName localhost).VirtualHardDiskPath)".TrimEnd("\")

        # Where we put Moby
        return "$VhdRoot\$VmName.vhdx"
    }

    function New-Switch {
        $ipParts = $SwitchSubnetAddress.Split('.')
        [int]$switchIp3 = $null
        [int32]::TryParse($ipParts[3] , [ref]$switchIp3 ) | Out-Null
        $Ip0 = $ipParts[0]
        $Ip1 = $ipParts[1]
        $Ip2 = $ipParts[2]
        $Ip3 = $switchIp3 + 1
        $switchAddress = "$Ip0.$Ip1.$Ip2.$Ip3"

        $vmSwitch = Get-VMSwitch $SwitchName -SwitchType Internal -ea SilentlyContinue
        $vmNetAdapter = Get-VMNetworkAdapter -ManagementOS -SwitchName $SwitchName -ea SilentlyContinue
        if ($vmSwitch -and $vmNetAdapter) {
            Write-Host "Using existing Switch: $SwitchName"
        } else {
            Write-Host "Creating Switch: $SwitchName..."

            Remove-VMSwitch $SwitchName -Force -ea SilentlyContinue
            $null = New-VMSwitch $SwitchName -SwitchType Internal -ea SilentlyContinue
            $vmNetAdapter = Get-VMNetworkAdapter -ManagementOS -SwitchName $SwitchName

            Write-Host "Switch created."
        }

        # Make sure there are no lingering net adapter
        $netAdapters = Get-NetAdapter | Where-Object { $_.Name.StartsWith("vEthernet ($SwitchName)") }
        if (($netAdapters).Length -gt 1) {
            Write-Host "Disable and rename invalid NetAdapters"

            $now = (Get-Date -Format FileDateTimeUniversal)
            $index = 1
            $invalidNetAdapters = $netAdapters | Where-Object { $_.DeviceID -ne $vmNetAdapter.DeviceId }

            foreach ($netAdapter in $invalidNetAdapters) {
                $null = Disable-NetAdapter -Name $netAdapter.Name -Confirm:$false
                $null = Rename-NetAdapter -Name $netAdapter.Name -NewName "Broken Docker Adapter ($now) ($index)"
                $index++
            }
        }

        # Make sure the Switch has the right IP address
        $networkAdapter = Get-NetAdapter | Where-Object { $_.DeviceID -eq $vmNetAdapter.DeviceId }
        if ($networkAdapter.InterfaceAlias -eq $(Get-NetIPAddress -IPAddress $switchAddress -ea SilentlyContinue).InterfaceAlias) {
            Disable-NetAdapterBinding -Name $networkAdapter.Name -ComponentID ms_server -ea SilentlyContinue
            Enable-NetAdapterBinding -Name $networkAdapter.Name -ComponentID ms_server -ea SilentlyContinue
            Write-Host "Using existing Switch IP address"
            return
        }

        Remove-NetIPAddress -InterfaceAlias $networkAdapter.InterfaceAlias -Confirm:$false -ea SilentlyContinue
        Set-NetIPInterface -InterfaceAlias $networkAdapter.InterfaceAlias -Dhcp Disabled -ea SilentlyContinue
        New-NetIPAddress -InterfaceAlias $networkAdapter.InterfaceAlias -AddressFamily IPv4 -IPAddress $switchAddress -PrefixLength ($SwitchSubnetMaskSize) -ea Stop | Out-Null
        
        Disable-NetAdapterBinding -Name $networkAdapter.Name -ComponentID ms_server -ea SilentlyContinue
        Enable-NetAdapterBinding -Name $networkAdapter.Name -ComponentID ms_server -ea SilentlyContinue
        Write-Host "Set IP address on switch"
    }

    function Remove-Switch {
        Write-Host "Destroying Switch $SwitchName..."

        # Let's remove the IP otherwise a nasty bug makes it impossible
        # to recreate the vswitch
        $vmNetAdapter = Get-VMNetworkAdapter -ManagementOS -SwitchName $SwitchName -ea SilentlyContinue
        if ($vmNetAdapter) {
            $networkAdapter = Get-NetAdapter | Where-Object { $_.DeviceID -eq $vmNetAdapter.DeviceId }
            Remove-NetIPAddress -InterfaceAlias $networkAdapter.InterfaceAlias -Confirm:$false -ea SilentlyContinue
        }

        Remove-VMSwitch $SwitchName -Force -ea SilentlyContinue
    }

    function New-MobyLinuxVM {
        if (!(Test-Path $IsoFile)) {
            Fatal "ISO file at $IsoFile does not exist"
        }

        $CPUs = [Math]::min((Get-VMHost -ComputerName localhost).LogicalProcessorCount, $CPUs)

        $vm = Get-VM $VmName -ea SilentlyContinue
        if ($vm) {
            if ($vm.Length -ne 1) {
                Fatal "Multiple VMs exist with the name $VmName. Delete invalid ones or reset Docker to factory defaults."
            }
        } else {
            Write-Host "Creating VM $VmName..."

            # Create the Snapshot Directory if it doesn't already exist
            $SnapShotDir = $($VhdPathOverride -split "Virtual Hard Disks")[0] + "Snapshots"
            if (!$(Test-Path $SnapShotDir)) {
                $null = New-Item -ItemType Directory -Path $SnapShotDir -Force
            }

            $vm = Hyper-V\New-VM -Name $VmName -Generation 2 -NoVHD

            $SetVMSplatParams = @{
                Name                    = $VmName
                AutomaticStartAction    = "Nothing"
                AutomaticStopAction     = "ShutDown"
                CheckpointType          = "Production"
                SnapShotFileLocation    = $SnapShotDir
            }
            $null = Hyper-V\Set-VM @SetVMSplatParams
        }

        if ($vm.Generation -ne 2) {
            Fatal "VM $VmName is a Generation $($vm.Generation) VM. It should be a Generation 2."
        }

        if ($vm.State -ne "Off") {
            Write-Host "VM $VmName is $($vm.State). Cannot change its settings."
            return
        }

        Write-Host "Setting CPUs to $CPUs and Memory to $Memory MB"
        $Memory = ([Math]::min($Memory, (Hyper-V\Get-VMMemory -VMName $VMName).MaximumPerNumaNode))
        Hyper-V\Set-VM -Name $VMName -MemoryStartupBytes ($Memory*1024*1024) -ProcessorCount $CPUs -StaticMemory

        $VmVhdFile = Get-Vhd-Root
        $vhd = Get-VHD -Path $VmVhdFile -ea SilentlyContinue

        # Fix permissions on "$env:SystemDrive\Users\Public" and "$env:SystemDrive\ProgramData\Microsoft\Windows\Hyper-V"
        # the because lots of software (like Docker) likes throwing stuff in these locations
        #$PublicUserDirectoryPath = "$env:SystemDrive\Users\Public"
        $PublicUserDirectoryPath = "$env:SystemDrive\Users\Public\Documents\Hyper-V"
        $HyperVConfigDir = "$env:SystemDrive\ProgramData\Microsoft\Windows\Hyper-V"
        $DockerProgramData = "C:\ProgramData\Docker"
        [System.Collections.ArrayList]$DirsToPotentiallyFix = @($PublicUserDirectoryPath,$HyperVConfigDir,$DockerProgramData)
        
        foreach ($dir in $DirsToPotentiallyFix) {
            if (Test-Path $dir) {
                try {
                    if ($PSVersionTable.PSEdition -eq "Core") {
                        [System.Collections.ArrayList]$ArgsToPass = @()
                        $null = $ArgsToPass.Add($dir)
                        foreach ($FuncString in $script:FunctionsForSBUse) {$null = $ArgsToPass.Add($FuncString)}
            
                        $FixPermissionsResult = Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                            $args[1..$($args.Count-1)] | foreach {Invoke-Expression $_}
                            FixNTVirtualMachinesPerms -DirectoryPath $args[0]
                        } -ArgumentList $ArgsToPass
                    }
                    else {
                        FixNTVirtualMachinesPerms -DirectoryPath $dir
                    }
                }
                catch {
                    Write-Error $_
                    Write-Error "The FixNTVirtualMachinesPerms function failed! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
        }

        if (!$vhd) {
            Write-Host "Creating dynamic VHD: $VmVhdFile"
            $vhd = New-VHD -ComputerName localhost -Path $VmVhdFile -Dynamic -SizeBytes $VhdSize
        }

        if ($vm.HardDrives.Path -ne $VmVhdFile) {
            if ($vm.HardDrives) {
                Write-Host "Remove existing VHDs"
                Hyper-V\Remove-VMHardDiskDrive $vm.HardDrives -ea SilentlyContinue
            }

            Write-Host "Attach VHD $VmVhdFile"
            Add-VMHardDiskDrive -VMName $vm.Name -Path $VmVhdFile
        }

        $vmNetAdapter = Get-VMNetworkAdapter -VMName $vm.Name
        if (!$vmNetAdapter) {
            Write-Host "Attach Net Adapter"
            $vmNetAdapter = Hyper-V\Add-VMNetworkAdapter -VMName $VMName -SwitchName $SwitchName -Passthru
        }

        Write-Host "Connect Internal Switch $SwitchName"
        Hyper-V\Connect-VMNetworkAdapter -VMName $VMName -SwitchName $SwitchName
        #Connect-VMNetworkAdapter -VMName $vm.Name -Name $vmNetAdapter.Name -SwitchName $SwitchName
        #$vmNetAdapter | Hyper-V\Connect-VMNetworkAdapter -VMSwitch $(Hyper-V\Get-VMSwitch -ComputerName localhost $SwitchName -SwitchType Internal)

        if ($vm.DVDDrives) {
            Write-Host "Remove existing DVDs"
            $ExistingDvDDriveInfo = Get-VMDvdDrive -VMName $VMName
            Hyper-V\Remove-VMDvdDrive -VMName $VMName -ControllerNumber $ExistingDvDDriveInfo.ControllerNumber -ControllerLocation $ExistingDvDDriveInfo.ControllerLocation
        }

        Write-Host "Attach DVD $IsoFile"
        Add-VMDvdDrive -VMName $vm.Name -Path $IsoFile

        if ($PSVersionTable.PSEdition -eq "Core") {
            Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                $iso = Get-VMFirmware -VMName $args[0] | Select-Object -ExpandProperty BootOrder | Where-Object { $_.FirmwarePath.EndsWith("Scsi(0,1)") }
                Set-VMFirmware -VMName $args[0] -EnableSecureBoot Off -FirstBootDevice $iso
                Set-VMComPort -VMName $args[0] -number 1 -Path "\\.\pipe\docker$($args[0])-com1"
            } -ArgumentList $VmName
        }
        else {
            $iso = Get-VMFirmware -VMName $vm.Name | Select-Object -ExpandProperty BootOrder | Where-Object { $_.FirmwarePath.EndsWith("Scsi(0,1)") }
            Set-VMFirmware -VMName $vm.Name -EnableSecureBoot Off -FirstBootDevice $iso
            Set-VMComPort -VMName $vm.Name -number 1 -Path "\\.\pipe\docker$VmName-com1"
        }

        # Enable only required VM integration services
        <#
        $intSvc = @()
        $intSvc += "Microsoft:$($vm.Id)\84EAAE65-2F2E-45F5-9BB5-0E857DC8EB47" # Heartbeat
        $intSvc += "Microsoft:$($vm.Id)\9F8233AC-BE49-4C79-8EE3-E7E1985B2077" # Shutdown
        $intSvc += "Microsoft:$($vm.Id)\2497F4DE-E9FA-4204-80E4-4B75C46419C0" # TimeSynch
        #>
        $DesiredIntegrationServices = @(
            "Heartbeat"
            "Shutdown"
            "Guest Service Interface"
            "Key-Value Pair Exchange"
            "Time Synchronization"
        )

        $CurrentIntegrationServices = Get-VMIntegrationService -VMName $vm.Name
        foreach ($IntegrationService in $CurrentIntegrationServices) {
            if ($DesiredIntegrationServices -contains $IntegrationService.Name -and !$IntegrationService.Enabled) {
                $null = Enable-VMIntegrationService -VMName $vm.Name -Name $IntegrationService.Name
                Write-Host "Enabled $($IntegrationService.Name)"
            } else {
                $null = Disable-VMIntegrationService -VMName $vm.Name -Name $IntegrationService.Name
                Write-Host "Disabled $($IntegrationService.Name)"
            }
        }
        #$vm | Hyper-V\Disable-VMConsoleSupport
        Hyper-V\Enable-VMConsoleSupport -VMName $VMName

        Write-Host "VM created."
    }

    function Remove-MobyLinuxVM {
        Write-Host "Removing VM $VmName..."

        Remove-VM $VmName -Force -ea SilentlyContinue

        if (!$KeepVolume) {
            $VmVhdFile = Get-Vhd-Root
            Write-Host "Delete VHD $VmVhdFile"
            Remove-Item $VmVhdFile -ea SilentlyContinue
        }
    }

    function Start-MobyLinuxVM {
        Write-Host "Starting VM $VmName..."

        $vm = Get-VM $VmName -ea SilentlyContinue

        if ($vm.DVDDrives) {
            Write-Host "Remove existing DVDs"
            Remove-VMDvdDrive $vm.DVDDrives -ea SilentlyContinue
        }

        Write-Host "Attach DVD $IsoFile"
        Add-VMDvdDrive -VMName $vm.Name -ControllerNumber 0 -ControllerLocation 1 -Path $IsoFile

        if (Test-Path $confIsoFile) {
            if ((Get-Item $confIsoFile).length -gt 0) {
                Write-Host "Attach Config ISO $confIsoFile"
                if ((Get-VMScsiController -VMName $vm.Name).length -le 1) {
                    Add-VMScsiController -VMName $vm.Name
                }
                Add-VMDvdDrive -VMName $vm.Name -ControllerNumber 1 -ControllerLocation 1 -Path $confIsoFile
            }
        }
        
        if ($PSVersionTable.PSEdition -eq "Core") {
            Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                $iso = Get-VMFirmware -VMName $args[0] | Select-Object -ExpandProperty BootOrder | Where-Object { $_.FirmwarePath.EndsWith("Scsi(0,1)") }
                Set-VMFirmware -VMName $args[0] -EnableSecureBoot Off -BootOrder $iso
            } -ArgumentList $VmName
        }
        else {
            $iso = Get-VMFirmware -VMName $vm.Name | Select-Object -ExpandProperty BootOrder | Where-Object { $_.FirmwarePath.EndsWith("Scsi(0,1)") }
            Set-VMFirmware -VMName $vm.Name -EnableSecureBoot Off -BootOrder $iso
        }

        Start-VM -VMName $VmName
    }

    function Stop-MobyLinuxVM {
        $vms = Get-VM $VmName -ea SilentlyContinue
        if (!$vms) {
            Write-Host "VM $VmName does not exist"
            return
        }

        foreach ($vm in $vms) {
            Stop-VM-Force($vm)
        }
    }

    function Stop-VM-Force {
        Param($vm)

        if ($vm.State -eq 'Off') {
            Write-Host "VM $VmName is stopped"
            return
        }

        $vmId = $vm.VMId.Guid

        $code = {
            #Param($vmId) # Passing the $vm ref is not possible because it will be disposed already

            $vm = Hyper-V\Get-VM -Name $VmName -ea SilentlyContinue
            if (!$vm) {
                Write-Host "VM with Name $VmName does not exist"
                return
            }

            $shutdownService = Hyper-V\Get-VMIntegrationService -VMName $VmName -Name Shutdown -ea SilentlyContinue
            if ($shutdownService -and $shutdownService.PrimaryOperationalStatus -eq 'Ok') {
                Write-Host "Shutdown VM $VmName..."
                Hyper-V\Stop-VM -VMName $vm.Name -Confirm:$false -Force -ea SilentlyContinue
                if ($vm.State -eq 'Off') {
                    return
                }
            }

            Write-Host "Turn Off VM $VmName..."
            Hyper-V\Stop-VM -VMName $vm.Name -Confirm:$false -TurnOff -Force -ea SilentlyContinue
        }

        Write-Host "Stopping VM $VmName..."
        $null = New-Runspace -RunspaceName "StopVM$VmName" -ScriptBlock $code
        $Counter = 0
        while ($(Hyper-V\Get-VM -Name $VmName).State -ne "Off") {
            Write-Verbose "Waiting for $VmName to Stop..."
            Start-Sleep -Seconds 5
            $Counter++
        }

        $vm = Hyper-V\Get-VM -Name $VmName -ea SilentlyContinue
        if ($vm.State -eq 'Off') {
            Write-Host "VM $VmName is stopped"
            return
        }

        # If the VM cannot be stopped properly after the timeout
        # then we have to kill the process and wait till the state changes to "Off"
        for ($count = 1; $count -le 10; $count++) {
            $ProcessID = (Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_ComputerSystem -Filter "Name = '$vmId'").ProcessID
            if (!$ProcessID) {
                Write-Host "VM $VmName killed. Waiting for state to change"
                for ($count = 1; $count -le 20; $count++) {
                    $vm = Hyper-V\Get-VM -Name $VmName -ea SilentlyContinue
                    if ($vm.State -eq 'Off') {
                        Write-Host "Killed VM $VmName is off"
                        #Remove-Switch
                        $oldKeepVolumeValue = $KeepVolume
                        $KeepVolume = $true
                        Remove-HyperVVM
                        $KeepVolume = $oldKeepVolumeValue
                        return
                    }
                    Start-Sleep -Seconds 1
                }
                Fatal "Killed VM $VmName did not stop"
            }

            if ($ProcessID) {
                Write-Host "Kill VM $VmName process..."
                Stop-Process $ProcessID -Force -Confirm:$false -ea SilentlyContinue
            }
            Start-Sleep -Seconds 1
        }

        Fatal "Couldn't stop VM $VmName"
    }

    function Fatal {
        throw "$args"
        return 1
    }

    # Main entry point
    Try {
        Switch ($PSBoundParameters.GetEnumerator().Where({$_.Value -eq $true}).Key) {
            'Stop'     { Stop-MobyLinuxVM }
            'Destroy'  { Stop-MobyLinuxVM; Remove-Switch; Remove-MobyLinuxVM }
            'Create'   { New-Switch; New-MobyLinuxVM }
            'Start'    { Start-MobyLinuxVM }
        }
    } Catch {
        throw
        return 1
    }
}

# SIG # Begin signature block
# MIIMaAYJKoZIhvcNAQcCoIIMWTCCDFUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUTT8lvwPhjXv4VLyjvbspKmbG
# ui2gggndMIIEJjCCAw6gAwIBAgITawAAADqEP46TDmc/hQAAAAAAOjANBgkqhkiG
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
# BDEWBBRwfoYYg87/feUGTx1+C3e7Yb9ofTANBgkqhkiG9w0BAQEFAASCAQBDu7QT
# vin7XCBU7vronR7z5y9108oOnBzaPjxsEFjEH/+oUNwZQAOiNQRStjmIbCu999qZ
# Ne3e0K5VWkaBPQTSNlgEyY7iYSKzxhpnoKJpiGFh5GuZkkkVPrJFvG4ZG+xH21fh
# LDsLYA5YTYxSLUY81AgGn+YTxhye3wfHjxOug9xyUVhYvZlrBRxUUo3s6OAxRKGs
# ZBdWwdgz25/lnGRR5nWM0LD7+Lk+/b8zsCxqsCM5KyUFITWu2m9dBTZzUFuTNlKn
# uoqZ7/JmfYBvSkuNbYHP5kVcOpstIWVxL40RCMq52CEBmexvMVE34WqdQ8T9eNZS
# CQsRgYtAAjFoNPgX
# SIG # End signature block
