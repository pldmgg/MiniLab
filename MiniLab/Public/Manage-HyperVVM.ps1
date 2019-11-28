<#
    .SYNOPSIS
        Manages a HyperV VM.

        This is a refactor of the PowerShell Script used to deploy a MobyLinux VM on Hyper-V during a Docker CE install.
        The refactor was done mostly to fix permissions issues that occur when running Hyper-V on a Guest VM in order
        to deploy a Nested VM, but it also works just fine on baremetal Hyper-V.

    .DESCRIPTION
        Creates/Destroys/Starts/Stops A HyperV VM

        This function is a refactored version of MobyLinux.ps1 that is bundled with a DockerCE install.

        This function deploys newly created VMs to "C:\Users\Public\Documents". This location is hardcoded for now.

    .PARAMETER VmName
        If passed, use this name for the HyperV VM

    .PARAMETER IsoFile
        Path to the ISO image, must be set for Create/ReCreate

    .PARAMETER SwitchName
        Name of the switch you want to attatch to your new VM.

    .PARAMETER VMGen
        Generation of the VM you would like to create. Can be either 1 or 2. Defaults to 2.

    .PARAMETER VhdSize
        Uint64 value representing size of new .vhd/.vhdx. Example: [uint64]30GB

    .PARAMETER PreferredIntegrationServices
        List of Hyper-V Integration Services you would like enabled for your new VM.
        Valid values are: "Heartbeat","Shutdown","TimeSynch","GuestServiceInterface","KeyValueExchange","VSS"

        Defaults to enabling: "Heartbeat","Shutdown","TimeSynch","GuestServiceInterface","KeyValueExchange"

    .PARAMETER VhdPathOverride
        By default, VHD file(s) for the new VM are stored under "C:\Users\Public\Documents\HyperV".

        If you want VHD(s) stored elsewhere, provide this parameter with a full path to a directory.

    .PARAMETER NoVhd
        This parameter is a switch. Use it to create a new VM without a VHD. For situations where
        you want to attach a VHD later.

    .PARAMETER Create
        Create a HyperV VM

    .PARAMETER CPUs
        CPUs used in the VM (optional on Create, default: min(2, number of CPUs on the host))

    .PARAMETER Memory
        Memory allocated for the VM at start in MB (optional on Create, default: 2048 MB)

    .PARAMETER Destroy
        Remove a HyperV VM

    .PARAMETER KeepVolume
        If passed, will not delete the VHD on Destroy

    .PARAMETER Start
        Start an existing HyperV VM

    .PARAMETER Stop
        Stop a running HyperV VM

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Manage-HyperVVM -VMName "TestVM" -SwitchName "ToMgmt" -IsoFile .\mobylinux.iso -VMGen 1 -Create

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Manage-HyperVVM -VMName "TestVM" -SwitchName "ToMgmt" -VHDPathOverride "C:\Win1016Serv.vhdx" -VMGen 2 -Memory 4096 -Create
#>
function Manage-HyperVVM {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$VmName,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='Create'
        )]
        [string]$IsoFile,

        [Parameter(
            Mandatory=$True,
            ParameterSetName='Create'    
        )]
        [string]$SwitchName,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='Create'    
        )]
        [ValidateSet(1,2)]
        [int]$VMGen = 2,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='Create'    
        )]
        [uint64]$VhdSize,

        [Parameter(
            Mandatory=$False,
            ParameterSetName='Create'
        )]
        [ValidateSet("Heartbeat","Shutdown","Time Synchronization","Guest Service Interface","Key-Value Pair Exchange","VSS")]
        [string[]]$PreferredIntegrationServices = @("Heartbeat","Shutdown","Time Synchronization","Guest Service Interface","Key-Value Pair Exchange"),

        [Parameter(Mandatory=$False)]
        [string]$VhdPathOverride,

        [Parameter(Mandatory=$False)]
        [switch]$NoVhd,
        
        [Parameter(
            Mandatory=$False,
            ParameterSetName='Create'
        )]
        [switch]$Create,
        
        [Parameter(
            Mandatory=$False,
            ParameterSetName='Create'
        )]
        [int]$CPUs = 1,
        
        [Parameter(
            Mandatory=$False,
            ParameterSetName='Create'
        )]
        [long]$Memory = 2048,
        
        [Parameter(
            Mandatory=$False,
            ParameterSetName='Destroy'
        )]
        [switch]$Destroy,
        
        [Parameter(
            Mandatory=$False,
            ParameterSetName='Destroy'
        )]
        [switch]$KeepVolume,
        
        [Parameter(
            Mandatory=$False,
            ParameterSetName='Start'
        )]
        [switch]$Start,
        
        [Parameter(
            Mandatory=$False,
            ParameterSetName='Stop'
        )]
        [switch]$Stop
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    # This is only a problem for Windows_Server_2016_14393.0.160715-1616.RS1_RELEASE_SERVER_EVAL_X64FRE_EN-US (technet_official).ISO
    <#
    if ($IsoFile) {
        if ($IsoFile -notmatch "C:\\Users\\Public") {
            Write-Error "The ISO File used to install the new VM's Operating System must be placed somewhere under 'C:\Users\Public' due to permissions issues! Halting!"
            $global:FunctionResult = "1"
            return       
        }
    }
    #>

    # Make sure we stop at Errors unless otherwise explicitly specified
    $ErrorActionPreference = "Stop"
    $ProgressPreference = "SilentlyContinue"

    # Explicitly disable Module autoloading and explicitly import the
    # Modules this script relies on. This is not strictly necessary but
    # good practise as it prevents arbitrary errors
    # More Info: https://blogs.msdn.microsoft.com/timid/2014/09/02/psmoduleautoloadingpreference-and-you/
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

    Write-Host "Script started at $(Get-Date -Format "HH:mm:ss.fff")"

    # Hard coded for now
    if (!$VhdSize) {
        $VhdSize = [uint64]30GB
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Helper Functions #####

    function Get-Vhd-Root {
        if($VhdPathOverride){
            return $VhdPathOverride
        }
        # Default location for VHDs
        $VhdRoot = "$((Hyper-V\Get-VMHost -ComputerName localhost).VirtualHardDiskPath)".TrimEnd("\")

        # Where we put the Nested VM
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

    function New-HyperVVM {
        <#
        if (!(Test-Path $IsoFile)) {
            Fatal "ISO file at $IsoFile does not exist"
        }
        #>

        $CPUs = [Math]::min((Hyper-V\Get-VMHost -ComputerName localhost).LogicalProcessorCount, $CPUs)

        $vm = Hyper-V\Get-VM $VmName -ea SilentlyContinue
        if ($vm) {
            if ($vm.Length -ne 1) {
                Fatal "Multiple VMs exist with the name $VmName. Delete invalid ones and try again."
            }
        }
        else {
            # Create the Snapshot Directory if it doesn't already exist
            $SnapShotDir = $($VhdPathOverride -split "Virtual Hard Disks")[0] + "Snapshots"
            if (!$(Test-Path $SnapShotDir)) {
                $null = New-Item -ItemType Directory -Path $SnapShotDir -Force
            }

            Write-Host "Creating VM $VmName..."
            $vm = Hyper-V\New-VM -Name $VmName -Generation $VMGen -NoVHD

            $SetVMSplatParams = @{
                Name                    = $VmName
                AutomaticStartAction    = "Nothing"
                AutomaticStopAction     = "ShutDown"
                CheckpointType          = "Production"
                SnapShotFileLocation    = $SnapShotDir
            }
            $null = Hyper-V\Set-VM @SetVMSplatParams
        }

        <#
        if ($vm.Generation -ne 2) {
            Fatal "VM $VmName is a Generation $($vm.Generation) VM. It should be a Generation 2."
        }
        #>

        if ($vm.State -ne "Off") {
            Write-Host "VM $VmName is $($vm.State). Cannot change its settings."
            return
        }

        Write-Host "Setting CPUs to $CPUs and Memory to $Memory MB"
        $Memory = ([Math]::min($Memory, (Hyper-V\Get-VMMemory -VMName $VMName).MaximumPerNumaNode))
        Hyper-V\Set-VM -Name $VMName -MemoryStartupBytes ($Memory*1024*1024) -ProcessorCount $CPUs -StaticMemory

        if (!$NoVhd) {
            $VmVhdFile = Get-Vhd-Root
            $vhd = Get-VHD -Path $VmVhdFile -ea SilentlyContinue
            
            if (!$vhd) {
                Write-Host "Creating dynamic VHD: $VmVhdFile"
                $vhd = New-VHD -ComputerName localhost -Path $VmVhdFile -Dynamic -SizeBytes $VhdSize
            }

            ## BEGIN Try and Update Permissions ##
            
            if ($($VMVhdFile -split "\\")[0] -eq $env:SystemDrive) {
                if ($VMVhdFile -match "\\Users\\") {
                    $UserDirPrep = $VMVHdFile -split "\\Users\\"
                    $UserDir = $UserDirPrep[0] + "\Users\" + $($UserDirPrep[1] -split "\\")[0]
                    # We can assume there is at least one folder under $HOME before getting to the .vhd file
                    $DirectoryThatMayNeedPermissionsFixPrep = $UserDir + '\' + $($UserDirPrep[1] -split "\\")[1]
                    
                    # If $DirectoryThatMayNeedPermissionsFixPrep isn't a SpecialFolder typically found under $HOME
                    # then assume we can mess with permissions. Else, target one directory deeper.
                    $HomeDirCount = $($HOME -split '\\').Count
                    $SpecialFoldersDirectlyUnderHomePrep = [enum]::GetNames('System.Environment+SpecialFolder') | foreach {
                        [environment]::GetFolderPath($_)
                    } | Sort-Object | Get-Unique | Where-Object {$_ -match "$($HOME -replace '\\','\\')"}
                    $SpecialFoldersDirectlyUnderHome = $SpecialFoldersDirectlyUnderHomePrep | Where-Object {$($_ -split '\\').Count -eq $HomeDirCount+1}

                    if ($SpecialFoldersDirectlyUnderHome -notcontains $DirectoryThatMayNeedPermissionsFixPrep) {
                        $DirectoryThatMayNeedPermissionsFix = $DirectoryThatMayNeedPermissionsFixPrep
                    }
                    else {
                        # Go one folder deeper...
                        $DirectoryThatMayNeedPermissionsFix = $UserDir + '\' + $($UserDirPrep[1] -split "\\")[1] + '\' + $($UserDirPrep[1] -split "\\")[2]
                    }

                    try {
                        if ($PSVersionTable.PSEdition -eq "Core") {
                            [System.Collections.ArrayList]$ArgsToPass = @()
                            $null = $ArgsToPass.Add($DirectoryThatMayNeedPermissionsFix)
                            foreach ($FuncString in $script:FunctionsForSBUse) {$null = $ArgsToPass.Add($FuncString)}
                
                            $FixPermissionsResult = Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                                $args[1..$($args.Count-1)] | foreach {Invoke-Expression $_}
                                FixNTVirtualMachinesPerms -DirectoryPath $args[0]
                            } -ArgumentList $ArgsToPass
                        }
                        else {
                            FixNTVirtualMachinesPerms -DirectoryPath $DirectoryThatMayNeedPermissionsFix
                        }
                    }
                    catch {
                        Write-Error $_
                        Write-Error "The FixNTVirtualMachinesPerms function failed! Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                }
                else {
                    $DirectoryThatMayNeedPermissionsFix = $VMVhdFile | Split-Path -Parent

                    try {
                        if ($PSVersionTable.PSEdition -eq "Core") {
                            [System.Collections.ArrayList]$ArgsToPass = @()
                            $null = $ArgsToPass.Add($DirectoryThatMayNeedPermissionsFix)
                            foreach ($FuncString in $script:FunctionsForSBUse) {$null = $ArgsToPass.Add($FuncString)}
                
                            $FixPermissionsResult = Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                                $args[1..$($args.Count-1)] | foreach {Invoke-Expression $_}
                                FixNTVirtualMachinesPerms -DirectoryPath $args[0]
                            } -ArgumentList $ArgsToPass
                        }
                        else {
                            FixNTVirtualMachinesPerms -DirectoryPath $DirectoryThatMayNeedPermissionsFix
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
            
            # Also fix permissions on "$env:SystemDrive\Users\Public" and "$env:SystemDrive\ProgramData\Microsoft\Windows\Hyper-V"
            # the because lots of software (like Docker) likes throwing stuff in these locations
            $PublicUserDirectoryPath = "$env:SystemDrive\Users\Public"
            $HyperVConfigDir = "$env:SystemDrive\ProgramData\Microsoft\Windows\Hyper-V"
            [System.Collections.ArrayList]$DirsToPotentiallyFix = @($PublicUserDirectoryPath,$HyperVConfigDir)
            
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

            ## END Try and Update Permissions ##

            if ($vm.HardDrives.Path -ne $VmVhdFile) {
                if ($vm.HardDrives) {
                    Write-Host "Remove existing VHDs"
                    Hyper-V\Remove-VMHardDiskDrive $vm.HardDrives -ea SilentlyContinue
                }

                Write-Host "Attach VHD $VmVhdFile"
                $null = Hyper-V\Add-VMHardDiskDrive -VMName $VMName -Path $VmVhdFile
            }
        }

        $vmNetAdapter = Hyper-V\Get-VMNetworkAdapter -VMName $VMName
        if (!$vmNetAdapter) {
            Write-Host "Attach Net Adapter"
            $vmNetAdapter = Hyper-V\Add-VMNetworkAdapter -VMName $VMName -SwitchName $SwitchName -Passthru
        }

        Write-Host "Connect Switch $SwitchName"
        Hyper-V\Connect-VMNetworkAdapter -VMName $VMName -SwitchName $SwitchName

        if ($IsoFile) {
            if ($vm.DVDDrives.Path -ne $IsoFile) {
                if ($vm.DVDDrives) {
                    Write-Host "Remove existing DVDs"
                    $ExistingDvDDriveInfo = Get-VMDvdDrive -VMName $VMName
                    Hyper-V\Remove-VMDvdDrive -VMName $VMName -ControllerNumber $ExistingDvDDriveInfo.ControllerNumber -ControllerLocation $ExistingDvDDriveInfo.ControllerLocation
                }

                Write-Host "Attach DVD $IsoFile"
                Hyper-V\Add-VMDvdDrive -VMName $VMName -Path $IsoFile
            }

            # Ensure $IsoFile is the first boot device
            $iso = Get-VMFirmware -VMName $vm.Name | Select-Object -ExpandProperty BootOrder | Where-Object { $_.FirmwarePath.EndsWith("Scsi(0,1)") }
            Set-VMFirmware -VMName $vm.Name -EnableSecureBoot Off -FirstBootDevice $iso
        }

        <#
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
        #>

        # Enable only prefered VM integration services
        [System.Collections.ArrayList]$intSvc = @()
        foreach ($integrationService in $PreferredIntegrationServices) {
            switch ($integrationService) {
                'Heartbeat'                 { $null = $intSvc.Add("Microsoft:$($vm.Id)\84EAAE65-2F2E-45F5-9BB5-0E857DC8EB47") }
                'Shutdown'                  { $null = $intSvc.Add("Microsoft:$($vm.Id)\9F8233AC-BE49-4C79-8EE3-E7E1985B2077") }
                'Time Synchronization'      { $null = $intSvc.Add("Microsoft:$($vm.Id)\2497F4DE-E9FA-4204-80E4-4B75C46419C0") }
                'Guest Service Interface'   { $null = $intSvc.Add("Microsoft:$($vm.Id)\6C09BB55-D683-4DA0-8931-C9BF705F6480") }
                'Key-Value Pair Exchange'   { $null = $intSvc.Add("Microsoft:$($vm.Id)\2A34B1C2-FD73-4043-8A5B-DD2159BC743F") }
                'VSS'                       { $null = $intSvc.Add("Microsoft:$($vm.Id)\5CED1297-4598-4915-A5FC-AD21BB4D02A4") }
            }
        }
        
        Hyper-V\Get-VMIntegrationService -VMName $VMName | foreach {
            if ($PreferredIntegrationServices -contains $_.Name) {
                $null = Hyper-V\Enable-VMIntegrationService -VMName $VMName -Name $_.Name
                Write-Host "Enabled $($_.Name)"
            }
            else {
                $null = Hyper-V\Disable-VMIntegrationService -VMName $VMName -Name $_.Name
                Write-Host "Disabled $($_.Name)"
            }
        }
        #$vm | Hyper-V\Disable-VMConsoleSupport
        Hyper-V\Enable-VMConsoleSupport -VMName $VMName

        Write-Host "VM created."
    }

    function Remove-HyperVVM {
        Write-Host "Removing VM $VmName..."

        Hyper-V\Remove-VM $VmName -Force -ea SilentlyContinue

        if (!$KeepVolume) {
            $VmVhdFile = Get-Vhd-Root
            Write-Host "Delete VHD $VmVhdFile"
            Remove-Item $VmVhdFile -ea SilentlyContinue
        }
    }

    function Start-HyperVVM {
        Write-Host "Starting VM $VmName..."
        Hyper-V\Start-VM -VMName $VmName
    }

    function Stop-HyperVVM {
        $vms = Hyper-V\Get-VM $VmName -ea SilentlyContinue
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
            'Stop'     { Stop-HyperVVM }
            'Destroy'  { Stop-HyperVVM; Remove-HyperVVM }
            'Create'   { New-HyperVVM }
            'Start'    { Start-HyperVVM }
        }
    } Catch {
        throw
        return 1
    }
}

# SIG # Begin signature block
# MIIMaAYJKoZIhvcNAQcCoIIMWTCCDFUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUJX6YK5yCKNKKhe2xwq156tDo
# LDygggndMIIEJjCCAw6gAwIBAgITawAAADqEP46TDmc/hQAAAAAAOjANBgkqhkiG
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
# BDEWBBQxF5mc6lJihaUrXjY/D5j1bxzEsjANBgkqhkiG9w0BAQEFAASCAQAH2WUr
# JMcj4I5bwuOfN9/X+otYJpSQDyvvX9dWcwRsTGhUUlQdg65w3Skb1W1PF7jxYc0R
# iF+n5zqI2RtV+tu1XIgUN0q4LB28BYYWVW56rDef3u+SkgzzuEwOQIufKUrg9qim
# 6P+LOy7m3T9xht+F36MDl44e7Uh65jM0f7dP/FcBoNMdYt757DEThGy/vF5zQwmW
# 20WLYKA4pB7sxV9gqGDrCNR4KRFI5FwsFUBUPjOwbGF1JeSnHN3fZVk8NCisllcA
# 8lJPcIfCFUpCtw9dqQGuBgz9FTEMXtQHWlbk8BMn0lzr7Adi06l77B9hLMJTK0dT
# p7gINuZd4xxiLESe
# SIG # End signature block
