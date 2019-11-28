<#
    .SYNOPSIS
        This function is meant to be used in situations where Docker-For-Windows (Docker CE) is being installed
        on a Windows Guest VM (as opposed to Bare Metal). It gathers a lot of information about the Windows
        Guest VM, as well as its Hyper-V hypervisor (if appropriate credentials are provided). The function can
        be run from anywhere as long as it's pointed at a Guest VM (via the -TargetHostNameOrIP or -TargetVM parameters).

        If you do not have access to the Guest VM's hypervisor or if the hypervisor is not Hyper-V, make sure to
        use the -TryWithoutHypervisorInfo switch.

    .DESCRIPTION
        See .SYNOPSIS

    .PARAMETER TargetHostNameOrIP
        This parameter is OPTIONAL.

        This parameter takes a string that represents the IP Address, DNS-Resolvable HostName, or FQDN
        of the Guest VM that you would like to gather info from. If it is NOT used (and if
        the -TargetVMName parameter is not used), the function will assume that the localhost
        is the Guest VM that you would like to gather information about.

    .PARAMETER TargetVMName
        This parameter is MANDATORY (for its parameter set).

        This parameter takes a string that represents the name of the Hyper-V VM that you would like
        to gather info from. Using this parameter requires that you use the -HypervisorFQDNOrIP
        and -HypervisorCreds parameters, unless the localhost IS the Hyper-V hypervisor.

    .PARAMETER HypervisorFQDNOrIP
        This parameter is OPTIONAL.

        This parameter takes a string that represents the IP, DNS-Resolvable HostName, or FQDN of the
        Hyper-V hypervisor that is managing the Guest VM that you would like to gather info from. If
        the localhost is NOT the Hyper-V hypervisor and if you are NOT using the -TryWithoutHypervisorInfo
        switch, then this parameter becomes MANDATORY.
        
    .PARAMETER TargetHostNameCreds
        This parameter is OPTIONAL.

        This parameter takes a pscredential object that contains credentials with permission to access
        the Guest VM that you would like to gather info from. If the localhost is the Guest VM target, or
        if you are logged in as a user that already has access to the Guest VM, then you do NOT need to use
        this parameter.

    .PARAMETER HypervisorCreds
        This parameter is OPTIONAL.

        This parameter takes a pscredential object that contains credentials with permission to access
        the Hyper-V hypervisor that is managing the Guest VM that you would like to gather info from. If
        the localhost IS the Hyper-V hypervisor, or if you are logged in as a user that already has access
        to the Hyper-V hypervisor, then you do NOT need to use this parameter.

    .PARAMETER TryWithoutHypervisorInfo
        This parameter is OPTIONAL.

        This parameter is a switch. If used, this function will not attempt to gather any information about
        the hypervisor managing the target Guest VM. Be sure to use this switch if you do not have access
        to the hypervisor or if the hypervisor is not Hyper-V.

    .PARAMETER AllowRestarts
        This parameter is OPTIONAL.

        This parameter is a switch.

        By default, this function installs Hyper-V on the target Guest VM is it isn't already. This is part
        of a test that is used to determine if an External vSwitch attached to a Nested VM on the Guest VM
        can actually reach an outside network.

        If Hyper-V has not already been installed on the target Guest VM, then a restart will be required.
        You can use this switch to allow the Guest VM to restart. The function will remain in a holding
        pattern until the Guest VM comes back online, so you will NOT need to run this function twice.

    .PARAMETER NoMacAddressSpoofing
        This parameter is OPTIONAL.

        This parameter is a switch. If used, this function will NOT conduct the test to determine if
        an External vSwitch attached to a Nested VM on the Guest VM can reach an outside network. In other
        words, the assumption will be that all Nested VMs will be on a Hyper-V Internal network on
        the Guest VM.

        HOWEVER, since it is still possible to configure networking such that Nested VMs on an Internal
        Hyper-V network can reach an outside network, a test will still be conducted to determine if
        an Internal vSwitch attached to a Nested VM can reach an outside network via NAT.

    .PARAMETER SkipHyperVInstallCheck
        This parameter is OPTIONAL.

        This parameter is a switch. If used, this function will assume that Hyper-V is already installed
        on the target Guest VM and not attempt any verification or installation.

    .PARAMETER SkipExternalvSwitchCheck
        This parameter is OPTIONAL.

        This parameter is a switch. If used, this function will NOT conduct the test to determine if
        an External vSwitch attached to a Nested VM on the Guest VM can reach an outside network. In other
        words, the assumption will be that all Nested VMs will be on a Hyper-V Internal network on
        the Guest VM.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-GuestVMAndHypervisorInfo
        
#>
function Get-GuestVMAndHypervisorInfo {
    [CmdletBinding(DefaultParameterSetName='Default')]
    Param(
        [Parameter(
            Mandatory = $False,
            ParameterSetName = 'Default'
        )]
        [string]$TargetHostNameOrIP,

        [Parameter(
            Mandatory=$True,
            ParameterSetName = 'UsingVMName'
        )]
        [string]$TargetVMName,

        [Parameter(Mandatory=$False)]
        [string]$HypervisorFQDNOrIP,

        [Parameter(Mandatory=$False)]
        $TargetHostNameCreds,

        [Parameter(Mandatory=$False)]
        $HypervisorCreds,

        [Parameter(Mandatory=$False)]
        [switch]$TryWithoutHypervisorInfo,

        [Parameter(Mandatory=$False)]
        [switch]$AllowRestarts,

        # -NoMacAddressSpoofing WILL result in creating a Local NAT with an Internal vSwitch on the
        # Target Machine (assuming it's a Guest VM). Maybe change this parameter to 'CreateNAT' instead
        # of 'NoMacAddressSpoofing'
        [Parameter(Mandatory=$False)]
        [switch]$NoMacAddressSpoofing,

        [Parameter(Mandatory=$False)]
        [switch]$SkipHyperVInstallCheck,

        [Parameter(Mandatory=$False)]
        [switch]$SkipExternalvSwitchCheck
    )

    if ($PSBoundParameters['TargetHostNameCreds']) {
        if ($TargetHostNameCreds.GetType().FullName -ne "System.Management.Automation.PSCredential") {
            Write-Error "The object provided to the -TargetHostNameCreds parameter must be a System.Management.Automation.PSCredential! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    if ($PSBoundParameters['HypervisorCreds']) {
        if ($HypervisorCreds.GetType().FullName -ne "System.Management.Automation.PSCredential") {
            Write-Error "The object provided to the -HypervisorCreds parameter must be a System.Management.Automation.PSCredential! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if (!$TargetHostNameOrIP -and !$TargetVMName) {
        $TargetHostNameOrIP = $env:ComputerName
    }

    if ($TargetVMName) {
        if ($TryWithoutHypervisorInfo) {
            $ErrMsg = "Using the -TargetVMName parameter requires that we gather information from " +
            "the hypervisor, but the -TryWithoutHypervisorInfo switch was also supplied. Impossible situation. Halting!"
            Write-Error $ErrMsg
            $global:FunctionResult = "1"
            return
        }

        if (!$HypervisorFQDNOrIP) {
            # Assume that $env:ComputerName is the hypervisor
            $HypervisorFQDNOrIP = $env:ComputerName
            if ($(Get-Module -ListAvailable).Name -notcontains "Hyper-V" -and $(Get-Module).Name -notcontains "Hyper-V") {
                Write-Warning "The localhost $env:ComputerName does not appear to be a hypervisor!"
                $HypervisorFQDNOrIP = Read-Host -Prompt "Please enter the FQDN or IP of the hypervisor that manages $TargetVMName"
            }
        }
    }

    # We only REALLY need to resolve the Hypervisor's network location if we are using $TargetVMName
    if ($HypervisorFQDNOrIP) {
        try {
            $HypervisorNetworkInfo = ResolveHost -HostNameOrIP $HypervisorFQDNOrIP -ErrorAction Stop
        }
        catch {
            if ($TargetVMName) {
                Write-Error "Unable to resolve $HypervisorFQDNOrIP! Halting!"
                $global:FunctionResult = "1"
                return
            }
            else {
                Write-Warning "Unable to resolve $HypervisorFQDNOrIP!"
                # In which case, we need to TryWithoutHypervisorInfo
                $TryWithoutHypervisorInfo = $True
            }
        }
    }

    ## BEGIN $TargetVMName adjudication ##

    if ($TargetVMName) {
        # If $TargetVMName is provided (as opposed to $TargetHostNameOrIP), it is MANDATORY that we get
        # Hyper-V Hypervisor Info. If we can't for whatever reason, we need to HALT.

        # Make sure the $TargetVMName exists on the hypervisor and get some info about it from the Hypervisor's perspective
        if ($HypervisorNetworkInfo.HostName -ne $env:ComputerName) {
            $InvokeCommandSB = {
                try {
                    $TargetVMInfoFromHyperV = Get-VM -Name $using:TargetVMName -ErrorAction Stop
                    $VMProcessorInfo = Get-VMProcessor -VMName $using:TargetVMName
                    $VMNetworkAdapterInfo = Get-VmNetworkAdapter -VmName $using:TargetVMName
                    $VMMemoryInfo = Get-VMMemory -VmName $using:TargetVMName
                }
                catch {
                    Write-Error "Unable to find $using:TargetVMName on $($using:HypervisorNetworkInfo.HostName)!"
                    return
                }

                # Need to Get $HostNameNetworkInfo via Network Adapter IP
                $GuestVMIPAddresses = $TargetVMInfoFromHyperV.NetworkAdapters.IPAddresses

                [pscustomobject]@{
                    HypervisorComputerInfo  = Get-CimInstance Win32_ComputerSystem
                    HypervisorOSInfo        = Get-CimInstance Win32_OperatingSystem
                    TargetVMInfoFromHyperV  = $TargetVMInfoFromHyperV
                    VMProcessorInfo         = $VMProcessorInfo
                    VMNetworkAdapterInfo    = $VMNetworkAdapterInfo
                    VMMemoryInfo            = $VMMemoryInfo
                    GuestVMIPAddresses      = $GuestVMIPAddresses
                }
            }

            $GetWorkingCredsSplatParams = @{
                RemoteHostNameOrIP          = $HypervisorNetworkInfo.FQDN
                ErrorAction                 = "Stop"
            }
            if ($HypervisorCreds) {
                $GetWorkingCredsSplatParams.Add("AltCredentials",$HypervisorCreds)
            }

            try {
                $GetHypervisorCredsInfo = GetWorkingCredentials @GetWorkingCredsSplatParams
                if (!$GetHypervisorCredsInfo.DeterminedCredsThatWorkedOnRemoteHost) {throw "Can't determine working credentials for $($HypervisorNetworkInfo.FQDN)!"}
                
                if ($GetHypervisorCredsInfo.CurrentLoggedInUserCredsWorked -eq $True) {
                    $HypervisorCreds = $null
                }

                $HypervisorInvCmdLocation = $GetHypervisorCredsInfo.RemoteHostWorkingLocation
            }
            catch {
                Write-Error $_
                if ($PSBoundParameters['HypervisorCreds']) {
                    Write-Error "The GetWorkingCredentials function failed! Check the credentials provided to the -HypervisorCreds parameter! Halting!"
                }
                else {
                    Write-Error "The GetWorkingCredentials function failed! Try using the -HypervisorCreds parameter! Halting!"
                }
                $global:FunctionResult = "1"
                return
            }

            $InvCmdSplatParams = @{
                ComputerName        = $HypervisorInvCmdLocation
                ScriptBlock         = $InvokeCommandSB
                ErrorAction         = "Stop"
            }
            if ($HypervisorCreds) {
                $InvCmdSplatParams.Add("Credential",$HypervisorCreds)
            }
            
            try {
                $InvokeCommandOutput = Invoke-Command @InvCmdSplatParams

                $HypervisorComputerInfo = $InvokeCommandOutput.HypervisorComputerInfo
                $HypervisorOSInfo = $InvokeCommandOutput.HypervisorOSInfo
                $TargetVMInfoFromHyperV = $InvokeCommandOutput.TargetVMInfoFromHyperV
                $VMProcessorInfo = $InvokeCommandOutput.VMProcessorInfo
                $VMNetworkAdapterInfo = $InvokeCommandOutput.VMNetworkAdapterInfo
                $VMMemoryInfo = $InvokeCommandOutput.VMMemoryInfo
                $GuestVMIPAddresses = $InvokeCommandOutput.GuestVMIPAddresses
            }
            catch {
                Write-Error $_
                Write-Error "The Get-GuestVMAndHypervisorInfo function was unable to gather information (i.e. `$HypervisorComputerInfo etc) about the Hyper-V host! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        else {
            # Guest VM Info from Hypervisor Perspective
            try {
                $TargetVMInfoFromHyperV = Get-VM -Name $TargetVMName -ErrorAction Stop
                $VMProcessorInfo = Get-VMProcessor -VMName $TargetVMName
                $VMNetworkAdapterInfo = Get-VmNetworkAdapter -VmName $TargetVMName
                $VMMemoryInfo = Get-VMMemory -VmName $TargetVMName
                $HypervisorComputerInfo = Get-CimInstance Win32_ComputerSystem
                $HypervisorOSInfo = Get-CimInstance Win32_OperatingSystem
                $GuestVMIPAddresses = $TargetVMInfoFromHyperV.NetworkAdapters.IPAddresses
            }
            catch {
                Write-Error $_
                Write-Error "The Get-GuestVMAndHypervisorInfo function was unable to gather information (i.e. `$HypervisorComputerInfo etc) about the Hyper-V host! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        # Now, we need to get $HostNameOSInfo and $HostNameComputerInfo
        [System.Collections.ArrayList]$ResolvedIPs = @()
        foreach ($IPAddr in $GuestVMIPAddresses) {
            try {
                $HostNameNetworkInfoPrep = ResolveHost -HostNameOrIP $IPAddr -ErrorAction Stop

                $null = $ResolvedIPs.Add($HostNameNetworkInfoPrep)
            }
            catch {
                Write-Verbose "Unable to resolve $IPAddr"
            }
        }

        # If we didn't resolve any additional info beyond just IP Address, HALT
        if ($ResolvedIP.Count -eq 0 -or ![bool]$($ResolvedIP.HostName -match "[\w]")) {
            Write-Error "Unable to resolve any network information regarding $TargetVMName! Halting!"
            $global:FunctionResult = "1"
            return
        }

        if ($ResolvedIPs.Count -gt 1) {
            # Choose NetworkInfo that is on the same domain as our workstation
            $NTDomainInfo = Get-CimInstance Win32_NTDomain
            foreach ($ResolvedIP in $ResolvedIPs) {
                if ($ResolvedIP.Domain -eq $NTDomainInfo.DnsForestName) {
                    $HostNameNetworkInfo = $ResolvedIP
                }
            }
            # If we still don't have one, pick one that is on the same subnet as our workstation's primary IP
            if (!$HostNameNetworkInfo) {
                $PrimaryIfIndex = $(Get-CimInstance Win32_IP4RouteTable | Where-Object {
                    $_.Destination -eq '0.0.0.0' -and $_.Mask -eq '0.0.0.0'
                } | Sort-Object Metric1)[0].InterfaceIndex
                $NicInfo = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object {$_.InterfaceIndex -eq $PrimaryIfIndex}
                $PrimaryIP = $NicInfo.IPAddress | Where-Object {TestIsValidIPAddress -IPAddress $_}
                $Mask = $NicInfo.IPSubnet | Where-Object {TestIsValidIPAddress -IPAddress $_}
                $IPRange = GetIPRange -ip $PrimaryIP -mask $Mask

                foreach ($ResolvedIP in $ResolvedIPs) {
                    if ($IPRange -contains $ResolvedIP.IPAddressList[0]) {
                        $HostNameNetworkInfo = $ResolvedIP
                    }
                }
            }
            # If we still don't have one, pick one that we can reach
            if (!$HostNameNetworkInfo) {
                foreach ($ResolvedIP in $ResolvedIPs) {
                    $Ping = [System.Net.NetworkInformation.Ping]::new()
                    $PingResult =$Ping.Send($($ResolvedIP.IPAddressList[0]),1000)
                    if ($PingResult.Status -eq "Success") {
                        $HostNameNetworkInfo = $ResolvedIP
                    }
                }
            }
            # If we still don't have one, just pick one
            if (!$HostNameNetworkInfo) {
                $HostNameNetworkInfo = $ResolvedIPs[0]
            }
        }
        else {
            $HostNameNetworkInfo = $ResolvedIPs[0]
        }

        # Now we need to get some info about the Guest VM
        $InvokeCommandSB = {
            [pscustomobject]@{
                HostNameComputerInfo  = Get-CimInstance Win32_ComputerSystem
                HostNameOSInfo        = Get-CimInstance Win32_OperatingSystem
                HostNameProcessorInfo = Get-CimInstance Win32_Processor
                HostNameBIOSInfo      = Get-CimInstance Win32_BIOS
            }
        }

        $GetWorkingCredsSplatParams = @{
            RemoteHostNameOrIP          = $HostNameNetworkInfo.FQDN
            ErrorAction                 = "Stop"
        }
        if ($TargetHostNameCreds) {
            $GetWorkingCredsSplatParams.Add("AltCredentials",$TargetHostNameCreds)
        }

        try {
            $GetTargetHostCredsInfo = GetWorkingCredentials @GetWorkingCredsSplatParams
            if (!$GetTargetHostCredsInfo.DeterminedCredsThatWorkedOnRemoteHost) {throw "Can't determine working credentials for $($HostNameNetworkInfo.FQDN)!"}
            
            if ($GetTargetHostCredsInfo.CurrentLoggedInUserCredsWorked -eq $True) {
                $TargetHostNameCreds = $null
            }
            
            $TargetHostInvCmdLocation = $GetTargetHostCredsInfo.RemoteHostWorkingLocation
        }
        catch {
            Write-Error $_
            if ($PSBoundParameters['TargetHostNameCreds']) {
                Write-Error "The GetWorkingCredentials function failed! Check the credentials provided to the -TargetHostNameCreds parameter! Halting!"
            }
            else {
                Write-Error "The GetWorkingCredentials function failed! Try using the -TargetHostNameCreds parameter! Halting!"
            }
            $global:FunctionResult = "1"
            return
        }

        $InvCmdSplatParams = @{
            ComputerName    = $TargetHostInvCmdLocation
            ScriptBlock     = $InvokeCommandSB
            ErrorAction     = "Stop"
        }
        if ($TargetHostNameCreds) {
            $InvCmdSplatParams.Add("Credential",$TargetHostNameCreds)
        }

        try {
            $InvokeCommandOutput = Invoke-Command @InvCmdSplatParams

            #$HostNameVirtualStatusInfo = Get-ComputerVirtualStatus -ComputerName $HostNameNetworkInfo.FQDN -WarningAction SilentlyContinue -ErrorAction Stop
            $HostNameComputerInfo = $InvokeCommandOutput.HostNameComputerInfo
            $HostNameOSInfo = $InvokeCommandOutput.HostNameOSInfo
            $HostNameProcessorInfo = $InvokeCommandOutput.HostNameProcessorInfo
            $HostNameBIOSInfo = $InvokeCommandOutput.HostNameBIOSInfo
        }
        catch {
            Write-Error $_
            Write-Error "The Get-GuestVMAndHypervisorInfo function was unable to gather information (i.e. `$HostNameComputerInfo, etc) about the Target Guest VM! Halting!"
            $global:FunctionResult = "1"
            return
        }

        # Now we have $HypervisorNetworkInfo, $HypervisorComputerInfo, $HypervisorOSInfo, $TargetVMInfoFromHyperV, 
        # $HostNameNetworkInfo, $HostNameComputerInfo, $HostNameOSInfo, and $HostNameBIOSInfo
    }

    ## END $TargetVMName adjudication ##


    ## BEGIN $TargetHostNameOrIP adjudication ##

    if ($TargetHostNameOrIP) {
        # If $TargetHostNameOrIP is provided (as opposed to $TargetVMName), we's LIKE TO
        # get information from the Hyper-V Hypervisor, but it's not strictly necessary.
        # However, like with $TargetVMName it is still MANDATORY that we get info about
        # the Target Host. If we can't for whatever reason, we need to HALT

        # We need to be able to get Network Info about the Target Host regardless of whether or not
        # our workstation is actually the Target Host. So if we can't get the info, HALT
        try {
            $HostNameNetworkInfo = ResolveHost -HostNameOrIP $TargetHostNameOrIP -ErrorAction Stop
        }
        catch {
            Write-Error "Unable to resolve $TargetHostNameOrIP! Halting!"
            $global:FunctionResult = "1"
            return
        }

        # BEGIN Get Guest VM Info # 
        
        if ($HostNameNetworkInfo.HostName -ne $env:ComputerName) {
            $InvokeCommandSB = {
                $IntegrationServicesRegistryPath = "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters"
                $HostNameBiosInfoSB = Get-CimInstance Win32_BIOS
                $HostNameComputerInfoSB = Get-CimInstance Win32_ComputerSystem
                $HostNameOSInfoSB = Get-CimInstance Win32_OperatingSystem
                $HostNameProcessorInfoSB = Get-CimInstance Win32_Processor

                $HostNameIntegrationServicesPresentSB = Test-Path $IntegrationServicesRegistryPath

                if ($HostNameIntegrationServicesPresentSB) {
                    $HostNameGuestVMInfoSB = Get-ItemProperty $IntegrationServicesRegistryPath
                }
                else {
                    $HostNameGuestVMInfoSB = "IntegrationServices_Not_Installed"
                }

                [pscustomobject]@{
                    HostNameComputerInfo  = $HostNameComputerInfoSB
                    HostNameOSInfo        = $HostNameOSInfoSB
                    HostNameProcessorInfo = $HostNameProcessorInfoSB
                    HostNameBIOSInfo      = $HostNameBiosInfoSB
                    HostNameGuestVMInfo   = $HostNameGuestVMInfoSB
                }
            }

            $GetWorkingCredsSplatParams = @{
                RemoteHostNameOrIP          = $HostNameNetworkInfo.FQDN
                ErrorAction                 = "Stop"
            }
            if ($TargetHostNameCreds) {
                $GetWorkingCredsSplatParams.Add("AltCredentials",$TargetHostNameCreds)
            }
    
            try {
                $GetTargetHostCredsInfo = GetWorkingCredentials @GetWorkingCredsSplatParams
                if (!$GetTargetHostCredsInfo.DeterminedCredsThatWorkedOnRemoteHost) {throw "Can't determine working credentials for $($HostNameNetworkInfo.FQDN)!"}
                
                if ($GetTargetHostCredsInfo.CurrentLoggedInUserCredsWorked -eq $True) {
                    $TargetHostNameCreds = $null
                }

                $TargetHostInvCmdLocation = $GetTargetHostCredsInfo.RemoteHostWorkingLocation
            }
            catch {
                Write-Error $_
                if ($PSBoundParameters['TargetHostNameCreds']) {
                    Write-Error "The GetWorkingCredentials function failed! Check the credentials provided to the -TargetHostNameCreds parameter! Halting!"
                }
                else {
                    Write-Error "The GetWorkingCredentials function failed! Try using the -TargetHostNameCreds parameter! Halting!"
                }
                $global:FunctionResult = "1"
                return
            }

            $InvCmdSplatParams = @{
                ComputerName    = $TargetHostInvCmdLocation
                ScriptBlock     = $InvokeCommandSB
                ErrorAction     = "Stop"
            }
            if ($TargetHostNameCreds) {
                $InvCmdSplatParams.Add("Credential",$TargetHostNameCreds)
            }
    
            try {
                $InvokeCommandOutput = Invoke-Command @InvCmdSplatParams

                #$HostNameVirtualStatusInfo = Get-ComputerVirtualStatus -ComputerName $HostNameNetworkInfo.FQDN -WarningAction SilentlyContinue -ErrorAction Stop
                $HostNameComputerInfo = $InvokeCommandOutput.HostNameComputerInfo
                $HostNameOSInfo = $InvokeCommandOutput.HostNameOSInfo
                $HostNameProcessorInfo = $InvokeCommandOutput.HostNameProcessorInfo
                $HostNameBIOSInfo = $InvokeCommandOutput.HostNameBIOSInfo
                $HostNameGuestVMInfo = $InvokeCommandOutput.HostNameGuestVMInfo
            }
            catch {
                Write-Error $_
                Write-Error "The Get-GuestVMAndHypervisorInfo function was unable to gather information about $TargetHostInvCmdLocation (i.e. `$HostNameComputerInfo, etc)! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        else {
            $IntegrationServicesRegistryPath = "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters"
            $HostNameBiosInfo = Get-CimInstance Win32_BIOS
            $HostNameIntegrationServicesPresent = Test-Path $IntegrationServicesRegistryPath

            if ($HostNameIntegrationServicesPresent) {
                $HostNameGuestVMInfo = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters"
            }
            else {
                $HostNameGuestVMInfo = "IntegrationServices_Not_Installed"
            }

            $HostNameComputerInfo = Get-CimInstance Win32_ComputerSystem
            $HostNameOSInfo = Get-CimInstance Win32_OperatingSystem
            $HostNameProcessorInfo = Get-CimInstance Win32_Processor
            $HostNameBIOSInfo = Get-CimInstance Win32_BIOS

            $TargetHostInvCmdLocation = $env:ComputerName
        }

        if ($HostNameBIOSInfo.SMBIOSBIOSVersion -match "Hyper-V|VirtualBox|VMWare|Xen" -or
        $HostNameBIOSInfo.Manufacturer -match "Hyper-V|VirtualBox|VMWare|Xen" -or
        $HostNameBIOSInfo.Name -match "Hyper-V|VirtualBox|VMWare|Xen" -or
        $HostNameBIOSInfo.SerialNumber -match "Hyper-V|VirtualBox|VMWare|Xen" -or
        $HostNameBIOSInfo.Version -match "Hyper-V|VirtualBox|VMWare|Xen|VRTUAL" -or
        $HostNameIntegrationServicesPresent) {
            Add-Member -InputObject $HostNameBIOSInfo NoteProperty -Name "IsVirtual" -Value $True
        }
        else {
            Add-Member -InputObject $HostNameBIOSInfo NoteProperty -Name "IsVirtual" -Value $False
        }

        if (!$HostNameBIOSInfo.IsVirtual) {
            Write-Error "This function is meant to determine if a Guest VM is capable of Nested Virtualization, but $TargetHostNameOrIP is a physical machine! Halting!"
            $global:FunctionResult = "1"
            return
        }

        if (!$($HostNameBIOSInfo.SMBIOSBIOSVersion -match "Hyper-V" -or $HostNameBIOSInfo.Name -match "Hyper-V")) {
            Write-Warning "The hypervisor for $($HostNameNetworkInfo.FQDN) is NOT Microsoft's Hyper-V. Unable to get additional information about the hypervisor!"
            $HypervisorIsHyperV = $False
            $TryWithoutHypervisorInfo = $True
        }
        else {
            $HypervisorIsHyperV = $True
        }

        # END Get Guest VM Info #

        # BEGIN Get Hypervisor Info #

        if ($HypervisorIsHyperV -and !$TryWithoutHypervisorInfo) {
            # Now we need to try and get some info about the hypervisor
            if ($HostNameGuestVMInfo -eq "IntegrationServices_Not_Installed") {
                # Still need the FQDN/Location of the hypervisor
                if (!$HypervisorFQDNOrIP -and !$TryWithoutHypervisorInfo) {
                    while (!$HypervisorFQDNOrIP) {
                        Write-Warning "The localhost $env:ComputerName does not appear to be a hypervisor!"
                        $HypervisorFQDNOrIP = Read-Host -Prompt "Please enter the FQDN or IP of the hypervisor that manages $TargetHostInvCmdLocation"
                    }
                }
            }

            if ($HostNameGuestVMInfo.PhysicalHostNameFullyQualified) {
                $HypervisorFQDNOrIPToResolve = $HostNameGuestVMInfo.PhysicalHostNameFullyQualified
            }
            elseif ($HypervisorFQDNOrIP) {
                $HypervisorFQDNOrIPToResolve = $HypervisorFQDNOrIP
            }
            
            # Now we need the FQDN of the hypervisor...
            try {
                $HypervisorNetworkInfo = ResolveHost -HostNameOrIP $HypervisorFQDNOrIPToResolve -ErrorAction Stop
            }
            catch {
                Write-Warning "Unable to resolve $HypervisorFQDNOrIPToResolve! Trying without hypervisor info..."
                $TryWithoutHypervisorInfo = $True
            }
            
            try {
                # Still need the name of the Guest VM according the the hypervisor
                if ($HypervisorNetworkInfo.HostName -ne $env:ComputerName) {
                    try {
                        $InvokeCommandSB = {
                            # We an determine the $TargetVMName by finding the Guest VM Network Adapter with an IP that matches
                            # $HostNameNetworkInfo.IPAddressList
                            $TargetVMName = $(Get-VM | Where-Object {$_.NetworkAdapters.IPAddresses -contains $using:HostNameNetworkInfo.IPAddressList[0]}).Name

                            try {
                                $TargetVMInfoFromHyperV = Get-VM -Name $TargetVMName -ErrorAction Stop
                                $VMProcessorInfo = Get-VMProcessor -VMName $TargetVMName
                                $VMNetworkAdapterInfo = Get-VmNetworkAdapter -VmName $TargetVMName
                                $VMMemoryInfo = Get-VMMemory -VmName $TargetVMName
                            }
                            catch {
                                $TargetVMInfoFromHyperV = "Unable_to_find_VM"
                            }

                            [pscustomobject]@{
                                HypervisorComputerInfo  = Get-CimInstance Win32_ComputerSystem
                                HypervisorOSInfo        = Get-CimInstance Win32_OperatingSystem
                                TargetVMInfoFromHyperV  = $TargetVMInfoFromHyperV
                                VMProcessorInfo         = $VMProcessorInfo
                                VMNetworkAdapterInfo    = $VMNetworkAdapterInfo
                                VMMemoryInfo            = $VMMemoryInfo
                            }
                        }

                        $GetWorkingCredsSplatParams = @{
                            RemoteHostNameOrIP          = $HypervisorNetworkInfo.FQDN
                            ErrorAction                 = "Stop"
                        }
                        if ($HypervisorCreds) {
                            $GetWorkingCredsSplatParams.Add("AltCredentials",$HypervisorCreds)
                        }
            
                        try {
                            $GetHypervisorCredsInfo = GetWorkingCredentials @GetWorkingCredsSplatParams
                            if (!$GetHypervisorCredsInfo.DeterminedCredsThatWorkedOnRemoteHost) {throw "Can't determine working credentials for $($HypervisorNetworkInfo.FQDN)!"}
                            
                            if ($GetHypervisorCredsInfo.CurrentLoggedInUserCredsWorked -eq $True) {
                                $HypervisorCreds = $null
                            }
            
                            $HypervisorInvCmdLocation = $GetHypervisorCredsInfo.RemoteHostWorkingLocation
                        }
                        catch {
                            if ($PSBoundParameters['HypervisorCreds']) {
                                throw "The GetWorkingCredentials function failed! Check the credentials provided to the -HypervisorCreds parameter! Halting!"
                            }
                            else {
                                throw "The GetWorkingCredentials function failed! Try using the -HypervisorCreds parameter! Halting!"
                            }
                        }

                        $InvCmdSplatParams = @{
                            ComputerName        = $HypervisorInvCmdLocation
                            ScriptBlock         = $InvokeCommandSB
                            ErrorAction         = "Stop"
                        }
                        if ($HypervisorCreds) {
                            $InvCmdSplatParams.Add("Credential",$HypervisorCreds)
                        }

                        try {
                            $InvokeCommandOutput = Invoke-Command @InvCmdSplatParams
                            
                            $HypervisorComputerInfo = $InvokeCommandOutput.HypervisorComputerInfo
                            $HypervisorOSInfo = $InvokeCommandOutput.HypervisorOSInfo
                            $TargetVMInfoFromHyperV = $InvokeCommandOutput.TargetVMInfoFromHyperV
                            $VMProcessorInfo = $InvokeCommandOutput.VMProcessorInfo
                            $VMNetworkAdapterInfo = $InvokeCommandOutput.VMNetworkAdapterInfo
                            $VMMemoryInfo = $InvokeCommandOutput.VMMemoryInfo
                        }
                        catch {
                            throw "The Get-GuestVMAndHypervisorInfo function was not able to gather information (i.e. `$HypervisorComputerInfo, etc) about the Hyper-V Host and the Target Guest VM by remoting into the Hyper-V Host! Halting!"
                        }
                    }
                    catch {
                        if (!$TryWithoutHypervisorInfo) {
                            Write-Error $_
                            Write-Error "Unable to get Hyper-V Hypervisor info! Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            Write-Verbose "Unabel to get info about the hypervisor. Trying without hypervisor info..."
                        }
                    }
                }
                else {
                    # We an determine the $TargetVMName by finding the Guest VM Network Adapter with an IP that matches
                    # $HostNameNetworkInfo.IPAddressList
                    $TargetVMName = $(Get-VMNetworkAdapter -All | Where-Object {$_.IPAddresses -contains $HostNameNetworkInfo.IPAddressList[0]}).VMName
                    #$TargetVMName = $(Get-VM | Where-Object {$_.NetworkAdapters.IPAddresses -contains $HostNameNetworkInfo.IPAddressList[0]}).Name

                    try {
                        $TargetVMInfoFromHyperV = Get-VM -Name $TargetVMName -ErrorAction Stop
                        $VMProcessorInfo = Get-VMProcessor -VMName $TargetVMName
                        $VMNetworkAdapterInfo = Get-VmNetworkAdapter -VmName $TargetVMName
                        $VMMemoryInfo = Get-VMMemory -VmName $TargetVMName
                    }
                    catch {
                        $TargetVMInfoFromHyperV = "Unable_to_find_VM"
                    }

                    $HypervisorComputerInfo = Get-CimInstance Win32_ComputerSystem
                    $HypervisorOSInfo = Get-CimInstance Win32_OperatingSystem
                }
            }
            catch {
                if (!$TryWithoutHypervisorInfo) {
                    Write-Error $_
                    Write-Error "Unable to get Hyper-V Hypervisor info! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
                else {
                    Write-Verbose "Unable to get info about the hypervisor. Trying without hypervisor info..."
                }
            }

            if ($TargetVMInfoFromHyperV -eq "Unable_to_find_VM") {
                Write-Error "Unable to find VM $TargetVMName on the specified hypervisor $($HypervisorNetworkInfo.FQDN)! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        elseif (!$HypervisorIsHyperV) {
            $TryWithoutHypervisorInfo = $True
        }
        elseif ((!$HypervisorIsHyperV -and !$TryWithoutHypervisorInfo)) {
            $ErrMsg = "Unable to get info about $($HostNameNetworkInfo.FQDN) from the hypervisor! " +
            "If you would like to try without hypervisor information, use the -TryWithoutHypervisorInfo switch. Halting!"
            Write-Error $ErrMsg
            $global:FunctionResult = "1"
            return
        }

        # Now we have $HypervisorNetworkInfo, $HypervisorComputerInfo, $HypervisorOSInfo, $TargetVMInfoFromHyperV, 
        # $HostNameGuestVMInfo, $HostNameNetworkInfo, $HostNameComputerInfo, and $HostNameOSInfo, $HostNameBIOSInfo,
        # and $HostNameProcessorInfo

        # End Get Hypervisor Info #

    }

    ## END $TargetHostNameOrIP adjudication ##

    # NOTE: $TryWithoutHypervisorInfo should never be $True if -TargetVMName parameter is used
    if ($($TryWithoutHypervisorInfo -or $NoMacAddressSpoofing) -and !$Hypervisorcreds -and
    !$GuestVMAndHVInfo.HypervisorCreds -and !$SkipExternalvSwitchCheck
    ) {
        if ($HostNameNetworkInfo.HostName -ne $env:ComputerName) {
            $InvokeCommandSB = {Get-Module -ListAvailable -Name Hyper-V}
            
            $InvCmdSplatParams = @{
                ComputerName    = $TargetHostInvCmdLocation
                ScriptBlock     = $InvokeCommandSB
                ErrorAction     = "SilentlyContinue"
            }
            if ($TargetHostNameCreds) {
                $InvCmdSplatParams.Add("Credential",$TargetHostNameCreds)
            }
            
            $HyperVInstallCheck = [bool]$(Invoke-Command @InvCmdSplatParams)

            $FunctionsForRemoteUse = @(
                ${Function:GetElevation}.Ast.Extent.Text    
                ${Function:TestIsValidIPAddress}.Ast.Extent.Text
                ${Function:Get-VagrantBoxManualDownload}.Ast.Extent.Text
                ${Function:NewUniqueString}.Ast.Extent.Text
                ${Function:GetvSwitchAllRelatedInfo}.Ast.Extent.Text
                ${Function:FixNTVirtualMachinesPerms}.Ast.Extent.Text
                ${Function:Manage-HyperVVM}.Ast.Extent.Text
                ${Function:Deploy-HyperVVagrantBoxManually}.Ast.Extent.Text
                ${Function:FixVagrantPrivateKeyPerms}.Ast.Extent.Text
                ${Function:InstallFeatureDism}.Ast.Extent.Text
                ${Function:InstallHyperVFeatures}.Ast.Extent.Text
                ${Function:TestHyperVExternalvSwitch}.Ast.Extent.Text
                'Install-Module ProgramManagement; Import-Module ProgramManagement'
                ${Function:GetPendingReboot}.Ast.Extent.Text
            )
            
            $InvokeCommandSB = {
                # Load the functions we packed up:
                $using:FunctionsForRemoteUse | foreach { Invoke-Expression $_ }

                # Check for pre-existing PendingReboot
                if ($PSVersionTable.PSEdition -eq "Core") {
                    $GetPendingRebootAsString = ${Function:GetPendingReboot}.Ast.Extent.Text
                    
                    $RebootPendingCheck = Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                        Invoke-Expression $args[0]
                        $(GetPendingReboot).RebootPending
                    } -ArgumentList $GetPendingRebootAsString

                    $RebootPendingFileCheck = Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                        Invoke-Expression $args[0]
                        $(GetPendingReboot).PendFileRenVal
                    } -ArgumentList $GetPendingRebootAsString
                }
                else {
                    $RebootPendingCheck = $(GetPendingReboot).RebootPending
                    $RebootPendingFileCheck = $(GetPendingReboot).PendFileRenVal
                }

                if (!$RebootPendingCheck -or $RebootPendingFileCheck -eq $null) {
                    $TestHyperVExternalSwitchSplatParams = @{}
                    if ($using:SkipHyperVInstallCheck) {
                        $TestHyperVExternalSwitchSplatParams.Add("SkipHyperVInstallCheck",$True)
                    }
                    if ($using:AllowRestarts) {
                        $TestHyperVExternalSwitchSplatParams.Add("AllowRestarts",$True)
                    }

                    $TestHyperVExternalSwitchResults = TestHyperVExternalvSwitch @TestHyperVExternalSwitchSplatParams

                    $TestHyperVExternalSwitchResults
                }
                else {
                    [pscustomobject]@{RestartNeeded = $True}
                    return
                }
            }

            $InvCmdSplatParams = @{
                ComputerName    = $TargetHostInvCmdLocation
                ScriptBlock     = $InvokeCommandSB
                ErrorAction     = "SilentlyContinue"
            }
            if ($TargetHostNameCreds) {
                $InvCmdSplatParams.Add("Credential",$TargetHostNameCreds)
            }

            try {
                $TestHyperVExternalSwitchResults = Invoke-Command @InvCmdSplatParams -ErrorAction SilentlyContinue -ErrorVariable ICTHVSErr
                if (!$TestHyperVExternalSwitchResults) {throw "The Invoke-Command TestHyperVExternalvSwitch function failed!"}
            }
            catch {
                Write-Error $_
                if ($($ICTHVSErr | Out-String) -match "The operation has timed out") {
                    Write-Error "There was a problem downloading the Vagrant Box to be used to test the External vSwitch! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
                else {
                    Write-Host "Errors for Invoke-Command TestHyperVExternalvSwitch function are as follows:"
                    Write-Error $($ICTHVSErr | Out-String)
                    $global:FunctionResult = "1"
                    return
                }
            }

            if ($TestHyperVExternalSwitchResults -eq "RestartNeeded" -or $TestHyperVExternalSwitchResults.RestartNeeded) {
                Write-Warning "You must restart $TargetHostInvCmdLocation before the Get-GuestVMAndHypervisorInfo function can proceed! Halting!"
                [pscustomobject]@{RestartNeeded = $True}
                return
            }
        }
        else {
            $HyperVInstallCheck = [bool]$(Get-Module -ListAvailable -Name Hyper-V)

            try {
                # Check for pre-existing PendingReboot
                if ($PSVersionTable.PSEdition -eq "Core") {
                    $GetPendingRebootAsString = ${Function:GetPendingReboot}.Ast.Extent.Text
                    
                    $RebootPendingCheck = Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                        Invoke-Expression $args[0]
                        $(GetPendingReboot).RebootPending
                    } -ArgumentList $GetPendingRebootAsString

                    $RebootPendingFileCheck = Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                        Invoke-Expression $args[0]
                        $(GetPendingReboot).PendFileRenVal
                    } -ArgumentList $GetPendingRebootAsString
                }
                else {
                    $RebootPendingCheck = $(GetPendingReboot).RebootPending
                    $RebootPendingFileCheck = $(GetPendingReboot).PendFileRenVal
                }

                if (!$RebootPendingCheck -or $RebootPendingFileCheck -eq $null) {
                    # Use the TestHyperVExternalvSwitch function here
                    $TestHyperVExternalSwitchSplatParams = @{
                        ErrorAction         = "SilentlyContinue"
                        ErrorVariable       = "THVSErr"
                    }
                    if ($HyperVInstallCheck) {
                        $TestHyperVExternalSwitchSplatParams.Add("SkipHyperVInstallCheck",$True)
                    }
                    $TestHyperVExternalSwitchResults = TestHyperVExternalvSwitch @TestHyperVExternalSwitchSplatParams
                    if (!$TestHyperVExternalSwitchResults) {throw "The TestHyperVExternalvSwitch function failed!"}

                    if ($TestHyperVExternalSwitchResults -eq "RestartNeeded") {
                        Write-Warning "You must restart $env:ComputerName before the Get-GuestVMAndHypervisorInfo function can proceed! Halting!"

                        if ($AllowRestarts) {
                            Restart-Computer -Confirm:$False -Force
                        }

                        [pscustomobject]@{RestartNeeded = $True}
                        return
                    }
                }
                else {
                    Write-Warning "There is currently a reboot pending. Please restart $env:ComputerName before proceeding. Halting!"
                    [pscustomobject]@{RestartNeeded = $True}
                    return
                }
            }
            catch {
                Write-Error $_
                if ($($THVSErr | Out-String) -match "The operation has timed out") {
                    Write-Error "There was a problem downloading the Vagrant Box to be used to test the External vSwitch! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
                else {
                    Write-Host "Errors for the TestHyperVExternalvSwitch function are as follows:"
                    Write-Error $($THVSErr | Out-String)
                    $global:FunctionResult = "1"
                    return
                }
            }
        }

        if ($TestHyperVExternalSwitchResults -eq $null) {
            Write-Error "There was a problem with the TestHyperVExternalvSwitch function! This usually has to do with AWS or Vagrant websites throttling traffic. Try starting a fresh PowerShell Session. Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($HypervisorCreds -eq $null -and $GetHypervisorCredsInfo.DeterminedCredsThatWorkedOnRemoteHost) {
        $FinalHypervisorCreds = whoami
    }
    else {
        $FinalHypervisorCreds = $HypervisorCreds
    }

    $Output = [ordered]@{
        HypervisorNetworkInfo           = $HypervisorNetworkInfo
        HypervisorInvCmdLocation        = $HypervisorInvCmdLocation
        HypervisorComputerInfo          = $HypervisorComputerInfo
        HypervisorOSInfo                = $HypervisorOSInfo
        TargetVMInfoFromHyperV          = $TargetVMInfoFromHyperV
        VMProcessorInfo                 = $VMProcessorInfo
        VMNetworkAdapterInfo            = $VMNetworkAdapterInfo
        VMMemoryInfo                    = $VMMemoryInfo
        HypervisorCreds                 = $FinalHypervisorCreds
        HostNameNetworkInfo             = $HostNameNetworkInfo
        TargetHostInvCmdLocation        = $TargetHostInvCmdLocation
        HostNameComputerInfo            = $HostNameComputerInfo
        HostNameOSInfo                  = $HostNameOSInfo
        HostNameProcessorInfo           = $HostNameProcessorInfo
        HostNameBIOSInfo                = $HostNameBIOSInfo
        TargetHostNameCreds             = if ($TargetHostNameCreds -eq $null) {whoami} else {$TargetHostNameCreds}
    }

    if ($TryWithoutHypervisorInfo) {
        if ($HyperVInstallCheck -eq $False) {
            $RestartNeeded = $True
            if ($AllowRestarts) {
                $RestartOccurred = $True
            }
            else {
                $RestartOccurred = $False
            }
        }
        else {
            $RestartNeeded = $False
            $RestartOccurred = $False
        }

        $Output.Add("RestartNeeded",$RestartNeeded)
        $Output.Add("RestartOccurred",$RestartOccurred)

        if (!$SkipExternalvSwitchCheck) {
            if ($TestHyperVExternalSwitchResults.VirtualizationExtensionsExposed -eq $null) {
                $Output.Add("VirtualizationExtensionsExposed",$False)
            }
            else {
                $Output.Add("VirtualizationExtensionsExposed",$TestHyperVExternalSwitchResults.VirtualizationExtensionsExposed)
            }

            if ($TestHyperVExternalSwitchResults.MacAddressSpoofingEnabled -eq $null) {
                $Output.Add("MacAddressSpoofingEnabled","Unknown")
            }
            else {
                $Output.Add("MacAddressSpoofingEnabled",$TestHyperVExternalSwitchResults.MacAddressSpoofingEnabled)
            }
        }
        else {
            if ($(Confirm-AWSVM -EA SilentlyContinue) -or $(Confirm-AzureVM -EA SilentlyContinue) -or
            $(Confirm-GoogleComputeVM -EA SilentlyContinue)
            ) {
                $Output.Add("VirtualizationExtensionsExposed",$True)
                $Output.Add("MacAddressSpoofingEnabled",$False)
            }
            else {
                # No other choice but to assume both are $True...
                $Output.Add("VirtualizationExtensionsExposed",$True)
                $Output.Add("MacAddressSpoofingEnabled",$True)
            }
        }
    }
    else {
        $Output.Add("VirtualizationExtensionsExposed",$VMProcessorInfo.ExposeVirtualizationExtensions)
        $Output.Add("MacAddressSpoofingEnabled",$($VMNetworkAdapterInfo.MacAddressSpoofing -contains "On"))
    }

    [pscustomobject]$Output
}

# SIG # Begin signature block
# MIIMaAYJKoZIhvcNAQcCoIIMWTCCDFUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU5sw8VLqaTLnL4firfUg0GAhR
# QgygggndMIIEJjCCAw6gAwIBAgITawAAADqEP46TDmc/hQAAAAAAOjANBgkqhkiG
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
# BDEWBBQqmt8dA8PJye0qA387z5Hq4PFRYDANBgkqhkiG9w0BAQEFAASCAQCxVSZa
# Y/7dwS+Xz6/YNJNxq/pnkWOXwbu+UG5Yp+JIm+YsYLVHLvXl49Heom0LJBuFdpaa
# 1y19kFwJ3d7VTACk1AbtpbbN7WPPiglRMEcJMtkxKA6d3qjnJnIP7/L/E4E7mExj
# SE/aUzhUzhL7zRUa1GJJoY7SCRZQaHseup8O4NlWcjaPQGkCdZUXHiG9WzCiPyIE
# t6V7Rf56+GbdltkFqaOaait2BmuPoPc0B/+0lLIyeVejzLJHZXtlfRXJVkYw+Ba7
# w2SAl1EsfBNFUtEavzelUvGFiLX/LCBmS81iX/zyYT6o1uPpua88kwQPx6LDthLN
# Fz/7eS5PTFJgOtpq
# SIG # End signature block
