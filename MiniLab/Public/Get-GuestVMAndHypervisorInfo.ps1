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

        # -TryWithoutHypervisorInfo MIGHT result in creating a Local NAT
        # with an Internal vSwitch on the Target Machine (assuming it's a Guest VM). It depends if
        # Get-NestedVirtCapabilities detemines whether the Target Machine can use an External vSwitch or not.
        # If it can, then a Local NAT will NOT be created.
        # If a NAT already exists on the Target Machine, that NAT will be changed to
        # 10.0.75.0/24 with IP 10.0.75.1 if it isn't already
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
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU8PSx2ByxSiqdJfVaRix7OCkO
# DQWgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFDH9k7ecK27OUZBg
# fKRd8BR0bfGXMA0GCSqGSIb3DQEBAQUABIIBAEkkRiKlZAbQZvlm8hkuhPdxQjuM
# xtpH1ciwhwYSEP+o35xP9H2O1Ls6xZDCnkFmwRwiv36WGuV3HhEwON291pWBUP15
# ex3wmxssmKryVO1nZAi8OWE0jcLMkHmOKu1J6pAly/C4A3kDH+wrfPiNkySn5wKt
# lT3VmG2rQswPCD4CRRMqOfonNqLGlc6A8wgnhlVYW/lQa3aqHclXIhltC8UdNltG
# K3yYthOEwkYh24tFCVFx/5n9gHoOJw+Mcf8Jz7sVCyuZbZvn1nRYjs/MV6lj7MbB
# YayMmp5rAIZ42keVy+2+fHuc4NPe2ZeL1vJox60n3kvgUEVy5O7ZF3k/7YM=
# SIG # End signature block
