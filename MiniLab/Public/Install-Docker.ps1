<#
    .SYNOPSIS
        This function adds an IP or hostname/fqdn to "WSMan:\localhost\Client\TrustedHosts". It also ensures
        that the WSMan Client is configured to allow for remoting.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER InstallEnvironment
        This parameter is OPTIONAL (but highly recommended).

        This parameter takes a string with either the value "BareMetal" or "GuestVM". Use 'BareMetal' if
        you are installing Docker on a baremetal machine. Use "GuestVM" if you are installing Docker on
        a Guest VM.

        If you do not use this parameter, the function will attempt to determine if the target machine
        is baremetal or if it is a Guest VM, however, the logic it uses to make this determination is not
        bulletproof, which is why this parameter should be used if at all possible.

    .PARAMETER TargetHostNameOrIP
        This parameter is OPTIONAL.

        This parameter takes a string that represents the IP Address, DNS-Resolvable HostName, or FQDN
        of the Guest VM that you would like to install Docker-For-Windows (Docker CE) on. If it is NOT
        used (and if the -TargetVMName parameter is not used), the function will assume that you would
        like to install Docker on the localhost.

    .PARAMETER TargetVMName
        This parameter is MANDATORY (for its parameter set).

        This parameter should only be used if Docker is being installed on a Guest VM.

        This parameter takes a string that represents the name of the Hyper-V VM that you would like
        to install Docker on. Using this parameter requires that you use the -HypervisorFQDNOrIP
        and -HypervisorCreds parameters, unless the localhost IS the Hyper-V hypervisor.

    .PARAMETER HypervisorFQDNOrIP
        This parameter is OPTIONAL.

        This parameter should only be used if Docker is being installed on a Guest VM.

        This parameter takes a string that represents the IP, DNS-Resolvable HostName, or FQDN of the
        Hyper-V hypervisor that is managing the Guest VM that you would like to install Docker on. If
        you are installing Docker on a Guest VM and if the localhost is NOT the Hyper-V hypervisor and
        if you are NOT using the -TryWithoutHypervisorInfo switch, then this parameter becomes MANDATORY.

    .PARAMETER TargetHostNameCreds
        This parameter is OPTIONAL.

        This parameter takes a pscredential object that contains credentials with permission to access
        the Remote Host that you would like to install Docker on. If you are installing Docker on the
        localhost, or if you are logged in as a user that already has access to the target machine
        then you should NOT use this parameter.

    .PARAMETER HypervisorCreds
        This parameter is OPTIONAL.

        This parameter should only be used if Docker is being installed on a Guest VM.

        This parameter takes a pscredential object that contains credentials with permission to access
        the Hyper-V hypervisor that is managing the Guest VM that you would like to install Docker on. If
        the localhost IS the Hyper-V hypervisor, or if you are logged in as a user that already has access
        to the Hyper-V hypervisor, then you do NOT need to use this parameter.

    .PARAMETER GuestVMandHVInfo
        This parameter is OPTIONAL.

        This parameter should only be used if Docker is being installed on a Guest VM.

        This parameter takes a pscustomobject that represents that output of the Get-GuestVMandHypervisorInfo
        function.

        If you intend to install Docker on a Guest VM, you can use this parameter to forego using the following
        parameters:
            -InstallEnvironment
            -TargetHostNameIP
            -TargetVMName
            -HypervisorFQDNOrIP
            -TargetHostNameCreds
            -HypervisorCreds

    .PARAMETER GuestVMMemoryInGB
        This parameter is OPTIONAL.

        This parameter should only be used if Docker is being installed on a Guest VM.

        This parameter takes an integer that represents the amount of memory (in GB) that you
        would like the Guest VM (that you are installing Docker on) to have.

        Using this parameter assumes you can access to the Hyper-V hypervisor that is managing the
        target Guest VM (whether it is via the -HypervisorCreds parameter on because you are logged
        into the localhost as a user that has access to the hypervisor).

    .PARAMETER AllowRestarts
        This parameter is OPTIONAL.

        This parameter is a switch. If used, if the target machine needs to be restarted as a result
        of the Docker install (most likely because Hyper-V was installed for the first time), then
        it will be restarted.

    .PARAMETER MobyLinuxVMMemoryInGB
        This parameter is OPTIONAL, however, it has a default value of 2.

        This parameter takes an integer (even numbers only) that represents the amount of Memory
        in GB that you would like to allocate to the MobyLinux VM that is created to run Linux
        Containers on Docker-For-Windows (Docker CE).

    .PARAMETER TryWithoutHypervisorInfo
        This parameter is OPTIONAL.

        This parameter should only be used if Docker is being installed on a Guest VM.

        This parameter is a switch. If used, then this function will attempt to install
        Docker on the target Guest VM without gathering any information about the Hyper-V
        hypervisor that is managing the Guest VM. Use this parameter if you do not have
        access to the hypervisor managing the target Guest VM.

    .PARAMETER NoMacAddressSpoofing
        This parameter is OPTIONAL.

        This parameter should only be used if Docker is being installed on a Guest VM.

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
        on the target machine and not attempt any verification or installation prior to installing Docker.

    .PARAMETER SkipEnableNestedVM
        This parameter is OPTIONAL.

        This parameter should only be used if Docker is being installed on a Guest VM.

        This parameter is a switch. If used, this function will NOT attempt to make any configuration changes
        to the Hyper-V hypervisor or target Guest VM in order to make Nested Virtualization possible.

    .PARAMETER RecreateMobyLinuxVM
        This parameter is OPTIONAL.

        This parameter is a switch. If Docker was installed at one point but has since been uninstalled, and
        the MobyLinux VM from the previous installation still exists, use this parameter to recreate it
        for use with this new Docker installation.

    .PARAMETER NATIP
        This parameter is OPTIONAL.

        This parameter takes a string that represents the IPv4 addess that you would like the DocketNAT
        vSwitch to use. It defaults to 10.0.75.1.

    .PARAMETER NATNetworkMask
        This parameter is OPTIONAL.

        This parameter takes an integer from 24 to 31 inclusive that represents the CIDR notation of the
        network mask that you would like to use for the DockerNAT. This parameter must be used in
        conjunction with the -NATIP parameter.

    .PARAMETER NATName
        This parameter is OPTIONAL.

        This parameter takes a string that represents the name of the Hyper-V vSwitch that will be used
        for DockerNAT. This parameter must be used in conjunction with the -NATIP and -NATNetworkMask
        parameters.

    .PARAMETER PreRelease
        This parameter is OPTIONAL.

        This parameter is a switch. If used, Docker-For-Windows (Docker CE) will be installed from the
        Edge (as opposed to Stable) branch.

    .PARAMETER AllowLogout
        This parameter is OPTIONAL.

        This parameter is a switch. If used, and if Docker is being installed on the localhost in an
        interactive PowerShell session, then the logged in user will be logged out at the end of
        installation (which is required as a normal part of installing Docker-For-Windows/Docker CE).

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Install-Docker
        
#>
function Install-Docker {
    [CmdletBinding(DefaultParameterSetName='Default')]
    Param(
        [Parameter(Mandatory = $False)]
        [ValidateSet("BareMetal","GuestVM")]
        [string]$InstallEnvironment,

        [Parameter(
            Mandatory = $False,
            ParameterSetName = 'Default'
        )]
        [string]$TargetHostNameOrIP,

        [Parameter(
            Mandatory=$False,
            ParameterSetName = 'UsingVMName'
        )]
        [string]$TargetVMName,

        [Parameter(Mandatory=$False)]
        [string]$HypervisorFQDNOrIP,

        [Parameter(Mandatory=$False)]
        $TargetHostNameCreds,

        [Parameter(Mandatory=$False)]
        $HypervisorCreds,

        [Parameter(
            Mandatory=$True,
            ParameterSetName = 'InfoAlreadyCollected'
        )]
        $GuestVMAndHVInfo,

        [Parameter(Mandatory=$False)]
        [ValidateScript({
            $(($_ % 4) -eq 0) -and $($_ -ge 4)
        })]
        [int]$GuestVMMemoryInGB, # Use this parameter if you are installing Docker on a GuestVM and want to increase that GuestVM's memory

        [Parameter(Mandatory=$False)]
        [switch]$AllowRestarts,

        [Parameter(Mandatory=$False)]
        [ValidateScript({
            $(($_ % 2) -eq 0) -and $($_ -ge 2)
        })]
        [int]$MobyLinuxVMMemoryInGB = 2,

        [Parameter(Mandatory=$False)]
        [switch]$TryWithoutHypervisorInfo,

        # -NoMacAddressSpoofing WILL result in creating a Local NAT with an Internal vSwitch on the
        # Target Machine (assuming it's a Guest VM). Maybe change this parameter to 'CreateNAT' instead
        # of 'NoMacAddressSpoofing'
        [Parameter(Mandatory=$False)]
        [switch]$NoMacAddressSpoofing,

        [Parameter(Mandatory=$False)]
        [switch]$SkipHyperVInstallCheck,

        [Parameter(Mandatory=$False)]
        [switch]$SkipEnableNestedVM,

        [Parameter(Mandatory=$False)]
        [switch]$RecreateMobyLinuxVM,

        [Parameter(Mandatory=$False)]
        [string]$NATIP,

        [Parameter(Mandatory=$False)]
        [ValidateRange(24,31)]
        [string]$NATNetworkMask,

        [Parameter(Mandatory=$False)]
        [string]$NATName,

        [Parameter(Mandatory=$False)]
        [switch]$PreRelease,

        [Parameter(Mandatory=$False)]
        [switch]$AllowLogout
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

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

    if (!$GuestVMAndHVInfo) {
        if (!$TargetHostNameOrIP -and !$TargetVMName) {
            $TargetHostNameOrIP = $env:ComputerName
        }

        try {
            $HostNameNetworkInfo = ResolveHost -HostNameOrIP $TargetHostNameOrIP
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
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
    }

    # Determine the $InstallEnvironment (either "BareMetal" or "GuestVM")
    if (!$InstallEnvironment) {
        if ($GuestVMAndHVInfo -or $TargetVMName) {
            $InstallEnvironment = "GuestVM"
        }
        if (!$GuestVMAndHVInfo -and !$TargetVMName) {
            if ($TargetHostInvCmdLocation -match $env:ComputerName) {
                $IntegrationServicesRegistryPath = "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters"
                $HostNameBiosInfo = Get-CimInstance Win32_BIOS
                $HostNameIntegrationServicesPresent = Test-Path $IntegrationServicesRegistryPath

                if ($HostNameIntegrationServicesPresent) {
                    $HostNameGuestVMInfo = Get-ItemProperty $IntegrationServicesRegistryPath
                }
            }
            else {
                # Determine if $TargetHostNameOrIP is Physical or Virtual
                try {
                    $EnvProbeSB = {
                        $IntegrationServicesRegistryPath = "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters"
                        $HostNameBiosInfoSB = Get-CimInstance Win32_BIOS
                        $HostNameIntegrationServicesPresentSB = Test-Path $IntegrationServicesRegistryPath

                        $Output = [ordered]@{
                            HostNameBIOSInfo                    = $HostNameBiosInfoSB
                            HostNameIntegrationServicesPresent  = $HostNameIntegrationServicesPresentSB
                        }

                        if ($HostNameIntegrationServicesPresentSB) {
                            $HostNameGuestVMInfoSB = Get-ItemProperty $IntegrationServicesRegistryPath
                            $Output.Add("HostNameGuestVMInfo",$HostNameGuestVMInfoSB)
                        }

                        [pscustomobject]$Output
                    }

                    $EnvProbeSplatParams = @{
                        ComputerName    = $TargetHostInvCmdLocation
                        ScriptBlock     = $EnvProbeSB
                        ErrorAction     = "Stop"
                    }
                    if ($TargetHostNameCreds -ne $null) {
                        $EnvProbeSplatParams.Add("Credential",$TargetHostNameCreds)
                    }

                    try {
                        $InvokeCommandOutput = Invoke-Command @EnvProbeSplatParams

                        $HostNameBiosInfo = $InvokeCommandOutput.HostNameBIOSInfo
                        $HostNameIntegrationServicesPresent = $InvokeCommandOutput.HostNameIntegrationServicesPresent
                        if ($HostNameIntegrationServicesPresent) {
                            $HostNameGuestVMInfo = $InvokeCommandOutput.HostNameGuestVMInfo
                        }
                    }
                    catch {
                        Write-Error $_
                        Write-Error "Probing the Target Machine failed to determine if it is Physical or Virtual failed! Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                }
                catch {
                    Write-Error $_
                    Write-Error "Unable to get `$HostNameBIOSInfo or `$HostnameIntegrationServicesPresent! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }

            if ($HostNameBIOSInfo.SMBIOSBIOSVersion -match "Hyper-V|VirtualBox|VMWare|Xen" -or
            $HostNameBIOSInfo.Manufacturer -match "Hyper-V|VirtualBox|VMWare|Xen" -or
            $HostNameBIOSInfo.Name -match "Hyper-V|VirtualBox|VMWare|Xen" -or
            $HostNameBIOSInfo.SerialNumber -match "Hyper-V|VirtualBox|VMWare|Xen" -or
            $HostNameBIOSInfo.Version -match "Hyper-V|VirtualBox|VMWare|Xen|VRTUAL" -or
            $HostNameIntegrationServicesPresent -eq $True
            ) {
                Add-Member -InputObject $HostNameBIOSInfo NoteProperty -Name "IsVirtual" -Value $True
            }
            else {
                Add-Member -InputObject $HostNameBIOSInfo NoteProperty -Name "IsVirtual" -Value $False
            }

            if ($HostNameBIOSInfo.IsVirtual) {
                $InstallEnvironment = "GuestVM"
            }
            else {
                $InstallEnvironment = "BareMetal"
            }
        }
    }

    if ($InstallEnvironment -eq "BareMetal" -and $GuestVMMemoryInGB) {
        $GuestVMMemErrMsg = "The -GuestVMMemoryInGB parameter should only be used if Docker is going to be installed" +
        "on a Guest VM and you would like to increase the amount of memory available to that Guest VM! Halting!"
        Write-Error $GuestVMMemErrMsg
        $global:FunctionResult = "1"
        return
    }

    if ([bool]$PSBoundParameters['MobyLinuxVMMemoryInGB']) {
        $MobyLinuxVMMemoryInMB = [Math]::Round($MobyLinuxVMMemoryInGB * 1KB)
    }

    # Constants
    #$DockerToolsUrl = "https://download.docker.com/win/stable/DockerToolbox.exe"
    #$DockerCEUrl = "https://download.docker.com/win/stable/Docker%20for%20Windows%20Installer.exe"

    # Gather Information about the target install environment. If it's a GuestVM, then changes will be made
    # to the Hyper-V hypervisor and Guest VM as needed to allow for Nested Virtualization, which may or may not
    # involve restarting the Guest VM. Otherwise, these 'if' blocks are just responsible for defining
    # $Locale, i.e. the machine that is running this function - either the "Hypervisor", "GuestVM",
    # "BareMetalTarget", or "Elsewhere"
    if ($InstallEnvironment -eq "GuestVM") {
        # We might need credentials for the hypervisor...
        if ($HostNameGuestVMInfo) {
            $HyperVLocationToResolve = $HostNameGuestVMInfo.PhysicalHostNameFullyQualified
        }
        elseif ($HypervisorFQDNOrIP) {
            $HyperVLocationToResolve = $HypervisorFQDNOrIP
        }
        else {
            $HyperVLocationToResolve = Read-Host -Prompt "Please enter the IP, FQDN, or DNS-Resolvable hostname of the Hyper-V machine hosting the Guest VM."
        }

        try {
            try {
                $HypervisorNetworkInfo = ResolveHost -HostNameOrIP $HyperVLocationToResolve -ErrorAction Stop
            }
            catch {
                throw "Unable to resolve $HyperVLocationToResolve! Halting!"
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
        }
        catch {
            if ($TryWithoutHypervisorInfo) {
                $HypervisorNetworkInfo = $null
                $HypervisorComputerInfo = $null
                $HypervisorOSInfo = $null
            }
            else {
                Write-Error $_
                Write-Error "Unable to get Hyper-V Hypervisor info! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        if (![bool]$PSBoundParameters['GuestVMAndHVInfo']) {
            $GetVMAndHVSplatParams = @{}
        
            if ($($TargetHostNameOrIP -or $TargetHostInvCmdLocation) -and $GetVMAndHVSplatParams.Keys -notcontains "TargetHostNameOrIP") {
                if ($TargetHostInvCmdLocation) {
                    $GetVMAndHVSplatParams.Add("TargetHostNameOrIP",$TargetHostInvCmdLocation)
                }
                elseif ($TargetHostNameOrIP) {
                    $GetVMAndHVSplatParams.Add("TargetHostNameOrIP",$TargetHostNameOrIP)
                }
            }
            elseif ($TargetVMName -and $GetVMAndHVSplatParams.Keys -notcontains "TargetVMName") {
                $GetVMAndHVSplatParams.Add("TargetVMName",$TargetVMName)
            }

            if ($TargetHostNameCreds -and $GetVMAndHVSplatParams.Keys -notcontains "TargetHostNameCreds") {
                $GetVMAndHVSplatParams.Add("TargetHostNameCreds",$TargetHostNameCreds)
            }

            if ($($HypervisorFQDNOrIP -or $HypervisorInvCmdLocation) -and $GetVMAndHVSplatParams.Keys -notcontains "HypervisorFQDNOrIP") {
                if ($HypervisorInvCmdLocation) {
                    $GetVMAndHVSplatParams.Add("HypervisorFQDNOrIP",$HypervisorInvCmdLocation)
                }
                elseif ($HypervisorFQDNOrIP) {
                    $GetVMAndHVSplatParams.Add("HypervisorFQDNOrIP",$HypervisorFQDNOrIP)
                }
            }

            if ($HypervisorCreds -and $GetVMAndHVSplatParams.Keys -notcontains "HypervisorCreds") {
                $GetVMAndHVSplatParams.Add("HypervisorCreds",$HypervisorCreds)
            }
            
            if ($($TryWithoutHypervisorInfo -and $GetVMAndHVSplatParams.Keys -notcontains "TryWithoutHypervisorInfo") -or 
            $($(ConfirmAWSVM -EA SilentlyContinue) -or $(ConfirmAzureVM -EA SilentlyContinue) -or
            $(ConfirmGoogleComputeVM -EA SilentlyContinue))
            ) {
                $GetVMAndHVSplatParams.Add("TryWithoutHypervisorInfo",$True)
            }

            if ($AllowRestarts -and $GetVMAndHVSplatParams.Keys -notcontains "AllowRestarts") {
                $GetVMAndHVSplatParams.Add("AllowRestarts",$True)
            }

            if ($NoMacAddressSpoofing -and $GetVMAndHVSplatParams.Keys -notcontains "NoMacAddressSpoofing") {
                $GetVMAndHVSplatParams.Add("NoMacAddressSpoofing",$True)
            }

            if ($SkipHyperVInstallCheck -and $GetVMAndHVSplatParams.Keys -notcontains "SkipHyperVInstallCheck") {
                $GetVMAndHVSplatParams.Add("SkipHyperVInstallCheck",$True)
            }

            if ($SkipExternalvSwitchCheck -and $GetVMAndHVSplatParams.Keys -notcontains "SkipExternalvSwitchCheck") {
                $GetVMAndHVSplatParams.Add("SkipExternalvSwitchCheck",$True)
            }

            try {
                $GuestVMAndHVInfo = Get-GuestVMAndHypervisorInfo @GetVMAndHVSplatParams -ErrorAction SilentlyContinue -ErrorVariable GGIErr
                if (!$GuestVMAndHVInfo) {throw "The Get-GuestVMAndHypervisorInfo function failed! Halting!"}

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

                if ($GuestVMAndHVInfo.RestartNeeded -and !$AllowRestarts) {
                    Write-Verbose "A restart might be necessary before Docker CE can be instelled on $env:ComputerName..."
                }
            }
            catch {
                Write-Error $_
                if ($($GGIErr | Out-String) -match "The operation has timed out") {
                    Write-Error "There was a problem downloading the Vagrant Box to be used to test the External vSwitch! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
                else {
                    Write-Host "Errors for the Get-GuestVMAndHypervisorInfo function are as follows:"
                    Write-Error $($GGIErr | Out-String)
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
        else {
            $ValidGuestVMAndHVInfoNoteProperties = @(
                "HypervisorNetworkInfo"
                "HypervisorInvCmdLocation"
                "HypervisorComputerInfo"
                "HypervisorOSInfo"
                "TargetVMInfoFromHyperV"
                "VMProcessorInfo"
                "VMNetworkAdapterInfo"
                "VMMemoryInfo"
                "HypervisorCreds"
                "HostNameNetworkInfo"
                "TargetHostInvCmdLocation"
                "HostNameComputerInfo"
                "HostNameOSInfo"
                "HostNameProcessorInfo"
                "HostNameBIOSInfo"
                "TargetHostNameCreds"
                "RestartNeeded"
                "RestartOccurred"
                "VirtualizationExtensionsExposed"
                "MacAddressSpoofingEnabled"
            )
            [System.Collections.ArrayList]$FoundIssueWithGuestVMAndHVInfo = @()
            $ParamObjMembers = $($GuestVMAndHVInfo | Get-Member -MemberType NoteProperty).Name
            foreach ($noteProp in $ParamObjMembers) {
                if ($ValidGuestVMAndHVInfoNoteProperties -notcontains $noteProp) {
                    $null = $FoundIssueWithGuestVMAndHVInfo.Add($noteProp)
                }
            }
            if ($FoundIssueWithGuestVMAndHVInfo.Count -gt 3) {
                $ParamObjMembers
                Write-Error "The object provided to the -GuestVMAndHVInfo parameter is invalid! It must be output from the Get-GuestVMAndHypervisorInfo function! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        if (!$GuestVMAndHVInfo) {
            Write-Error "There was a problem with the Get-GuestVMandHypervisorInfo function! Halting!"
            $global:FunctionResult = "1"
            return
        }

        if ($GuestVMAndHVInfo.RestartOccurred -eq $True) {
            Write-Error "$($GuestVMAndHVInfo.HostNameNetworkInfo.FQDN) was restarted! Please re-run the Install-Docker function after $($GuestVMAndHVInfo.FQDN) has finished restarting (approximately 5 minutes)."
            $global:FunctionResult = "1"
            return
        }

        if ($GuestVMAndHVInfo.HypervisorCreds -ne $null) {
            $HypervisorCreds = $GuestVMAndHVInfo.HypervisorCreds
        }
        if ($GuestVMAndHVInfo.TargetHostNameCreds -ne $null) {
            $TargetHostNameCreds = $GuestVMAndHVInfo.TargetHostNameCreds
            if ($TargetHostNameCreds -eq $(whoami)) {
                $TargetHostNameCreds = $null
            }
        }

        if ($($GuestVMAndHVInfo.VirtualizationExtensionsExposed -eq $False -or
        $GuestVMAndHVInfo.VirtualizationExtensionsExposed -match "Unknown") -and $TryWithoutHypervisorInfo) {
            Write-Error "The Guest VM $($GuestVMAndHVInfo.HostNameNetworkInfo.FQDN) is not capable of running 64-bit Nested VMs! Since DockerCE depends on the MobyLinux VM, DockerCE will NOT be installed! Try the EnableNestedVM function for remediation. Halting!"
            $global:FunctionResult = "1"
            return
        }

        # Determine where this function is being run
        if ($env:ComputerName -eq $GuestVMAndHVInfo.HypervisorNetworkInfo.HostName) {
            $Locale = "Hypervisor"
        }
        elseif ($env:ComputerName -eq $GuestVMAndHVInfo.HostNameNetworkInfo.HostName) {
            $Locale = "GuestVM"
        }
        else {
            $Locale = "Elsewhere"
        }

        if (!$SkipEnableNestedVM) {
            $EnableNestedVMSplatParams = @{
                GuestVMAndHVInfo        = $GuestVMAndHVInfo
                SkipPrompt              = $True
                ErrorAction             = "SilentlyContinue"
                ErrorVariable           = "ENVErr"
                WarningAction           = "SilentlyContinue"
            }
            if ($AllowRestarts) {
                if ($env:ComputerName -eq $GuestVMAndHVInfo.HostNameNetworkInfo.HostName) {
                    $DefaultRestartWarning = "If any restarts occur, Vagrant will NOT have been installed " +
                    "(only prerequisites will have been configured). To complete Vagrant installation after restart, " +
                    "you must re-run the Install-Vagrant function AFTER restarting!"
                    Write-Warning $DefaultRestartWarning
                }
                $EnableNestedVMSplatParams.Add("AllowRestarts",$True)
            }
            if ($TryWithoutHypervisorInfo) {
                $EnableNestedVMSplatParams.Add("TryWithoutHypervisorInfo",$True)
            }
            if ($NoMacAddressSpoofing) {
                $EnableNestedVMSplatParams.Add("NoMacAddressSpoofing",$True)
            }
            if ($SkipHyperVInstallCheck) {
                $EnableNestedVMSplatParams.Add("SkipHyperVInstallCheck",$True)
            }
            if ($NATIP) {
                $EnableNestedVMSplatParams.Add("NATIP",$NATIP)
            }
            if ($NATNetworkMask) {
                $EnableNestedVMSplatParams.Add("NATNetworkMask",$NATNetworkMask)
            }
            if ($NATName) {
                $EnableNestedVMSplatParams.Add("NATName",$NATName)
            }
    
            try {
                $EnableNestedVMResults = EnableNestedVM @EnableNestedVMSplatParams
                if (!$EnableNestedVMResults) {throw "The EnableNestedVM function failed! Halting!"}
            }
            catch {
                Write-Error $_
                Write-Host "Errors for the EnableNestedVM function are as follows:"
                Write-Error $($ENVErr | Out-String)
                $global:FunctionResult = "1"
                return
            }

            if ($EnableNestedVMResults.RestartOccurred) {
                if ($EnableNestedVMResults.GuestVMSettingsThatWereChanged -contains "HyperVInstall") {
                    Write-Host "Sleeping for 300 seconds to wait for restart after Hyper-V install..."
                    Start-Sleep -Seconds 300

                    $GetVMAndHVSplatParams = @{}
        
                    if ($($TargetHostNameOrIP -or $TargetHostInvCmdLocation) -and $GetVMAndHVSplatParams.Keys -notcontains "TargetHostNameOrIP") {
                        if ($TargetHostInvCmdLocation) {
                            $GetVMAndHVSplatParams.Add("TargetHostNameOrIP",$TargetHostInvCmdLocation)
                        }
                        elseif ($TargetHostNameOrIP) {
                            $GetVMAndHVSplatParams.Add("TargetHostNameOrIP",$TargetHostNameOrIP)
                        }
                    }
                    elseif ($TargetVMName -and $GetVMAndHVSplatParams.Keys -notcontains "TargetVMName") {
                        $GetVMAndHVSplatParams.Add("TargetVMName",$TargetVMName)
                    }

                    if ($TargetHostNameCreds -and $GetVMAndHVSplatParams.Keys -notcontains "TargetHostNameCreds") {
                        $GetVMAndHVSplatParams.Add("TargetHostNameCreds",$TargetHostNameCreds)
                    }

                    if ($($HypervisorFQDNOrIP -or $HypervisorInvCmdLocation) -and $GetVMAndHVSplatParams.Keys -notcontains "HypervisorFQDNOrIP") {
                        if ($HypervisorInvCmdLocation) {
                            $GetVMAndHVSplatParams.Add("HypervisorFQDNOrIP",$HypervisorInvCmdLocation)
                        }
                        elseif ($HypervisorFQDNOrIP) {
                            $GetVMAndHVSplatParams.Add("HypervisorFQDNOrIP",$HypervisorFQDNOrIP)
                        }
                    }

                    if ($HypervisorCreds -and $GetVMAndHVSplatParams.Keys -notcontains "HypervisorCreds") {
                        $GetVMAndHVSplatParams.Add("HypervisorCreds",$HypervisorCreds)
                    }
                    
                    if ($($TryWithoutHypervisorInfo -and $GetVMAndHVSplatParams.Keys -notcontains "TryWithoutHypervisorInfo") -or 
                    $($(ConfirmAWSVM -EA SilentlyContinue) -or $(ConfirmAzureVM -EA SilentlyContinue) -or
                    $(ConfirmGoogleComputeVM -EA SilentlyContinue))
                    ) {
                        $GetVMAndHVSplatParams.Add("TryWithoutHypervisorInfo",$True)
                    }

                    if ($AllowRestarts -and $GetVMAndHVSplatParams.Keys -notcontains "AllowRestarts") {
                        $GetVMAndHVSplatParams.Add("AllowRestarts",$True)
                    }

                    if ($NoMacAddressSpoofing -and $GetVMAndHVSplatParams.Keys -notcontains "NoMacAddressSpoofing") {
                        $GetVMAndHVSplatParams.Add("NoMacAddressSpoofing",$True)
                    }

                    if ($SkipHyperVInstallCheck -and $GetVMAndHVSplatParams.Keys -notcontains "SkipHyperVInstallCheck") {
                        $GetVMAndHVSplatParams.Add("SkipHyperVInstallCheck",$True)
                    }

                    if ($SkipExternalvSwitchCheck -and $GetVMAndHVSplatParams.Keys -notcontains "SkipExternalvSwitchCheck") {
                        $GetVMAndHVSplatParams.Add("SkipExternalvSwitchCheck",$True)
                    }

                    try {
                        $GuestVMAndHVInfo = Get-GuestVMAndHypervisorInfo @GetVMAndHVSplatParams -ErrorAction SilentlyContinue -ErrorVariable GGIErr
                        if (!$GuestVMAndHVInfo) {throw "The Get-GuestVMAndHypervisorInfo function failed! Halting!"}
                    }
                    catch {
                        Write-Error $_
                        if ($($GGIErr | Out-String) -match "The operation has timed out") {
                            Write-Error "There was a problem downloading the Vagrant Box to be used to test the External vSwitch! Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            Write-Host "Errors for the Get-GuestVMAndHypervisorInfo function are as follows:"
                            Write-Error $($GGIErr | Out-String)
                            $global:FunctionResult = "1"
                            return
                        }
                    }

                    $EnableNestedVMSplatParams = @{
                        GuestVMAndHVInfo        = $GuestVMAndHVInfo
                        SkipPrompt              = $True
                        ErrorAction             = "SilentlyContinue"
                        ErrorVariable           = "ENVErr"
                        WarningAction           = "SilentlyContinue"
                        SkipHyperVInstallCheck  = $True
                    }
                    if ($TryWithoutHypervisorInfo) {
                        $EnableNestedVMSplatParams.Add("TryWithoutHypervisorInfo",$True)
                    }
                    if ($NoMacAddressSpoofing) {
                        $EnableNestedVMSplatParams.Add("NoMacAddressSpoofing",$True)
                    }
                    if ($NATIP) {
                        $EnableNestedVMSplatParams.Add("NATIP",$NATIP)
                    }
                    if ($NATNetworkMask) {
                        $EnableNestedVMSplatParams.Add("NATNetworkMask",$NATNetworkMask)
                    }
                    if ($NATName) {
                        $EnableNestedVMSplatParams.Add("NATName",$NATName)
                    }
                    
                    try {
                        $EnableNestedVMResults = EnableNestedVM @EnableNestedVMSplatParams
                        if (!$EnableNestedVMResults) {throw "The EnableNestedVM function failed! Halting!"}
                    }
                    catch {
                        Write-Error $_
                        Write-Host "Errors for the EnableNestedVM function are as follows:"
                        Write-Error $($ENVErr | Out-String)
                        $global:FunctionResult = "1"
                        return
                    }
                }
                else {
                    Write-Host "Sleeping for 180 seconds to wait for Guest VM to be ready..."
                    Start-Sleep -Seconds 180
                }
            }

            if ($EnableNestedVMResults.UnsatisfiedChanges.Count -gt 1 -or
            $($EnableNestedVMResults.UnsatisfiedChanges.Count -eq 1 -and $EnableNestedVMResults.UnsatisfiedChanges[0] -ne "None")
            ) {
                $GuestVMReady = $False
            }
            else {
                $GuestVMReady = $True
            }

            if (!$GuestVMReady) {
                $EnableNestedVMResults
                Write-Error "The EnableNestedVM function was not able to make all necessary changes to the Guest VM $($GuestVMAndHVInfo.HostNameNetworkInfo.HostName)! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    }
    if ($InstallEnvironment -eq "BareMetal") {
        # Determine where this function is being run
        try {
            $HostNameNetworkInfo = ResolveHost -HostNameOrIP $TargetHostNameOrIP
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        if ($env:ComputerName -match "$($HostNameNetworkInfo.HostName)|$($HostNameNetworkInfo.FQDN)") {
            $Locale = "BareMetalTarget"
        }
        else {
            $Locale = "Elsewhere"
        }

        if ($AllowRestarts) {
            if ($env:ComputerName -eq $HostNameNetworkInfo.HostName) {
                $DefaultRestartWarning = "If any restarts occur, Docker will NOT have been installed " +
                "(only prerequisites will have been configured). To complete Docker installation after restart, " +
                "you must re-run the Install-Docker function AFTER restarting!"
                Write-Warning $DefaultRestartWarning
            }
        }
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    if ($InstallEnvironment -eq "GuestVM") {
        Write-Host "Attempting to install DockerCE on Guest VM..."
    }
    if ($InstallEnvironment -eq "BareMetal") {
        if ($PSBoundParameters['NoMacAddressSpoofing'] -or $PSBoundParameters['GuestVMAndHVInfo'] -or
        $PSBoundParameters['SkipEnableNestedVM'] -or $PSBoundParameters['GuestVMMemoryInGB'] -or
        $PSBoundParameters['HypervisorFQDNOrIP'] -or $PSBoundParameters['HypervisorCreds']
        ) {
            $ErrMsg = "The parameters -NoMacAddressSpoofing, -GuestVMAndHVInfo, -SkipEnableNestedVM, -GuestVMMemoryInGB, " +
            "-HypervisorFQDNOrIP, and -HypervisorCreds are only meant to be used when installing Docer CE on a " +
            "Guest VM, but the install environment was determined to be Bare Metal! Halting!"
            Write-Error $ErrMsg
            $global:FunctionResult = "1"
            return
        }
        Write-Host "Attempting to install DockerCE on Baremetal..."
    }

    if ($Locale -match "GuestVM|BareMetalTarget") {
        $DoDockerInstallSplatParams = @{}
        if ($MobyLinuxVMMemoryInGB) {
            $DoDockerInstallSplatParams.Add("MobyLinuxVMMemoryInGB",$MobyLinuxVMMemoryInGB)
        }
        if ($AllowRestarts) {
            $DoDockerInstallSplatParams.Add("AllowRestarts",$True)
        }
        if ($SkipHyperVInstallCheck) {
            $DoDockerInstallSplatParams.Add("SkipHyperVInstallCheck",$True)
        }
        if ($RecreateMobyLinuxVM) {
            $DoDockerInstallSplatParams.Add("RecreateMobyLinuxVM",$RecreateMobyLinuxVM)
        }
        if ($PreRelease) {
            $DoDockerInstallSplatParams.Add("PreRelease",$True)
        }
        if ($AllowLogout) {
            $DoDockerInstallSplatParams.Add("AllowLogout",$True)
        }

        try {
            DoDockerInstall @DoDockerInstallSplatParams
        }
        catch {
            Write-Error $_
            Write-Error "The DoDockerInstall function failed! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    if ($Locale -match "Hypervisor|Elsewhere") {
        # Solution to define local function in remote Invoke-Command ScriptBlock from:
        # https://www.reddit.com/r/PowerShell/comments/7oux5q/invokecommandas_on_remote_machine_using/
        $FunctionsForRemoteUse = @(
            ${Function:Update-PackageManagement}.Ast.Extent.Text
            ${Function:Manual-PSGalleryModuleInstall}.Ast.Extent.Text
            ${Function:GetElevation}.Ast.Extent.Text
            ${Function:Install-Program}.Ast.Extent.Text
            ${Function:Install-ChocolateyCmdLine}.Ast.Extent.Text
            ${Function:Refresh-ChocolateyEnv}.Ast.Extent.Text
            ${Function:InstallFeatureDism}.Ast.Extent.Text
            ${Function:InstallHyperVFeatures}.Ast.Extent.Text
            ${Function:TestIsValidIPAddress}.Ast.Extent.Text
            ${Function:GetvSwitchAllRelatedInfo}.Ast.Extent.Text
            ${Function:DoDockerInstall}.Ast.Extent.Text
            ${Function:GetFileLockProcess}.Ast.Extent.Text
        )
    
        $RunDockerInstallSB = {
            # Load the functions we packed up:
            $using:FunctionsForRemoteUse | foreach { Invoke-Expression $_ }

            $DoDockerInstallSplatParams = @{}
            if ($using:MobyLinuxVMMemoryInGB) {
                $DoDockerInstallSplatParams.Add("MobyLinuxVMMemoryInGB",$using:MobyLinuxVMMemoryInGB)
            }
            if ($using:AllowRestarts) {
                $DoDockerInstallSplatParams.Add("AllowRestarts",$True)
            }
            if ($using:SkipHyperVInstallCheck) {
                $DoDockerInstallSplatParams.Add("SkipHyperVInstallCheck",$True)
            }
            if ($using:RecreateMobyLinuxVM) {
                $DoDockerInstallSplatParams.Add("RecreateMobyLinuxVM",$True)
            }
            if ($using:PreRelease) {
                $DoDockerInstallSplatParams.Add("PreRelease",$True)
            }
    
            DoDockerInstall @DoDockerInstallSplatParams
        }
    
        if ($GuestVMAndHVInfo) {
            # The fact that $GuestVMAndHVInfo has TargetHostNameCreds means that they work because the
            # Get-GuestVMAndHypervisorInfo function figured that out for us.
            $TargetHostNameCreds = $GuestVMAndHVInfo.TargetHostNameCreds
            if ($TargetHostNameCreds -eq $(whoami)) {
                $TargetHostNameCreds = $null
            }
    
            $TargetHostInvCmdLocation = $GuestVMAndHVInfo.TargetHostInvCmdLocation
        }

        $DockerInstallSplatParams = @{
            ComputerName        = $TargetHostInvCmdLocation
            ScriptBlock         = $RunDockerInstallSB
        }
        if ($TargetHostNameCreds) {
            $DockerInstallSplatParams.Add("Credential",$TargetHostNameCreds)
        }
    
        try {
            $InvokeCommandOutput = Invoke-Command @DockerInstallSplatParams -ErrorAction SilentlyContinue -ErrorVariable DoDockerErr
    
            if ($InvokeCommandOutput -eq "Restarting") {
                Write-Host "$($TargetHostInvCmdLocation) is restarting..."
            }
            elseif ($InvokeCommandOutput -eq $null) {
                throw "The DoDockerInstall function failed!"
            }
            elseif ($InvokeCommandOutput -ne $null) {
                $InvokeCommandOutput
                return
            }
        }
        catch {
            if ($($_ | Out-String) -match "The I/O operation has been aborted") {
                $CaughtRestarting = $True
            }
            else {
                Write-Error $_
                Write-Host "Errors for the DoDockerInstall function are as follows:"
                Write-Error $($DoDockerErr | Out-String)
                $global:FunctionResult = "1"
                return
            }
        }
    
        # Run the DoDockerInstall function again on the Target Guest VM
        if ($InvokeCommandOutput -eq "Restarting" -or $CaughtRestarting) {
            # IMPORTANT NOTE: Depending on the Hyper-V features that needed to be Enabled, in the first run
            # of DoDocker install, the Guest VM might restart TWICE before it's ready.
            # With each restart, the OS takes about 90 seconds to boot, and feature installation
            # operations take about 60 seconds per reboot, so we're looking at 300 seconds, ande we'll
            # add another 60 seconds just to make sure, making it 360 seconds
            Write-Host "Sleeping for 360 seconds..."
            Start-Sleep -Seconds 360
            Write-Host "Running DoDockerInstall post-restart..."
    
            try {
                $InvokeCommandOutput = Invoke-Command @DockerInstallSplatParams -ErrorAction SilentlyContinue -ErrorVariable DoDockerErr
    
                if ($InvokeCommandOutput -eq "Restarting") {
                    Write-Host "$($TargetHostInvCmdLocation) is restarting..."
                }
                elseif ($InvokeCommandOutput -eq $null) {
                    throw "The DoDockerInstall function failed!"
                }
                elseif ($InvokeCommandOutput -ne $null) {
                    $InvokeCommandOutput
                    return
                }
            }
            catch {
                Write-Error $_
                Write-Host "Errors for the DoDockerInstall function are as follows:"
                Write-Error $($DoDockerErr | Out-String)
                $global:FunctionResult = "1"
                return
            }
        }
    }
    
    ##### END Main Body #####
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUSy9ROhRoTX2YBYB8W2Qi+nGJ
# 7g+gggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFDuz0LB0U6i3OPdp
# 4jTMcO7g5CjDMA0GCSqGSIb3DQEBAQUABIIBAHYM48R+gTvp/aCCRAy48iJAx3kf
# Ifu+u9qBtuUMOSJAM7spRKIVIxzfEQKRNJbnMjrqchMPJMNjKSkUgLKG0F57GYxn
# KSR3aohzlpUPTKd3HwR+1aenyZequddN8E1Nx3iPclzDcVWUl4Ij3ioOfYJsB1mW
# fdg5k64kCYjdDjMq3fwg4byb3k6HrP1ELOU8ioCFEv1IlD131bK7kvycAZK+pJT9
# VzQtoYrXbLPMstzMsNx0NJvMVVoVoYXXa4pj7SJkvbKS9xj75flUO80Ncv5s9ek3
# Rz8vpnjo1uOVPG4JQmsIE9fMq+3qjB1/pst+9xv5vuJEUqlcOrnzbubdhyM=
# SIG # End signature block
