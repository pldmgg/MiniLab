function EnableNestedVM {
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

        # -NoMacAddressSpoofing WILL result in creating a Local NAT with an Internal vSwitch on the
        # Target Machine (assuming it's a Guest VM). Maybe change this parameter to 'CreateNAT' instead
        # of 'NoMacAddressSpoofing'
        [Parameter(Mandatory=$False)]
        [switch]$NoMacAddressSpoofing,

        # -TryWithoutHypervisorInfo MIGHT result in creating a Local NAT
        # with an Internal vSwitch on the Target Machine (assuming it's a Guest VM). It depends if
        # Get-NestedVirtCapabilities detemines whether the Target Machine can use an External vSwitch or not.
        # If it can, then a Local NAT will NOT be created.
        # If a NAT already exists on the Target Machine, that NAT will be changed to
        # 10.0.75.0/24 with IP 10.0.75.1 if it isn't already
        [Parameter(Mandatory=$False)]
        [switch]$TryWithoutHypervisorInfo,

        # If used along with $TryWithoutHypervisorInfo, if
        # $GuestVMNestedVirtCapabilties.NetworkingPossibilities -eq "Mac Address Spoofing", creates a Local NAT
        # on the TargetMachine (as opposed to assuming Mac Address Spoofing is enabled on the Hyper-V hypervisor
        # for the Guest VM and using an External vSwitch)
        # IMPORANT: If a NAT already exists on the Target Machine, that NAT will be changed to
        # 10.0.75.0/24 with IP 10.0.75.1 if it isn't already
        [Parameter(Mandatory=$False)]
        [switch]$Force,

        [Parameter(Mandatory=$False)]
        [string]$NATIP,

        [Parameter(Mandatory=$False)]
        [ValidateRange(24,31)]
        [int]$NATNetworkMask,

        [Parameter(Mandatory=$False)]
        [string]$NATName,

        [Parameter(
            Mandatory=$True,
            ParameterSetName = 'InfoAlreadyCollected'
        )]
        $GuestVMAndHVInfo, # Uses output of Get-GuestVMAndHypervisorInfo function

        [Parameter(Mandatory=$False)]
        [switch]$SkipPrompt,

        [Parameter(Mandatory=$False)]
        [switch]$SkipHyperVInstallCheck,

        [Parameter(Mandatory=$False)]
        [ValidateScript({
            $(($_ % 4) -eq 0) -and $($_ -ge 4)
        })]
        [int]$GuestVMMemoryInGB,

        [Parameter(Mandatory=$False)]
        [switch]$AllowRestarts
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if (!$(GetElevation)) {
        Write-Error "This function must be used from an Elevated PowerShell Session (i.e. Run As Administrator)! Halting!"
        $global:FunctionResult = "1"
        return
    }

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

    if ($NATIP) {
        if (!$(TestIsValidIPAddress -IPAddress $NATIP)) {
            Write-Error "$NATIP is NOT a valid IPv4 IP Address! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($Force -and !$TryWithoutHypervisorInfo) {
        Write-Error "The -Force switch should only be used if the -TryWithoutHypervisor info switch is also used! Halting!"
        $global:FunctionResult = "1"
        return
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
                Write-Error "The Get-WorkingCredentials function failed! Check the credentials provided to the -TargetHostNameCreds parameter! Halting!"
            }
            else {
                Write-Error "The Get-WorkingCredentials function failed! Try using the -TargetHostNameCreds parameter! Halting!"
            }
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

            if ($GuestVMAndHVInfo.RestartNeeded -and $RebootPendingCheck -and $RebootPendingFileCheck -ne $null -and !$AllowRestarts) {
                Write-Verbose "You might need to restart $env:ComputerName before the GetNestedVirtCapabilities function can proceed! Halting!"
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

    if (!$HypervisorCreds -and !$GuestVMAndHVInfo.HypervisorCreds -and 
    $($GuestVMAndHVInfo.HypervisorComputerInfo -eq $null -or
    $GuestVMAndHVInfo.HypervisorNetworkInfo -eq $null -or
    $GuestVMAndHVInfo.HypervisorOSInfo -eq $null -or
    $(ConfirmAWSVM -EA SilentlyContinue) -or $(ConfirmAzureVM -EA SilentlyContinue) -or
    $(ConfirmGoogleComputeVM -EA SilentlyContinue))
    ) {
        $TryWithoutHypervisorInfo = $True
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

    try {
        $GuestNestedVirtCapabiltiesSplatParams = @{
            ErrorAction         = "SilentlyContinue"
            ErrorVariable       = "GNCErr"
            WarningAction       = "SilentlyContinue"
            GuestVMAndHVInfo    = $GuestVMAndHVInfo
        }
        if ($TryWithoutHypervisorInfo) {
            $GuestNestedVirtCapabiltiesSplatParams.Add("TryWithoutHypervisorInfo",$True)
        }
        if ($SkipHyperVInstallCheck) {
            $GuestNestedVirtCapabiltiesSplatParams.Add("SkipHyperVInstallCheck",$True)
        }

        $GuestVMNestedVirtCapabilties = GetNestedVirtCapabilities @GuestNestedVirtCapabiltiesSplatParams
        if (!$GuestVMNestedVirtCapabilties) {throw "The Get-NestedVirtCapabiltiies function failed! Halting!"}
    }
    catch {
        Write-Error $_
        Write-Host "Errors from the GetNestedVirtCapabilities function are as follows:"
        Write-Error $($GNCErr | Out-String)
        $global:FunctionResult = "1"
        return
    }

    if ($GuestVMNestedVirtCapabilties.NestedVirtualizationPossible -eq $False) {
        if ($TryWithoutHypervisorInfo -and !$Force) {
            Write-Warning "Nested Virtualization is NOT possible without access to the hypervisor. Steps to remediate are as follows:"
            $GuestVMNestedVirtCapabilties.StepsToAllow64BitNestedVMs
            $global:FunctionResult = "1"
            return
        }
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

    if (!$TryWithoutHypervisorInfo) {
        if ($AllowRestarts -and $Locale -eq "GuestVM" -and !$SkipPrompt) {
            Write-Warning "The Guest VM (i.e. this computer - $env:ComputerName) might need to be restarted in order to enable Nested Virtualization!"
            $ContinueChoice = Read-Host -Prompt "Are you sure you want to continue? [Yes\No]"
            if ($ContinueChoice -notmatch "Yes|yes|Y|y") {
                Write-Error "User chose not to proceed! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        $VMInfo = $GuestVMAndHVInfo.TargetVMInfoFromHyperV
        $VMName = $VMInfo.VMName
        $VMProcessorInfo = $GuestVMAndHVInfo.VMProcessorInfo
        $VMNetworkAdapterInfo = $GuestVMAndHVInfo.VMNetworkAdapterInfo
        $VMMemoryInfo = $GuestVMAndHVInfo.VMMemoryInfo

        # Add some additional properties to $VMInfo
        Add-Member -InputObject $VMInfo NoteProperty -Name "ExposeVirtualizationExtensions" -Value $VMProcessorInfo.ExposeVirtualizationExtensions -Force
        Add-Member -InputObject $VMInfo NoteProperty -Name "SnapshotEnabled" -Value $false -Force
        Add-Member -InputObject $VMInfo NoteProperty -Name "MacAddressSpoofing" -Value $VMNetworkAdapterInfo.MacAddressSpoofing -Force
        Add-Member -InputObject $VMInfo NoteProperty -Name "MemorySize" -Value $VMMemoryInfo.Startup -Force
    }

    # Constants
    $4GB = 4294967296

    if ($GuestVMMemoryInGB) {
        $Factor = $GuestVMMemoryInGB / 4
        $FinalMem = $4GB * $Factor
    }
    elseif ($VMMemoryInfo) {
        if ($VMMemoryInfo.Startup -lt $4GB) {
            $FinalMem = $4GB
        }
        else {
            $FinalMem = $VMMemoryInfo.Startup
        }
    }
    else {
        $FinalMem = $4GB
    }
    $FinalMemRounded = ConvertSize -From Bytes -To GB -Value $FinalMem

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    if (!$TryWithoutHypervisorInfo) {
        #Write-Host "`nThis function will set the following for $VMName in order to enable nesting:"
        Write-Host ""

        $prompt = $false
        
        [System.Collections.ArrayList]$NeededChanges = @()
        [System.Collections.ArrayList]$AttemptedChanges = @()
        [System.Collections.ArrayList]$UnsatisfiedChanges = @()
        # Output text for proposed actions
        if ($VMInfo.State -eq 'Saved') {
            if ($AllowRestarts) {
                Write-Host "Vm State: $($VMInfo.State)" -ForegroundColor yellow
                Write-Warning "$VMName will be restarted"
                Write-Warning "Saved state will be removed"
                $prompt = $true
                $null = $AttemptedChanges.Add("RemoveSavedState")
                if ($AttemptedChanges -notcontains "Restart") {
                    $null = $AttemptedChanges.Add("Restart")
                }
            }
            else {
                $WarnMsgAllowRestarts = "The -AllowRestarts parameter was NOT used. The VM $VMName needs to " +
                "be turned OFF in order to remove the Saved state! Please do so manually on the Hyper-V Host via: " +
                "`n    Stop-VM -VMName $VMName`n    Remove-VMSavedState -VMName $VMName"
                Write-Warning $WarnMsgAllowRestarts
                $null = $UnsatisfiedChanges.Add("RemoveSavedState")
            }
            $null = $NeededChanges.Add("RemoveSavedState")
            if ($NeededChanges -notcontains "Restart") {
                $null = $NeededChanges.Add("Restart")
            }
        }
        if ($VMInfo.DynamicMemoryEnabled -eq $true) {
            if ($AllowRestarts) {
                Write-Warning "$VMName will be restarted"
                Write-Warning "Dynamic memory will be disabled"
                $prompt = $true
                $null = $AttemptedChanges.Add("DisableDynamicMemory")
                if ($AttemptedChanges -notcontains "Restart") {
                    $null = $AttemptedChanges.Add("Restart")
                }
            }
            else {
                $WarnMsgAllowRestarts1 = "The -AllowRestarts parameter was NOT used. Dynamic memory for the VM " +
                "$VMName needs to be disabled. Please do so manually on the Hyper-V Host while $VMName is OFF via:" +
                "`n    Stop-VM -VMName $VMName`n    Set-VMMemory -VMName $VMName -DynamicMemoryEnabled `$false"
                Write-Warning $WarnMsgAllowRestarts1
                $null = $UnsatisfiedChanges.Add("DisableDynamicMemory")
                if ($UnsatisfiedChanges -notcontains "Restart") {
                    $null = $UnsatisfiedChanges.Add("Restart")
                }
            }
            $null = $NeededChanges.Add("DisableDynamicMemory")
            if ($NeededChanges -notcontains "Restart") {
                $null = $NeededChanges.Add("Restart")
            }
        }
        if ($VMInfo.ExposeVirtualizationExtensions -eq $false) {
            if ($AllowRestarts) {
                Write-Warning "$VMName will be restarted"
                Write-Warning "Virtualization extensions will be enabled"
                $prompt = $true
                $null = $AttemptedChanges.Add("ExposeVirtualizationExtensions")
                if ($AttemptedChanges -notcontains "Restart") {
                    $null = $AttemptedChanges.Add("Restart")
                }
            }
            else {
                $WarnMsgAllowRestarts2 = "The -AllowRestarts parameter was NOT used. Virtualization extensions for the " +
                "VM $VMName needs to be exposed. Please do so manually on the Hyper-V Host while $VMName is OFF via:" +
                "`n    Stop-VM -VMName $VMName`n    Set-VMProcessor -VMName $VMName -ExposeVirtualizationExtensions `$true"
                Write-Warning $WarnMsgAllowRestarts2
                $null = $UnsatisfiedChanges.Add("ExposeVirtualizationExtensions")
                if ($UnsatisfiedChanges -notcontains "Restart") {
                    $null = $UnsatisfiedChanges.Add("Restart")
                }
            }
            $null = $NeededChanges.Add("ExposeVirtualizationExtensions")
            if ($NeededChanges -notcontains "Restart") {
                $null = $NeededChanges.Add("Restart")
            }
        }
        if ($VMInfo.MacAddressSpoofing -eq 'Off' -and !$NoMacAddressSpoofing) {
            Write-Warning "MAC address spoofing will be enabled."
            $prompt = $true
            $null = $NeededChanges.Add("TurnMacSpoofingOn")
            $null = $AttemptedChanges.Add("TurnMacSpoofingOn")
        }
        if ($VMInfo.MemorySize -ne $FinalMem) {
            Write-Warning "VM memory will be set to $FinalMemRounded GB"
            $prompt = $true
            $null = $NeededChanges.Add("AdjustStartupMemory")
            $null = $AttemptedChanges.Add("AdjustStartupMemory")
        }
        if ($VMInfo.ProcessorCount -lt 2) {
            Write-Warning "VM Processor Count will be set to 2"
            $prompt = $true
            $null = $NeededChanges.Add("UpProcessorCount")
            $null = $AttemptedChanges.Add("UpProcessorCount")
        }
        if ($GuestVMNestedVirtCapabilties.NetworkingPossibilities -contains "Mac Address Spoofing" -and !$NoMacAddressSpoofing) {
            Write-Warning "Mac Address Spoofing is enabled. We will NOT create a NAT interface on the Guest VM. No action taken."
        }
        if ($NoMacAddressSpoofing -or $NATIP -or $NATNetworkMask) {
            if (!$NATIP) {
                $NATIP = "10.0.75.1"
            }
            if (!$NATNetworkMask) {
                $NATNetworkMask = 24
            }
            $IPRange = Get-IPRange -ip $NATIP -cidr $NATNetworkMask
            $NATSubnet = "$($IPRange[0])/$NATNetworkMask"

            $WarnMsg1 = "On $VMName, if an Internal vSwitch called 'LocalNAT' does NOT already exist and if NO OTHER Network Adapter " +
            "is using subnet $NATSubnet with IP $NATIP, then an Internal vSwitch called 'LocalNAT' will be created"
            Write-Warning $WarnMsg1
            $prompt = $True
        }

        if ($prompt) {
            if (!$SkipPrompt) {
                Write-Host ""
                $char = Read-Host -Prompt "Do you agree to all of these changes to VM $VMName`? [Yes/No]"
                while ($char -notmatch "Yes|yes|Y|y|No|no|N|n") {
                    Write-Host "Invalid Input, Y or N"
                    $char = Read-Host -Prompt "Do you agree to all of these changes to VM $VMName`? [Yes/No]"
                }
            }
            else {
                $char = "Yes"
            }
        }

        if ($char -match "Yes|yes|Y|y") {
            [System.Collections.ArrayList]$VMSettingsThatWereChanged = @()

            if ($NoMacAddressSpoofing) {
                if ($Locale -eq "GuestVM") {
                    if (!$SkipHyperVInstallCheck) {
                        # Install Hyper-V Features if they haven't aready

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
                        try {
                            $InstallContainersFeatureDismResult = InstallFeatureDism -Feature Containers -ParentFunction $MyInvocation.MyCommand.Name
                        }
                        catch {
                            Write-Error $_
                            Write-Error "The InstallFeatureDism function (as executed by the $($MyInvocation.MyCommand.Name) function) failed! Halting!"
                            $global:FunctionResult = "1"
                            return
                        }

                        if ($HyperVFeaturesInstallResults.InstallFailures.Count -gt 0) {
                            Write-Error "Please remedy the Hyper-V Features that failed to install before proceeding. Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        
                        if ($HyperVFeaturesInstallResults.InstallResults.RestartNeeded -notcontains $True -and !$InstallContainersFeatureDismResult.RestartNeeded) {
                            Write-Host "All dependencies are already installed...proceeding..." -ForegroundColor Green
                        }
                        else {
                            if ($HyperVFeaturesInstallResults.InstallResults.RestartNeeded -contains $True -or $InstallContainersFeatureDismResult.RestartNeeded) {
                                if ($AllowRestarts) {
                                    Write-Host "Shutting down $env:ComputerName..."
                                    # NOTE: The below output "Restarting" is important when running this function via Invoke-Command
                                    $null = $VMSettingsThatWereChanged.Add("HyperVInstall")
                                    $null = $VMSettingsThatWereChanged.Add("Restart")
                                    Stop-Computer -Confirm:$false
                                }
                                else {
                                    Write-Error "You must restart $env:ComputerName before proceeding! Halting!"
                                    return
                                }
                            }
                        }
                    }

                    try {
                        if ($(Get-Module -ListAvailable).Name -notcontains "Hyper-V" -and $(Get-Module).Name -notcontains "Hyper-V") {
                            throw "Hyper-V does NOT appear to be installed on $env:ComputerName! Halting!"
                        }
                        # NOTE: New-VMSwitch is the cmdlet that actually creates the Network Adapter called 'vEthernet ($NATName)'
                        # New-NetNat is another type of object that we just happen to be calling the same thing (i.e. '$NATName'),
                        # but it doesn't HAVE to be named the same thing.

                        # NOTE: 10.075.0/24 is the default Docker For Windows (i.e. Docker CE) NAT subnet. Figured we might as well
                        # use the same if one isn't provided to the is function.
                        if (!$NATIP) {
                            $NATIP = "10.0.75.1"
                        }
                        if (!$NATNetworkMask) {
                            $NATNetworkMask = 24
                        }
                        if (!$NATName) {
                            $NATName = "LocalNAT"
                        }
                        $NATSubnet = "$NATIP/$NATNetworkMask"

                        [System.Collections.ArrayList]$ExistingvSwitchInfo = @()
                        if ([bool]$(GetvSwitchAllRelatedInfo -IPAddress $NATIP -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)) {
                            $vSwitchInfoByIP = GetvSwitchAllRelatedInfo -IPAddress $NATIP -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

                            if ($vSwitchInfoByIP) {
                                $null = $ExistingvSwitchInfo.Add($vSwitchInfoByIP)
                            }
                        }
                        if ([bool]$(GetvSwitchAllRelatedInfo -vSwitchName $NATName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)) {
                            $vSwitchInfoByName = GetvSwitchAllRelatedInfo -vSwitchName $NATName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

                            if ($vSwitchInfoByName) {
                                $null = $ExistingvSwitchInfo.Add($vSwitchInfoByName)
                            }
                        }

                        if ($ExistingvSwitchInfo.Count -eq 0) {
                            if ($PSVersionTable.PSEdition -eq "Core") {
                                Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                                    $null = New-NetNat -Name $args[0] -InternalIPInterfaceAddressPrefix $args[1]
                                    $null = New-VMSwitch -Name $args[0] -SwitchType Internal
                                    $null = Get-NetAdapter "vEthernet ($($args[0]))" | New-NetIPAddress -IPAddress $args[2] -AddressFamily IPv4 -PrefixLength $args[3]
                                } -ArgumentList $NATName,$NATSubnet,$NATIP,$NATNetworkMask
                            }
                            else {
                                $null = New-NetNat -Name $NATName -InternalIPInterfaceAddressPrefix $NATSubnet
                                $null = New-VMSwitch -Name $NATName -SwitchType Internal
                                $null = Get-NetAdapter "vEthernet ($NATName)" | New-NetIPAddress -IPAddress $NATIP -AddressFamily IPv4 -PrefixLength $NATNetworkMask
                            }
                        
                            $null = $NeededChanges.Add("NetworkAddressTranslation")
                            $null = $AttemptedChanges.Add("NetworkAddressTranslation")
                            $null = $VMSettingsThatWereChanged.Add("NetworkAddressTranslation")
                        }
                        else {
                            $null = $NeededChanges.Add("None - LocalNAT Already Exists")
                        }
                    }
                    catch {
                        Write-Error $_
                        Write-Warning "Failed to create 'vEthernet ($NATName)'! However, it is possible that Mac Address Spoofing is enabled on this Guest VM, in which case NAT is not needed."
                    }
                }
                elseif ($Locale -match "Hypervisor|Elsewhere") {
                    $FunctionsForRemoteUse = @(
                        ${Function:InstallFeatureDism}.Ast.Extent.Text
                        ${Function:InstallHyperVFeatures}.Ast.Extent.Text
                        ${Function:TestIsValidIPAddress}.Ast.Extent.Text
                        ${Function:GetvSwitchAllRelatedInfo}.Ast.Extent.Text
                    )
        
                    $NewNatSB = {
                        # Load the functions we packed up:
                        $using:FunctionsForRemoteUse | foreach { Invoke-Expression $_ }
                        [System.Collections.ArrayList]$VMSettingsThatWereChangedInSB = @()
                        
                        if (!$using:SkipHyperVInstallCheck) {
                            # Install Hyper-V Features if they haven't aready

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
                            try {
                                $InstallContainersFeatureDismResult = InstallFeatureDism -Feature Containers -ParentFunction $MyInvocation.MyCommand.Name
                            }
                            catch {
                                Write-Error $_
                                Write-Error "The InstallFeatureDism function (as executed by the $($MyInvocation.MyCommand.Name) function) failed! Halting!"
                                $global:FunctionResult = "1"
                                return
                            }

                            if ($HyperVFeaturesInstallResults.InstallFailures.Count -gt 0) {
                                Write-Error "Please remedy the Hyper-V Features that failed to install before proceeding. Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                            
                            if ($HyperVFeaturesInstallResults.InstallResults.RestartNeeded -notcontains $True -and !$InstallContainersFeatureDismResult.RestartNeeded) {
                                Write-Host "All dependencies are already installed...proceeding..." -ForegroundColor Green
                            }
                            else {
                                if ($HyperVFeaturesInstallResults.InstallResults.RestartNeeded -contains $True -or $InstallContainersFeatureDismResult.RestartNeeded) {
                                    if ($using:AllowRestarts) {
                                        Write-Host "Shutting down $env:ComputerName..."
                                        # NOTE: The below output "Restarting" is important when running this function via Invoke-Command
                                        $null = $VMSettingsThatWereChangedInSB.Add("HyperVInstall")
                                        $null = $VMSettingsThatWereChangedInSB.Add("Restart")
                                        $VMSettingsThatWereChangedInSB
                                        Stop-Computer -Confirm:$false
                                        return
                                    }
                                    else {
                                        Write-Error "You must restart $env:ComputerName before proceeding! Halting!"
                                        $null = $VMSettingsThatWereChangedInSB.Add("HyperVInstall")
                                        $null = $VMSettingsThatWereChangedInSB.Add("RestartNeeded")
                                        $VMSettingsThatWereChangedInSB
                                        return
                                    }
                                }
                            }
                        }

                        try {
                            if ($(Get-Module -ListAvailable).Name -notcontains "Hyper-V" -and $(Get-Module).Name -notcontains "Hyper-V") {
                                throw "Hyper-V does NOT appear to be installed on $env:ComputerName! Halting!"
                            }
                            # NOTE: New-VMSwitch is the cmdlet that actually creates the Network Adapter called 'vEthernet ($NATName)'
                            # New-NetNat is another type of object that we just happen to be calling the same thing (i.e. '$NATName'),
                            # but it doesn't HAVE to be named the same thing.

                            # NOTE: 10.075.0/24 is the default Docker For Windows (i.e. Docker CE) NAT subnet. Figured we might as well
                            # use the same if one isn't provided to the is function.
                            if (!$using:NATIP) {
                                $NATIPSB = "10.0.75.1"
                            }
                            else {
                                $NATIPSB = $using:NATIP
                            }
                            if (!$using:NATNetworkMask) {
                                $NATNetworkMaskSB = 24
                            }
                            else {
                                $NATNetworkMaskSB = $using:NATNetworkMask
                            }
                            if (!$using:NATName) {
                                $NATNameSB = "LocalNAT"
                            }
                            else {
                                $NATNameSB = $using:NATName
                            }
                            $NATSubnet = "$NATIPSB/$NATNetworkMaskSB"

                            [System.Collections.ArrayList]$ExistingvSwitchInfo = @()
                            if ([bool]$(GetvSwitchAllRelatedInfo -IPAddress $NATIPSB -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)) {
                                $vSwitchInfoByIP = GetvSwitchAllRelatedInfo -IPAddress $NATIPSB -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

                                if ($vSwitchInfoByIP) {
                                    $null = $ExistingvSwitchInfo.Add($vSwitchInfoByIP)
                                }
                            }
                            if ([bool]$(GetvSwitchAllRelatedInfo -vSwitchName $NATNameSB -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)) {
                                $vSwitchInfoByName = GetvSwitchAllRelatedInfo -vSwitchName $NATNameSB -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

                                if ($vSwitchInfoByName) {
                                    $null = $ExistingvSwitchInfo.Add($vSwitchInfoByName)
                                }
                            }
                            
                            if ($ExistingvSwitchInfo.Count -eq 0) {
                                if ($PSVersionTable.PSEdition -eq "Core") {
                                    Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                                        $null = New-NetNat -Name $args[0] -InternalIPInterfaceAddressPrefix $args[1]
                                        $null = New-VMSwitch -Name $args[0] -SwitchType Internal
                                        $null = Get-NetAdapter "vEthernet ($($args[0]))" | New-NetIPAddress -IPAddress $args[2] -AddressFamily IPv4 -PrefixLength $args[3]
                                    } -ArgumentList $NATNameSB,$NATSubnet,$NATIPSB,$NATNetworkMaskSB
                                }
                                else {
                                    $null = New-NetNat -Name $NATNameSB -InternalIPInterfaceAddressPrefix $NATSubnet
                                    $null = New-VMSwitch -Name $NATNameSB -SwitchType Internal
                                    $null = Get-NetAdapter "vEthernet ($NATNameSB)" | New-NetIPAddress -IPAddress $NATIPSB -AddressFamily IPv4 -PrefixLength $NATNetworkMaskSB
                                }
                                
                                $null = $VMSettingsThatWereChangedInSB.Add("NetworkAddressTranslation")
                            }
                            else {
                                $null = $VMSettingsThatWereChangedInSB.Add("None - LocalNAT Already Exists")
                            }

                            $VMSettingsThatWereChangedInSB
                        }
                        catch {
                            Write-Error $_
                            Write-Warning "Failed to create 'vEthernet ($NATNameSB)'! However, it is possible that Mac Address Spoofing is enabled on this Guest VM, in which case Nested VM networking will work as expected without NAT."
                        }
                    }

                    $InvCmdSplatParams = @{
                        ComputerName        = $GuestVMAndHVInfo.TargetHostInvCmdLocation
                        ScriptBlock         = $NewNatSB
                        ErrorAction         = "SilentlyContinue"
                        ErrorVariable       = "HVIErr"
                    }
                    if ($TargetHostNameCreds) {
                        $InvCmdSplatParams.Add("Credential",$TargetHostNameCreds)
                    }
            
                    try {
                        [array]$VMSettingsThatWereChangedPrep = Invoke-Command @InvCmdSplatParams
                        if (!$VMSettingsThatWereChangedPrep) {throw "The NewNATSB failed!"}

                        foreach ($Setting in $VMSettingsThatWereChangedPrep) {
                            $null = $VMSettingsThatWereChanged.Add($Setting)
                        }
                    }
                    catch {
                        if ($($HVIErr | Out-String) -notmatch "WinRM cannot complete the operation") {
                            Write-Error $_
                            $ErrMsgNewNATSB = "The EnableNestedVM function was unable to gather additional information " +
                            "about $($GuestVMAndHVInfo.TargetHostInvCmdLocation) by remoting into " +
                            "$($GuestVMAndHVInfo.TargetHostInvCmdLocation)! If a restart occurred, it might not be " +
                            "ready yet. Halting!"
                            Write-Error $ErrMsgNewNATSB
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            $RestartOccurredFlag = $True
                            $null = $VMSettingsThatWereChanged.Add("HyperVInstall")
                            $null = $AttemptedChanges.Add("HyperVInstall")
                            $null = $NeededChanges.Add("HyperVInstall")
                        }
                    }
                }
            }

            if ($Locale -eq "Hypervisor") {
                if ($($VMInfo.State -eq 'Saved' -or $VMInfo.DynamicMemoryEnabled -eq $true -or
                $VMInfo.ExposeVirtualizationExtensions -eq $false -or $VMInfo.ProcessorCount -lt 2) -and
                $AllowRestarts
                ) {
                    if ($VMSettingsThatWereChanged -contains "HyperVInstall") {
                        Start-Sleep -Seconds 30
                    }
                    while ($(Get-VM $VMName).State -ne "Off") {
                        if ($(Get-VM $VMName).State -ne "Stopping") {
                            try {
                                Stop-VM -VMName $VMName -TurnOff -Confirm:$False -Force -WarningAction SilentlyContinue -WarningVariable StateCheck
                            }
                            catch {
                                Start-Sleep -Seconds 15
                            }
                        }
                    }

                    $i = 0
                    while ($(Get-VM -Name $VMName).State -ne "Off") {
                        Write-Verbose "Waiting for $VMName to turn off..."
                        $i++
                        if ($i -gt 10) {
                            Write-Error "$VMName hasn't turned off within 10 seconds! Please check its status manually on the hypervisor. Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        Start-Sleep -Seconds 1
                    }

                    $null = $VMSettingsThatWereChangedInSB.Add("Restart")
                }
                if ($VMInfo.State -eq 'Saved' -and $AllowRestarts) {
                    Remove-VMSavedState -VMName $VMName
                    #Add-Member -InputObject $VMSettingsThatWereChanged NoteProperty -Name "SavedState" -Value "Removed"
                    $null = $VMSettingsThatWereChanged.Add("RemoveSavedState")
                }
                if ($VMInfo.DynamicMemoryEnabled -eq $true -and $AllowRestarts) {
                    Set-VMMemory -VMName $VMName -DynamicMemoryEnabled $false
                    #Add-Member -InputObject $VMSettingsThatWereChanged NoteProperty -Name "DynamicMemory" -Value "Disabled"
                    $null = $VMSettingsThatWereChanged.Add("DisableDynamicMemory")
                }
                if ($VMInfo.ExposeVirtualizationExtensions -eq $false -and $AllowRestarts) {
                    Set-VMProcessor -VMName $VMName -ExposeVirtualizationExtensions $true
                    #Add-Member -InputObject $VMSettingsThatWereChanged NoteProperty -Name "ExposeVirtualizationExtensions" -Value $true
                    $null = $VMSettingsThatWereChanged.Add("ExposeVirtualizationExtensions")
                }
                if ($VMInfo.MacAddressSpoofing -eq 'Off' -and !$NoMacAddressSpoofing) {
                    Set-VMNetworkAdapter -VMName $VMName -MacAddressSpoofing on
                    #Add-Member -InputObject $VMSettingsThatWereChanged NoteProperty -Name "MacAddressSpoofing" -Value "On"
                    $null = $VMSettingsThatWereChanged.Add("TurnMacSpoofingOn")
                }
                if ($VMInfo.MemorySize -ne $FinalMem) {
                    Set-VMMemory -VMName $VMName -StartupBytes $FinalMem
                    #Add-Member -InputObject $VMSettingsThatWereChanged NoteProperty -Name "VMMemory" -Value $FinalMem
                    $null = $VMSettingsThatWereChanged.Add("AdjustStartupMemory")
                }
                if ($VMInfo.ProcessorCount -lt 2) {
                    Set-VMProcessor -VMname $VMName -Count 2
                    #Add-Member -InputObject $VMSettingsThatWereChanged NoteProperty -Name "UpProcessorCount" -Value 2
                    $null = $VMSettingsThatWereChanged.Add("UpProcessorCount")
                }

                if ($(Get-VM -Name $VMName).State -eq "Off") {
                    Start-VM -VMName $VMName

                    $i = 0
                    while ($(Get-VM -Name $VMName).State -ne "Running") {
                        Write-Verbose "Waiting for $VMName to turn on..."
                        $i++
                        if ($i -gt 10) {
                            Write-Error "$VMName hasn't turned on within 10 seconds! Please check its status manually on the hypervisor. Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        Start-Sleep -Seconds 1
                    }
                }
            }

            if ($Locale -match "GuestVM|Elsewhere" -and
            $($GuestVMAndHVInfo.VirtualizationExtensionsExposed -eq $False -or
            $VMInfo.State -eq 'Saved' -or $VMInfo.DynamicMemoryEnabled -eq $true -or
            $VMInfo.ExposeVirtualizationExtensions -eq $false -or
            $($VMInfo.MacAddressSpoofing -eq 'Off' -and !$NoMacAddressSpoofing) -or
            $VMInfo.MemorySize -ne $FinalMem)
            ) {
                $HypervisorGuestVMChangesSB = {
                    [System.Collections.ArrayList]$VMSettingsThatWereChangedInSB = @()
                    
                    if ($($using:VMInfo.State -eq 'Saved' -or $using:VMInfo.DynamicMemoryEnabled -eq $true -or
                    $using:VMInfo.ExposeVirtualizationExtensions -eq $false -or $using:VMInfo.ProcessorCount -lt 2) -and
                    $using:AllowRestarts
                    ) {
                        if ($using:VMSettingsThatWereChanged -contains "HyperVInstall") {
                            Start-Sleep -Seconds 30
                        }
                        while ($(Get-VM $using:VMName).State -ne "Off") {
                            if ($(Get-VM $using:VMName).State -ne "Stopping") {
                                try {
                                    Stop-VM -VMName $using:VMName -TurnOff -Confirm:$False -Force -WarningAction SilentlyContinue -WarningVariable StateCheck
                                }
                                catch {
                                    Start-Sleep -Seconds 15
                                }
                            }
                        }

                        $i = 0
                        while ($(Get-VM -Name $using:VMName).State -ne "Off") {
                            Write-Verbose "Waiting for $($using:VMName) to turn off..."
                            $i++
                            if ($i -gt 10) {
                                Write-Error "$($using:VMName) hasn't turned off within 10 seconds! Please check its status manually on the hypervisor. Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                            Start-Sleep -Seconds 1
                        }

                        $null = $VMSettingsThatWereChangedInSB.Add("Restart")
                    }
                    if ($using:VMInfo.State -eq 'Saved' -and $using:AllowRestarts) {
                        Remove-VMSavedState -VMName $using:VMName
                        #Add-Member -InputObject $VMSettingsThatWereChangedInSB NoteProperty -Name "SavedState" -Value "Removed"
                        $null = $VMSettingsThatWereChangedInSB.Add("RemoveSavedState")
                    }
                    if ($using:VMInfo.DynamicMemoryEnabled -eq $true -and $using:AllowRestarts) {
                        Set-VMMemory -VMName $using:VMName -DynamicMemoryEnabled $false
                        #Add-Member -InputObject $VMSettingsThatWereChangedInSB NoteProperty -Name "DynamicMemory" -Value "Disabled"
                        $null = $VMSettingsThatWereChangedInSB.Add("DisableDynamicMemory")
                    }
                    if ($using:VMInfo.ExposeVirtualizationExtensions -eq $false -and $using:AllowRestarts) {
                        Set-VMProcessor -VMName $using:VMName -ExposeVirtualizationExtensions $true
                        #Add-Member -InputObject $VMSettingsThatWereChangedInSB NoteProperty -Name "ExposeVirtualizationExtensions" -Value $true
                        $null = $VMSettingsThatWereChangedInSB.Add("ExposeVirtualizationExtensions")
                    }
                    if ($using:VMInfo.MacAddressSpoofing -eq 'Off') {
                        Set-VMNetworkAdapter -VMName $using:VMName -MacAddressSpoofing On
                        #Add-Member -InputObject $VMSettingsThatWereChangedInSB NoteProperty -Name "MacAddressSpoofing" -Value "On"
                        $null = $VMSettingsThatWereChangedInSB.Add("TurnMacSpoofingOn")
                    }
                    if ($using:VMInfo.MemorySize -ne $using:FinalMem) {
                        Set-VMMemory -VMName $using:VMName -StartupBytes $using:FinalMem
                        #Add-Member -InputObject $VMSettingsThatWereChangedInSB NoteProperty -Name "VMMemory" -Value $using:FinalMem
                        $null = $VMSettingsThatWereChangedInSB.Add("AdjustStartupMemory")
                    }
                    if ($using:VMInfo.ProcessorCount -lt 2) {
                        Set-VMProcessor -VMname $using:VMName -Count 2
                        #Add-Member -InputObject $VMSettingsThatWereChanged NoteProperty -Name "UpProcessorCount" -Value 2
                        $null = $VMSettingsThatWereChangedInSB.Add("UpProcessorCount")
                    }
        
                    if ($(Get-VM -Name $using:VMName).State -eq "Off") {
                        Start-VM -VMName $using:VMName
        
                        $i = 0
                        while ($(Get-VM -Name $using:VMName).State -ne "Running") {
                            Write-Verbose "Waiting for $($using:VMName) to turn on..."
                            $i++
                            if ($i -gt 10) {
                                Write-Error "$($using:VMName) hasn't turned on within 10 seconds! Please check its status manually on the hypervisor. Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                            Start-Sleep -Seconds 1
                        }
                    }
        
                    $VMSettingsThatWereChangedInSB
                }

                $InvCmdSplatParams = @{
                    ComputerName        = $GuestVMAndHVInfo.HypervisorInvCmdLocation
                    ScriptBlock         = $HypervisorGuestVMChangesSB
                    ErrorAction         = "Stop"
                }
                if ($HypervisorCreds) {
                    $InvCmdSplatParams.Add("Credential",$HypervisorCreds)
                }
        
                try {
                    #$GuestVMAndHVInfo | Export-Clixml $HOME\Downloads\GuestVMAndHVInfo.xml
                    #$InvCmdSplatParams | Export-Clixml $HOME\Downloads\InvCmdSplatParams.xml
                    $VMSettingsThatWereChangedPrep = Invoke-Command @InvCmdSplatParams
                    if (!$VMSettingsThatWereChangedPrep) {throw "The NewNATSB failed!"}

                    foreach ($Setting in $VMSettingsThatWereChangedPrep) {
                        if ($VMSettingsThatWereChanged -notcontains $Setting) {
                            $null = $VMSettingsThatWereChanged.Add($Setting)
                        }   
                    }
                }
                catch {
                    Write-Error $_
                    Write-Error "The EnableNestedVM function was unable to report on `$VMSettingsThatWereChanged by remoting into the Hyper-V Host! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
        }

        if($char -match "No|no|N|n") {
            Write-Error "User chose not to proceed! No action taken! Halting!"
            $global:FunctionResult = "0"
            return
        }
    }
    if ($TryWithoutHypervisorInfo) {
        if ($TryWithoutHypervisorInfo -and !$NoMacAddressSpoofing) {
            $WarnMsg = "We are attempting to configure the Guest VM for Nested Virtualization without any information (or access to) the Hypervisor. " +
            "This just means that the only configuration action we might take is attempting to create a NAT interface on the Guest VM."
            Write-Warning $WarnMsg
        }

        if ($GuestVMNestedVirtCapabilties.NetworkingPossibilities -contains "Mac Address Spoofing" -and !$NoMacAddressSpoofing) {
            Write-Warning "Mac Address Spoofing is enabled. We will NOT create a NAT interface on the Guest VM. No action taken."

            [System.Collections.ArrayList]$VMSettingsThatWereChanged = @("None")
            [System.Collections.ArrayList]$NeededChanges = @("None")
            [System.Collections.ArrayList]$AttemptedChanges = @("None")
            [System.Collections.ArrayList]$UnsatisfiedChanges = @("None")
        }
        else {
            [System.Collections.ArrayList]$NeededChanges = @("NetworkAddressTranslation")
            $AttemptedChanges = $NeededChanges

            Write-Warning "Potential changes to $($GuestVMAndHVInfo.HostNameNetworkInfo.HostName) are as follows:"
            $WarnMsg1 = "If a restart IS NOT necessary (i.e. if Hyper-V is already installed on $env:ComputerName), " +
            "and if an Internal vSwitch called 'LocalNAT' does NOT already exist and if NO OTHER Network Adapter " +
            "is using subnet $NATSubnet with IP $NATIP, then an Internal vSwitch called 'LocalNAT' will be " +
            "created with the aforementioned information"
            Write-Warning $WarnMsg1
            $WarnMsg2 = "If a restart IS necessary, please run the EnableNestedVM function again after the restart " +
            "once $env:Computer has finished installing Hyper-V components."
            Write-Warning $WarnMsg2
            Write-Host ""

            $prompt = $true

            if ($prompt) {
                if (!$SkipPrompt) {
                    Write-Host ""
                    $char = Read-Host -Prompt "Do you agree to all of these (potential) changes to VM $env:ComputerName ? [Yes/No]"
                    while ($char -notmatch "Yes|yes|Y|y|No|no|N|n") {
                        Write-Host "Invalid Input, Y or N"
                        $char = Read-Host -Prompt "Do you agree to all of these (potential) changes to VM $env:ComputerName? [Yes/No]"
                    }
                }
                else {
                    $char = "Yes"
                }
            }

            if($char -match "No|no|N|n") {
                Write-Error "User chose not to proceed! No action taken! Halting!"
                $global:FunctionResult = "0"
                return
            }

            if ($char -match "Yes|yes|Y|y") {
                if ($Locale -eq "GuestVM") {
                    [System.Collections.ArrayList]$VMSettingsThatWereChanged = @()
                    
                    if (!$SkipHyperVInstallCheck) {
                        # Install Hyper-V Features if they haven't aready

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
                        try {
                            $InstallContainersFeatureDismResult = InstallFeatureDism -Feature Containers -ParentFunction $MyInvocation.MyCommand.Name
                        }
                        catch {
                            Write-Error $_
                            Write-Error "The InstallFeatureDism function (as executed by the $($MyInvocation.MyCommand.Name) function) failed! Halting!"
                            $global:FunctionResult = "1"
                            return
                        }

                        if ($HyperVFeaturesInstallResults.InstallFailures.Count -gt 0) {
                            Write-Error "Please remedy the Hyper-V Features that failed to install before proceeding. Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                        
                        if ($HyperVFeaturesInstallResults.InstallResults.RestartNeeded -notcontains $True -and !$InstallContainersFeatureDismResult.RestartNeeded) {
                            Write-Host "All dependencies are already installed...proceeding..." -ForegroundColor Green
                        }
                        else {
                            if ($HyperVFeaturesInstallResults.InstallResults.RestartNeeded -contains $True -or $InstallContainersFeatureDismResult.RestartNeeded) {
                                if ($AllowRestarts) {
                                    Write-Host "Restarting $env:ComputerName..."
                                    # NOTE: The below output "Restarting" is important when running this function via Invoke-Command
                                    $null = $VMSettingsThatWereChanged.Add("HyperVInstall")
                                    $null = $VMSettingsThatWereChanged.Add("Restart")
                                    Restart-Computer -Confirm:$false -Force
                                }
                                else {
                                    Write-Error "You must restart $env:ComputerName before proceeding! Halting!"
                                    return
                                }
                            }
                        }
                    }

                    try {
                        if ($(Get-Module -ListAvailable).Name -notcontains "Hyper-V" -and $(Get-Module).Name -notcontains "Hyper-V") {
                            throw "Hyper-V does NOT appear to be installed on $env:ComputerName! Halting!"
                        }
                        # NOTE: New-VMSwitch is the cmdlet that actually creates the Network Adapter called 'vEthernet ($NATName)'
                        # New-NetNat is another type of object that we just happen to be calling the same thing (i.e. '$NATName'),
                        # but it doesn't HAVE to be named the same thing.

                        # NOTE: 10.075.0/24 is the default Docker For Windows (i.e. Docker CE) NAT subnet. Figured we might as well
                        # use the same if one isn't provided to the is function.
                        if (!$NATIP) {
                            $NATIP = "10.0.75.1"
                        }
                        if (!$NATNetworkMask) {
                            $NATNetworkMask = 24
                        }
                        if (!$NATName) {
                            $NATName = "LocalNAT"
                        }
                        $NATSubnet = "$NATIP/$NATNetworkMask"

                        [System.Collections.ArrayList]$ExistingvSwitchInfo = @()
                        if ([bool]$(GetvSwitchAllRelatedInfo -IPAddress $NATIP -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)) {
                            $vSwitchInfoByIP = GetvSwitchAllRelatedInfo -IPAddress $NATIP -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

                            if ($vSwitchInfoByIP) {
                                $null = $ExistingvSwitchInfo.Add($vSwitchInfoByIP)
                            }
                        }
                        if ([bool]$(GetvSwitchAllRelatedInfo -vSwitchName $NATName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)) {
                            $vSwitchInfoByName = GetvSwitchAllRelatedInfo -vSwitchName $NATName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

                            if ($vSwitchInfoByName) {
                                $null = $ExistingvSwitchInfo.Add($vSwitchInfoByName)
                            }
                        }

                        if ($ExistingvSwitchInfo.Count -eq 0) {
                            if ($PSVersionTable.PSEdition -eq "Core") {
                                Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                                    $null = New-NetNat -Name $args[0] -InternalIPInterfaceAddressPrefix $args[1]
                                    $null = New-VMSwitch -Name $args[0] -SwitchType Internal
                                    $null = Get-NetAdapter "vEthernet ($($args[0]))" | New-NetIPAddress -IPAddress $args[2] -AddressFamily IPv4 -PrefixLength $args[3]
                                } -ArgumentList $NATName,$NATSubnet,$NATIP,$NATNetworkMask
                            }
                            else {
                                $null = New-NetNat -Name $NATName -InternalIPInterfaceAddressPrefix $NATSubnet
                                $null = New-VMSwitch -Name $NATName -SwitchType Internal
                                $null = Get-NetAdapter "vEthernet ($NATName)" | New-NetIPAddress -IPAddress $NATIP -AddressFamily IPv4 -PrefixLength $NATNetworkMask
                            }
                        
                            [System.Collections.ArrayList]$NeededChanges = @("NetworkAddressTranslation")
                        }
                        else {
                            [System.Collections.ArrayList][Array]$NeededChanges = @("None - LocalNAT Already Exists")
                        }
                        
                        $AttemptedChanges = $NeededChanges
                        $VMSettingsThatWereChanged = $NeededChanges
                    }
                    catch {
                        Write-Error $_
                        Write-Warning "Failed to create 'vEthernet ($NATName)'! However, it is possible that Mac Address Spoofing is enabled on this Guest VM, in which case"
                        $AttemptedChanges = $NeededChanges
                        $UnsatisfiedChanges = $NeededChanges
                    }
                }
                elseif ($Locale -eq "Elsewhere") {
                    $FunctionsForRemoteUse = @(
                        ${Function:InstallFeatureDism}.Ast.Extent.Text
                        ${Function:InstallHyperVFeatures}.Ast.Extent.Text
                        ${Function:TestIsValidIPAddress}.Ast.Extent.Text
                        ${Function:GetvSwitchAllRelatedInfo}.Ast.Extent.Text
                    )
        
                    $NewNatSB = {
                        # Load the functions we packed up:
                        $using:FunctionsForRemoteUse | foreach { Invoke-Expression $_ }
                        [System.Collections.ArrayList]$VMSettingsThatWereChangedInSB = @()
                        
                        if (!$using:SkipHyperVInstallCheck) {
                            # Install Hyper-V Features if they haven't aready

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
                            try {
                                $InstallContainersFeatureDismResult = InstallFeatureDism -Feature Containers -ParentFunction $MyInvocation.MyCommand.Name
                            }
                            catch {
                                Write-Error $_
                                Write-Error "The InstallFeatureDism function (as executed by the $($MyInvocation.MyCommand.Name) function) failed! Halting!"
                                $global:FunctionResult = "1"
                                return
                            }

                            if ($HyperVFeaturesInstallResults.InstallFailures.Count -gt 0) {
                                Write-Error "Please remedy the Hyper-V Features that failed to install before proceeding. Halting!"
                                $global:FunctionResult = "1"
                                return
                            }
                            
                            if ($HyperVFeaturesInstallResults.InstallResults.RestartNeeded -notcontains $True -and !$InstallContainersFeatureDismResult.RestartNeeded) {
                                Write-Host "All dependencies are already installed...proceeding..." -ForegroundColor Green
                            }
                            else {
                                if ($HyperVFeaturesInstallResults.InstallResults.RestartNeeded -contains $True -or $InstallContainersFeatureDismResult.RestartNeeded) {
                                    if ($using:AllowRestarts) {
                                        Write-Host "Restarting $env:ComputerName..."
                                        # NOTE: The below output "Restarting" is important when running this function via Invoke-Command
                                        $null = $VMSettingsThatWereChangedInSB.Add("HyperVInstall")
                                        $null = $VMSettingsThatWereChangedInSB.Add("Restart")
                                        $VMSettingsThatWereChangedInSB
                                        Restart-Computer -Confirm:$false -Force
                                        return
                                    }
                                    else {
                                        Write-Error "You must restart $env:ComputerName before proceeding! Halting!"
                                        $null = $VMSettingsThatWereChangedInSB.Add("HyperVInstall")
                                        $null = $VMSettingsThatWereChangedInSB.Add("RestartNeeded")
                                        $VMSettingsThatWereChangedInSB
                                        return
                                    }
                                }
                            }
                        }

                        try {
                            if ($(Get-Module -ListAvailable).Name -notcontains "Hyper-V" -and $(Get-Module).Name -notcontains "Hyper-V") {
                                throw "Hyper-V does NOT appear to be installed on $env:ComputerName! Halting!"
                            }
                            # NOTE: New-VMSwitch is the cmdlet that actually creates the Network Adapter called 'vEthernet ($NATName)'
                            # New-NetNat is another type of object that we just happen to be calling the same thing (i.e. '$NATName'),
                            # but it doesn't HAVE to be named the same thing.

                            # NOTE: 10.075.0/24 is the default Docker For Windows (i.e. Docker CE) NAT subnet. Figured we might as well
                            # use the same if one isn't provided to the is function.
                            if (!$using:NATIP) {
                                $NATIPSB = "10.0.75.1"
                            }
                            else {
                                $NATIPSB = $using:NATIP
                            }
                            if (!$using:NATNetworkMask) {
                                $NATNetworkMaskSB = 24
                            }
                            else {
                                $NATNetworkMaskSB = $using:NATNetworkMask
                            }
                            if (!$using:NATName) {
                                $NATNameSB = "LocalNAT"
                            }
                            else {
                                $NATNameSB = $using:NATName
                            }
                            $NATSubnet = "$NATIPSB/$NATNetworkMaskSB"

                            [System.Collections.ArrayList]$ExistingvSwitchInfo = @()
                            if ([bool]$(GetvSwitchAllRelatedInfo -IPAddress $NATIPSB -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)) {
                                $vSwitchInfoByIP = GetvSwitchAllRelatedInfo -IPAddress $NATIPSB -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

                                if ($vSwitchInfoByIP) {
                                    $null = $ExistingvSwitchInfo.Add($vSwitchInfoByIP)
                                }
                            }
                            if ([bool]$(GetvSwitchAllRelatedInfo -vSwitchName $NATNameSB -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)) {
                                $vSwitchInfoByName = GetvSwitchAllRelatedInfo -vSwitchName $NATNameSB -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

                                if ($vSwitchInfoByName) {
                                    $null = $ExistingvSwitchInfo.Add($vSwitchInfoByName)
                                }
                            }
                            
                            if ($ExistingvSwitchInfo.Count -eq 0) {
                                if ($PSVersionTable.PSEdition -eq "Core") {
                                    Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                                        $null = New-NetNat -Name $args[0] -InternalIPInterfaceAddressPrefix $args[1]
                                        $null = New-VMSwitch -Name $args[0] -SwitchType Internal
                                        $null = Get-NetAdapter "vEthernet ($($args[0]))" | New-NetIPAddress -IPAddress $args[2] -AddressFamily IPv4 -PrefixLength $args[3]
                                    } -ArgumentList $NATNameSB,$NATSubnet,$NATIPSB,$NATNetworkMaskSB
                                }
                                else {
                                    $null = New-NetNat -Name $NATNameSB -InternalIPInterfaceAddressPrefix $NATSubnet
                                    $null = New-VMSwitch -Name $NATNameSB -SwitchType Internal
                                    $null = Get-NetAdapter "vEthernet ($NATNameSB)" | New-NetIPAddress -IPAddress $NATIPSB -AddressFamily IPv4 -PrefixLength $NATNetworkMaskSB
                                }
                            
                                $null = $VMSettingsThatWereChangedInSB.Add("NetworkAddressTranslation")
                            }
                            else {
                                $null = $VMSettingsThatWereChangedInSB.Add("None - LocalNAT Already Exists")
                            }

                            $VMSettingsThatWereChangedInSB
                        }
                        catch {
                            Write-Error $_
                            Write-Warning "Failed to create 'vEthernet ($NATNameSB)'! However, it is possible that Mac Address Spoofing is enabled on this Guest VM, in which case Nested VM networking will work as expected without NAT."
                        }
                    }

                    $InvCmdSplatParams = @{
                        ComputerName        = $GuestVMAndHVInfo.TargetHostInvCmdLocation
                        ScriptBlock         = $NewNatSB
                        ErrorAction         = "SilentlyContinue"
                        ErrorVariable       = "HVIErr"
                    }
                    if ($TargetHostNameCreds) {
                        $InvCmdSplatParams.Add("Credential",$TargetHostNameCreds)
                    }
            
                    try {
                        $VMSettingsThatWereChanged = Invoke-Command @InvCmdSplatParams
                        if (!$VMSettingsThatWereChanged) {throw "The NewNATSB failed!"}

                        if ($VMSettingsThatWereChanged -contains "None - LocalNAT Already Exists") {
                            [System.Collections.ArrayList]$NeededChanges = @("None - LocalNAT Already Exists")
                        }
                        $AttemptedChanges = $NeededChanges
                        if ($VMSettingsThatWereChanged -eq $null) {
                            $UnsatisfiedChanges = $NeededChanges
                        }
                    }
                    catch {
                        if ($($HVIErr | Out-String) -notmatch "WinRM cannot complete the operation") {
                            Write-Error $_
                            $ErrMsgNewNATSB = "The EnableNestedVM function was unable to gather additional information " +
                            "about $($GuestVMAndHVInfo.TargetHostInvCmdLocation) by remoting into " +
                            "$($GuestVMAndHVInfo.TargetHostInvCmdLocation)! If a restart occurred, it might not be " +
                            "ready yet. Halting!"
                            Write-Error $ErrMsgNewNATSB
                            $global:FunctionResult = "1"
                            return
                        }
                        else {
                            $RestartOccurred = $True
                            [System.Collections.ArrayList]$VMSettingsThatWereChanged = @("HyperVInstall")

                            [System.Collections.ArrayList]$AttemptedChanges = @("HyperVInstall")
                            $NeededChanges = $AttemptedChanges
                        }
                    }
                }
            }
        }
    }

    $RestartOccurred = if ($VMSettingsThatWereChanged -contains "Restart" -or $RestartOccurredFlag) {$True} else {$False}
    $RestartStillNeeded = if ($VMSettingsThatWereChanged -contains "RestartNeeded") {$True} else {$False}
    $ReRunFunction = if ($RestartOccurred -or $RestartStillNeeded) {$True} else {$False}

    foreach ($Setting in $VMSettingsThatWereChanged) {
        if ($NeededChanges -notcontains $Setting) {
            $null = $NeededChanges.Add($Setting)
        }
        if ($AttemptedChanges -notcontains $Setting) {
            $null = $AttemptedChanges.Add($Setting)
        }
    }

    if ($VMSettingsThatWereChanged.Count -eq 0) {
        Write-Warning "No changes were made to the Guest VM!"
    }
    if ($VMSettingsThatWereChanged.Count -eq 0 -and $AttemptedChanges.Count -gt 0) {
        Write-Warning "Changes to the Guest VM were attempted, but did not succeed! No changes were made to the Guest VM!"
    }
    if ($UnsatisfiedChanges.Count -gt 0) {
        Write-Warning "There are changes that still need to be made to the Guest VM in order to allow for a 64-bit Nested VM!"
    }
    if ($NeededChanges.Count -eq 0) {
        Write-Host "The VM $VMName is already configured for Nested Virtualization! No action taken!" -ForegroundColor green
    }

    [pscustomobject]@{
        GuestVMSettingsThatWereChanged       = [System.Collections.ArrayList][Array]$VMSettingsThatWereChanged
        NeededChanges                        = $NeededChanges
        AttemptedChanges                     = $AttemptedChanges
        UnsatisfiedChanges                   = $UnsatisfiedChanges
        RestartOccurred                      = $RestartOccurred
        RestartStillNeeded                   = $RestartStillNeeded
        ReRunFunction                        = $ReRunFunction
    }

    ##### END Main Body #####

}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUw9sG6mouTd3tw5eHbmoQxaLT
# 6sigggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFK/WIVJBbUHaXimD
# kxnY2aUEf6DNMA0GCSqGSIb3DQEBAQUABIIBABJZEX8YQxuzkZo+zv4yr/bfEmwf
# M98csi5tAEeSXvknS99kYUWCVOqWoluLJYO9zshPZ9wktIqqwIt7dZMTIabhKHjR
# R+xJ0LEAhVaIBLvYrQGLgIk/00K8/kW1ec+h+VFb2Nzo+5TscnwFCaRfNFEDupc1
# DfRw4yevP0EGLK5vTEix2/5Xim/pz14/BKirYVJ5j7xAd97a2b6OICXLrlfO9B4Y
# iJJGhl00Fqsc2oCfrQNIAZSLnSdn4FQgAXf7k1LkdWUhgG8Ty9vGSiMvHYoxsTwE
# oBov2at1os8EzGQIlK/Ym1zQujQbbIUYtROzaJmHBdBxzUWdY1zWZgSOfsE=
# SIG # End signature block
