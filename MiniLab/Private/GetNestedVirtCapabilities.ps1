function GetNestedVirtCapabilities {
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

        [Parameter(
            Mandatory=$True,
            ParameterSetName = 'InfoAlreadyCollected'
        )]
        $GuestVMAndHVInfo, # Uses output of Get-GuestVMAndHypervisorInfo function

        [Parameter(Mandatory=$False)]
        [switch]$SkipHyperVInstallCheck
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

    <#
    # From: https://msdn.microsoft.com/en-us/library/ms724358(VS.85).aspx
    $WindowsEditionTable = @{
        Windows10Pro                    = "30"
        Windows10Enterprise             = "4"
        Windows10S                      = "B2"
        Windows10SN                     = "B3"
        ServerHyperCoreV                = "40"
        ServerDatacenterEvaluation      = "50"
        ServerDatacenterFull            = "8"
        ServerDatacenterCore            = "C"
        Windows10EnterpriseE            = "46"
        Windows10EnterpriseEvaluation   = "48"
        Windows10EnterpriseN            = "1B"
        Windows10EnterpriseNEvaluation  = "54"
        ServerEnterpriseFull            = "A"
        ServerEnterpriseCore            = "E"
        MicrosoftHyperVServer           = "2A"
        Windows10ProN                   = "31"
        ServerStandardEvaluation        = "4F"
        ServerStandard                  = "7"
        ServerStandardCore              = "D"
    }
    #>

    # Get Guest VM and hypervisor info

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

    if ($GuestVMAndHVInfo.HypervisorCreds -ne $null) {
        $HypervisorCreds = $GuestVMAndHVInfo.HypervisorCreds
    }
    if ($GuestVMAndHVInfo.TargetHostNameCreds -ne $null) {
        $TargetHostNameCreds = $GuestVMAndHVInfo.TargetHostNameCreds
        if ($TargetHostNameCreds -eq $(whoami)) {
            $TargetHostNameCreds = $null
        }
    }

    if ($GuestVMAndHVInfo.HostNameBIOSInfo.IsVirtual -eq $False) {
        Write-Error "The GetNestedVirtCapabilities function should only be used to determine if a Guest VM is capable of Nested Virtualization. $($GuestVMAndHVInfo.HostNameNetworkInfo.FQDN) is a physical machine! Halting!"
        $global:FunctionResult = "1"
        return
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    [System.Collections.ArrayList]$HypervisorSoftwareThatWillWorkOnGuestVM = @()
    [System.Collections.ArrayList]$PossibleOSArchitectureOfNestedVMs = @()
    [System.Collections.ArrayList]$StepsToAllow64BitNestedVMs = @()

    ## BEGIN Analyzing info about the Guest VM - i.e. the Virtual Machine Configuration itself ##

    # We need to determine if we have access to the Hyper-V hypervisor. If we're in a public cloud (like AWS, Azure, etc)
    # we can assume that we don't, in which case we cannot use Mac Address Spoofing for Nested VM networking, which means
    # that we need to run Get-GuestVMAndHypervisorInfo with the -TryWithoutHypervisorInfo switch and that we need to 
    # setup a NAT Adapter on the Guest VM Hyper-V Host (as opposed to an External vSwitch). This info all needs to be
    # in this function's output.
    [System.Collections.ArrayList]$NetworkingOptions = @()
    if ($(ConfirmAWSVM -EA SilentlyContinue) -or $(ConfirmAzureVM -EA SilentlyContinue) -or 
    $(ConfirmGoogleComputeVM -EA SilentlyContinue) -or $GuestVMAndHVInfo.HypervisorNetworkInfo -eq $null -or
    $GuestVMAndHVInfo.HypervisorComputerInfo -eq $null -or $GuestVMAndHVInfo.HypervisorOSInfo -eq $null -or
    $TryWithoutHypervisorInfo
    ) {
        $null = $NetworkingOptions.Add("Network Address Translation")
        
        $null = $StepsToAllow64BitNestedVMs.Add("Might need Disable Dynamic Memory")
        $null = $StepsToAllow64BitNestedVMs.Add("Might need to Remove Save States")
    }

    if ($GuestVMAndHVInfo.MacAddressSpoofingEnabled -eq $True -or $GuestVMAndHVInfo.VMNetworkAdapterInfo.MacAddressSpoofing -eq $True) {
        $null = $NetworkingOptions.Add("Mac Address Spoofing")
    }
    elseif ($GuestVMAndHVInfo.MacAddressSpoofingEnabled -ne $True -or
    $($GuestVMAndHVInfo.MacAddressSpoofingEnabled -ne $True -and $GuestVMAndHVInfo.VMNetworkAdapterInfo -eq $null)
    ) {
        $null = $StepsToAllow64BitNestedVMs.Add("Might need to Turn On MacAddress Spoofing")
    }

    if ($($GuestVMAndHVInfo.VMProcessorInfo -ne $null -and 
    $GuestVMAndHVInfo.VMProcessorInfo.ExposeVirtualizationExtensions -eq $False) -or
    $GuestVMAndHVInfo.VirtualizationExtensionsExposed -match "Unknown" -or
    $GuestVMAndHVInfo.VirtualizationExtensionsExposed -eq $False
    ) {
        $null = $StepsToAllow64BitNestedVMs.Add("Expose Virtualization Extensions")
        $NestedVirtualizationPossible = $False
    }
    elseif ($GuestVMAndHVInfo.VirtualizationExtensionsExposed -eq $null) {
        $null = $StepsToAllow64BitNestedVMs.Add("Might need to Expose Virtualization Extensions")
        $null = $PossibleOSArchitectureOfNestedVMs.Add("MAYBE_64-bit")
    }

    # Other information about the hypervisor...
    if ($GuestVMAndHVInfo.HypervisorOSInfo -ne $null -and $GuestVMAndHVInfo.HypervisorOSInfo.OSArchitecture -ne "64-bit") {
        $null = $StepsToAllow64BitNestedVMs.Add("The hypervisor must be running on a 64-bit Operating System.")
    }

    if ($GuestVMAndHVInfo.HypervisorOSInfo -ne $null) {
        $HypervisorOSNameCheck = $GuestVMAndHVInfo.HypervisorOSInfo.Caption -match "Windows 10||Windows Server 2016"
        $HypervisorOSTypeCheck = $GuestVMAndHVInfo.HypervisorOSInfo.Caption -match "Pro|Enterprise|Server"

        if (!$($HypervisorOSNameCheck -and $HypervisorOSTypeCheck) -and $GuestVMAndHVInfo.HypervisorOSInfo -ne $null) {
            $NestedVirtualizationPossible = $False
            $null = $StepsToAllow64BitNestedVMs.Add("The hypervisor must be running on Windows 10 Pro/Enterprise or Windows Server 2016.")
        }
    }

    # Guest VM bust be version 8.0 or higher
    if ($GuestVMAndHVInfo.TargetVMInfoFromHyperV -ne $null) {
        if ($([version]$GuestVMAndHVInfo.TargetVMInfoFromHyperV.Version).Major -lt 8) {
            $null = $StepsToAllow64BitNestedVMs.Add("Guest VM Configuration must be Version 8.0 or higher")
        }
    }

    ## END Analyzing info about the Guest VM - i.e. the Virtual Machine Configuration itself ##

    ## BEGIN Analyzing info about the Guest VM OS ##

    if ($GuestVMAndHVInfo.HostNameOSInfo.OSArchitecture -ne "64-bit") {
        $NestedVirtualizationPossible = $False
        $null = $StepsToAllow64BitNestedVMs.Add("Change the Guest VM OS Architecture to 64-bit")
    }

    # If at this point, $StepsToAllow64BitNestedVMs.Count -eq 0, or just "Might need to Turn On MacAddress Spoofing"
    # then we know the following to be true
    if ($StepsToAllow64BitNestedVMs.Count -eq 0 -or
    $($StepsToAllow64BitNestedVMs.Count -eq 1 -and $StepsToAllow64BitNestedVMs[0] -eq "Might need to Turn On MacAddress Spoofing")) {
        $NestedVirtualizationPossible = $True
        $null = $PossibleOSArchitectureOfNestedVMs.Add("32-bit")
        $null = $HypervisorSoftwareThatWillWorkOnGuestVM.Add("VMWare")
        $null = $HypervisorSoftwareThatWillWorkOnGuestVM.Add("Xen")
        $null = $HypervisorSoftwareThatWillWorkOnGuestVM.Add("VirtualBox")
    }

    $GuestVMOSNameCheck = $GuestVMAndHVInfo.HostNameOSInfo.Caption -match "Windows 10||Windows Server 2016"
    $GuestVMOSTypeCheck = $GuestVMAndHVInfo.HostNameOSInfo.Caption -match "Pro|Enterprise|Server"

    ## END Analyzing info about the Guest VM OS ##

    ## BEGIN Mixed Analysis ##

    # If the Hypervisor and VM are Windows 2016, then 64-bit Nested VMs are also possible
    if (!$($GuestVMOSNameCheck -and $GuestVMOSTypeCheck)) {
        $null = $StepsToAllow64BitNestedVMs.Add("Run Windows 10 Pro/Enterprise or Windows Server 2016 as the Guest VM OS.")
    }
    else {
        if (!$GuestVMAndHVInfo.HostNameProcessorInfo.VirtualizationFirmwareEnabled) {
            $null = $StepsToAllow64BitNestedVMs.Add("Might need to Enable VirtualizationFirmware")
        }

        $null = $HypervisorSoftwareThatWillWorkOnGuestVM.Add("Hyper-V")
        if ($PossibleOSArchitectureOfNestedVMs -notcontains "MAYBE_64-bit") {
            $null = $PossibleOSArchitectureOfNestedVMs.Add("64-bit")
        }
    }

    if ($GuestVMAndHVInfo.HypervisorOSInfo -eq $null -and 
    $GuestVMAndHVInfo.HostNameBIOSInfo.SMBIOSBIOSVersion -notmatch "Hyper-V|VMWare|Xen|American Megatrends" -and 
    $GuestVMAndHVInfo.HostNameBIOSInfo.Manufacturer -notmatch "Hyper-V|VMWare|Xen|American Megatrends" -and 
    $GuestVMAndHVInfo.HostNameBIOSInfo.Name -notmatch "Hyper-V|VMWare|Xen|American Megatrends" -and 
    $GuestVMAndHVInfo.HostNameBIOSInfo.SerialNumber -notmatch "Hyper-V|VMWare|Xen|American Megatrends" -and 
    $GuestVMAndHVInfo.HostNameBIOSInfo.Version -notmatch "Hyper-V|VMWare|Xen|American Megatrends|VRTUAL"
    ) {
        $null = $StepsToAllow64BitNestedVMs.Add("Use Hyper-V or VMWare or Xen as the baremetal hypervisor.")
    }

    if ($GuestVMAndHVInfo.VirtualizationExtensionsExposed -eq $True) {
        $NestedVirtualizationPossible = $True
    }

    $FinalSteps = [pscustomobject]@{
        StepsThatAreDefinitelyNeeded = $($StepsToAllow64BitNestedVMs | Where-Object {$_ -notmatch "Might need"})
        StepsThatMightBeNeeded       = $($StepsToAllow64BitNestedVMs | Where-Object {$_ -match "Might need"})
    }

    ## END Mixed Analysis ##

    [pscustomobject]@{
        NestedVirtualizationPossible                = $NestedVirtualizationPossible
        PossibleOSArchitectureOfNestedVMs           = if ($NestedVirtualizationPossible) {$PossibleOSArchitectureOfNestedVMs} else {$null}
        HypervisorSoftwareThatWillWorkOnGuestVM     = if ($NestedVirtualizationPossible) {$HypervisorSoftwareThatWillWorkOnGuestVM} else {$null}
        StepsToAllow64BitNestedVMs                  = $FinalSteps
        NetworkingPossibilities                     = if ($NestedVirtualizationPossible) {[array]$NetworkingOptions} else {$null}
        GuestVMAndHVInfo                            = $GuestVMAndHVInfo
    }

    ##### END Main Body #####
}

# SIG # Begin signature block
# MIIMaAYJKoZIhvcNAQcCoIIMWTCCDFUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUkcbMvAj0xxpnco0HLC38YGEO
# 3/OgggndMIIEJjCCAw6gAwIBAgITawAAADqEP46TDmc/hQAAAAAAOjANBgkqhkiG
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
# BDEWBBQnlxbye3LxsYAGw8+99UKKn20zxjANBgkqhkiG9w0BAQEFAASCAQAIGxae
# DuVEFUXWIPfa7BYjgzjk2qBgChqgiarAwiGohkv3spKQWa0z3zT9ud9hwyvb/Xea
# sj5TU/Ap+AvwGh/LXv+N1CwMpK5fG0TvDmBPS8eiW+9xKrplgWeCDYUUn1Wn9Asz
# W8Md6/YMWUZy9HciEIB27z/XwP5vakTijk+3wBPti1x+gHwDjUB96u/GhajxacMb
# z9/J2uF4M5zVWUGkEuzci+33Z8r9usKD+a9bAbXSFm94bV1P1UrOdfyeXap0VYyt
# 0udQPeUXbgYoNejrIWdyYSxLaRCKI4Q/TkhOrKli7JNIoxV7MNz4dOaE6/RVgFH9
# SYbj0XGXgVb+8jyp
# SIG # End signature block
