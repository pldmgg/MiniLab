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
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUkcbMvAj0xxpnco0HLC38YGEO
# 3/Ogggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFCeXFvJ7cvGxgAbD
# z731QoqfbTPGMA0GCSqGSIb3DQEBAQUABIIBAB/bk6Ytd3Uu9hxjlytTRZLtyFlb
# qFWxiU4GZKP3gISAbpuayWcF+Z0zMpbmvKJ/U2CCKyPBeLdiqkUuq7JB3M7dxfk2
# DYfLIy2GCtDjx14HI+xV/qlID9g/NEjLBY6JHa/94PtFGvMedrDuxznRUet1/yrf
# +AR6YAUwK9mZmDT5/Bxd5ZfEwgDx7I4oMd6fy51RYqtl7bnyX0eAbohR2Mt8hTVz
# SVoNuB7ncJBnsu0F7DdaQF2dubMLQlZU3UzgsTDCbG65NQApEPqZ2d+/1RFPmHB/
# qtTfbxhzBnf9TTzjddF1wsZ8uc0s1+z6+bkPfMT9CVj1abPcDwYFck9PyWE=
# SIG # End signature block
