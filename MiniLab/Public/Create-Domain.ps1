<#
    .SYNOPSIS
        This function creates a new Primary Domain Controller by either...
        
        A) Creating a brand new Windows Server VM; or
        B) Using an existing Windows Server on the network
        
        ...and then running a DSC configuration on it.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER CreateNewVMs
        This parameter is OPTIONAL.

        This parameter is a switch. If used, a new Windows 2016 Standard Server Virtual Machine will be deployed
        to the localhost. If Hyper-V is not installed, it will be installed (and you will need to reatart the localhost
        before proceeding).
        
        This VM will become the new Primary DC.

    .PARAMETER VMStorageDirectory
        This parameter is OPTIONAL, but becomes MANDATORY if the -CreateNewVMs parameter is used.

        This parameter takes a string that represents the full path to a directory on a LOCAL drive that will contain all
        new VM files (configuration, vhd(x), etc.)

    .PARAMETER Windows2016VagrantBox
        This parameter is OPTIONAL, but becomes MANDATORY if the -CreateNewVMs parameter is used.

        This parameter takes a string that represents the name of a Vagrant Box that can be downloaded from
        https://app.vagrantup.com/boxes/search. Default value is "jborean93/WindowsServer2016". Another good
        Windows 2016 Server Vagrant Box is "StefanScherer/windows_2016".

        You can alternatively specify a Windows 2012 R2 Standard Server Vagrant Box if desired.

    .PARAMETER NewDomain
        This parameter is MANDATORY.

        This parameter takes a string that represents the name of the new domain you would like to create.
        Example: alpha.lab

    .PARAMETER DomainAdminCredentials
        This parameter is MANDATORY.

        This parameter takes a PSCredential. A new Domain Account will be created using these credentials. This account will be
        added to the following Security Groups on the New Domain:
            - Domain Admins
            - Domain Users
            - Enterprise Admins
            - Group Policy Creator Owners
            - Schema Admins

    .PARAMETER LocalAdministratorAccountCredentials
        This parameter is MANDATORY.

        This parameter takes a PSCredential.

        The credential provided to this parameter will be applied to the Local Built-In Administrator Account on the
        target Windows Server. In other words, the pscredential provided to this parameter does NOT need to match
        the current UserName/Password of the Local Administrator Account on the target Windows Server, because the
        pscredential provided to this parameter will overwrite whatever the existing credentials are.

    .PARAMETER PSRemotingCredentials
        This parameter is MANDATORY.

        This parameter takes a PSCredential.

        The credential provided to this parameter should correspond to a User Account that has permission to
        remote into the target Windows Server. If you're using a Vagrant Box (which is what will be deployed
        if you use the -CreateNewVMs switch), then the value for this parameter should be created via:

            $VagrantVMPassword = ConvertTo-SecureString 'vagrant' -AsPlainText -Force
            $VagrantVMAdminCreds = [pscredential]::new("vagrant",$VagrantVMPassword)

    .PARAMETER IPOfServerToBeDomainController
        This parameter is OPTIONAL, however, if you do NOT use the -CreateNewVMs parameter, this parameter becomes MANDATORY.

        This parameter takes a string that represents an IPv4 Address referring to an EXISTING Windows Server on the network
        that will become the new Primary Domain Controller.

    .PARAMETER PrimaryHyperVHostIPOverride
        This parameter is OPTIONAL.

        This parameter takes a string that represents an IPv4 Address that you would like to use as your External Netowrk on your
        Hyper-V host.

    .PARAMETER SkipHyperVInstallCheck
        This parameter is OPTIONAL.

        This parameter is a switch. If used, this function will not check to make sure Hyper-V is installed on the localhost.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> $VagrantVMPassword = ConvertTo-SecureString 'vagrant' -AsPlainText -Force
        PS C:\Users\zeroadmin> $VagrantVMAdminCreds = [pscredential]::new("vagrant",$VagrantVMPassword)
        PS C:\Users\zeroadmin> $DomainAdminCreds = [pscredential]::new("alpha\alphaadmin",$(Read-Host 'Enter Passsword' -AsSecureString))
        Enter Passsword: ************
        PS C:\Users\zeroadmin> $LocalAdminAccountCreds = [pscredential]::new("Administrator",$(Read-Host 'Enter Passsword' -AsSecureString))
        Enter Passsword: ****************
        PS C:\Users\zeroadmin> $CreateDomainSplatParams = @{
        >> CreateNewVMs                            = $True
        >> VMStorageDirectory                      = "H:\VirtualMachines"
        >> NewDomain                               = "alpha.lab"
        >> PSRemotingCredentials                   = $VagrantVMAdminCreds
        >> DomainAdminCredentials                  = $DomainAdminCreds
        >> LocalAdministratorAccountCredentials    = $LocalAdminAccountCreds
        >> }
        PS C:\Users\zeroadmin> $CreateDomainResult = Create-Domain @CreateDomainSplatParams
        
#>
function Create-Domain {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$False)]
        [switch]$CreateNewVMs,

        [Parameter(Mandatory=$False)]
        [string]$VMStorageDirectory,

        [Parameter(Mandatory=$False)]
        [string]$Windows2016VagrantBox = "jborean93/WindowsServer2016", # Alternate - StefanScherer/windows_2016

        [Parameter(Mandatory=$True)]
        [ValidatePattern("^([a-z0-9]+(-[a-z0-9]+)*\.)+([a-z]){2,}$")]
        [string]$NewDomain,

        [Parameter(Mandatory=$True)]
        [pscredential]$DomainAdminCredentials,

        [Parameter(Mandatory=$True)]
        [pscredential]$LocalAdministratorAccountCredentials,

        [Parameter(Mandatory=$True)]
        [pscredential]$PSRemotingCredentials,

        [Parameter(Mandatory=$False)]
        [string]$IPofServerToBeDomainController,
        
        [Parameter(Mandatory=$False)]
        [string]$PrimaryHyperVHostIPOverride,

        [Parameter(Mandatory=$False)]
        [switch]$SkipHyperVInstallCheck
    )

    #region >> Helper Functions

    # TestIsValidIPAddress
    # ResolveHost
    # Deploy-HyperVVagrantBoxManually
    # Get-VagrantBoxManualDownload
    # New-DomainController

    #endregion >> Helper Functions

    #region >> Prep

    $StartTime = Get-Date

    $ElevationCheck = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    if (!$ElevationCheck) {
        Write-Error "You must run the build.ps1 as an Administrator (i.e. elevated PowerShell Session)! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $PrimaryIfIndex = $(Get-CimInstance Win32_IP4RouteTable | Where-Object {
        $_.Destination -eq '0.0.0.0' -and $_.Mask -eq '0.0.0.0'
    } | Sort-Object Metric1)[0].InterfaceIndex
    $NicInfo = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object {$_.InterfaceIndex -eq $PrimaryIfIndex}
    $PrimaryIP = $NicInfo.IPAddress | Where-Object {TestIsValidIPAddress -IPAddress $_}

    if ($PrimaryHyperVHostIPOverride) {
        if (!$(TestIsValidIPAddress -IPAddress $PrimaryHyperVHostIPOverride)) {
            Write-Error "'$PrimaryHyperVHostIPOverride' is not a valid IPv4 ip address! Halting!"
            $global:FunctionResult = "1"
            return
        }
        $PrimaryIP = $PrimaryHyperVHostIPOverride
    }

    if ($PSBoundParameters['CreateNewVMs'] -and !$PSBoundParameters['VMStorageDirectory']) {
        $VMStorageDirectory = Read-Host -Prompt "Please enter the full path to the directory where all VM files will be stored"
    }

    if (!$PSBoundParameters['CreateNewVMs'] -and $PSBoundParameters['VMStorageDirectory']) {
        $CreateNewVMs = $True
    }

    if (!$PSBoundParameters['LocalAdministratorAccountCredentials']) {
        if (!$IPofServerToBeDomainController) {
            $PromptMsg = "Please enter the *desired* password for the Local 'Administrator' account on the server that will become the new Domain Controller"
        }
        else {
            $PromptMsg = "Please enter the password for the Local 'Administrator' Account on $IPofServerToBeDomainController"
        }
        $LocalAdministratorAccountPassword = Read-Host -Prompt $PromptMsg -AsSecureString
        $LocalAdministratorAccountCredentials = [pscredential]::new("Administrator",$LocalAdministratorAccountPassword)
    }

    if (!$CreateNewVMs -and $PSBoundParameters['NewDomain'] -and !$PSBoundParameters['IPofServerToBeDomainController']) {
        $PromptMsg = "Please enter the IP Address of the existing Server that will become the new Domain Controller"
        $IPofServerToBeDomainController = Read-Host -Prompt $PromptMsg
    }

    if ($CreateNewVMs -and $PSBoundParameters['IPofServerToBeDomainController']) {
        $ErrMsg = "The parameter -IPofServerToBeDomainController was used in conjunction with " +
        "parameters that indicate that a new VM should be deployed (i.e. -CreateNewVMs and/or " +
        "-VMStorageDirectory). Please only use the -IPofServerToBeDomainController if " +
        "that server are already exists on the network. Halting!"
        Write-Error $ErrMsg
        $global:FunctionResult = "1"
        return
    }

    if (!$CreateNewVMs -and ! $PSBoundParameters['IPofServerToBeDomainController']) {
        Write-Error "The $($MyInvocation.MyCommand.Name) function requires either the -CreateNewVMs or -IPOfServerToBeDomainController parameter! Halting!"
        $global:FunctionResult = "1"
        return
    }

    <#
    if ($PSBoundParameters['IPofServerToBeDomainController']) {
        # Make sure we can reach RemoteHost IP(s) via WinRM/WSMan
        if (![bool]$(Test-Connection -Protocol WSMan -ComputerName $IPofServerToBeDomainController -Count 1 -ErrorAction SilentlyContinue)) {
            Write-Error "Unable to reach '$IPofServerToBeDomainController' via WinRM/WSMan! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    #>

    $FinalDomainName = $NewDomain
    $DomainShortName = $($FinalDomainName -split '\.')[0]

    #endregion >> Prep

    # Create the new VMs if desired
    if ($CreateNewVMs) {
        # Check to Make Sure Hyper-V is installed
        if (!$SkipHyperVInstallCheck) {
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
    
            if ($HyperVFeaturesInstallResults.InstallResults.Count -gt 0 -or $InstallContainersFeatureDismResult.RestartNeeded) {
                if (!$AllowRestarts) {
                    Write-Warning "You must restart $env:ComputerName before proceeding! Halting!"
                    # IMPORTANT NOTE: The below Write-Output "RestartNeeded" is necessary
                    Write-Output "RestartNeeded"
                    $global:FunctionResult = "1"
                    return
                }
                else {
                    Restart-Computer -Confirm:$False -Force
                }
            }
        }

        #region >> Hardware Resource Check

        # Make sure we have at least 35GB of Storage and 6GB of READILY AVAILABLE Memory
        # Check Storage...
        $LocalDrives = Get-CimInstance Win32_LogicalDisk | Where-Object {$_.Drivetype -eq 3} | foreach {Get-PSDrive $_.DeviceId[0] -ErrorAction SilentlyContinue}
        if ([bool]$(Get-Item $VMStorageDirectory).LinkType) {
            $VMStorageDirectoryDriveLetter = $(Get-Item $VMStorageDirectory).Target[0].Substring(0,1)
        }
        else {
            $VMStorageDirectoryDriveLetter = $VMStorageDirectory.Substring(0,1)
        }

        if ($LocalDrives.Name -notcontains $VMStorageDirectoryDriveLetter) {
            Write-Error "'$VMStorageDirectory' does not appear to be a local drive! VMs MUST be stored on a local drive! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $VMStorageDirectoryDriveInfo = Get-WmiObject Win32_LogicalDisk -ComputerName $env:ComputerName -Filter "DeviceID='$VMStorageDirectoryDriveLetter`:'"
        
        if ($([Math]::Round($VMStorageDirectoryDriveInfo.FreeSpace / 1MB)-2000) -lt 35000) {
            Write-Error "Drive '$VMStorageDirectoryDriveLetter' does not have at least 100GB of free space available! Halting!"
            $global:FunctionResult = "1"
            return
        }

        # Check Memory...
        $OSInfo = Get-CimInstance Win32_OperatingSystem
        $TotalMemory = $OSInfo.TotalVisibleMemorySize
        $MemoryAvailable = $OSInfo.FreePhysicalMemory
        $TotalMemoryInGB = [Math]::Round($TotalMemory / 1MB)
        $MemoryAvailableInGB = [Math]::Round($MemoryAvailable / 1MB)
        if ($MemoryAvailableInGB -lt 6 -and !$ForceWithLowMemory) {
            $MemoryErrorMsg = "The Hyper-V hypervisor $env:ComputerName should have at least 6GB of memory " +
            "readily available in order to run the new VMs. It currently only has about $MemoryAvailableInGB " +
            "GB available for immediate use. Halting!"
            Write-Error $MemoryErrorMsg
            $global:FunctionResult = "1"
            return
        }

        #endregion >> Hardware Resource Check

        #region >> Deploy New VMs

        $StartVMDeployment = Get-Date

        # Prepare To Manage .box Files
        if (!$(Test-Path "$VMStorageDirectory\BoxDownloads")) {
            $null = New-Item -ItemType Directory -Path "$VMStorageDirectory\BoxDownloads" -Force
        }
        $BoxNameRegex = [regex]::Escape($($Windows2016VagrantBox -split '/')[0])
        $BoxFileAlreadyPresentCheck = Get-ChildItem "$VMStorageDirectory\BoxDownloads" -File -Filter "*.box" | Where-Object {$_.Name -match $BoxNameRegex}
        $DecompressedBoxDirectoryPresentCheck = Get-ChildItem "$VMStorageDirectory\BoxDownloads" -Directory | Where-Object {$_.Name -match $BoxNameRegex}
        if ([bool]$DecompressedBoxDirectoryPresentCheck) {
            $DecompressedBoxDirectoryItem = $DecompressedBoxDirectoryPresentCheck
            $DecompressedBoxDir = $DecompressedBoxDirectoryItem.FullName
        }
        elseif ([bool]$BoxFileAlreadyPresentCheck) {
            $BoxFileItem = $BoxFileAlreadyPresentCheck
            $BoxFilePath = $BoxFileItem.FullName
        }
        else {
            $BoxFileItem = Get-VagrantBoxManualDownload -VagrantBox $Windows2016VagrantBox -VagrantProvider "hyperv" -DownloadDirectory "$VMStorageDirectory\BoxDownloads"
            $BoxFilePath = $BoxFileItem.FullName
        }

        $NewVMDeploySB = {
            $DeployBoxSplatParams = @{
                VagrantBox                  = $Windows2016VagrantBox
                CPUs                        = 2
                Memory                      = 4096
                VagrantProvider             = "hyperv"
                VMName                      = $DomainShortName + 'DC1'
                VMDestinationDirectory      = $VMStorageDirectory
                SkipHyperVInstallCheck      = $True
            }
            
            if ($DecompressedBoxDir) {
                if ($(Get-Item $DecompressedBoxDir).PSIsContainer) {
                    $DeployBoxSplatParams.Add('DecompressedBoxDirectory',$DecompressedBoxDir)
                }
            }
            if ($BoxFilePath) {
                if (-not $(Get-Item $BoxFilePath).PSIsContainer) {
                    $DeployBoxSplatParams.Add('BoxFilePath',$BoxFilePath)
                }
            }
            
            Write-Host "Deploying Hyper-V Vagrant Box..."
            $DeployBoxResult = Deploy-HyperVVagrantBoxManually @DeployBoxSplatParams
            $DeployBoxResult
        }

        if (!$IPofServerToBeDomainController) {
            $DomainShortName = $($NewDomain -split "\.")[0]
            Write-Host "Deploying New Domain Controller VM '$DomainShortName`DC1'..."

            if ($global:RSSyncHash) {
                $RunspaceNames = $($global:RSSyncHash.Keys | Where-Object {$_ -match "Result$"}) | foreach {$_ -replace 'Result',''}
                $NewDCVMDeployJobName = NewUniqueString -PossibleNewUniqueString "NewDCVM" -ArrayOfStrings $RunspaceNames
            }
            else {
                $NewDCVMDeployJobName = "NewDCVM"
            }

            $NewDCVMDeployJobSplatParams = @{
                RunspaceName    = $NewDCVMDeployJobName
                Scriptblock     = $NewVMDeploySB
                Wait            = $True
            }
            $NewDCVMDeployResult = New-Runspace @NewDCVMDeployJobSplatParams

            $IPofServerToBeDomainController = $NewDCVMDeployResult.VMIPAddress

            while (![bool]$(Get-VM -Name "$DomainShortName`DC1" -ErrorAction SilentlyContinue)) {
                Write-Host "Waiting for $DomainShortName`DC1 VM to be deployed..."
                Start-Sleep -Seconds 15
            }
            
            if (!$IPofServerToBeDomainController) {
                $IPofServerToBeDomainController = $(Get-VMNetworkAdapter -VMName "$DomainShortName`DC1").IPAddresses | Where-Object {TestIsValidIPAddress -IPAddress $_}
            }
        }

        [System.Collections.ArrayList]$VMsNotReportingIP = @()
        if (!$(TestIsValidIPAddress -IPAddress $IPofServerToBeDomainController)) {
            $null = $VMsNotReportingIP.Add("$DomainShortName`DC1")
        }

        if ($VMsNotReportingIP.Count -gt 0) {
            Write-Error "The following VMs did NOT report thier IP Addresses within 30 minutes:`n$($VMsNotReportingIP -join "`n")`nHalting!"
            $global:FunctionResult = "1"
            return
        }

        # Make sure IP is a valid IPv4 address
        if (![bool]$(TestIsValidIPAddress -IPAddress $IPofServerToBeDomainController)) {
            Write-Error "'$IPofServerToBeDomainController' is NOT a valid IPv4 IP Address! Halting!"
            $global:FunctionResult = "1"
            return
        }

        Write-Host "Finished Deploying New VMs..."

        #endregion >> Deploy New VMs
    }

    #region >> Update WinRM/WSMAN

    Write-Host "Updating WinRM/WSMan to allow for PSRemoting to Servers ..."
    try {
        $null = Enable-PSRemoting -Force -ErrorAction Stop
    }
    catch {
        # In the below, 0 is 'Public'
        $NICsWPublicProfile = @(Get-NetConnectionProfile | Where-Object {$_.NetworkCategory -eq 0})
        if ($NICsWPublicProfile.Count -gt 0) {
            foreach ($Nic in $NICsWPublicProfile) {
                Set-NetConnectionProfile -InterfaceIndex $Nic.InterfaceIndex -NetworkCategory 'Private'
            }
        }

        try {
            $null = Enable-PSRemoting -Force
        }
        catch {
            Write-Error $_
            Write-Error "Problem with Enable-PSRemoting WinRM Quick Config! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    # If $env:ComputerName is not part of a Domain, we need to add this registry entry to make sure WinRM works as expected
    if (!$(Get-CimInstance Win32_Computersystem).PartOfDomain) {
        $null = reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
    }

    # Add the New Server's IP Addresses to $env:ComputerName's TrustedHosts
    $CurrentTrustedHosts = $(Get-Item WSMan:\localhost\Client\TrustedHosts).Value
    [System.Collections.ArrayList][array]$CurrentTrustedHostsAsArray = $CurrentTrustedHosts -split ','

    [System.Collections.ArrayList]$ItemsToAddToWSMANTrustedHosts = @(
        $IPofServerToBeDomainController
    )

    foreach ($NetItem in $ItemsToAddToWSMANTrustedHosts) {
        if ($CurrentTrustedHostsAsArray -notcontains $NetItem) {
            $null = $CurrentTrustedHostsAsArray.Add($NetItem)
        }
    }
    $UpdatedTrustedHostsString = $($CurrentTrustedHostsAsArray | Where-Object {![string]::IsNullOrWhiteSpace($_)}) -join ','
    Set-Item WSMan:\localhost\Client\TrustedHosts $UpdatedTrustedHostsString -Force

    Write-Host "Finished updating WinRM/WSMan..."

    #endregion >> Update WinRM/WSMAN


    #region >> Make Sure WinRM/WSMan Is Ready on the Remote Hosts

    Write-Host "Attempting New PSSession to Server To Become DC for up to 30 minutes to ensure it is ready..."
    $PSSessionName = NewUniqueString -ArrayOfStrings $(Get-PSSession).Name -PossibleNewUniqueString "ToDC1Check"
    $Counter = 0
    while (![bool]$(Get-PSSession -Name $PSSessionName -ErrorAction SilentlyContinue)) {
        try {
            $DCPSSession = New-PSSession -ComputerName $IPofServerToBeDomainController -Credential $PSRemotingCredentials -Name $PSSessionName -ErrorAction SilentlyContinue
            if (![bool]$(Get-PSSession -Name $PSSessionName -ErrorAction SilentlyContinue)) {throw}
        }
        catch {
            if ($Counter -le 120) {
                Write-Warning "New-PSSession '$PSSessionName' failed. Trying again in 15 seconds..."
                Start-Sleep -Seconds 15
            }
            else {
                Write-Error "Unable to create new PSSession to '$PSSessionName' using account '$($PSRemotingCredentials.UserName)'! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        $Counter++
    }

    # Clear the PSSessions
    Get-PSSession | Remove-PSSession

    if ($CreateNewVMs) {
        $EndVMDeployment = Get-Date
        $TotalTime = $EndVMDeployment - $StartVMDeployment
        Write-Host "VM Deployment took $($TotalTime.Hours) hours and $($TotalTime.Minutes) minutes..." -ForegroundColor Yellow
    }

    #endregion >> Make Sure WinRM/WSMan Is Ready on the Remote Hosts
        
        
    #region >> Prep New Domain Controller

    $DomainShortName = $($NewDomain -split "\.")[0]
    $DomainSNLower = $DomainShortName.ToLowerInvariant()
    if (!$IPofServerToBeDomainController) {
        $VagrantVMPassword = ConvertTo-SecureString 'vagrant' -AsPlainText -Force
        $PSRemotingCredentials = [pscredential]::new("vagrant",$VagrantVMPassword)
    }
    if (![bool]$LocalAdministratorAccountCredentials) {
        $LocalAdministratorAccountPassword = Read-Host -Prompt "Please enter password for the Local 'Administrator' Account on $IPofServerToBeDomainController" -AsSecureString
        $LocalAdministratorAccountCredentials = [pscredential]::new("Administrator",$LocalAdministratorAccountPassword)
    }
    if (!$PSRemotingCredentials) {
        $PSRemotingCredentials = $LocalAdministratorAccountCredentials
    }
    if (!$DomainAdminCredentials) {
        $DomainAdminUserAcct = $DomainSNLower + '\' + $DomainSNLower + 'admin'
        $DomainAdminPassword = ConvertTo-SecureString 'P@ssword321!' -AsPlainText -Force
        $DomainAdminCredentials = [pscredential]::new($DomainAdminUserAcct,$DomainAdminPassword)
    }

    #region >> Rename Server To Be Domain Controller If Necessary

    # Check current HostName (and also set the local Administrator account password)
    $InvCmdCheckSB = {
        # Make sure the Local 'Administrator' account has its password set
        $UserAccount = Get-LocalUser -Name "Administrator"
        $UserAccount | Set-LocalUser -Password $args[0]
        $env:ComputerName
    }
    $InvCmdCheckSplatParams = @{
        ComputerName            = $IPofServerToBeDomainController
        Credential              = $PSRemotingCredentials
        ScriptBlock             = $InvCmdCheckSB
        ArgumentList            = $LocalAdministratorAccountCredentials.Password
        ErrorAction             = "Stop"
    }
    try {
        $RemoteHostNameDC = Invoke-Command @InvCmdCheckSplatParams
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    $RenameComputerJobSB = {
        $RenameComputerSBAsString = 'Rename-Computer -NewName $args[0] -LocalCredential $args[1] -Force -Restart'
        $RenameComputerSB = [scriptblock]::Create($RenameComputerSBAsString)

        $InvCmdRenameComputerSplatParams = @{
            ComputerName    = $IPofServerToBeDomainController
            Credential      = $PSRemotingCredentials
            ScriptBlock     = $RenameComputerSB
            ArgumentList    = $DesiredHostNameDC,$PSRemotingCredentials
            ErrorAction     = "Stop"
        }

        try {
            $null = Invoke-Command @InvCmdRenameComputerSplatParams
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }

    $DesiredHostNameDC = $DomainShortName + "DC1"

    # Rename the Server that will become the DC
    if ($RemoteHostNameDC -ne $DesiredHostNameDC) {
        Write-Host "Renaming '$IPofServerToBeDomainController' from '$RemoteHostNameDC' to '$DesiredHostNameDC'..."
        
        $RunspaceNames = $($global:RSSyncHash.Keys | Where-Object {$_ -match "Result$"}) | foreach {$_ -replace 'Result',''}
        $RenameDCJobName = NewUniqueString -PossibleNewUniqueString "RenameDC" -ArrayOfStrings $RunspaceNames

        $RenameDCJobSplatParams = @{
            RunspaceName    = $RenameDCJobName
            Scriptblock     = $RenameComputerJobSB
            Wait            = $True
        }
        $RenameDCJobInfo = New-Runspace @RenameDCJobSplatParams
    }

    if ($RenameDCJobInfo) {
        Write-Host "Sleeping for 5 minutes to give '$IPofServerToBeDomainController' time to reboot after name change..."
        Start-Sleep -Seconds 300
    
        # Try to make a PSSession for 15 minutes to verify the Host Name was changed
        Write-Host "Trying to remote into DC1 at $IPofServerToBeDomainController after HostName change..."
        $PSSessionName = NewUniqueString -ArrayOfStrings $(Get-PSSession).Name -PossibleNewUniqueString "ToDC1PostRename"
        $Counter = 0
        while (![bool]$(Get-PSSession -Name $PSSessionName -ErrorAction SilentlyContinue)) {
            try {
                $DCPSSession = New-PSSession -ComputerName $IPofServerToBeDomainController -Credential $PSRemotingCredentials -Name $PSSessionName -ErrorAction SilentlyContinue
                if (![bool]$(Get-PSSession -Name $PSSessionName -ErrorAction SilentlyContinue)) {throw}
            }
            catch {
                if ($Counter -le 60) {
                    Write-Warning "New-PSSession '$PSSessionName' failed. Trying again in 15 seconds..."
                    Start-Sleep -Seconds 15
                }
                else {
                    Write-Error "Unable to create new PSSession to '$PSSessionName' using account '$($PSRemotingCredentials.UserName)'! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
            $Counter++
        }
    
        # Verify the name of the Remote Host has been changed
        try {
            $NewHostNameCheckSplatParams = @{
                Session             = $DCPSSession
                ScriptBlock         = {$env:ComputerName}
            }
            $RemoteHostNameDC = Invoke-Command @NewHostNameCheckSplatParams 
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    
        if ($RemoteHostNameDC -ne $DesiredHostNameDC) {
            Write-Error "Failed to rename Server to become Domain Controller '$IPofServerToBeDomainController'! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    #endregion >> Rename Server To Be Domain Controller If Necessary

    #endregion >> Prep New Domain Controller


    #region >> Make the Domain Controller

    try {
        Write-Host "Creating the New Domain Controller..."
        $NewDomainControllerSplatParams = @{
            DesiredHostName                         = $DesiredHostNameDC
            NewDomainName                           = $NewDomain
            NewDomainAdminCredentials               = $DomainAdminCredentials
            ServerIP                                = $IPofServerToBeDomainController
            PSRemotingLocalAdminCredentials         = $PSRemotingCredentials
            LocalAdministratorAccountCredentials    = $LocalAdministratorAccountCredentials
            ErrorAction                             = "Stop"
        }
        $NewDomainControllerResults = New-DomainController @NewDomainControllerSplatParams
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    if (![bool]$($NewDomainControllerResults -match "DC Installation Success")) {
        Write-Error "Unable to determine if creation of the New Domain Controller '$DesiredHostNameDC' at '$IPofServerToBeDomainController' was successfule! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $EndTime = Get-Date
    $TotalAllOpsTime = $EndTime - $StartTime
    Write-Host "All operations for the $($MyInvocation.MyCommand.Name) function took $($TotalAllOpsTime.Hours) hours and $($TotalAllOpsTime.Minutes) minutes" -ForegroundColor Yellow

    $NewDomainControllerResults

    #endregion >> Make the Domain Controller

}

# SIG # Begin signature block
# MIIMaAYJKoZIhvcNAQcCoIIMWTCCDFUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUdpgVDVw6/J9OMKX8YjuLhcRa
# Nq2gggndMIIEJjCCAw6gAwIBAgITawAAADqEP46TDmc/hQAAAAAAOjANBgkqhkiG
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
# BDEWBBSHAPe7Iwg3hDLuXKNIeSx03uudLjANBgkqhkiG9w0BAQEFAASCAQAq95nM
# lT0lWtsExzunIY+kIyFxYYb3PWB+qgKYPMOb57BViX65NuyBDydodyFB/KPr0/Pl
# jHwOA9Ybhzp+IQdtcy5cQe8N2B7uVBhPrbXtJ3KK0pFzMsQ3fQpqNNQkwBMwB1ro
# /kH/OwFXbTxfRpaFlmA9+g1m7XH8DiCVpbBrIS91PAOtiFOHEBa5EuW+fVTMVOJn
# IXaWTI1evNbxt8GmfCKsuRjCyZK/tg12Q+LfromkwL/Z06Kn2FnDF74mPyJCzwoe
# p6nSTbnh0zIfB/O3ctUtKF3A4U7RrXE/LwwwOoEZUmTvBIMEGghoxR6QudpO2gT4
# iLaZgCeOh3Z4OzIt
# SIG # End signature block
