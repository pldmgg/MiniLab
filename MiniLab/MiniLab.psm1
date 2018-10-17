[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

# Get public and private function definition files.
[array]$Public  = Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1" -ErrorAction SilentlyContinue
[array]$Private = Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" -ErrorAction SilentlyContinue
$ThisModule = $(Get-Item $PSCommandPath).BaseName

# Dot source the Private functions
foreach ($import in $Private) {
    try {
        . $import.FullName
    }
    catch {
        Write-Error -Message "Failed to import function $($import.FullName): $_"
    }
}

[System.Collections.Arraylist]$ModulesToInstallAndImport = @("Hyper-V")
if (Test-Path "$PSScriptRoot\module.requirements.psd1") {
    $ModuleManifestData = Import-PowerShellDataFile "$PSScriptRoot\module.requirements.psd1"
    $ModuleManifestData.Keys | Where-Object {$_ -ne "PSDependOptions"} | foreach {$null = $ModulesToinstallAndImport.Add($_)}
}

if ($ModulesToInstallAndImport.Count -gt 0) {
    # NOTE: If you're not sure if the Required Module is Locally Available or Externally Available,
    # add it the the -RequiredModules string array just to be certain
    $InvModDepSplatParams = @{
        RequiredModules                     = $ModulesToInstallAndImport
        InstallModulesNotAvailableLocally   = $True
        ErrorAction                         = "SilentlyContinue"
        WarningAction                       = "SilentlyContinue"
    }
    $ModuleDependenciesMap = InvokeModuleDependencies @InvModDepSplatParams
}

# Public Functions


<#
    .SYNOPSIS
        This function adds an IP or hostname/fqdn to "WSMan:\localhost\Client\TrustedHosts". It also ensures
        that the WSMan Client is configured to allow for remoting.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER NewRemoteHost
        This parameter is MANDATORY.

        This parameter takes a string that represents the IP Address, HostName, or FQDN of the Remote Host
        that you would like to PSRemote to.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Add-WinRMTrustedHost -NewRemoteHost 192.168.2.49
        
#>
function Add-WinRMTrustedHost {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [string]$NewRemoteHost
    )

    # Make sure WinRM in Enabled and Running on $env:ComputerName
    try {
        $null = Enable-PSRemoting -Force -ErrorAction Stop
    }
    catch {
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
            Write-Error "Problem with Enabble-PSRemoting WinRM Quick Config! Halting!"
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

    $HostsToAddToWSMANTrustedHosts = @($NewRemoteHost)
    foreach ($HostItem in $HostsToAddToWSMANTrustedHosts) {
        if ($CurrentTrustedHostsAsArray -notcontains $HostItem) {
            $null = $CurrentTrustedHostsAsArray.Add($HostItem)
        }
        else {
            Write-Warning "Current WinRM Trusted Hosts Config already includes $HostItem"
            return
        }
    }
    $UpdatedTrustedHostsString = $($CurrentTrustedHostsAsArray | Where-Object {![string]::IsNullOrWhiteSpace($_)}) -join ','
    Set-Item WSMan:\localhost\Client\TrustedHosts $UpdatedTrustedHostsString -Force
}


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


<#
    .SYNOPSIS
        This function creates a new Enterprise Root Certification Authority by either...
        
        A) Creating a brand new Windows Server VM; or
        B) Using an existing Windows Server on the network
        
        ...and then running a configuration script over a PS Remoting Session.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER CreateNewVMs
        This parameter is OPTIONAL.

        This parameter is a switch. If used, a new Windows 2016 Standard Server Virtual Machine will be deployed
        to the localhost. If Hyper-V is not installed, it will be installed (and you will need to reatart the localhost
        before proceeding).

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

    .PARAMETER ExistingDomain
        This parameter is MANDATORY.

        This parameter takes a string that represents the name of the domain that the Root CA will join.
        Example: alpha.lab

    .PARAMETER DomainAdminCredentials
        This parameter is MANDATORY.

        This parameter takes a PSCredential. The Domain Admin Credentials will be used to join the Root CA Server to the domain
        as well as configre the new Root CA. This means that the Domain Account provided to this parameter MUST be a member
        of the following Security Groups in Active Directory:
            - Domain Admins
            - Domain Users
            - Enterprise Admins
            - Group Policy Creator Owners
            - Schema Admins

    .PARAMETER PSRemotingCredentials
        This parameter is MANDATORY.

        This parameter takes a PSCredential.

        The credential provided to this parameter should correspond to a User Account that has permission to
        remote into the target Windows Server. If you're using a Vagrant Box (which is what will be deployed
        if you use the -CreateNewVMs switch), then the value for this parameter should be created via:

            $VagrantVMPassword = ConvertTo-SecureString 'vagrant' -AsPlainText -Force
            $VagrantVMAdminCreds = [pscredential]::new("vagrant",$VagrantVMPassword)

    .PARAMETER IPOfServerToBeRootCA
        This parameter is OPTIONAL, however, if you do NOT use the -CreateNewVMs parameter, this parameter becomes MANDATORY.

        This parameter takes a string that represents an IPv4 Address referring to an EXISTING Windows Server on the network
        that will become the new Root CA.

    .PARAMETER IPofDomainController
        This parameter is OPTIONAL, however, if you cannot resolve the Domain Name provided to the -ExistingDomain parameter
        from the localhost, then this parameter becomes MANDATORY.

        This parameter takes a string that represents an IPv4 address referring to a Domain Controller (not readonly) on the
        domain specified by the -ExistingDomain parameter.

    .PARAMETER SkipHyperVInstallCheck
        This parameter is OPTIONAL.

        This parameter is a switch. If used, this function will not check to make sure Hyper-V is installed on the localhost.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> $VagrantVMPassword = ConvertTo-SecureString 'vagrant' -AsPlainText -Force
        PS C:\Users\zeroadmin> $VagrantVMAdminCreds = [pscredential]::new("vagrant",$VagrantVMPassword)
        PS C:\Users\zeroadmin> $DomainAdminCreds = [pscredential]::new("alpha\alphaadmin",$(Read-Host 'Enter Passsword' -AsSecureString))
        Enter Passsword: ************
        PS C:\Users\zeroadmin> $CreateRootCASplatParams = @{
        >> CreateNewVMs                            = $True
        >> VMStorageDirectory                      = "H:\VirtualMachines"
        >> ExistingDomain                          = "alpha.lab"
        >> IPOfDomainController                    = "192..168.2.112"
        >> PSRemotingCredentials                   = $VagrantVMAdminCreds
        >> DomainAdminCredentials                  = $DomainAdminCreds
        >> }
        PS C:\Users\zeroadmin> $CreateRootCAResult = Create-RootCA @CreateRootCASplatParams

#>
function Create-RootCA {
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
        [string]$ExistingDomain,

        [Parameter(Mandatory=$True)]
        [pscredential]$DomainAdminCredentials,

        [Parameter(Mandatory=$True)]
        [pscredential]$PSRemotingCredentials,

        [Parameter(Mandatory=$False)]
        [string]$IPofServerToBeRootCA,

        [Parameter(Mandatory=$False)]
        [string]$IPofDomainController,

        [Parameter(Mandatory=$False)]
        [switch]$SkipHyperVInstallCheck
    )

    #region >> Helper Functions

    # TestIsValidIPAddress
    # ResolveHost
    # GetDomainController
    # Deploy-HyperVVagrantBoxManually
    # Get-VagrantBoxManualDownload
    # New-RootCA

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

    if ($PSBoundParameters['CreateNewVMs']-and !$PSBoundParameters['VMStorageDirectory']) {
        $VMStorageDirectory = Read-Host -Prompt "Please enter the full path to the directory where all VM files will be stored"
    }

    if (!$PSBoundParameters['CreateNewVMs'] -and $PSBoundParameters['VMStorageDirectory']) {
        $CreateNewVMs = $True
    }

    if ($CreateNewVMs -and $PSBoundParameters['IPofServerToBeRootCA']) {
        $ErrMsg = "The parameter-IPofServerToBeRootCA, and was used in conjunction with parameters " +
        "that indicate that a new VM should be deployed (i.e. -CreateNewVMs and/or -VMStorageDirectory) " +
        "Please only use -IPofServerToBeRootCA if that server are already exists on the network. Halting!"
        Write-Error $ErrMsg
        $global:FunctionResult = "1"
        return
    }

    if (!$CreateNewVMs -and ! $PSBoundParameters['IPofServerToBeRootCA']) {
        Write-Error "The $($MyInvocation.MyCommand.Name) function requires either the -CreateNewVMs or -IPOfServerToBeRootCA parameter! Halting!"
        $global:FunctionResult = "1"
        return
    }

    <#
    if ($PSBoundParameters['IPofServerToBeRootCA']) {
        # Make sure we can reach RemoteHost IP(s) via WinRM/WSMan
        if (![bool]$(Test-Connection -Protocol WSMan -ComputerName $IPofServerToBeRootCA -Count 1 -ErrorAction SilentlyContinue)) {
            Write-Error "Unable to reach '$IPofServerToBeRootCA' via WinRM/WSMan! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    #>

    if (!$PSBoundParameters['IPofDomainController']) {
        # Make sure we can Resolve the Domain/Domain Controller
        try {
            [array]$ResolveDomain = Resolve-DNSName -Name $ExistingDomain -ErrorAction Stop
            $IPofDomainController = $ResolveDomain[0].IPAddress
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }
    if (!$(TestIsValidIPAddress -IPAddress $IPofDomainController)) {
        Write-Error "'$IPOfDomainController' is NOT a valid IPv4 address! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $FinalDomainName = if ($NewDomain) {$NewDomain} else {$ExistingDomain}
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
            $MemoryErrorMsg = "The Hyper-V hypervisor $env:ComputerName should have at least 12GB of memory " +
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
                VMName                      = $DomainShortName + 'RootCA'
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

        if (!$IPofServerToBeRootCA) {
            $DomainShortName = $($ExistingDomain -split "\.")[0]

            Write-Host "Deploying New Root CA VM '$DomainShortName`RootCA'..."
            
            if ($global:RSSyncHash) {
                $RunspaceNames = $($global:RSSyncHash.Keys | Where-Object {$_ -match "Result$"}) | foreach {$_ -replace 'Result',''}
                $NewRootCAVMDeployJobName = NewUniqueString -PossibleNewUniqueString "NewRootCAVM" -ArrayOfStrings $RunspaceNames
            }
            else {
                $NewRootCAVMDeployJobName = "NewRootCAVM"
            }

            $NewRootCAVMDeployJobSplatParams = @{
                RunspaceName    = $NewRootCAVMDeployJobName
                Scriptblock     = $NewVMDeploySB
                Wait            = $True
            }
            $NewRootCAVMDeployResult = New-Runspace @NewRootCAVMDeployJobSplatParams

            $IPofServerToBeRootCA = $NewRootCAVMDeployResult.VMIPAddress

            while (![bool]$(Get-VM -Name "$DomainShortName`RootCA" -ErrorAction SilentlyContinue)) {
                Write-Host "Waiting for $DomainShortName`RootCA VM to be deployed..."
                Start-Sleep -Seconds 15
            }

            if (!$IPofServerToBeRootCA) {
                $IPofServerToBeDomainController = $(Get-VMNetworkAdapter -VMName "$DomainShortName`RootCA").IPAddresses | Where-Object {TestIsValidIPAddress -IPAddress $_}
            }
        }

        [System.Collections.ArrayList]$VMsNotReportingIP = @()
        if (!$(TestIsValidIPAddress -IPAddress $IPofServerToBeRootCA)) {
            $null = $VMsNotReportingIP.Add("$DomainShortName`RootCA")
        }

        if ($VMsNotReportingIP.Count -gt 0) {
            Write-Error "The following VMs did NOT report thier IP Addresses within 30 minutes:`n$($VMsNotReportingIP -join "`n")`nHalting!"
            $global:FunctionResult = "1"
            return
        }

        # Make sure IP is a valid IPv4 address
        if (![bool]$(TestIsValidIPAddress -IPAddress $IPofServerToBeRootCA)) {
            Write-Error "'$IPofServerToBeRootCA' is NOT a valid IPv4 IP Address! Halting!"
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
        $IPofServerToBeRootCA
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

    Write-Host "Attempting New PSSession to Remote Hosts for up to 30 minutes to ensure they are ready..."

    $PSSessionName = NewUniqueString -ArrayOfStrings $(Get-PSSession).Name -PossibleNewUniqueString "ToRootCACheck"
    $Counter = 0
    while (![bool]$(Get-PSSession -Name $PSSessionName -ErrorAction SilentlyContinue)) {
        try {
            $RootCAPSSession = New-PSSession -ComputerName $IPofServerToBeRootCA -Credential $PSRemotingCredentials -Name $PSSessionName -ErrorAction SilentlyContinue
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


    #region >> Join the Servers to Domain And Rename If Necessary

    # Check if DC and RootCA should be the same server. If not, then need to join RootCA to Domain.
    if ($IPofDomainController -ne $IPofServerToBeRootCA) {
        $JoinDomainRSJobSB = {
            $JoinDomainSBAsString = @(
                '# Synchronize time with time servers'
                '$null = W32tm /resync /rediscover /nowait'
                ''
                '# Make sure the DNS Client points to IP of Domain Controller (and others from DHCP)'
                '$PrimaryIfIndex = $(Get-CimInstance Win32_IP4RouteTable | Where-Object {'
                '    $_.Destination -eq "0.0.0.0" -and $_.Mask -eq "0.0.0.0"'
                '} | Sort-Object Metric1)[0].InterfaceIndex'
                '$NicInfo = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object {$_.InterfaceIndex -eq $PrimaryIfIndex}'
                '$PrimaryIP = $NicInfo.IPAddress | Where-Object {TestIsValidIPAddress -IPAddress $_}'
                '$CurrentDNSServerListInfo = Get-DnsClientServerAddress -InterfaceIndex $PrimaryIfIndex -AddressFamily IPv4'
                '$CurrentDNSServerList = $CurrentDNSServerListInfo.ServerAddresses'
                '$UpdatedDNSServerList = [System.Collections.ArrayList][array]$CurrentDNSServerList'
                '$UpdatedDNSServerList.Insert(0,$args[0])'
                '$null = Set-DnsClientServerAddress -InterfaceIndex $PrimaryIfIndex -ServerAddresses $UpdatedDNSServerList'
                ''
                '$CurrentDNSSuffixSearchOrder = $(Get-DNSClientGlobalSetting).SuffixSearchList'
                '[System.Collections.ArrayList]$UpdatedDNSSuffixList = $CurrentDNSSuffixSearchOrder'
                '$UpdatedDNSSuffixList.Insert(0,$args[2])'
                'Set-DnsClientGlobalSetting -SuffixSearchList $UpdatedDNSSuffixList'
                ''
                '# Try resolving the Domain for 30 minutes'
                '$Counter = 0'
                'while (![bool]$(Resolve-DNSName $args[2] -ErrorAction SilentlyContinue) -and $Counter -le 120) {'
                '    Write-Host "Waiting for DNS to resolve Domain Controller..."'
                '    Start-Sleep -Seconds 15'
                '    $Counter++'
                '}'
                'if (![bool]$(Resolve-DNSName $args[2] -ErrorAction SilentlyContinue)) {'
                '    Write-Error "Unable to resolve Domain $($args[2])! Halting!"'
                '    $global:FunctionResult = "1"'
                '    return'
                '}'
                ''
                '# Join Domain'
                'Rename-Computer -NewName $args[1]'
                'Start-Sleep -Seconds 10'
                'Add-Computer -DomainName $args[2] -Credential $args[3] -Options JoinWithNewName,AccountCreate -Force -Restart'
            )
            
            try {
                $JoinDomainSB = [scriptblock]::Create($($JoinDomainSBAsString -join "`n"))
            }
            catch {
                Write-Error "Problem creating `$JoinDomainSB! Halting!"
                $global:FunctionResult = "1"
                return
            }
    
            $InvCmdJoinDomainSplatParams = @{
                ComputerName    = $IPofServerToBeRootCA
                Credential      = $PSRemotingCredentials
                ScriptBlock     = $JoinDomainSB
                ArgumentList    = $IPofDomainController,$DesiredHostNameRootCA,$ExistingDomain,$DomainAdminCredentials
            }
            try {
                Invoke-Command @InvCmdJoinDomainSplatParams
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }

        # Check if RootCA is already part of $ExistingDomain/$NewDomain
        $InvCmdRootCADomainSplatParams = @{
            ComputerName        = $IPofServerToBeRootCA
            Credential          = $PSRemotingCredentials
            ScriptBlock         = {$(Get-CimInstance win32_computersystem).Domain}
            ErrorAction         = "Stop"
        }
        try {
            $RootCADomain = Invoke-Command @InvCmdRootCADomainSplatParams
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        if ($RootCADomain -ne $ExistingDomain) {
            Write-Host "Joining the Root CA to the Domain..."
            $DesiredHostNameRootCA = $DomainShortName + "RootCA"

            $RunspaceNames = $($global:RSSyncHash.Keys | Where-Object {$_ -match "Result$"}) | foreach {$_ -replace 'Result',''}
            $JoinRootCAJobName = NewUniqueString -PossibleNewUniqueString "JoinRootCA" -ArrayOfStrings $RunspaceNames

            <#
            $JoinRootCAArgList = @(
                $IPofServerToBeRootCA
                $PSRemotingCredentials
                $IPofDomainController
                $DesiredHostNameRootCA
                $ExistingDomain
                $DomainAdminCredentials
            )
            #>
            $JoinRootCAJobSplatParams = @{
                RunspaceName    = $JoinRootCAJobName
                Scriptblock     = $JoinDomainRSJobSB
                Wait            = $True
            }
            $JoinRootCAResult = New-Runspace @JoinRootCAJobSplatParams

            # Verify Root CA is Joined to Domain
            # Try to create a PSSession to the Root CA for 15 minutes, then give up
            Write-Host "Trying to remote into RootCA at '$IPofServerToBeRootCA' with Domain Admin Credentials after Joining Domain..."
            $PSSessionName = NewUniqueString -ArrayOfStrings $(Get-PSSession).Name -PossibleNewUniqueString "ToRootCAPostDomainJoin"
            $Counter = 0
            while (![bool]$(Get-PSSession -Name $PSSessionName -ErrorAction SilentlyContinue)) {
                try {
                    $RootCAPSSessionPostDomainJoin = New-PSSession -ComputerName $IPofServerToBeRootCA -Credential $DomainAdminCredentials -Name $PSSessionName -ErrorAction SilentlyContinue
                    if (![bool]$(Get-PSSession -Name $PSSessionName -ErrorAction SilentlyContinue)) {throw}
                }
                catch {
                    if ($Counter -le 60) {
                        Write-Warning "New-PSSession '$PSSessionName' failed. Trying again in 15 seconds..."
                        Start-Sleep -Seconds 15
                    }
                    else {
                        Write-Error "Unable to create new PSSession to '$PSSessionName' using account '$($DomainAdminCredentials.UserName)'! Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                }
                $Counter++
            }

            if (!$RootCAPSSessionPostDomainJoin) {
                Write-Error "Unable to create a PSSession to the Root CA Server at '$IPofServerToBeRootCA' using Domain Admin Credentials $($DomainAdminCredentials.UserName)! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    }

    #endregion >> Join the Servers to Domain And Rename If Necessary


    #region >> Create the Root CA

    # Remove All Existing PSSessions
    Get-PSSession | Remove-PSSession

    Write-Host "Creating the New Root CA..."
    $NewRootCAResult = New-RootCA -DomainAdminCredentials $DomainAdminCredentials -RootCAIPOrFQDN $IPofServerToBeRootCA

    #endregion >> Create the Root CA

    $EndTime = Get-Date
    $TotalAllOpsTime = $EndTime - $StartTime
    Write-Host "All operations for the $($MyInvocation.MyCommand.Name) function took $($TotalAllOpsTime.Hours) hours and $($TotalAllOpsTime.Minutes) minutes" -ForegroundColor Yellow

    $NewRootCAResult

}


<#
    .SYNOPSIS
        This function creates a new Enterprise Subordinate/Intermediate/Issuing Certification Authority by either...
        
        A) Creating a brand new Windows Server VM; or
        B) Using an existing Windows Server on the network
        
        ...and then running a configuration script over a PS Remoting Session. Since this script needs to 
        request a Certificate from the Root CA, in order to avoid the double-hop authentication issue,
        a one-time-use Scheduled Task is created, immediately run, and deleted immediately after completion.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER CreateNewVMs
        This parameter is OPTIONAL.

        This parameter is a switch. If used, a new Windows 2016 Standard Server Virtual Machine will be deployed
        to the localhost. If Hyper-V is not installed, it will be installed (and you will need to reatart the localhost
        before proceeding).

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

    .PARAMETER ExistingDomain
        This parameter is MANDATORY.

        This parameter takes a string that represents the name of the domain that the Subordinate CA will join.
        Example: alpha.lab

    .PARAMETER DomainAdminCredentials
        This parameter is MANDATORY.

        This parameter takes a PSCredential. The Domain Admin Credentials will be used to join the Subordinate CA Server to the domain
        as well as configre the new Subordinate CA. This means that the Domain Account provided to this parameter MUST be a member
        of the following Security Groups in Active Directory:
            - Domain Admins
            - Domain Users
            - Enterprise Admins
            - Group Policy Creator Owners
            - Schema Admins

    .PARAMETER PSRemotingCredentials
        This parameter is MANDATORY.

        This parameter takes a PSCredential.

        The credential provided to this parameter should correspond to a User Account that has permission to
        remote into the target Windows Server. If you're using a Vagrant Box (which is what will be deployed
        if you use the -CreateNewVMs switch), then the value for this parameter should be created via:

            $VagrantVMPassword = ConvertTo-SecureString 'vagrant' -AsPlainText -Force
            $VagrantVMAdminCreds = [pscredential]::new("vagrant",$VagrantVMPassword)

    .PARAMETER IPOfServerToBeSubCA
        This parameter is OPTIONAL, however, if you do NOT use the -CreateNewVMs parameter, this parameter becomes MANDATORY.

        This parameter takes a string that represents an IPv4 Address referring to an EXISTING Windows Server on the network
        that will become the new Subordinate CA.

    .PARAMETER IPofDomainController
        This parameter is OPTIONAL, however, if you cannot resolve the Domain Name provided to the -ExistingDomain parameter
        from the localhost, then this parameter becomes MANDATORY.

        This parameter takes a string that represents an IPv4 address referring to a Domain Controller (not readonly) on the
        domain specified by the -ExistingDomain parameter.

    .PARAMETER IPOfRootCA
        This parameter is MANDATORY.

        This parameter takes a string that represents an IPv4 address referring to the Root CA on the domain specified by the
        -ExistingDomain parameter.

    .PARAMETER SkipHyperVInstallCheck
        This parameter is OPTIONAL.

        This parameter is a switch. If used, this function will not check to make sure Hyper-V is installed on the localhost.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> $VagrantVMPassword = ConvertTo-SecureString 'vagrant' -AsPlainText -Force
        PS C:\Users\zeroadmin> $VagrantVMAdminCreds = [pscredential]::new("vagrant",$VagrantVMPassword)
        PS C:\Users\zeroadmin> $DomainAdminCreds = [pscredential]::new("alpha\alphaadmin",$(Read-Host 'Enter Passsword' -AsSecureString))
        Enter Passsword: ************
        PS C:\Users\zeroadmin> $CreateSubCASplatParams = @{
        >> CreateNewVMs                            = $True
        >> VMStorageDirectory                      = "H:\VirtualMachines"
        >> ExistingDomain                          = "alpha.lab"
        >> IPOfDomainController                    = "192.168.2.112"
        >> IPOfRootCA                              = "192.168.2.113"
        >> PSRemotingCredentials                   = $VagrantVMAdminCreds
        >> DomainAdminCredentials                  = $DomainAdminCreds
        >> }
        PS C:\Users\zeroadmin> $CreateSubCAResult = Create-SubordinateCA @CreateSubCASplatParams

#>
function Create-SubordinateCA {
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
        [string]$ExistingDomain,

        [Parameter(Mandatory=$True)]
        [pscredential]$DomainAdminCredentials,

        [Parameter(Mandatory=$True)]
        [pscredential]$PSRemotingCredentials,

        [Parameter(Mandatory=$False)]
        [string]$IPofServerToBeSubCA,

        [Parameter(Mandatory=$False)]
        [string]$IPofDomainController,

        [Parameter(Mandatory=$True)]
        [string]$IPofRootCA,

        [Parameter(Mandatory=$False)]
        [switch]$SkipHyperVInstallCheck
    )

    #region >> Helper Functions

    # TestIsValidIPAddress
    # ResolveHost
    # GetDomainController
    # Deploy-HyperVVagrantBoxManually
    # Get-VagrantBoxManualDownload
    # New-SubordinateCA

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

    if ($PSBoundParameters['CreateNewVMs']-and !$PSBoundParameters['VMStorageDirectory']) {
        $VMStorageDirectory = Read-Host -Prompt "Please enter the full path to the directory where all VM files will be stored"
    }

    if (!$PSBoundParameters['CreateNewVMs'] -and $PSBoundParameters['VMStorageDirectory']) {
        $CreateNewVMs = $True
    }

    if ($CreateNewVMs -and $PSBoundParameters['IPofServerToBeSubCA']) {
        $ErrMsg = "The parameter-IPofServerToBeSubCA, and was used in conjunction with parameters " +
        "that indicate that a new VM should be deployed (i.e. -CreateNewVMs and/or -VMStorageDirectory) " +
        "Please only use -IPofServerToBeSubCA if that server are already exists on the network. Halting!"
        Write-Error $ErrMsg
        $global:FunctionResult = "1"
        return
    }

    if (!$CreateNewVMs -and ! $PSBoundParameters['IPofServerToBeSubCA']) {
        Write-Error "The $($MyInvocation.MyCommand.Name) function requires either the -CreateNewVMs or -IPOfServerToBeSubCA parameter! Halting!"
        $global:FunctionResult = "1"
        return
    }

    <#
    if ($PSBoundParameters['IPofServerToBeSubCA']) {
        # Make sure we can reach RemoteHost IP(s) via WinRM/WSMan
        if (![bool]$(Test-Connection -Protocol WSMan -ComputerName $IPofServerToBeSubCA -Count 1 -ErrorAction SilentlyContinue)) {
            Write-Error "Unable to reach '$IPofServerToBeSubCA' via WinRM/WSMan! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    #>

    if (!$PSBoundParameters['IPofDomainController']) {
        # Make sure we can Resolve the Domain/Domain Controller
        try {
            [array]$ResolveDomain = Resolve-DNSName -Name $ExistingDomain -ErrorAction Stop
            $IPofDomainController = $ResolveDomain[0].IPAddress
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }
    if (!$(TestIsValidIPAddress -IPAddress $IPofDomainController)) {
        Write-Error "'$IPOfDomainController' is NOT a valid IPv4 address! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$(TestIsValidIPAddress -IPAddress $IPofRootCA)) {
        Write-Error "'$IPofRootCA' is NOT a valid IPv4 address! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $FinalDomainName = if ($NewDomain) {$NewDomain} else {$ExistingDomain}
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
            $MemoryErrorMsg = "The Hyper-V hypervisor $env:ComputerName should have at least 12GB of memory " +
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
                VMName                      = $DomainShortName + 'SubCA'
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

        if (!$IPofServerToBeSubCA) {
            $DomainShortName = $($ExistingDomain -split "\.")[0]

            Write-Host "Deploying New Subordinate CA VM '$DomainShortName`SubCA'..."

            if ($global:RSSyncHash) {
                $RunspaceNames = $($global:RSSyncHash.Keys | Where-Object {$_ -match "Result$"}) | foreach {$_ -replace 'Result',''}
                $NewSubCAVMDeployJobName = NewUniqueString -PossibleNewUniqueString "NewSubCAVM" -ArrayOfStrings $RunspaceNames
            }
            else {
                $NewSubCAVMDeployJobName = "NewSubCAVM"
            }

            $NewSubCAVMDeployJobSplatParams = @{
                RunspaceName    = $NewSubCAVMDeployJobName
                Scriptblock     = $NewVMDeploySB
                Wait            = $True
            }
            $NewSubCAVMDeployResult = New-Runspace @NewSubCAVMDeployJobSplatParams

            $IPofServerToBeSubCA = $NewSubCAVMDeployResult.VMIPAddress

            while (![bool]$(Get-VM -Name "$DomainShortName`SubCA" -ErrorAction SilentlyContinue)) {
                Write-Host "Waiting for $DomainShortName`SubCA VM to be deployed..."
                Start-Sleep -Seconds 15
            }

            if (!$IPofServerToBeSubCA) {
                $IPofServerToBeSubCA = $(Get-VM -Name "$DomainShortName`SubCA").NetworkAdpaters.IPAddresses | Where-Object {TestIsValidIPAddress -IPAddress $_}
            }
        }

        [System.Collections.ArrayList]$VMsNotReportingIP = @()
        if (!$(TestIsValidIPAddress -IPAddress $IPofServerToBeSubCA)) {
            $null = $VMsNotReportingIP.Add("$DomainShortName`SubCA")
        }

        if ($VMsNotReportingIP.Count -gt 0) {
            Write-Error "The following VMs did NOT report thier IP Addresses within 30 minutes:`n$($VMsNotReportingIP -join "`n")`nHalting!"
            $global:FunctionResult = "1"
            return
        }

        # Make sure IP is a valid IPv4 address
        if (![bool]$(TestIsValidIPAddress -IPAddress $IPofServerToBeSubCA)) {
            Write-Error "'$IPofServerToBeSubCA' is NOT a valid IPv4 IP Address! Halting!"
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
        $IPofServerToBeSubCA
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

    Write-Host "Attempting New PSSession to Remote Hosts for up to 30 minutes to ensure they are ready..."

    $PSSessionName = NewUniqueString -ArrayOfStrings $(Get-PSSession).Name -PossibleNewUniqueString "ToSubCACheck"
    $Counter = 0
    while (![bool]$(Get-PSSession -Name $PSSessionName -ErrorAction SilentlyContinue)) {
        try {
            $SubCAPSSession = New-PSSession -ComputerName $IPofServerToBeSubCA -Credential $PSRemotingCredentials -Name $PSSessionName -ErrorAction SilentlyContinue
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


    #region >> Join the Servers to Domain And Rename If Necessary

    $JoinDomainRSJobSB = {
        $JoinDomainSBAsString = @(
            '# Synchronize time with time servers'
            '$null = W32tm /resync /rediscover /nowait'
            ''
            '# Make sure the DNS Client points to IP of Domain Controller (and others from DHCP)'
            '$PrimaryIfIndex = $(Get-CimInstance Win32_IP4RouteTable | Where-Object {'
            '    $_.Destination -eq "0.0.0.0" -and $_.Mask -eq "0.0.0.0"'
            '} | Sort-Object Metric1)[0].InterfaceIndex'
            '$NicInfo = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object {$_.InterfaceIndex -eq $PrimaryIfIndex}'
            '$PrimaryIP = $NicInfo.IPAddress | Where-Object {TestIsValidIPAddress -IPAddress $_}'
            '$CurrentDNSServerListInfo = Get-DnsClientServerAddress -InterfaceIndex $PrimaryIfIndex -AddressFamily IPv4'
            '$CurrentDNSServerList = $CurrentDNSServerListInfo.ServerAddresses'
            '$UpdatedDNSServerList = [System.Collections.ArrayList][array]$CurrentDNSServerList'
            '$UpdatedDNSServerList.Insert(0,$args[0])'
            '$null = Set-DnsClientServerAddress -InterfaceIndex $PrimaryIfIndex -ServerAddresses $UpdatedDNSServerList'
            ''
            '$CurrentDNSSuffixSearchOrder = $(Get-DNSClientGlobalSetting).SuffixSearchList'
            '[System.Collections.ArrayList]$UpdatedDNSSuffixList = $CurrentDNSSuffixSearchOrder'
            '$UpdatedDNSSuffixList.Insert(0,$args[2])'
            'Set-DnsClientGlobalSetting -SuffixSearchList $UpdatedDNSSuffixList'
            ''
            '# Try resolving the Domain for 30 minutes'
            '$Counter = 0'
            'while (![bool]$(Resolve-DNSName $args[2] -ErrorAction SilentlyContinue) -and $Counter -le 120) {'
            '    Write-Host "Waiting for DNS to resolve Domain Controller..."'
            '    Start-Sleep -Seconds 15'
            '    $Counter++'
            '}'
            'if (![bool]$(Resolve-DNSName $args[2] -ErrorAction SilentlyContinue)) {'
            '    Write-Error "Unable to resolve Domain $($args[2])! Halting!"'
            '    $global:FunctionResult = "1"'
            '    return'
            '}'
            ''
            '# Join Domain'
            'Rename-Computer -NewName $args[1]'
            'Start-Sleep -Seconds 10'
            'Add-Computer -DomainName $args[2] -Credential $args[3] -Options JoinWithNewName,AccountCreate -Force -Restart'
        )
        
        try {
            $JoinDomainSB = [scriptblock]::Create($($JoinDomainSBAsString -join "`n"))
        }
        catch {
            Write-Error "Problem creating `$JoinDomainSB! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $InvCmdJoinDomainSplatParams = @{
            ComputerName    = $IPofServerToBeSubCA
            Credential      = $PSRemotingCredentials
            ScriptBlock     = $JoinDomainSB
            ArgumentList    = $IPofDomainController,$DesiredHostNameSubCA,$ExistingDomain,$DomainAdminCredentials
        }
        try {
            Invoke-Command @InvCmdJoinDomainSplatParams
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }

    # Check if SubCA is already part of $ExistingDomain/$NewDomain
    $InvCmdSubCADomainSplatParams = @{
        ComputerName        = $IPofServerToBeSubCA
        Credential          = $PSRemotingCredentials
        ScriptBlock         = {$(Get-CimInstance win32_computersystem).Domain}
        ErrorAction         = "Stop"
    }
    try {
        $SubCADomain = Invoke-Command @InvCmdSubCADomainSplatParams
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    if ($SubCADomain -ne $ExistingDomain) {
        Write-Host "Joining the Sub CA to the Domain..."
        $DesiredHostNameSubCA = $DomainShortName + "SubCA"

        $RunspaceNames = $($global:RSSyncHash.Keys | Where-Object {$_ -match "Result$"}) | foreach {$_ -replace 'Result',''}
        $JoinSubCAJobName = NewUniqueString -PossibleNewUniqueString "JoinSubCA" -ArrayOfStrings $RunspaceNames

        <#
        $JoinSubCAArgList = @(
            $IPofServerToBeSubCA
            $PSRemotingCredentials
            $IPofDomainController
            $DesiredHostNameSubCA
            $ExistingDomain
            $DomainAdminCredentials
        )
        #>
        $JoinSubCAJobSplatParams = @{
            RunspaceName    = $JoinSubCAJobName
            Scriptblock     = $JoinDomainRSJobSB
            Wait            = $True
        }
        $JoinSubCAResult = New-Runspace @JoinSubCAJobSplatParams

        # Verify Sub CA is Joined to Domain
        # Try to create a PSSession to the Sub CA for 15 minutes, then give up
        Write-Host "Trying to remote into SubCA at '$IPofServerToBeSubCA' with Domain Admin Credentials after Joining Domain..."
        $PSSessionName = NewUniqueString -ArrayOfStrings $(Get-PSSession).Name -PossibleNewUniqueString "ToSubCAPostDomainJoin"
        $Counter = 0
        while (![bool]$(Get-PSSession -Name $PSSessionName -ErrorAction SilentlyContinue)) {
            try {
                $SubCAPSSessionPostDomainJoin = New-PSSession -ComputerName $IPofServerToBeSubCA -Credential $DomainAdminCredentials -Name $PSSessionName -ErrorAction SilentlyContinue
                if (![bool]$(Get-PSSession -Name $PSSessionName -ErrorAction SilentlyContinue)) {throw}
            }
            catch {
                if ($Counter -le 60) {
                    Write-Warning "New-PSSession '$PSSessionName' failed. Trying again in 15 seconds..."
                    Start-Sleep -Seconds 15
                }
                else {
                    Write-Error "Unable to create new PSSession to '$PSSessionName' using account '$($DomainAdminCredentials.UserName)'! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
            $Counter++
        }

        if (!$SubCAPSSessionPostDomainJoin) {
            Write-Error "Unable to create a PSSession to the Sub CA Server at '$IPofServerToBeSubCA' using Domain Admin Credentials $($DomainAdminCredentials.UserName)! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    #endregion >> Join the Servers to Domain And Rename If Necessary


    #region >> Create the Sub CA

    # Remove All Existing PSSessions
    Get-PSSession | Remove-PSSession

    Write-Host "Creating the New Subordinate CA..."
    $NewSubCAResult = New-SubordinateCA -DomainAdminCredentials $DomainAdminCredentials -RootCAIPOrFQDN $IPofRootCA -SubCAIPOrFQDN $IPofServerToBeSubCA

    #endregion >> Create the Sub CA

    $EndTime = Get-Date
    $TotalAllOpsTime = $EndTime - $StartTime
    Write-Host "All operations for the $($MyInvocation.MyCommand.Name) function took $($TotalAllOpsTime.Hours) hours and $($TotalAllOpsTime.Minutes) minutes" -ForegroundColor Yellow

    $NewSubCAResult

}


<#
    .SYNOPSIS
        This function creates a new Enterprise Root Certificate Authority and new Enterprise Subordinate/Intermediate/Issuing
        Certification Authority on a Domain. If you do not want to create the Root and Subordinate CAs on an existing
        domain, this function is capable of creating a brand new domain and deploying the CAs to that new domain.

    .DESCRIPTION
        This function is an example of 'Service Deployment' function that can be found within the MiniLab Module. A
        'Service Deployment' function is responsible for deploying as many servers as is necessary to get a particular
        service working on a domain/network. This may involve a myriad of feature/role installations and configuration
        setttings across multiple servers.

    .NOTES

    .PARAMETER CreateNewVMs
        This parameter is OPTIONAL.

        This parameter is a switch. If used, new Windows 2016 Standard Server Virtual Machines will be deployed
        to the localhost. If Hyper-V is not installed, it will be installed (and you will need to restart the localhost
        before proceeding).

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

    .PARAMETER ExistingDomain
        This parameter is OPTIONAL, however, either this parameter or the -NewDomain parameter are MANDATORY.

        This parameter takes a string that represents the name of the domain that the Root and Subordinate CAs will
        join (if they aren't already).

        Example: alpha.lab

    .PARAMETER NewDomain
        This parameter is OPTIONAL, however, either this parameter or the -ExistingDomain parameter are MANDATORY.

        This parameter takes a string that represents the name of the domain that the Root and Subordinate CAs will
        join (if they aren't already).
        
        Example: alpha.lab

    .PARAMETER DomainAdminCredentials
        This parameter is MANDATORY.

        This parameter takes a PSCredential. The Domain Admin Credentials will be used to join the Subordinate CA Server to the domain
        as well as configre the new Subordinate CA. This means that the Domain Account provided to this parameter MUST be a member
        of the following Security Groups in Active Directory:
            - Domain Admins
            - Domain Users
            - Enterprise Admins
            - Group Policy Creator Owners
            - Schema Admins

        If you are creating a New Domain, these credentials will be used to create a new Domain Account that is a member of the
        aforementioned Security Groups.

    .PARAMETER PSRemotingCredentials
        This parameter is MANDATORY.

        This parameter takes a PSCredential.

        The credential provided to this parameter should correspond to a User Account that has permission to
        remote into ALL target Windows Servers. If your target servers are Vagrant Boxes (which is what will be deployed
        if you use the -CreateNewVMs switch), then the value for this parameter should be created via:

            $VagrantVMPassword = ConvertTo-SecureString 'vagrant' -AsPlainText -Force
            $VagrantVMAdminCreds = [pscredential]::new("vagrant",$VagrantVMPassword)

    .PARAMETER LocalAdministratorAccountCredentials
        This parameter is OPTIONAL, however, is you are creating a New Domain, then this parameter is MANDATORY.

        This parameter takes a PSCredential.

        The credential provided to this parameter will be applied to the Local Built-In Administrator Account on the
        target Windows Server. In other words, the pscredential provided to this parameter does NOT need to match
        the current UserName/Password of the Local Administrator Account on the target Windows Server, because the
        pscredential provided to this parameter will overwrite whatever the existing credentials are.

    .PARAMETER DCIsRootCA
        This parameter is OPTIONAL.

        This parameter is a switch. If used, the  Root CA will be installed on the Primary Domain Controller. This is not
        best practice, but if you have limited hardware resources, this could come in handy.

    .PARAMETER IPofServerToBeDomainController
        This parameter is OPTIONAL.

        This parameter takes a string that represents an IPv4 Address referring to an EXISTING Windows Server on the network
        that will become the new Primary Domain Controller.

    .PARAMETER IPOfServerToBeRootCA
        This parameter is OPTIONAL.

        This parameter takes a string that represents an IPv4 Address referring to an EXISTING Windows Server on the network
        that will become the new Root CA.
    
    .PARAMETER IPOfServerToBeSubCA
        This parameter is OPTIONAL.

        This parameter takes a string that represents an IPv4 Address referring to an EXISTING Windows Server on the network
        that will become the new Subordinate CA.

    .PARAMETER SkipHyperVInstallCheck
        This parameter is OPTIONAL.

        This parameter is a switch. If used, this function will not check to make sure Hyper-V is installed on the localhost.

    .EXAMPLE
        # Create a New Domain With 3 Servers - Primary Domain Controller, Root CA, and Subordinate CA
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> $VagrantVMPassword = ConvertTo-SecureString 'vagrant' -AsPlainText -Force
        PS C:\Users\zeroadmin> $VagrantVMAdminCreds = [pscredential]::new("vagrant",$VagrantVMPassword)
        PS C:\Users\zeroadmin> $DomainAdminCreds = [pscredential]::new("alpha\alphaadmin",$(Read-Host 'Enter Passsword' -AsSecureString))
        Enter Passsword: ************
        PS C:\Users\zeroadmin> $LocalAdminAccountCreds = [pscredential]::new("Administrator",$(Read-Host 'Enter Passsword' -AsSecureString))
        Enter Passsword: **************
        PS C:\Users\zeroadmin> $CreateTwoTierPKISplatParams = @{
        >> CreateNewVMs                            = $True
        >> VMStorageDirectory                      = "H:\VirtualMachines"
        >> NewDomain                               = "alpha.lab"
        >> PSRemotingCredentials                   = $VagrantVMAdminCreds
        >> DomainAdminCredentials                  = $DomainAdminCreds
        >> LocalAdministratorAccountCredentials    = $LocalAdminAccountCreds
        >> }
        PS C:\Users\zeroadmin> Create-TwoTierPKI @CreateTwoTierPKISplatParams

    .EXAMPLE
        # Create a New Domain With 2 Servers - Primary Domain Controller (which will also be the Root CA), and Subordinate CA
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> $VagrantVMPassword = ConvertTo-SecureString 'vagrant' -AsPlainText -Force
        PS C:\Users\zeroadmin> $VagrantVMAdminCreds = [pscredential]::new("vagrant",$VagrantVMPassword)
        PS C:\Users\zeroadmin> $DomainAdminCreds = [pscredential]::new("alpha\alphaadmin",$(Read-Host 'Enter Passsword' -AsSecureString))
        Enter Passsword: ************
        PS C:\Users\zeroadmin> $LocalAdminAccountCreds = [pscredential]::new("Administrator",$(Read-Host 'Enter Passsword' -AsSecureString))
        Enter Passsword: **************
        PS C:\Users\zeroadmin> $CreateTwoTierPKISplatParams = @{
        >> CreateNewVMs                            = $True
        >> VMStorageDirectory                      = "H:\VirtualMachines"
        >> NewDomain                               = "alpha.lab"
        >> PSRemotingCredentials                   = $VagrantVMAdminCreds
        >> DomainAdminCredentials                  = $DomainAdminCreds
        >> LocalAdministratorAccountCredentials    = $LocalAdminAccountCreds
        >> SkipHyperVInstallCheck                  = $True
        >> DCIsRootCA                              = $True
        >> }
        PS C:\Users\zeroadmin> Create-TwoTierPKI @CreateTwoTierPKISplatParams

    .EXAMPLE
        # Add Two-Tier PKI to your Existing Domain
        # IMPORTANT NOTE: If you can't resolve the -ExistingDomain from the localhost, be sure to use the -IPOfServerToBeDomainController
        # parameter with the IP Address of an EXISTING Domain Controller on the domain specified by -ExistingDomain

        PS C:\Users\zeroadmin> $VagrantVMPassword = ConvertTo-SecureString 'vagrant' -AsPlainText -Force
        PS C:\Users\zeroadmin> $VagrantVMAdminCreds = [pscredential]::new("vagrant",$VagrantVMPassword)
        PS C:\Users\zeroadmin> $DomainAdminCreds = [pscredential]::new("alpha\alphaadmin",$(Read-Host 'Enter Passsword' -AsSecureString))
        Enter Passsword: ************
        PS C:\Users\zeroadmin> $LocalAdminAccountCreds = [pscredential]::new("Administrator",$(Read-Host 'Enter Passsword' -AsSecureString))
        Enter Passsword: **************
        PS C:\Users\zeroadmin> $CreateTwoTierPKISplatParams = @{
        >> CreateNewVMs                            = $True
        >> VMStorageDirectory                      = "H:\VirtualMachines"
        >> ExistingDomain                          = "alpha.lab"
        >> PSRemotingCredentials                   = $VagrantVMAdminCreds
        >> DomainAdminCredentials                  = $DomainAdminCreds
        >> }
        PS C:\Users\zeroadmin> Create-TwoTierPKI @CreateTwoTierPKISplatParams


#>
function Create-TwoTierPKI {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$False)]
        [switch]$CreateNewVMs,

        [Parameter(Mandatory=$False)]
        [string]$VMStorageDirectory,

        [Parameter(Mandatory=$False)]
        [string]$Windows2016VagrantBox = "jborean93/WindowsServer2016", # Alternate - StefanScherer/windows_2016

        [Parameter(Mandatory=$False)]
        [ValidatePattern("^([a-z0-9]+(-[a-z0-9]+)*\.)+([a-z]){2,}$")]
        [string]$NewDomain,

        [Parameter(Mandatory=$True)]
        [pscredential]$DomainAdminCredentials, # If creating a New Domain, this will be a New Domain Account

        [Parameter(Mandatory=$False)]
        [pscredential]$LocalAdministratorAccountCredentials,

        [Parameter(Mandatory=$False)]
        [pscredential]$PSRemotingCredentials, # These credentials must grant access to ALL Servers

        [Parameter(Mandatory=$False)]
        [string]$ExistingDomain,

        [Parameter(Mandatory=$False)]
        [switch]$DCIsRootCA,

        [Parameter(Mandatory=$False)]
        [string]$IPofServerToBeDomainController,

        [Parameter(Mandatory=$False)]
        [string]$IPofServerToBeRootCA,

        [Parameter(Mandatory=$False)]
        [string]$IPofServerToBeSubCA,

        [Parameter(Mandatory=$False)]
        [switch]$SkipHyperVInstallCheck
    )

    #region >> Helper Functions

    # TestIsValidIPAddress
    # ResolveHost
    # GetDomainController
    # Deploy-HyperVVagrantBoxManually
    # Get-VagrantBoxManualDownload
    # New-DomainController
    # New-RootCA
    # New-SubordinateCA

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

    if ($($PSBoundParameters['CreateNewVMs'] -or $PSBoundParameters['NewDomain']) -and
    !$PSBoundParameters['VMStorageDirectory']
    ) {
        $VMStorageDirectory = Read-Host -Prompt "Please enter the full path to the directory where all VM files will be stored"
    }

    if (!$PSBoundParameters['CreateNewVMs'] -and
    $($PSBoundParameters['VMStorageDirectory'] -or $PSBoundParameters['NewDomain'])
    ) {
        $CreateNewVMs = $True
    }

    if ($PSBoundParameters['NewDomain'] -and !$PSBoundParameters['LocalAdministratorAccountCredentials']) {
        if (!$IPofServerToBeDomainController) {
            $PromptMsg = "Please enter the *desired* password for the Local 'Administrator' account on the server that will become the new Domain Controller"
        }
        else {
            $PromptMsg = "Please enter the password for the Local 'Administrator' Account on $IPofServerToBeDomainController"
        }
        $LocalAdministratorAccountPassword = Read-Host -Prompt $PromptMsg -AsSecureString
        $LocalAdministratorAccountCredentials = [pscredential]::new("Administrator",$LocalAdministratorAccountPassword)
    }

    if ($($PSBoundParameters['IPofServerToBeRootCA'] -and !$PSBoundParameters['IPofServerToBeSubCA']) -or
    $(!$PSBoundParameters['IPofServerToBeRootCA'] -and $PSBoundParameters['IPofServerToBeSubCA'])
    ) {
        Write-Error "You must use BOTH -IPofServerToBeRootCA and -IPofServerToBeSubCA parameters or NEITHER of them! Halting!"
        $global:FunctionResult = "1"
        return
    }
    
    if ($PSBoundParameters['NewDomain'] -and $PSBoundParameters['ExistingDomain']) {
        Write-Error "Please use *either* the -NewDomain parameter *or* the -ExistingDomain parameter! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$PSBoundParameters['NewDomain'] -and !$PSBoundParameters['ExistingDomain']) {
        Write-Error "The $($MyInvocation.MyCommand.Name) function requires either the -ExistingDomain or the -NewDomain parameters! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$CreateNewVMs -and $PSBoundParameters['NewDomain'] -and !$PSBoundParameters['IPofServerToBeDomainController']) {
        $PromptMsg = "Please enter the IP Address of the existing Windows Server that will become the new Domain Controller"
        $IPofServerToBeDomainController = Read-Host -Prompt $PromptMsg
        while (![bool]$(TestIsValidIPAddress -IPAddress $IPofServerToBeDomainController)) {
            Write-Warning "'$IPofServerToBeDomainController' is NOT a valid IPv4 address!"
            $IPofServerToBeDomainController = Read-Host -Prompt $PromptMsg
        }
    }

    if ($CreateNewVMs -and 
    $($PSBoundParameters['IPofServerToBeDomainController'] -or $PSBoundParameters['ExistingDomain']) -and
    $PSBoundParameters['IPofServerToBeRootCA'] -and $PSBoundParameters['IPofServerToBeSubCA']
    ) {
        $ErrMsg = "The parameters -IPofServerToBeDomainController, -IPofServerToBeRootCA, and " +
        "-IPofServerToBeSubCA were used in conjunction with parameters that indicate that new VMs " +
        "should be deployed (i.e. -CreateNewVMs, -VMStorageDirectory, or -NewDomain). Please only " +
        "use -IPofServer* parameters if those servers are already exist. Halting!"
        Write-Error $ErrMsg
        $global:FunctionResult = "1"
        return
    }

    if (!$CreateNewVMs -and !$PSBoundParameters['IPofServerToBeRootCA']) {
        $PromptMsg = = "Please enter the IP Address of the existing Windows Server that will become the new Root CA"
        $IPofServerToBeRootCA = Read-Host -Prompt $PromptMsg
        while (![bool]$(TestIsValidIPAddress -IPAddress $IPofServerToBeRootCA)) {
            Write-Warning "'$IPofServerToBeRootCA' is NOT a valid IPv4 address!"
            $IPofServerToBeRootCA = Read-Host -Prompt $PromptMsg
        }
    }

    if (!$CreateNewVMs -and !$PSBoundParameters['IPofServerToBeSubCA']) {
        $PromptMsg = = "Please enter the IP Address of the existing Windows Server that will become the new Root CA"
        $IPofServerToBeSubCA = Read-Host -Prompt $PromptMsg
        while (![bool]$(TestIsValidIPAddress -IPAddress $IPofServerToBeSubCA)) {
            Write-Warning "'$IPofServerToBeSubCA' is NOT a valid IPv4 address!"
            $IPofServerToBeSubCA = Read-Host -Prompt $PromptMsg
        }
    }

    if ($PSBoundParameters['IPofServerToBeDomainController'] -and $PSBoundParameters['IPofServerToBeRootCA']) {
        if ($IPofServerToBeDomainController -eq $IPofServerToBeRootCA) {
            $DCIsRootCA = $True
        }
    }

    if (!$PSBoundParameters['NewDomain']) {
        if (!$PSBoundParameters['IPofServerToBeDomainController']) {
            # Make sure we can Resolve the Domain/Domain Controller
            try {
                [array]$ResolveDomain = Resolve-DNSName -Name $ExistingDomain -ErrorAction Stop
                $IPofServerToBeDomainController = $ResolveDomain[0].IPAddress
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
        if (!$(TestIsValidIPAddress -IPAddress $IPofServerToBeDomainController)) {
            Write-Error "'$IPofServerToBeDomainController' is NOT a valid IPv4 address! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    $FunctionsForRemoteUse = $script:FunctionsForSBUse

    $CreateDCSplatParams = @{
        PSRemotingCredentials                   = $PSRemotingCredentials
        DomainAdminCredentials                  = $DomainAdminCredentials
        LocalAdministratorAccountCredentials    = $LocalAdministratorAccountCredentials
    }

    $CreateRootCASplatParams = @{
        PSRemotingCredentials                   = $PSRemotingCredentials
        DomainAdminCredentials                  = $DomainAdminCredentials
    }

    $CreateSubCASplatParams = @{
        PSRemotingCredentials                   = $PSRemotingCredentials
        DomainAdminCredentials                  = $DomainAdminCredentials
    }

    $FinalDomainName = if ($NewDomain) {$NewDomain} else {$ExistingDomain}
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

        # Make sure we have at least 100GB of Storage and 12GB of READILY AVAILABLE Memory
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
        
        if ($([Math]::Round($VMStorageDirectoryDriveInfo.FreeSpace / 1MB)-2000) -lt 100000) {
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
        if ($MemoryAvailableInGB -lt 12 -and !$ForceWithLowMemory) {
            $MemoryErrorMsg = "The Hyper-V hypervisor $env:ComputerName should have at least 12GB of memory " +
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

        if ([Environment]::OSVersion.Version -lt [version]"10.0.17063") {
            if (![bool]$(Get-Command bsdtar -ErrorAction SilentlyContinue)) {
                # Download bsdtar from latest MSYS2 available on pldmgg github
                $WindowsNativeLinuxUtilsZipUrl = "https://github.com/pldmgg/WindowsNativeLinuxUtils/raw/master/MSYS2_20161025/bsdtar.zip"
                Invoke-WebRequest -Uri $WindowsNativeLinuxUtilsZipUrl -OutFile "$HOME\Downloads\bsdtar.zip"
                Expand-Archive -Path "$HOME\Downloads\bsdtar.zip" -DestinationPath "$HOME\Downloads" -Force
                $BsdTarDirectory = "$HOME\Downloads\bsdtar"
    
                if ($($env:Path -split ";") -notcontains $BsdTarDirectory) {
                    if ($env:Path[-1] -eq ";") {
                        $env:Path = "$env:Path$BsdTarDirectory"
                    }
                    else {
                        $env:Path = "$env:Path;$BsdTarDirectory"
                    }
                }
                $TarCmd = "bsdtar"
            }
            else {
                $TarCmd = "tar"
            }
        }
        
        if ($BoxFileItem) {
            $DecompressedBoxDir = "$VMStorageDirectory\BoxDownloads\$($BoxFileItem.BaseName)"
            if (!$(Test-Path $DecompressedBoxDir)) {
                $null = New-Item -ItemType Directory -Path $DecompressedBoxDir
            }

            # Extract the .box File
            Push-Location $DecompressedBoxDir

            if ($PSVersionTable.PSEdition -eq "Core") {
                <#
                GetWinPSInCore -ScriptBlock {
                    $FunctionsForRemoteUse | foreach {Invoke-Expression $_}

                    while ([bool]$(GetFileLockProcess -FilePath $BoxFilePath -ErrorAction SilentlyContinue)) {
                        Write-Host "$BoxFilePath is currently being used by another process...Waiting for it to become available"
                        Start-Sleep -Seconds 5
                    }
                }
                #>
                Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                    $args[0] | foreach {Invoke-Expression $_}

                    while ([bool]$(GetFileLockProcess -FilePath $args[1] -ErrorAction SilentlyContinue)) {
                        Write-Host "'$($args[1])' is currently being used by another process...Waiting for it to become available"
                        Start-Sleep -Seconds 5
                    }
                } -ArgumentList $FunctionsForRemoteUse,$BoxFilePath
            }
            else {
                while ([bool]$(GetFileLockProcess -FilePath $BoxFilePath -ErrorAction SilentlyContinue)) {
                    Write-Host "$BoxFilePath is currently being used by another process...Waiting for it to become available"
                    Start-Sleep -Seconds 5
                }
            }

            try {
                #Write-Host "Extracting .box file..."
                
                $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
                $ProcessInfo.WorkingDirectory = $DecompressedBoxDir
                $ProcessInfo.FileName = $TarCmd
                $ProcessInfo.RedirectStandardError = $true
                $ProcessInfo.RedirectStandardOutput = $true
                $ProcessInfo.UseShellExecute = $false
                $ProcessInfo.Arguments = "-xzvf $BoxFilePath"
                $Process = New-Object System.Diagnostics.Process
                $Process.StartInfo = $ProcessInfo
                $Process.Start() | Out-Null
                # Below $FinishedInAlottedTime returns boolean true/false
                # 1800000 ms is 30 minutes
                $FinishedInAlottedTime = $Process.WaitForExit(1800000)
                if (!$FinishedInAlottedTime) {
                    $Process.Kill()
                }
                $stdout = $Process.StandardOutput.ReadToEnd()
                $stderr = $Process.StandardError.ReadToEnd()
                $AllOutput = $stdout + $stderr
    
                if ($stderr) {
                    if ($stderr -match "failed") {
                        throw $stderr
                    }
                    else {
                        Write-Verbose $stderr
                    }
                }
            }
            catch {
                Write-Error $_
                #Remove-Item $BoxFilePath -Force
                $global:FunctionResult = "1"
                return
            }

            Pop-Location
        }

        # Make sure $BoxFilePath doesn't exist as a variable so that the below VM Deployment scriptblock
        # copies the $DecompressedBoxDir
        Remove-Variable -Name 'BoxFilePath' -Force -ErrorAction SilentlyContinue

        $ErrMsg = "Unable to find the decompressed Vagrant Box directory! Halting!"
        if (!$DecompressedBoxDir) {
            Write-Error $ErrMsg
            $global:FunctionResult = "1"
            return
        }
        if ($DecompressedBoxDir) {
            if (!$(Test-Path $DecompressedBoxDir)) {
                Write-Error $ErrMsg
                $global:FunctionResult = "1"
                return
            }
        }

        $NewVMDeploySB = {
            $DeployBoxSplatParams = @{
                VagrantBox                  = $Windows2016VagrantBox
                CPUs                        = 2
                Memory                      = 4096
                VagrantProvider             = "hyperv"
                VMName                      = $UpdatedVMName
                VMDestinationDirectory      = $VMStorageDirectory
                CopyDecompressedDirectory   = $True
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

        if ($NewDomain -and !$IPofServerToBeDomainController) {
            $DomainShortName = $($NewDomain -split "\.")[0]
            $NewDCVMName = $UpdatedVMName = $DomainShortName + 'DC1'
            Write-Host "Deploying New Domain Controller VM '$UpdatedVMName'..."

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
            }
            $null = New-Runspace @NewDCVMDeployJobSplatParams

            <#
            $NewDCVMDeployJobSplatParams = @{
                Name            = $NewDCVMDeployJobName
                Scriptblock     = $NewVMDeploySB
                ArgumentList    = $FunctionsForRemoteUse
            }
            $NewDCVMDeployJobInfo = Start-Job @NewDCVMDeployJobSplatParams
            #>
        }
        if (!$IPofServerToBeRootCA -and !$DCIsRootCA) {
            if ($NewDomain) {
                $DomainShortName = $($NewDomain -split "\.")[0]
            }
            if ($ExistingDomain) {
                $DomainShortName = $($ExistingDomain -split "\.")[0]
            }
            $NewRootCAVMName = $UpdatedVMName = $DomainShortName + "RootCA"
            Write-Host "Deploying New Root CA VM '$UpdatedVMName'..."

            if ($global:RSSyncHash) {
                $RunspaceNames = $($global:RSSyncHash.Keys | Where-Object {$_ -match "Result$"}) | foreach {$_ -replace 'Result',''}
                $NewRootCAVMDeployJobName = NewUniqueString -PossibleNewUniqueString "NewRootCAVM" -ArrayOfStrings $RunspaceNames
            }
            else {
                $NewRootCAVMDeployJobName = "NewRootCAVM"
            }

            $NewRootCAVMDeployJobSplatParams = @{
                RunspaceName    = $NewRootCAVMDeployJobName
                Scriptblock     = $NewVMDeploySB
            }
            $null = New-Runspace @NewRootCAVMDeployJobSplatParams

            <#
            $NewRootCAVMDeployJobSplatParams = @{
                Name            = $NewRootCAVMDeployJobName
                Scriptblock     = $NewVMDeploySB
                ArgumentList    = $FunctionsForRemoteUse
            }
            $NewRootCAVMDeployJobInfo = Start-Job @NewRootCAVMDeployJobSplatParams
            #>
        }
        if (!$IPofServerToBeSubCA) {
            if ($NewDomain) {
                $DomainShortName = $($NewDomain -split "\.")[0]
            }
            if ($ExistingDomain) {
                $DomainShortName = $($ExistingDomain -split "\.")[0]
            }
            $NewSubCAVMName = $UpdatedVMName = $DomainShortName + "SubCA"
            Write-Host "Deploying New Subordinate CA VM '$UpdatedVMName'..."

            if ($global:RSSyncHash) {
                $RunspaceNames = $($global:RSSyncHash.Keys | Where-Object {$_ -match "Result$"}) | foreach {$_ -replace 'Result',''}
                $NewSubCAVMDeployJobName = NewUniqueString -PossibleNewUniqueString "NewSubCAVM" -ArrayOfStrings $RunspaceNames
            }
            else {
                $NewSubCAVMDeployJobName = "NewSubCAVM"
            }

            $NewSubCAVMDeployJobSplatParams = @{
                RunspaceName    = $NewSubCAVMDeployJobName
                Scriptblock     = $NewVMDeploySB
            }
            $null = New-Runspace @NewSubCAVMDeployJobSplatParams

            <#
            $NewSubCAVMDeployJobSplatParams = @{
                Name            = $NewSubCAVMDeployJobName
                Scriptblock     = $NewVMDeploySB
                ArgumentList    = $FunctionsForRemoteUse
            }
            $NewSubCAVMDeployJobInfo = Start-Job @NewSubCAVMDeployJobSplatParams
            #>
        }

        [System.Collections.ArrayList]$ResultProperties = @()
        if ($NewDomain -and !$IPofServerToBeDomainController) {
            $NewDCResultProperty = $NewDCVMDeployJobName + "Result"
            $null = $ResultProperties.Add($NewDCResultProperty)
        }
        if (!$IPofServerToBeRootCA -and !$DCIsRootCA) {
            $NewRootCAResultProperty = $NewRootCAVMDeployJobName + "Result"
            $null = $ResultProperties.Add($NewRootCAResultProperty)
        }
        if (!$IPofServerToBeSubCA) {
            $NewSubCAResultProperty = $NewSubCAVMDeployJobName + "Result"
            $null = $ResultProperties.Add($NewSubCAResultProperty)
        }

        # VM deployment operations have 60 minutes to complete...
        $Counter = 0
        while (!$VMsReady -and $Counter -le 60) {
            [System.Collections.ArrayList]$ResultCollection = @()
            foreach ($ResultProp in $ResultProperties) {
                if ($global:RSSyncHash.$ResultProp.Errors.Count -gt 0 -and $global:RSSyncHash.$ResultProp.Done -eq $True) {
                    $Errmsg = "One or more errors occurred with the Deploy-HyperVVagrantBoxManually " +
                    "function within the Runspaces. Please inspect the 'Errors' property in the " +
                    "`$global:RSSynchHash object. Halting!"
                    Write-Error $ErrMsg
                    $global:FunctionResult = "1"
                    return
                }

                if ($global:RSSyncHash.$ResultProp.Done -ne $True) {
                    Write-Host "Waiting for $ResultProp ..."
                    $null = $ResultCollection.Add($False)
                }
                else {
                    $null = $ResultCollection.Add($True)
                }
            }

            if ($ResultCollection -contains $False -or $ResultCollection.Count -eq 0) {
                Write-Host "VMs not ready. Checking again in 60 seconds ..."
                $VMsReady = $False
                Start-Sleep -Seconds 60
                $Counter++
            }
            else {
                $VMsReady = $True
                Write-Host "VMs are ready to be configured!" -ForegroundColor Green
            }
        }
        if ($Counter -gt 60) {
            Write-Error "VMs were not deployed within 60 minutes! Halting!"
            $global:FunctionResult = "1"
            return
        }

        Write-Host "Waiting for VMs to report their IP Addresses (for up to 30 minutes)..."

        # NOTE: Each VM has 30 minutes to report its IP Address
        $Counter = 0
        if ($NewDomain -and !$IPofServerToBeDomainController) {
            $NewDCVMDeployResult = $global:RSSyncHash.$NewDCResultProperty.Output

            $IPofServerToBeDomainController = $NewDCVMDeployResult.VMIPAddress

            if (!$(TestIsValidIPAddress -IPAddress $IPofServerToBeDomainController)) {
                $VMNetAdapter = Get-VMNetworkAdapter -VMName $NewDCVMName -ErrorAction SilentlyContinue
                $IPofServerToBeDomainController = $NewDCVMIPCheck = $VMNetAdapter.IPAddresses | Where-Object {TestIsValidIPAddress -IPAddress $_}
                while (!$NewDCVMIPCheck -and $Counter -le 60) {
                    Start-Sleep -Seconds 60

                    $VMNetAdapter = Get-VMNetworkAdapter -VMName $NewDCVMName -ErrorAction SilentlyContinue
                    $IPofServerToBeDomainController = $NewDCVMIPCheck = $VMNetAdapter.IPAddresses | Where-Object {TestIsValidIPAddress -IPAddress $_}
                    $Counter++
                }
            }
        }

        $Counter = 0
        if (!$IPofServerToBeRootCA) {
            if ($DCIsRootCA) {
                $IPofServerToBeRootCA = $IPofServerToBeDomainController
            }

            if (!$DCIsRootCA) {
                $NewRootCAVMDeployResult = $global:RSSyncHash.$NewRootCAResultProperty.Output

                $IPofServerToBeRootCA = $NewRootCAVMDeployResult.VMIPAddress

                if (!$(TestIsValidIPAddress -IPAddress $IPofServerToBeRootCA)) {
                    $VMNetAdapter = Get-VMNetworkAdapter -VMName $NewRootCAVMName -ErrorAction SilentlyContinue
                    $IPofServerToBeRootCA = $NewRootCAVMIPCheck = $VMNetAdapter.IPAddresses | Where-Object {TestIsValidIPAddress -IPAddress $_}
                    while (!$NewRootCAVMIPCheck -and $Counter -le 60) {
                        Start-Sleep -Seconds 60
    
                        $VMNetAdapter = Get-VMNetworkAdapter -VMName $NewRootCAVMName -ErrorAction SilentlyContinue
                        $IPofServerToBeRootCA = $NewRootCAVMIPCheck = $VMNetAdapter.IPAddresses | Where-Object {TestIsValidIPAddress -IPAddress $_}
                        $Counter++
                    }
                }
            }
        }

        $Counter = 0
        if (!$IPofServerToBeSubCA) {
            $NewSubCAVMDeployResult = $global:RSSyncHash.$NewSubCAResultProperty.Output

            $IPofServerToBeSubCA = $NewRSubCAVMDeployResult.VMIPAddress

            if (!$(TestIsValidIPAddress -IPAddress $IPofServerToBeSubCA)) {
                $VMNetAdapter = Get-VMNetworkAdapter -VMName $NewSubCAVMName -ErrorAction SilentlyContinue
                $IPofServerToBeSubCA = $NewSubCAVMIPCheck = $VMNetAdapter.IPAddresses | Where-Object {TestIsValidIPAddress -IPAddress $_}
                while (!$NewSubCAVMIPCheck -and $Counter -le 60) {
                    Start-Sleep -Seconds 60

                    $VMNetAdapter = Get-VMNetworkAdapter -VMName $NewSubCAVMName -ErrorAction SilentlyContinue
                    $IPofServerToBeSubCA = $NewSubCAVMIPCheck = $VMNetAdapter.IPAddresses | Where-Object {TestIsValidIPAddress -IPAddress $_}
                    $Counter++
                }
            }
        }

        [System.Collections.ArrayList]$VMsNotReportingIP = @()
        if (!$(TestIsValidIPAddress -IPAddress $IPofServerToBeDomainController)) {
            $null = $VMsNotReportingIP.Add($NewDCVMName)
        }
        if (!$(TestIsValidIPAddress -IPAddress $IPofServerToBeRootCA)) {
            $null = $VMsNotReportingIP.Add($NewRootCAVMName)
        }
        if (!$(TestIsValidIPAddress -IPAddress $IPofServerToBeSubCA)) {
            $null = $VMsNotReportingIP.Add($NewSubCAVMName)
        }

        if ($VMsNotReportingIP.Count -gt 0) {
            Write-Error "The following VMs did NOT report thier IP Addresses within 30 minutes:`n$($VMsNotReportingIP -join "`n")`nHalting!"
            $global:FunctionResult = "1"
            return
        }

        Write-Host "Finished Deploying New VMs..." -ForegroundColor Green

        if ($NewDomain) {
            Write-Host "IP of DC is $IPOfServerToBeDomainController"
        }
        Write-Host "IP of Root CA is $IPOfServerToBeRootCA"
        Write-Host "IP of Sub CA is $IPOfServerToBeSubCA"

        #region >> Update WinRM/WSMAN

        Write-Host "Updating WinRM/WSMan to allow for PSRemoting to Servers ..."
        try {
            $null = Enable-PSRemoting -Force -ErrorAction Stop
        }
        catch {
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
                Write-Error "Problem with Enabble-PSRemoting WinRM Quick Config! Halting!"
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
            $IPofServerToBeRootCA
            $IPofServerToBeSubCA
        )
        if ($IPofServerToBeDomainController) {
            $null = $ItemsToAddToWSMANTrustedHosts.Add($IPofServerToBeDomainController)
        }
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

        Write-Host "Attempting New PSSession to Remote Hosts for up to 30 minutes to ensure they are ready..."
        if ($NewDomain) {
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
                        Write-Error "Unable to create new PSSession to '$PSSessionName' to '$IPofServerToBeDomainController' using account '$($PSRemotingCredentials.UserName)' within 30 minutes! Halting!"
                        $global:FunctionResult = "1"
                        return
                    }
                }
                $Counter++
            }
        }

        $PSSessionName = NewUniqueString -ArrayOfStrings $(Get-PSSession).Name -PossibleNewUniqueString "ToRootCACheck"
        $Counter = 0
        while (![bool]$(Get-PSSession -Name $PSSessionName -ErrorAction SilentlyContinue)) {
            try {
                $RootCAPSSession = New-PSSession -ComputerName $IPofServerToBeRootCA -Credential $PSRemotingCredentials -Name $PSSessionName -ErrorAction SilentlyContinue
                if (![bool]$(Get-PSSession -Name $PSSessionName -ErrorAction SilentlyContinue)) {throw}
            }
            catch {
                if ($Counter -le 120) {
                    Write-Warning "New-PSSession '$PSSessionName' failed. Trying again in 15 seconds..."
                    Start-Sleep -Seconds 15
                }
                else {
                    Write-Error "Unable to create new PSSession to '$PSSessionName' to '$IPofServerToBeRootCA' using account '$($PSRemotingCredentials.UserName)' within 30 minutes! Halting!"
                    $global:FunctionResult = "1"
                    $RootCAPSRemotingFailure = $True
                    return
                }
            }
            $Counter++
        }

        $PSSessionName = NewUniqueString -ArrayOfStrings $(Get-PSSession).Name -PossibleNewUniqueString "ToSubCACheck"
        $Counter = 0
        while (![bool]$(Get-PSSession -Name $PSSessionName -ErrorAction SilentlyContinue)) {
            try {
                $SubCAPSSession = New-PSSession -ComputerName $IPofServerToBeSubCA -Credential $PSRemotingCredentials -Name $PSSessionName -ErrorAction SilentlyContinue
                if (![bool]$(Get-PSSession -Name $PSSessionName -ErrorAction SilentlyContinue)) {throw}
            }
            catch {
                if ($Counter -le 60) {
                    Write-Warning "New-PSSession '$PSSessionName' failed. Trying again in 15 seconds..."
                    Start-Sleep -Seconds 15
                }
                else {
                    Write-Error "Unable to create new PSSession to '$PSSessionName' to '$IPofServerToBeSubCA' using account '$($PSRemotingCredentials.UserName)' within 30 minutes! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
            $Counter++
        }

        # Clear the PSSessions
        Get-PSSession | Remove-PSSession

        $EndVMDeployment = Get-Date

        if ($StartVMDeployment -and $EndVMDeployment) {
            $TotalTime = $EndVMDeployment - $StartVMDeployment
            Write-Host "VM Deployment took $($TotalTime.Hours) hours and $($TotalTime.Minutes) minutes..." -ForegroundColor Yellow
        }

        #endregion >> Make Sure WinRM/WSMan Is Ready on the Remote Hosts

        # Finish setting splat params for Create-Domain, Create-RootCA, and Create-SubordinateCA functions...
        if ($NewDomain) {
            $CreateDCSplatParams.Add("IPofServerToBeDomainController",$IPofServerToBeDomainController)
            $CreateDCSplatParams.Add("NewDomain",$FinalDomainName)

            #Write-Host "Splat Params for Create-Domain are:" -ForegroundColor Yellow
            #$CreateDCSplatParams
        }

        $CreateRootCASplatParams.Add("IPofServerToBeRootCA",$IPofServerToBeRootCA)
        $CreateRootCASplatParams.Add("IPofDomainController",$IPofServerToBeDomainController)
        $CreateRootCASplatParams.Add("ExistingDomain",$FinalDomainName)
        #Write-Host "Splat Params for Create-RootCA are:" -ForegroundColor Yellow
        #$CreateRootCASplatParams

        $CreateSubCASplatParams.Add("IPofServerToBeSubCA",$IPofServerToBeSubCA)
        $CreateSubCASplatParams.Add("IPofDomainController",$IPofServerToBeDomainController)
        $CreateSubCASplatParams.Add("IPofRootCA",$IPofServerToBeRootCA)
        $CreateSubCASplatParams.Add("ExistingDomain",$FinalDomainName)
        #Write-Host "Splat Params for Create-SubordinateCA are:" -ForegroundColor Yellow
        #$CreateSubCASplatParams

        
        #endregion >> Deploy New VMs
    }

    #region >> Create the Services
    
    if ($NewDomain) {
        try {
            $CreateDCResult = Create-Domain @CreateDCSplatParams
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }

    try {
        $CreateRootCAResult = Create-RootCA @CreateRootCASplatParams
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }
    
    try {
        $CreateSubCAResult = Create-SubordinateCA @CreateSubCASplatParams
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    $EndTime = Get-Date
    $TotalAllOpsTime = $EndTime - $StartTime
    Write-Host "All operations for the $($MyInvocation.MyCommand.Name) function took $($TotalAllOpsTime.Hours) hours and $($TotalAllOpsTime.Minutes) minutes" -ForegroundColor Yellow

    $Output = @{
        CreateRootCAResult      = $CreateRootCAResult
        CreateSubCAResult       = $CreateSubCAResult
    }
    if ($CreateDCResult) {
        $Output.Add("CreateDCResult",$CreateDCResult)
    }

    [pscustomobject]$Output

    #end >> Create the Services
}


<#
    .SYNOPSIS
        This function creates a new Enterprise Root Certificate Authority and new Enterprise Subordinate/Intermediate/Issuing
        Certification Authority on a Domain. If you do not want to create the Root and Subordinate CAs on an existing
        domain, this function is capable of creating a brand new domain and deploying the CAs to that new domain.

    .DESCRIPTION
        This function is an example of 'Service Deployment' function that can be found within the MiniLab Module. A
        'Service Deployment' function is responsible for deploying as many servers as is necessary to get a particular
        service working on a domain/network. This may involve a myriad of feature/role installations and configuration
        setttings across multiple servers.

    .NOTES

    .PARAMETER CreateNewVMs
        This parameter is OPTIONAL.

        This parameter is a switch. If used, new Windows 2016 Standard Server Virtual Machines will be deployed
        to the localhost. If Hyper-V is not installed, it will be installed (and you will need to restart the localhost
        before proceeding).

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

    .PARAMETER ExistingDomain
        This parameter is OPTIONAL, however, either this parameter or the -NewDomain parameter are MANDATORY.

        This parameter takes a string that represents the name of the domain that the Root and Subordinate CAs will
        join (if they aren't already).

        Example: alpha.lab

    .PARAMETER NewDomain
        This parameter is OPTIONAL, however, either this parameter or the -ExistingDomain parameter are MANDATORY.

        This parameter takes a string that represents the name of the domain that the Root and Subordinate CAs will
        join (if they aren't already).
        
        Example: alpha.lab

    .PARAMETER DomainAdminCredentials
        This parameter is MANDATORY.

        This parameter takes a PSCredential. The Domain Admin Credentials will be used to join the Subordinate CA Server to the domain
        as well as configre the new Subordinate CA. This means that the Domain Account provided to this parameter MUST be a member
        of the following Security Groups in Active Directory:
            - Domain Admins
            - Domain Users
            - Enterprise Admins
            - Group Policy Creator Owners
            - Schema Admins

        If you are creating a New Domain, these credentials will be used to create a new Domain Account that is a member of the
        aforementioned Security Groups.

    .PARAMETER PSRemotingCredentials
        This parameter is MANDATORY.

        This parameter takes a PSCredential.

        The credential provided to this parameter should correspond to a User Account that has permission to
        remote into ALL target Windows Servers. If your target servers are Vagrant Boxes (which is what will be deployed
        if you use the -CreateNewVMs switch), then the value for this parameter should be created via:

            $VagrantVMPassword = ConvertTo-SecureString 'vagrant' -AsPlainText -Force
            $VagrantVMAdminCreds = [pscredential]::new("vagrant",$VagrantVMPassword)

    .PARAMETER LocalAdministratorAccountCredentials
        This parameter is OPTIONAL, however, is you are creating a New Domain, then this parameter is MANDATORY.

        This parameter takes a PSCredential.

        The credential provided to this parameter will be applied to the Local Built-In Administrator Account on the
        target Windows Server. In other words, the pscredential provided to this parameter does NOT need to match
        the current UserName/Password of the Local Administrator Account on the target Windows Server, because the
        pscredential provided to this parameter will overwrite whatever the existing credentials are.

    .PARAMETER DCIsRootCA
        This parameter is OPTIONAL.

        This parameter is a switch. If used, the  Root CA will be installed on the Primary Domain Controller. This is not
        best practice, but if you have limited hardware resources, this could come in handy.

    .PARAMETER IPofServerToBeDomainController
        This parameter is OPTIONAL.

        This parameter takes a string that represents an IPv4 Address referring to an EXISTING Windows Server on the network
        that will become the new Primary Domain Controller.

    .PARAMETER IPOfServerToBeRootCA
        This parameter is OPTIONAL.

        This parameter takes a string that represents an IPv4 Address referring to an EXISTING Windows Server on the network
        that will become the new Root CA.
    
    .PARAMETER IPOfServerToBeSubCA
        This parameter is OPTIONAL.

        This parameter takes a string that represents an IPv4 Address referring to an EXISTING Windows Server on the network
        that will become the new Subordinate CA.

    .PARAMETER SkipHyperVInstallCheck
        This parameter is OPTIONAL.

        This parameter is a switch. If used, this function will not check to make sure Hyper-V is installed on the localhost.

    .EXAMPLE
        # Create a New Domain With 3 Servers - Primary Domain Controller, Root CA, and Subordinate CA
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> $VagrantVMPassword = ConvertTo-SecureString 'vagrant' -AsPlainText -Force
        PS C:\Users\zeroadmin> $VagrantVMAdminCreds = [pscredential]::new("vagrant",$VagrantVMPassword)
        PS C:\Users\zeroadmin> $DomainAdminCreds = [pscredential]::new("alpha\alphaadmin",$(Read-Host 'Enter Passsword' -AsSecureString))
        Enter Passsword: ************
        PS C:\Users\zeroadmin> $LocalAdminAccountCreds = [pscredential]::new("Administrator",$(Read-Host 'Enter Passsword' -AsSecureString))
        Enter Passsword: **************
        PS C:\Users\zeroadmin> $CreateTwoTierPKISplatParams = @{
        >> CreateNewVMs                            = $True
        >> VMStorageDirectory                      = "H:\VirtualMachines"
        >> NewDomain                               = "alpha.lab"
        >> PSRemotingCredentials                   = $VagrantVMAdminCreds
        >> DomainAdminCredentials                  = $DomainAdminCreds
        >> LocalAdministratorAccountCredentials    = $LocalAdminAccountCreds
        >> }
        PS C:\Users\zeroadmin> Create-TwoTierPKI @CreateTwoTierPKISplatParams

    .EXAMPLE
        # Create a New Domain With 2 Servers - Primary Domain Controller (which will also be the Root CA), and Subordinate CA
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> $VagrantVMPassword = ConvertTo-SecureString 'vagrant' -AsPlainText -Force
        PS C:\Users\zeroadmin> $VagrantVMAdminCreds = [pscredential]::new("vagrant",$VagrantVMPassword)
        PS C:\Users\zeroadmin> $DomainAdminCreds = [pscredential]::new("alpha\alphaadmin",$(Read-Host 'Enter Passsword' -AsSecureString))
        Enter Passsword: ************
        PS C:\Users\zeroadmin> $LocalAdminAccountCreds = [pscredential]::new("Administrator",$(Read-Host 'Enter Passsword' -AsSecureString))
        Enter Passsword: **************
        PS C:\Users\zeroadmin> $CreateTwoTierPKISplatParams = @{
        >> CreateNewVMs                            = $True
        >> VMStorageDirectory                      = "H:\VirtualMachines"
        >> NewDomain                               = "alpha.lab"
        >> PSRemotingCredentials                   = $VagrantVMAdminCreds
        >> DomainAdminCredentials                  = $DomainAdminCreds
        >> LocalAdministratorAccountCredentials    = $LocalAdminAccountCreds
        >> SkipHyperVInstallCheck                  = $True
        >> DCIsRootCA                              = $True
        >> }
        PS C:\Users\zeroadmin> Create-TwoTierPKI @CreateTwoTierPKISplatParams

    .EXAMPLE
        # Add Two-Tier PKI to your Existing Domain
        # IMPORTANT NOTE: If you can't resolve the -ExistingDomain from the localhost, be sure to use the -IPOfServerToBeDomainController
        # parameter with the IP Address of an EXISTING Domain Controller on the domain specified by -ExistingDomain

        PS C:\Users\zeroadmin> $VagrantVMPassword = ConvertTo-SecureString 'vagrant' -AsPlainText -Force
        PS C:\Users\zeroadmin> $VagrantVMAdminCreds = [pscredential]::new("vagrant",$VagrantVMPassword)
        PS C:\Users\zeroadmin> $DomainAdminCreds = [pscredential]::new("alpha\alphaadmin",$(Read-Host 'Enter Passsword' -AsSecureString))
        Enter Passsword: ************
        PS C:\Users\zeroadmin> $LocalAdminAccountCreds = [pscredential]::new("Administrator",$(Read-Host 'Enter Passsword' -AsSecureString))
        Enter Passsword: **************
        PS C:\Users\zeroadmin> $CreateTwoTierPKISplatParams = @{
        >> CreateNewVMs                            = $True
        >> VMStorageDirectory                      = "H:\VirtualMachines"
        >> ExistingDomain                          = "alpha.lab"
        >> PSRemotingCredentials                   = $VagrantVMAdminCreds
        >> DomainAdminCredentials                  = $DomainAdminCreds
        >> }
        PS C:\Users\zeroadmin> Create-TwoTierPKI @CreateTwoTierPKISplatParams


#>
function Create-TwoTierPKICFSSL {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$False)]
        [switch]$CreateNewVMs,

        [Parameter(Mandatory=$False)]
        [string]$VMStorageDirectory,

        [Parameter(Mandatory=$False)]
        [string]$Windows2016VagrantBox = "jborean93/WindowsServer2016", # Alternate - StefanScherer/windows_2016

        [Parameter(Mandatory=$False)]
        [ValidatePattern("^([a-z0-9]+(-[a-z0-9]+)*\.)+([a-z]){2,}$")]
        [string]$NewDomain,

        [Parameter(Mandatory=$True)]
        [pscredential]$DomainAdminCredentials, # If creating a New Domain, this will be a New Domain Account

        [Parameter(Mandatory=$False)]
        [pscredential]$LocalAdministratorAccountCredentials,

        [Parameter(Mandatory=$False)]
        [pscredential]$PSRemotingCredentials, # These credentials must grant access to ALL Servers

        [Parameter(Mandatory=$False)]
        [string]$ExistingDomain,

        [Parameter(Mandatory=$False)]
        [switch]$DCIsRootCA,

        [Parameter(Mandatory=$False)]
        [string]$IPofServerToBeDomainController,

        [Parameter(Mandatory=$False)]
        [string]$IPofServerToBeRootCA,

        [Parameter(Mandatory=$False)]
        [string]$IPofServerToBeSubCA,

        [Parameter(Mandatory=$False)]
        [switch]$SkipHyperVInstallCheck
    )

    "placeholder"
}


<#
    .SYNOPSIS
        This function downloads the specified Vagrant Virtual Machine from https://app.vagrantup.com
        and deploys it to the Hyper-V hypervisor on the Local Host. If Hyper-V is not installed on the
        Local Host, it will be installed.

        IMPORTANT NOTE: Before using this function, you MUST uninstall any other Virtualization Software
        on the Local Windows Host (VirtualBox, VMWare, etc)

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER VagrantBox
        This parameter is MANDATORY.

        This parameter takes a string that represents the name of the Vagrant Box VM that you would like
        deployed to Hyper-V. Use https://app.vagrantup.com to search for Vagrant Boxes. One of my favorite
        VMs is 'centos/7'.

    .PARAMETER BoxFilePath
        This parameter is OPTIONAL.

        This parameter takes a string that represents the full path to a .box file on the filesystem.

        Do NOT use this parameter with the -DecompressedBoxFileDirectory parameter.

    .PARAMETER DecompressedBoxDirectory
        This parameter is OPTIONAL.

        This parameter takes a string that represents the full path to a directory that contains the contents
        of a decompressed .box file.

        Do NOT use this parameter with the -BoxFilePath parameter.

    .PARAMETER VagrantProvider
        This parameter is MANDATORY.

        This parameter currently takes only one value: 'hyperv'. At some point, this function will be able
        to deploy VMs to hypervisors other than Hyper-V, which is why it still exists as a parameter.

    .PARAMETER VMName
        This parameter is MANDATORY.

        This parameter takes a string that represents the name that you would like your new VM to have in Hyper-V.

    .PARAMETER VMDestinationDirectory
        This parameter is MANDATORY.

        This parameter takes a string that rperesents the full path to the directory that will contain ALL
        files related to the new Hyper-V VM (VHDs, SnapShots, Configuration Files, etc). Make sure you
        pick a directory on a drive that has enough space.

        IMPORTANT NOTE: Vagrant Boxes are downloaded in a compressed format. A good rule of thumb is that
        you'll need approximately QUADRUPLE the amount of space on the drive in order to decompress and
        deploy the Vagrant VM. This is especially true with Windows Vagrant Box VMs.

    .PARAMETER CopyDecompressedDirectory
        This parameter is OPTIONAL.

        This parameter is a switch. If used, the director containing the contents of the decompressed .box
        file will be COPIED as opposed to MOVED to the location specified by the -VMDestinationDirectory
        parameter.

    .PARAMETER Memory
        This parameter is OPTIONAL, however, its default value is 2048.

        This parameter takes an integer that represents the amount of memory in MB to
        allocate to the VM. Valid values are: 1024,2048,4096,8192,12288,16384,32768

    .PARAMETER CPUs
        This parameter is OPTIONAL, hwoever, its default value is 1.

        This parameter takes an integer that represents the number of vCPUs to allocate
        to the VM. Valid values are : 1,2

    .PARAMETER Generation
        This parameter is OPTIONAL, however, if the vagrant VM is Linux, it will default to 1, and if it is
        Windows, it will default to 2.

        This parameter takes an integer that represents the Hyper-V VM Generation of the Vagrant Box.
        Valid values are : 1,2

    .PARAMETER TemporaryDownloadDirectory
        This parameter is OPTIONAL, but is defacto MANDATORY and defaults to "$HOME\Downloads".

        This parameter takes a string that represents the full path to the directory that will be used
        for Vagrant decompression operations. After everything is decompressed, the resulting files
        will be moved to the directory specified by the -VMDestinationDirectory parameter.

    .PARAMETER AllowRestarts
        This parameter is OPTIONAL.

        This parameter is a switch. If used, and if Hyper-V is NOT already installed on the Local
        Host, then Hyper-V will be installed and the Local Host will be restarted after installation.

    .PARAMETER SkipPreDownloadCheck
        This parameter is OPTIONAL.

        This parameter is a switch. By default, this function checks to see if the destination drive
        has enough space before downloading the Vagrant Box VM. It also ensures there is at least 2GB
        of free space on the drive AFTER the Vagrant Box is downloaded (otherwise, it will not download the
        Vagrant Box). Use this switch if you would like to attempt to download and deploy the Vagrant Box
        VM regardless of how much space is available on the storage drive.

    .PARAMETER SkipHyperVInstallCheck
        This parameter is OPTIONAL.

        This parameter is a switch. By default, this function checks to see if Hyper-V is installed on the
        Local Host. This takes about 10 seconds. If you would like to skip this check, use this switch.

    .PARAMETER Repository
        This parameter is OPTIONAL.

        This parameter currently only takes the string 'Vagrant', which refers to the default Vagrant Box
        Repository at https://app.vagrantup.com. Other Vagrant Repositories exist. At some point, this
        function will be updated to include those other repositories.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> $DeployHyperVVagrantBoxSplatParams = @{
            VagrantBox              = "centos/7"
            VagrantProvider         = "hyperv"
            VMName                  = "CentOS7Vault"
            VMDestinationDirectory  = "H:\HyperV-VMs"
        }
        PS C:\Users\zeroadmin> $DeployVaultServerVMResult = Deploy-HyperVVagrantBoxManually @DeployHyperVVagrantBoxSplatParams
        
#>
function Deploy-HyperVVagrantBoxManually {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidatePattern("[\w]+\/[\w]+")]
        [string]$VagrantBox,

        [Parameter(Mandatory=$False)]
        [string]$BoxFilePath,

        [Parameter(Mandatory=$False)]
        [string]$DecompressedBoxDirectory,

        [Parameter(Mandatory=$True)]
        [ValidateSet("hyperv")]
        [string]$VagrantProvider,

        [Parameter(Mandatory=$True)]
        [string]$VMName,

        [Parameter(Mandatory=$True)]
        [string]$VMDestinationDirectory,

        [Parameter(Mandatory=$False)]
        [switch]$CopyDecompressedDirectory,

        [Parameter(Mandatory=$True)]
        [ValidateSet(1024,2048,4096,8192,12288,16384,32768)]
        [int]$Memory,

        [Parameter(Mandatory=$True)]
        [ValidateSet(1,2)]
        [int]$CPUs,

        [Parameter(Mandatory=$False)]
        [ValidateSet(1,2)]
        [int]$Generation,

        [Parameter(Mandatory=$False)]
        [string]$TemporaryDownloadDirectory,

        [Parameter(Mandatory=$False)]
        [switch]$AllowRestarts,

        [Parameter(Mandatory=$False)]
        [switch]$SkipPreDownloadCheck,

        [Parameter(Mandatory=$False)]
        [switch]$SkipHyperVInstallCheck,

        [Parameter(Mandatory=$False)]
        [ValidateSet("Vagrant","AWS")]
        [string]$Repository
    )

    #region >> Variable/Parameter Transforms and PreRun Prep

    if (!$SkipHyperVInstallCheck) {
        # Check to Make Sure Hyper-V is installed
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

    if (!$(Test-Path $VMDestinationDirectory)) {
        Write-Error "The path '$VMDestinationDirectory' does not exist! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($($VMDestinationDirectory | Split-Path -Leaf) -eq $VMName) {
        $VMDestinationDirectory = $VMDestinationDirectory | Split-Path -Parent
    }

    # Make sure $VMDestinationDirectory is a local hard drive
    if ([bool]$(Get-Item $VMDestinationDirectory).LinkType) {
        $DestDirDriveLetter = $(Get-Item $VMDestinationDirectory).Target[0].Substring(0,1)
    }
    else {
        $DestDirDriveLetter = $VMDestinationDirectory.Substring(0,1)
    }
    $DownloadDirDriveInfo = [System.IO.DriveInfo]::GetDrives() | Where-Object {
        $_.Name -eq $($DestDirDriveLetter + ':\') -and $_.DriveType -eq "Fixed"
    }
    if (!$DownloadDirDriveInfo) {
        Write-Error "The '$($DestDirDriveLetter + ':\')' drive is NOT a local hard drive! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$TemporaryDownloadDirectory) {
        $TemporaryDownloadDirectory = "$VMDestinationDirectory\BoxDownloads"
    }

    if ($PSBoundParameters['BoxFilePath'] -and $PSBoundParameters['DecompressedBoxDirectory']) {
        Write-Error "Please use *either* the -BoxFilePath *or* the -DecompressedBoxDirectory parameter (not both)! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($PSBoundParameters['DecompressedBoxDirectory']) {
        if (!$($DecompressedBoxDirectory -match $($VagrantBox -split '/')[0])) {
            $ErrMsg = "The directory '$DecompressedBoxDirectory' does not match the VagrantBox name " +
            "'$VagrantBox'! If it is, in fact, a valid decompressed .box file directory, please include " +
            "'$($($VagrantBox -split'/')[0])' in the directory name. Halting!"
            Write-Error $ErrMsg
            $global:FunctionResult = "1"
            return
        }
        if ($(Get-ChildItem -Path $DecompressedBoxDirectory -File).Name -notcontains "VagrantFile") {
            Write-Error "The directory '$DecompressedBoxDirectory' does not a contain a file called 'VagrantFile'! Is it a valid decompressed .box file directory? Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    
    if (![bool]$(Get-Module Hyper-V)) {
        try {
            if ($PSVersionTable.PSEdition -eq "Core") {
                Import-WinModule Hyper-V -ErrorAction Stop
            }
            else {
                Import-Module Hyper-V -ErrorAction Stop
            }
        }
        catch {
            if ($PSVersionTable.PSEdition -eq "Core") {
                $HyperVModuleManifestPaths = Invoke-WinCommand -ScriptBlock {$(Get-Module -ListAvailable -Name Hyper-V).Path}
            }
            else {
                # Using full path to Dism Module Manifest because sometimes there are issues with just 'Import-Module Dism'
                $HyperVModuleManifestPaths = $(Get-Module -ListAvailable -Name Hyper-V).Path
            }

            foreach ($MMPath in $HyperVModuleManifestPaths) {
                try {
                    if ($PSVersionTable.PSEdition -eq "Core") {
                        Import-WinModule $MMPath -ErrorAction Stop
                        break
                    }
                    else {
                        Import-Module $MMPath -ErrorAction Stop
                        break
                    }
                }
                catch {
                    Write-Verbose "Unable to import $MMPath..."
                }
            }
        }
    }

    try {
        $VMs = Get-VM
    }
    catch {
        Write-Error "Problem with the 'Get-VM' cmdlet! Is Hyper-V installed? Halting!"
        $global:FunctionResult = "1"
        return
    }

    try {
        $NewVMName = NewUniqueString -ArrayOfStrings $VMs.Name -PossibleNewUniqueString $VMName
        $VMFinalLocationDir = "$VMDestinationDirectory\$NewVMName"    
        if (!$(Test-Path $VMDestinationDirectory)) {
            $null = New-Item -ItemType Directory -Path $VMDestinationDirectory
        }
        if (!$(Test-Path $TemporaryDownloadDirectory)) {
            $null = New-Item -ItemType Directory -Path $TemporaryDownloadDirectory
        }
        if (!$(Test-Path $VMFinalLocationDir)) {
            $null = New-Item -ItemType Directory -Path $VMFinalLocationDir
        }
        if ($(Get-ChildItem -Path $VMFinalLocationDir).Count -gt 0) {
            throw "The directory '$VMFinalLocationDir' is not empty! Do you already have a VM deployed with the same name? Halting!"
        }
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    # Set some other variables that we will need
    $PrimaryIfIndex = $(Get-CimInstance Win32_IP4RouteTable | Where-Object {
        $_.Destination -eq '0.0.0.0' -and $_.Mask -eq '0.0.0.0'
    } | Sort-Object Metric1)[0].InterfaceIndex
    $NicInfo = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object {$_.InterfaceIndex -eq $PrimaryIfIndex}
    $PrimaryIP = $NicInfo.IPAddress | Where-Object {TestIsValidIPAddress -IPAddress $_}

    if ([Environment]::OSVersion.Version -lt [version]"10.0.17063") {
        if (![bool]$(Get-Command bsdtar -ErrorAction SilentlyContinue)) {
            # Download bsdtar from latest MSYS2 available on pldmgg github
            $WindowsNativeLinuxUtilsZipUrl = "https://github.com/pldmgg/WindowsNativeLinuxUtils/raw/master/MSYS2_20161025/bsdtar.zip"
            Invoke-WebRequest -Uri $WindowsNativeLinuxUtilsZipUrl -OutFile "$HOME\Downloads\bsdtar.zip"
            Expand-Archive -Path "$HOME\Downloads\bsdtar.zip" -DestinationPath "$HOME\Downloads" -Force
            $BsdTarDirectory = "$HOME\Downloads\bsdtar"

            if ($($env:Path -split ";") -notcontains $BsdTarDirectory) {
                if ($env:Path[-1] -eq ";") {
                    $env:Path = "$env:Path$BsdTarDirectory"
                }
                else {
                    $env:Path = "$env:Path;$BsdTarDirectory"
                }
            }
        }

        $TarCmd = "bsdtar"
    }
    else {
        $TarCmd = "tar"
    }

    #endregion >> Variable/Parameter Transforms and PreRun Prep


    #region >> Main Body

    if (!$BoxFilePath -and !$DecompressedBoxDirectory) {
        $GetVagrantBoxSplatParams = @{
            VagrantBox          = $VagrantBox
            VagrantProvider     = $VagrantProvider
            DownloadDirectory   = $TemporaryDownloadDirectory
            ErrorAction         = "SilentlyContinue"
            ErrorVariable       = "GVBMDErr"
        }
        if ($Repository) {
            $GetVagrantBoxSplatParams.Add("Repository",$Repository)
        }

        try {
            $DownloadedBoxFilePath = Get-VagrantBoxManualDownload @GetVagrantBoxSplatParams
            if (!$DownloadedBoxFilePath) {throw "The Get-VagrantBoxManualDownload function failed! Halting!"}
        }
        catch {
            Write-Error $_
            Write-Host "Errors for the Get-VagrantBoxManualDownload function are as follows:"
            Write-Error $($GVBMDErr | Out-String)
            if ($($_ | Out-String) -eq $null -and $($GVBMDErr | Out-String) -eq $null) {
                Write-Error "The Get-VagrantBoxManualDownload function failed to download the .box file!"
            }
            $global:FunctionResult = "1"
            return
        }
    
        $BoxFilePath = $DownloadedBoxFilePath
    }

    if ($BoxFilePath) {
        if (!$(Test-Path $BoxFilePath)) {
            Write-Error "The path $BoxFilePath was not found! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if (!$DecompressedBoxDirectory) {
        $DownloadedVMDir = "$TemporaryDownloadDirectory\$NewVMName"
        if (!$(Test-Path $DownloadedVMDir)) {
            $null = New-Item -ItemType Directory -Path $DownloadedVMDir
        }
        
        # Extract the .box File
        Push-Location $DownloadedVMDir

        Write-Host "Checking file lock of .box file..."
        if ($PSVersionTable.PSEdition -eq "Core") {
            # Make sure the PSSession Type Accelerator exists
            $TypeAccelerators = [psobject].Assembly.GetType("System.Management.Automation.TypeAccelerators")::get
            if ($TypeAccelerators.Name -notcontains "PSSession") {
                [PowerShell].Assembly.GetType("System.Management.Automation.TypeAccelerators")::Add("PSSession","System.Management.Automation.Runspaces.PSSession")
            }
            
            $Module = Get-Module MiniLab
            # NOTE: The below $FunctionsForSBUse is loaded when the MiniLab Module is imported
            [System.Collections.ArrayList]$ArgsToPass = @()
            $null = $ArgsToPass.Add($BoxFilePath)
            foreach ($FuncString in $script:FunctionsForSBUse) {$null = $ArgsToPass.Add($FuncString)}

            $FileLockBool = Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                $args[1..$($args.Count-1)] | foreach {Invoke-Expression $_}
                [bool]$(GetFileLockProcess -FilePath $args[0] -ErrorAction SilentlyContinue)
            } -ArgumentList $ArgsToPass
            
            while ($FileLockBool) {
                Write-Host "$BoxFilePath is currently being used by another process...Waiting for it to become available"
                Start-Sleep -Seconds 5
            }
        }
        else {
            while ([bool]$(GetFileLockProcess -FilePath $BoxFilePath -ErrorAction SilentlyContinue)) {
                Write-Host "$BoxFilePath is currently being used by another process...Waiting for it to become available"
                Start-Sleep -Seconds 5
            }
        }

        try {
            Write-Host "Extracting .box file..."
            
            $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
            $ProcessInfo.WorkingDirectory = $DownloadedVMDir
            $ProcessInfo.FileName = $TarCmd
            $ProcessInfo.RedirectStandardError = $true
            $ProcessInfo.RedirectStandardOutput = $true
            $ProcessInfo.UseShellExecute = $false
            $ProcessInfo.Arguments = "-xzvf $BoxFilePath"
            $Process = New-Object System.Diagnostics.Process
            $Process.StartInfo = $ProcessInfo
            $Process.Start() | Out-Null
            # Below $FinishedInAlottedTime returns boolean true/false
            # 1800000 ms is 30 minutes
            $FinishedInAlottedTime = $Process.WaitForExit(1800000)
            if (!$FinishedInAlottedTime) {
                $Process.Kill()
            }
            $stdout = $Process.StandardOutput.ReadToEnd()
            $stderr = $Process.StandardError.ReadToEnd()
            $AllOutput = $stdout + $stderr

            if ($stderr) {
                if ($stderr -match "failed") {
                    throw $stderr
                }
                else {
                    Write-Warning $stderr
                }
            }
        }
        catch {
            Write-Error $_
            #Remove-Item $BoxFilePath -Force
            $global:FunctionResult = "1"
            return
        }
        Pop-Location

        $DecompressedBoxDirectory = $DownloadedVMDir
    }

    if ($DecompressedBoxDirectory) {
        if (!$(Test-Path $DecompressedBoxDirectory)) {
            Write-Error "The path $DecompressedBoxDirectory was not found! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    try {
        if ($CopyDecompressedDirectory) {
            Write-Host "Copying decompressed VM from '$DecompressedBoxDirectory' to '$VMDestinationDirectory\$NewVMName'..."
            $ItemsToCopy = Get-ChildItem $DecompressedBoxDirectory
            $ItemsToCopy | foreach {Copy-Item -Path $_.FullName -Recurse -Destination "$VMDestinationDirectory\$NewVMName" -Force -ErrorAction SilentlyContinue}
        }
        else {
            Write-Host "Moving decompressed VM from '$DecompressedBoxDirectory' to '$VMDestinationDirectory'..."
            if (Test-Path "$VMDestinationDirectory\$NewVMName") {
                Remove-Item -Path "$VMDestinationDirectory\$NewVMName" -Recurse -Force
            }
            Move-Item -Path $DecompressedBoxDirectory -Destination $VMDestinationDirectory -Force -ErrorAction Stop

            if ("$VMDestinationDirectory\$($DecompressedBoxDirectory | Split-Path -Leaf)" -ne "$VMDestinationDirectory\$NewVMName") {
                Rename-Item -Path "$VMDestinationDirectory\$($DecompressedBoxDirectory | Split-Path -Leaf)" -NewName $NewVMName
            }
        }

        # Determine the External vSwitch that is associated with the Host Machine's Primary IP
        $PrimaryIfIndex = $(Get-CimInstance Win32_IP4RouteTable | Where-Object {
            $_.Destination -eq '0.0.0.0' -and $_.Mask -eq '0.0.0.0'
        } | Sort-Object Metric1)[0].InterfaceIndex
        $NicInfo = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object {$_.InterfaceIndex -eq $PrimaryIfIndex}
        $PrimaryIP = $NicInfo.IPAddress | Where-Object {TestIsValidIPAddress -IPAddress $_}
        $PrimaryInterfaceAlias = $(Get-CimInstance Win32_NetworkAdapter | Where-Object {$_.InterfaceIndex -eq $PrimaryIfIndex}).NetConnectionId

        $ExternalvSwitches = Get-VMSwitch -SwitchType External
        if ($ExternalvSwitches.Count -gt 1) {
            foreach ($vSwitchName in $ExternalvSwitches.Name) {
                $AllRelatedvSwitchInfo = GetvSwitchAllRelatedInfo -vSwitchName $vSwitchName -WarningAction SilentlyContinue
                if ($($NicInfo.MacAddress -replace ":","") -eq $AllRelatedvSwitchInfo.MacAddress) {
                    $vSwitchToUse = $AllRelatedvSwitchInfo.BasicvSwitchInfo
                }
            }
        }
        elseif ($ExternalvSwitches.Count -eq 0) {
            $null = New-VMSwitch -Name "ToExternal" -NetAdapterName $PrimaryInterfaceAlias
            $ExternalSwitchCreated = $True
            $vSwitchToUse = Get-VMSwitch -Name "ToExternal"
        }
        else {
            $vSwitchToUse = $ExternalvSwitches[0]
        }

        # Instead of actually importing the VM, it's easier (and more reliable) to just create a new one using the existing
        # .vhd/.vhdx so we don't have to deal with potential Hyper-V Version Incompatibilities
        $SwitchName = $vSwitchToUse.Name

        if (!$Generation) {
            if ($VagrantBox -match "Win|Windows") {
                $VMGen = 2
            }
            else {
                $VMGen = 1
            }
        }
        else {
            $VMGen = $Generation
        }

        # Create the NEW VM
        $NewTempVMParams = @{
            VMName              = $NewVMName
            SwitchName          = $SwitchName
            VMGen               = $VMGen
            Memory              = $Memory
            CPUs                = $CPUs
            VhdPathOverride     = $(Get-ChildItem -Path $VMFinalLocationDir -Recurse -File | Where-Object {$_ -match "\.vhd$|\.vhdx$"})[0].FullName
        }
        Write-Host "Creating VM..."
        $CreateVMOutput = Manage-HyperVVM @NewTempVMParams -Create
        
        if ($PSVersionTable.PSEdition -eq "Core") {
            [System.Collections.ArrayList]$ArgsToPass = @()
            $null = $ArgsToPass.Add($VMDestinationDirectory)
            foreach ($FuncString in $script:FunctionsForSBUse) {$null = $ArgsToPass.Add($FuncString)}

            $FixPermissionsResult = Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                $args[1..$($args.Count-1)] | foreach {Invoke-Expression $_}
                FixNTVirtualMachinesPerms -DirectoryPath $args[0]
            } -ArgumentList $ArgsToPass
        }
        else {
            FixNTVirtualMachinesPerms -DirectoryPath $VMDestinationDirectory
        }

        Write-Host "Starting VM..."
        #Start-VM -Name $NewVMName
        $StartVMOutput = Manage-HyperVVM -VMName $NewVMName -Start
    }
    catch {
        Write-Error $_
        
        # Cleanup
        #Remove-Item $BoxFilePath -Force
        <#
        if (Test-Path $DownloadedVMDir) {
            Remove-Item $DownloadedVMDir -Recurse -Force
        }
        
        if ($(Get-VM).Name -contains $NewVMName) {
            $null = Manage-HyperVVM -VMName $NewVMname -Destroy

            if (Test-Path $VMFinalLocationDir) {
                Remove-Item $VMFinalLocationDir -Recurse -Force
            }
        }
        if ($ExternalSwitchCreated) {
            Remove-VMSwitch "ToExternal" -Force -ErrorAction SilentlyContinue
        }
        #>

        $global:FunctionResult = "1"
        return
    }

    # Wait for up to 30 minutes for the new VM to report its IP Address
    $NewVMIP = $(Get-VMNetworkAdapter -VMName $NewVMName).IPAddresses | Where-Object {TestIsValidIPAddress -IPAddress $_}
    $Counter = 0
    while (!$NewVMIP -and $Counter -le 30) {
        Write-Host "Waiting for VM $NewVMName to report its IP Address..."
        Start-Sleep -Seconds 60
        $NewVMIP = $(Get-VMNetworkAdapter -VMName $NewVMName).IPAddresses | Where-Object {TestIsValidIPAddress -IPAddress $_}
        $Counter++
    }
    if (!$NewVMIP) {
        $NewVMIP = "<$NewVMName`IPAddress>"
    }

    if ($VagrantBox -notmatch "Win|Windows") {
        if (!$(Test-Path "$HOME\.ssh")) {
            New-Item -ItemType Directory -Path "$HOME\.ssh"
        }

        $VagrantKeyFilename = "vagrant_unsecure_key"
        if (!$(Test-Path "$HOME\.ssh\$VagrantKeyFilename")) {
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/hashicorp/vagrant/master/keys/vagrant" -OutFile "$HOME\.ssh\$VagrantKeyFilename"
        }
        if (!$(Test-Path "$HOME\.ssh\$VagrantKeyFilename.pub")) {
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/hashicorp/vagrant/master/keys/vagrant.pub" -OutFile "$HOME\.ssh\$VagrantKeyFilename.pub"
        }

        if (!$(Test-Path "$HOME\.ssh\$VagrantKeyFilename")) {
            Write-Warning "There was a problem downloading the Unsecure Vagrant Private Key! You must use the Hyper-V Console with username/password vagrant/vagrant!"
        }
        if (!$(Test-Path "$HOME\.ssh\$VagrantKeyFilename.pub")) {
            Write-Warning "There was a problem downloading the Unsecure Vagrant Public Key! You must use the Hyper-V Console with username/password vagrant/vagrant!"
        }
        
        Write-Host "To login to the Vagrant VM, use 'ssh -i `"$HOME\.ssh\$VagrantKeyFilename`" vagrant@$NewVMIP' OR use the Hyper-V Console GUI with username/password vagrant/vagrant"
    }

    $Output = @{
        VMName                  = $NewVMName
        VMIPAddress             = $NewVMIP
        CreateVMOutput          = $CreateVMOutput
        StartVMOutput           = $StartVMOutput
        BoxFileLocation         = $BoxFilePath
        HyperVVMLocation        = $VMDestinationDirectory
        ExternalSwitchCreated   = if ($ExternalSwitchCreated) {$True} else {$False}
    }
    if ($MoveDecompressedDir) {
        $Output.Add("DecompressedBoxFileLocation",$DecompressedBoxFileLocation.FullName)
    }

    [pscustomobject]$Output

    #endregion >> Main Body
}


<#
    .SYNOPSIS
        This script/function requests and receives a New Certificate from your Windows-based Issuing Certificate Authority.

        When used in conjunction with the Generate-CertTemplate.ps1 script/function, all needs can be satisfied.
        (See: https://github.com/pldmgg/misc-powershell/blob/master/Generate-CertTemplate.ps1)

        IMPORTANT NOTE: By running the function without any parameters, the user will be walked through several prompts. 
        This is the recommended way to use this function until the user feels comfortable with parameters mentioned below.

    .DESCRIPTION
        This function/script is split into the following sections (ctl-f to jump to each of these sections)
        - Libraries and Helper Functions (~Lines 1127-2794)
        - Initial Variable Definition and Validation (~Lines 2796-3274)
        - Writing the Certificate Request Config File (~Lines 3276-3490)
        - Generate Certificate Request, Submit to Issuing Certificate Authority, and Recieve Response (~Lines 3492-END)

        DEPENDENCIES
            OPTIONAL DEPENDENCIES (One of the two will be required depending on if you use the ADCS Website)
            1) RSAT (Windows Server Feature) - If you're not using the ADCS Website, then the Get-ADObject cmdlet is used for various purposes. This cmdlet
            is available only if RSAT is installed on the Windows Server.

            2) Win32 OpenSSL - If $UseOpenSSL = "Yes", the script/function depends on the latest Win32 OpenSSL binary that can be found here:
            https://indy.fulgan.com/SSL/
            Simply extract the (32-bit) zip and place the directory on your filesystem in a location to be referenced by the parameter $PathToWin32OpenSSL.

            IMPORTANT NOTE 2: The above third-party Win32 OpenSSL binary is referenced by OpenSSL.org here:
            https://wiki.openssl.org/index.php/Binaries

    .PARAMETER CertGenWorking
        This parameter is MANDATORY.

        This parameter takes a string that represents the full path to a directory that will contain all output
        files.

    .PARAMETER BasisTemplate
        This parameter is OPTIONAL, but becomes MANDATORY if the -IntendedPurposeValues parameter is not used.

        This parameter takes a string that represents either the CN or the displayName of the Certificate Template that you are 
        basing this New Certificate on.
        
        IMPORTANT NOTE: If you are requesting the new certificate via the ADCS Web Enrollment Website, the
        Certificate Template will ONLY appear in the Certificate Template drop-down (which makes it a valid option
        for this parameter) if msPKITemplateSchemaVersion is "2" or "1" AND pKIExpirationPeriod is 1 year or LESS. 
        See the Generate-CertTemplate.ps1 script/function for more details here:
        https://github.com/pldmgg/misc-powershell/blob/master/DueForRefactor/Generate-CertTemplate.ps1

    .PARAMETER CertificateCN
        This parameter is MANDATORY.

        This parameter takes a string that represents the name that you would like to give the New Certificate. This name will
        appear in the following locations:
            - "FriendlyName" field of the Certificate Request
            - "Friendly name" field the New Certificate itself
            - "Friendly Name" field when viewing the New Certificate in the Local Certificate Store
            - "Subject" field of the Certificate Request
            - "Subject" field on the New Certificate itself
            - "Issued To" field when viewing the New Certificate in the Local Certificate Store

    .PARAMETER CertificateRequestConfigFile
        This parameter is MANDATORY.

        This parameter takes a string that represents a file name to be used for the Certificate Request
        Configuration file to be submitted to the Issuing Certificate Authority. File extension should be .inf.

        A default value is supplied: "NewCertRequestConfig_$CertificateCN"+$(Get-Date -format 'dd-MMM-yyyy_HHmm')+".inf"

    .PARAMETER CertificateRequestFile
        This parameter is MANDATORY.

        This parameter takes a string that represents a file name to be used for the Certificate Request file to be submitted
        to the Issuing Certificate Authority. File extension should be .csr.

        A default value is supplied: "NewCertRequest_$CertificateCN"+$(Get-Date -format 'dd-MMM-yyyy_HHmm')+".csr"

    .PARAMETER CertFileOut
        This parameter is MANDATORY.

        This parameter takes a string that represents a file name to be used for the New Public Certificate received from the
        Issuing Certificate Authority. The file extension should be .cer.

        A default value is supplied: "NewCertificate_$CertificateCN"+$(Get-Date -format 'dd-MMM-yyyy_HHmm')+".cer"

    .PARAMETER CertificateChainOut
        This parameter is MANDATORY.

        This parameter takes a string that represents a file name to be used for the Chain of Public Certificates from 
        the New Public Certificate up to the Root Certificate Authority. File extension should be .p7b.

        A default value is supplied: "NewCertificateChain_$CertificateCN"+$(Get-Date -format 'dd-MMM-yyyy_HHmm')+".p7b"

        IMPORTANT NOTE: File extension will be .p7b even if format is actually PKCS10 (which should have extension .p10).
        This is to ensure that Microsoft Crypto Shell Extensions recognizes the file. (Some systems do not have .p10 associated
        with Crypto Shell Extensions by default, leading to confusion).

    .PARAMETER PFXFileOut
        This parameter is MANDATORY.

        This parameter takes a string that represents a file name to be used for the file containing both Public AND 
        Private Keys for the New Certificate. File extension should be .pfx.

        A default values is supplied: "NewCertificate_$CertificateCN"+$(Get-Date -format 'dd-MMM-yyyy_HHmm')+".pfx"

    .PARAMETER PFXPwdAsSecureString
        This parameter is OPTIONAL.

        This parameter takes a securestring.

        In order to export a .pfx file from the Local Certificate Store, a password must be supplied (or permissions based on user accounts 
        must be configured beforehand, but this is outside the scope of this script). 

        IMPORTANT NOTE: This same password is applied to $ProtectedPrivateKeyOut if OpenSSL is used to create
        Linux-compatible certificates in .pem format.

    .PARAMETER ADCSWebEnrollmentURL
        This parameter is OPTIONAL.

        This parameter takes a string that represents the URL for the ADCS Web Enrollment website.
        Example: https://pki.test.lab/certsrv

    .PARAMETER ADCSWebAuthType
        This parameter is OPTIONAL.

        This parameter takes one of two inputs:
        1) The string "Windows"; OR
        2) The string "Basic"

        The IIS Web Server hosting the ADCS Web Enrollment site can be configured to use Windows Authentication, Basic
        Authentication, or both. Use this parameter to specify either "Windows" or "Basic" authentication.

    .PARAMETER ADCSWebAuthUserName
        This parameter is OPTIONAL. Do NOT use this parameter if you are using the -ADCSWebCreds parameter.

        This parameter takes a string that represents a username with permission to access the ADCS Web Enrollment site.
        
        If $ADCSWebAuthType = "Basic", then INCLUDE the domain prefix as part of the username. 
        Example: test2\testadmin .

        If $ADCSWebAuthType = "Windows", then DO NOT INCLUDE the domain prefix as part of the username.
        Example: testadmin

        (NOTE: If you mix up the above username formatting, then the script will figure it out. This is more of an FYI.)

    .PARAMETER ADCSWebAuthPass
        This parameter is OPTIONAL. Do NOT use this parameter if you are using the -ADCSWebCreds parameter.

        This parameter takes a securestring.

        If $ADCSWebEnrollmentUrl is used, then this parameter becomes MANDATORY. Under this circumstance, if 
        this parameter is left blank, the user will be prompted for secure input. If using this script as part of a larger
        automated process, use a wrapper function to pass this parameter securely (this is outside the scope of this script).

    .PARAMETER ADCSWebCreds
        This parameter is OPTIONAL. Do NOT use this parameter if you are using the -ADCSWebAuthuserName and
        -ADCSWebAuthPass parameters.

        This parameter takes a PSCredential.

        IMPORTANT NOTE: When speicfying the UserName for the PSCredential, make sure the format adheres to the
        following:

        If $ADCSWebAuthType = "Basic", then INCLUDE the domain prefix as part of the username. 
        Example: test2\testadmin .

        If $ADCSWebAuthType = "Windows", then DO NOT INCLUDE the domain prefix as part of the username.
        Example: testadmin

        (NOTE: If you mix up the above username formatting, then the script will figure it out. This is more of an FYI.)

    .PARAMETER CertADCSWebResponseOutFile
        This parameter is MANDATORY.

        This parameter takes a string that represents a valid file path that will contain the HTTP response after
        submitting the Certificate Request via the ADCS Web Enrollment site.

        A default value is supplied: "NewCertificate_$CertificateCN"+"_ADCSWebResponse"+$(Get-Date -format 'dd-MMM-yyyy_HHmm')+".txt"

    .PARAMETER Organization
        This parameter is MANDATORY.

        This parameter takes a string that represents an Organization name. This will be added to "Subject" field in the
        Certificate.

    .PARAMETER OrganizationalUnit
        This parameter is MANDATORY.

        This parameter takes a string that represents an Organization's Department. This will be added to the "Subject" field
        in the Certificate.

    .PARAMETER Locality
        This parameter is MANDATORY.

        This parameter takes a string that represents a City. This will be added to the "Subject" field in the Certificate.

    .PARAMETER State
        This parameter is MANDATORY.

        This parameter takes a string that represents a State. This will be added to the "Subject" field in the Certificate.

    .PARAMETER Country
        This parameter is MANDATORY.

        This parameter takes a string that represents a Country. This will be added to the "Subject" field in the Certificate.

    .PARAMETER KeyLength
        This parameter is MANDATORY.

        This parameter takes a string representing a key length of either "2048" or "4096".

        A default value is supplied: 2048

        For more information, see:
        https://technet.microsoft.com/en-us/library/hh831574(v=ws.11).aspx

    .PARAMETER HashAlgorithmValue
        This parameter is MANDATORY.

        This parameter takes a string that must be one of the following values:
        "SHA1","SHA256","SHA384","SHA512","MD5","MD4","MD2"

        A default value is supplied: SHA256

        For more information, see:
        https://technet.microsoft.com/en-us/library/hh831574(v=ws.11).aspx

    .PARAMETER EncryptionAlgorithmValue
        This parameter is MANDATORY.

        This parameter takes a string representing an available encryption algorithm. Valid values:
        "AES","DES","3DES","RC2","RC4"

        A default value is supplied: AES

    .PARAMETER PrivateKeyExportableValue
        This parameter is MANDATORY.

        The parameter takes a string with one of two values: "True", "False"

        Setting the value to "True" means that the Private Key will be exportable.

        A default value is supplied: True

    .PARAMETER KeySpecValue
        This parameter is MANDATORY.

        The parameter takes a string that must be one of two values: "1", "2"

        A default value is supplied: 1

        For details about Key Spec Values, see: https://technet.microsoft.com/en-us/library/hh831574(v=ws.11).aspx

    .PARAMETER KeyUsageValue
        This parameter is MANDATORY.

        This parameter takes a string that represents a hexadecimal value.

        A defult value is supplied: 80

        For reference, here are some commonly used values -

        A valid value is the hex sum of one or more of following:
            CERT_DIGITAL_SIGNATURE_KEY_USAGE = 80
            CERT_NON_REPUDIATION_KEY_USAGE = 40
            CERT_KEY_ENCIPHERMENT_KEY_USAGE = 20
            CERT_DATA_ENCIPHERMENT_KEY_USAGE = 10
            CERT_KEY_AGREEMENT_KEY_USAGE = 8
            CERT_KEY_CERT_SIGN_KEY_USAGE = 4
            CERT_OFFLINE_CRL_SIGN_KEY_USAGE = 2
            CERT_CRL_SIGN_KEY_USAGE = 2
            CERT_ENCIPHER_ONLY_KEY_USAGE = 1
        
        Some Commonly Used Values:
            'c0' (i.e. 80+40)
            'a0' (i.e. 80+20)
            'f0' (i.e. 80+40+20+10)
            '30' (i.e. 20+10)
            '80'
        
        All Valid Values:
        "1","10","11","12","13","14","15","16","17","18","2","20","21","22","23","24","25","26","27","28","3","30","38","4","40",
        "41","42","43","44","45","46","47","48","5","50","58","6","60","68","7","70","78","8","80","81","82","83","84","85","86","87","88","9","90",
        "98","a","a0","a8","b","b0","b8","c","c0","c","8","d","d0","d8","e","e0","e8","f","f0","f8"

        For more information see: https://technet.microsoft.com/en-us/library/hh831574(v=ws.11).aspx

    .PARAMETER MachineKeySet
        This parameter is MANDATORY.

        This parameter takes a string that must be one of two values: "True", "False"

        A default value is provided: "False"

        If you would like the Private Key exported, use "False".

        If you are creating this certificate to be used in the User's security context (like for a developer
        to sign their code), use "False".
        
        If you are using this certificate for a service that runs in the Computer's security context (such as
        a Web Server, Domain Controller, etc) and DO NOT need the Private Key exported use "True".

        For more info, see: https://technet.microsoft.com/en-us/library/hh831574(v=ws.11).aspx

    .PARAMETER SecureEmail
        This parameter is MANDATORY.

        This parameter takes string that must be one of two values: "Yes", "No"
        
        A default value is provided: "No"

        If the New Certificate is going to be used to digitally sign and/or encrypt emails, this parameter
        should be set to "Yes".

    .PARAMETER UserProtected
        This parameter is MANDATORY.

        This parameter takes  a string that must be one of two values: "True", "False"

        A default value is provided: False

        If $MachineKeySet is set to "True", then $UserProtected MUST be set to "False". If $MachineKeySet is
        set to "False", then $UserProtected can be set to either "True" or "False". 

        If $UserProtected is set to "True", a CryptoAPI password window is displayed when the key is generated
        during the certificate request process. Once the key is protected with a password, you must enter this
        password every time the key is accessed.

        IMPORTANT NOTE: Do not set this parameter to "True" if you want this script/function to run unattended.

    .PARAMETER ProviderNameValue
        This parameter is MANDATORY.

        This parameter takes a string that represents the name of the Cryptographic Provider you would like to use for the 
        New Certificate.

        A default value is provided: "Microsoft RSA SChannel Cryptographic Provider"
        
        Valid values are as follows:
        "Microsoft Base Cryptographic Provider v1.0","Microsoft Base DSS and Diffie-Hellman Cryptographic Provider",
        "Microsoft Base DSS Cryptographic Provider","Microsoft Base Smart Card Crypto Provider",
        "Microsoft DH SChannel Cryptographic Provider","Microsoft Enhanced Cryptographic Provider v1.0",
        "Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider",
        "Microsoft Enhanced RSA and AES Cryptographic Provider","Microsoft RSA SChannel Cryptographic Provider",
        "Microsoft Strong Cryptographic Provider","Microsoft Software Key Storage Provider",
        "Microsoft Passport Key Storage Provider"
        
        For more details and a list of valid values, see:
        https://technet.microsoft.com/en-us/library/hh831574(v=ws.11).aspx

        WARNING: The Certificate Template that this New Certificate is based on (i.e. the value provided for the parameter 
        $BasisTemplate) COULD POTENTIALLY limit the availble Crypographic Provders for the Certificate Request. Make sure 
        the Cryptographic Provider you use is allowed by the Basis Certificate Template.

    .PARAMETER RequestTypeValue
        This parameter is MANDATORY.

        A default value is provided: PKCS10

        This parameter takes a string that indicates the format of the Certificate Request. Valid values are:
        "CMC", "PKCS10", "PKCS10-", "PKCS7"

        For more details, see: https://technet.microsoft.com/en-us/library/hh831574(v=ws.11).aspx

    .PARAMETER IntendedPurposeValues
        This parameter is OPTIONAL, but becomes MANDATORY if the -BasisTemplate parameter is not used.

        This parameter takes an array of strings. Valid values are as follows:

        "Code Signing","Document Signing","Client Authentication","Server Authentication",
        "Remote Desktop","Private Key Archival","Directory Service Email Replication","Key Recovery Agent",
        "OCSP Signing","Microsoft Trust List Signing","EFS","Secure E-mail","Enrollment Agent","Smart Card Logon",
        "File Recovery","IPSec IKE Intermediate","KDC Authentication","Windows Update",
        "Windows Third Party Application Component","Windows TCB Component","Windows Store",
        "Windows Software Extension Verification","Windows RT Verification","Windows Kits Component",
        "No OCSP Failover to CRL","Auto Update End Revocation","Auto Update CA Revocation","Revoked List Signer",
        "Protected Process Verification","Protected Process Light Verification","Platform Certificate",
        "Microsoft Publisher","Kernel Mode Code Signing","HAL Extension","Endorsement Key Certificate",
        "Early Launch Antimalware Driver","Dynamic Code Generator","DNS Server Trust","Document Encryption",
        "Disallowed List","Attestation Identity Key Certificate","System Health Authentication","CTL Usage",
        "IP Security End System","IP Security Tunnel Termination","IP Security User","Time Stamping",
        "Microsoft Time Stamping","Windows Hardware Driver Verification","Windows System Component Verification",
        "OEM Windows System Component Verification","Embedded Windows System Component Verification","Root List Signer",
        "Qualified Subordination","Key Recovery","Lifetime Signing","Key Pack Licenses","License Server Verification"

        IMPORTANT NOTE: If this parameter is not set by user, the Intended Purpose Value(s) of the
        Basis Certificate Template (i.e. $BasisTemplate) will be used. If $BasisTemplate is not provided, then
        the user will be prompted.

    .PARAMETER UseOpenSSL
        This parameter is MANDATORY.

        A default value is provided: "Yes"

        The parameter takes a string that must be one of two values: "Yes", "No"

        This parameter determines whether the Win32 OpenSSL binary should be used to extract
        certificates/keys in a format (.pem) readily used in Linux environments.

    .PARAMETER AllPublicKeysInChainOut
        This parameter is OPTIONAL. This parameter becomes MANDATORY if the parameter -UseOpenSSL is "Yes"

        This parameter takes a string that represents a file name. This file will contain all public certificates in
        the chain, from the New Certificate up to the Root Certificate Authority. File extension should be .pem

        A default value is provided: "NewCertificate_$CertificateCN"+"_all_public_keys_in_chain"+".pem"

    .PARAMETER ProtectedPrivateKeyOut
        This parameter is OPTIONAL. This parameter becomes MANDATORY if the parameter -UseOpenSSL is "Yes"

        This parameter takes a string that represents a file name. This file will contain the password-protected private
        key for the New Certificate. File extension should be .pem

        A default value is provided: "NewCertificate_$CertificateCN"+"_protected_private_key"+".pem"

    .PARAMETER UnProtectedPrivateKeyOut
        This parameter is OPTIONAL. This parameter becomes MANDATORY if the parameter -UseOpenSSL is "Yes"

        This parameter takes a string that represents a file name. This file will contain the raw private
        key for the New Certificate. File extension should be .key

        A default value is provided: "NewCertificate_$CertificateCN"+"_unprotected_private_key"+".key"

    .PARAMETER StripPrivateKeyOfPassword
        This parameter is OPTIONAL. This parameter becomes MANDATORY if the parameter -UseOpenSSL is "Yes"

        The parameter takes a string  that must be one of two values: "Yes", "No"

        This parameter removes the password from the file $ProtectedPrivateKeyOut and outputs the result to
        $UnProtectedPrivateKeyOut.

        A default value is provided: Yes

    .PARAMETER SANObjectsToAdd
        This parameter is OPTIONAL.

        This parameter takes an array of strings. All possible values are: 
        "DNS","Distinguished Name","URL","IP Address","Email","UPN","GUID"

    .PARAMETER DNSSANObjects
        This parameter is OPTIONAL. This parameter becomes MANDATORY if $SANObjectsToAdd includes "DNS".
        
        This parameter takes an array of strings. Each string represents a DNS address.
        Example: "www.fabrikam.com","www.contoso.com"

    .PARAMETER DistinguishedNameSANObjects
        This parameter is OPTIONAL. This parameter becomes MANDATORY if $SANObjectsToAdd includes "Distinguished Name".

        This parameter takes an array of strings. Each string represents an LDAP Path.
        Example: "CN=www01,OU=Web Servers,DC=fabrikam,DC=com","CN=www01,OU=Load Balancers,DC=fabrikam,DC=com"

    .PARAMETER URLSANObjects
        This parameter is OPTIONAL. This parameter becomes MANDATORY if $SANObjectsToAdd includes "URL".

        This parameter takes an array of string. Ech string represents a Url.
        Example: "http://www.fabrikam.com","http://www.contoso.com"

    .PARAMETER IPAddressSANObjects
        This parameter is OPTIONAL. This parameter becomes MANDATORY if $SANObjectsToAdd includes "IP Address".

        This parameter takes an array of strings. Each string represents an IP Address.
        Example: "172.31.10.13","192.168.2.125"

    .PARAMETER EmailSANObjects
        This parameter is OPTIONAL. This parameter becomes MANDATORY if $SANObjectsToAdd includes "Email".

        This paramter takes an array of strings. Each string should represent and Email Address.
        Example: "mike@fabrikam.com","hazem@fabrikam.com"

    .PARAMETER UPNSANObjects
        This parameter is OPTIONAL. This parameter becomes MANDATORY if $SANObjectsToAdd includes "UPN".

        This parameter takes an array of strings. Each string should represent a Principal Name object.
        Example: "mike@fabrikam.com","hazem@fabrikam.com"

    .PARAMETER GUIDSANObjects
        This parameter is OPTIONAL. This parameter becomes MANDATORY if $SANObjectsToAdd includes "GUID".

        This parameter takes an array of strings. Each string should represent a GUID.
        Example: "f7c3ac41-b8ce-4fb4-aa58-3d1dc0e36b39","g8D4ac41-b8ce-4fb4-aa58-3d1dc0e47c48"

    .PARAMETER CSRGenOnly
        This parameter is OPTIONAL.

        This parameter is a switch. If used, a Certificate Signing Request (CSR) will be created, but it
        will NOT be submitted to the Issuing Certificate Authority. This is useful for requesting
        certificates from non-Microsoft Certificate Authorities.

    .EXAMPLE
        # Scenario 1: No Parameters Provided
        # Executing the script/function without any parameters will ask for input on defacto mandatory parameters.
        # All other parameters will use default values which should be fine under the vast majority of circumstances.
        # De facto mandatory parameters are as follows:
        #   -CertGenWorking
        #   -BasisTemplate
        #   -CertificateCN
        #   -Organization
        #   -OrganizationalUnit
        #   -Locality
        #   -State
        #   -Country

        PS C:\Users\zeroadmin> Generate-Certificate

    .EXAMPLE
        # Scenario 2: Generate a Certificate for a Web Server From Machine on Same Domain As Your CA
        # Assuming you run this function from a workstation on the same Domain as your ADCS Certificate
        # Authorit(ies) under an account that has privileges to request new Certificates, do the following:

        PS C:\Users\zeroadmin> $GenCertSplatParams = @{
            CertGenWorking              = "$HOME\Downloads\temp"
            BasisTemplate               = "WebServer"
            CertificateCN               = "VaultServer"
            Organization                = "Boop Inc"
            OrganizationalUnit          = "DevOps"
            Locality                    = "Philadelphia"
            State                       = "PA"
            Country                     = "US"
            CertFileOut                 = "VaultServer.cer"
            PFXFileOut                  = "VaultServer.pfx"
            CertificateChainOut         = "VaultServerChain.p7b"
            AllPublicKeysInChainOut     = "VaultServerChain.pem"
            ProtectedPrivateKeyOut      = "VaultServerPwdProtectedPrivateKey.pem"
            UnProtectedPrivateKeyOut    = "VaultServerUnProtectedPrivateKey.pem"
            SANObjectsToAdd             = @("IP Address","DNS")
            IPAddressSANObjects         = @("$VaultServerIP","0.0.0.0")
            DNSSANObjects               = "VaultServer.zero.lab"
        }
        PS C:\Users\zeroadmin> $GenVaultCertResult = Generate-Certificate @GenCertSplatParams
        
    .EXAMPLE
        # Scenario 3: Generate a Certificate for a Web Server From Machine on a Different Domain Than Your CA
        # Assuming the ADCS Website is available -

        PS C:\Users\zeroadmin> $GenCertSplatParams = @{
            CertGenWorking              = "$HOME\Downloads\temp"
            BasisTemplate               = "WebServer"
            ADCSWebEnrollmentURL        = "https://pki.test2.lab/certsrv"
            ADCSWebAuthType             = "Windows"
            ADCSWebCreds                = [pscredential]::new("testadmin",$(Read-Host "Please enter the password for 'zeroadmin'" -AsSecureString))
            CertificateCN               = "VaultServer"
            Organization                = "Boop Inc"
            OrganizationalUnit          = "DevOps"
            Locality                    = "Philadelphia"
            State                       = "PA"
            Country                     = "US"
            CertFileOut                 = "VaultServer.cer"
            PFXFileOut                  = "VaultServer.pfx"
            CertificateChainOut         = "VaultServerChain.p7b"
            AllPublicKeysInChainOut     = "VaultServerChain.pem"
            ProtectedPrivateKeyOut      = "VaultServerPwdProtectedPrivateKey.pem"
            UnProtectedPrivateKeyOut    = "VaultServerUnProtectedPrivateKey.pem"
            SANObjectsToAdd             = @("IP Address","DNS")
            IPAddressSANObjects         = @("$VaultServerIP","0.0.0.0")
            DNSSANObjects               = "VaultServer.zero.lab"
        }
        PS C:\Users\zeroadmin> $GenVaultCertResult = Generate-Certificate @GenCertSplatParams

    .OUTPUTS
        All outputs are written to the $CertGenWorking directory specified by the user.

        ALWAYS GENERATED
        The following outputs are ALWAYS generated by this function/script, regardless of optional parameters: 
            - A Certificate Request Configuration File (with .inf file extension) - 
                RELEVANT PARAMETER: $CertificateRequestConfigFile
            - A Certificate Request File (with .csr file extenstion) - 
                RELEVANT PARAMETER: $CertificateRequestFile
            - A Public Certificate with the New Certificate Name (NewCertificate_$CertificateCN_[Timestamp].cer) - 
                RELEVANT PARAMETER: $CertFileOut
                NOTE: This file is not explicitly generated by the script. Rather, it is received from the Issuing Certificate Authority after 
                the Certificate Request is submitted and accepted by the Issuing Certificate Authority. 
                NOTE: If you choose to use Win32 OpenSSL to extract certs/keys from the .pfx file (see below), this file should have SIMILAR CONTENT
                to the file $PublicKeySansChainOutFile. To clarify, $PublicKeySansChainOutFile does NOT have what appear to be extraneous newlines, 
                but $CertFileOut DOES. Even though $CertFileOut has what appear to be extraneous newlines, Microsoft Crypto Shell Extensions will 
                be able to read both files as if they were the same. However, Linux machines will need to use $PublicKeySansChainOutFile (Also, the 
                file extension for $PublicKeySansChainOutFile can safely be changed from .cer to .pem without issue)
            - A PSCustomObject with properties:
                - FileOutputHashTable
                - CertNamevsContentsHash

                The 'FileOutputHashTable' property can help the user quickly and easily reference output 
                files in $CertGenWorking. Example content:

                    Key   : CertificateRequestFile
                    Value : NewCertRequest_aws-coreos3-client-server-cert04-Sep-2016_2127.csr
                    Name  : CertificateRequestFile

                    Key   : IntermediateCAPublicCertFile
                    Value : ZeroSCA_Public_Cert.pem
                    Name  : IntermediateCAPublicCertFile

                    Key   : EndPointPublicCertFile
                    Value : aws-coreos3-client-server-cert_Public_Cert.pem
                    Name  : EndPointPublicCertFile

                    Key   : AllPublicKeysInChainOut
                    Value : NewCertificate_aws-coreos3-client-server-cert_all_public_keys_in_chain.pem
                    Name  : AllPublicKeysInChainOut

                    Key   : CertificateRequestConfigFile
                    Value : NewCertRequestConfig_aws-coreos3-client-server-cert04-Sep-2016_2127.inf
                    Name  : CertificateRequestConfigFile

                    Key   : EndPointUnProtectedPrivateKey
                    Value : NewCertificate_aws-coreos3-client-server-cert_unprotected_private_key.key
                    Name  : EndPointUnProtectedPrivateKey

                    Key   : RootCAPublicCertFile
                    Value : ZeroDC01_Public_Cert.pem
                    Name  : RootCAPublicCertFile

                    Key   : CertADCSWebResponseOutFile
                    Value : NewCertificate_aws-coreos3-client-server-cert_ADCSWebResponse04-Sep-2016_2127.txt
                    Name  : CertADCSWebResponseOutFile

                    Key   : CertFileOut
                    Value : NewCertificate_aws-coreos3-client-server-cert04-Sep-2016_2127.cer
                    Name  : CertFileOut

                    Key   : PFXFileOut
                    Value : NewCertificate_aws-coreos3-client-server-cert04-Sep-2016_2127.pfx
                    Name  : PFXFileOut

                    Key   : EndPointProtectedPrivateKey
                    Value : NewCertificate_aws-coreos3-client-server-cert_protected_private_key.pem
                    Name  : EndPointProtectedPrivateKey

                The 'CertNamevsContentHash' hashtable can help the user quickly access the content of each of the
                aforementioned files. Example content for the 'CertNamevsContentsHash' property:

                    Key   : EndPointUnProtectedPrivateKey
                    Value : -----BEGIN RSA PRIVATE KEY-----
                            ...
                            -----END RSA PRIVATE KEY-----
                    Name  : EndPointUnProtectedPrivateKey

                    Key   : aws-coreos3-client-server-cert
                    Value : -----BEGIN CERTIFICATE-----
                            ...
                            -----END CERTIFICATE-----
                    Name  : aws-coreos3-client-server-cert

                    Key   : ZeroSCA
                    Value : -----BEGIN CERTIFICATE-----
                            ...
                            -----END CERTIFICATE-----
                    Name  : ZeroSCA

                    Key   : ZeroDC01
                    Value : -----BEGIN CERTIFICATE-----
                            ...
                            -----END CERTIFICATE-----
                    Name  : ZeroDC01

        GENERATED WHEN $MachineKeySet = "False"
        The following outputs are ONLY generated by this function/script when $MachineKeySet = "False" (this is its default setting)
            - A .pfx File Containing the Entire Public Certificate Chain AS WELL AS the Private Key of your New Certificate (with .pfx file extension) - 
                RELEVANT PARAMETER: $PFXFileOut
                NOTE: The Private Key must be marked as exportable in your Certificate Request Configuration File in order for the .pfx file to
                contain the private key. This is controlled by the parameter $PrivateKeyExportableValue = "True". The Private Key is marked as 
                exportable by default.
        
        GENERATED WHEN $ADCSWebEnrollmentUrl is NOT provided
        The following outputs are ONLY generated by this function/script when $ADCSWebEnrollmentUrl is NOT provided (this is its default setting)
        (NOTE: Under this scenario, the workstation running the script must be part of the same domain as the Issuing Certificate Authority):
            - A Certificate Request Response File (with .rsp file extension) 
                NOTE: This file is not explicitly generated by the script. Rather, it is received from the Issuing Certificate Authority after 
                the Certificate Request is submitted
            - A Certificate Chain File (with .p7b file extension) -
                RELEVANT PARAMETER: $CertificateChainOut
                NOTE: This file is not explicitly generated by the script. Rather, it is received from the Issuing Certificate Authority after 
                the Certificate Request is submitted and accepted by the Issuing Certificate Authority
                NOTE: This file contains the entire chain of public certificates, from the requested certificate, up to the Root CA
                WARNING: In order to parse the public certificates for each entity up the chain, you MUST use the Crypto Shell Extensions GUI,
                otherwise, if you look at this content with a text editor, it appears as only one (1) public certificate.  Use the OpenSSL
                Certificate Chain File ($AllPublicKeysInChainOut) optional output in order to view a text file that parses each entity's public certificate.
        
        GENERATED WHEN $ADCSWebEnrollmentUrl IS provided
        The following outputs are ONLY generated by this function/script when $ADCSWebEnrollmentUrl IS provided
        (NOTE: Under this scenario, the workstation running the script is sending a web request to the ADCS Web Enrollment website):
            - An File Containing the HTTP Response From the ADCS Web Enrollment Site (with .txt file extension) - 
                RELEVANT PARAMETER: $CertADCSWebResponseOutFile
        
        GENERATED WHEN $UseOpenSSL = "Yes"
        The following outputs are ONLY generated by this function/script when $UseOpenSSL = "Yes"
        (WARNING: This creates a Dependency on a third party Win32 OpenSSL binary that can be found here: https://indy.fulgan.com/SSL/
        For more information, see the DEPENDENCIES Section below)
            - A Certificate Chain File (ending with "all_public_keys_in_chain.pem") -
                RELEVANT PARAMETER: $AllPublicKeysInChainOut
                NOTE: This optional parameter differs from the aforementioned .p7b certificate chain output in that it actually parses
                each entity's public certificate in a way that is viewable in a text editor.
            - EACH Public Certificate in the Certificate Chain File (file name like [Certificate CN]_Public_Cert.cer)
                - A Public Certificate with the New Certificate Name ($CertificateCN_Public_Cert.cer) -
                    RELEVANT PARAMETER: $PublicKeySansChainOutFile
                    NOTE: This file should have SIMILAR CONTENT to $CertFileOut referenced earlier. To clarify, $PublicKeySansChainOutFile does NOT have
                    what appear to be extraneous newlines, but $CertFileOut DOES. Even though $CertFileOut has what appear to be extraneous newlines, Microsoft Crypto Shell Extensions will 
                    be able to read both files as if they were the same. However, Linux machines will need to use $PublicKeySansChainOutFile (Also, the 
                    file extension for $PublicKeySansChainOutFile can safely be changed from .cer to .pem without issue)
                - Additional Public Certificates in Chain including [Subordinate CA CN]_Public_Cert.cer and [Root CA CN]_Public_Cert.cer
            - A Password Protected Private Key file (ending with "protected_private_key.pem") -
                RELEVANT PARAMETER: $ProtectedPrivateKeyOut
                NOTE: This is the New Certificate's Private Key that is protected by a password defined by the $PFXPwdAsSecureString parameter.

        GENERATED WHEN $UseOpenSSL = "Yes" AND $StripPrivateKeyOfPassword = "Yes"
            - An Unprotected Private Key File (ends with unprotected_private_key.key) -
                RELEVANT PARAMETER: $UnProtectedPrivateKeyOut

#>
function Generate-Certificate {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$CertGenWorking = "$HOME\Downloads\CertGenWorking",

        [Parameter(Mandatory=$False)]
        [string]$BasisTemplate,

        [Parameter(Mandatory=$False)]
        [string]$CertificateCN = $(Read-Host -Prompt "Please enter the Name that you would like your Certificate to have
        For a Computer/Client/Server Certificate, recommend using host FQDN)"),

        # This function creates the $CertificateRequestConfigFile. It should NOT exist prior to running this function
        [Parameter(Mandatory=$False)]
        [string]$CertificateRequestConfigFile = "NewCertRequestConfig_$CertificateCN"+$(Get-Date -format 'dd-MMM-yyyy_HHmm')+".inf",

        # This function creates the $CertificateRequestFile. It should NOT exist prior to running this function
        [Parameter(Mandatory=$False)]
        [string]$CertificateRequestFile = "NewCertRequest_$CertificateCN"+$(Get-Date -format 'dd-MMM-yyyy_HHmm')+".csr",

        # This function creates $CertFileOut. It should NOT exist prior to running this function
        [Parameter(Mandatory=$False)]
        [string]$CertFileOut = "NewCertificate_$CertificateCN"+$(Get-Date -format 'dd-MMM-yyyy_HHmm')+".cer",

        # This function creates the $CertificateChainOut. It should NOT exist prior to running this function
        [Parameter(Mandatory=$False)]
        [string]$CertificateChainOut = "NewCertificateChain_$CertificateCN"+$(Get-Date -format 'dd-MMM-yyyy_HHmm')+".p7b",

        # This function creates the $PFXFileOut. It should NOT exist prior to running this function
        [Parameter(Mandatory=$False)]
        [string]$PFXFileOut = "NewCertificate_$CertificateCN"+$(Get-Date -format 'dd-MMM-yyyy_HHmm')+".pfx",

        [Parameter(Mandatory=$False)]
        [securestring]$PFXPwdAsSecureString,

        # If the workstation being used to request the certificate is part of the same domain as the Issuing Certificate Authority, we can identify
        # the Issuing Certificate Authority with certutil, so there is no need to set an $IssuingCertificateAuth Parameter
        #[Parameter(Mandatory=$False)]
        #$IssuingCertAuth = $(Read-Host -Prompt "Please enter the FQDN the server responsible for Issuing New Certificates."),

        [Parameter(Mandatory=$False)]
        [ValidatePattern("certsrv$")]
        [string]$ADCSWebEnrollmentUrl, # Example: https://pki.zero.lab/certsrv"

        [Parameter(Mandatory=$False)]
        [ValidateSet("Windows","Basic")]
        [string]$ADCSWebAuthType,

        [Parameter(Mandatory=$False)]
        [string]$ADCSWebAuthUserName,

        [Parameter(Mandatory=$False)]
        [securestring]$ADCSWebAuthPass,

        [Parameter(Mandatory=$False)]
        [System.Management.Automation.PSCredential]$ADCSWebCreds,

        # This function creates the $CertADCSWebResponseOutFile file. It should NOT exist prior to running this function
        [Parameter(Mandatory=$False)]
        [string]$CertADCSWebResponseOutFile = "NewCertificate_$CertificateCN"+"_ADCSWebResponse"+$(Get-Date -format 'dd-MMM-yyyy_HHmm')+".txt",

        [Parameter(Mandatory=$False)]
        $Organization = $(Read-Host -Prompt "Please enter the name of the the Company that will appear on the New Certificate"),

        [Parameter(Mandatory=$False)]
        $OrganizationalUnit = $(Read-Host -Prompt "Please enter the name of the Department that you work for within your Company"),

        [Parameter(Mandatory=$False)]
        $Locality = $(Read-Host -Prompt "Please enter the City where your Company is located"),

        [Parameter(Mandatory=$False)]
        $State = $(Read-Host -Prompt "Please enter the State where your Company is located"),

        [Parameter(Mandatory=$False)]
        $Country = $(Read-Host -Prompt "Please enter the Country where your Company is located"),

        <#
        # ValidityPeriod is controlled by the Certificate Template and cannot be modified at the time of certificate request
        # (Unless it is a special circumstance where "RequestType = Cert" resulting in a self-signed cert where no request
        # is actually submitted)
        [Parameter(Mandatory=$False)]
        $ValidityPeriodValue = $(Read-Host -Prompt "Please enter the length of time that the certificate will be valid for.
        NOTE: Values must be in Months or Years. For example '6 months' or '2 years'"),
        #>

        [Parameter(Mandatory=$False)]
        [ValidateSet("2048","4096")]
        $KeyLength = "2048",

        [Parameter(Mandatory=$False)]
        [ValidateSet("SHA1","SHA256","SHA384","SHA512","MD5","MD4","MD2")]
        $HashAlgorithmValue = "SHA256",

        <#
        # KeyAlgorithm should be determined by ProviderName. Run "certutil -csplist" to see which Providers use which Key Algorithms
        [Parameter(Mandatory=$False)]
        [ValidateSet("RSA","DH","DSA","ECDH_P256","ECDH_P521","ECDSA_P256","ECDSA_P384","ECDSA_P521")]
        $KeyAlgorithmValue,
        #>

        [Parameter(Mandatory=$False)]
        [ValidateSet("AES","DES","3DES","RC2","RC4")]
        $EncryptionAlgorithmValue = "AES",

        [Parameter(Mandatory=$False)]
        [ValidateSet("True","False")]
        $PrivateKeyExportableValue = "True",

        # Valid values are '1' for AT_KEYEXCHANGE and '2' for AT_SIGNATURE [1,2]"
        [Parameter(Mandatory=$False)]
        [ValidateSet("1","2")]
        $KeySpecValue = "1",

        <#
        The below $KeyUsageValue is the HEXADECIMAL SUM of the KeyUsage hexadecimal values you would like to use.

        A valid value is the hex sum of one or more of following:
            CERT_DIGITAL_SIGNATURE_KEY_USAGE = 80
            CERT_NON_REPUDIATION_KEY_USAGE = 40
            CERT_KEY_ENCIPHERMENT_KEY_USAGE = 20
            CERT_DATA_ENCIPHERMENT_KEY_USAGE = 10
            CERT_KEY_AGREEMENT_KEY_USAGE = 8
            CERT_KEY_CERT_SIGN_KEY_USAGE = 4
            CERT_OFFLINE_CRL_SIGN_KEY_USAGE = 2
            CERT_CRL_SIGN_KEY_USAGE = 2
            CERT_ENCIPHER_ONLY_KEY_USAGE = 1
        
        Commonly Used Values:
            'c0' (i.e. 80+40)
            'a0' (i.e. 80+20)
            'f0' (i.e. 80+40+20+10)
            '30' (i.e. 20+10)
            '80'
        #>
        [Parameter(Mandatory=$False)]
        [ValidateSet("1","10","11","12","13","14","15","16","17","18","2","20","21","22","23","24","25","26","27","28","3","30","38","4","40",
        "41","42","43","44","45","46","47","48","5","50","58","6","60","68","7","70","78","8","80","81","82","83","84","85","86","87","88","9","90",
        "98","a","a0","a8","b","b0","b8","c","c0","c","8","d","d0","d8","e","e0","e8","f","f0","f8")]
        $KeyUsageValue = "80",
        
        [Parameter(Mandatory=$False)]
        [ValidateSet("True","False")]
        $MachineKeySet = "False",

        [Parameter(Mandatory=$False)]
        [ValidateSet("Yes","No")]
        $SecureEmail = "No",

        [Parameter(Mandatory=$False)]
        [ValidateSet("True","False")]
        $UserProtected = "False",

        [Parameter(Mandatory=$False)]
        [ValidateSet("Microsoft Base Cryptographic Provider v1.0","Microsoft Base DSS and Diffie-Hellman Cryptographic Provider",
        "Microsoft Base DSS Cryptographic Provider","Microsoft Base Smart Card Crypto Provider",
        "Microsoft DH SChannel Cryptographic Provider","Microsoft Enhanced Cryptographic Provider v1.0",
        "Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider",
        "Microsoft Enhanced RSA and AES Cryptographic Provider","Microsoft RSA SChannel Cryptographic Provider",
        "Microsoft Strong Cryptographic Provider","Microsoft Software Key Storage Provider",
        "Microsoft Passport Key Storage Provider")]
        [string]$ProviderNameValue = "Microsoft RSA SChannel Cryptographic Provider",

        [Parameter(Mandatory=$False)]
        [ValidateSet("CMC", "PKCS10", "PKCS10-", "PKCS7")]
        $RequestTypeValue = "PKCS10",

        [Parameter(Mandatory=$False)]
        [ValidateSet("Code Signing","Document Signing","Client Authentication","Server Authentication",
        "Remote Desktop","Private Key Archival","Directory Service Email Replication","Key Recovery Agent",
        "OCSP Signing","Microsoft Trust List Signing","EFS","Secure E-mail","Enrollment Agent","Smart Card Logon",
        "File Recovery","IPSec IKE Intermediate","KDC Authentication","Windows Update",
        "Windows Third Party Application Component","Windows TCB Component","Windows Store",
        "Windows Software Extension Verification","Windows RT Verification","Windows Kits Component",
        "No OCSP Failover to CRL","Auto Update End Revocation","Auto Update CA Revocation","Revoked List Signer",
        "Protected Process Verification","Protected Process Light Verification","Platform Certificate",
        "Microsoft Publisher","Kernel Mode Code Signing","HAL Extension","Endorsement Key Certificate",
        "Early Launch Antimalware Driver","Dynamic Code Generator","DNS Server Trust","Document Encryption",
        "Disallowed List","Attestation Identity Key Certificate","System Health Authentication","CTL Usage",
        "IP Security End System","IP Security Tunnel Termination","IP Security User","Time Stamping",
        "Microsoft Time Stamping","Windows Hardware Driver Verification","Windows System Component Verification",
        "OEM Windows System Component Verification","Embedded Windows System Component Verification","Root List Signer",
        "Qualified Subordination","Key Recovery","Lifetime Signing","Key Pack Licenses","License Server Verification")]
        [string[]]$IntendedPurposeValues,

        [Parameter(Mandatory=$False)]
        [ValidateSet("Yes","No")]
        $UseOpenSSL = "Yes",

        [Parameter(Mandatory=$False)]
        [string]$AllPublicKeysInChainOut = "NewCertificate_$CertificateCN"+"_all_public_keys_in_chain"+".pem",

        [Parameter(Mandatory=$False)]
        [string]$ProtectedPrivateKeyOut = "NewCertificate_$CertificateCN"+"_protected_private_key"+".pem",
        
        [Parameter(Mandatory=$False)]
        [string]$UnProtectedPrivateKeyOut = "NewCertificate_$CertificateCN"+"_unprotected_private_key"+".key",

        [Parameter(Mandatory=$False)]
        [ValidateSet("Yes","No")]
        $StripPrivateKeyOfPassword = "Yes",

        [Parameter(Mandatory=$False)]
        [ValidateSet("DNS","Distinguished Name","URL","IP Address","Email","UPN","GUID")]
        [string[]]$SANObjectsToAdd,

        [Parameter(Mandatory=$False)]
        [string[]]$DNSSANObjects, # Example: www.fabrikam.com, www.contoso.org

        [Parameter(Mandatory=$False)]
        [string[]]$DistinguishedNameSANObjects, # Example: CN=www01,OU=Web Servers,DC=fabrikam,DC=com; CN=www01,OU=Load Balancers,DC=fabrikam,DC=com"

        [Parameter(Mandatory=$False)]
        [string[]]$URLSANObjects, # Example: http://www.fabrikam.com, http://www.contoso.com

        [Parameter(Mandatory=$False)]
        [string[]]$IPAddressSANObjects, # Example: 192.168.2.12, 10.10.1.15

        [Parameter(Mandatory=$False)]
        [string[]]$EmailSANObjects, # Example: mike@fabrikam.com, hazem@fabrikam.com

        [Parameter(Mandatory=$False)]
        [string[]]$UPNSANObjects, # Example: mike@fabrikam.com, hazem@fabrikam.com

        [Parameter(Mandatory=$False)]
        [string[]]$GUIDSANObjects,

        [Parameter(Mandatory=$False)]
        [switch]$CSRGenOnly
    )

    #region >> Libraries and Helper Functions

    function Compare-Arrays {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$False)]
            [array]$LargerArray,

            [Parameter(Mandatory=$False)]
            [array]$SmallerArray
        )

        -not @($SmallerArray | where {$LargerArray -notcontains $_}).Count
    }

    $OIDHashTable = @{
        # Remote Desktop
        "Remote Desktop" = "1.3.6.1.4.1.311.54.1.2"
        # Windows Update
        "Windows Update" = "1.3.6.1.4.1.311.76.6.1"
        # Windows Third Party Applicaiton Component
        "Windows Third Party Application Component" = "1.3.6.1.4.1.311.10.3.25"
        # Windows TCB Component
        "Windows TCB Component" = "1.3.6.1.4.1.311.10.3.23"
        # Windows Store
        "Windows Store" = "1.3.6.1.4.1.311.76.3.1"
        # Windows Software Extension verification
        " Windows Software Extension Verification" = "1.3.6.1.4.1.311.10.3.26"
        # Windows RT Verification
        "Windows RT Verification" = "1.3.6.1.4.1.311.10.3.21"
        # Windows Kits Component
        "Windows Kits Component" = "1.3.6.1.4.1.311.10.3.20"
        # ROOT_PROGRAM_NO_OCSP_FAILOVER_TO_CRL
        "No OCSP Failover to CRL" = "1.3.6.1.4.1.311.60.3.3"
        # ROOT_PROGRAM_AUTO_UPDATE_END_REVOCATION
        "Auto Update End Revocation" = "1.3.6.1.4.1.311.60.3.2"
        # ROOT_PROGRAM_AUTO_UPDATE_CA_REVOCATION
        "Auto Update CA Revocation" = "1.3.6.1.4.1.311.60.3.1"
        # Revoked List Signer
        "Revoked List Signer" = "1.3.6.1.4.1.311.10.3.19"
        # Protected Process Verification
        "Protected Process Verification" = "1.3.6.1.4.1.311.10.3.24"
        # Protected Process Light Verification
        "Protected Process Light Verification" = "1.3.6.1.4.1.311.10.3.22"
        # Platform Certificate
        "Platform Certificate" = "2.23.133.8.2"
        # Microsoft Publisher
        "Microsoft Publisher" = "1.3.6.1.4.1.311.76.8.1"
        # Kernel Mode Code Signing
        "Kernel Mode Code Signing" = "1.3.6.1.4.1.311.6.1.1"
        # HAL Extension
        "HAL Extension" = "1.3.6.1.4.1.311.61.5.1"
        # Endorsement Key Certificate
        "Endorsement Key Certificate" = "2.23.133.8.1"
        # Early Launch Antimalware Driver
        "Early Launch Antimalware Driver" = "1.3.6.1.4.1.311.61.4.1"
        # Dynamic Code Generator
        "Dynamic Code Generator" = "1.3.6.1.4.1.311.76.5.1"
        # Domain Name System (DNS) Server Trust
        "DNS Server Trust" = "1.3.6.1.4.1.311.64.1.1"
        # Document Encryption
        "Document Encryption" = "1.3.6.1.4.1.311.80.1"
        # Disallowed List
        "Disallowed List" = "1.3.6.1.4.1.10.3.30"
        # Attestation Identity Key Certificate
        "Attestation Identity Key Certificate" = "2.23.133.8.3"
        "Generic Conference Contro" = "0.0.20.124.0.1"
        "X509Extensions" = "1.3.6.1.4.1.311.2.1.14"
        "EnrollmentCspProvider" = "1.3.6.1.4.1.311.13.2.2"
        # System Health Authentication
        "System Health Authentication" = "1.3.6.1.4.1.311.47.1.1"
        "OsVersion" = "1.3.6.1.4.1.311.13.2.3"
        "RenewalCertificate" = "1.3.6.1.4.1.311.13.1"
        "Certificate Template" = "1.3.6.1.4.1.311.20.2"
        "RequestClientInfo" = "1.3.6.1.4.1.311.21.20"
        "ArchivedKeyAttr" = "1.3.6.1.4.1.311.21.13"
        "EncryptedKeyHash" = "1.3.6.1.4.1.311.21.21"
        "EnrollmentNameValuePair" = "1.3.6.1.4.1.311.13.2.1"
        "IdAtName" = "2.5.4.41"
        "IdAtCommonName" = "2.5.4.3"
        "IdAtLocalityName" = "2.5.4.7"
        "IdAtStateOrProvinceName" = "2.5.4.8"
        "IdAtOrganizationName" = "2.5.4.10"
        "IdAtOrganizationalUnitName" = "2.5.4.11"
        "IdAtTitle" = "2.5.4.12"
        "IdAtDnQualifier" = "2.5.4.46"
        "IdAtCountryName" = "2.5.4.6"
        "IdAtSerialNumber" = "2.5.4.5"
        "IdAtPseudonym" = "2.5.4.65"
        "IdDomainComponent" = "0.9.2342.19200300.100.1.25"
        "IdEmailAddress" = "1.2.840.113549.1.9.1"
        "IdCeAuthorityKeyIdentifier" = "2.5.29.35"
        "IdCeSubjectKeyIdentifier" = "2.5.29.14"
        "IdCeKeyUsage" = "2.5.29.15"
        "IdCePrivateKeyUsagePeriod" = "2.5.29.16"
        "IdCeCertificatePolicies" = "2.5.29.32"
        "IdCePolicyMappings" = "2.5.29.33"
        "IdCeSubjectAltName" = "2.5.29.17"
        "IdCeIssuerAltName" = "2.5.29.18"
        "IdCeBasicConstraints" = "2.5.29.19"
        "IdCeNameConstraints" = "2.5.29.30"
        "idCdPolicyConstraints" = "2.5.29.36"
        "IdCeExtKeyUsage" = "2.5.29.37"
        "IdCeCRLDistributionPoints" = "2.5.29.31"
        "IdCeInhibitAnyPolicy" = "2.5.29.54"
        "IdPeAuthorityInfoAccess" = "1.3.6.1.5.5.7.1.1"
        "IdPeSubjectInfoAccess" = "1.3.6.1.5.5.7.1.11"
        "IdCeCRLNumber" = "2.5.29.20"
        "IdCeDeltaCRLIndicator" = "2.5.29.27"
        "IdCeIssuingDistributionPoint" = "2.5.29.28"
        "IdCeFreshestCRL" = "2.5.29.46"
        "IdCeCRLReason" = "2.5.29.21"
        "IdCeHoldInstructionCode" = "2.5.29.23"
        "IdCeInvalidityDate" = "2.5.29.24"
        "IdCeCertificateIssuer" = "2.5.29.29"
        "IdModAttributeCert" = "1.3.6.1.5.5.7.0.12"
        "IdPeAcAuditIdentity" = "1.3.6.1.5.5.7.1.4"
        "IdCeTargetInformation" = "2.5.29.55"
        "IdCeNoRevAvail" = "2.5.29.56"
        "IdAcaAuthenticationInfo" = "1.3.6.1.5.5.7.10.1"
        "IdAcaAccessIdentity" = "1.3.6.1.5.5.7.10.2"
        "IdAcaChargingIdentity" = "1.3.6.1.5.5.7.10.3"
        "IdAcaGroup" = "1.3.6.1.5.5.7.10.4"
        "IdAtRole" = "2.5.4.72"
        "IdAtClearance" = "2.5.1.5.55"
        "IdAcaEncAttrs" = "1.3.6.1.5.5.7.10.6"
        "IdPeAcProxying" = "1.3.6.1.5.5.7.1.10"
        "IdPeAaControls" = "1.3.6.1.5.5.7.1.6"
        "IdCtContentInfo" = "1.2.840.113549.1.9.16.1.6"
        "IdDataAuthpack" = "1.2.840.113549.1.7.1"
        "IdSignedData" = "1.2.840.113549.1.7.2"
        "IdEnvelopedData" = "1.2.840.113549.1.7.3"
        "IdDigestedData" = "1.2.840.113549.1.7.5"
        "IdEncryptedData" = "1.2.840.113549.1.7.6"
        "IdCtAuthData" = "1.2.840.113549.1.9.16.1.2"
        "IdContentType" = "1.2.840.113549.1.9.3"
        "IdMessageDigest" = "1.2.840.113549.1.9.4"
        "IdSigningTime" = "1.2.840.113549.1.9.5"
        "IdCounterSignature" = "1.2.840.113549.1.9.6"
        "RsaEncryption" = "1.2.840.113549.1.1.1"
        "IdRsaesOaep" = "1.2.840.113549.1.1.7"
        "IdPSpecified" = "1.2.840.113549.1.1.9"
        "IdRsassaPss" = "1.2.840.113549.1.1.10"
        "Md2WithRSAEncryption" = "1.2.840.113549.1.1.2"
        "Md5WithRSAEncryption" = "1.2.840.113549.1.1.4"
        "Sha1WithRSAEncryption" = "1.2.840.113549.1.1.5"
        "Sha256WithRSAEncryption" = "1.2.840.113549.1.1.11"
        "Sha384WithRSAEncryption" = "1.2.840.113549.1.1.12"
        "Sha512WithRSAEncryption" = "1.2.840.113549.1.1.13"
        "IdMd2" = "1.2.840.113549.2.2"
        "IdMd5" = "1.2.840.113549.2.5"
        "IdSha1" = "1.3.14.3.2.26"
        "IdSha256" = "2.16.840.1.101.3.4.2.1"
        "IdSha384" = "2.16.840.1.101.3.4.2.2"
        "IdSha512" = "2.16.840.1.101.3.4.2.3"
        "IdMgf1" = "1.2.840.113549.1.1.8"
        "IdDsaWithSha1" = "1.2.840.10040.4.3"
        "EcdsaWithSHA1" = "1.2.840.10045.4.1"
        "IdDsa" = "1.2.840.10040.4.1"
        "DhPublicNumber" = "1.2.840.10046.2.1"
        "IdKeyExchangeAlgorithm" = "2.16.840.1.101.2.1.1.22"
        "IdEcPublicKey" = "1.2.840.10045.2.1"
        "PrimeField" = "1.2.840.10045.1.1"
        "CharacteristicTwoField" = "1.2.840.10045.1.2"
        "GnBasis" = "1.2.840.10045.1.2.1.1"
        "TpBasis" = "1.2.840.10045.1.2.1.2"
        "PpBasis" = "1.2.840.10045.1.2.1.3"
        "IdAlgEsdh" = "1.2.840.113549.1.9.16.3.5"
        "IdAlgSsdh" = "1.2.840.113549.1.9.16.3.10"
        "IdAlgCms3DesWrap" = "1.2.840.113549.1.9.16.3.6"
        "IdAlgCmsRc2Wrap" = "1.2.840.113549.1.9.16.3.7"
        "IdPbkDf2" = "1.2.840.113549.1.5.12"
        "DesEde3Cbc" = "1.2.840.113549.3.7"
        "Rc2Cbc" = "1.2.840.113549.3.2"
        "HmacSha1" = "1.3.6.1.5.5.8.1.2"
        "IdAes128Cbc" = "2.16.840.1.101.3.4.1.2"
        "IdAes192Cbc" = "2.16.840.1.101.3.4.1.22"
        "IdAes256Cbc" = "2.16.840.1.101.3.4.1.42"
        "IdAes128Wrap" = "2.16.840.1.101.3.4.1.5"
        "IdAes192Wrap" = "2.16.840.1.101.3.4.1.25"
        "IdAes256Wrap" = "2.16.840.1.101.3.4.1.45"
        "IdCmcIdentification" = "1.3.6.1.5.5.7.7.2"
        "IdCmcIdentityProof" = "1.3.6.1.5.5.7.7.3"
        "IdCmcDataReturn" = "1.3.6.1.5.5.7.7.4"
        "IdCmcTransactionId" = "1.3.6.1.5.5.7.7.5"
        "IdCmcSenderNonce" = "1.3.6.1.5.5.7.7.6"
        "IdCmcRecipientNonce" = "1.3.6.1.5.5.7.7.7"
        "IdCmcRegInfo" = "1.3.6.1.5.5.7.7.18"
        "IdCmcResponseInfo" = "1.3.6.1.5.5.7.7.19"
        "IdCmcQueryPending" = "1.3.6.1.5.5.7.7.21"
        "IdCmcPopLinkRandom" = "1.3.6.1.5.5.7.7.22"
        "IdCmcPopLinkWitness" = "1.3.6.1.5.5.7.7.23"
        "IdCctPKIData" = "1.3.6.1.5.5.7.12.2"
        "IdCctPKIResponse" = "1.3.6.1.5.5.7.12.3"
        "IdCmccMCStatusInfo" = "1.3.6.1.5.5.7.7.1"
        "IdCmcAddExtensions" = "1.3.6.1.5.5.7.7.8"
        "IdCmcEncryptedPop" = "1.3.6.1.5.5.7.7.9"
        "IdCmcDecryptedPop" = "1.3.6.1.5.5.7.7.10"
        "IdCmcLraPopWitness" = "1.3.6.1.5.5.7.7.11"
        "IdCmcGetCert" = "1.3.6.1.5.5.7.7.15"
        "IdCmcGetCRL" = "1.3.6.1.5.5.7.7.16"
        "IdCmcRevokeRequest" = "1.3.6.1.5.5.7.7.17"
        "IdCmcConfirmCertAcceptance" = "1.3.6.1.5.5.7.7.24"
        "IdExtensionReq" = "1.2.840.113549.1.9.14"
        "IdAlgNoSignature" = "1.3.6.1.5.5.7.6.2"
        "PasswordBasedMac" = "1.2.840.113533.7.66.13"
        "IdRegCtrlRegToken" = "1.3.6.1.5.5.7.5.1.1"
        "IdRegCtrlAuthenticator" = "1.3.6.1.5.5.7.5.1.2"
        "IdRegCtrlPkiPublicationInfo" = "1.3.6.1.5.5.7.5.1.3"
        "IdRegCtrlPkiArchiveOptions" = "1.3.6.1.5.5.7.5.1.4"
        "IdRegCtrlOldCertID" = "1.3.6.1.5.5.7.5.1.5"
        "IdRegCtrlProtocolEncrKey" = "1.3.6.1.5.5.7.5.1.6"
        "IdRegInfoUtf8Pairs" = "1.3.6.1.5.5.7.5.2.1"
        "IdRegInfoCertReq" = "1.3.6.1.5.5.7.5.2.2"
        "SpnegoToken" = "1.3.6.1.5.5.2"
        "SpnegoNegTok" = "1.3.6.1.5.5.2.4.2"
        "GSS_KRB5_NT_USER_NAME" = "1.2.840.113554.1.2.1.1"
        "GSS_KRB5_NT_MACHINE_UID_NAME" = "1.2.840.113554.1.2.1.2"
        "GSS_KRB5_NT_STRING_UID_NAME" = "1.2.840.113554.1.2.1.3"
        "GSS_C_NT_HOSTBASED_SERVICE" = "1.2.840.113554.1.2.1.4"
        "KerberosToken" = "1.2.840.113554.1.2.2"
        "Negoex" = "1.3.6.1.4.1.311.2.2.30" 
        "GSS_KRB5_NT_PRINCIPAL_NAME" = "1.2.840.113554.1.2.2.1"
        "GSS_KRB5_NT_PRINCIPAL" = "1.2.840.113554.1.2.2.2"
        "UserToUserMechanism" = "1.2.840.113554.1.2.2.3"
        "MsKerberosToken" = "1.2.840.48018.1.2.2"
        "NLMP" = "1.3.6.1.4.1.311.2.2.10"
        "IdPkixOcspBasic" = "1.3.6.1.5.5.7.48.1.1"
        "IdPkixOcspNonce" = "1.3.6.1.5.5.7.48.1.2"
        "IdPkixOcspCrl" = "1.3.6.1.5.5.7.48.1.3"
        "IdPkixOcspResponse" = "1.3.6.1.5.5.7.48.1.4"
        "IdPkixOcspNocheck" = "1.3.6.1.5.5.7.48.1.5"
        "IdPkixOcspArchiveCutoff" = "1.3.6.1.5.5.7.48.1.6"
        "IdPkixOcspServiceLocator" = "1.3.6.1.5.5.7.48.1.7"
        # Smartcard Logon
        "IdMsKpScLogon" = "1.3.6.1.4.1.311.20.2.2"
        "IdPkinitSan" = "1.3.6.1.5.2.2"
        "IdPkinitAuthData" = "1.3.6.1.5.2.3.1"
        "IdPkinitDHKeyData" = "1.3.6.1.5.2.3.2"
        "IdPkinitRkeyData" = "1.3.6.1.5.2.3.3"
        "IdPkinitKPClientAuth" = "1.3.6.1.5.2.3.4"
        "IdPkinitKPKdc" = "1.3.6.1.5.2.3.5"
        "SHA1 with RSA signature" = "1.3.14.3.2.29"
        "AUTHORITY_KEY_IDENTIFIER" = "2.5.29.1"
        "KEY_ATTRIBUTES" = "2.5.29.2"
        "CERT_POLICIES_95" = "2.5.29.3"
        "KEY_USAGE_RESTRICTION" = "2.5.29.4"
        "SUBJECT_ALT_NAME" = "2.5.29.7"
        "ISSUER_ALT_NAME" = "2.5.29.8"
        "Subject_Directory_Attributes" = "2.5.29.9"
        "BASIC_CONSTRAINTS" = "2.5.29.10"
        "ANY_CERT_POLICY" = "2.5.29.32.0"
        "LEGACY_POLICY_MAPPINGS" = "2.5.29.5"
        # Certificate Request Agent
        "ENROLLMENT_AGENT" = "1.3.6.1.4.1.311.20.2.1"
        "PKIX" = "1.3.6.1.5.5.7"
        "PKIX_PE" = "1.3.6.1.5.5.7.1"
        "NEXT_UPDATE_LOCATION" = "1.3.6.1.4.1.311.10.2"
        "REMOVE_CERTIFICATE" = "1.3.6.1.4.1.311.10.8.1"
        "CROSS_CERT_DIST_POINTS" = "1.3.6.1.4.1.311.10.9.1"
        "CTL" = "1.3.6.1.4.1.311.10.1"
        "SORTED_CTL" = "1.3.6.1.4.1.311.10.1.1"
        "SERIALIZED" = "1.3.6.1.4.1.311.10.3.3.1"
        "NT_PRINCIPAL_NAME" = "1.3.6.1.4.1.311.20.2.3"
        "PRODUCT_UPDATE" = "1.3.6.1.4.1.311.31.1"
        "ANY_APPLICATION_POLICY" = "1.3.6.1.4.1.311.10.12.1"
        # CTL Usage
        "AUTO_ENROLL_CTL_USAGE" = "1.3.6.1.4.1.311.20.1"
        "CERT_MANIFOLD" = "1.3.6.1.4.1.311.20.3"
        "CERTSRV_CA_VERSION" = "1.3.6.1.4.1.311.21.1"
        "CERTSRV_PREVIOUS_CERT_HASH" = "1.3.6.1.4.1.311.21.2"
        "CRL_VIRTUAL_BASE" = "1.3.6.1.4.1.311.21.3"
        "CRL_NEXT_PUBLISH" = "1.3.6.1.4.1.311.21.4"
        # Private Key Archival
        "KP_CA_EXCHANGE" = "1.3.6.1.4.1.311.21.5"
        # Key Recovery Agent
        "KP_KEY_RECOVERY_AGENT" = "1.3.6.1.4.1.311.21.6"
        "CERTIFICATE_TEMPLATE" = "1.3.6.1.4.1.311.21.7"
        "ENTERPRISE_OID_ROOT" = "1.3.6.1.4.1.311.21.8"
        "RDN_DUMMY_SIGNER" = "1.3.6.1.4.1.311.21.9"
        "APPLICATION_CERT_POLICIES" = "1.3.6.1.4.1.311.21.10"
        "APPLICATION_POLICY_MAPPINGS" = "1.3.6.1.4.1.311.21.11"
        "APPLICATION_POLICY_CONSTRAINTS" = "1.3.6.1.4.1.311.21.12"
        "CRL_SELF_CDP" = "1.3.6.1.4.1.311.21.14"
        "REQUIRE_CERT_CHAIN_POLICY" = "1.3.6.1.4.1.311.21.15"
        "ARCHIVED_KEY_CERT_HASH" = "1.3.6.1.4.1.311.21.16"
        "ISSUED_CERT_HASH" = "1.3.6.1.4.1.311.21.17"
        "DS_EMAIL_REPLICATION" = "1.3.6.1.4.1.311.21.19"
        "CERTSRV_CROSSCA_VERSION" = "1.3.6.1.4.1.311.21.22"
        "NTDS_REPLICATION" = "1.3.6.1.4.1.311.25.1"
        "PKIX_KP" = "1.3.6.1.5.5.7.3"
        "PKIX_KP_SERVER_AUTH" = "1.3.6.1.5.5.7.3.1"
        "PKIX_KP_CLIENT_AUTH" = "1.3.6.1.5.5.7.3.2"
        "PKIX_KP_CODE_SIGNING" = "1.3.6.1.5.5.7.3.3"
        # Secure Email
        "PKIX_KP_EMAIL_PROTECTION" = "1.3.6.1.5.5.7.3.4"
        # IP Security End System
        "PKIX_KP_IPSEC_END_SYSTEM" = "1.3.6.1.5.5.7.3.5"
        # IP Security Tunnel Termination
        "PKIX_KP_IPSEC_TUNNEL" = "1.3.6.1.5.5.7.3.6"
        # IP Security User
        "PKIX_KP_IPSEC_USER" = "1.3.6.1.5.5.7.3.7"
        # Time Stamping
        "PKIX_KP_TIMESTAMP_SIGNING" = "1.3.6.1.5.5.7.3.8"
        "KP_OCSP_SIGNING" = "1.3.6.1.5.5.7.3.9"
        # IP security IKE intermediate
        "IPSEC_KP_IKE_INTERMEDIATE" = "1.3.6.1.5.5.8.2.2"
        # Microsoft Trust List Signing
        "KP_CTL_USAGE_SIGNING" = "1.3.6.1.4.1.311.10.3.1"
        # Microsoft Time Stamping
        "KP_TIME_STAMP_SIGNING" = "1.3.6.1.4.1.311.10.3.2"
        "SERVER_GATED_CRYPTO" = "1.3.6.1.4.1.311.10.3.3"
        "SGC_NETSCAPE" = "2.16.840.1.113730.4.1"
        "KP_EFS" = "1.3.6.1.4.1.311.10.3.4"
        "EFS_RECOVERY" = "1.3.6.1.4.1.311.10.3.4.1"
        # Windows Hardware Driver Verification
        "WHQL_CRYPTO" = "1.3.6.1.4.1.311.10.3.5"
        # Windows System Component Verification
        "NT5_CRYPTO" = "1.3.6.1.4.1.311.10.3.6"
        # OEM Windows System Component Verification
        "OEM_WHQL_CRYPTO" = "1.3.6.1.4.1.311.10.3.7"
        # Embedded Windows System Component Verification
        "EMBEDDED_NT_CRYPTO" = "1.3.6.1.4.1.311.10.3.8"
        # Root List Signer
        "ROOT_LIST_SIGNER" = "1.3.6.1.4.1.311.10.3.9"
        # Qualified Subordination
        "KP_QUALIFIED_SUBORDINATION" = "1.3.6.1.4.1.311.10.3.10"
        # Key Recovery
        "KP_KEY_RECOVERY" = "1.3.6.1.4.1.311.10.3.11"
        "KP_DOCUMENT_SIGNING" = "1.3.6.1.4.1.311.10.3.12"
        # Lifetime Signing
        "KP_LIFETIME_SIGNING" = "1.3.6.1.4.1.311.10.3.13"
        "KP_MOBILE_DEVICE_SOFTWARE" = "1.3.6.1.4.1.311.10.3.14"
        # Digital Rights
        "DRM" = "1.3.6.1.4.1.311.10.5.1"
        "DRM_INDIVIDUALIZATION" = "1.3.6.1.4.1.311.10.5.2"
        # Key Pack Licenses
        "LICENSES" = "1.3.6.1.4.1.311.10.6.1"
        # License Server Verification
        "LICENSE_SERVER" = "1.3.6.1.4.1.311.10.6.2"
        "YESNO_TRUST_ATTR" = "1.3.6.1.4.1.311.10.4.1"
        "PKIX_POLICY_QUALIFIER_CPS" = "1.3.6.1.5.5.7.2.1"
        "PKIX_POLICY_QUALIFIER_USERNOTICE" = "1.3.6.1.5.5.7.2.2"
        "CERT_POLICIES_95_QUALIFIER1" = "2.16.840.1.113733.1.7.1.1"
        "RSA" = "1.2.840.113549"
        "PKCS" = "1.2.840.113549.1"
        "RSA_HASH" = "1.2.840.113549.2"
        "RSA_ENCRYPT" = "1.2.840.113549.3"
        "PKCS_1" = "1.2.840.113549.1.1"
        "PKCS_2" = "1.2.840.113549.1.2"
        "PKCS_3" = "1.2.840.113549.1.3"
        "PKCS_4" = "1.2.840.113549.1.4"
        "PKCS_5" = "1.2.840.113549.1.5"
        "PKCS_6" = "1.2.840.113549.1.6"
        "PKCS_7" = "1.2.840.113549.1.7"
        "PKCS_8" = "1.2.840.113549.1.8"
        "PKCS_9" = "1.2.840.113549.1.9"
        "PKCS_10" = "1.2.840.113549.1.10"
        "PKCS_12" = "1.2.840.113549.1.12"
        "RSA_MD4RSA" = "1.2.840.113549.1.1.3"
        "RSA_SETOAEP_RSA" = "1.2.840.113549.1.1.6"
        "RSA_DH" = "1.2.840.113549.1.3.1"
        "RSA_signEnvData" = "1.2.840.113549.1.7.4"
        "RSA_unstructName" = "1.2.840.113549.1.9.2"
        "RSA_challengePwd" = "1.2.840.113549.1.9.7"
        "RSA_unstructAddr" = "1.2.840.113549.1.9.8"
        "RSA_extCertAttrs" = "1.2.840.113549.1.9.9"
        "RSA_SMIMECapabilities" = "1.2.840.113549.1.9.15"
        "RSA_preferSignedData" = "1.2.840.113549.1.9.15.1"
        "RSA_SMIMEalg" = "1.2.840.113549.1.9.16.3"
        "RSA_MD4" = "1.2.840.113549.2.4"
        "RSA_RC4" = "1.2.840.113549.3.4"
        "RSA_RC5_CBCPad" = "1.2.840.113549.3.9"
        "ANSI_X942" = "1.2.840.10046"
        "X957" = "1.2.840.10040"
        "DS" = "2.5"
        "DSALG" = "2.5.8"
        "DSALG_CRPT" = "2.5.8.1"
        "DSALG_HASH" = "2.5.8.2"
        "DSALG_SIGN" = "2.5.8.3"
        "DSALG_RSA" = "2.5.8.1.1"
        "OIW" = "1.3.14"
        "OIWSEC" = "1.3.14.3.2"
        "OIWSEC_md4RSA" = "1.3.14.3.2.2"
        "OIWSEC_md5RSA" = "1.3.14.3.2.3"
        "OIWSEC_md4RSA2" = "1.3.14.3.2.4"
        "OIWSEC_desECB" = "1.3.14.3.2.6"
        "OIWSEC_desCBC" = "1.3.14.3.2.7"
        "OIWSEC_desOFB" = "1.3.14.3.2.8"
        "OIWSEC_desCFB" = "1.3.14.3.2.9"
        "OIWSEC_desMAC" = "1.3.14.3.2.10"
        "OIWSEC_rsaSign" = "1.3.14.3.2.11"
        "OIWSEC_dsa" = "1.3.14.3.2.12"
        "OIWSEC_shaDSA" = "1.3.14.3.2.13"
        "OIWSEC_mdc2RSA" = "1.3.14.3.2.14"
        "OIWSEC_shaRSA" = "1.3.14.3.2.15"
        "OIWSEC_dhCommMod" = "1.3.14.3.2.16"
        "OIWSEC_desEDE" = "1.3.14.3.2.17"
        "OIWSEC_sha" = "1.3.14.3.2.18"
        "OIWSEC_mdc2" = "1.3.14.3.2.19"
        "OIWSEC_dsaComm" = "1.3.14.3.2.20"
        "OIWSEC_dsaCommSHA" = "1.3.14.3.2.21"
        "OIWSEC_rsaXchg" = "1.3.14.3.2.22"
        "OIWSEC_keyHashSeal" = "1.3.14.3.2.23"
        "OIWSEC_md2RSASign" = "1.3.14.3.2.24"
        "OIWSEC_md5RSASign" = "1.3.14.3.2.25"
        "OIWSEC_dsaSHA1" = "1.3.14.3.2.27"
        "OIWSEC_dsaCommSHA1" = "1.3.14.3.2.28"
        "OIWDIR" = "1.3.14.7.2"
        "OIWDIR_CRPT" = "1.3.14.7.2.1"
        "OIWDIR_HASH" = "1.3.14.7.2.2"
        "OIWDIR_SIGN" = "1.3.14.7.2.3"
        "OIWDIR_md2" = "1.3.14.7.2.2.1"
        "OIWDIR_md2RSA" = "1.3.14.7.2.3.1"
        "INFOSEC" = "2.16.840.1.101.2.1"
        "INFOSEC_sdnsSignature" = "2.16.840.1.101.2.1.1.1"
        "INFOSEC_mosaicSignature" = "2.16.840.1.101.2.1.1.2"
        "INFOSEC_sdnsConfidentiality" = "2.16.840.1.101.2.1.1.3"
        "INFOSEC_mosaicConfidentiality" = "2.16.840.1.101.2.1.1.4"
        "INFOSEC_sdnsIntegrity" = "2.16.840.1.101.2.1.1.5"
        "INFOSEC_mosaicIntegrity" = "2.16.840.1.101.2.1.1.6"
        "INFOSEC_sdnsTokenProtection" = "2.16.840.1.101.2.1.1.7"
        "INFOSEC_mosaicTokenProtection" = "2.16.840.1.101.2.1.1.8"
        "INFOSEC_sdnsKeyManagement" = "2.16.840.1.101.2.1.1.9"
        "INFOSEC_mosaicKeyManagement" = "2.16.840.1.101.2.1.1.10"
        "INFOSEC_sdnsKMandSig" = "2.16.840.1.101.2.1.1.11"
        "INFOSEC_mosaicKMandSig" = "2.16.840.1.101.2.1.1.12"
        "INFOSEC_SuiteASignature" = "2.16.840.1.101.2.1.1.13"
        "INFOSEC_SuiteAConfidentiality" = "2.16.840.1.101.2.1.1.14"
        "INFOSEC_SuiteAIntegrity" = "2.16.840.1.101.2.1.1.15"
        "INFOSEC_SuiteATokenProtection" = "2.16.840.1.101.2.1.1.16"
        "INFOSEC_SuiteAKeyManagement" = "2.16.840.1.101.2.1.1.17"
        "INFOSEC_SuiteAKMandSig" = "2.16.840.1.101.2.1.1.18"
        "INFOSEC_mosaicUpdatedSig" = "2.16.840.1.101.2.1.1.19"
        "INFOSEC_mosaicKMandUpdSig" = "2.16.840.1.101.2.1.1.20"
        "INFOSEC_mosaicUpdatedInteg" = "2.16.840.1.101.2.1.1.21"
        "SUR_NAME" = "2.5.4.4"
        "STREET_ADDRESS" = "2.5.4.9"
        "DESCRIPTION" = "2.5.4.13"
        "SEARCH_GUIDE" = "2.5.4.14"
        "BUSINESS_CATEGORY" = "2.5.4.15"
        "POSTAL_ADDRESS" = "2.5.4.16"
        "POSTAL_CODE" = "2.5.4.17"
        "POST_OFFICE_BOX" = "2.5.4.18"
        "PHYSICAL_DELIVERY_OFFICE_NAME" = "2.5.4.19"
        "TELEPHONE_NUMBER" = "2.5.4.20"
        "TELEX_NUMBER" = "2.5.4.21"
        "TELETEXT_TERMINAL_IDENTIFIER" = "2.5.4.22"
        "FACSIMILE_TELEPHONE_NUMBER" = "2.5.4.23"
        "X21_ADDRESS" = "2.5.4.24"
        "INTERNATIONAL_ISDN_NUMBER" = "2.5.4.25"
        "REGISTERED_ADDRESS" = "2.5.4.26"
        "DESTINATION_INDICATOR" = "2.5.4.27"
        "PREFERRED_DELIVERY_METHOD" = "2.5.4.28"
        "PRESENTATION_ADDRESS" = "2.5.4.29"
        "SUPPORTED_APPLICATION_CONTEXT" = "2.5.4.30"
        "MEMBER" = "2.5.4.31"
        "OWNER" = "2.5.4.32"
        "ROLE_OCCUPANT" = "2.5.4.33"
        "SEE_ALSO" = "2.5.4.34"
        "USER_PASSWORD" = "2.5.4.35"
        "USER_CERTIFICATE" = "2.5.4.36"
        "CA_CERTIFICATE" = "2.5.4.37"
        "AUTHORITY_REVOCATION_LIST" = "2.5.4.38"
        "CERTIFICATE_REVOCATION_LIST" = "2.5.4.39"
        "CROSS_CERTIFICATE_PAIR" = "2.5.4.40"
        "GIVEN_NAME" = "2.5.4.42"
        "INITIALS" = "2.5.4.43"
        "PKCS_12_FRIENDLY_NAME_ATTR" = "1.2.840.113549.1.9.20"
        "PKCS_12_LOCAL_KEY_ID" = "1.2.840.113549.1.9.21"
        "PKCS_12_KEY_PROVIDER_NAME_ATTR" = "1.3.6.1.4.1.311.17.1"
        "LOCAL_MACHINE_KEYSET" = "1.3.6.1.4.1.311.17.2"
        "KEYID_RDN" = "1.3.6.1.4.1.311.10.7.1"
        "PKIX_ACC_DESCR" = "1.3.6.1.5.5.7.48"
        "PKIX_OCSP" = "1.3.6.1.5.5.7.48.1"
        "PKIX_CA_ISSUERS" = "1.3.6.1.5.5.7.48.2"
        "VERISIGN_PRIVATE_6_9" = "2.16.840.1.113733.1.6.9"
        "VERISIGN_ONSITE_JURISDICTION_HASH" = "2.16.840.1.113733.1.6.11"
        "VERISIGN_BITSTRING_6_13" = "2.16.840.1.113733.1.6.13"
        "VERISIGN_ISS_STRONG_CRYPTO" = "2.16.840.1.113733.1.8.1"
        "NETSCAPE" = "2.16.840.1.113730"
        "NETSCAPE_CERT_EXTENSION" = "2.16.840.1.113730.1"
        "NETSCAPE_CERT_TYPE" = "2.16.840.1.113730.1.1"
        "NETSCAPE_BASE_URL" = "2.16.840.1.113730.1.2"
        "NETSCAPE_REVOCATION_URL" = "2.16.840.1.113730.1.3"
        "NETSCAPE_CA_REVOCATION_URL" = "2.16.840.1.113730.1.4"
        "NETSCAPE_CERT_RENEWAL_URL" = "2.16.840.1.113730.1.7"
        "NETSCAPE_CA_POLICY_URL" = "2.16.840.1.113730.1.8"
        "NETSCAPE_SSL_SERVER_NAME" = "2.16.840.1.113730.1.12"
        "NETSCAPE_COMMENT" = "2.16.840.1.113730.1.13"
        "NETSCAPE_DATA_TYPE" = "2.16.840.1.113730.2"
        "NETSCAPE_CERT_SEQUENCE" = "2.16.840.1.113730.2.5"
        "CMC" = "1.3.6.1.5.5.7.7"
        "CMC_ADD_ATTRIBUTES" = "1.3.6.1.4.1.311.10.10.1"
        "PKCS_7_SIGNEDANDENVELOPED" = "1.2.840.113549.1.7.4"
        "CERT_PROP_ID_PREFIX" = "1.3.6.1.4.1.311.10.11."
        "CERT_KEY_IDENTIFIER_PROP_ID" = "1.3.6.1.4.1.311.10.11.20"
        "CERT_ISSUER_SERIAL_NUMBER_MD5_HASH_PROP_ID" = "1.3.6.1.4.1.311.10.11.28"
        "CERT_SUBJECT_NAME_MD5_HASH_PROP_ID" = "1.3.6.1.4.1.311.10.11.29"
    }

    function Get-IntendedPurposePSObjects {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$False)]
            [System.Collections.Hashtable]$OIDHashTable
        )
    
        $IntendedPurpose = "Code Signing"
        $OfficialName = "PKIX_KP_CODE_SIGNING"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
    
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
        
        $IntendedPurpose = "Document Signing"
        $OfficialName = "KP_DOCUMENT_SIGNING"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Client Authentication"
        $OfficialName = "PKIX_KP_CLIENT_AUTH"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Private Key Archival"
        $OfficialName = "KP_CA_EXCHANGE"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Directory Service Email Replication"
        $OfficialName = "DS_EMAIL_REPLICATION"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Key Recovery Agent"
        $OfficialName = "KP_KEY_RECOVERY_AGENT"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "OCSP Signing"
        $OfficialName = "KP_OCSP_SIGNING"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Server Authentication"
        $OfficialName = "PKIX_KP_SERVER_AUTH"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        ##### Below this point, Intended Purposes will be set but WILL NOT show up in the Certificate Templates Console under Intended Purpose column #####
        
        $IntendedPurpose = "EFS"
        $OfficialName = "KP_EFS"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Secure E-Mail"
        $OfficialName = "PKIX_KP_EMAIL_PROTECTION"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Enrollment Agent"
        $OfficialName = "ENROLLMENT_AGENT"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Microsoft Trust List Signing"
        $OfficialName = "KP_CTL_USAGE_SIGNING"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Smartcard Logon"
        $OfficialName = "IdMsKpScLogon"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "File Recovery"
        $OfficialName = "EFS_RECOVERY"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "IPSec IKE Intermediate"
        $OfficialName = "IPSEC_KP_IKE_INTERMEDIATE"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "KDC Authentication"
        $OfficialName = "IdPkinitKPKdc"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        ##### Begin Newly Added #####
        $IntendedPurpose = "Remote Desktop"
        $OfficialName = "Remote Desktop"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        # Cannot be overridden in Certificate Request
        $IntendedPurpose = "Windows Update"
        $OfficialName = "Windows Update"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Windows Third Party Application Component"
        $OfficialName = "Windows Third Party Application Component"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Windows TCB Component"
        $OfficialName = "Windows TCB Component"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Windows Store"
        $OfficialName = "Windows Store"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Windows Software Extension Verification"
        $OfficialName = "Windows Software Extension Verification"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Windows RT Verification"
        $OfficialName = "Windows RT Verification"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Windows Kits Component"
        $OfficialName = "Windows Kits Component"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "No OCSP Failover to CRL"
        $OfficialName = "No OCSP Failover to CRL"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Auto Update End Revocation"
        $OfficialName = "Auto Update End Revocation"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Auto Update CA Revocation"
        $OfficialName = "Auto Update CA Revocation"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Revoked List Signer"
        $OfficialName = "Revoked List Signer"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Protected Process Verification"
        $OfficialName = "Protected Process Verification"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Protected Process Light Verification"
        $OfficialName = "Protected Process Light Verification"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Platform Certificate"
        $OfficialName = "Platform Certificate"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Microsoft Publisher"
        $OfficialName = "Microsoft Publisher"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Kernel Mode Code Signing"
        $OfficialName = "Kernel Mode Code Signing"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "HAL Extension"
        $OfficialName = "HAL Extension"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Endorsement Key Certificate"
        $OfficialName = "Endorsement Key Certificate"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Early Launch Antimalware Driver"
        $OfficialName = "Early Launch Antimalware Driver"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Dynamic Code Generator"
        $OfficialName = "Dynamic Code Generator"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "DNS Server Trust"
        $OfficialName = "DNS Server Trust"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Document Encryption"
        $OfficialName = "Document Encryption"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Disallowed List"
        $OfficialName = "Disallowed List"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Attestation Identity Key Certificate"
        $OfficialName = "Attestation Identity Key Certificate"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "System Health Authentication"
        $OfficialName = "System Health Authentication"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "CTL Usage"
        $OfficialName = "AUTO_ENROLL_CTL_USAGE"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "IP Security End System"
        $OfficialName = "PKIX_KP_IPSEC_END_SYSTEM"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "IP Security Tunnel Termination"
        $OfficialName = "PKIX_KP_IPSEC_TUNNEL"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "IP Security User"
        $OfficialName = "PKIX_KP_IPSEC_USER"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Time Stamping"
        $OfficialName = "PKIX_KP_TIMESTAMP_SIGNING"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Microsoft Time Stamping"
        $OfficialName = "KP_TIME_STAMP_SIGNING"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Windows Hardware Driver Verification"
        $OfficialName = "WHQL_CRYPTO"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Windows System Component Verification"
        $OfficialName = "NT5_CRYPTO"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "OEM Windows System Component Verification"
        $OfficialName = "OEM_WHQL_CRYPTO"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Embedded Windows System Component Verification"
        $OfficialName = "EMBEDDED_NT_CRYPTO"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Root List Signer"
        $OfficialName = "ROOT_LIST_SIGNER"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Qualified Subordination"
        $OfficialName = "KP_QUALIFIED_SUBORDINATION"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Key Recovery"
        $OfficialName = "KP_KEY_RECOVERY"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Lifetime Signing"
        $OfficialName = "KP_LIFETIME_SIGNING"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "Key Pack Licenses"
        $OfficialName = "LICENSES"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    
        $IntendedPurpose = "License Server Verification"
        $OfficialName = "LICENSE_SERVER"
        $OfficialOID = $OIDHashTable.$OfficialName
        $szOIDString = "szOID_$OfficialName"
        $CertRequestConfigFileLine = "szOID_$OfficialName = `"$OfficialOID`""
        $ExtKeyUse = $AppPol = $OfficialOID
        
        [pscustomobject]@{
            IntendedPurpose                 = $IntendedPurpose
            OfficialName                    = $OfficialName
            OfficialOID                     = $OfficialOID
            szOIDString                     = $szOIDString
            CertRequestConfigFileLine       = $CertRequestConfigFileLine
            ExtKeyUse                       = $OfficialOID
            AppPol                          = $OfficialOID
        }
    }

    function Install-RSAT {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$False)]
            [string]$DownloadDirectory = "$HOME\Downloads",
    
            [Parameter(Mandatory=$False)]
            [switch]$AllowRestart,
    
            [Parameter(Mandatory=$False)]
            [switch]$Force
        )
    
        Write-Host "Please wait..."
    
        if (!$(Get-Module -ListAvailable -Name ActiveDirectory) -or $Force) {
            $OSInfo = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
            $OSCimInfo = Get-CimInstance Win32_OperatingSystem
            $OSArchitecture = $OSCimInfo.OSArchitecture
    
            if ([version]$OSCimInfo.Version -lt [version]"6.3") {
                Write-Error "This function only handles RSAT Installation for Windows 8.1 and higher! Halting!"
                $global:FunctionResult = "1"
                return
            }
            
            if ($OSInfo.ProductName -notlike "*Server*") {
                $KBCheck = [bool]$(Get-WmiObject -query 'select * from win32_quickfixengineering' | Where-Object {
                    $_.HotFixID -eq 'KB958830' -or $_.HotFixID -eq 'KB2693643'
                })
    
                if (!$KBCheck -or $Force) {
                    if ($([version]$OSCimInfo.Version).Major -lt 10 -and [version]$OSCimInfo.Version -ge [version]"6.3") {
                        if ($OSArchitecture -eq "64-bit") {
                            $OutFileName = "Windows8.1-KB2693643-x64.msu"
                        }
                        if ($OSArchitecture -eq "32-bit") {
                            $OutFileName = "Windows8.1-KB2693643-x86.msu"
                        }
    
                        $DownloadUrl = "https://download.microsoft.com/download/1/8/E/18EA4843-C596-4542-9236-DE46F780806E/$OutFileName"
                    }
                    if ($([version]$OSCimInfo.Version).Major -ge 10) {
                        if ([int]$OSInfo.ReleaseId -ge 1803) {
                            if ($OSArchitecture -eq "64-bit") {
                                $OutFileName = "WindowsTH-RSAT_WS_1803-x64.msu"
                            }
                            if ($OSArchitecture -eq "32-bit") {
                                $OutFileName = "WindowsTH-RSAT_WS_1803-x86.msu"
                            }
                        }
                        if ([int]$OSInfo.ReleaseId -ge 1709 -and [int]$OSInfo.ReleaseId -lt 1803) {
                            if ($OSArchitecture -eq "64-bit") {
                                $OutFileName = "WindowsTH-RSAT_WS_1709-x64.msu"
                            }
                            if ($OSArchitecture -eq "32-bit") {
                                $OutFileName = "WindowsTH-RSAT_WS_1709-x86.msu"
                            }
                        }
                        if ([int]$OSInfo.ReleaseId -lt 1709) {
                            if ($OSArchitecture -eq "64-bit") {
                                $OutFileName = "WindowsTH-RSAT_WS2016-x64.msu"
                            }
                            if ($OSArchitecture -eq "32-bit") {
                                $OutFileName = "WindowsTH-RSAT_WS2016-x86.msu"
                            }
                        }
    
                        $DownloadUrl = "https://download.microsoft.com/download/1/D/8/1D8B5022-5477-4B9A-8104-6A71FF9D98AB/$OutFileName"
                    }
    
                    try {
                        # Make sure the Url exists...
                        $HTTP_Request = [System.Net.WebRequest]::Create($DownloadUrl)
                        $HTTP_Response = $HTTP_Request.GetResponse()
                    }
                    catch {
                        Write-Error $_
                        $global:FunctionResult = "1"
                        return
                    }
    
                    try {
                        # Download via System.Net.WebClient is a lot faster than Invoke-WebRequest...
                        $WebClient = [System.Net.WebClient]::new()
                        $WebClient.Downloadfile($DownloadUrl, "$DownloadDirectory\$OutFileName")
                    }
                    catch {
                        Write-Error $_
                        $global:FunctionResult = "1"
                        return
                    }
    
                    Write-Host "Beginning installation..."
                    if ($AllowRestart) {
                        $Arguments = "`"$DownloadDirectory\$OutFileName`" /quiet /log:`"$DownloadDirectory\wusaRSATInstall.log`""
                    }
                    else {
                        $Arguments = "`"$DownloadDirectory\$OutFileName`" /quiet /norestart /log:`"$DownloadDirectory\wusaRSATInstall.log`""
                    }
                    #Start-Process -FilePath $(Get-Command wusa.exe).Source -ArgumentList "`"$DownloadDirectory\$OutFileName`" /quiet /log:`"$DownloadDirectory\wusaRSATInstall.log`"" -NoNewWindow -Wait
    
                    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
                    #$ProcessInfo.WorkingDirectory = $BinaryPath | Split-Path -Parent
                    $ProcessInfo.FileName = $(Get-Command wusa.exe).Source
                    $ProcessInfo.RedirectStandardError = $true
                    $ProcessInfo.RedirectStandardOutput = $true
                    #$ProcessInfo.StandardOutputEncoding = [System.Text.Encoding]::Unicode
                    #$ProcessInfo.StandardErrorEncoding = [System.Text.Encoding]::Unicode
                    $ProcessInfo.UseShellExecute = $false
                    $ProcessInfo.Arguments = $Arguments
                    $Process = New-Object System.Diagnostics.Process
                    $Process.StartInfo = $ProcessInfo
                    $Process.Start() | Out-Null
                    # Below $FinishedInAlottedTime returns boolean true/false
                    # Wait 20 seconds for wusa to finish...
                    $FinishedInAlottedTime = $Process.WaitForExit(20000)
                    if (!$FinishedInAlottedTime) {
                        $Process.Kill()
                    }
                    $stdout = $Process.StandardOutput.ReadToEnd()
                    $stderr = $Process.StandardError.ReadToEnd()
                    $AllOutput = $stdout + $stderr
    
                    # Check the log to make sure there weren't any errors
                    # NOTE: Get-WinEvent cmdlet does NOT work consistently on all Windows Operating Systems...
                    Write-Host "Reviewing wusa.exe logs..."
                    $EventLogReader = [System.Diagnostics.Eventing.Reader.EventLogReader]::new("$DownloadDirectory\wusaRSATInstall.log", [System.Diagnostics.Eventing.Reader.PathType]::FilePath)
                    [System.Collections.ArrayList]$EventsFromLog = @()
                    
                    $Event = $EventLogReader.ReadEvent()
                    $null = $EventsFromLog.Add($Event)
                    while ($Event -ne $null) {
                        $Event = $EventLogReader.ReadEvent()
                        $null = $EventsFromLog.Add($Event)
                    }
    
                    if ($EventsFromLog.LevelDisplayName -contains "Error") {
                        $ErrorRecord = $EventsFromLog | Where-Object {$_.LevelDisplayName -eq "Error"}
                        $ProblemDetails = $ErrorRecord.Properties.Value | Where-Object {$_ -match "[\w]"}
                        $ProblemDetailsString = $ProblemDetails[0..$($ProblemDetails.Count-2)] -join ": "
    
                        $ErrMsg = "wusa.exe failed to install '$DownloadDirectory\$OutFileName' due to '$ProblemDetailsString'. " +
                        "This could be because of a pending restart. Please restart $env:ComputerName and try the Install-RSAT function again."
                        Write-Error $ErrMsg
                        $global:FunctionResult = "1"
                        return
                    }
    
                    if ($AllowRestart) {
                        Restart-Computer -Confirm:$false -Force
                    }
                    else{
                        $Output = "RestartNeeded"
                    }
                }
            }
            if ($OSInfo.ProductName -like "*Server*") {
                #Import-Module ServerManager
                if (!$(Get-WindowsFeature RSAT-AD-Tools).Installed) {
                    Write-Host "Beginning installation..."
                    if ($AllowRestart) {
                        Install-WindowsFeature -Name RSAT -IncludeAllSubFeature -IncludeManagementTools -Restart
                    }
                    else {
                        Install-WindowsFeature -Name RSAT -IncludeAllSubFeature -IncludeManagementTools
                        $Output = "RestartNeeded"
                    }
                }
            }
        }
        else {
            Write-Warning "RSAT is already installed! No action taken."
        }
    
        if ($Output -eq "RestartNeeded") {
            Write-Warning "You must restart your computer in order to finish RSAT installation."
        }
    
        $Output
    }
    
    #endregion >> Libraries and Helper Functions
    

    #region >> Variable Definition And Validation

    # Make a working Directory Where Generated Certificates will be Saved
    if (Test-Path $CertGenWorking) {
        $NewDirName = NewUniqueString -PossibleNewUniqueString $($CertGenWorking | Split-Path -Leaf) -ArrayOfStrings $(Get-ChildItem -Path $($CertGenWorking | Split-Path -Parent) -Directory).Name
        $CertGenWorking = "$CertGenWorking`_Certs_$(Get-Date -Format MMddyy_hhmmss)"
    }
    if (!$(Test-Path $CertGenWorking)) {
        $null = New-Item -ItemType Directory -Path $CertGenWorking
    }

    # Check Cert:\CurrentUser\My for a Certificate with the same CN as our intended new Certificate.
    [array]$ExistingCertInStore = Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -match "CN=$CertificateCN,"}
    if ($ExistingCertInStore.Count -gt 0) {
        Write-Warning "There is already a Certificate in your Certificate Store under 'Cert:\CurrentUser\My' with Common Name (CN) $CertificateCN!"

        $ContinuePrompt = Read-Host -Prompt "Are you sure you want to continue? [Yes\No]"
        while ($ContinuePrompt -notmatch "Yes|yes|Y|y|No|no|N|n") {
            Write-Host "$ContinuePrompt is not a valid option. Please enter 'Yes' or 'No'"
            $ContinuePrompt = Read-Host -Prompt "Are you sure you want to continue? [Yes\No]"
        }

        if ($ContinuePrompt -match "Yes|yes|Y|y") {
            $ThumprintToAvoid = $ExistingCertInStore.Thumbprint
        }
        else {
            Write-Error "User chose not proceed due to existing Certificate concerns. Halting!"
            $global:FunctionResult = "1"
            return
        }
        
    }

    if (!$PSBoundParameters['BasisTemplate'] -and !$PSBoundParameters['IntendedPurposeValues']) {
        $BasisTemplate = "WebServer"
    } 
    
    if ($PSBoundParameters['BasisTemplate'] -and $PSBoundParameters['IntendedPurposeValues']) {
        Write-Error "The $($MyInvocation.MyCommand.Name) function must use either the -BasisTemplate parameter or the -IntendedPurposeValues parameter! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$MachineKeySet) {
        $MachineKeySetPrompt = "If you would like the private key exported, please enter 'False'. If you are " +
        "creating this certificate to be used in the User's security context (like for a developer to sign their code)," +
        "enter 'False'. If you are using this certificate for a service that runs in the Computer's security context " +
        "(such as a Web Server, Domain Controller, etc) enter 'True' [TRUE/FALSE]"
        $MachineKeySet = Read-Host -Prompt $MachineKeySetPrompt
        while ($MachineKeySet -notmatch "True|False") {
            Write-Host "$MachineKeySet is not a valid option. Please enter either 'True' or 'False'" -ForeGroundColor Yellow
            $MachineKeySet = Read-Host -Prompt $MachineKeySetPrompt
        }
    }
    $MachineKeySet = $MachineKeySet.ToUpper()
    $PrivateKeyExportableValue = $PrivateKeyExportableValue.ToUpper()
    $KeyUsageValueUpdated = "0x" + $KeyUsageValue

    if (!$SecureEmail) {
        $SecureEmail = Read-Host -Prompt "Are you using this new certificate for Secure E-Mail? [Yes/No]"
        while ($SecureEmail -notmatch "Yes|No") {
            Write-Host "$SecureEmail is not a vaild option. Please enter either 'Yes' or 'No'" -ForeGroundColor Yellow
            $SecureEmail = Read-Host -Prompt "Are you using this new certificate for Secure E-Mail? [Yes/No]"
        }
    }
    if ($SecureEmail -eq "Yes") {
        $KeySpecValue = "2"
        $SMIMEValue = "TRUE"
    }
    else {
        $KeySpecValue = "1"
        $SMIMEValue = "FALSE"
    }

    if (!$UserProtected) {
        $UserProtected = Read-Host -Prompt "Would you like to password protect the keys on this certificate? [True/False]"
        while ($UserProtected -notmatch "True|False") {
            Write-Host "$UserProtected is not a valid option. Please enter either 'True' or 'False'"
            $UserProtected = Read-Host -Prompt "Would you like to password protect the keys on this certificate? [True/False]"
        }
    }
    if ($UserProtected -eq "True") {
        $MachineKeySet = "FALSE"
    }
    $UserProtected = $UserProtected.ToUpper()

    if (!$UseOpenSSL) {
        $UseOpenSSL = Read-Host -Prompt "Would you like to use Win32 OpenSSL to extract public cert and private key from the Microsoft .pfx file? [Yes/No]"
        while ($UseOpenSSL -notmatch "Yes|No") {
            Write-Host "$UseOpenSSL is not a valid option. Please enter 'Yes' or 'No'"
            $UseOpenSSL = Read-Host -Prompt "Would you like to use Win32 OpenSSL to extract public cert and private key from the Microsoft .pfx file? [Yes/No]"
        }
    }

    $Win32CompSys = Get-CimInstance Win32_ComputerSystem
    $DomainPrefix = $($Win32CompSys.Domain).Split(".") | Select-Object -Index 0
    $DomainSuffix = $($Win32CompSys.Domain).Split(".") | Select-Object -Index 1
    $Hostname = $Win32CompSys.Name
    $HostFQDN = $Hostname+'.'+$DomainPrefix+'.'+$DomainSuffix

    # If using Win32 OpenSSL, check to make sure the path to binary is valid...
    if ($UseOpenSSL -eq "Yes" -and !$CSRGenOnly) {
        if ($PathToWin32OpenSSL) {
            if (!$(Test-Path $PathToWin32OpenSSL)) {
                $OpenSSLPathDNE = $True
            }

            $env:Path = "$PathToWin32OpenSSL;$env:Path"
        }

        # Check is openssl.exe is already available
        if ([bool]$(Get-Command openssl -ErrorAction SilentlyContinue)) {
            # Check to make sure the version is at least 1.1.0
            $OpenSSLExeInfo = Get-Item $(Get-Command openssl).Source
            $OpenSSLExeVersion = [version]$($OpenSSLExeInfo.VersionInfo.ProductVersion -split '-')[0]
        }

        # We need at least vertion 1.1.0 of OpenSSL
        if ($OpenSSLExeVersion.Major -lt 1 -or $($OpenSSLExeVersion.Major -eq 1 -and $OpenSSLExeVersion.Minor -lt 1) -or
        ![bool]$(Get-Command openssl -ErrorAction SilentlyContinue)
        ) {
            if ($PSVersionTable.PSEdition -eq "Desktop") {[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"}
            $OpenSSLWinBinariesUrl = 'https://indy.fulgan.com/SSL/'
            #$OpenSSLWinBinariesUrl = "http://wiki.overbyte.eu/wiki/index.php/ICS_Download"
            $IWRResult = Invoke-WebRequest -Uri $OpenSSLWinBinariesUrl -UseBasicParsing
            if ($OpenSSLWinBinariesUrl -match "fulgan") {
                $LatestOpenSSLWinBinaryUrl = $OpenSSLWinBinariesUrl + $($IWRResult.Links | Where-Object {$_.OuterHTML -match "win64\.zip"})[-1].href
            }
            if ($OpenSSLWinBinariesUrl -match "overbyte") {
                $LatestOpenSSLWinBinaryUrl = $($IWRResult.Links | Where-Object {$_.OuterHTML -match "win64\.zip"})[0].href
            }
            $OutputFileName = $($LatestOpenSSLWinBinaryUrl -split '/')[-1]
            $OutputFilePath = "$HOME\Downloads\$OutputFileName"
            Invoke-WebRequest -Uri $LatestOpenSSLWinBinaryUrl -OutFile $OutputFilePath
            $ExpansionDirectory = $OutputFilePath -replace '\.zip$',''
            if (Test-Path $ExpansionDirectory) {
                Remove-Item "$ExpansionDirectory\*" -Recurse -Force
            }
            else {
                $null = New-Item -ItemType Directory -Path $ExpansionDirectory
            }
            $null = Expand-Archive -Path $OutputFilePath -DestinationPath $ExpansionDirectory -Force
            $WinOpenSSLFiles = Get-ChildItem -Path $ExpansionDirectory
            $WinOpenSSLParentDir = $WinOpenSSLFiles[0].Directory.FullName
            [System.Collections.Arraylist][array]$CurrentEnvPathArray = $env:Path -split ';' | Where-Object {![System.String]::IsNullOrWhiteSpace($_)}
            if ($CurrentEnvPathArray -notcontains $WinOpenSSLParentDir) {
                $CurrentEnvPathArray.Insert(0,$WinOpenSSLParentDir)
                $env:Path = $CurrentEnvPathArray -join ';'
            }
        }

        if (![bool]$(Get-Command openssl -ErrorAction SilentlyContinue)) {
            Write-Error "Problem setting openssl.exe to `$env:Path! Halting!"
            $global:FunctionResult = "1"
            return
        }

        $PathToWin32OpenSSL = $(Get-Command openssl).Source | Split-Path -Parent
    }

    # Check for contradictions in $MachineKeySet value and $PrivateKeyExportableValue and $UseOpenSSL
    if ($MachineKeySet -eq "TRUE" -and $PrivateKeyExportableValue -eq "TRUE") {
        $WrnMsg = "MachineKeySet and PrivateKeyExportableValue have both been set to TRUE, but " +
        "Private Key cannot be exported if MachineKeySet = TRUE!"
        Write-Warning $WrnMsg

        $ShouldPrivKeyBeExportable = Read-Host -Prompt "Would you like the Private Key to be exportable? [Yes/No]"
        while ($ShouldPrivKeyBeExportable -notmatch "Yes|yes|Y|y|No|no|N|n") {
            Write-Host "$ShouldPrivKeyBeExportable is not a valid option. Please enter either 'Yes' or 'No'" -ForeGroundColor Yellow
            $ShouldPrivKeyBeExportable = Read-Host -Prompt "Would you like the Private Key to be exportable? [Yes/No]"
        }
        if ($ShouldPrivKeyBeExportable -match "Yes|yes|Y|y") {
            $MachineKeySet = "FALSE"
            $PrivateKeyExportableValue = "TRUE"
        }
        else {
            $MachineKeySet = "TRUE"
            $PrivateKeyExportableValue = "FALSE"
        }
    }
    if ($MachineKeySet -eq "TRUE" -and $UseOpenSSL -eq "Yes") {
        $WrnMsg = "MachineKeySet and UseOpenSSL have both been set to TRUE. OpenSSL targets a .pfx file exported from the " +
        "local Certificate Store. If MachineKeySet is set to TRUE, no .pfx file will be exported from the " +
        "local Certificate Store!"
        Write-Warning $WrnMsg
        $ShouldUseOpenSSL = Read-Host -Prompt "Would you like to use OpenSSL in order to generate keys in formats compatible with Linux? [Yes\No]"
        while ($ShouldUseOpenSSL -notmatch "Yes|yes|Y|y|No|no|N|n") {
            Write-Host "$ShouldUseOpenSSL is not a valid option. Please enter either 'Yes' or 'No'" -ForeGroundColor Yellow
            $ShouldUseOpenSSL = Read-Host -Prompt "Would you like to use OpenSSL in order to generate keys in formats compatible with Linux? [Yes\No]"
        }
        if ($ShouldUseOpenSSL -match "Yes|yes|Y|y") {
            $MachineKeySet = "FALSE"
            $UseOpenSSL = "Yes"
        }
        else {
            $MachineKeySet = "TRUE"
            $UseOpenSSL = "No"
        }
    }
    if ($MachineKeySet -eq "FALSE" -and $PFXPwdAsSecureString -eq $null -and !$CSRGenOnly) {
        $PFXPwdAsSecureStringA = Read-Host -Prompt "Please enter a password to use when exporting .pfx bundle certificate/key bundle" -AsSecureString
        $PFXPwdAsSecureStringB = Read-Host -Prompt "Please enter the same password again" -AsSecureString

        while ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PFXPwdAsSecureStringA)) -ne
        [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PFXPwdAsSecureStringB))
        ) {
            Write-Warning "Passwords don't match!"
            $PFXPwdAsSecureStringA = Read-Host -Prompt "Please enter a password to use when exporting .pfx bundle certificate/key bundle" -AsSecureString
            $PFXPwdAsSecureStringB = Read-Host -Prompt "Please enter the same password again" -AsSecureString
        }

        $PFXPwdAsSecureString = $PFXPwdAsSecureStringA
    }

    if (!$CSRGenOnly) {
        if ($PFXPwdAsSecureString.GetType().Name -eq "String") {
            $PFXPwdAsSecureString = ConvertTo-SecureString -String $PFXPwdAsSecureString -Force -AsPlainText
        }
    }

    # If the workstation being used to request the Certificate is part of the same Domain as the Issuing Certificate Authority, leverage certutil...
    if (!$ADCSWebEnrollmentUrl -and !$CSRGenOnly) {
        #$NeededRSATFeatures = @("RSAT","RSAT-Role-Tools","RSAT-AD-Tools","RSAT-AD-PowerShell","RSAT-ADDS","RSAT-AD-AdminCenter","RSAT-ADDS-Tools","RSAT-ADLDS")

        if (!$(Get-Module -ListAvailable -Name ActiveDirectory)) {
            try {
                $InstallRSATResult = Install-RSAT -ErrorAction Stop
                if ($InstallRSATResult -eq "RestartNeeded") {
                    $WrnMsg = "$env:ComputerName must be restarted post RSAT install in order to use the " +
                    "ActiveDirectory Module. The Generate-Certificate function can continue but it cannot " +
                    "verify that '$BasisTemplate' is appropriate for the requested certificate."
                    Write-Warning $WrnMsg
                }
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
        if (!$(Get-Module -Name ActiveDirectory)) {
            try {
                if ($PSVersionTable.PSEdition -eq "Core") {
                    Import-WinModule ActiveDirectory -ErrorAction Stop
                }
                else {
                    Import-Module ActiveDirectory -ErrorAction Stop
                }
            }
            catch {
                Write-Warning $_.Exception.Message
            }
        }

        $AvailableCertificateAuthorities = (((certutil | Select-String -Pattern "Config:") -replace "Config:[\s]{1,32}``") -replace "'","").trim()
        $IssuingCertAuth = foreach ($obj1 in $AvailableCertificateAuthorities) {
            $obj2 = certutil -config $obj1 -CAInfo type | Select-String -Pattern "Enterprise Subordinate CA" | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
            if ($obj2 -eq "Enterprise Subordinate CA") {
                $obj1
            }
        }
        $IssuingCertAuthFQDN = $IssuingCertAuth.Split("\") | Select-Object -Index 0
        $IssuingCertAuthHostname = $IssuingCertAuth.Split("\") | Select-Object -Index 1
        $null = certutil -config $IssuingCertAuth -ping
        if ($LASTEXITCODE -eq 0) {
            Write-Verbose "Successfully contacted the Issuing Certificate Authority: $IssuingCertAuth"
        }
        else {
            Write-Verbose "Cannot contact the Issuing Certificate Authority: $IssuingCertAuth. Halting!"
            $global:FunctionResult = "1"
            return
        }
        
        if ($PSBoundParameters['BasisTemplate']) {
            # $AllAvailableCertificateTemplates Using PSPKI
            # $AllAvailableCertificateTemplates = Get-PSPKICertificateTemplate
            # Using certutil
            $AllAvailableCertificateTemplatesPrep = certutil -ADTemplate
            # Determine valid CN using PSPKI
            # $ValidCertificateTemplatesByCN = $AllAvailableCertificateTemplatesPrep.Name
            # Determine valid displayNames using certutil
            $ValidCertificateTemplatesByCN = foreach ($obj1 in $AllAvailableCertificateTemplatesPrep) {
                $obj2 = $obj1 | Select-String -Pattern "[\w]{1,32}:[\s][\w]" | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
                $obj3 = $obj2 -replace ':[\s][\w]',''
                $obj3
            }
            # Determine valid displayNames using PSPKI
            # $ValidCertificateTemplatesByDisplayName = $AllAvailableCertificateTemplatesPrep.DisplayName
            # Determine valid displayNames using certutil
            $ValidCertificateTemplatesByDisplayName = foreach ($obj1 in $AllAvailableCertificateTemplatesPrep) {
                $obj2 = $obj1 | Select-String -Pattern "\:(.*)\-\-" | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
                $obj3 = ($obj2 -replace ": ","") -replace " --",""
                $obj3
            }

            if ($ValidCertificateTemplatesByCN -notcontains $BasisTemplate -and $ValidCertificateTemplatesByDisplayName -notcontains $BasisTemplate) {
                $TemplateMsg = "You must base your New Certificate Template on an existing Certificate Template.`n" +
                "To do so, please enter either the displayName or CN of the Certificate Template you would like to use as your base.`n" +
                "Valid displayName values are as follows:`n$($ValidDisplayNamesAsString -join "`n")`n" +
                "Valid CN values are as follows:`n$($ValidCNNamesAsString -join "`n")"

                $BasisTemplate = Read-Host -Prompt "Please enter the displayName or CN of the Certificate Template you would like to use as your base"
                while ($($ValidCertificateTemplatesByCN + $ValidCertificateTemplatesByDisplayName) -notcontains $BasisTemplate) {
                    Write-Host "$BasisTemplate is not a valid displayName or CN of an existing Certificate Template on Issuing Certificate Authority $IssuingCertAuth!" -ForeGroundColor Yellow
                    $BasisTemplate = Read-Host -Prompt "Please enter the displayName or CN of the Certificate Template you would like to use as your base"
                }
            }

            # Get all Certificate Template Properties of the Basis Template
            $LDAPSearchBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=$DomainPrefix,DC=$DomainSuffix"

            # Set displayName and CN Values for user-provided $BasisTemplate
            if ($ValidCertificateTemplatesByCN -contains $BasisTemplate) {
                $cnForBasisTemplate = $BasisTemplate
                if ($InstallRSATResult -eq "RestartNeeded") {
                    Write-Verbose "Unable to use 'Get-ADObject' from ActiveDirectory Module without restart..."
                }
                else {
                    if ([bool]$(Get-Command Get-ADObject -ErrorAction SilentlyContinue)) {
                        try {
                            $CertificateTemplateLDAPObject = Get-ADObject -SearchBase $LDAPSearchBase -Filter "cn -eq '$cnForBasisTemplate'"
                            $AllCertificateTemplateProperties = Get-ADObject -SearchBase $LDAPSearchBase -Filter "cn -eq '$cnForBasisTemplate'" -Properties *
                            $displayNameForBasisTemplate = $AllCertificateTemplateProperties.DisplayName
                        }
                        catch {
                            Write-Waring $($_ | Out-String)
                        }
                    }
                }
            }
            if ($ValidCertificateTemplatesByDisplayName -contains $BasisTemplate) {
                $displayNameForBasisTemplate = $BasisTemplate
                if ($InstallRSATResult -eq "RestartNeeded") {
                    Write-Verbose "Unable to use 'Get-ADObject' from ActiveDirectory Module without restart..."
                }
                else {
                    if ([bool]$(Get-Command Get-ADObject -ErrorAction SilentlyContinue)) {
                        try {
                            $CertificateTemplateLDAPObject = Get-ADObject -SearchBase $LDAPSearchBase -Filter "displayName -eq '$displayNameForBasisTemplate'"
                            $AllCertificateTemplateProperties = Get-ADObject -SearchBase $LDAPSearchBase -Filter "displayName -eq '$displayNameForBasisTemplate'" -Properties *
                            $cnForBasisTemplate = $AllCertificateTemplateProperties.CN
                        }
                        catch {
                            Write-Warning $($_ | Out-String)
                        }
                    }
                }
            }

            # Validate $ProviderNameValue
            # All available Cryptographic Providers (CSPs) are as follows:
            $PossibleProvidersPrep = certutil -csplist | Select-String "Provider Name" -Context 0,1
            $PossibleProviders = foreach ($obj1 in $PossibleProvidersPrep) {
                $obj2 = $obj1.Context.PostContext | Select-String 'FAIL' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Success
                $obj3 = $obj1.Context.PostContext | Select-String 'not ready' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Success
                if ($obj2 -ne "True" -and $obj3 -ne "True") {
                    $obj1.Line -replace "Provider Name: ",""
                }
            }
            # Available Cryptographic Providers (CSPs) based on user choice in Certificate Template (i.e. $BasisTemplate)
            # Does the Basis Certificate Template LDAP Object have an attribute called pKIDefaultCSPs that is set?
            if ($AllCertificateTemplateProperties) {
                $CertificateTemplateLDAPObjectSetAttributes = $AllCertificateTemplateProperties.PropertyNames
                if ($CertificateTemplateLDAPObjectSetAttributes -notcontains "pKIDefaultCSPs") {
                    $PKIMsg = "The Basis Template $BasisTemplate does NOT have the attribute pKIDefaultCSPs set. " +
                    "This means that Cryptographic Providers are NOT Limited, and (almost) any ProviderNameValue is valid"
                    Write-Host $PKIMsg
                }
                else {
                    $AvailableCSPsBasedOnCertificateTemplate = $AllCertificateTemplateProperties.pkiDefaultCSPs -replace '[0-9],',''
                    if ($AvailableCSPsBasedOnCertificateTemplate -notcontains $ProviderNameValue) {
                        Write-Warning "$ProviderNameValue is not one of the available Provider Names on Certificate Template $BasisTemplate!"
                        Write-Host "Valid Provider Names based on your choice in Basis Certificate Template are as follows:`n$($AvailableCSPsBasedOnCertificateTemplate -join "`n")"
                        $ProviderNameValue = Read-Host -Prompt "Please enter the name of the Cryptographic Provider (CSP) you would like to use"
                        while ($AvailableCSPsBasedOnCertificateTemplate -notcontains $ProviderNameValue) {
                            Write-Warning "$ProviderNameValue is not one of the available Provider Names on Certificate Template $BasisTemplate!"
                            Write-Host "Valid Provider Names based on your choice in Basis Certificate Template are as follows:`n$($AvailableCSPsBasedOnCertificateTemplate -join "`n")"
                            $ProviderNameValue = Read-Host -Prompt "Please enter the name of the Cryptographic Provider (CSP) you would like to use"
                        }
                    }
                }
            }
        }
    }
    # If the workstation being used to request the Certificate is NOT part of the same Domain as the Issuing Certificate Authority, use ADCS Web Enrollment Site...
    if ($ADCSWebEnrollmentUrl -and !$CSRGenOnly) {
        # Make sure there is no trailing / on $ADCSWebEnrollmentUrl
        if ($ADCSWebEnrollmentUrl.EndsWith('/')) {
            $ADCSWebEnrollmentUrl = $ADCSWebEnrollmentUrl.Substring(0,$ADCSWebEnrollmentUrl.Length-1)
        } 

        # The IIS Web Server hosting ADCS Web Enrollment may be configured for Windows Authentication, Basic Authentication, or both.
        if ($ADCSWebAuthType -eq "Windows") {
            if (!$ADCSWebCreds) {
                if (!$ADCSWebAuthUserName) {
                    $ADCSWebAuthUserName = Read-Host -Prompt "Please specify the AD account to be used for ADCS Web Enrollment authentication."
                    # IMPORTANT NOTE: $ADCSWebAuthUserName should NOT include the domain prefix. Example: testadmin
                }
                if ($ADCSWebAuthUserName -match "[\w\W]\\[\w\W]") {
                    $ADCSWebAuthUserName = $ADCSWebAuthUserName.Split("\")[1]
                }

                if (!$ADCSWebAuthPass) {
                    $ADCSWebAuthPass = Read-Host -Prompt "Please enter a password to be used for ADCS Web Enrollment authentication" -AsSecureString
                }

                $ADCSWebCreds = New-Object System.Management.Automation.PSCredential ($ADCSWebAuthUserName, $ADCSWebAuthPass)
            }

            # Test Connection to $ADCSWebEnrollmentUrl
            # Validate $ADCSWebEnrollmentUrl...
            $StatusCode = $(Invoke-WebRequest -Uri "$ADCSWebEnrollmentUrl/" -Credential $ADCSWebCreds).StatusCode
            if ($StatusCode -eq "200") {
                Write-Host "Connection to $ADCSWebEnrollmentUrl was successful...continuing"
            }
            else {
                Write-Host "Connection to $ADCSWebEnrollmentUrl was NOT successful. Please check your credentials and/or DNS."
                $global:FunctionResult = "1"
                return
            }
        }
        if ($ADCSWebAuthType -eq "Basic") {
            if (!$ADCSWebAuthUserName) {
                $PromptMsg = "Please specify the AD account to be used for ADCS Web Enrollment authentication. " +
                "Please *include* the domain prefix. Example: test\testadmin"
                $ADCSWebAuthUserName = Read-Host -Prompt $PromptMsg
            }
            while (![bool]$($ADCSWebAuthUserName -match "[\w\W]\\[\w\W]")) {
                Write-Host "Please include the domain prefix before the username. Example: test\testadmin"
                $ADCSWebAuthUserName = Read-Host -Prompt $PromptMsg
            }

            if (!$ADCSWebAuthPass) {
                $ADCSWebAuthPass = Read-Host -Prompt "Please enter a password to be used for ADCS Web Enrollment authentication" -AsSecureString
            }
            # If $ADCSWebAuthPass is a Secure String, convert it back to Plaintext
            if ($ADCSWebAuthPass.GetType().Name -eq "SecureString") {
                $ADCSWebAuthPass = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($ADCSWebAuthPass))
            }

            $pair = "${$ADCSWebAuthUserName}:${$ADCSWebAuthPass}"
            $bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
            $base64 = [System.Convert]::ToBase64String($bytes)
            $basicAuthValue = "Basic $base64"
            $headers = @{Authorization = $basicAuthValue}

            # Test Connection to $ADCSWebEnrollmentUrl
            # Validate $ADCSWebEnrollmentUrl...
            $StatusCode = $(Invoke-WebRequest -Uri "$ADCSWebEnrollmentUrl/" -Headers $headers).StatusCode
            if ($StatusCode -eq "200") {
                Write-Host "Connection to $ADCSWebEnrollmentUrl was successful...continuing" -ForeGroundColor Green
            }
            else {
                Write-Error "Connection to $ADCSWebEnrollmentUrl was NOT successful. Please check your credentials and/or DNS."
                $global:FunctionResult = "1"
                return
            }
        }

        if ($PSBoundParameters['BasisTemplate']) {
            # Check available Certificate Templates...
            if ($ADCSWebAuthType -eq "Windows") {
                $CertTemplCheckInitialResponse = Invoke-WebRequest -Uri "$ADCSWebEnrollmentUrl/certrqxt.asp" -Credential $ADCSWebCreds
            }
            if ($ADCSWebAuthType -eq "Basic") {
                $CertTemplCheckInitialResponse = Invoke-WebRequest -Uri "$ADCSWebEnrollmentUrl/certrqxt.asp" -Headers $headers
            }

            $ValidADCSWebEnrollCertTemplatesPrep = ($CertTemplCheckInitialResponse.RawContent.Split("`r") | Select-String -Pattern 'Option Value=".*').Matches.Value
            $ValidADCSWEbEnrollCertTemplates = foreach ($obj1 in $ValidADCSWebEnrollCertTemplatesPrep) {
                $obj1.Split(";")[1]
            }
            # Validate specified Certificate Template...
            while ($ValidADCSWebEnrollCertTemplates -notcontains $BasisTemplate) {
                Write-Warning "$BasisTemplate is not on the list of available Certificate Templates on the ADCS Web Enrollment site."
                $DDMsg = "IMPORTANT NOTE: For a Certificate Template to appear in the Certificate Template drop-down on the ADCS " +
                "Web Enrollment site, the msPKITemplateSchemaVersion attribute MUST BE '2' or '1' AND pKIExpirationPeriod MUST " +
                "BE 1 year or LESS"
                Write-Host $DDMsg -ForeGroundColor Yellow
                Write-Host "Certificate Templates available via ADCS Web Enrollment are as follows:`n$($ValidADCSWebEnrollCertTemplates -join "`n")"
                $BasisTemplate = Read-Host -Prompt "Please enter the name of an existing Certificate Template that you would like your New Certificate to be based on"
            }

            $CertTemplvsCSPHT = @{}
            $ValidADCSWebEnrollCertTemplatesPrep | foreach {
                $key = $($_ -split ";")[1]
                $value = [array]$($($_ -split ";")[8] -split "\?")
                $CertTemplvsCSPHT.Add($key,$value)
            }
            
            $ValidADCSWebEnrollCSPs = $CertTemplvsCSPHT.$BasisTemplate

            while ($ValidADCSWebEnrollCSPs -notcontains $ProviderNameValue) {
                $PNMsg = "$ProviderNameVaule is not a valid Provider Name. Valid Provider Names based on your choice in Basis " +
                "Certificate Template are as follows:`n$($ValidADCSWebEnrollCSPs -join "`n")"
                Write-Host $PNMsg
                $ProviderNameValue = Read-Host -Prompt "Please enter the name of the Cryptographic Provider (CSP) you would like to use"
            }
        }
    }
    
    #endregion >> Variable Definition And Validation
    

    #region >> Writing the Certificate Request Config File

    # This content is saved to $CertGenWorking\$CertificateRequestConfigFile
    # For more information about the contents of the config file, see: https://technet.microsoft.com/en-us/library/hh831574(v=ws.11).aspx 

    Set-Content -Value '[Version]' -Path "$CertGenWorking\$CertificateRequestConfigFile"
    Add-Content -Value 'Signature="$Windows NT$"' -Path "$CertGenWorking\$CertificateRequestConfigFile"
    Add-Content -Value "`n`r" -Path "$CertGenWorking\$CertificateRequestConfigFile"
    Add-Content -Value '[NewRequest]' -Path "$CertGenWorking\$CertificateRequestConfigFile"
    Add-Content -Value "FriendlyName = $CertificateCN" -Path "$CertGenWorking\$CertificateRequestConfigFile"

    # For below Subject, for a wildcard use "CN=*.DOMAIN.COM"
    Add-Content -Value "Subject = `"CN=$CertificateCN,OU=$OrganizationalUnit,O=$Organization,L=$Locality,S=$State,C=$Country`"" -Path $CertGenWorking\$CertificateRequestConfigFile

    Add-Content -Value "KeyLength = $KeyLength" -Path "$CertGenWorking\$CertificateRequestConfigFile"

    Add-Content -Value "HashAlgorithm = $HashAlgorithmValue" -Path "$CertGenWorking\$CertificateRequestConfigFile"

    Add-Content -Value "EncryptionAlgorithm = $EncryptionAlgorithmValue" -Path "$CertGenWorking\$CertificateRequestConfigFile"

    Add-Content -Value "Exportable = $PrivateKeyExportableValue" -Path "$CertGenWorking\$CertificateRequestConfigFile"

    Add-Content -Value "KeySpec = $KeySpecValue" -Path "$CertGenWorking\$CertificateRequestConfigFile"

    Add-Content -Value "KeyUsage = $KeyUsageValueUpdated" -Path "$CertGenWorking\$CertificateRequestConfigFile"

    Add-Content -Value "MachineKeySet = $MachineKeySet" -Path "$CertGenWorking\$CertificateRequestConfigFile"

    Add-Content -Value "SMIME = $SMIMEValue" -Path "$CertGenWorking\$CertificateRequestConfigFile"

    Add-Content -Value 'PrivateKeyArchive = FALSE' -Path "$CertGenWorking\$CertificateRequestConfigFile"

    Add-Content -Value "UserProtected = $UserProtected" -Path "$CertGenWorking\$CertificateRequestConfigFile"

    Add-Content -Value 'UseExistingKeySet = FALSE' -Path "$CertGenWorking\$CertificateRequestConfigFile"

    # Next, get the $ProviderTypeValue based on $ProviderNameValue
    if ($PSBoundParameters['BasisTemplate']) {
        $ProviderTypeValuePrep = certutil -csplist | Select-String $ProviderNameValue -Context 0,1
        $ProviderTypeValue = $ProviderTypeValuePrep.Context.PostContext | Select-String -Pattern '[0-9]{1,2}' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
        Add-Content -Value "ProviderName = `"$ProviderNameValue`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"
        Add-Content -Value "ProviderType = $ProviderTypeValue" -Path "$CertGenWorking\$CertificateRequestConfigFile"
    }
    else {
        $ProviderNameValue = "Microsoft RSA SChannel Cryptographic Provider"
        $ProviderTypeValue = "12"
        Add-Content -Value "ProviderName = `"$ProviderNameValue`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"
        Add-Content -Value "ProviderType = $ProviderTypeValue" -Path "$CertGenWorking\$CertificateRequestConfigFile"
    }

    Add-Content -Value "RequestType = $RequestTypeValue" -Path "$CertGenWorking\$CertificateRequestConfigFile"

    <#
    TODO: Logic for self-signed and/or self-issued certificates that DO NOT generate a CSR and DO NOT submit to Certificate Authority
    if ($RequestTypeValue -eq "Cert") {
        $ValidityPeriodValue = Read-Host -Prompt "Please enter the length of time that the certificate will be valid for.
        #NOTE: Values must be in Months or Years. For example '6 months' or '2 years'"
        $ValidityPeriodPrep = $ValidityPeriodValue.Split(" ") | Select-Object -Index 1
        if ($ValidityPeriodPrep.EndsWith("s")) {
            $ValidityPeriod = $ValidityPeriodPrep.substring(0,1).toupper()+$validityPeriodPrep.substring(1).tolower()
        }
        else {
            $ValidityPeriod = $ValidityPeriodPrep.substring(0,1).toupper()+$validityPeriodPrep.substring(1).tolower()+'s'
        }
        $ValidityPeriodUnits = $ValidityPeriodValue.Split(" ") | Select-Object -Index 0

        Add-Content -Value "ValidityPeriodUnits = $ValidityPeriodUnits" -Path "$CertGenWorking\$CertificateRequestConfigFile"
        Add-Content -Value "ValidityPeriod = $ValidityPeriod" -Path "$CertGenWorking\$CertificateRequestConfigFile"
    }
    #>

    $GetIntendedPurposePSObjects = Get-IntendedPurposePSObjects -OIDHashTable $OIDHashTable
    [System.Collections.ArrayList]$RelevantPSObjects = @()
    if ($IntendedPurposeValues) {
        foreach ($IntendedPurposeValue in [array]$IntendedPurposeValues) {
            foreach ($PSObject in $GetIntendedPurposePSObjects) {
                if ($IntendedPurposeValue -eq $PSObject.IntendedPurpose) {
                    $null = $RelevantPSObjects.Add($PSObject)
                }
            }
        }
    }
    else {
        [array]$OfficialOIDs = $AllCertificateTemplateProperties.pKIExtendedKeyUsage

        [System.Collections.ArrayList]$RelevantPSObjects = @()
        foreach ($OID in $OfficialOIDs) {
            foreach ($PSObject in $GetIntendedPurposePSObjects) {
                if ($OID -eq $PSObject.OfficialOID) {
                    $null = $RelevantPSObjects.Add($PSObject)
                }
            }
        }
    }

    if ($IntendedPurposeValues) {
        Add-Content -Value "`n`r" -Path "$CertGenWorking\$CertificateRequestConfigFile"
        Add-Content -Value '[Strings]' -Path "$CertGenWorking\$CertificateRequestConfigFile"
        Add-Content -Value 'szOID_ENHANCED_KEY_USAGE = "2.5.29.37"' -Path "$CertGenWorking\$CertificateRequestConfigFile"

        foreach ($line in $RelevantPSObjects.CertRequestConfigFileLine) {
            Add-Content -Value $line -Path "$CertGenWorking\$CertificateRequestConfigFile"
        }

        Add-Content -Value "`n`r" -Path "$CertGenWorking\$CertificateRequestConfigFile"
        Add-Content -Value '[Extensions]' -Path "$CertGenWorking\$CertificateRequestConfigFile"

        [array]$szOIDArray = $RelevantPSObjects.szOIDString
        $szOIDArrayFirstItem = $szOIDArray[0]
        Add-Content -Value "%szOID_ENHANCED_KEY_USAGE%=`"{text}%$szOIDArrayFirstItem%,`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"

        foreach ($string in $szOIDArray[1..$($szOIDArray.Count-1)]) {
            Add-Content -Value "_continue_ = `"%$string%`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"
        }
    }

    if ($SANObjectsToAdd) {
        if (![bool]$($(Get-Content "$CertGenWorking\$CertificateRequestConfigFile") -match "\[Extensions\]")) {
            Add-Content -Value "`n`r" -Path "$CertGenWorking\$CertificateRequestConfigFile"
            Add-Content -Value '[Extensions]' -Path "$CertGenWorking\$CertificateRequestConfigFile"
        }

        Add-Content -Value '2.5.29.17 = "{text}"' -Path "$CertGenWorking\$CertificateRequestConfigFile"
        
        if ($SANObjectsToAdd -contains "DNS") {
            if (!$DNSSANObjects) {
                $DNSSANObjects = Read-Host -Prompt "Please enter one or more DNS SAN objects separated by commas`nExample: www.fabrikam.com, www.contoso.org"
                $DNSSANObjects = $DNSSANObjects.Split(",").Trim()
            }

            foreach ($DNSSAN in $DNSSANObjects) {
                Add-Content -Value "_continue_ = `"dns=$DNSSAN&`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"
            }
        }
        if ($SANObjectsToAdd -contains "Distinguished Name") {
            if (!$DistinguishedNameSANObjects) {
                $DNMsg = "Please enter one or more Distinguished Name SAN objects ***separated by semi-colons***`n" +
                "Example: CN=www01,OU=Web Servers,DC=fabrikam,DC=com; CN=www01,OU=Load Balancers,DC=fabrikam,DC=com"
                $DistinguishedNameSANObjects = Read-Host -Prompt $DNMsg
                $DistinguishedNameSANObjects = $DistinguishedNameSANObjects.Split(";").Trim()
            }

            foreach ($DNObj in $DistinguishedNameSANObjects) {
                Add-Content -Value "_continue_ = `"dn=$DNObj&`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"
            }
        }
        if ($SANObjectsToAdd -contains "URL") {
            if (!$URLSANObjects) {
                $URLMsg = "Please enter one or more URL SAN objects separated by commas`nExample: " +
                "http://www.fabrikam.com, http://www.contoso.com"
                $URLSANObjects = Read-Host -Prompt $URLMsg
                $URLSANObjects = $URLSANObjects.Split(",").Trim()
            }
            
            foreach ($UrlObj in $URLSANObjects) {
                Add-Content -Value "_continue_ = `"url=$UrlObj&`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"
            }
        }
        if ($SANObjectsToAdd -contains "IP Address") {
            if (!$IPAddressSANObjects) {
                $IPAddressSANObjects = Read-Host -Prompt "Please enter one or more IP Addresses separated by commas`nExample: 172.31.10.13, 192.168.2.125"
                $IPAddressSANObjects = $IPAddressSANObjects.Split(",").Trim()
            }

            foreach ($IPAddr in $IPAddressSANObjects) {
                if (!$(TestIsValidIPAddress -IPAddress $IPAddr)) {
                    Write-Error "$IPAddr is not a valid IP Address! Halting!"

                    # Cleanup
                    Remove-Item $CertGenWorking -Recurse -Force

                    $global:FunctionResult = "1"
                    return
                }
            }
            
            foreach ($IPAddr in $IPAddressSANObjects) {
                Add-Content -Value "_continue_ = `"ipaddress=$IPAddr&`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"
            }
        }
        if ($SANObjectsToAdd -contains "Email") {
            if (!$EmailSANObjects) {
                $EmailSANObjects = Read-Host -Prompt "Please enter one or more Email SAN objects separated by commas`nExample: mike@fabrikam.com, hazem@fabrikam.com"
                $EmailSANObjects = $EmailSANObjects.Split(",").Trim()
            }
            
            foreach ($EmailAddr in $EmailSANObjectsArray) {
                Add-Content -Value "_continue_ = `"email=$EmailAddr&`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"
            }
        }
        if ($SANObjectsToAdd -contains "UPN") {
            if (!$UPNSANObjects) {
                $UPNSANObjects = Read-Host -Prompt "Please enter one or more UPN SAN objects separated by commas`nExample: mike@fabrikam.com, hazem@fabrikam.com"
                $UPNSANObjects = $UPNSANObjects.Split(",").Trim()
            }
            
            foreach ($UPN in $UPNSANObjects) {
                Add-Content -Value "_continue_ = `"upn=$UPN&`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"
            }
        }
        if ($SANObjectsToAdd -contains "GUID") {
            if (!$GUIDSANObjects) {
                $GUIDMsg = "Please enter one or more GUID SAN objects separated by commas`nExample: " +
                "f7c3ac41-b8ce-4fb4-aa58-3d1dc0e36b39, g8D4ac41-b8ce-4fb4-aa58-3d1dc0e47c48"
                $GUIDSANObjects = Read-Host -Prompt $GUIDMsg
                $GUIDSANObjects = $GUIDSANObjects.Split(",").Trim()
            }
            
            foreach ($GUID in $GUIDSANObjectsArray) {
                Add-Content -Value "_continue_ = `"guid=$GUID&`"" -Path "$CertGenWorking\$CertificateRequestConfigFile"
            }
        }
    }

    #endregion >> Writing the Certificate Request Config File


    #region >> Generate Certificate Request and Submit to Issuing Certificate Authority

    ## Generate new Certificate Request File: ##
    # NOTE: The generation of a Certificate Request File using the below "certreq.exe -new" command also adds the CSR to the 
    # Client Machine's Certificate Request Store located at PSDrive "Cert:\CurrentUser\REQUEST" which is also known as 
    # "Microsoft.PowerShell.Security\Certificate::CurrentUser\Request"
    # There doesn't appear to be an equivalent to this using PowerShell cmdlets
    $null = certreq.exe -new "$CertGenWorking\$CertificateRequestConfigFile" "$CertGenWorking\$CertificateRequestFile"

    if ($CSRGenOnly) {
        [pscustomobject]@{
            CSRFile         = $(Get-Item "$CertGenWorking\$CertificateRequestFile")
            CSRContent      = $(Get-Content "$CertGenWorking\$CertificateRequestFile")
        }
        return
    }

    # TODO: If the Certificate Request Configuration File referenced in the above command contains "RequestType = Cert", then instead of the above command, 
    # the below certreq command should be used:
    # certreq.exe -new -cert [CertId] "$CertGenWorking\$CertificateRequestConfigFile" "$CertGenWorking\$CertificateRequestFile"

    if ($ADCSWebEnrollmentUrl) {
        # POST Data as a hash table
        $postParams = @{            
            "Mode"             = "newreq"
            "CertRequest"      = $(Get-Content "$CertGenWorking\$CertificateRequestFile" -Encoding Ascii | Out-String)
            "CertAttrib"       = "CertificateTemplate:$BasisTemplate"
            "FriendlyType"     = "Saved-Request+Certificate+($(Get-Date -DisplayHint Date -Format M/dd/yyyy),+$(Get-Date -DisplayHint Date -Format h:mm:ss+tt))"
            "Thumbprint"       = ""
            "TargetStoreFlags" = "0"
            "SaveCert"         = "yes"
        }

        # Submit New Certificate Request and Download New Certificate
        if ($ADCSWebAuthType -eq "Windows") {
            # Send the POST Data
            Invoke-RestMethod -Uri "$ADCSWebEnrollmentUrl/certfnsh.asp" -Method Post -Body $postParams -Credential $ADCSWebCreds -OutFile "$CertGenWorking\$CertADCSWebResponseOutFile"
        
            # Download New Certificate
            $ReqId = (Get-Content "$CertGenWorking\$CertADCSWebResponseOutFile" | Select-String -Pattern "ReqID=[0-9]{1,5}" | Select-Object -Index 0).Matches.Value.Split("=")[1]
            if ($ReqId -eq $null) {
                Write-Host "The Certificate Request was successfully submitted via ADCS Web Enrollment, but was rejected. Please check the format and contents of
                the Certificate Request Config File and try again."
                $global:FunctionResult = "1"
                return
            }

            $CertWebRawContent = (Invoke-WebRequest -Uri "$ADCSWebEnrollmentUrl/certnew.cer?ReqID=$ReqId&Enc=b64" -Credential $ADCSWebCreds).RawContent
            # Replace the line that begins with `r with ;;; then split on ;;; and select the last object in the index
            (($CertWebRawContent.Split("`n") -replace "^`r",";;;") -join "`n").Split(";;;")[-1].Trim() | Out-File "$CertGenWorking\$CertFileOut"
            # Alternate: Skip everything up until `r
            #$CertWebRawContent.Split("`n") | Select-Object -Skip $([array]::indexof($($CertWebRawContent.Split("`n")),"`r")) | Out-File "$CertGenWorking\$CertFileOut"
        }
        if ($ADCSWebAuthType -eq "Basic") {
            # Send the POST Data
            Invoke-RestMethod -Uri "$ADCSWebEnrollmentUrl/certfnsh.asp" -Method Post -Body $postParams -Headers $headers -OutFile "$CertGenWorking\$CertADCSWebResponseOutFile"

            # Download New Certificate
            $ReqId = (Get-Content "$CertGenWorking\$CertADCSWebResponseOutFile" | Select-String -Pattern "ReqID=[0-9]{1,5}" | Select-Object -Index 0).Matches.Value.Split("=")[1]
            if ($ReqId -eq $null) {
                Write-Host "The Certificate Request was successfully submitted via ADCS Web Enrollment, but was rejected. Please check the format and contents of
                the Certificate Request Config File and try again."
                $global:FunctionResult = "1"
                return
            }

            $CertWebRawContent = (Invoke-WebRequest -Uri "$ADCSWebEnrollmentUrl/certnew.cer?ReqID=$ReqId&Enc=b64" -Headers $headers).RawContent
            $CertWebRawContentArray = $CertWebRawContent.Split("`n") 
            $CertWebRawContentArray | Select-Object -Skip $([array]::indexof($CertWebRawContentArray,"`r")) | Out-File "$CertGenWorking\$CertFileOut"
        }
    }

    if (!$ADCSWebEnrollmentUrl) {
        ## Submit New Certificate Request File to Issuing Certificate Authority and Specify a Certificate to Use as a Base ##
        if (Test-Path "$CertGenWorking\$CertificateRequestFile") {
            if (!$cnForBasisTemplate) {
                $cnForBasisTemplate = "WebServer"
            }
            $null = certreq.exe -submit -attrib "CertificateTemplate:$cnForBasisTemplate" -config "$IssuingCertAuth" "$CertGenWorking\$CertificateRequestFile" "$CertGenWorking\$CertFileOut" "$CertGenWorking\$CertificateChainOut"
            # Equivalent of above certreq command using "Get-Certificate" cmdlet is below. We decided to use certreq.exe though because it actually outputs
            # files to the filesystem as opposed to just working with the client machine's certificate store.  This is more similar to the same process on Linux.
            #
            # ## Begin "Get-Certificate" equivalent ##
            # $LocationOfCSRInStore = $(Get-ChildItem Cert:\CurrentUser\Request | Where-Object {$_.Subject -like "*$CertificateCN*"}) | Select-Object -ExpandProperty PSPath
            # Get-Certificate -Template $cnForBasisTemplate -Url "https:\\$IssuingCertAuthFQDN\certsrv" -Request $LocationOfCSRInStore -CertStoreLocation Cert:\CurrentUser\My
            # NOTE: The above Get-Certificate command ALSO imports the certificate generated by the above request, making the below "Import-Certificate" command unnecessary
            # ## End "Get-Certificate" equivalent ##
        }
    }
        
    if (Test-Path "$CertGenWorking\$CertFileOut") {
        ## Generate .pfx file by installing certificate in store and then exporting with private key ##
        # NOTE: I'm not sure why importing a file that only contains the public certificate (i.e, the .cer file) suddenly makes the private key available
        # in the Certificate Store. It just works for some reason...
        # First, install the public certificate in store
        $null = Import-Certificate -FilePath "$CertGenWorking\$CertFileOut" -CertStoreLocation Cert:\CurrentUser\My
        # certreq.exe equivalent of the above Import-Certificate command is below. It is not as reliable as Import-Certifcate.
        # certreq -accept -user "$CertGenWorking\$CertFileOut"     

        # Then, export cert with private key in the form of a .pfx file
        if ($MachineKeySet -eq "FALSE") {
            if ($ThumprintToAvoid) {
                $LocationOfCertInStore = $(Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -match "CN=$CertificateCN," -and $_.Thumbprint -notmatch $ThumprintToAvoid}) | Select-Object -ExpandProperty PSPath
            }
            else {
                $LocationOfCertInStore = $(Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -match "CN=$CertificateCN,"}) | Select-Object -ExpandProperty PSPath
            }

            if ($LocationOfCertInStore.Count -gt 1) {
                Write-Host "Certificates to inspect:`n$($LocationOfCertInStore -join "`n")" -ForeGroundColor Yellow
                Write-Error "You have more than one certificate in your Certificate Store under Cert:\CurrentUser\My with the Common Name (CN) '$CertificateCN'. Please correct this and try again."
                $global:FunctionResult = "1"
                return
            }

            $null = Export-PfxCertificate -Cert $LocationOfCertInStore -FilePath "$CertGenWorking\$PFXFileOut" -Password $PFXPwdAsSecureString
            # Equivalent of above using certutil
            # $ThumbprintOfCertToExport = $(Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -like "*$CertificateCN*"}) | Select-Object -ExpandProperty Thumbprint
            # certutil -exportPFX -p "$PFXPwdPlainText" my $ThumbprintOfCertToExport "$CertGenWorking\$PFXFileOut"

            if ($UseOpenSSL -eq "Yes" -or $UseOpenSSL -eq "y") {
                # OpenSSL can't handle PowerShell SecureStrings, so need to convert it back into Plain Text
                $PwdForPFXOpenSSL = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PFXPwdAsSecureString))

                # Extract Private Key and Keep It Password Protected
                & "$PathToWin32OpenSSL\openssl.exe" pkcs12 -in "$CertGenWorking\$PFXFileOut" -nocerts -out "$CertGenWorking\$ProtectedPrivateKeyOut" -nodes -password pass:$PwdForPFXOpenSSL 2>&1 | Out-Null

                # The .pfx File Contains ALL Public Certificates in Chain 
                # The below extracts ALL Public Certificates in Chain
                & "$PathToWin32OpenSSL\openssl.exe" pkcs12 -in "$CertGenWorking\$PFXFileOut" -nokeys -out "$CertGenWorking\$AllPublicKeysInChainOut" -password pass:$PwdForPFXOpenSSL 2>&1 | Out-Null

                # Parse the Public Certificate Chain File and and Write Each Public Certificate to a Separate File
                # These files should have the EXACT SAME CONTENT as the .cer counterparts
                $PublicKeySansChainPrep1 = Get-Content "$CertGenWorking\$AllPublicKeysInChainOut"
                $LinesToReplace1 = $PublicKeySansChainPrep1 | Select-String -Pattern "issuer" | Sort-Object | Get-Unique
                $LinesToReplace2 = $PublicKeySansChainPrep1 | Select-String -Pattern "Bag Attributes" | Sort-Object | Get-Unique
                $PublicKeySansChainPrep2 = (Get-Content "$CertGenWorking\$AllPublicKeysInChainOut") -join "`n"
                foreach ($obj1 in $LinesToReplace1) {
                    $PublicKeySansChainPrep2 = $PublicKeySansChainPrep2 -replace "$obj1",";;;"
                }
                foreach ($obj1 in $LinesToReplace2) {
                    $PublicKeySansChainPrep2 = $PublicKeySansChainPrep2 -replace "$obj1",";;;"
                }
                $PublicKeySansChainPrep3 = $PublicKeySansChainPrep2.Split(";;;")
                $PublicKeySansChainPrep4 = foreach ($obj1 in $PublicKeySansChainPrep3) {
                    if ($obj1.Trim().StartsWith("-")) {
                        $obj1.Trim()
                    }
                }
                # Setup Hash Containing Cert Name vs Content Pairs
                $CertNamevsContentsHash = @{}
                foreach ($obj1 in $PublicKeySansChainPrep4) {
                    # First line after BEGIN CERTIFICATE
                    $obj2 = $obj1.Split("`n")[1]
                    
                    $ContextCounter = 3
                    $CertNamePrep = $null
                    while (!$CertNamePrep) {
                        $CertNamePrep = (($PublicKeySansChainPrep1 | Select-String -SimpleMatch $obj2 -Context $ContextCounter).Context.PreContext | Select-String -Pattern "subject").Line
                        $ContextCounter++
                    }
                    $CertName = $($CertNamePrep.Split("=") | Select-Object -Last 1).Trim()
                    $CertNamevsContentsHash.Add($CertName, $obj1)
                }

                # Write each Hash Key Value to Separate Files (i.e. writing all public keys in chain to separate files)
                foreach ($obj1 in $CertNamevsContentsHash.Keys) {
                    $CertNamevsContentsHash.$obj1 | Out-File "$CertGenWorking\$obj1`_Public_Cert.pem" -Encoding Ascii
                }

                # Determine if we should remove the password from the private key (i.e. $ProtectedPrivateKeyOut)
                if ($StripPrivateKeyOfPassword -eq $null) {
                    $StripPrivateKeyOfPassword = Read-Host -Prompt "Would you like to remove password protection from the private key? [Yes/No]"
                    if ($StripPrivateKeyOfPassword -eq "Yes" -or $StripPrivateKeyOfPassword -eq "y" -or $StripPrivateKeyOfPassword -eq "No" -or $StripPrivateKeyOfPassword -eq "n") {
                        Write-Host "The value for StripPrivateKeyOfPassword is valid...continuing"
                    }
                    else {
                        Write-Host "The value for StripPrivateKeyOfPassword is not valid. Please enter either 'Yes', 'y', 'No', or 'n'."
                        $StripPrivateKeyOfPassword = Read-Host -Prompt "Would you like to remove password protection from the private key? [Yes/No]"
                        if ($StripPrivateKeyOfPassword -eq "Yes" -or $StripPrivateKeyOfPassword -eq "y" -or $StripPrivateKeyOfPassword -eq "No" -or $StripPrivateKeyOfPassword -eq "n") {
                            Write-Host "The value for StripPrivateKeyOfPassword is valid...continuing"
                        }
                        else {
                            Write-Host "The value for StripPrivateKeyOfPassword is not valid. Please enter either 'Yes', 'y', 'No', or 'n'. Halting!"
                            $global:FunctionResult = "1"
                            return
                        }
                    }
                    if ($StripPrivateKeyOfPassword -eq "Yes" -or $StripPrivateKeyOfPassword -eq "y") {
                        # Strip Private Key of Password
                        & "$PathToWin32OpenSSL\openssl.exe" rsa -in "$CertGenWorking\$ProtectedPrivateKeyOut" -out "$CertGenWorking\$UnProtectedPrivateKeyOut" 2>&1 | Out-Null
                    }
                }
                if ($StripPrivateKeyOfPassword -eq "Yes" -or $StripPrivateKeyOfPassword -eq "y") {
                    # Strip Private Key of Password
                    & "$PathToWin32OpenSSL\openssl.exe" rsa -in "$CertGenWorking\$ProtectedPrivateKeyOut" -out "$CertGenWorking\$UnProtectedPrivateKeyOut" 2>&1 | Out-Null
                }
            }
        }
    }

    # Create Global HashTable of Outputs for use in scripts that source this script
    $GenerateCertificateFileOutputHash = @{}
    $GenerateCertificateFileOutputHash.Add("CertificateRequestConfigFile", "$CertGenWorking\$CertificateRequestConfigFile")
    $GenerateCertificateFileOutputHash.Add("CertificateRequestFile", "$CertGenWorking\$CertificateRequestFile")
    $GenerateCertificateFileOutputHash.Add("CertFileOut", "$CertGenWorking\$CertFileOut")
    if ($MachineKeySet -eq "FALSE") {
        $GenerateCertificateFileOutputHash.Add("PFXFileOut", "$CertGenWorking\$PFXFileOut")
    }
    if (!$ADCSWebEnrollmentUrl) {
        $CertUtilResponseFile = (Get-Item "$CertGenWorking\*.rsp").Name
        $GenerateCertificateFileOutputHash.Add("CertUtilResponseFile", "$CertGenWorking\$CertUtilResponseFile")

        $GenerateCertificateFileOutputHash.Add("CertificateChainOut", "$CertGenWorking\$CertificateChainOut")
    }
    if ($ADCSWebEnrollmentUrl) {
        $GenerateCertificateFileOutputHash.Add("CertADCSWebResponseOutFile", "$CertGenWorking\$CertADCSWebResponseOutFile")
    }
    if ($UseOpenSSL -eq "Yes") {
        $GenerateCertificateFileOutputHash.Add("AllPublicKeysInChainOut", "$CertGenWorking\$AllPublicKeysInChainOut")

        # Make CertName vs Contents Key/Value Pair hashtable available to scripts that source this script
        $CertNamevsContentsHash = $CertNamevsContentsHash

        $AdditionalPublicKeysArray = (Get-Item "$CertGenWorking\*_Public_Cert.pem").Name
        # For each Certificate in the hashtable $CertNamevsContentsHash, determine it it's a Root, Intermediate, or End Entity
        foreach ($obj1 in $AdditionalPublicKeysArray) {
            $SubjectTypePrep = (certutil -dump $CertGenWorking\$obj1 | Select-String -Pattern "Subject Type=").Line
            if ($SubjectTypePrep) {
                $SubjectType = $SubjectTypePrep.Split("=")[-1].Trim()
            }
            else {
                $SubjectType = "End Entity"
            }
            $RootCertFlag = certutil -dump $CertGenWorking\$obj1 | Select-String -Pattern "Subject matches issuer"
            $EndPointCNFlag = certutil -dump $CertGenWorking\$obj1 | Select-String -Pattern "CN=$CertificateCN"
            if ($SubjectType -eq "CA" -and $RootCertFlag.Matches.Success -eq $true) {
                $RootCAPublicCertFile = $obj1
                $GenerateCertificateFileOutputHash.Add("RootCAPublicCertFile", "$CertGenWorking\$RootCAPublicCertFile")
            }
            if ($SubjectType -eq "CA" -and $RootCertFlag.Matches.Success -ne $true) {
                $IntermediateCAPublicCertFile = $obj1
                $GenerateCertificateFileOutputHash.Add("IntermediateCAPublicCertFile", "$CertGenWorking\$IntermediateCAPublicCertFile")
            }
            if ($SubjectType -eq "End Entity" -and $EndPointCNFlag.Matches.Success -eq $true) {
                $EndPointPublicCertFile = $obj1
                $GenerateCertificateFileOutputHash.Add("EndPointPublicCertFile", "$CertGenWorking\$EndPointPublicCertFile")
            }
        }

        # Alternate Logic using .Net to Inspect Certificate files to Determine RootCA, Intermediate CA, and Endpoint
        <#
        foreach ($obj1 in $AdditionalPublicKeysArray) {
            $certPrint = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $certPrint.Import("$CertGenWorking\$obj1")
            if ($certPrint.Issuer -eq $certPrint.Subject) {
                $RootCAPublicCertFile = $obj1
                $RootCASubject = $certPrint.Subject
                $GenerateCertificateFileOutputHash.Add("RootCAPublicCertFile", "$CertGenWorking\$RootCAPublicCertFile")
            }
        }
        foreach ($obj1 in $AdditionalPublicKeysArray) {
            $certPrint = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $certPrint.Import("$CertGenWorking\$obj1")
            if ($certPrint.Issuer -eq $RootCASubject -and $certPrint.Subject -ne $RootCASubject) {
                $IntermediateCAPublicCertFile = $obj1
                $IntermediateCASubject = $certPrint.Subject
                $GenerateCertificateFileOutputHash.Add("IntermediateCAPublicCertFile", "$CertGenWorking\$IntermediateCAPublicCertFile")
            }
        }
        foreach ($obj1 in $AdditionalPublicKeysArray) {
            $certPrint = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $certPrint.Import("$CertGenWorking\$obj1")
            if ($certPrint.Issuer -eq $IntermediateCASubject) {
                $EndPointPublicCertFile = $obj1
                $EndPointSubject = $certPrint.Subject
                $GenerateCertificateFileOutputHash.Add("EndPointPublicCertFile", "$CertGenWorking\$EndPointPublicCertFile")
            }
        }
        #>

        $GenerateCertificateFileOutputHash.Add("EndPointProtectedPrivateKey", "$CertGenWorking\$ProtectedPrivateKeyOut")
    }
    if ($StripPrivateKeyOfPassword -eq "Yes" -or $StripPrivateKeyOfPassword -eq "y") {
        $GenerateCertificateFileOutputHash.Add("EndPointUnProtectedPrivateKey", "$CertGenWorking\$UnProtectedPrivateKeyOut")

        # Add UnProtected Private Key to $CertNamevsContentsHash
        $UnProtectedPrivateKeyContent = ((Get-Content $CertGenWorking\$UnProtectedPrivateKeyOut) -join "`n").Trim()
        $CertNamevsContentsHash.Add("EndPointUnProtectedPrivateKey", "$CertGenWorking\$UnProtectedPrivateKeyContent")
    }

    # Cleanup
    if ($LocationOfCertInStore) {
        Remove-Item $LocationOfCertInStore
    }

    # Return PSObject that contains $GenerateCertificateFileOutputHash and $CertNamevsContentsHash HashTables
    [pscustomobject]@{
        FileOutputHashTable       = $GenerateCertificateFileOutputHash
        CertNamevsContentsHash    = $CertNamevsContentsHash
    }

    $global:FunctionResult = "0"

    # ***IMPORTANT NOTE: If you want to write the Certificates contained in the $CertNamevsContentsHash out to files again
    # at some point in the future, make sure you use the "Out-File" cmdlet instead of the "Set-Content" cmdlet

    #endregion >> Generate Certificate Request and Submit to Issuing Certificate Authority

}


<#
    .SYNOPSIS
     Gets info about the Docker-For-Windows Docker Server and Client on a Windows host. This is mainly
     used to determine if the Docker Server is running in Windows Container mode or Linux Container mode.

    .DESCRIPTION
        See .SYNOPSIS

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-DockerInfo
        
#>
function Get-DockerInfo {
    $DockerVersionInfo = docker version
    [System.Collections.ArrayList]$DockerClientInfo = @()
    [System.Collections.ArrayList]$DockerServerInfo = @()
    foreach ($line in $DockerVersionInfo) {
        if ($line -match "^Client") {
            $ClientOrServer = "Client"
        }
        if ($line -match "^Server") {
            $ClientOrServer = "Server"
        }
        if (![string]::IsNullOrEmpty($line)) {
            if ($ClientOrServer -eq "Client" -and $line -notmatch "^Client") {
                $null = $DockerClientInfo.Add($line.Trim())
            }
            if ($ClientOrServer -eq "Server" -and $line -notmatch "^Server") {
                $null = $DockerServerInfo.Add($line.Trim())
            }
        }
    }

    [pscustomobject]$DockerClientPSObject = @{}
    [pscustomobject]$DockerServerPSObject = @{}
    foreach ($Property in $DockerClientInfo) {
        $KeyValuePrep = $Property -split ":[\s]+"
        $key = $KeyValuePrep[0].Trim()
        $value = $KeyValuePrep[1].Trim()

        $null = $DockerClientPSObject.Add($key,$value)
    }
    foreach ($Property in $DockerServerInfo) {
        if ([bool]$($Property -match ":[\s]+")) {
            $KeyValuePrep = $Property -split ":[\s]+"
        }
        elseif ([bool]$($Property -match ":")) {
            $KeyValuePrep = $Property -split ":"
        }
        $key = $KeyValuePrep[0].Trim()
        if ($KeyValuePrep[1] -ne $null) {
            $value = $KeyValuePrep[1].Trim()
        }

        $null = $DockerServerPSObject.Add($key,$value)
    }

    [pscustomobject]@{
        DockerServerInfo    = $DockerServerPSObject
        DockerClientInfo    = $DockerClientPSObject
    }
}


<#
    .SYNOPSIS
        This function creates a New Self-Signed Certificate meant to be used for DSC secret encryption and exports it to the
        specified directory.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER MachineName
        This parameter is MANDATORY.

        This parameter takes a string that represents the Subject Alternative Name (SAN) on the Self-Signed Certificate.

    .PARAMETER ExportDirectory
        This parameter is MANDATORY.

        This parameter takes a string that represents the full path to a directory that will contain the new Self-Signed Certificate.

    .EXAMPLE
        # Import the MiniLab Module and -

        PS C:\Users\zeroadmin> Get-DSCEncryptionCert -MachineName $env:ComputerName -ExportDirectory "C:\DSCConfigs"

#>
function Get-DSCEncryptionCert {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [string]$MachineName,

        [Parameter(Mandatory=$True)]
        [string]$ExportDirectory
    )

    if (!$(Test-Path $ExportDirectory)) {
        Write-Error "The path '$ExportDirectory' was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $CertificateFriendlyName = "DSC Credential Encryption"
    $Cert = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object {
        $_.FriendlyName -eq $CertificateFriendlyName
    } | Select-Object -First 1

    if (!$Cert) {
        $NewSelfSignedCertExSplatParams = @{
            Subject             = "CN=$Machinename"
            EKU                 = @('1.3.6.1.4.1.311.80.1','1.3.6.1.5.5.7.3.1','1.3.6.1.5.5.7.3.2')
            KeyUsage            = 'DigitalSignature, KeyEncipherment, DataEncipherment'
            SAN                 = $MachineName
            FriendlyName        = $CertificateFriendlyName
            Exportable          = $True
            StoreLocation       = 'LocalMachine'
            StoreName           = 'My'
            KeyLength           = 2048
            ProviderName        = 'Microsoft Enhanced Cryptographic Provider v1.0'
            AlgorithmName       = "RSA"
            SignatureAlgorithm  = "SHA256"
        }

        New-SelfsignedCertificateEx @NewSelfSignedCertExSplatParams

        # There is a slight delay before new cert shows up in Cert:
        # So wait for it to show.
        while (!$Cert) {
            $Cert = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object {$_.FriendlyName -eq $CertificateFriendlyName}
        }
    }

    $null = Export-Certificate -Type CERT -Cert $Cert -FilePath "$ExportDirectory\DSCEncryption.cer"

    $CertInfo = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new()
    $CertInfo.Import("$ExportDirectory\DSCEncryption.cer")

    [pscustomobject]@{
        CertFile        = Get-Item "$ExportDirectory\DSCEncryption.cer"
        CertInfo        = $CertInfo
    }
}


<#
    .SYNOPSIS
        This function creates a New Self-Signed Certificate meant to be used for DSC secret encryption and exports it to the
        specified directory.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER CommonName
        This parameter is MANDATORY.

        This parameter takes a string that represents the Common Name (CN) on the Self-Signed Certificate.

    .PARAMETER ExportDirectory
        This parameter is MANDATORY.

        This parameter takes a string that represents the full path to a directory that will contain the new Self-Signed Certificate.

    .EXAMPLE
        # Import the MiniLab Module and -

        PS C:\Users\zeroadmin> Get-EncryptionCert -CommonName "EncryptionCert" -ExportDirectory "$HOME\EncryptionCerts"

#>
function Get-EncryptionCert {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [string]$CommonName,

        [Parameter(Mandatory=$True)]
        [string]$ExportDirectory
    )

    if (!$(Test-Path $ExportDirectory)) {
        Write-Error "The path '$ExportDirectory' was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $CertificateFriendlyName = $CommonName
    $Cert = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object {
        $_.FriendlyName -eq $CertificateFriendlyName
    } | Select-Object -First 1

    if (!$Cert) {
        $NewSelfSignedCertExSplatParams = @{
            Subject             = "CN=$CommonName"
            EKU                 = @('1.3.6.1.4.1.311.80.1','1.3.6.1.5.5.7.3.1','1.3.6.1.5.5.7.3.2')
            KeyUsage            = 'DigitalSignature, KeyEncipherment, DataEncipherment'
            SAN                 = $CommonName
            FriendlyName        = $CertificateFriendlyName
            Exportable          = $True
            StoreLocation       = 'LocalMachine'
            StoreName           = 'My'
            KeyLength           = 2048
            ProviderName        = 'Microsoft Enhanced Cryptographic Provider v1.0'
            AlgorithmName       = "RSA"
            SignatureAlgorithm  = "SHA256"
        }

        New-SelfsignedCertificateEx @NewSelfSignedCertExSplatParams

        # There is a slight delay before new cert shows up in Cert:
        # So wait for it to show.
        while (!$Cert) {
            $Cert = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object {$_.FriendlyName -eq $CertificateFriendlyName}
        }
    }

    #$null = Export-Certificate -Type CERT -Cert $Cert -FilePath "$ExportDirectory\$CommonName.cer"
    [System.IO.File]::WriteAllBytes("$ExportDirectory\$CommonName.cer", $Cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))

    [pscustomobject]@{
        CertFile        = Get-Item "$ExportDirectory\$CommonName.cer"
        CertInfo        = $Cert
    }
}


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


<#
    .SYNOPSIS
        This function downloads a Vagrant Box (.box file) to the specified -DownloadDirectory

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER VagrantBox
        This parameter is MANDATORY.

        This parameter takes a string that represents the name of a Vagrant Box that can be found
        on https://app.vagrantup.com. Example: centos/7

    .PARAMETER VagrantProvider
        This parameter is MANDATORY.

        This parameter takes a string that must be one of the following values:
        "hyperv","virtualbox","vmware_workstation","docker"

    .PARAMETER DownloadDirectory
        This parameter is MANDATORY.

        This parameter takes a string that represents a full path to a directory that the .box file
        will be downloaded to.

    .PARAMETER SkipPreDownloadCheck
        This parameter is OPTIONAL.

        This parameter is a switch.

        By default, this function checks to make sure there is eough space on the target drive BEFORE
        it attempts ot download the .box file. This calculation ensures that there is at least 2GB of
        free space on the storage drive after the .box file has been downloaded. If you would like to
        skip this check, use this switch.

    .PARAMETER Repository
        This parameter is OPTIONAL.

        This parameter currently only takes the string 'Vagrant', which refers to the default Vagrant Box
        Repository at https://app.vagrantup.com. Other Vagrant Repositories exist. At some point, this
        function will be updated to include those other repositories.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Fix-SSHPermissions
        
#>
function Get-VagrantBoxManualDownload {
    [CmdletBinding(DefaultParameterSetName='ExternalNetworkVM')]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidatePattern("[\w]+\/[\w]+")]
        [string]$VagrantBox,

        [Parameter(Mandatory=$True)]
        [ValidateSet("hyperv","virtualbox","vmware_workstation","docker")]
        [string]$VagrantProvider,

        [Parameter(Mandatory=$True)]
        [string]$DownloadDirectory,

        [Parameter(Mandatory=$False)]
        [switch]$SkipPreDownloadCheck,

        [Parameter(Mandatory=$False)]
        [ValidateSet("Vagrant","AWS")]
        [string]$Repository
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if (!$(Test-Path $DownloadDirectory)) {
        Write-Error "The path $DownloadDirectory was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if (!$(Get-Item $DownloadDirectory).PSIsContainer) {
        Write-Error "$DownloadDirectory is NOT a directory! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$Repository) {
        $Repository = "Vagrant"
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    if ($Repository -eq "Vagrant") {
        # Find the latest version of the .box you want that also has the provider you want
        $BoxInfoUrl = "https://app.vagrantup.com/" + $($VagrantBox -split '/')[0] + "/boxes/" + $($VagrantBox -split '/')[1]
        $VagrantBoxVersionPrep = Invoke-WebRequest -Uri $BoxInfoUrl
        $VersionsInOrderOfRelease = $($VagrantBoxVersionPrep.Links | Where-Object {$_.href -match "versions"}).href | foreach {$($_ -split "/")[-1]}
        $VagrantBoxLatestVersion = $VersionsInOrderOfRelease[0]

        foreach ($version in $VersionsInOrderOfRelease) {
            $VagrantBoxDownloadUrl = "https://vagrantcloud.com/" + $($VagrantBox -split '/')[0] + "/boxes/" + $($VagrantBox -split '/')[1] + "/versions/" + $version + "/providers/" + $VagrantProvider + ".box"
            Write-Host "Trying download from $VagrantBoxDownloadUrl ..."

            try {
                # Make sure the Url exists...
                $HTTP_Request = [System.Net.WebRequest]::Create($VagrantBoxDownloadUrl)
                $HTTP_Response = $HTTP_Request.GetResponse()

                Write-Host "Received HTTP Response $($HTTP_Response.StatusCode)"
            }
            catch {
                continue
            }

            try {
                $bytes = $HTTP_Response.GetResponseHeader("Content-Length")
                $BoxSizeInMB = [Math]::Round($bytes / 1MB)

                $FinalVagrantBoxDownloadUrl = $VagrantBoxDownloadUrl
                $BoxVersion = $version

                break
            }
            catch {
                continue
            }
        }

        if (!$FinalVagrantBoxDownloadUrl) {
            Write-Error "Unable to resolve URL for Vagrant Box $VagrantBox that matches the specified provider (i.e. $VagrantProvider)! Halting!"
            $global:FunctionResult = "1"
            return
        }

        Write-Host "FinalVagrantBoxDownloadUrl is $FinalVagrantBoxDownloadUrl"

        if (!$SkipPreDownloadCheck) {
            # Determine if we have enough space on the $DownloadDirectory's Drive before downloading
            if ([bool]$(Get-Item $DownloadDirectory).LinkType) {
                $DownloadDirLogicalDriveLetter = $(Get-Item $DownloadDirectory).Target[0].Substring(0,1)
            }
            else {
                $DownloadDirLogicalDriveLetter = $DownloadDirectory.Substring(0,1)
            }
            
            $DownloadDirDriveInfo = [System.IO.DriveInfo]::GetDrives() | Where-Object {$_.Name -eq $($DownloadDirLogicalDriveLetter + ':\')}
            
            if ($([Math]::Round($DownloadDirDriveInfo.AvailableFreeSpace / 1MB)-2000) -gt $BoxSizeInMB) {
                $OutFileName = $($VagrantBox -replace '/','-') + "_" + $BoxVersion + ".box"
            }
            if ($([Math]::Round($DownloadDirDriveInfo.AvailableFreeSpace / 1MB)-2000) -lt $BoxSizeInMB) {
                Write-Error "Not enough space on $DownloadDirLogicalDriveLetter`:\ Drive to download the compressed .box file and subsequently expand it! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        else {
            $OutFileName = $($VagrantBox -replace '/','-') + "_" + $BoxVersion + ".box"
        }

        # Download the .box file
        try {
            # System.Net.WebClient is a lot faster than Invoke-WebRequest for large files...
            Write-Host "Downloading $FinalVagrantBoxDownloadUrl ..."
            #& $CurlCmd -Lk -o "$DownloadDirectory\$OutFileName" "$FinalVagrantBoxDownloadUrl"
            $WebClient = [System.Net.WebClient]::new()
            $WebClient.Downloadfile($FinalVagrantBoxDownloadUrl, "$DownloadDirectory\$OutFileName")
            $WebClient.Dispose()
        }
        catch {
            $WebClient.Dispose()
            Write-Error $_
            Write-Warning "If $FinalVagrantBoxDownloadUrl definitely exists, starting a fresh PowerShell Session could remedy this issue!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($Repository -eq "AWS") {
        if ($VagrantBox -eq "pldmgg/centos7vswitchtest") {
            $BoxInfoUrl = $VagrantBoxDownloadUrl = $FinalVagrantBoxDownloadUrl = "https://s3.amazonaws.com/ipxebooting/CentOS7ExternalvSwitchTest.box"
        }
        if ($VagrantBox -eq "pldmgg/centos7dhcp") {
            $BoxInfoUrl = $VagrantBoxDownloadUrl = $FinalVagrantBoxDownloadUrl = "https://s3.amazonaws.com/ipxebooting/CentOS7DHCP.box"
        }
        
        Write-Host "Trying download from $VagrantBoxDownloadUrl ..."

        try {
            # Make sure the Url exists...
            $HTTP_Request = [System.Net.WebRequest]::Create($VagrantBoxDownloadUrl)
            $HTTP_Response = $HTTP_Request.GetResponse()

            Write-Host "Received HTTP Response $($HTTP_Response.StatusCode)"
        }
        catch {
            Write-Error "Unable to reach '$VagrantBoxDownloadUrl'! Halting!"
            $global:FunctionResult = "1"
            return
        }

        try {
            $bytes = $HTTP_Response.GetResponseHeader("Content-Length")
            $BoxSizeInMB = [Math]::Round($bytes / 1MB)
        }
        catch {
            Write-Warning "There was a problem pre-determining how large the .box file to be downloaded is..."
        }

        if (!$SkipPreDownloadCheck) {
            # Determine if we have enough space on the $DownloadDirectory's Drive before downloading
            if ([bool]$(Get-Item $DownloadDirectory).LinkType) {
                $DownloadDirLogicalDriveLetter = $(Get-Item $DownloadDirectory).Target[0].Substring(0,1)
            }
            else {
                $DownloadDirLogicalDriveLetter = $DownloadDirectory.Substring(0,1)
            }
            $DownloadDirDriveInfo = Get-WmiObject Win32_LogicalDisk -ComputerName $env:ComputerName -Filter "DeviceID='$DownloadDirLogicalDriveLetter`:'"
            
            if ($([Math]::Round($DownloadDirDriveInfo.FreeSpace / 1MB)-2000) -gt $BoxSizeInMB) {
                $OutFileName = $($VagrantBox -replace '/','-') + "_" + $BoxVersion + ".box"
            }
            if ($([Math]::Round($DownloadDirDriveInfo.FreeSpace / 1MB)-2000) -lt $BoxSizeInMB) {
                Write-Error "Not enough space on $DownloadDirLogicalDriveLetter`:\ Drive to download the compressed .box file and subsequently expand it! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        else {
            $OutFileName = $($VagrantBox -replace '/','-') + "_" + $BoxVersion + ".box"
        }

        # Download the .box file
        try {
            # System.Net.WebClient is a lot faster than Invoke-WebRequest for large files...
            Write-Host "Downloading $FinalVagrantBoxDownloadUrl ..."
            #& $CurlCmd -Lk -o "$DownloadDirectory\$OutFileName" "$FinalVagrantBoxDownloadUrl"
            $WebClient = [System.Net.WebClient]::new()
            $WebClient.Downloadfile($FinalVagrantBoxDownloadUrl, "$DownloadDirectory\$OutFileName")
            $WebClient.Dispose()
        }
        catch {
            $WebClient.Dispose()
            Write-Error $_
            Write-Warning "If $FinalVagrantBoxDownloadUrl definitely exists, starting a fresh PowerShell Session could remedy this issue!"
            $global:FunctionResult = "1"
            return
        }
    }

    Get-Item "$DownloadDirectory\$OutFileName"

    ##### END Main Body #####
}


<#
    .SYNOPSIS
        This function downloads openssl.exe from either https://indy.fulgan.com/SSL/ or
        http://wiki.overbyte.eu/wiki/index.php/ICS_Download" and adds it to $env:Path

    .DESCRIPTION
        See .SYNOPSIS

    .PARAMETER OpenSSLWinBinariesUrl
        This parameter is OPTIONAL, however, it has a default value of https://indy.fulgan.com/SSL/

        This parameter takes a string that represents the Url that contains a link to a zip file
        containing openssl.exe.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-WinOpenSSL
        
#>
function Get-WinOpenSSL {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$False)]
        [ValidateSet("https://indy.fulgan.com/SSL/","http://wiki.overbyte.eu/wiki/index.php/ICS_Download")]
        [string]$OpenSSLWinBinariesUrl = "https://indy.fulgan.com/SSL/"
    )

    if ($PSVersionTable.PSEdition -eq "Desktop") {
        [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
    }

    $IWRResult = Invoke-WebRequest -Uri $OpenSSLWinBinariesUrl -UseBasicParsing

    if ($OpenSSLWinBinariesUrl -match "fulgan") {
        $LatestOpenSSLWinBinaryUrl = $OpenSSLWinBinariesUrl + $($IWRResult.Links | Where-Object {$_.OuterHTML -match "win64\.zip"})[-1].href
    }
    if ($OpenSSLWinBinariesUrl -match "overbyte") {
        $LatestOpenSSLWinBinaryUrl = $($IWRResult.Links | Where-Object {$_.OuterHTML -match "win64\.zip"})[0].href
    }
    $OutputFileName = $($LatestOpenSSLWinBinaryUrl -split '/')[-1]
    $OutputFilePath = "$HOME\Downloads\$OutputFileName"

    Invoke-WebRequest -Uri $LatestOpenSSLWinBinaryUrl -OutFile $OutputFilePath

    $ExpansionDirectory = $OutputFilePath -replace '\.zip$',''
    if (Test-Path $ExpansionDirectory) {
        Remove-Item "$ExpansionDirectory\*" -Recurse -Force
    }
    else {
        $null = New-Item -ItemType Directory -Path $ExpansionDirectory
    }
    $null = Expand-Archive -Path $OutputFilePath -DestinationPath $ExpansionDirectory -Force
    $WinOpenSSLFiles = Get-ChildItem -Path $ExpansionDirectory

    $WinOpenSSLParentDir = $WinOpenSSLFiles[0].Directory.FullName
    [System.Collections.Arraylist][array]$CurrentEnvPathArray = $env:Path -split ';' | Where-Object {![System.String]::IsNullOrWhiteSpace($_)}
    if ($CurrentEnvPathArray -notcontains $WinOpenSSLParentDir) {
        $CurrentEnvPathArray.Insert(0,$WinOpenSSLParentDir)
        $env:Path = $CurrentEnvPathArray -join ';'
    }
}


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


<#
    .SYNOPSIS
        This function joins a Linux machine to a Windows Active Directory Domain.

        Currently, this function only supports RedHat/CentOS.

        Most of this function is from:

        https://winsysblog.com/2018/01/join-linux-active-directory-powershell-core.html

    .DESCRIPTION
        See .SYNOPSIS

    .PARAMETER DomainName
        This parameter is MANDATORY.

        This parameter takes a string that represents Active Directory Domain that you would like to join.

    .PARAMETER DomainCreds
        This parameter is MANDATORY.

        This parameter takes a pscredential object that represents a UserName and Password that can join
        a host to teh Active Directory Domain.

    .EXAMPLE
        # Open an elevated PowerShell Core (pwsh) session on a Linux, import the module, and -

        [CentOS7Host] # sudo pwsh

        PS /home/testadmin> $DomainCreds = [pscredential]::new("zero\zeroadmin",$(Read-Host "Enter Password" -AsSecureString))
        PS /home/testadmin> Join-LinuxToAD -DomainName "zero.lab" -DomainCreds $DomainCreds
#>
function Join-LinuxToAD {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [string]$DomainName,

        [Parameter(Mandatory=$True)]
        [pscredential]$DomainCreds
    )

    if (!$(GetElevation)) {
        Write-Error "You must run the $($MyInvocation.MyCommand.Name) function with elevated permissions! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$IsLinux) {
        Write-Error "This host is not Linux. Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (![bool]$($PSVersionTable.OS -match 'RedHat|CentOS|\.el[0-9]\.')) {
        Write-Error "Currently, the $(MyInvocation.MyCommand.Name) function only works on RedHat/CentOS Linux Distros! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Make sure nslookup is installed
    which nslookup *>/dev/null
    if ($LASTEXITCODE -ne 0) {
        $null = yum install bind-utils -y
    }

    # Ensure you can lookup AD DNS
    $null = nslookup $DomainName
    if ($LASTEXITCODE -ne 0) {
        Write-Error 'Could not find domain in DNS. Checking settings'
        $global:FunctionResult = "1"
        return
    }

    #Ensure Samba and dependencies installed
    $DependenciesToInstall = @(
        "sssd"
        "realmd"
        "oddjob"
        "oddjob-mkhomedir"
        "adcli"
        "samba-common"
        "samba-common-tools"
        "krb5-workstation"
        "openldap-clients"
        "policycoreutils-python"
    )

    [System.Collections.ArrayList]$SuccessfullyInstalledDependencies = @()
    [System.Collections.ArrayList]$FailedInstalledDependencies = @()
    foreach ($Dependency in $DependenciesToInstall) {
        $null = yum install $Dependency -y

        if ($LASTEXITCODE -ne 0) {
            $null = $FailedInstalledDependencies.Add($Dependency)
        }
        else {
            $null = $SuccessfullyInstalledDependencies.Add($Dependency)
        }
    }

    if ($FailedInstalledDependencies.Count -gt 0) {
        Write-Error "Failed to install the following dependencies:`n$($FailedInstalledDependencies -join "`n")`nHalting!"
        $global:FunctionResult = "1"
        return
    }

    # Join domain with realm
    $DomainUserName = $DomainCreds.UserName
    if ($DomainUserName -match "\\") {$DomainUserName = $($DomainUserName -split "\\")[-1]}
    $PTPasswd = $DomainCreds.GetNetworkCredential().Password
    printf "$PTPasswd" | realm join $DomainName --user=$DomainUserName

    if ($LASTEXITCODE -ne 0) {
        Write-Error -Message "Could not join domain $DomainName. See error output"
        exit
    }
    if ($LASTEXITCODE -eq 0) {
        Write-Output 'Success'
    }
}


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


<#
    .SYNOPSIS
        This function moves Docker-For-Windows (DockerCE) Windows and Linux Container storage
        to the specified location(s).

    .DESCRIPTION
        See .SYNOPSIS

    .PARAMETER NewDockerDrive
        This parameter is OPTIONAL.

        This parameter takes a letter (A-Z) that represents the drive that you would like to move
        Windows and Linux Container storage to.

        If you use this parameter, do not use the -CustomWindowsImageStoragePath or -CustomLinuxImageStoragePath
        parameters.

    .PARAMETER CustomWindowsImageStoragePath
        This parameter is OPTIONAL.

        This parameter takes a string that represents a full path to a directory where you would like
        Windows Container storage moved.

        Do not use this parameter if you are using the -NewDockerDrive parameter.

    .PARAMETER CustomLinuxImageStoragePath
        This parameter is OPTIONAL.

        This parameter takes a string that represents a full path to a directory where you would like
        Linux Container storage moved.

        Do not use this parameter if you are using the -NewDockerDrive parameter.

    .PARAMETER MoveWindowsImagesOnly
        This parameter is OPTIONAL.

        This parameter is a switch. If used, only Windows Container storage will be moved.

    .PARAMETER MoveLinuxImagesOnly
        This parameter is OPTIONAL.

        This parameter is a switch. If used, only Linux Container storage will be moved.

    .PARAMETER Force
        This parameter is OPTIONAL.

        This parameter is a switch.

        Moving Windows Docker Storage to a new location causes existing Windows docker images and containers to be removed.
        Default behavior for this function is prompt the user to confirm this action before proceeding. Use the -Force
        switch to skip this prompt.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Move-DockerStorage -NewDockerDrive H -Force
        
#>
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
    if ($CustomWindowsImageStoragePath -and $MoveLinuxImagesOnly) {
        Write-Error "The switch -MoveLinuxImagesOnly was used in conjunction with the -CustomWindowsImageStoragePath parameter! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($CustomLinuxImageStoragePath -and $MoveWindowsImagesOnly) {
        Write-Error "The switch -MoveWindowsImagesOnly was used in conjunction with the -CustomLinuxImageStoragePath parameter! Halting!"
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
    $LocalDrives = Get-CimInstance Win32_LogicalDisk | Where-Object {$_.Drivetype -eq 3} | foreach {Get-PSDrive $_.DeviceId[0] -ErrorAction SilentlyContinue}

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

        # Make sure we switch to Linuc Container Mode to ensure MobyLinuxVM is recreated in he new Storage Location
        $null = Switch-DockerContainerType -ContainerType Linux
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


<#
    .SYNOPSIS
        This function creates a new Primary Domain Controller on the specified Windows 2012 R2 or Windows 2016 Server.

        This function MUST be used remotely (i.e. run it from a Workstation that can use PS Remoting to access the target
        Windows Server that will become the new Domain Controller).

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER DesiredHostName
        This parameter is MANDATORY.

        This parameter takes a string that represents the HostName that you would like the target Windows 2016 Server to have.

    .PARAMETER NewDomainName
        This parameter is MANDATORY.

        This parameter takes a string that represents the name of the new domain you would like to create.
        Example: alpha.lab

    .PARAMETER NewDomainAdminCredentials
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

    .PARAMETER PSRemotingLocalAdminCredentials
        This parameter is MANDATORY.

        This parameter takes a PSCredential.

        The credential provided to this parameter should correspond to a User Account that has permission to
        remote into the target Windows Server. If you're using a Vagrant Box (which is what will be deployed
        if you use the -CreateNewVMs switch), then the value for this parameter should be created via:

            $VagrantVMPassword = ConvertTo-SecureString 'vagrant' -AsPlainText -Force
            $VagrantVMAdminCreds = [pscredential]::new("vagrant",$VagrantVMPassword)

    .PARAMETER ServerIP
        This parameter is OPTIONAL, however, if you do NOT use the -CreateNewVMs parameter, this parameter becomes MANDATORY.

        This parameter takes a string that represents an IPv4 Address of the Windows Server that will become the new Primary
        Domain Controller.

    .PARAMETER RemoteDSCDirectory
        This parameter is OPTIONAL, however, the value defaults to "C:\DSCConfigs".

        This parameter takes a string that represents the full path to a directory on -ServerIP that will contain the DSC
        configuration files needed to create the new Primary Domain Controller.

    .PARAMETER DSCResultsDownloadDirectory
        This parameter is OPTIONAL, however, the value defaults to "$HOME\Downloads\DSCConfigResultsFor$DesiredHostName".

        This parameter takes a string that represents the full path to a directory on the localhost that will contain any
        DSC config output files generated by creating the new Primary Domain Controller. This makes it easy to review what
        DSC did on the remote host.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> $VagrantVMPassword = ConvertTo-SecureString 'vagrant' -AsPlainText -Force
        PS C:\Users\zeroadmin> $VagrantVMAdminCreds = [pscredential]::new("vagrant",$VagrantVMPassword)
        PS C:\Users\zeroadmin> $DomainAdminCreds = [pscredential]::new("alpha\alphaadmin",$(Read-Host 'Enter Passsword' -AsSecureString))
        Enter Passsword: ************
        PS C:\Users\zeroadmin> $LocalAdminAccountCreds = [pscredential]::new("Administrator",$(Read-Host 'Enter Passsword' -AsSecureString))
        Enter Passsword: ****************
        PS C:\Users\zeroadmin> $NewDomainControllerSplatParams = @{
        >> DesiredHostName                         = "AlphaDC01"
        >> NewDomainName                           = "alpha.lab"
        >> NewDomainAdminCredentials               = $DomainAdminCreds
        >> ServerIP                                = "192.168.2.112"
        >> PSRemotingLocalAdminCredentials         = $VagrantVMAdminCreds
        >> LocalAdministratorAccountCredentials    = $LocalAdminAccountCreds
        >> }
        PS C:\Users\zeroadmin> $NewDomainControllerResults = New-DomainController @NewDomainControllerSplatParams
        
#>
function New-DomainController {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [ValidatePattern("^[a-zA-Z1-9]{4,10}$")]
        [string]$DesiredHostName,

        [Parameter(Mandatory=$True)]
        [ValidatePattern("^([a-z0-9]+(-[a-z0-9]+)*\.)+([a-z]){2,}$")]
        [string]$NewDomainName,

        [Parameter(Mandatory=$True)]
        [pscredential]$NewDomainAdminCredentials,

        [Parameter(Mandatory=$True)]
        [pscredential]$LocalAdministratorAccountCredentials,

        [Parameter(Mandatory=$True)]
        [pscredential]$PSRemotingLocalAdminCredentials,

        [Parameter(Mandatory=$True)]
        [string]$ServerIP,

        [Parameter(Mandatory=$False)]
        [string]$RemoteDSCDirectory,

        [Parameter(Mandatory=$False)]
        [string]$DSCResultsDownloadDirectory
    )

    #region >> Prep

    if (!$RemoteDSCDirectory) {
        $RemoteDSCDirectory = "C:\DSCConfigs"
    }
    if (!$DSCResultsDownloadDirectory) {
        $DSCResultsDownloadDirectory = "$HOME\Downloads\DSCConfigResultsFor$DesiredHostName"
    }
    if ($LocalAdministratorAccountCredentials.UserName -ne "Administrator") {
        Write-Error "The -LocalAdministratorAccount PSCredential must have a UserName property equal to 'Administrator'! Halting!"
        $global:FunctionResult = "1"
        return
    }
    $NewDomainShortName = $($NewDomainName -split "\.")[0]
    if ($NewDomainAdminCredentials.UserName -notmatch "$NewDomainShortName\\[\w]+$") {
        Write-Error "The User Account provided to the -NewDomainAdminCredentials parameter must be in format: $NewDomainShortName\\<UserName>`nHalting!"
        $global:FunctionResult = "1"
        return
    }
    if ($NewDomainAdminCredentials.UserName -match "$NewDomainShortName\\Administrator$") {
        Write-Error "The User Account provided to the -NewDomainAdminCredentials cannot be: $NewDomainShortName\\Administrator`nHalting!"
        $global:FunctionResult = "1"
        return
    }

    $PrimaryIfIndex = $(Get-CimInstance Win32_IP4RouteTable | Where-Object {
        $_.Destination -eq '0.0.0.0' -and $_.Mask -eq '0.0.0.0'
    } | Sort-Object Metric1)[0].InterfaceIndex
    $NicInfo = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object {$_.InterfaceIndex -eq $PrimaryIfIndex}
    $PrimaryIP = $NicInfo.IPAddress | Where-Object {TestIsValidIPAddress -IPAddress $_}
    if ($ServerIP -eq $PrimaryIP) {
        Write-Error "This $($MyInvocation.MyCommand.Name) function must be run remotely (i.e. from a workstation that can access the target Windows Server via PS Remoting)! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $CharacterIndexToSplitOn = [Math]::Round($(0..$($NewDomainAdminCredentials.UserName.Length) | Measure-Object -Average).Average)
    $NewDomainAdminFirstName = $NewDomainAdminCredentials.UserName.SubString(0,$CharacterIndexToSplitOn)
    $NewDomainAdminLastName = $NewDomainAdminCredentials.UserName.SubString($CharacterIndexToSplitOn,$($($NewDomainAdminCredentials.UserName.Length)-$CharacterIndexToSplitOn))

    $NewBackupDomainAdminFirstName = $($NewDomainAdminCredentials.UserName -split "\\")[-1]
    $NewBackupDomainAdminLastName =  "backup"
    
    $NeededDSCResources = @(
        "PSDesiredStateConfiguration"
        "xPSDesiredStateConfiguration"
        "xActiveDirectory"
    )

    [System.Collections.ArrayList]$DSCModulesToTransfer = @()
    foreach ($DSCResource in $NeededDSCResources) {
        # NOTE: Usually $Module.ModuleBase is the version number directory, and its parent is the
        # directory that actually matches the Module Name. $ModuleBaseParent is the name of the
        # directory that matches the name of the Module
        $ModMapObj = $script:ModuleDependenciesMap.SuccessfulModuleImports | Where-Object {$_.ModuleName -eq $DSCResource}
        #$ModMapObj = GetModMapObject -PotentialModMapObject $PotentialModMapObject

        $ModuleBaseParent = $($ModMapObj.ManifestFileItem.FullName -split $DSCResource)[0] + $DSCResource
        
        if ($DSCResource -ne "PSDesiredStateConfiguration") {
            $null = $DSCModulesToTransfer.Add($ModuleBaseParent)
        }

        switch ($DSCResource) {
            'PSDesiredStateConfiguration' {
                try {
                    $PSDSCVersion = $ModMapObj.ManifestFileItem.FullName | Split-Path -Parent | Split-Path -Leaf
                }
                catch {
                    try {
                        $PSDSCModule = Get-Module -ListAvailable "PSDesiredStateConfiguration"
                        $PSDSCVersion = $($PSDSCModule.Version | Sort-Object | Get-Unique).ToString()
                    }
                    catch {
                        Write-Verbose "Unable to get PSDesiredStateConfiguration version information from $env:ComputerName"
                    }
                }
            }
        
            'xPSDesiredStateConfiguration' {
                $xPSDSCVersion = $ModMapObj.ManifestFileItem.FullName | Split-Path -Parent | Split-Path -Leaf
            }
        
            'xActiveDirectory' {
                $xActiveDirectoryVersion = $ModMapObj.ManifestFileItem.FullName | Split-Path -Parent | Split-Path -Leaf
            }
        }
    }

    # Make sure WinRM in Enabled and Running on $env:ComputerName
    try {
        $null = Enable-PSRemoting -Force -ErrorAction Stop
    }
    catch {
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
            Write-Error "Problem with Enabble-PSRemoting WinRM Quick Config! Halting!"
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

    $IPsToAddToWSMANTrustedHosts = @($ServerIP)
    foreach ($IPAddr in $IPsToAddToWSMANTrustedHosts) {
        if ($CurrentTrustedHostsAsArray -notcontains $IPAddr) {
            $null = $CurrentTrustedHostsAsArray.Add($IPAddr)
        }
    }
    $UpdatedTrustedHostsString = $($CurrentTrustedHostsAsArray | Where-Object {![string]::IsNullOrWhiteSpace($_)}) -join ','
    Set-Item WSMan:\localhost\Client\TrustedHosts $UpdatedTrustedHostsString -Force

    #endregion >> Prep


    #region >> Helper Functions

    # New-SelfSignedCertifciateEx
    # Get-DSCEncryptionCert
    
    #endregion >> Helper Functions

    
    #region >> Rename Computer

    # Waiting for maximum of 15 minutes for the Server to accept new PSSessions...
    $Counter = 0
    while (![bool]$(Get-PSSession -Name "To$DesiredHostName" -ErrorAction SilentlyContinue)) {
        try {
            New-PSSession -ComputerName $ServerIP -Credential $PSRemotingLocalAdminCredentials -Name "To$DesiredHostName" -ErrorAction SilentlyContinue
            if (![bool]$(Get-PSSession -Name "To$DesiredHostName" -ErrorAction SilentlyContinue)) {throw}
        }
        catch {
            if ($Counter -le 60) {
                Write-Warning "New-PSSession 'To$DesiredHostName' failed. Trying again in 15 seconds..."
                Start-Sleep -Seconds 15
            }
            else {
                Write-Error "Unable to create new PSSession to 'To$DesiredHostName' using Local Admin account '$($PSRemotingLocalAdminCredentials.UserName)'! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        $Counter++
    }

    $InvCmdCheckSB = {
        # Make sure the Local 'Administrator' account has its password set
        $UserAccount = Get-LocalUser -Name "Administrator"
        $UserAccount | Set-LocalUser -Password $args[0]
        $env:ComputerName
    }
    $InvCmdCheckSplatParams = @{
        Session                 = Get-PSSession -Name "To$DesiredHostName"
        ScriptBlock             = $InvCmdCheckSB
        ArgumentList            = $LocalAdministratorAccountCredentials.Password
        ErrorAction             = "Stop"
    }
    try {
        $RemoteHostName = Invoke-Command @InvCmdCheckSplatParams
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    if ($RemoteHostName -ne $DesiredHostName) {
        $RenameComputerSB = {
            Rename-Computer -NewName $args[0] -LocalCredential $args[1] -Force -Restart -ErrorAction SilentlyContinue
        }
        $InvCmdRenameComputerSplatParams = @{
            Session         = Get-PSSession -Name "To$DesiredHostName"
            ScriptBlock     = $RenameComputerSB
            ArgumentList    = $DesiredHostName,$PSRemotingLocalAdminCredentials
            ErrorAction     = "SilentlyContinue"
        }
        try {
            Invoke-Command @InvCmdRenameComputerSplatParams
        }
        catch {
            Write-Error "Problem with renaming the $ServerIP to $DesiredHostName! Halting!"
            $global:FunctionResult = "1"
            return
        }

        Write-Host "Sleeping for 5 minutes to give the Server a chance to restart after name change..."
        Start-Sleep -Seconds 300
    }

    #endregion >> Rename Computer


    #region >> Wait For HostName Change

    Get-PSSession -Name "To$DesiredHostName" | Remove-PSSession
    
    # Waiting for maximum of 15 minutes for the Server to accept new PSSessions Post Name Change Reboot...
    $Counter = 0
    while (![bool]$(Get-PSSession -Name "To$DesiredHostName" -ErrorAction SilentlyContinue)) {
        try {
            New-PSSession -ComputerName $ServerIP -Credential $PSRemotingLocalAdminCredentials -Name "To$DesiredHostName" -ErrorAction SilentlyContinue
            if (![bool]$(Get-PSSession -Name "To$DesiredHostName" -ErrorAction SilentlyContinue)) {throw}
        }
        catch {
            if ($Counter -le 60) {
                Write-Warning "New-PSSession 'To$DesiredHostName' failed. Trying again in 15 seconds..."
                Start-Sleep -Seconds 15
            }
            else {
                Write-Error "Unable to create new PSSession to 'To$DesiredHostName' using Local Admin account '$($PSRemotingLocalAdminCredentials.UserName)'! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        $Counter++
    }

    #endregion >> Wait for HostName Change

    
    #region >> Prep DSC On the RemoteHost

    try {
        # Copy the DSC PowerShell Modules to the Remote Host
        $ProgramFilesPSModulePath = "C:\Program Files\WindowsPowerShell\Modules"
        foreach ($ModuleDirPath in $DSCModulesToTransfer) {
            $CopyItemSplatParams = @{
                Path            = $ModuleDirPath
                Recurse         = $True
                Destination     = "$ProgramFilesPSModulePath\$($ModuleDirPath | Split-Path -Leaf)"
                ToSession       = Get-PSSession -Name "To$DesiredHostName"
                Force           = $True
            }
            Copy-Item @CopyItemSplatParams
        }

        $FunctionsForRemoteUse = @(
            ${Function:Get-DSCEncryptionCert}.Ast.Extent.Text
            ${Function:New-SelfSignedCertificateEx}.Ast.Extent.Text
        )

        $DSCPrepSB = {
            # Load the functions we packed up:
            $using:FunctionsForRemoteUse | foreach { Invoke-Expression $_ }

            if (!$(Test-Path $using:RemoteDSCDirectory)) {
                $null = New-Item -ItemType Directory -Path $using:RemoteDSCDirectory -Force
            }

            if ($($env:PSModulePath -split ";") -notcontains $using:ProgramFilesPSModulePath) {
                $env:PSModulePath = $using:ProgramFilesPSModulePath + ";" + $env:PSModulePath
            }

            # Setup WinRM
            try {
                $null = Enable-PSRemoting -Force -ErrorAction Stop
            }
            catch {
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

            $DSCEncryptionCACertInfo = Get-DSCEncryptionCert -MachineName $using:DesiredHostName -ExportDirectory $using:RemoteDSCDirectory

            #### Configure the Local Configuration Manager (LCM) ####
            if (Test-Path "$using:RemoteDSCDirectory\$using:DesiredHostName.meta.mof") {
                Remove-Item "$using:RemoteDSCDirectory\$using:DesiredHostName.meta.mof" -Force
            }
            Configuration LCMConfig {
                Node "localhost" {
                    LocalConfigurationManager {
                        ConfigurationMode = "ApplyAndAutoCorrect"
                        RefreshFrequencyMins = 30
                        ConfigurationModeFrequencyMins = 15
                        RefreshMode = "PUSH"
                        RebootNodeIfNeeded = $True
                        ActionAfterReboot = "ContinueConfiguration"
                        CertificateId = $DSCEncryptionCACertInfo.CertInfo.Thumbprint
                    }
                }
            }
            # Create the .meta.mof file
            $LCMMetaMOFFileItem = LCMConfig -OutputPath $using:RemoteDSCDirectory
            if (!$LCMMetaMOFFileItem) {
                Write-Error "Problem creating the .meta.mof file for $using:DesiredHostName!"
                return
            }
            # Make sure the .mof file is directly under $usingRemoteDSCDirectory alongside the encryption Cert
            if ($LCMMetaMOFFileItem.FullName -ne "$using:RemoteDSCDirectory\$($LCMMetaMOFFileItem.Name)") {
                Copy-Item -Path $LCMMetaMOFFileItem.FullName -Destination "$using:RemoteDSCDirectory\$($LCMMetaMOFFileItem.Name)" -Force
            }

            # Apply the .meta.mof (i.e. LCM Settings)
            Write-Host "Applying LCM Config..."
            $null = Set-DscLocalConfigurationManager -Path $using:RemoteDSCDirectory -Force

            # Output the DSC Encryption Certificate Info
            $DSCEncryptionCACertInfo
        }

        $DSCEncryptionCACertInfo = Invoke-Command -Session $(Get-PSSession -Name "To$DesiredHostName") -ScriptBlock $DSCPrepSB

        if (!$(Test-Path $DSCResultsDownloadDirectory)) {
            $null = New-Item -ItemType Directory -Path $DSCResultsDownloadDirectory
        }
        $CopyItemSplatParams = @{
            Path            = "$RemoteDSCDirectory\DSCEncryption.cer"
            Recurse         = $True
            Destination     = "$DSCResultsDownloadDirectory\DSCEncryption.cer"
            FromSession       = Get-PSSession -Name "To$DesiredHostName"
            Force           = $True   
        }
        Copy-Item @CopyItemSplatParams
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    #endregion >> Prep DSC On the RemoteHost


    #region >> Apply DomainController DSC Config

    # The below commented config info is loaded in the Invoke-Command ScriptBlock, but is also commented out here
    # so that it's easier to review $StandaloneRootCAConfigAsStringPrep
    <#
    $ConfigData = @{
        AllNodes = @(
            @{

                NodeName = '*'
                PsDscAllowDomainUser = $true
                PsDscAllowPlainTextPassword = $true
            }
            @{
                NodeName = $DesiredHostName
                Purpose = 'Domain Controller'
                WindowsFeatures = 'AD-Domain-Services','RSAT-AD-Tools'
                RetryCount = 20
                RetryIntervalSec = 30
            }
        )

        NonNodeData = @{
            DomainName = $NewDomainName
            ADGroups = 'Information Systems'
            OrganizationalUnits = 'Information Systems','Executive'
            AdUsers = @(
                @{
                    FirstName = $NewBackupDomainAdminFirstName
                    LastName = $NewBackupDomainAdminLastName
                    Department = 'Information Systems'
                    Title = 'System Administrator'
                }
            )
        }
    }
    #>

    $NewDomainControllerConfigAsStringPrep = @(
        'configuration NewDomainController {'
        '    param ('
        '        [Parameter(Mandatory=$True)]'
        '        [pscredential]$NewDomainAdminCredentials,'
        ''
        '        [Parameter(Mandatory=$True)]'
        '        [pscredential]$LocalAdministratorAccountCredentials'
        '    )'
        ''
        "    #Import-DscResource -ModuleName 'PSDesiredStateConfiguration' -ModuleVersion $PSDSCVersion"
        "    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration' -ModuleVersion $xPSDSCVersion"
        "    Import-DscResource -ModuleName 'xActiveDirectory' -ModuleVersion $xActiveDirectoryVersion"
        ''
        '    $NewDomainAdminUser = $($NewDomainAdminCredentials.UserName -split "\\")[-1]'
        '    $NewDomainAdminUserBackup = $NewDomainAdminUser + "backup"'
        '            '
        '    Node $AllNodes.where({ $_.Purpose -eq "Domain Controller" }).NodeName'
        '    {'
        '        @($ConfigurationData.NonNodeData.ADGroups).foreach({'
        '            xADGroup $_'
        '            {'
        '                Ensure = "Present"'
        '                GroupName = $_'
        '                DependsOn = "[xADUser]FirstUser"'
        '            }'
        '        })'
        ''
        '        @($ConfigurationData.NonNodeData.OrganizationalUnits).foreach({'
        '            xADOrganizationalUnit $_'
        '            {'
        '                Ensure = "Present"'
        '                Name = ($_ -replace "-")'
        '                Path = ("DC={0},DC={1}" -f ($ConfigurationData.NonNodeData.DomainName -split "\.")[0], ($ConfigurationData.NonNodeData.DomainName -split "\.")[1])'
        '                DependsOn = "[xADUser]FirstUser"'
        '            }'
        '        })'
        ''
        '        @($ConfigurationData.NonNodeData.ADUsers).foreach({'
        '            xADUser "$($_.FirstName) $($_.LastName)"'
        '            {'
        '                Ensure = "Present"'
        '                DomainName = $ConfigurationData.NonNodeData.DomainName'
        '                GivenName = $_.FirstName'
        '                SurName = $_.LastName'
        '                UserName = ("{0}{1}" -f $_.FirstName, $_.LastName)'
        '                Department = $_.Department'
        '                Path = ("OU={0},DC={1},DC={2}" -f $_.Department, ($ConfigurationData.NonNodeData.DomainName -split "\.")[0], ($ConfigurationData.NonNodeData.DomainName -split "\.")[1])'
        '                JobTitle = $_.Title'
        '                Password = $NewDomainAdminCredentials'
        '                DependsOn = "[xADOrganizationalUnit]$($_.Department)"'
        '            }'
        '        })'
        ''
        '        ($Node.WindowsFeatures).foreach({'
        '            WindowsFeature $_'
        '            {'
        '                Ensure = "Present"'
        '                Name = $_'
        '            }'
        '        })'
        ''
        '        xADDomain ADDomain'
        '        {'
        '            DomainName = $ConfigurationData.NonNodeData.DomainName'
        '            DomainAdministratorCredential = $LocalAdministratorAccountCredentials'
        '            SafemodeAdministratorPassword = $LocalAdministratorAccountCredentials'
        '            DependsOn = "[WindowsFeature]AD-Domain-Services"'
        '        }'
        ''
        '        xWaitForADDomain DscForestWait'
        '        {'
        '            DomainName = $ConfigurationData.NonNodeData.DomainName'
        '            DomainUserCredential = $LocalAdministratorAccountCredentials'
        '            RetryCount = $Node.RetryCount'
        '            RetryIntervalSec = $Node.RetryIntervalSec'
        '            DependsOn = "[xADDomain]ADDomain"'
        '        }'
        ''
        '        xADUser FirstUser'
        '        {'
        '            DomainName = $ConfigurationData.NonNodeData.DomainName'
        '            DomainAdministratorCredential = $LocalAdministratorAccountCredentials'
        '            UserName = $NewDomainAdminUser'
        '            Password = $NewDomainAdminCredentials'
        '            Ensure = "Present"'
        '            DependsOn = "[xWaitForADDomain]DscForestWait"'
        '        }'
        ''
        '        xADGroup DomainAdmins {'
        '            GroupName = "Domain Admins"'
        '            MembersToInclude = $NewDomainAdminUser,$NewDomainAdminUserBackup'
        '            DependsOn = "[xADUser]FirstUser"'
        '        }'
        '        '
        '        xADGroup EnterpriseAdmins {'
        '            GroupName = "Enterprise Admins"'
        '            GroupScope = "Universal"'
        '            MembersToInclude = $NewDomainAdminUser,$NewDomainAdminUserBackup'
        '            DependsOn = "[xADUser]FirstUser"'
        '        }'
        ''
        '        xADGroup GroupPolicyOwners {'
        '            GroupName = "Group Policy Creator Owners"'
        '            MembersToInclude = $NewDomainAdminUser,$NewDomainAdminUserBackup'
        '            DependsOn = "[xADUser]FirstUser"'
        '        }'
        ''
        '        xADGroup SchemaAdmins {'
        '            GroupName = "Schema Admins"'
        '            GroupScope = "Universal"'
        '            MembersToInclude = $NewDomainAdminUser,$NewDomainAdminUserBackup'
        '            DependsOn = "[xADUser]FirstUser"'
        '        }'
        '    }'
        '}'
    )

    try {
        $NewDomainControllerConfigAsString = [scriptblock]::Create($($NewDomainControllerConfigAsStringPrep -join "`n")).ToString()
    }
    catch {
        Write-Error $_
        Write-Error "There is a problem with the NewDomainController DSC Configuration Function! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $NewDomainControllerSB = {
        #### Apply the DSC Configuration ####
        # Load the NewDomainController DSC Configuration function
        $using:NewDomainControllerConfigAsString | Invoke-Expression

        $NewDomainControllerConfigData = @{
            AllNodes = @(
                @{
                    NodeName = '*'
                    PsDscAllowDomainUser = $true
                    #PsDscAllowPlainTextPassword = $true
                    CertificateFile = $using:DSCEncryptionCACertInfo.CertFile.FullName
                    Thumbprint = $using:DSCEncryptionCACertInfo.CertInfo.Thumbprint
                }
                @{
                    NodeName = $using:DesiredHostName
                    Purpose = 'Domain Controller'
                    WindowsFeatures = 'AD-Domain-Services','RSAT-AD-Tools'
                    RetryCount = 20
                    RetryIntervalSec = 30
                }
            )
    
            NonNodeData = @{
                DomainName = $using:NewDomainName
                ADGroups = 'Information Systems'
                OrganizationalUnits = 'Information Systems','Executive'
                AdUsers = @(
                    @{
                        FirstName = $using:NewBackupDomainAdminFirstName
                        LastName = $using:NewBackupDomainAdminLastName
                        Department = 'Information Systems'
                        Title = 'System Administrator'
                    }
                )
            }
        }

        # IMPORTANT NOTE: The resulting .mof file (representing the DSC configuration), will be in the
        # directory "$using:RemoteDSCDir\STANDALONE_ROOTCA"
        if (Test-Path "$using:RemoteDSCDirectory\$($using:DesiredHostName).mof") {
            Remove-Item "$using:RemoteDSCDirectory\$($using:DesiredHostName).mof" -Force
        }
        $NewDomainControllerConfigSplatParams = @{
            NewDomainAdminCredentials               = $using:NewDomainAdminCredentials
            LocalAdministratorAccountCredentials    = $using:LocalAdministratorAccountCredentials
            OutputPath                              = $using:RemoteDSCDirectory
            ConfigurationData                       = $NewDomainControllerConfigData
        }
        $MOFFileItem = NewDomainController @NewDomainControllerConfigSplatParams
        if (!$MOFFileItem) {
            Write-Error "Problem creating the .mof file for $using:DesiredHostName!"
            return
        }

        # Make sure the .mof file is directly under $usingRemoteDSCDirectory alongside the encryption Cert
        if ($MOFFileItem.FullName -ne "$using:RemoteDSCDirectory\$($MOFFileItem.Name)") {
            Copy-Item -Path $MOFFileItem.FullName -Destination "$using:RemoteDSCDirectory\$($MOFFileItem.Name)" -Force
        }

        # Apply the .mof (i.e. setup the New Domain Controller)
        Write-Host "Applying NewDomainController Config..."
        Start-DscConfiguration -Path $using:RemoteDSCDirectory -Force -Wait
    }
    
    try {
        $NewDCDSCApplication = Invoke-Command -Session $(Get-PSSession -Name "To$DesiredHostName") -ScriptBlock $NewDomainControllerSB
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    Write-Host "Sleeping for 5 minutes to give the new Domain Controller a chance to finish implementing config..."
    Start-Sleep -Seconds 300

    # Try to use $NewDomainAdminCredentials to create a PSSession with the Domain Controller
    # Try for maximum of 15 minutes and then give up
    $Counter = 0
    while (![bool]$(Get-PSSession -Name "ToDCPostDomainCreation" -ErrorAction SilentlyContinue)) {
        try {
            New-PSSession -ComputerName $ServerIP -Credential $NewDomainAdminCredentials -Name "ToDCPostDomainCreation" -ErrorAction SilentlyContinue
            if (![bool]$(Get-PSSession -Name "ToDCPostDomainCreation" -ErrorAction SilentlyContinue)) {throw}
        }
        catch {
            if ($Counter -le 60) {
                Write-Warning "New-PSSession 'ToDCPostDomainCreation' failed. Trying again in 15 seconds..."
                Start-Sleep -Seconds 15
            }
            else {
                Write-Error "Unable to create new PSSession to 'ToDCPostDomainCreation' using New Domain Admin account '$($NewDomainAdminCredentials.UserName)'! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        $Counter++
    }

    if ([bool]$(Get-PSSession -Name "ToDCPostDomainCreation" -ErrorAction SilentlyContinue)) {
        "DC Installation Success"
    }
    else {
        "DC Installation Failure"
    }

    #endregion >> Apply DomainController DSC Config
}


<#
    .SYNOPSIS
        This function configures the target Windows 2012 R2 or Windows 2016 Server to be a new Enterprise Root Certification Authority.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER DomainAdminCredentials
        This parameter is MANDATORY.

        This parameter takes a PSCredential. The Domain Admin Credentials will be used to configure the new Root CA. This means that
        the Domain Account provided MUST be a member of the following Security Groups in Active Directory:
            - Domain Admins
            - Domain Users
            - Enterprise Admins
            - Group Policy Creator Owners
            - Schema Admins

    .PARAMETER RootCAIPOrFQDN
        This parameter is OPTIONAL.

        This parameter takes a string that represents an IPv4 address or DNS-Resolveable FQDN that refers to the target Windows
        Server that will become the new Enterprise Root CA. If it is NOT used, then the localhost will be configured as the
        new Enterprise Root CA.

    .PARAMETER CAType
        This parameter is OPTIONAL, however, its default value is "EnterpriseRootCA".

        This parameter takes a string that represents the type of Root Certificate Authority that the target server will become.
        Currently this parameter only accepts "EnterpriseRootCA" as a valid value. But in the future, "StandaloneRootCA" will
        also become a valid value.

    .PARAMETER NewComputerTemplateCommonName
        This parameter is OPTIONAL, however, its default value is "<DomainPrefix>" + "Computer".

        This parameter takes a string that represents the desired Common Name for the new custom Computer (Machine)
        Certificate Template. This updates some undesirable defaults that come with the default Computer (Machine)
        Certificate Template.

    .PARAMETER NewWebServerTemplateCommonName
        This parameter is OPTIONAL, however, its default value is "<DomainPrefix>" + "WebServer".

        This parameter takes a string that represents the desired Common Name for the new custom WebServer
        Certificate Template. This updates some undesirable defaults that come with the default WebServer
        Certificate Template.

    .PARAMETER FileOutputDirectory
        This parameter is OPTIONAL, however, its default value is "C:\NewRootCAOutput".

        This parameter takes a string that represents the full path to a directory that will contain all files generated
        by the New-RootCA function.

        IMPORTANT NOTE: This directory will be made available to the network (it will become an SMB Share) so that the
        Subordinate Certificate Authority can download needed files. This SMB share will only be available TEMPORARILY.
        It will NOT survive a reboot.

    .PARAMETER CryptoProvider
        This parameter is OPTIONAL, however, its default value is "Microsoft Software Key Storage Provider".

        This parameter takes a string that represents the Cryptographic Provider used by the new Root CA.
        Currently, the only valid value for this parameter is "Microsoft Software Key Storage Provider".

    .PARAMETER KeyLength
        This parameter is OPTIONAL, however, its default value is 2048.

        This parameter takes an integer with value 2048 or 4096.

    .PARAMETER HashAlgorithm
        This parameter is OPTIONAL, however, its default value is SHA256.

        This parameter takes a string with acceptable values as follows: "SHA1","SHA256","SHA384","SHA512","MD5","MD4","MD2"

    .PARAMETER KeyAlgorithmValue
        This parameter is OPTIONAL, however, its default value is RSA.

        This parameter takes a string with acceptable values: "RSA"

    .PARAMETER CDPUrl
        This parameter is OPTIONAL, however, its default value is "http://pki.$DomainName/certdata/<CaName><CRLNameSuffix>.crl"

        This parameter takes a string that represents a Certificate Distribution List Revocation URL. The current default
        configuration does not make this Url active, however, it still needs to be configured.

    .PARAMETER AIAUrl
        This parameter is OPTIONAL, however, its default value is "http://pki.$DomainName/certdata/<CaName><CertificateName>.crt"

        This parameter takes a string that represents an Authority Information Access (AIA) Url (i.e. the location where the certificate of
        of certificate's issuer can be downloaded). The current default configuration does not mahe this Url active, but it still
        needs to be configured.

    .EXAMPLE
        # Make the localhost a Root CA

        PS C:\Users\zeroadmin> $DomainAdminCreds = [pscredential]::new("alpha\alphaadmin",$(Read-Host 'Enter Passsword' -AsSecureString))
        Enter Passsword: ************
        PS C:\Users\zeroadmin> $CreateRootCASplatParams = @{
        >> DomainAdminCredentials   = $DomainAdminCreds
        >> }
        PS C:\Users\zeroadmin> $CreateRootCAResult = Create-RootCA @CreateRootCASplatParams

    .EXAMPLE
        # Make the Remote Host a Root CA

        PS C:\Users\zeroadmin> $DomainAdminCreds = [pscredential]::new("alpha\alphaadmin",$(Read-Host 'Enter Passsword' -AsSecureString))
        Enter Passsword: ************
        PS C:\Users\zeroadmin> $CreateRootCASplatParams = @{
        >> DomainAdminCredentials   = $DomainAdminCreds
        >> RootCAIPOrFQDN           = "192.168.2.112"                
        >> }
        PS C:\Users\zeroadmin> $CreateRootCAResult = Create-RootCA @CreateRootCASplatParams

#>
function New-RootCA {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [pscredential]$DomainAdminCredentials,

        [Parameter(Mandatory=$False)]
        [string]$RootCAIPOrFQDN,

        [Parameter(Mandatory=$False)]
        #[ValidateSet("EnterpriseRootCa","StandaloneRootCa")]
        [ValidateSet("EnterpriseRootCA")]
        [string]$CAType,

        [Parameter(Mandatory=$False)]
        [string]$NewComputerTemplateCommonName,

        [Parameter(Mandatory=$False)]
        [string]$NewWebServerTemplateCommonName,

        [Parameter(Mandatory=$False)]
        [string]$FileOutputDirectory,

        [Parameter(Mandatory=$False)]
        <#
        [ValidateSet("Microsoft Base Cryptographic Provider v1.0","Microsoft Base DSS and Diffie-Hellman Cryptographic Provider",
        "Microsoft Base DSS Cryptographic Provider","Microsoft Base Smart Card Crypto Provider",
        "Microsoft DH SChannel Cryptographic Provider","Microsoft Enhanced Cryptographic Provider v1.0",
        "Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider",
        "Microsoft Enhanced RSA and AES Cryptographic Provider","Microsoft RSA SChannel Cryptographic Provider",
        "Microsoft Strong Cryptographic Provider","Microsoft Software Key Storage Provider",
        "Microsoft Passport Key Storage Provider")]
        #>
        [ValidateSet("Microsoft Software Key Storage Provider")]
        [string]$CryptoProvider,

        [Parameter(Mandatory=$False)]
        [ValidateSet("2048","4096")]
        [int]$KeyLength,

        [Parameter(Mandatory=$False)]
        [ValidateSet("SHA1","SHA256","SHA384","SHA512","MD5","MD4","MD2")]
        [string]$HashAlgorithm,

        # For now, stick to just using RSA
        [Parameter(Mandatory=$False)]
        #[ValidateSet("RSA","DH","DSA","ECDH_P256","ECDH_P521","ECDSA_P256","ECDSA_P384","ECDSA_P521")]
        [ValidateSet("RSA")]
        [string]$KeyAlgorithmValue,

        [Parameter(Mandatory=$False)]
        [ValidatePattern('http.*?\/<CaName><CRLNameSuffix>\.crl$')]
        [string]$CDPUrl,

        [Parameter(Mandatory=$False)]
        [ValidatePattern('http.*?\/<CaName><CertificateName>.crt$')]
        [string]$AIAUrl
    )
    
    #region >> Helper Functions

    # NewUniqueString
    # TestIsValidIPAddress
    # ResolveHost
    # GetDomainController

    function SetupRootCA {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=$True)]
            [pscredential]$DomainAdminCredentials,

            [Parameter(Mandatory=$True)]
            [System.Collections.ArrayList]$NetworkInfoPSObjects,

            [Parameter(Mandatory=$True)]
            [ValidateSet("EnterpriseRootCA")]
            [string]$CAType,

            [Parameter(Mandatory=$True)]
            [string]$NewComputerTemplateCommonName,

            [Parameter(Mandatory=$True)]
            [string]$NewWebServerTemplateCommonName,

            [Parameter(Mandatory=$True)]
            [string]$FileOutputDirectory,

            [Parameter(Mandatory=$True)]
            [ValidateSet("Microsoft Software Key Storage Provider")]
            [string]$CryptoProvider,

            [Parameter(Mandatory=$True)]
            [ValidateSet("2048","4096")]
            [int]$KeyLength,

            [Parameter(Mandatory=$True)]
            [ValidateSet("SHA1","SHA256","SHA384","SHA512","MD5","MD4","MD2")]
            [string]$HashAlgorithm,

            [Parameter(Mandatory=$True)]
            [ValidateSet("RSA")]
            [string]$KeyAlgorithmValue,

            [Parameter(Mandatory=$True)]
            [ValidatePattern('http.*?\/<CaName><CRLNameSuffix>\.crl$')]
            [string]$CDPUrl,

            [Parameter(Mandatory=$True)]
            [ValidatePattern('http.*?\/<CaName><CertificateName>.crt$')]
            [string]$AIAUrl
        )

        #region >> Prep

        # Import any Module Dependencies
        $RequiredModules = @("PSPKI","ServerManager")
        $InvModDepSplatParams = @{
            RequiredModules                     = $RequiredModules
            InstallModulesNotAvailableLocally   = $True
            ErrorAction                         = "Stop"
        }
        $ModuleDependenciesMap = InvokeModuleDependencies @InvModDepSplatParams
        $PSPKIModuleVerCheck = $ModuleDependenciesMap.SuccessfulModuleImports | Where-Object {$_.ModuleName -eq "PSPKI"}
        $ServerManagerModuleVerCheck = $ModuleDependenciesMap.SuccessfulModuleImports | Where-Object {$_.ModuleName -eq "ServerManager"}

        # Make sure we can find the Domain Controller(s)
        try {
            $DomainControllerInfo = GetDomainController -Domain $(Get-CimInstance win32_computersystem).Domain -WarningAction SilentlyContinue
            if (!$DomainControllerInfo -or $DomainControllerInfo.PrimaryDomainController -eq $null) {throw "Unable to find Primary Domain Controller! Halting!"}
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        # Make sure time is synchronized with NTP Servers/Domain Controllers (i.e. might be using NT5DS instead of NTP)
        # See: https://giritharan.com/time-synchronization-in-active-directory-domain/
        $null = W32tm /resync /rediscover /nowait

        if (!$FileOutputDirectory) {
            $FileOutputDirectory = "C:\NewRootCAOutput"
        }
        if (!$(Test-Path $FileOutputDirectory)) {
            $null = New-Item -ItemType Directory -Path $FileOutputDirectory 
        }

        $WindowsFeaturesToAdd = @(
            "Adcs-Cert-Authority"
            "RSAT-AD-Tools"
        )
        foreach ($FeatureName in $WindowsFeaturesToAdd) {
            $SplatParams = @{
                Name    = $FeatureName
            }
            if ($FeatureName -eq "Adcs-Cert-Authority") {
                $SplatParams.Add("IncludeManagementTools",$True)
            }

            try {
                $null = Add-WindowsFeature @SplatParams
            }
            catch {
                Write-Error $_
                Write-Error "Problem with 'Add-WindowsFeature $FeatureName'! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        $RelevantRootCANetworkInfo = $NetworkInfoPSObjects | Where-Object {$_.ServerPurpose -eq "RootCA"}

        # Make sure WinRM in Enabled and Running on $env:ComputerName
        try {
            $null = Enable-PSRemoting -Force -ErrorAction Stop
        }
        catch {
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
                Write-Error "Problem with Enabble-PSRemoting WinRM Quick Config! Halting!"
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

        $ItemsToAddToWSMANTrustedHosts = @(
            $RelevantRootCANetworkInfo.FQDN
            $RelevantRootCANetworkInfo.HostName
            $RelevantRootCANetworkInfo.IPAddress
        )
        foreach ($NetItem in $ItemsToAddToWSMANTrustedHosts) {
            if ($CurrentTrustedHostsAsArray -notcontains $NetItem) {
                $null = $CurrentTrustedHostsAsArray.Add($NetItem)
            }
        }
        $UpdatedTrustedHostsString = $($CurrentTrustedHostsAsArray | Where-Object {![string]::IsNullOrWhiteSpace($_)}) -join ','
        Set-Item WSMan:\localhost\Client\TrustedHosts $UpdatedTrustedHostsString -Force

        #endregion >> Prep

        #region >> Install ADCSCA
        try {
            $FinalCryptoProvider = $KeyAlgorithmValue + "#" + $CryptoProvider
            $InstallADCSCertAuthSplatParams = @{
                Credential                  = $DomainAdminCredentials
                CAType                      = $CAType
                CryptoProviderName          = $FinalCryptoProvider
                KeyLength                   = $KeyLength
                HashAlgorithmName           = $HashAlgorithm
                CACommonName                = $env:ComputerName
                CADistinguishedNameSuffix   = $RelevantRootCANetworkInfo.DomainLDAPString
                DatabaseDirectory           = $(Join-Path $env:SystemRoot "System32\CertLog")
                ValidityPeriod              = "years"
                ValidityPeriodUnits         = 20
                Force                       = $True
                ErrorAction                 = "Stop"
            }
            $null = Install-AdcsCertificationAuthority @InstallADCSCertAuthSplatParams
        }
        catch {
            Write-Error $_
            Write-Error "Problem with Install-AdcsCertificationAuthority cmdlet! Halting!"
            $global:FunctionResult = "1"
            return
        }

        try {
            $null = certutil -setreg CA\\CRLPeriod "Years"
            $null = certutil -setreg CA\\CRLPeriodUnits 1
            $null = certutil -setreg CA\\CRLOverlapPeriod "Days"
            $null = certutil -setreg CA\\CRLOverlapUnits 7

            Write-Host "Done initial certutil commands..."

            # Remove pre-existing ldap/http CDPs, add custom CDP
            if ($PSPKIModuleVerCheck.ModulePSCompatibility -eq "WinPS") {
                # Update the Local CDP
                $LocalCDP = (Get-CACrlDistributionPoint)[0]
                $null = $LocalCDP | Remove-CACrlDistributionPoint -Force
                $LocalCDP.PublishDeltaToServer = $false
                $null = $LocalCDP | Add-CACrlDistributionPoint -Force

                $null = Get-CACrlDistributionPoint | Where-Object { $_.URI -like "http*" -or $_.Uri -like "ldap*" } | Remove-CACrlDistributionPoint -Force
                $null = Add-CACrlDistributionPoint -Uri $CDPUrl -AddToCertificateCdp -Force

                # Remove pre-existing ldap/http AIAs, add custom AIA
                $null = Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like "http*" -or $_.Uri -like "ldap*" } | Remove-CAAuthorityInformationAccess -Force
                $null = Add-CAAuthorityInformationAccess -Uri $AIAUrl -AddToCertificateAIA -Force
            }
            else {
                $null = Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                    # Update the Local CDP
                    $LocalCDP = (Get-CACrlDistributionPoint)[0]
                    $null = $LocalCDP | Remove-CACrlDistributionPoint -Force
                    $LocalCDP.PublishDeltaToServer = $false
                    $null = $LocalCDP | Add-CACrlDistributionPoint -Force

                    $null = Get-CACrlDistributionPoint | Where-Object { $_.URI -like "http*" -or $_.Uri -like "ldap*" } | Remove-CACrlDistributionPoint -Force
                    $null = Add-CACrlDistributionPoint -Uri $args[0] -AddToCertificateCdp -Force

                    # Remove pre-existing ldap/http AIAs, add custom AIA
                    $null = Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like "http*" -or $_.Uri -like "ldap*" } | Remove-CAAuthorityInformationAccess -Force
                    $null = Add-CAAuthorityInformationAccess -Uri $args[1] -AddToCertificateAIA -Force
                } -ArgumentList $CDPUrl,$AIAUrl
            }

            Write-Host "Done CDP and AIA cmdlets..."

            # Enable all event auditing
            $null = certutil -setreg CA\\AuditFilter 127

            Write-Host "Done final certutil command..."
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        try {
            $null = Restart-Service certsvc -ErrorAction Stop
        }
        catch {
            Write-Error $_
            Write-Error "Problem with 'Restart-Service certsvc'! Halting!"
            $global:FunctionResult = "1"
            return
        }

        while ($(Get-Service certsvc).Status -ne "Running") {
            Write-Host "Waiting for the 'certsvc' service to start..."
            Start-Sleep -Seconds 5
        }

        #endregion >> Install ADCSCA

        #region >> New Computer/Machine Template

        Write-Host "Creating new Machine Certificate Template..."

        while (!$WebServTempl -or !$ComputerTempl) {
            # NOTE: ADSI type accelerator does not exist in PSCore
            if ($PSVersionTable.PSEdition -ne "Core") {
                $ConfigContext = $([System.DirectoryServices.DirectoryEntry]"LDAP://RootDSE").ConfigurationNamingContext
            }
            else {
                $DomainSplit = $(Get-CimInstance win32_computersystem).Domain -split "\."
                $ConfigContext = "CN=Configuration," + $($(foreach ($DC in $DomainSplit) {"DC=$DC"}) -join ",")
            }

            $LDAPLocation = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"
            $ADSI = New-Object System.DirectoryServices.DirectoryEntry($LDAPLocation,$DomainAdminCredentials.UserName,$($DomainAdminCredentials.GetNetworkCredential().Password),"Secure")

            $WebServTempl = $ADSI.psbase.children | Where-Object {$_.distinguishedName -match "CN=WebServer,"}
            $ComputerTempl = $ADSI.psbase.children | Where-Object {$_.distinguishedName -match "CN=Machine,"}

            Write-Host "Waiting for Active Directory 'LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext' to contain default Machine/Computer and WebServer Certificate Templates..."
            Start-Sleep -Seconds 15
        }

        $OIDRandComp = (Get-Random -Maximum 999999999999999).tostring('d15')
        $OIDRandComp = $OIDRandComp.Insert(8,'.')
        $CompOIDValue = $ComputerTempl.'msPKI-Cert-Template-OID'
        $NewCompTemplOID = $CompOIDValue.subString(0,$CompOIDValue.length-4)+$OIDRandComp

        $NewCompTempl = $ADSI.Create("pKICertificateTemplate","CN=$NewComputerTemplateCommonName")
        $NewCompTempl.put("distinguishedName","CN=$NewComputerTemplateCommonName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext")
        $NewCompTempl.put("flags","131680")
        $NewCompTempl.put("displayName","$NewComputerTemplateCommonName")
        $NewCompTempl.put("revision","100")
        $NewCompTempl.put("pKIDefaultKeySpec","1")
        $NewCompTempl.put("pKIMaxIssuingDepth","0")
        $pkiCritExt = "2.5.29.17","2.5.29.15"
        $NewCompTempl.put("pKICriticalExtensions",$pkiCritExt)
        $ExtKeyUse = "1.3.6.1.5.5.7.3.1","1.3.6.1.5.5.7.3.2"
        $NewCompTempl.put("pKIExtendedKeyUsage",$ExtKeyUse)
        $NewCompTempl.put("pKIDefaultCSPs","1,Microsoft RSA SChannel Cryptographic Provider")
        $NewCompTempl.put("msPKI-RA-Signature","0")
        $NewCompTempl.put("msPKI-Enrollment-Flag","0")
        $NewCompTempl.put("msPKI-Private-Key-Flag","0") # Used to be "50659328"
        $NewCompTempl.put("msPKI-Certificate-Name-Flag","1")
        $NewCompTempl.put("msPKI-Minimal-Key-Size","2048")
        $NewCompTempl.put("msPKI-Template-Schema-Version","2") # This needs to be either "1" or "2" for it to show up in the ADCS Website dropdown
        $NewCompTempl.put("msPKI-Template-Minor-Revision","2")
        $NewCompTempl.put("msPKI-Cert-Template-OID","$NewCompTemplOID")
        $AppPol = "1.3.6.1.5.5.7.3.1","1.3.6.1.5.5.7.3.2"
        $NewCompTempl.put("msPKI-Certificate-Application-Policy",$AppPol)
        $NewCompTempl.Setinfo()
        # Get the last few attributes from the existing default "CN=Machine" Certificate Template
        $NewCompTempl.pKIOverlapPeriod = $ComputerTempl.pKIOverlapPeriod # Used to be $WebServTempl.pKIOverlapPeriod
        $NewCompTempl.pKIKeyUsage = $ComputerTempl.pKIKeyUsage # Used to be $WebServTempl.pKIKeyUsage
        $NewCompTempl.pKIExpirationPeriod = $ComputerTempl.pKIExpirationPeriod # Used to be $WebServTempl.pKIExpirationPeriod
        $NewCompTempl.Setinfo()

        # Set Access Rights / Permissions on the $NewCompTempl LDAP object
        $AdObj = New-Object System.Security.Principal.NTAccount("Domain Computers")
        $identity = $AdObj.Translate([System.Security.Principal.SecurityIdentifier])
        $adRights = "ExtendedRight"
        $type = "Allow"
        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity,$adRights,$type)
        $NewCompTempl.psbase.ObjectSecurity.SetAccessRule($ACE)
        $NewCompTempl.psbase.commitchanges()

        #endregion >> New Computer/Machine Template

        #region >> New WebServer Template

        Write-Host "Creating new WebServer Certificate Template..."

        $OIDRandWebServ = (Get-Random -Maximum 999999999999999).tostring('d15')
        $OIDRandWebServ = $OIDRandWebServ.Insert(8,'.')
        $WebServOIDValue = $WebServTempl.'msPKI-Cert-Template-OID'
        $NewWebServTemplOID = $WebServOIDValue.subString(0,$WebServOIDValue.length-4)+$OIDRandWebServ

        $NewWebServTempl = $ADSI.Create("pKICertificateTemplate", "CN=$NewWebServerTemplateCommonName") 
        $NewWebServTempl.put("distinguishedName","CN=$NewWebServerTemplateCommonName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext")
        $NewWebServTempl.put("flags","131649")
        $NewWebServTempl.put("displayName","$NewWebServerTemplateCommonName")
        $NewWebServTempl.put("revision","100")
        $NewWebServTempl.put("pKIDefaultKeySpec","1")
        $NewWebServTempl.put("pKIMaxIssuingDepth","0")
        $pkiCritExt = "2.5.29.15"
        $NewWebServTempl.put("pKICriticalExtensions",$pkiCritExt)
        $ExtKeyUse = "1.3.6.1.5.5.7.3.1","1.3.6.1.5.5.7.3.2"
        $NewWebServTempl.put("pKIExtendedKeyUsage",$ExtKeyUse)
        $pkiCSP = "1,Microsoft RSA SChannel Cryptographic Provider","2,Microsoft DH SChannel Cryptographic Provider"
        $NewWebServTempl.put("pKIDefaultCSPs",$pkiCSP)
        $NewWebServTempl.put("msPKI-RA-Signature","0")
        $NewWebServTempl.put("msPKI-Enrollment-Flag","0")
        $NewWebServTempl.put("msPKI-Private-Key-Flag","0") # Used to be "16842752"
        $NewWebServTempl.put("msPKI-Certificate-Name-Flag","1")
        $NewWebServTempl.put("msPKI-Minimal-Key-Size","2048")
        $NewWebServTempl.put("msPKI-Template-Schema-Version","2") # This needs to be either "1" or "2" for it to show up in the ADCS Website dropdown
        $NewWebServTempl.put("msPKI-Template-Minor-Revision","2")
        $NewWebServTempl.put("msPKI-Cert-Template-OID","$NewWebServTemplOID")
        $AppPol = "1.3.6.1.5.5.7.3.1","1.3.6.1.5.5.7.3.2"
        $NewWebServTempl.put("msPKI-Certificate-Application-Policy",$AppPol)
        $NewWebServTempl.Setinfo()
        # Get the last few attributes from the existing default "CN=WebServer" Certificate Template
        $NewWebServTempl.pKIOverlapPeriod = $WebServTempl.pKIOverlapPeriod
        $NewWebServTempl.pKIKeyUsage = $WebServTempl.pKIKeyUsage
        $NewWebServTempl.pKIExpirationPeriod = $WebServTempl.pKIExpirationPeriod
        $NewWebServTempl.Setinfo()

        #endregion >> New WebServer Template

        #region >> Finish Up

        # Add the newly created custom Computer and WebServer Certificate Templates to List of Certificate Templates to Issue
        # For this to be (relatively) painless, we need the following PSPKI Module cmdlets
        if ($PSPKIModuleVerCheck.ModulePSCompatibility -eq "WinPS") {
            $null = Get-CertificationAuthority -Name $env:ComputerName | Get-CATemplate | Add-CATemplate -Name $NewComputerTemplateCommonName | Set-CATemplate
            $null = Get-CertificationAuthority -Name $env:ComputerName | Get-CATemplate | Add-CATemplate -Name $NewWebServerTemplateCommonName | Set-CATemplate
        }
        else {
            $null = Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                $null = Get-CertificationAuthority -Name $env:ComputerName | Get-CATemplate | Add-CATemplate -Name $args[0] | Set-CATemplate
                $null = Get-CertificationAuthority -Name $env:ComputerName | Get-CATemplate | Add-CATemplate -Name $args[1] | Set-CATemplate
            } -ArgumentList $NewComputerTemplateCommonName,$NewWebServerTemplateCommonName
        }

        # Export New Certificate Templates to NewCert-Templates Directory
        $ldifdeUserName = $($DomainAdminCredentials.UserName -split "\\")[-1]
        $ldifdeDomain = $RelevantRootCANetworkInfo.DomainName
        $ldifdePwd = $DomainAdminCredentials.GetNetworkCredential().Password
        $null = ldifde -m -v -b $ldifdeUserName $ldifdeDomain $ldifdePwd -d "CN=$NewComputerTemplateCommonName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext" -f "$FileOutputDirectory\$NewComputerTemplateCommonName.ldf"
        $null = ldifde -m -v -b $ldifdeUserName $ldifdeDomain $ldifdePwd -d "CN=$NewWebServerTemplateCommonName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext" -f "$FileOutputDirectory\$NewWebServerTemplateCommonName.ldf"

        # Side Note: You can import Certificate Templates on another Certificate Authority via ldife.exe with:
        <#
        ldifde -i -k -f "$FileOutputDirectory\$NewComputerTemplateCommonName.ldf"
        ldifde -i -k -f "$FileOutputDirectory\$NewWebServerTemplateCommonName.ldf"
        #>

        # Generate New CRL and Copy Contents of CertEnroll to $FileOutputDirectory
        # NOTE: The below 'certutil -crl' outputs the new .crl file to "C:\Windows\System32\CertSrv\CertEnroll"
        # which happens to contain some other important files that we'll need
        $null = certutil -crl
        Copy-Item -Path "C:\Windows\System32\CertSrv\CertEnroll\*" -Recurse -Destination $FileOutputDirectory -Force
        # Convert RootCA .crt DER Certificate to Base64 Just in Case You Want to Use With Linux
        $CrtFileItem = Get-ChildItem -Path $FileOutputDirectory -File -Recurse | Where-Object {$_.Name -match "$env:ComputerName\.crt"}
        $null = certutil -encode $($CrtFileItem.FullName) $($CrtFileItem.FullName -replace '\.crt','_base64.cer')

        # Make $FileOutputDirectory a Network Share until the Subordinate CA can download the files
        # IMPORTANT NOTE: The below -CATimeout parameter should be in Seconds. So after 12000 seconds, the SMB Share
        # will no longer be available
        # IMPORTANT NOTE: The below -Temporary switch means that the SMB Share will NOT survive a reboot
        $null = New-SMBShare -Name RootCAFiles -Path $FileOutputDirectory -CATimeout 12000 -Temporary
        # Now the SMB Share  should be available
        $RootCASMBShareFQDNLocation = '\\' + $RelevantRootCANetworkInfo.FQDN + "\RootCAFiles"
        $RootCASMBShareIPLocation = '\\' + $RelevantRootCANetworkInfo.IPAddress + "\RootCAFiles"

        Write-Host "Successfully configured Root Certificate Authority" -ForegroundColor Green
        Write-Host "RootCA Files needed by the new Subordinate/Issuing/Intermediate CA Server(s) are now TEMPORARILY available at SMB Share located:`n$RootCASMBShareFQDNLocation`nOR`n$RootCASMBShareIPLocation" -ForegroundColor Green
        
        #endregion >> Finish Up

        [pscustomobject] @{
            SMBShareIPLocation = $RootCASMBShareIPLocation
            SMBShareFQDNLocation = $RootCASMBShareFQDNLocation
        }
    }

    #endregion >> Helper Functions


    #region >> Initial Prep

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

    [System.Collections.ArrayList]$NetworkLocationObjsToResolve = @()
    if ($PSBoundParameters['RootCAIPOrFQDN']) {
        $RootCAPSObj = [pscustomobject]@{
            ServerPurpose       = "RootCA"
            NetworkLocation     = $RootCAIPOrFQDN
        }
    }
    else {
        $RootCAPSObj = [pscustomobject]@{
            ServerPurpose       = "RootCA"
            NetworkLocation     = $env:ComputerName + "." + $(Get-CimInstance win32_computersystem).Domain
        }
    }
    $null = $NetworkLocationObjsToResolve.Add($RootCAPSObj)

    [System.Collections.ArrayList]$NetworkInfoPSObjects = @()
    foreach ($NetworkLocationObj in $NetworkLocationObjsToResolve) {
        if ($($NetworkLocation -split "\.")[0] -ne $env:ComputerName -and
        $NetworkLocation -ne $PrimaryIP -and
        $NetworkLocation -ne "$env:ComputerName.$($(Get-CimInstance win32_computersystem).Domain)"
        ) {
            try {
                $NetworkInfo = ResolveHost -HostNameOrIP $NetworkLocationObj.NetworkLocation
                $DomainName = $NetworkInfo.Domain
                $FQDN = $NetworkInfo.FQDN
                $IPAddr = $NetworkInfo.IPAddressList[0]
                $DomainShortName = $($DomainName -split "\.")[0]
                $DomainLDAPString = $(foreach ($StringPart in $($DomainName -split "\.")) {"DC=$StringPart"}) -join ','

                if (!$NetworkInfo -or $DomainName -eq "Unknown" -or !$DomainName -or $FQDN -eq "Unknown" -or !$FQDN) {
                    throw "Unable to gather Domain Name and/or FQDN info about '$NetworkLocation'! Please check DNS. Halting!"
                }
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }

            # Make sure WinRM in Enabled and Running on $env:ComputerName
            try {
                $null = Enable-PSRemoting -Force -ErrorAction Stop
            }
            catch {
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
                    Write-Error "Problem with Enabble-PSRemoting WinRM Quick Config! Halting!"
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

            $ItemsToAddToWSMANTrustedHosts = @($IPAddr,$FQDN,$($($FQDN -split "\.")[0]))
            foreach ($NetItem in $ItemsToAddToWSMANTrustedHosts) {
                if ($CurrentTrustedHostsAsArray -notcontains $NetItem) {
                    $null = $CurrentTrustedHostsAsArray.Add($NetItem)
                }
            }
            $UpdatedTrustedHostsString = $($CurrentTrustedHostsAsArray | Where-Object {![string]::IsNullOrWhiteSpace($_)}) -join ','
            Set-Item WSMan:\localhost\Client\TrustedHosts $UpdatedTrustedHostsString -Force
        }
        else {
            $DomainName = $(Get-CimInstance win32_computersystem).Domain
            $DomainShortName = $($DomainName -split "\.")[0]
            $DomainLDAPString = $(foreach ($StringPart in $($DomainName -split "\.")) {"DC=$StringPart"}) -join ','
            $FQDN = $env:ComputerName + '.' + $DomainName
            $IPAddr = $PrimaryIP
        }

        $PSObj = [pscustomobject]@{
            ServerPurpose       = $NetworkLocationObj.ServerPurpose
            FQDN                = $FQDN
            HostName            = $($FQDN -split "\.")[0]
            IPAddress           = $IPAddr
            DomainName          = $DomainName
            DomainShortName     = $DomainShortName
            DomainLDAPString    = $DomainLDAPString
        }
        $null = $NetworkInfoPSObjects.Add($PSObj)
    }

    $RelevantRootCANetworkInfo = $NetworkInfoPSObjects | Where-Object {$_.ServerPurpose -eq "RootCA"}

    # Set some defaults if certain paramters are not used
    if (!$CAType) {
        $CAType = "EnterpriseRootCA"
    }
    if (!$NewComputerTemplateCommonName) {
        $NewComputerTemplateCommonName = $DomainShortName + "Computer"
        #$NewComputerTemplateCommonName = "Machine"
    }
    if (!$NewWebServerTemplateCommonName) {
        $NewWebServerTemplateCommonName = $DomainShortName + "WebServer"
        #$NewWebServerTemplateCommonName = "WebServer"
    }
    if (!$FileOutputDirectory) {
        $FileOutputDirectory = "C:\NewRootCAOutput"
    }
    if (!$CryptoProvider) {
        $CryptoProvider = "Microsoft Software Key Storage Provider"
    }
    if (!$KeyLength) {
        $KeyLength = 2048
    }
    if (!$HashAlgorithm) {
        $HashAlgorithm = "SHA256"
    }
    if (!$KeyAlgorithmValue) {
        $KeyAlgorithmValue = "RSA"
    }
    if (!$CDPUrl) {
        $CDPUrl = "http://pki.$($RelevantRootCANetworkInfo.DomainName)/certdata/<CaName><CRLNameSuffix>.crl"
    }
    if (!$AIAUrl) {
        $AIAUrl = "http://pki.$($RelevantRootCANetworkInfo.DomainName)/certdata/<CaName><CertificateName>.crt"
    }

    # Create SetupRootCA Helper Function Splat Parameters
    $SetupRootCASplatParams = @{
        DomainAdminCredentials              = $DomainAdminCredentials
        NetworkInfoPSObjects                = $NetworkInfoPSObjects
        CAType                              = $CAType
        NewComputerTemplateCommonName       = $NewComputerTemplateCommonName
        NewWebServerTemplateCommonName      = $NewWebServerTemplateCommonName
        FileOutputDirectory                 = $FileOutputDirectory
        CryptoProvider                      = $CryptoProvider
        KeyLength                           = $KeyLength
        HashAlgorithm                       = $HashAlgorithm
        KeyAlgorithmValue                   = $KeyAlgorithmValue
        CDPUrl                              = $CDPUrl
        AIAUrl                              = $AIAUrl
    }

    # Install any required PowerShell Modules
    <#
    # NOTE: This is handled by the MiniLab Module Import
    $RequiredModules = @("PSPKI")
    $InvModDepSplatParams = @{
        RequiredModules                     = $RequiredModules
        InstallModulesNotAvailableLocally   = $True
        ErrorAction                         = "Stop"
    }
    $ModuleDependenciesMap = InvokeModuleDependencies @InvModDepSplatParams
    #>

    #endregion >> Initial Prep


    #region >> Do RootCA Install

    if ($RelevantRootCANetworkInfo.HostName -ne $env:ComputerName) {
        $PSSessionName = NewUniqueString -ArrayOfStrings $(Get-PSSession).Name -PossibleNewUniqueString "ToRootCA"

        # Try to create a PSSession to the Root CA for 15 minutes, then give up
        $Counter = 0
        while (![bool]$(Get-PSSession -Name $PSSessionName -ErrorAction SilentlyContinue)) {
            try {
                $RootCAPSSession = New-PSSession -ComputerName $RelevantRootCANetworkInfo.IPAddress -Credential $DomainAdminCredentials -Name $PSSessionName -ErrorAction SilentlyContinue
                if (![bool]$(Get-PSSession -Name $PSSessionName -ErrorAction SilentlyContinue)) {throw}
            }
            catch {
                if ($Counter -le 60) {
                    Write-Warning "New-PSSession '$PSSessionName' failed. Trying again in 15 seconds..."
                    Start-Sleep -Seconds 15
                }
                else {
                    Write-Error "Unable to create new PSSession to '$PSSessionName' using account '$($DomainAdminCredentials.UserName)'! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
            $Counter++
        }

        if (!$RootCAPSSession) {
            Write-Error "Unable to create a PSSession to the Root CA Server at '$($RelevantRootCANetworkInfo.IPAddress)'! Halting!"
            $global:FunctionResult = "1"
            return
        }

        # Transfer any Required Modules that were installed on $env:ComputerName from an external source
        $NeededModules = @("PSPKI")
        [System.Collections.ArrayList]$ModulesToTransfer = @()
        foreach ($ModuleResource in $NeededModules) {
            $ModMapObj = $script:ModuleDependenciesMap.SuccessfulModuleImports | Where-Object {$_.ModuleName -eq $ModuleResource}
            if ($ModMapObj.ModulePSCompatibility -ne "WinPS") {
                $ModuleBase = Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                    if (![bool]$(Get-Module -ListAvailable $args[0])) {
                        Install-Module $args[0]
                    }
                    if (![bool]$(Get-Module -ListAvailable $args[0])) {
                        Write-Error $("Problem installing" + $args[0])
                    }
                    $Module = Get-Module -ListAvailable $args[0]
                    $($Module.ModuleBase -split $args[0])[0] + $args[0]
                } -ArgumentList $ModuleResource
            }
            else {
                $ModuleBase = $($ModMapObj.ManifestFileItem.FullName -split $ModuleResource)[0] + $ModuleResource
            }
            
            $null = $ModulesToTransfer.Add($ModuleBase)
        }
        
        $ProgramFilesPSModulePath = "C:\Program Files\WindowsPowerShell\Modules"
        foreach ($ModuleDirPath in $ModulesToTransfer) {
            $CopyItemSplatParams = @{
                Path            = $ModuleDirPath
                Recurse         = $True
                Destination     = "$ProgramFilesPSModulePath\$($ModuleDirPath | Split-Path -Leaf)"
                ToSession       = $RootCAPSSession
                Force           = $True
            }
            Copy-Item @CopyItemSplatParams
        }

        # Initialize the Remote Environment
        $FunctionsForRemoteUse = $script:FunctionsForSBUse
        $FunctionsForRemoteUse.Add($(${Function:SetupRootCA}.Ast.Extent.Text))
        $Output = Invoke-Command -Session $RootCAPSSession -ScriptBlock {
            $using:FunctionsForRemoteUse | foreach { Invoke-Expression $_ }
            $script:ModuleDependenciesMap = $args[0]
            SetupRootCA @using:SetupRootCASplatParams
        } -ArgumentList $script:ModuleDependenciesMap
    }
    else {
        $Output = SetupRootCA @SetupRootCASplatParams
    }

    $Output

    #endregion >> Do RootCA Install
}


<#
    .SYNOPSIS
        The New-Runspace function creates a Runspace that executes the specified ScriptBlock in the background
        and posts results to a Global Variable called $global:RSSyncHash.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER RunspaceName
        This parameter is MANDATORY.

        This parameter takes a string that represents the name of the new Runspace that you are creating. The name
        is represented as a key in the $global:RSSyncHash variable called: <RunspaceName>Result

    .PARAMETER ScriptBlock
        This parameter is MANDATORY.

        This parameter takes a scriptblock that will be executed in the new Runspace.

    .PARAMETER MirrorCurrentEnv
        This parameter is OPTIONAL, however, it is set to $True by default.

        This parameter is a switch. If used, all variables, functions, and Modules that are loaded in your
        current scope will be forwarded to the new Runspace.

        You can prevent the New-Runspace function from automatically mirroring your current environment by using
        this switch like: -MirrorCurrentEnv:$False 

    .PARAMETER Wait
        This parameter is OPTIONAL.

        This parameter is a switch. If used, the main PowerShell thread will wait for the Runsapce to return
        output before proceeeding.

    .EXAMPLE
        # Open a PowerShell Session, source the function, and -

        PS C:\Users\zeroadmin> $GetProcessResults = Get-Process

        # In the below, Runspace1 refers to your current interactive PowerShell Session...

        PS C:\Users\zeroadmin> Get-Runspace

        Id Name            ComputerName    Type          State         Availability
        -- ----            ------------    ----          -----         ------------
        1 Runspace1       localhost       Local         Opened        Busy

        # The below will create a 'Runspace Manager Runspace' (if it doesn't already exist)
        # to manage all other new Runspaces created by the New-Runspace function.
        # Additionally, it will create the Runspace that actually runs the -ScriptBlock.
        # The 'Runspace Manager Runspace' disposes of new Runspaces when they're
        # finished running.

        PS C:\Users\zeroadmin> New-RunSpace -RunSpaceName PSIds -ScriptBlock {$($GetProcessResults | Where-Object {$_.Name -eq "powershell"}).Id}

        # The 'Runspace Manager Runspace' persists just in case you create any additional
        # Runspaces, but the Runspace that actually ran the above -ScriptBlock does not.
        # In the below, 'Runspace2' is the 'Runspace Manager Runspace. 

        PS C:\Users\zeroadmin> Get-Runspace

        Id Name            ComputerName    Type          State         Availability
        -- ----            ------------    ----          -----         ------------
        1 Runspace1       localhost       Local         Opened        Busy
        2 Runspace2       localhost       Local         Opened        Busy

        # You can actively identify (as opposed to infer) the 'Runspace Manager Runspace'
        # by using one of three Global variables created by the New-Runspace function:

        PS C:\Users\zeroadmin> $global:RSJobCleanup.PowerShell.Runspace

        Id Name            ComputerName    Type          State         Availability
        -- ----            ------------    ----          -----         ------------
        2 Runspace2       localhost       Local         Opened        Busy

        # As mentioned above, the New-RunspaceName function creates three Global
        # Variables. They are $global:RSJobs, $global:RSJobCleanup, and
        # $global:RSSyncHash. Your output can be found in $global:RSSyncHash.

        PS C:\Users\zeroadmin> $global:RSSyncHash

        Name                           Value
        ----                           -----
        PSIdsResult                    @{Done=True; Errors=; Output=System.Object[]}
        ProcessedJobRecords            {@{Name=PSIdsHelper; PSInstance=System.Management.Automation.PowerShell; Runspace=System.Management.Automation.Runspaces.Loca...


        PS C:\Users\zeroadmin> $global:RSSyncHash.PSIdsResult

        Done Errors Output
        ---- ------ ------
        True        {1300, 2728, 2960, 3712...}


        PS C:\Users\zeroadmin> $global:RSSyncHash.PSIdsResult.Output
        1300
        2728
        2960
        3712
        4632

        # Important Note: You don't need to worry about passing variables / functions /
        # Modules to the Runspace. Everything in your current session/scope is
        # automatically forwarded by the New-Runspace function:

        PS C:\Users\zeroadmin> function Test-Func {'This is Test-Func output'}
        PS C:\Users\zeroadmin> New-RunSpace -RunSpaceName FuncTest -ScriptBlock {Test-Func}
        PS C:\Users\zeroadmin> $global:RSSyncHash

        Name                           Value
        ----                           -----
        FuncTestResult                 @{Done=True; Errors=; Output=This is Test-Func output}
        PSIdsResult                    @{Done=True; Errors=; Output=System.Object[]}
        ProcessedJobRecords            {@{Name=PSIdsHelper; PSInstance=System.Management.Automation.PowerShell; Runspace=System.Management.Automation.Runspaces.Loca...

        PS C:\Users\zeroadmin> $global:RSSyncHash.FuncTestResult.Output
        This is Test-Func output  
#>
function New-RunSpace {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [string]$RunspaceName,

        [Parameter(Mandatory=$True)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory=$False)]
        [switch]$MirrorCurrentEnv = $True,

        [Parameter(Mandatory=$False)]
        [switch]$Wait
    )

    #region >> Helper Functions

    function NewUniqueString {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$False)]
            [string[]]$ArrayOfStrings,
    
            [Parameter(Mandatory=$True)]
            [string]$PossibleNewUniqueString
        )
    
        if (!$ArrayOfStrings -or $ArrayOfStrings.Count -eq 0 -or ![bool]$($ArrayOfStrings -match "[\w]")) {
            $PossibleNewUniqueString
        }
        else {
            $OriginalString = $PossibleNewUniqueString
            $Iteration = 1
            while ($ArrayOfStrings -contains $PossibleNewUniqueString) {
                $AppendedValue = "_$Iteration"
                $PossibleNewUniqueString = $OriginalString + $AppendedValue
                $Iteration++
            }
    
            $PossibleNewUniqueString
        }
    }

    #endregion >> Helper Functions

    #region >> Runspace Prep

    # Create Global Variable Names that don't conflict with other exisiting Global Variables
    $ExistingGlobalVariables = Get-Variable -Scope Global
    $DesiredGlobalVariables = @("RSSyncHash","RSJobCleanup","RSJobs")
    if ($ExistingGlobalVariables.Name -notcontains 'RSSyncHash') {
        $GlobalRSSyncHashName = NewUniqueString -PossibleNewUniqueString "RSSyncHash" -ArrayOfStrings $ExistingGlobalVariables.Name
        Invoke-Expression "`$global:$GlobalRSSyncHashName = [hashtable]::Synchronized(@{})"
        $globalRSSyncHash = Get-Variable -Name $GlobalRSSyncHashName -Scope Global -ValueOnly
    }
    else {
        $GlobalRSSyncHashName = 'RSSyncHash'

        # Also make sure that $RunSpaceName is a unique key in $global:RSSyncHash
        if ($RSSyncHash.Keys -contains $RunSpaceName) {
            $RSNameOriginal = $RunSpaceName
            $RunSpaceName = NewUniqueString -PossibleNewUniqueString $RunSpaceName -ArrayOfStrings $RSSyncHash.Keys
            if ($RSNameOriginal -ne $RunSpaceName) {
                Write-Warning "The RunspaceName '$RSNameOriginal' already exists. Your new RunspaceName will be '$RunSpaceName'"
            }
        }

        $globalRSSyncHash = $global:RSSyncHash
    }
    if ($ExistingGlobalVariables.Name -notcontains 'RSJobCleanup') {
        $GlobalRSJobCleanupName = NewUniqueString -PossibleNewUniqueString "RSJobCleanup" -ArrayOfStrings $ExistingGlobalVariables.Name
        Invoke-Expression "`$global:$GlobalRSJobCleanupName = [hashtable]::Synchronized(@{})"
        $globalRSJobCleanup = Get-Variable -Name $GlobalRSJobCleanupName -Scope Global -ValueOnly
    }
    else {
        $GlobalRSJobCleanupName = 'RSJobCleanup'
        $globalRSJobCleanup = $global:RSJobCleanup
    }
    if ($ExistingGlobalVariables.Name -notcontains 'RSJobs') {
        $GlobalRSJobsName = NewUniqueString -PossibleNewUniqueString "RSJobs" -ArrayOfStrings $ExistingGlobalVariables.Name
        Invoke-Expression "`$global:$GlobalRSJobsName = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new())"
        $globalRSJobs = Get-Variable -Name $GlobalRSJobsName -Scope Global -ValueOnly
    }
    else {
        $GlobalRSJobsName = 'RSJobs'
        $globalRSJobs = $global:RSJobs
    }
    $GlobalVariables = @($GlobalSyncHashName,$GlobalRSJobCleanupName,$GlobalRSJobsName)
    #Write-Host "Global Variable names are: $($GlobalVariables -join ", ")"

    # Prep an empty pscustomobject for the RunspaceNameResult Key in $globalRSSyncHash
    $globalRSSyncHash."$RunspaceName`Result" = [pscustomobject]@{}

    #endregion >> Runspace Prep


    ##### BEGIN Runspace Manager Runspace (A Runspace to Manage All Runspaces) #####

    $globalRSJobCleanup.Flag = $True

    if ($ExistingGlobalVariables.Name -notcontains 'RSJobCleanup') {
        #Write-Host '$global:RSJobCleanup does NOT already exists. Creating New Runspace Manager Runspace...'
        $RunspaceMgrRunspace = [runspacefactory]::CreateRunspace()
        if ($PSVersionTable.PSEdition -ne "Core") {
            $RunspaceMgrRunspace.ApartmentState = "STA"
        }
        $RunspaceMgrRunspace.ThreadOptions = "ReuseThread"
        $RunspaceMgrRunspace.Open()

        # Prepare to Receive the Child Runspace Info to the RunspaceManagerRunspace
        $RunspaceMgrRunspace.SessionStateProxy.SetVariable("JobCleanup",$globalRSJobCleanup)
        $RunspaceMgrRunspace.SessionStateProxy.SetVariable("jobs",$globalRSJobs)
        $RunspaceMgrRunspace.SessionStateProxy.SetVariable("SyncHash",$globalRSSyncHash)

        $globalRSJobCleanup.PowerShell = [PowerShell]::Create().AddScript({

            ##### BEGIN Runspace Manager Runspace Helper Functions #####

            # Load the functions we packed up
            $FunctionsForSBUse | foreach { Invoke-Expression $_ }

            ##### END Runspace Manager Runspace Helper Functions #####

            # Routine to handle completed Runspaces
            $ProcessedJobRecords = [System.Collections.ArrayList]::new()
            $SyncHash.ProcessedJobRecords = $ProcessedJobRecords
            while ($JobCleanup.Flag) {
                if ($jobs.Count -gt 0) {
                    $Counter = 0
                    foreach($job in $jobs) { 
                        if ($ProcessedJobRecords.Runspace.InstanceId.Guid -notcontains $job.Runspace.InstanceId.Guid) {
                            $job | Export-CliXml "$HOME\job$Counter.xml" -Force
                            $CollectJobRecordPrep = Import-CliXML -Path "$HOME\job$Counter.xml"
                            Remove-Item -Path "$HOME\job$Counter.xml" -Force
                            $null = $ProcessedJobRecords.Add($CollectJobRecordPrep)
                        }

                        if ($job.AsyncHandle.IsCompleted -or $job.AsyncHandle -eq $null) {
                            [void]$job.PSInstance.EndInvoke($job.AsyncHandle)
                            $job.Runspace.Dispose()
                            $job.PSInstance.Dispose()
                            $job.AsyncHandle = $null
                            $job.PSInstance = $null
                        }
                        $Counter++
                    }

                    # Determine if we can have the Runspace Manager Runspace rest
                    $temparray = $jobs.clone()
                    $temparray | Where-Object {
                        $_.AsyncHandle.IsCompleted -or $_.AsyncHandle -eq $null
                    } | foreach {
                        $temparray.remove($_)
                    }

                    <#
                    if ($temparray.Count -eq 0 -or $temparray.AsyncHandle.IsCompleted -notcontains $False) {
                        $JobCleanup.Flag = $False
                    }
                    #>

                    Start-Sleep -Seconds 5

                    # Optional -
                    # For realtime updates to a GUI depending on changes in data within the $globalRSSyncHash, use
                    # a something like the following (replace with $RSSyncHash properties germane to your project)
                    <#
                    if ($RSSyncHash.WPFInfoDatagrid.Items.Count -ne 0 -and $($RSSynchash.IPArray.Count -ne 0 -or $RSSynchash.IPArray -ne $null)) {
                        if ($RSSyncHash.WPFInfoDatagrid.Items.Count -ge $RSSynchash.IPArray.Count) {
                            Update-Window -Control $RSSyncHash.WPFInfoPleaseWaitLabel -Property Visibility -Value "Hidden"
                        }
                    }
                    #>
                }
            } 
        })

        # Start the RunspaceManagerRunspace
        $globalRSJobCleanup.PowerShell.Runspace = $RunspaceMgrRunspace
        $globalRSJobCleanup.Thread = $globalRSJobCleanup.PowerShell.BeginInvoke()
    }

    ##### END Runspace Manager Runspace #####


    ##### BEGIN New Generic Runspace #####

    $GenericRunspace = [runspacefactory]::CreateRunspace()
    if ($PSVersionTable.PSEdition -ne "Core") {
        $GenericRunspace.ApartmentState = "STA"
    }
    $GenericRunspace.ThreadOptions = "ReuseThread"
    $GenericRunspace.Open()

    # Pass the $globalRSSyncHash to the Generic Runspace so it can read/write properties to it and potentially
    # coordinate with other runspaces
    $GenericRunspace.SessionStateProxy.SetVariable("SyncHash",$globalRSSyncHash)

    # Pass $globalRSJobCleanup and $globalRSJobs to the Generic Runspace so that the Runspace Manager Runspace can manage it
    $GenericRunspace.SessionStateProxy.SetVariable("JobCleanup",$globalRSJobCleanup)
    $GenericRunspace.SessionStateProxy.SetVariable("Jobs",$globalRSJobs)
    $GenericRunspace.SessionStateProxy.SetVariable("ScriptBlock",$ScriptBlock)

    # Pass all other notable environment characteristics 
    if ($MirrorCurrentEnv) {
        [System.Collections.ArrayList]$SetEnvStringArray = @()

        $VariablesNotToForward = @('globalRSSyncHash','RSSyncHash','globalRSJobCleanUp','RSJobCleanup',
        'globalRSJobs','RSJobs','ExistingGlobalVariables','DesiredGlobalVariables','$GlobalRSSyncHashName',
        'RSNameOriginal','GlobalRSJobCleanupName','GlobalRSJobsName','GlobalVariables','RunspaceMgrRunspace',
        'GenericRunspace','ScriptBlock')

        $Variables = Get-Variable
        foreach ($VarObj in $Variables) {
            if ($VariablesNotToForward -notcontains $VarObj.Name) {
                try {
                    $GenericRunspace.SessionStateProxy.SetVariable($VarObj.Name,$VarObj.Value)
                }
                catch {
                    Write-Verbose "Skipping `$$($VarObj.Name)..."
                }
            }
        }

        # Set Environment Variables
        $EnvVariables = Get-ChildItem Env:\
        if ($PSBoundParameters['EnvironmentVariablesToForward'] -and $EnvironmentVariablesToForward -notcontains '*') {
            $EnvVariables = foreach ($VarObj in $EnvVariables) {
                if ($EnvironmentVariablesToForward -contains $VarObj.Name) {
                    $VarObj
                }
            }
        }
        $SetEnvVarsPrep = foreach ($VarObj in $EnvVariables) {
            if ([char[]]$VarObj.Name -contains '(' -or [char[]]$VarObj.Name -contains ' ') {
                $EnvStringArr = @(
                    'try {'
                    $('    ${env:' + $VarObj.Name + '} = ' + "@'`n$($VarObj.Value)`n'@")
                    '}'
                    'catch {'
                    "    Write-Verbose 'Unable to forward environment variable $($VarObj.Name)'"
                    '}'
                )
            }
            else {
                $EnvStringArr = @(
                    'try {'
                    $('    $env:' + $VarObj.Name + ' = ' + "@'`n$($VarObj.Value)`n'@")
                    '}'
                    'catch {'
                    "    Write-Verbose 'Unable to forward environment variable $($VarObj.Name)'"
                    '}'
                )
            }
            $EnvStringArr -join "`n"
        }
        $SetEnvVarsString = $SetEnvVarsPrep -join "`n"

        $null = $SetEnvStringArray.Add($SetEnvVarsString)

        # Set Modules
        $Modules = Get-Module
        if ($PSBoundParameters['ModulesToForward'] -and $ModulesToForward -notcontains '*') {
            $Modules = foreach ($ModObj in $Modules) {
                if ($ModulesToForward -contains $ModObj.Name) {
                    $ModObj
                }
            }
        }

        $ModulesNotToForward = @('MiniLab')

        $SetModulesPrep = foreach ($ModObj in $Modules) {
            if ($ModulesNotToForward -notcontains $ModObj.Name) {
                $ModuleManifestFullPath = $(Get-ChildItem -Path $ModObj.ModuleBase -Recurse -File | Where-Object {
                    $_.Name -eq "$($ModObj.Name).psd1"
                }).FullName

                $ModStringArray = @(
                    '$tempfile = [IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName())'
                    "if (![bool]('$($ModObj.Name)' -match '\.WinModule')) {"
                    '    try {'
                    "        Import-Module '$($ModObj.Name)' -NoClobber -ErrorAction Stop 2>`$tempfile"
                    '    }'
                    '    catch {'
                    '        try {'
                    "            Import-Module '$ModuleManifestFullPath' -NoClobber -ErrorAction Stop 2>`$tempfile"
                    '        }'
                    '        catch {'
                    "            Write-Warning 'Unable to Import-Module $($ModObj.Name)'"
                    '        }'
                    '    }'
                    '}'
                    'if (Test-Path $tempfile) {'
                    '    Remove-Item $tempfile -Force'
                    '}'
                )
                $ModStringArray -join "`n"
            }
        }
        $SetModulesString = $SetModulesPrep -join "`n"

        $null = $SetEnvStringArray.Add($SetModulesString)
    
        # Set Functions
        $Functions = Get-ChildItem Function:\ | Where-Object {![System.String]::IsNullOrWhiteSpace($_.Name)}
        if ($PSBoundParameters['FunctionsToForward'] -and $FunctionsToForward -notcontains '*') {
            $Functions = foreach ($FuncObj in $Functions) {
                if ($FunctionsToForward -contains $FuncObj.Name) {
                    $FuncObj
                }
            }
        }
        $SetFunctionsPrep = foreach ($FuncObj in $Functions) {
            $FunctionText = Invoke-Expression $('@(${Function:' + $FuncObj.Name + '}.Ast.Extent.Text)')
            if ($($FunctionText -split "`n").Count -gt 1) {
                if ($($FunctionText -split "`n")[0] -match "^function ") {
                    if ($($FunctionText -split "`n") -match "^'@") {
                        Write-Warning "Unable to forward function $($FuncObj.Name) due to heredoc string: '@"
                    }
                    else {
                        'Invoke-Expression ' + "@'`n$FunctionText`n'@"
                    }
                }
            }
            elseif ($($FunctionText -split "`n").Count -eq 1) {
                if ($FunctionText -match "^function ") {
                    'Invoke-Expression ' + "@'`n$FunctionText`n'@"
                }
            }
        }
        $SetFunctionsString = $SetFunctionsPrep -join "`n"

        $null = $SetEnvStringArray.Add($SetFunctionsString)

        $GenericRunspace.SessionStateProxy.SetVariable("SetEnvStringArray",$SetEnvStringArray)
    }

    $GenericPSInstance = [powershell]::Create()

    # Define the main PowerShell Script that will run the $ScriptBlock
    $null = $GenericPSInstance.AddScript({
        $SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name Done -Value $False
        $SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name Errors -Value $null
        $SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name ErrorsDetailed -Value $null
        $SyncHash."$RunspaceName`Result".Errors = [System.Collections.ArrayList]::new()
        $SyncHash."$RunspaceName`Result".ErrorsDetailed = [System.Collections.ArrayList]::new()
        $SyncHash."$RunspaceName`Result" | Add-Member -Type NoteProperty -Name ThisRunspace -Value $($(Get-Runspace)[-1])
        [System.Collections.ArrayList]$LiveOutput = @()
        $SyncHash."$RunspaceName`Result" | Add-Member -Type NoteProperty -Name LiveOutput -Value $LiveOutput
        

        
        ##### BEGIN Generic Runspace Helper Functions #####

        # Load the environment we packed up
        if ($SetEnvStringArray) {
            foreach ($obj in $SetEnvStringArray) {
                if (![string]::IsNullOrWhiteSpace($obj)) {
                    try {
                        Invoke-Expression $obj
                    }
                    catch {
                        $null = $SyncHash."$RunSpaceName`Result".Errors.Add($_)

                        $ErrMsg = "Problem with:`n$obj`nError Message:`n" + $($_ | Out-String)
                        $null = $SyncHash."$RunSpaceName`Result".ErrorsDetailed.Add($ErrMsg)
                    }
                }
            }
        }

        ##### END Generic Runspace Helper Functions #####

        ##### BEGIN Script To Run #####

        try {
            # NOTE: Depending on the content of the scriptblock, InvokeReturnAsIs() and Invoke-Command can cause
            # the Runspace to hang. Invoke-Expression works all the time.
            #$Result = $ScriptBlock.InvokeReturnAsIs()
            #$Result = Invoke-Command -ScriptBlock $ScriptBlock
            #$SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name SBString -Value $ScriptBlock.ToString()
            $Result = Invoke-Expression -Command $ScriptBlock.ToString()
            $SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name Output -Value $Result
        }
        catch {
            $SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name Output -Value $Result

            $null = $SyncHash."$RunSpaceName`Result".Errors.Add($_)

            $ErrMsg = "Problem with:`n$($ScriptBlock.ToString())`nError Message:`n" + $($_ | Out-String)
            $null = $SyncHash."$RunSpaceName`Result".ErrorsDetailed.Add($ErrMsg)
        }

        ##### END Script To Run #####

        $SyncHash."$RunSpaceName`Result".Done = $True
    })

    # Start the Generic Runspace
    $GenericPSInstance.Runspace = $GenericRunspace

    if ($Wait) {
        # The below will make any output of $GenericRunspace available in $Object in current scope
        $Object = New-Object 'System.Management.Automation.PSDataCollection[psobject]'
        $GenericAsyncHandle = $GenericPSInstance.BeginInvoke($Object,$Object)

        $GenericRunspaceInfo = [pscustomobject]@{
            Name            = $RunSpaceName + "Generic"
            PSInstance      = $GenericPSInstance
            Runspace        = $GenericRunspace
            AsyncHandle     = $GenericAsyncHandle
        }
        $null = $globalRSJobs.Add($GenericRunspaceInfo)

        #while ($globalRSSyncHash."$RunSpaceName`Done" -ne $True) {
        while ($GenericAsyncHandle.IsCompleted -ne $True) {
            #Write-Host "Waiting for -ScriptBlock to finish..."
            Start-Sleep -Milliseconds 10
        }

        $globalRSSyncHash."$RunspaceName`Result".Output
        #$Object
    }
    else {
        $HelperRunspace = [runspacefactory]::CreateRunspace()
        if ($PSVersionTable.PSEdition -ne "Core") {
            $HelperRunspace.ApartmentState = "STA"
        }
        $HelperRunspace.ThreadOptions = "ReuseThread"
        $HelperRunspace.Open()

        # Pass the $globalRSSyncHash to the Helper Runspace so it can read/write properties to it and potentially
        # coordinate with other runspaces
        $HelperRunspace.SessionStateProxy.SetVariable("SyncHash",$globalRSSyncHash)

        # Pass $globalRSJobCleanup and $globalRSJobs to the Helper Runspace so that the Runspace Manager Runspace can manage it
        $HelperRunspace.SessionStateProxy.SetVariable("JobCleanup",$globalRSJobCleanup)
        $HelperRunspace.SessionStateProxy.SetVariable("Jobs",$globalRSJobs)

        # Set any other needed variables in the $HelperRunspace
        $HelperRunspace.SessionStateProxy.SetVariable("GenericRunspace",$GenericRunspace)
        $HelperRunspace.SessionStateProxy.SetVariable("GenericPSInstance",$GenericPSInstance)
        $HelperRunspace.SessionStateProxy.SetVariable("RunSpaceName",$RunSpaceName)

        $HelperPSInstance = [powershell]::Create()

        # Define the main PowerShell Script that will run the $ScriptBlock
        $null = $HelperPSInstance.AddScript({
            ##### BEGIN Script To Run #####

            # The below will make any output of $GenericRunspace available in $Object in current scope
            $Object = New-Object 'System.Management.Automation.PSDataCollection[psobject]'
            $GenericAsyncHandle = $GenericPSInstance.BeginInvoke($Object,$Object)

            $GenericRunspaceInfo = [pscustomobject]@{
                Name            = $RunSpaceName + "Generic"
                PSInstance      = $GenericPSInstance
                Runspace        = $GenericRunspace
                AsyncHandle     = $GenericAsyncHandle
            }
            $null = $Jobs.Add($GenericRunspaceInfo)

            #while ($SyncHash."$RunSpaceName`Done" -ne $True) {
            while ($GenericAsyncHandle.IsCompleted -ne $True) {
                #Write-Host "Waiting for -ScriptBlock to finish..."
                Start-Sleep -Milliseconds 10
            }

            ##### END Script To Run #####
        })

        # Start the Helper Runspace
        $HelperPSInstance.Runspace = $HelperRunspace
        $HelperAsyncHandle = $HelperPSInstance.BeginInvoke()

        $HelperRunspaceInfo = [pscustomobject]@{
            Name            = $RunSpaceName + "Helper"
            PSInstance      = $HelperPSInstance
            Runspace        = $HelperRunspace
            AsyncHandle     = $HelperAsyncHandle
        }
        $null = $globalRSJobs.Add($HelperRunspaceInfo)
    }

    ##### END Generic Runspace
}


<#
    .Synopsis
        This cmdlet generates a self-signed certificate.
    .Description
        This cmdlet generates a self-signed certificate with the required data.
    .NOTES
        New-SelfSignedCertificateEx.ps1
        Version 1.0
        
        Creates self-signed certificate. This tool is a base replacement
        for deprecated makecert.exe
        
        Vadims Podans (c) 2013
        http://en-us.sysadmins.lv/

    .Parameter Subject
        Specifies the certificate subject in a X500 distinguished name format.
        Example: CN=Test Cert, OU=Sandbox
    .Parameter NotBefore
        Specifies the date and time when the certificate become valid. By default previous day
        date is used.
    .Parameter NotAfter
        Specifies the date and time when the certificate expires. By default, the certificate is
        valid for 1 year.
    .Parameter SerialNumber
        Specifies the desired serial number in a hex format.
        Example: 01a4ff2
    .Parameter ProviderName
        Specifies the Cryptography Service Provider (CSP) name. You can use either legacy CSP
        and Key Storage Providers (KSP). By default "Microsoft Enhanced Cryptographic Provider v1.0"
        CSP is used.
    .Parameter AlgorithmName
        Specifies the public key algorithm. By default RSA algorithm is used. RSA is the only
        algorithm supported by legacy CSPs. With key storage providers (KSP) you can use CNG
        algorithms, like ECDH. For CNG algorithms you must use full name:
        ECDH_P256
        ECDH_P384
        ECDH_P521
        
        In addition, KeyLength parameter must be specified explicitly when non-RSA algorithm is used.
    .Parameter KeyLength
        Specifies the key length to generate. By default 2048-bit key is generated.
    .Parameter KeySpec
        Specifies the public key operations type. The possible values are: Exchange and Signature.
        Default value is Exchange.
    .Parameter EnhancedKeyUsage
        Specifies the intended uses of the public key contained in a certificate. You can
        specify either, EKU friendly name (for example 'Server Authentication') or
        object identifier (OID) value (for example '1.3.6.1.5.5.7.3.1').
    .Parameter KeyUsage
        Specifies restrictions on the operations that can be performed by the public key contained in the certificate.
        Possible values (and their respective integer values to make bitwise operations) are:
        EncipherOnly
        CrlSign
        KeyCertSign
        KeyAgreement
        DataEncipherment
        KeyEncipherment
        NonRepudiation
        DigitalSignature
        DecipherOnly
        
        you can combine key usages values by using bitwise OR operation. when combining multiple
        flags, they must be enclosed in quotes and separated by a comma character. For example,
        to combine KeyEncipherment and DigitalSignature flags you should type:
        "KeyEncipherment, DigitalSignature".
        
        If the certificate is CA certificate (see IsCA parameter), key usages extension is generated
        automatically with the following key usages: Certificate Signing, Off-line CRL Signing, CRL Signing.
    .Parameter SubjectAlternativeName
        Specifies alternative names for the subject. Unlike Subject field, this extension
        allows to specify more than one name. Also, multiple types of alternative names
        are supported. The cmdlet supports the following SAN types:
        RFC822 Name
        IP address (both, IPv4 and IPv6)
        Guid
        Directory name
        DNS name
    .Parameter IsCA
        Specifies whether the certificate is CA (IsCA = $true) or end entity (IsCA = $false)
        certificate. If this parameter is set to $false, PathLength parameter is ignored.
        Basic Constraints extension is marked as critical.
    .Parameter PathLength
        Specifies the number of additional CA certificates in the chain under this certificate. If
        PathLength parameter is set to zero, then no additional (subordinate) CA certificates are
        permitted under this CA.
    .Parameter CustomExtension
        Specifies the custom extension to include to a self-signed certificate. This parameter
        must not be used to specify the extension that is supported via other parameters. In order
        to use this parameter, the extension must be formed in a collection of initialized
        System.Security.Cryptography.X509Certificates.X509Extension objects.
    .Parameter SignatureAlgorithm
        Specifies signature algorithm used to sign the certificate. By default 'SHA1'
        algorithm is used.
    .Parameter FriendlyName
        Specifies friendly name for the certificate.
    .Parameter StoreLocation
        Specifies the store location to store self-signed certificate. Possible values are:
        'CurrentUser' and 'LocalMachine'. 'CurrentUser' store is intended for user certificates
        and computer (as well as CA) certificates must be stored in 'LocalMachine' store.
    .Parameter StoreName
        Specifies the container name in the certificate store. Possible container names are:
        AddressBook
        AuthRoot
        CertificateAuthority
        Disallowed
        My
        Root
        TrustedPeople
        TrustedPublisher
    .Parameter Path
        Specifies the path to a PFX file to export a self-signed certificate.
    .Parameter Password
        Specifies the password for PFX file.
    .Parameter AllowSMIME
        Enables Secure/Multipurpose Internet Mail Extensions for the certificate.
    .Parameter Exportable
        Marks private key as exportable. Smart card providers usually do not allow
        exportable keys.
 .Example
  # Creates a self-signed certificate intended for code signing and which is valid for 5 years. Certificate
  # is saved in the Personal store of the current user account.
  
        New-SelfsignedCertificateEx -Subject "CN=Test Code Signing" -EKU "Code Signing" -KeySpec "Signature" `
        -KeyUsage "DigitalSignature" -FriendlyName "Test code signing" -NotAfter [datetime]::now.AddYears(5)
        
        
    .Example
  # Creates a self-signed SSL certificate with multiple subject names and saves it to a file. Additionally, the
        # certificate is saved in the Personal store of the Local Machine store. Private key is marked as exportable,
        # so you can export the certificate with a associated private key to a file at any time. The certificate
  # includes SMIME capabilities.
  
  New-SelfsignedCertificateEx -Subject "CN=www.domain.com" -EKU "Server Authentication", "Client authentication" `
        -KeyUsage "KeyEcipherment, DigitalSignature" -SAN "sub.domain.com","www.domain.com","192.168.1.1" `
        -AllowSMIME -Path C:\test\ssl.pfx -Password (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force) -Exportable `
        -StoreLocation "LocalMachine"
        
    .Example
  # Creates a self-signed SSL certificate with multiple subject names and saves it to a file. Additionally, the
        # certificate is saved in the Personal store of the Local Machine store. Private key is marked as exportable,
        # so you can export the certificate with a associated private key to a file at any time. Certificate uses
        # Ellyptic Curve Cryptography (ECC) key algorithm ECDH with 256-bit key. The certificate is signed by using
  # SHA256 algorithm.
  
  New-SelfsignedCertificateEx -Subject "CN=www.domain.com" -EKU "Server Authentication", "Client authentication" `
        -KeyUsage "KeyEcipherment, DigitalSignature" -SAN "sub.domain.com","www.domain.com","192.168.1.1" `
        -StoreLocation "LocalMachine" -ProviderName "Microsoft Software Key Storae Provider" -AlgorithmName ecdh_256 `
  -KeyLength 256 -SignatureAlgorithm sha256
  
    .Example
  # Creates self-signed root CA certificate.

  New-SelfsignedCertificateEx -Subject "CN=Test Root CA, OU=Sandbox" -IsCA $true -ProviderName `
  "Microsoft Software Key Storage Provider" -Exportable
  
#>
function New-SelfSignedCertificateEx {
    [CmdletBinding(DefaultParameterSetName = '__store')]
 param (
  [Parameter(Mandatory = $true, Position = 0)]
  [string]$Subject,
  [Parameter(Position = 1)]
  [datetime]$NotBefore = [DateTime]::Now.AddDays(-1),
  [Parameter(Position = 2)]
  [datetime]$NotAfter = $NotBefore.AddDays(365),
  [string]$SerialNumber,
  [Alias('CSP')]
  [string]$ProviderName = "Microsoft Enhanced Cryptographic Provider v1.0",
  [string]$AlgorithmName = "RSA",
  [int]$KeyLength = 2048,
  [validateSet("Exchange","Signature")]
  [string]$KeySpec = "Exchange",
  [Alias('EKU')]
  [Security.Cryptography.Oid[]]$EnhancedKeyUsage,
  [Alias('KU')]
  [Security.Cryptography.X509Certificates.X509KeyUsageFlags]$KeyUsage,
  [Alias('SAN')]
  [String[]]$SubjectAlternativeName,
  [bool]$IsCA,
  [int]$PathLength = -1,
  [Security.Cryptography.X509Certificates.X509ExtensionCollection]$CustomExtension,
  [ValidateSet('MD5','SHA1','SHA256','SHA384','SHA512')]
  [string]$SignatureAlgorithm = "SHA1",
  [string]$FriendlyName,
  [Parameter(ParameterSetName = '__store')]
  [Security.Cryptography.X509Certificates.StoreLocation]$StoreLocation = "CurrentUser",
  [Parameter(ParameterSetName = '__store')]
  [Security.Cryptography.X509Certificates.StoreName]$StoreName = "My",
  [Parameter(Mandatory = $true, ParameterSetName = '__file')]
  [Alias('OutFile','OutPath','Out')]
  [IO.FileInfo]$Path,
  [Parameter(Mandatory = $true, ParameterSetName = '__file')]
  [Security.SecureString]$Password,
  [switch]$AllowSMIME,
  [switch]$Exportable
 )

 $ErrorActionPreference = "Stop"
 if ([Environment]::OSVersion.Version.Major -lt 6) {
  $NotSupported = New-Object NotSupportedException -ArgumentList "Windows XP and Windows Server 2003 are not supported!"
  throw $NotSupported
 }
 $ExtensionsToAdd = @()

    #region >> Constants
 # contexts
 New-Variable -Name UserContext -Value 0x1 -Option Constant
 New-Variable -Name MachineContext -Value 0x2 -Option Constant
 # encoding
 New-Variable -Name Base64Header -Value 0x0 -Option Constant
 New-Variable -Name Base64 -Value 0x1 -Option Constant
 New-Variable -Name Binary -Value 0x3 -Option Constant
 New-Variable -Name Base64RequestHeader -Value 0x4 -Option Constant
 # SANs
 New-Variable -Name OtherName -Value 0x1 -Option Constant
 New-Variable -Name RFC822Name -Value 0x2 -Option Constant
 New-Variable -Name DNSName -Value 0x3 -Option Constant
 New-Variable -Name DirectoryName -Value 0x5 -Option Constant
 New-Variable -Name URL -Value 0x7 -Option Constant
 New-Variable -Name IPAddress -Value 0x8 -Option Constant
 New-Variable -Name RegisteredID -Value 0x9 -Option Constant
 New-Variable -Name Guid -Value 0xa -Option Constant
 New-Variable -Name UPN -Value 0xb -Option Constant
 # installation options
 New-Variable -Name AllowNone -Value 0x0 -Option Constant
 New-Variable -Name AllowNoOutstandingRequest -Value 0x1 -Option Constant
 New-Variable -Name AllowUntrustedCertificate -Value 0x2 -Option Constant
 New-Variable -Name AllowUntrustedRoot -Value 0x4 -Option Constant
 # PFX export options
 New-Variable -Name PFXExportEEOnly -Value 0x0 -Option Constant
 New-Variable -Name PFXExportChainNoRoot -Value 0x1 -Option Constant
 New-Variable -Name PFXExportChainWithRoot -Value 0x2 -Option Constant
    #endregion >> Constants
 
    #region >> Subject Processing
 # http://msdn.microsoft.com/en-us/library/aa377051(VS.85).aspx
 $SubjectDN = New-Object -ComObject X509Enrollment.CX500DistinguishedName
 $SubjectDN.Encode($Subject, 0x0)
    #endregion >> Subject Processing

    #region >> Extensions

    #region >> Enhanced Key Usages Processing
 if ($EnhancedKeyUsage) {
  $OIDs = New-Object -ComObject X509Enrollment.CObjectIDs
  $EnhancedKeyUsage | %{
   $OID = New-Object -ComObject X509Enrollment.CObjectID
   $OID.InitializeFromValue($_.Value)
   # http://msdn.microsoft.com/en-us/library/aa376785(VS.85).aspx
   $OIDs.Add($OID)
  }
  # http://msdn.microsoft.com/en-us/library/aa378132(VS.85).aspx
  $EKU = New-Object -ComObject X509Enrollment.CX509ExtensionEnhancedKeyUsage
  $EKU.InitializeEncode($OIDs)
  $ExtensionsToAdd += "EKU"
 }
    #endregion >> Enhanced Key Usages Processing

    #region >> Key Usages Processing
 if ($KeyUsage -ne $null) {
  $KU = New-Object -ComObject X509Enrollment.CX509ExtensionKeyUsage
  $KU.InitializeEncode([int]$KeyUsage)
  $KU.Critical = $true
  $ExtensionsToAdd += "KU"
 }
    #endregion >> Key Usages Processing

    #region >> Basic Constraints Processing
 if ($PSBoundParameters.Keys.Contains("IsCA")) {
  # http://msdn.microsoft.com/en-us/library/aa378108(v=vs.85).aspx
  $BasicConstraints = New-Object -ComObject X509Enrollment.CX509ExtensionBasicConstraints
  if (!$IsCA) {$PathLength = -1}
  $BasicConstraints.InitializeEncode($IsCA,$PathLength)
  $BasicConstraints.Critical = $IsCA
  $ExtensionsToAdd += "BasicConstraints"
 }
    #endregion >> Basic Constraints Processing

    #region >> SAN Processing
 if ($SubjectAlternativeName) {
  $SAN = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
  $Names = New-Object -ComObject X509Enrollment.CAlternativeNames
  foreach ($altname in $SubjectAlternativeName) {
   $Name = New-Object -ComObject X509Enrollment.CAlternativeName
   if ($altname.Contains("@")) {
    $Name.InitializeFromString($RFC822Name,$altname)
   } else {
    try {
     $Bytes = [Net.IPAddress]::Parse($altname).GetAddressBytes()
     $Name.InitializeFromRawData($IPAddress,$Base64,[Convert]::ToBase64String($Bytes))
    } catch {
     try {
      $Bytes = [Guid]::Parse($altname).ToByteArray()
      $Name.InitializeFromRawData($Guid,$Base64,[Convert]::ToBase64String($Bytes))
     } catch {
      try {
       $Bytes = ([Security.Cryptography.X509Certificates.X500DistinguishedName]$altname).RawData
       $Name.InitializeFromRawData($DirectoryName,$Base64,[Convert]::ToBase64String($Bytes))
      } catch {$Name.InitializeFromString($DNSName,$altname)}
     }
    }
   }
   $Names.Add($Name)
  }
  $SAN.InitializeEncode($Names)
  $ExtensionsToAdd += "SAN"
 }
    #endregion >> SAN Processing

    #region >> Custom Extensions
 if ($CustomExtension) {
  $count = 0
  foreach ($ext in $CustomExtension) {
   # http://msdn.microsoft.com/en-us/library/aa378077(v=vs.85).aspx
   $Extension = New-Object -ComObject X509Enrollment.CX509Extension
   $EOID = New-Object -ComObject X509Enrollment.CObjectId
   $EOID.InitializeFromValue($ext.Oid.Value)
   $EValue = [Convert]::ToBase64String($ext.RawData)
   $Extension.Initialize($EOID,$Base64,$EValue)
   $Extension.Critical = $ext.Critical
   New-Variable -Name ("ext" + $count) -Value $Extension
   $ExtensionsToAdd += ("ext" + $count)
   $count++
  }
 }
    #endregion >> Custom Extensions

    #endregion >> Extensions

    #region >> Private Key
 # http://msdn.microsoft.com/en-us/library/aa378921(VS.85).aspx
 $PrivateKey = New-Object -ComObject X509Enrollment.CX509PrivateKey
 $PrivateKey.ProviderName = $ProviderName
 $AlgID = New-Object -ComObject X509Enrollment.CObjectId
 $AlgID.InitializeFromValue(([Security.Cryptography.Oid]$AlgorithmName).Value)
 $PrivateKey.Algorithm = $AlgID
 # http://msdn.microsoft.com/en-us/library/aa379409(VS.85).aspx
 $PrivateKey.KeySpec = switch ($KeySpec) {"Exchange" {1}; "Signature" {2}}
 $PrivateKey.Length = $KeyLength
 # key will be stored in current user certificate store
 switch ($PSCmdlet.ParameterSetName) {
  '__store' {
   $PrivateKey.MachineContext = if ($StoreLocation -eq "LocalMachine") {$true} else {$false}
  }
  '__file' {
   $PrivateKey.MachineContext = $false
  }
 }
 $PrivateKey.ExportPolicy = if ($Exportable) {1} else {0}
 $PrivateKey.Create()
    #endregion >> Private Key

 # http://msdn.microsoft.com/en-us/library/aa377124(VS.85).aspx
 $Cert = New-Object -ComObject X509Enrollment.CX509CertificateRequestCertificate
 if ($PrivateKey.MachineContext) {
  $Cert.InitializeFromPrivateKey($MachineContext,$PrivateKey,"")
 } else {
  $Cert.InitializeFromPrivateKey($UserContext,$PrivateKey,"")
 }
 $Cert.Subject = $SubjectDN
 $Cert.Issuer = $Cert.Subject
 $Cert.NotBefore = $NotBefore
 $Cert.NotAfter = $NotAfter
 foreach ($item in $ExtensionsToAdd) {$Cert.X509Extensions.Add((Get-Variable -Name $item -ValueOnly))}
 if (![string]::IsNullOrEmpty($SerialNumber)) {
  if ($SerialNumber -match "[^0-9a-fA-F]") {throw "Invalid serial number specified."}
  if ($SerialNumber.Length % 2) {$SerialNumber = "0" + $SerialNumber}
  $Bytes = $SerialNumber -split "(.{2})" | ?{$_} | %{[Convert]::ToByte($_,16)}
  $ByteString = [Convert]::ToBase64String($Bytes)
  $Cert.SerialNumber.InvokeSet($ByteString,1)
 }
 if ($AllowSMIME) {$Cert.SmimeCapabilities = $true}
 $SigOID = New-Object -ComObject X509Enrollment.CObjectId
 $SigOID.InitializeFromValue(([Security.Cryptography.Oid]$SignatureAlgorithm).Value)
 $Cert.SignatureInformation.HashAlgorithm = $SigOID
 # completing certificate request template building
 $Cert.Encode()
 
 # interface: http://msdn.microsoft.com/en-us/library/aa377809(VS.85).aspx
 $Request = New-Object -ComObject X509Enrollment.CX509enrollment
 $Request.InitializeFromRequest($Cert)
 $Request.CertificateFriendlyName = $FriendlyName
 $endCert = $Request.CreateRequest($Base64)
 $Request.InstallResponse($AllowUntrustedCertificate,$endCert,$Base64,"")
 switch ($PSCmdlet.ParameterSetName) {
  '__file' {
   $PFXString = $Request.CreatePFX(
    [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)),
    $PFXExportEEOnly,
    $Base64
   )
   Set-Content -Path $Path -Value ([Convert]::FromBase64String($PFXString)) -Encoding Byte
  }
 }
}


<#
    .SYNOPSIS
        This function configures the target Windows 2012 R2 or Windows 2016 Server to be a new Enterprise Root Certification Authority.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES
        # NOTE: For additional guidance, see:
        # https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/hh831348(v=ws.11)

    .PARAMETER DomainAdminCredentials
        This parameter is MANDATORY.

        This parameter takes a PSCredential. The Domain Admin Credentials will be used to configure the new Subordinate CA. This means that
        the Domain Account provided MUST be a member of the following Security Groups in Active Directory:
            - Domain Admins
            - Domain Users
            - Enterprise Admins
            - Group Policy Creator Owners
            - Schema Admins

    .PARAMETER RootCAIPOrFQDN
        This parameter is MANDATORY.

        This parameter takes a string that represents an IPv4 address or DNS-Resolveable FQDN that refers to the existing
        Enterprise Root CA. When configuring th Subordinate CA, files from the Root CA are needed. This parameter tells the
        Subordinate CA where to find them.

    .PARAMETER SubCAIPOrFQDN
        This parameter is OPTIONAL.

        This parameter takes a string that represents an IPv4 address or DNS-Resolveable FQDN that refers to the target Windows
        Server that will become the new Enterprise Subordinate CA. If it is NOT used, then the localhost will be configured as the
        new Enterprise Subordinate CA.

    .PARAMETER CAType
        This parameter is OPTIONAL, however, its default value is "EnterpriseSubordinateCA".

        This parameter takes a string that represents the type of Subordinate Certificate Authority that the target server will become.
        Currently this parameter only accepts "EnterpriseSubordinateCA" as a valid value.

    .PARAMETER NewComputerTemplateCommonName
        This parameter is OPTIONAL, however, its default value is "Machine".

        If you would like to make the the custom Computer/Machine Certificate Template generated by the New-RootCA function
        available for use on the Subordinate CA, then set this value to "<DomainPrefix>" + "Computer".

    .PARAMETER NewWebServerTemplateCommonName
        This parameter is OPTIONAL, however, its default value is "WebServer".

        If you would like to make the the custom WebServer Certificate Template generated by the New-RootCA function
        available for use on the Subordinate CA, then set this value to "<DomainPrefix>" + "WebServer".

    .PARAMETER FileOutputDirectory
        This parameter is OPTIONAL, however, its default value is "C:\NewSubCAOutput".

        This parameter takes a string that represents the full path to a directory that will contain all files generated
        by the New-SubordinateCA function.

    .PARAMETER CryptoProvider
        This parameter is OPTIONAL, however, its default value is "Microsoft Software Key Storage Provider".

        This parameter takes a string that represents the Cryptographic Provider used by the new Subordinate CA.
        Currently, the only valid value for this parameter is "Microsoft Software Key Storage Provider".

    .PARAMETER KeyLength
        This parameter is OPTIONAL, however, its default value is 2048.

        This parameter takes an integer with value 2048 or 4096.

    .PARAMETER HashAlgorithm
        This parameter is OPTIONAL, however, its default value is SHA256.

        This parameter takes a string with acceptable values as follows: "SHA1","SHA256","SHA384","SHA512","MD5","MD4","MD2"

    .PARAMETER KeyAlgorithmValue
        This parameter is OPTIONAL, however, its default value is RSA.

        This parameter takes a string with acceptable values: "RSA"

    .PARAMETER CDPUrl
        This parameter is OPTIONAL, however, its default value is "http://pki.$DomainName/certdata/<CaName><CRLNameSuffix>.crl"

        This parameter takes a string that represents a Certificate Distribution List Revocation URL.

    .PARAMETER AIAUrl
        This parameter is OPTIONAL, however, its default value is "http://pki.$DomainName/certdata/<CaName><CertificateName>.crt"

        This parameter takes a string that represents an Authority Information Access (AIA) Url (i.e. the location where the certificate of
        of certificate's issuer can be downloaded).

    .EXAMPLE
        # Make the localhost a Subordinate CA

        PS C:\Users\zeroadmin> $DomainAdminCreds = [pscredential]::new("alpha\alphaadmin",$(Read-Host 'Enter Passsword' -AsSecureString))
        Enter Passsword: ************
        PS C:\Users\zeroadmin> $CreateSubCASplatParams = @{
        >> DomainAdminCredentials   = $DomainAdminCreds
        >> RootCAIPOrFQDN           = "192.168.2.112"   
        >> }
        PS C:\Users\zeroadmin> $CreateSubCAResult = Create-SubordinateCA @CreateSubCASplatParams

    .EXAMPLE
        # Make the Remote Host a Subordinate CA

        PS C:\Users\zeroadmin> $DomainAdminCreds = [pscredential]::new("alpha\alphaadmin",$(Read-Host 'Enter Passsword' -AsSecureString))
        Enter Passsword: ************
        PS C:\Users\zeroadmin> $CreateSubCASplatParams = @{
        >> DomainAdminCredentials   = $DomainAdminCreds
        >> RootCAIPOrFQDN           = "192.168.2.112" 
        >> SubCAIPOrFQDN            = "192.168.2.113"                
        >> }
        PS C:\Users\zeroadmin> $CreateSubCAResult = Create-SubordinateCA @CreateSubCASplatParams
        
#>
function New-SubordinateCA {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [string]$RootCAIPOrFQDN,

        [Parameter(Mandatory=$True)]
        [pscredential]$DomainAdminCredentials,

        [Parameter(Mandatory=$False)]
        [string]$SubCAIPOrFQDN,

        [Parameter(Mandatory=$False)]
        [ValidateSet("EnterpriseSubordinateCA")]
        [string]$CAType,

        [Parameter(Mandatory=$False)]
        [string]$NewComputerTemplateCommonName,

        [Parameter(Mandatory=$False)]
        [string]$NewWebServerTemplateCommonName,

        [Parameter(Mandatory=$False)]
        [string]$FileOutputDirectory,

        [Parameter(Mandatory=$False)]
        <#
        [ValidateSet("Microsoft Base Cryptographic Provider v1.0","Microsoft Base DSS and Diffie-Hellman Cryptographic Provider",
        "Microsoft Base DSS Cryptographic Provider","Microsoft Base Smart Card Crypto Provider",
        "Microsoft DH SChannel Cryptographic Provider","Microsoft Enhanced Cryptographic Provider v1.0",
        "Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider",
        "Microsoft Enhanced RSA and AES Cryptographic Provider","Microsoft RSA SChannel Cryptographic Provider",
        "Microsoft Strong Cryptographic Provider","Microsoft Software Key Storage Provider",
        "Microsoft Passport Key Storage Provider")]
        #>
        [ValidateSet("Microsoft Software Key Storage Provider")]
        [string]$CryptoProvider,

        [Parameter(Mandatory=$False)]
        [ValidateSet("2048","4096")]
        [int]$KeyLength,

        [Parameter(Mandatory=$False)]
        [ValidateSet("SHA1","SHA256","SHA384","SHA512","MD5","MD4","MD2")]
        [string]$HashAlgorithm,

        # For now, stick to just using RSA
        [Parameter(Mandatory=$False)]
        #[ValidateSet("RSA","DH","DSA","ECDH_P256","ECDH_P521","ECDSA_P256","ECDSA_P384","ECDSA_P521")]
        [ValidateSet("RSA")]
        [string]$KeyAlgorithmValue,

        [Parameter(Mandatory=$False)]
        [ValidatePattern('http.*?\/<CaName><CRLNameSuffix>\.crl$')]
        [string]$CDPUrl,

        [Parameter(Mandatory=$False)]
        [ValidatePattern('http.*?\/<CaName><CertificateName>.crt$')]
        [string]$AIAUrl
    )

    #region >> Helper Functions

    # NewUniqueString
    # TestIsValidIPAddress
    # ResolveHost
    # GetDomainController

    function SetupSubCA {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=$True)]
            [pscredential]$DomainAdminCredentials,

            [Parameter(Mandatory=$True)]
            [System.Collections.ArrayList]$NetworkInfoPSObjects,

            [Parameter(Mandatory=$True)]
            [ValidateSet("EnterpriseSubordinateCA")]
            [string]$CAType,

            [Parameter(Mandatory=$True)]
            [string]$NewComputerTemplateCommonName,

            [Parameter(Mandatory=$True)]
            [string]$NewWebServerTemplateCommonName,

            [Parameter(Mandatory=$True)]
            [string]$FileOutputDirectory,

            [Parameter(Mandatory=$True)]
            [ValidateSet("Microsoft Software Key Storage Provider")]
            [string]$CryptoProvider,

            [Parameter(Mandatory=$True)]
            [ValidateSet("2048","4096")]
            [int]$KeyLength,

            [Parameter(Mandatory=$True)]
            [ValidateSet("SHA1","SHA256","SHA384","SHA512","MD5","MD4","MD2")]
            [string]$HashAlgorithm,

            [Parameter(Mandatory=$True)]
            [ValidateSet("RSA")]
            [string]$KeyAlgorithmValue,

            [Parameter(Mandatory=$True)]
            [ValidatePattern('http.*?\/<CaName><CRLNameSuffix>\.crl$')]
            [string]$CDPUrl,

            [Parameter(Mandatory=$True)]
            [ValidatePattern('http.*?\/<CaName><CertificateName>.crt$')]
            [string]$AIAUrl
        )

        #region >> Prep

        # Import any Module Dependencies
        $RequiredModules = @("PSPKI","ServerManager")
        $InvModDepSplatParams = @{
            RequiredModules                     = $RequiredModules
            InstallModulesNotAvailableLocally   = $True
            ErrorAction                         = "Stop"
        }
        $ModuleDependenciesMap = InvokeModuleDependencies @InvModDepSplatParams
        $PSPKIModuleVerCheck = $ModuleDependenciesMap.SuccessfulModuleImports | Where-Object {$_.ModuleName -eq "PSPKI"}
        $ServerManagerModuleVerCheck = $ModuleDependenciesMap.SuccessfulModuleImports | Where-Object {$_.ModuleName -eq "ServerManager"}

        # Make sure we can find the Domain Controller(s)
        try {
            $DomainControllerInfo = GetDomainController -Domain $(Get-CimInstance win32_computersystem).Domain -UseLogonServer -WarningAction SilentlyContinue
            if (!$DomainControllerInfo -or $DomainControllerInfo.PrimaryDomainController -eq $null) {throw "Unable to find Primary Domain Controller! Halting!"}
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        # Make sure time is synchronized with NTP Servers/Domain Controllers (i.e. might be using NT5DS instead of NTP)
        # See: https://giritharan.com/time-synchronization-in-active-directory-domain/
        $null = W32tm /resync /rediscover /nowait

        if (!$FileOutputDirectory) {
            $FileOutputDirectory = "C:\NewSubCAOutput"
        }
        if (!$(Test-Path $FileOutputDirectory)) {
            $null = New-Item -ItemType Directory -Path $FileOutputDirectory 
        }

        $WindowsFeaturesToAdd = @(
            "Adcs-Cert-Authority"
            "Adcs-Web-Enrollment"
            "Adcs-Enroll-Web-Pol"
            "Adcs-Enroll-Web-Svc"
            "Web-Mgmt-Console"
            "RSAT-AD-Tools"
        )
        foreach ($FeatureName in $WindowsFeaturesToAdd) {
            $SplatParams = @{
                Name    = $FeatureName
            }
            if ($FeatureName -eq "Adcs-Cert-Authority") {
                $SplatParams.Add("IncludeManagementTools",$True)
            }

            try {
                $null = Add-WindowsFeature @SplatParams
            }
            catch {
                Write-Error "Problem with 'Add-WindowsFeature $FeatureName'! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        $RelevantRootCANetworkInfo = $NetworkInfoPSObjects | Where-Object {$_.ServerPurpose -eq "RootCA"}
        $RelevantSubCANetworkInfo = $NetworkInfoPSObjects | Where-Object {$_.ServerPurpose -eq "SubCA"}

        # Make sure WinRM in Enabled and Running on $env:ComputerName
        try {
            $null = Enable-PSRemoting -Force -ErrorAction Stop
        }
        catch {
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

        $ItemsToAddToWSMANTrustedHosts = @(
            $RelevantRootCANetworkInfo.FQDN
            $RelevantRootCANetworkInfo.HostName
            $RelevantRootCANetworkInfo.IPAddress
            $RelevantSubCANetworkInfo.FQDN
            $RelevantSubCANetworkInfo.HostName
            $RelevantSubCANetworkInfo.IPAddress
        )
        foreach ($NetItem in $ItemsToAddToWSMANTrustedHosts) {
            if ($CurrentTrustedHostsAsArray -notcontains $NetItem) {
                $null = $CurrentTrustedHostsAsArray.Add($NetItem)
            }
        }
        $UpdatedTrustedHostsString = $($CurrentTrustedHostsAsArray | Where-Object {![string]::IsNullOrWhiteSpace($_)}) -join ','
        Set-Item WSMan:\localhost\Client\TrustedHosts $UpdatedTrustedHostsString -Force

        # Mount the RootCA Temporary SMB Share To Get the Following Files
        <#
        Mode                LastWriteTime         Length Name
        ----                -------------         ------ ----
        -a----        5/22/2018   8:09 AM           1524 CustomComputerTemplate.ldf
        -a----        5/22/2018   8:09 AM           1517 CustomWebServerTemplate.ldf
        -a----        5/22/2018   8:07 AM            841 RootCA.alpha.lab_ROOTCA.crt
        -a----        5/22/2018   8:09 AM           1216 RootCA.alpha.lab_ROOTCA_base64.cer
        -a----        5/22/2018   8:09 AM            483 ROOTCA.crl
        #>
        # This also serves as a way to determine if the Root CA is ready
        while (!$RootCASMBShareMount) {
            $NewPSDriveSplatParams = @{
                Name            = "R"
                PSProvider      = "FileSystem"
                Root            = "\\$($RelevantRootCANetworkInfo.FQDN)\RootCAFiles"
                Credential      = $DomainAdminCredentials
                ErrorAction     = "SilentlyContinue"
            }
            $RootCASMBShareMount = New-PSDrive @NewPSDriveSplatParams

            if (!$RootCASMBShareMount) {
                Write-Host "Waiting for RootCA SMB Share to become available. Sleeping for 15 seconds..."
                Start-Sleep -Seconds 15
            }
        }

        #endregion >> Prep

        #region >> Install ADCSCA

        try {
            $CertRequestFile = $FileOutputDirectory + "\" + $RelevantSubCANetworkInfo.FQDN + "_" + $RelevantSubCANetworkInfo.HostName + ".csr"
            $FinalCryptoProvider = $KeyAlgorithmValue + "#" + $CryptoProvider
            $InstallADCSCertAuthSplatParams = @{
                Credential                  = $DomainAdminCredentials
                CAType                      = $CAType
                CryptoProviderName          = $FinalCryptoProvider
                KeyLength                   = $KeyLength
                HashAlgorithmName           = $HashAlgorithm
                CACommonName                = $env:ComputerName
                CADistinguishedNameSuffix   = $RelevantSubCANetworkInfo.DomainLDAPString
                OutputCertRequestFile       = $CertRequestFile
                Force                       = $True
                ErrorAction                 = "Stop"
            }
            $null = Install-AdcsCertificationAuthority @InstallADCSCertAuthSplatParams *>"$FileOutputDirectory\InstallAdcsCertificationAuthority.log"
        }
        catch {
            Write-Error $_
            Write-Error "Problem with Install-AdcsCertificationAuthority cmdlet! Halting!"
            $global:FunctionResult = "1"
            return
        }

        # Copy RootCA .crt and .crl From Network Share to SubCA CertEnroll Directory
        Copy-Item -Path "$($RootCASMBShareMount.Name)`:\*" -Recurse -Destination "C:\Windows\System32\CertSrv\CertEnroll" -Force

        # Copy RootCA .crt and .crl From Network Share to the $FileOutputDirectory
        Copy-Item -Path "$($RootCASMBShareMount.Name)`:\*" -Recurse -Destination $FileOutputDirectory -Force

        # Install the RootCA .crt to the Certificate Store
        Write-Host "Installing RootCA Certificate via 'certutil -addstore `"Root`" <RootCertFile>'..."
        [array]$RootCACrtFile = Get-ChildItem -Path $FileOutputDirectory -Filter "*.crt"
        if ($RootCACrtFile.Count -eq 0) {
            Write-Error "Unable to find RootCA .crt file under the directory '$FileOutputDirectory'! Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($RootCACrtFile.Count -gt 1) {
            $RootCACrtFile = $RootCACrtFile | Where-Object {$_.Name -eq $($RelevantRootCANetworkInfo.FQDN + "_" + $RelevantRootCANetworkInfo.HostName + '.crt')}
        }
        if ($RootCACrtFile -eq 1) {
            $RootCACrtFile = $RootCACrtFile[0]
        }
        $null = certutil -f -addstore "Root" "$($RootCACrtFile.FullName)"

        # Install RootCA .crl
        Write-Host "Installing RootCA CRL via 'certutil -addstore `"Root`" <RootCRLFile>'..."
        [array]$RootCACrlFile = Get-ChildItem -Path $FileOutputDirectory -Filter "*.crl"
        if ($RootCACrlFile.Count -eq 0) {
            Write-Error "Unable to find RootCA .crl file under the directory '$FileOutputDirectory'! Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($RootCACrlFile.Count -gt 1) {
            $RootCACrlFile = $RootCACrlFile | Where-Object {$_.Name -eq $($RelevantRootCANetworkInfo.HostName + '.crl')}
        }
        if ($RootCACrlFile -eq 1) {
            $RootCACrlFile = $RootCACrlFile[0]
        }
        $null = certutil -f -addstore "Root" "$($RootCACrlFile.FullName)"

        # Create the Certdata IIS folder
        $CertDataIISFolder = "C:\inetpub\wwwroot\certdata"
        if (!$(Test-Path $CertDataIISFolder)) {
            $null = New-Item -ItemType Directory -Path $CertDataIISFolder -Force
        }

        # Stage certdata IIS site and enable directory browsing
        Write-Host "Enable directory browsing for IIS via appcmd.exe..."
        Copy-Item -Path "$FileOutputDirectory\*" -Recurse -Destination $CertDataIISFolder -Force
        $null = & "C:\Windows\system32\inetsrv\appcmd.exe" set config "Default Web Site/certdata" /section:directoryBrowse /enabled:true

        # Update DNS Alias
        Write-Host "Update DNS with CNAME that refers 'pki.$($RelevantSubCANetworkInfo.DomainName)' to '$($RelevantSubCANetworkInfo.FQDN)' ..."
        $LogonServer = $($(Get-CimInstance win32_ntdomain).DomainControllerName | Where-Object {![string]::IsNullOrWhiteSpace($_)}).Replace('\\','').Trim()
        $DomainControllerFQDN = $LogonServer + '.' + $RelevantSubCANetworkInfo.DomainName
        Invoke-Command -ComputerName $DomainControllerFQDN -Credential $DomainAdminCredentials -ScriptBlock {
            $NetInfo = $using:RelevantSubCANetworkInfo
            Add-DnsServerResourceRecordCname -Name "pki" -HostnameAlias $NetInfo.FQDN -ZoneName $NetInfo.DomainName
        }

        # Request and Install SCA Certificate from Existing CSR
        $RootCACertUtilLocation = "$($RelevantRootCANetworkInfo.FQDN)\$($RelevantRootCANetworkInfo.HostName)" 
        $SubCACertUtilLocation = "$($RelevantSubCANetworkInfo.FQDN)\$($RelevantSubCANetworkInfo.HostName)"
        $SubCACerFileOut = $FileOutputDirectory + "\" + $RelevantSubCANetworkInfo.FQDN + "_" + $RelevantSubCANetworkInfo.HostName + ".cer"
        $CertificateChainOut = $FileOutputDirectory + "\" + $RelevantSubCANetworkInfo.FQDN + "_" + $RelevantSubCANetworkInfo.HostName + ".p7b"
        $SubCACertResponse = $FileOutputDirectory + "\" + $RelevantSubCANetworkInfo.FQDN + "_" + $RelevantSubCANetworkInfo.HostName + ".rsp"
        $FileCheck = @($SubCACerFileOut,$CertificateChainOut,$SubCACertResponse)
        foreach ($FilePath in $FileCheck) {
            if (Test-Path $FilePath) {
                Remove-Item $FilePath -Force
            }
        }

        Write-Host "Submitting certificate request for SubCA Cert Authority using certreq..."
        $RequestID = $(certreq -f -q -config "$RootCACertUtilLocation" -submit "$CertRequestFile").split('"')[2]
        Write-Host "Request ID is $RequestID"
        if (!$RequestID) {
            $RequestID = 2
            Write-Host "Request ID is $RequestID"
        }
        Start-Sleep -Seconds 5
        Write-Host "Retrieving certificate request for SubCA Cert Authority using certreq..."
        $null = certreq -f -q -retrieve -config $RootCACertUtilLocation $RequestID $SubCACerFileOut $CertificateChainOut
        Start-Sleep -Seconds 5
        

        # Install the Certificate Chain on the SubCA
        # Manually create the .p7b file...
        <#
        $CertsCollections = [Security.Cryptography.X509Certificates.X509Certificate2Collection]::new()
        $X509Cert2Info = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new()
        $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
        $X509Cert2Info.Import($SubCACerFileOut)
        $chain.ChainPolicy.RevocationMode = "NoCheck"
        $null = $chain.Build($X509Cert2Info)
        $chain.ChainElements | ForEach-Object {[void]$CertsCollections.Add($_.Certificate)}
        $chain.Reset()
        Set-Content -Path $CertificateChainOut -Value $CertsCollections.Export("pkcs7") -Encoding Byte
        #>
        Write-Host "Accepting $SubCACerFileOut using certreq.exe ..."
        $null = certreq -f -q -accept $SubCACerFileOut
        Write-Host "Installing $CertificateChainOut to $SubCACertUtilLocation ..."
        $null = certutil -f -config $SubCACertUtilLocation -installCert $CertificateChainOut
  
        try {
            Restart-Service certsvc -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        while ($(Get-Service certsvc).Status -ne "Running") {
            Write-Host "Waiting for the 'certsvc' service to start..."
            Start-Sleep -Seconds 5
        }

        # Enable the Subordinate CA to issue Certificates with Subject Alternate Names (SAN)
        Write-Host "Enable the Subordinate CA to issue Certificates with Subject Alternate Names (SAN) via certutil command..."
        $null = certutil -f -setreg policy\\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2

        try {
            $null = Stop-Service certsvc -Force -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        while ($(Get-Service certsvc).Status -ne "Stopped") {
            Write-Host "Waiting for the 'certsvc' service to stop..."
            Start-Sleep -Seconds 5
        }

        # Install Certification Authority Web Enrollment
        try {
            Write-Host "Running Install-AdcsWebEnrollment cmdlet..."
            $null = Install-AdcsWebEnrollment -Force *>"$FileOutputDirectory\InstallAdcsWebEnrollment.log"
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        try {
            $null = Start-Service certsvc -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        while ($(Get-Service certsvc).Status -ne "Running") {
            Write-Host "Waiting for the 'certsvc' service to start..."
            Start-Sleep -Seconds 5
        }

        while (!$ADCSEnrollWebSvcSuccess) {
            try {
                Write-Host "Running Install-AdcsEnrollmentWebService cmdlet..."
                $EWebSvcSplatParams = @{
                    AuthenticationType          = "UserName"
                    ApplicationPoolIdentity     = $True
                    CAConfig                    = $SubCACertUtilLocation
                    Force                       = $True
                    ErrorAction                 = "Stop"
                }
                # Install Certificate Enrollment Web Service
                $ADCSEnrollmentWebSvcInstallResult = Install-AdcsEnrollmentWebService @EWebSvcSplatParams *>"$FileOutputDirectory\ADCSEnrWebSvcInstall.log"
                $ADCSEnrollWebSvcSuccess = $True
                $ADCSEnrollmentWebSvcInstallResult | Export-CliXml "$HOME\ADCSEnrollmentWebSvcInstallResult.xml"
            }
            catch {
                try {
                    $null = Restart-Service certsvc -Force -ErrorAction Stop
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }

                while ($(Get-Service certsvc).Status -ne "Running") {
                    Write-Host "Waiting for the 'certsvc' service to start..."
                    Start-Sleep -Seconds 5
                }

                Write-Host "The 'Install-AdcsEnrollmentWebService' cmdlet failed. Trying again in 5 seconds..."
                Start-Sleep -Seconds 5
            }
        }

        # Publish SubCA CRL
        # Generate New CRL and Copy Contents of CertEnroll to $FileOutputDirectory
        # NOTE: The below 'certutil -crl' outputs the new .crl file to "C:\Windows\System32\CertSrv\CertEnroll"
        # which happens to contain some other important files that we'll need
        Write-Host "Publishing SubCA CRL ..."
        $null = certutil -f -crl
        Copy-Item -Path "C:\Windows\System32\CertSrv\CertEnroll\*" -Recurse -Destination $FileOutputDirectory -Force
        # Convert SubCA .crt DER Certificate to Base64 Just in Case You Want to Use With Linux
        $CrtFileItem = Get-ChildItem -Path $FileOutputDirectory -File -Recurse | Where-Object {$_.Name -match "$env:ComputerName\.crt"}
        $null = certutil -f -encode $($CrtFileItem.FullName) $($CrtFileItem.FullName -replace '\.crt','_base64.cer')
        
        # Copy SubCA CRL From SubCA CertEnroll directory to C:\inetpub\wwwroot\certdata" do
        $SubCACrlFileItem = $(Get-ChildItem -Path "C:\Windows\System32\CertSrv\CertEnroll" -File | Where-Object {$_.Name -match "\.crl"} | Sort-Object -Property LastWriteTime)[-1]
        Copy-Item -Path $SubCACrlFileItem.FullName -Destination "C:\inetpub\wwwroot\certdata\$($SubCACrlFileItem.Name)" -Force
        
        # Copy SubCA Cert From $FileOutputDirectory to C:\inetpub\wwwroot\certdata
        $SubCACerFileItem = Get-ChildItem -Path $FileOutputDirectory -File -Recurse | Where-Object {$_.Name -match "$env:ComputerName\.cer"}
        Copy-Item $SubCACerFileItem.FullName -Destination "C:\inetpub\wwwroot\certdata\$($SubCACerFileItem.Name)"

        # Import New Certificate Templates that were exported by the RootCA to a Network Share
        # NOTE: This shouldn't be necessary if we're using and Enterprise Root CA. If it's a Standalone Root CA,
        # this IS necessary.
        #ldifde -i -k -f $($RootCASMBShareMount.Name + ':\' + $NewComputerTemplateCommonName + '.ldf')
        #ldifde -i -k -f $($RootCASMBShareMount.Name + ':\' + $NewWebServerTemplateCommonName + '.ldf')
        
        try {
            if ($PSPKIModuleVerCheck.ModulePSCompatibility -eq "WinPS") {
                # Add New Cert Templates to List of Temps to Issue using the PSPKI Module
                $null = Get-CertificationAuthority -Name $env:ComputerName | Get-CATemplate | Add-CATemplate -Name $NewComputerTemplateCommonName | Set-CATemplate
                $null = Get-CertificationAuthority -Name $env:ComputerName | Get-CATemplate | Add-CATemplate -Name $NewWebServerTemplateCommonName | Set-CATemplate
            }
            else {
                $null = Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                    # Add New Cert Templates to List of Temps to Issue using the PSPKI Module
                    $null = Get-CertificationAuthority -Name $env:ComputerName | Get-CATemplate | Add-CATemplate -Name $NewComputerTemplateCommonName | Set-CATemplate
                    $null = Get-CertificationAuthority -Name $env:ComputerName | Get-CATemplate | Add-CATemplate -Name $NewWebServerTemplateCommonName | Set-CATemplate
                } -ArgumentList $NewComputerTemplateCommonName,$NewWebServerTemplateCommonName
            }
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        # Request PKI WebServer Alias Certificate
        # Make sure time is synchronized with NTP Servers/Domain Controllers (i.e. might be using NT5DS instead of NTP)
        # See: https://giritharan.com/time-synchronization-in-active-directory-domain/
        $null = W32tm /resync /rediscover /nowait

        Write-Host "Requesting PKI Website WebServer Certificate..."
        $PKIWebsiteCertFileOut = "$FileOutputDirectory\pki.$($RelevantSubCANetworkInfo.DomainName).cer"
        $PKIWebSiteCertInfFile = "$FileOutputDirectory\pki.$($RelevantSubCANetworkInfo.DomainName).inf"
        $PKIWebSiteCertRequestFile = "$FileOutputDirectory\pki.$($RelevantSubCANetworkInfo.DomainName).csr"

        $inf = @(
            '[Version]'
            'Signature="$Windows NT$"'
            ''
            '[NewRequest]'
            "FriendlyName = pki.$($RelevantSubCANetworkInfo.DomainName)"
            "Subject = `"CN=pki.$($RelevantSubCANetworkInfo.DomainName)`""
            'KeyLength = 2048'
            'HashAlgorithm = SHA256'
            'Exportable = TRUE'
            'KeySpec = 1'
            'KeyUsage = 0xa0'
            'MachineKeySet = TRUE'
            'SMIME = FALSE'
            'PrivateKeyArchive = FALSE'
            'UserProtected = FALSE'
            'UseExistingKeySet = FALSE'
            'ProviderName = "Microsoft RSA SChannel Cryptographic Provider"'
            'ProviderType = 12'
            'RequestType = PKCS10'
            ''
            '[Extensions]'
            '2.5.29.17 = "{text}"'
            "_continue_ = `"dns=pki.$($RelevantSubCANetworkInfo.DomainName)&`""
            "_continue_ = `"ipaddress=$($RelevantSubCANetworkInfo.IPAddress)&`""
        )

        $inf | Out-File $PKIWebSiteCertInfFile
        # NOTE: The generation of a Certificate Request File using the below "certreq.exe -new" command also adds the CSR to the 
        # Client Machine's Certificate Request Store located at PSDrive "Cert:\CurrentUser\REQUEST"
        # There doesn't appear to be an equivalent to this using PowerShell cmdlets
        $null = certreq.exe -f -new "$PKIWebSiteCertInfFile" "$PKIWebSiteCertRequestFile"
        $null = certreq.exe -f -submit -attrib "CertificateTemplate:$NewWebServerTemplateCommonName" -config "$SubCACertUtilLocation" "$PKIWebSiteCertRequestFile" "$PKIWebsiteCertFileOut"

        if (!$(Test-Path $PKIWebsiteCertFileOut)) {
            Write-Error "There was a problem requesting a WebServer Certificate from the Subordinate CA for the PKI (certsrv) website! Halting!"
            $global:FunctionResult = "1"
            return
        }
        else {
            Write-Host "Received $PKIWebsiteCertFileOut..."
        }

        # Copy PKI SubCA Alias Cert From $FileOutputDirectory to C:\inetpub\wwwroot\certdata
        Copy-Item -Path $PKIWebsiteCertFileOut -Destination "C:\inetpub\wwwroot\certdata\pki.$($RelevantSubCANetworkInfo.DomainName).cer"

        # Get the Thumbprint of the pki website certificate
        # NOTE: At this point, pki.<domain>.cer Certificate should already be loaded in the SubCA's (i.e. $env:ComputerName's)
        # Certificate Store. The thumbprint is how we reference the specific Certificate in the Store.
        $X509Cert2Info = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new()
        $X509Cert2Info.Import($PKIWebsiteCertFileOut)
        $PKIWebsiteCertThumbPrint = $X509Cert2Info.ThumbPrint
        $SubCACertThumbprint = $(Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Subject -match "CN=$env:ComputerName,"}).Thumbprint

        # Install the PKIWebsite Certificate under Cert:\CurrentUser\My
        Write-Host "Importing the PKI Website Certificate to Cert:\CurrentUser\My ..."
        $null = Import-Certificate -FilePath $PKIWebsiteCertFileOut -CertStoreLocation "Cert:\LocalMachine\My"
        $PKICertSerialNumber = $(Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -eq $PKIWebsiteCertThumbPrint}).SerialNumber
        # Make sure it is ready to be used by IIS by ensuring the Private Key is readily available
        Write-Host "Make sure PKI Website Certificate is ready to be used by IIS by running 'certutil -repairstore'..."
        $null = certutil -repairstore "My" $PKICertSerialNumber

        Write-Host "Running Install-AdcsEnrollmentPolicyWebService cmdlet..."
        while (!$ADCSEnrollmentPolicySuccess) {
            try {
                $EPolSplatParams = @{
                    AuthenticationType      = "UserName"
                    SSLCertThumbprint       = $SubCACertThumbprint
                    Force                   = $True
                    ErrorAction             = "Stop"
                }
                $ADCSEnrollmentPolicyInstallResult = Install-AdcsEnrollmentPolicyWebService @EPolSplatParams
                $ADCSEnrollmentPolicySuccess = $True
                $ADCSEnrollmentPolicyInstallResult | Export-CliXml "$HOME\ADCSEnrollmentPolicyInstallResult.xml"
            }
            catch {
                try {
                    $null = Restart-Service certsvc -Force -ErrorAction Stop
                }
                catch {
                    Write-Error $_
                    $global:FunctionResult = "1"
                    return
                }

                while ($(Get-Service certsvc).Status -ne "Running") {
                    Write-Host "Waiting for the 'certsvc' service to start..."
                    Start-Sleep -Seconds 5
                }

                Write-Host "The 'Install-AdcsEnrollmentPolicyWebService' cmdlet failed. Trying again in 5 seconds..."
                Start-Sleep -Seconds 5
            }
        }

        try {
            Write-Host "Configuring CRL, CDP, AIA, CA Auditing..."
            # Configure CRL, CDP, AIA, CA Auditing
            # Update CRL Validity period
            $null = certutil -f -setreg CA\\CRLPeriod "Weeks"
            $null = certutil -f -setreg CA\\CRLPeriodUnits 4
            $null = certutil -f -setreg CA\\CRLOverlapPeriod "Days"
            $null = certutil -f -setreg CA\\CRLOverlapUnits 3

            if ($PSPKIModuleVerCheck.ModulePSCompatibility -eq "WinPS") {
                # Remove pre-existing http CDP, add custom CDP
                $null = Get-CACrlDistributionPoint | Where-Object { $_.URI -like "http#*" } | Remove-CACrlDistributionPoint -Force
                $null = Add-CACrlDistributionPoint -Uri $CDPUrl -AddToCertificateCdp -Force

                # Remove pre-existing http AIA, add custom AIA
                $null = Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like "http*" } | Remove-CAAuthorityInformationAccess -Force
                $null = Add-CAAuthorityInformationAccess -Uri $AIAUrl -AddToCertificateAIA -Force
            }
            else {
                $null = Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                    # Remove pre-existing http CDP, add custom CDP
                    $null = Get-CACrlDistributionPoint | Where-Object { $_.URI -like "http#*" } | Remove-CACrlDistributionPoint -Force
                    $null = Add-CACrlDistributionPoint -Uri $args[0] -AddToCertificateCdp -Force

                    # Remove pre-existing http AIA, add custom AIA
                    $null = Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like "http*" } | Remove-CAAuthorityInformationAccess -Force
                    $null = Add-CAAuthorityInformationAccess -Uri $args[1] -AddToCertificateAIA -Force
                } -ArgumentList $CDPUrl,$AIAUrl
            }

            # Enable all event auditing
            $null = certutil -f -setreg CA\\AuditFilter 127
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        try {
            Restart-Service certsvc -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        while ($(Get-Service certsvc).Status -ne "Running") {
            Write-Host "Waiting for the 'certsvc' service to start..."
            Start-Sleep -Seconds 5
        }

        #endregion >> Install ADCSCA

        #region >> Finish IIS Config

        # Configure HTTPS Binding
        try {
            Write-Host "Configuring IIS https binding to use $PKIWebsiteCertFileOut..."
            Import-Module WebAdministration
            Remove-Item IIS:\SslBindings\*
            $null = Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -eq $PKIWebsiteCertThumbPrint} | New-Item IIS:\SslBindings\0.0.0.0!443
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        # Configure Application Settings
        Write-Host "Configuring IIS Application Settings via appcmd.exe..."
        $null = & "C:\Windows\system32\inetsrv\appcmd.exe" set config /commit:MACHINE /section:appSettings /+"[key='Friendly Name',value='$($RelevantSubCANetworkInfo.DomainName) Domain Certification Authority']"

        try {
            Restart-Service certsvc -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        while ($(Get-Service certsvc).Status -ne "Running") {
            Write-Host "Waiting for the 'certsvc' service to start..."
            Start-Sleep -Seconds 5
        }

        try {
            Restart-Service iisadmin -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        while ($(Get-Service iisadmin).Status -ne "Running") {
            Write-Host "Waiting for the 'iis' service to start..."
            Start-Sleep -Seconds 5
        }

        #endregion >> Finish IIS Config

        [pscustomobject]@{
            PKIWebsiteUrls                  = @("https://pki.$($RelevantSubCANetworkInfo.DomainName)/certsrv","https://pki.$($RelevantSubCANetworkInfo.IPAddress)/certsrv")
            PKIWebsiteCertSSLCertificate    = Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -eq $PKIWebsiteCertThumbPrint}
            AllOutputFiles                  = Get-ChildItem $FileOutputDirectory
        }
    }

    #endregion >> Helper Functions

    
    #region >> Initial Prep

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

    [System.Collections.ArrayList]$NetworkLocationObjsToResolve = @(
        [pscustomobject]@{
            ServerPurpose       = "RootCA"
            NetworkLocation     = $RootCAIPOrFQDN
        }
    )
    if ($PSBoundParameters['SubCAIPOrFQDN']) {
        $SubCAPSObj = [pscustomobject]@{
            ServerPurpose       = "SubCA"
            NetworkLocation     = $SubCAIPOrFQDN
        }
    }
    else {
        $SubCAPSObj = [pscustomobject]@{
            ServerPurpose       = "SubCA"
            NetworkLocation     = $env:ComputerName + "." + $(Get-CimInstance win32_computersystem).Domain
        }
    }
    $null = $NetworkLocationObjsToResolve.Add($SubCAPSObj)

    [System.Collections.ArrayList]$NetworkInfoPSObjects = @()
    foreach ($NetworkLocationObj in $NetworkLocationObjsToResolve) {
        if ($($NetworkLocation -split "\.")[0] -ne $env:ComputerName -and
        $NetworkLocation -ne $PrimaryIP -and
        $NetworkLocation -ne "$env:ComputerName.$($(Get-CimInstance win32_computersystem).Domain)"
        ) {
            try {
                $NetworkInfo = ResolveHost -HostNameOrIP $NetworkLocationObj.NetworkLocation
                $DomainName = $NetworkInfo.Domain
                $FQDN = $NetworkInfo.FQDN
                $IPAddr = $NetworkInfo.IPAddressList[0]
                $DomainShortName = $($DomainName -split "\.")[0]
                $DomainLDAPString = $(foreach ($StringPart in $($DomainName -split "\.")) {"DC=$StringPart"}) -join ','

                if (!$NetworkInfo -or $DomainName -eq "Unknown" -or !$DomainName -or $FQDN -eq "Unknown" -or !$FQDN) {
                    throw "Unable to gather Domain Name and/or FQDN info about '$NetworkLocation'! Please check DNS. Halting!"
                }
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }

            # Make sure WinRM in Enabled and Running on $env:ComputerName
            try {
                $null = Enable-PSRemoting -Force -ErrorAction Stop
            }
            catch {
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
                    Write-Error "Problem with Enabble-PSRemoting WinRM Quick Config! Halting!"
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

            $ItemsToAddToWSMANTrustedHosts = @($IPAddr,$FQDN,$($($FQDN -split "\.")[0]))
            foreach ($NetItem in $ItemsToAddToWSMANTrustedHosts) {
                if ($CurrentTrustedHostsAsArray -notcontains $NetItem) {
                    $null = $CurrentTrustedHostsAsArray.Add($NetItem)
                }
            }
            $UpdatedTrustedHostsString = $($CurrentTrustedHostsAsArray | Where-Object {![string]::IsNullOrWhiteSpace($_)}) -join ','
            Set-Item WSMan:\localhost\Client\TrustedHosts $UpdatedTrustedHostsString -Force
        }
        else {
            $DomainName = $(Get-CimInstance win32_computersystem).Domain
            $DomainShortName = $($DomainName -split "\.")[0]
            $DomainLDAPString = $(foreach ($StringPart in $($DomainName -split "\.")) {"DC=$StringPart"}) -join ','
            $FQDN = $env:ComputerName + '.' + $DomainName
            $IPAddr = $PrimaryIP
        }

        $PSObj = [pscustomobject]@{
            ServerPurpose       = $NetworkLocationObj.ServerPurpose
            FQDN                = $FQDN
            HostName            = $($FQDN -split "\.")[0]
            IPAddress           = $IPAddr
            DomainName          = $DomainName
            DomainShortName     = $DomainShortName
            DomainLDAPString    = $DomainLDAPString
        }
        $null = $NetworkInfoPSObjects.Add($PSObj)
    }

    $RelevantRootCANetworkInfo = $NetworkInfoPSObjects | Where-Object {$_.ServerPurpose -eq "RootCA"}
    $RelevantSubCANetworkInfo = $NetworkInfoPSObjects | Where-Object {$_.ServerPurpose -eq "SubCA"}

    # Set some defaults if certain paramters are not used
    if (!$CAType) {
        $CAType = "EnterpriseSubordinateCA"
    }
    if (!$NewComputerTemplateCommonName) {
        #$NewComputerTemplateCommonName = $DomainShortName + "Computer"
        $NewComputerTemplateCommonName = "Machine"
    }
    if (!$NewWebServerTemplateCommonName) {
        #$NewWebServerTemplateCommonName = $DomainShortName + "WebServer"
        $NewWebServerTemplateCommonName = "WebServer"
    }
    if (!$FileOutputDirectory) {
        $FileOutputDirectory = "C:\NewSubCAOutput"
    }
    if (!$CryptoProvider) {
        $CryptoProvider = "Microsoft Software Key Storage Provider"
    }
    if (!$KeyLength) {
        $KeyLength = 2048
    }
    if (!$HashAlgorithm) {
        $HashAlgorithm = "SHA256"
    }
    if (!$KeyAlgorithmValue) {
        $KeyAlgorithmValue = "RSA"
    }
    if (!$CDPUrl) {
        $CDPUrl = "http://pki.$($RelevantSubCANetworkInfo.DomainName)/certdata/<CaName><CRLNameSuffix>.crl"
    }
    if (!$AIAUrl) {
        $AIAUrl = "http://pki.$($RelevantSubCANetworkInfo.DomainName)/certdata/<CaName><CertificateName>.crt"
    }

    # Create SetupSubCA Helper Function Splat Parameters
    $SetupSubCASplatParams = @{
        DomainAdminCredentials              = $DomainAdminCredentials
        NetworkInfoPSObjects                = $NetworkInfoPSObjects
        CAType                              = $CAType
        NewComputerTemplateCommonName       = $NewComputerTemplateCommonName
        NewWebServerTemplateCommonName      = $NewWebServerTemplateCommonName
        FileOutputDirectory                 = $FileOutputDirectory
        CryptoProvider                      = $CryptoProvider
        KeyLength                           = $KeyLength
        HashAlgorithm                       = $HashAlgorithm
        KeyAlgorithmValue                   = $KeyAlgorithmValue
        CDPUrl                              = $CDPUrl
        AIAUrl                              = $AIAUrl
    }

    # Install any required PowerShell Modules
    <#
    # NOTE: This is handled by the MiniLab Module Import
    $RequiredModules = @("PSPKI")
    $InvModDepSplatParams = @{
        RequiredModules                     = $RequiredModules
        InstallModulesNotAvailableLocally   = $True
        ErrorAction                         = "Stop"
    }
    $ModuleDependenciesMap = InvokeModuleDependencies @InvModDepSplatParams
    #>

    #endregion >> Initial Prep


    #region >> Do SubCA Install

    if ($RelevantSubCANetworkInfo.HostName -ne $env:ComputerName) {
        $PSSessionName = NewUniqueString -ArrayOfStrings $(Get-PSSession).Name -PossibleNewUniqueString "ToSubCA"

        # Try to create a PSSession to the server that will become the Subordate CA for 15 minutes, then give up
        $Counter = 0
        while (![bool]$(Get-PSSession -Name $PSSessionName -ErrorAction SilentlyContinue)) {
            try {
                $SubCAPSSession = New-PSSession -ComputerName $RelevantSubCANetworkInfo.IPAddress -Credential $DomainAdminCredentials -Name $PSSessionName -ErrorAction SilentlyContinue
                if (![bool]$(Get-PSSession -Name $PSSessionName -ErrorAction SilentlyContinue)) {throw}
            }
            catch {
                if ($Counter -le 60) {
                    Write-Warning "New-PSSession '$PSSessionName' failed. Trying again in 15 seconds..."
                    Start-Sleep -Seconds 15
                }
                else {
                    Write-Error "Unable to create new PSSession to '$PSSessionName' using account '$($DomainAdminCredentials.UserName)'! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
            $Counter++
        }

        if (!$SubCAPSSession) {
            Write-Error "Unable to create a PSSession to the intended Subordinate CA Server at '$($RelevantSubCANetworkInfo.IPAddress)'! Halting!"
            $global:FunctionResult = "1"
            return
        }

        # Transfer any Required Modules that were installed on $env:ComputerName from an external source
        $NeededModules = @("PSPKI")
        [System.Collections.ArrayList]$ModulesToTransfer = @()
        foreach ($ModuleResource in $NeededModules) {
            $ModMapObj = $script:ModuleDependenciesMap.SuccessfulModuleImports | Where-Object {$_.ModuleName -eq $ModuleResource}
            if ($ModMapObj.ModulePSCompatibility -ne "WinPS") {
                $ModuleBase = Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                    if (![bool]$(Get-Module -ListAvailable $args[0])) {
                        Install-Module $args[0]
                    }
                    if (![bool]$(Get-Module -ListAvailable $args[0])) {
                        Write-Error $("Problem installing" + $args[0])
                    }
                    $Module = Get-Module -ListAvailable $args[0]
                    $($Module.ModuleBase -split $args[0])[0] + $args[0]
                } -ArgumentList $ModuleResource
            }
            else {
                $ModuleBase = $($ModMapObj.ManifestFileItem.FullName -split $ModuleResource)[0] + $ModuleResource
            }
            
            $null = $ModulesToTransfer.Add($ModuleBase)
        }

        $ProgramFilesPSModulePath = "C:\Program Files\WindowsPowerShell\Modules"
        foreach ($ModuleDirPath in $ModulesToTransfer) {
            $CopyItemSplatParams = @{
                Path            = $ModuleDirPath
                Recurse         = $True
                Destination     = "$ProgramFilesPSModulePath\$($ModuleDirPath | Split-Path -Leaf)"
                ToSession       = $SubCAPSSession
                Force           = $True
            }
            Copy-Item @CopyItemSplatParams
        }

        # Get ready to run SetupSubCA function remotely as a Scheduled task to that certreq/certutil don't hang due
        # to double-hop issue when requesting a Certificate from the Root CA ...

        $FunctionsForRemoteUse = @(
            ${Function:GetDomainController}.Ast.Extent.Text
            ${Function:SetupSubCA}.Ast.Extent.Text
        )

        # Initialize the Remote Environment
        $FunctionsForRemoteUse = $script:FunctionsForSBUse
        $FunctionsForRemoteUse.Add($(${Function:SetupSubCA}.Ast.Extent.Text))
        $DomainAdminAccount = $DomainAdminCredentials.UserName
        $DomainAdminPwd = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($DomainAdminCredentials.Password))
        $Output = Invoke-Command -Session $SubCAPSSession -ScriptBlock {
            $using:FunctionsForRemoteUse | foreach { Invoke-Expression $_ }
            $script:ModuleDependenciesMap = $args[0]
            ${Function:GetDomainController}.Ast.Extent.Text | Set-Content "$HOME\SetupSubCA.psm1"
            ${Function:SetupSubCA}.Ast.Extent.Text | Add-Content "$HOME\SetupSubCA.psm1"
            ${Function:GetModuleDependencies}.Ast.Extent.Text | Add-Content "$HOME\SetupSubCA.psm1"
            ${Function:InvokePSCompatibility}.Ast.Extent.Text | Add-Content "$HOME\SetupSubCA.psm1"
            ${Function:InvokeModuleDependencies}.Ast.Extent.Text | Add-Content "$HOME\SetupSubCA.psm1"
            $using:NetworkInfoPSObjects | Export-CliXml "$HOME\NetworkInfoPSObjects.xml"

            $ExecutionScript = @(
                'Start-Transcript -Path "$HOME\NewSubCATask.log" -Append'
                ''
                'Import-Module "$HOME\SetupSubCA.psm1"'
                '$NetworkInfoPSObjects = Import-CliXML "$HOME\NetworkInfoPSObjects.xml"'
                ''
                "`$DomainAdminPwdSS = ConvertTo-SecureString '$using:DomainAdminPwd' -AsPlainText -Force"
                "`$DomainAdminCredentials = [pscredential]::new('$using:DomainAdminAccount',`$DomainAdminPwdSS)"
                ''
                '$SetupSubCASplatParams = @{'
                '    DomainAdminCredentials              = $DomainAdminCredentials'
                '    NetworkInfoPSObjects                = $NetworkInfoPSObjects'
                "    CAType                              = '$using:CAType'"
                "    NewComputerTemplateCommonName       = '$using:NewComputerTemplateCommonName'"
                "    NewWebServerTemplateCommonName      = '$using:NewWebServerTemplateCommonName'"
                "    FileOutputDirectory                 = '$using:FileOutputDirectory'"
                "    CryptoProvider                      = '$using:CryptoProvider'"
                "    KeyLength                           = '$using:KeyLength'"
                "    HashAlgorithm                       = '$using:HashAlgorithm'"
                "    KeyAlgorithmValue                   = '$using:KeyAlgorithmValue'"
                "    CDPUrl                              = '$using:CDPUrl'"
                "    AIAUrl                              = '$using:AIAUrl'"
                '}'
                ''
                '    SetupSubCA @SetupSubCASplatParams -OutVariable Output -ErrorAction SilentlyContinue -ErrorVariable NewSubCAErrs'
                ''
                '    $Output | Export-CliXml "$HOME\SetupSubCAOutput.xml"'
                ''
                '    if ($NewSubCAErrs) {'
                '        Write-Warning "Ignored errors are as follows:"'
                '        Write-Error ($NewSubCAErrs | Select-Object -Unique | Out-String)'
                '    }'
                ''
                '    Stop-Transcript'
                ''
                '    # Delete this script file after it is finished running'
                '    Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force'
                ''
            )
            
            Set-Content -Path "$HOME\NewSubCAExecutionScript.ps1" -Value $ExecutionScript

            $Trigger = New-ScheduledTaskTrigger -Once -At $(Get-Date).AddSeconds(10)
            $Trigger.EndBoundary = $(Get-Date).AddHours(4).ToString('s')
            # IMPORTANT NORE: The double quotes around the -File value are MANDATORY. They CANNOT be single quotes or without quotes
            # or the Scheduled Task will error out!
            $null = Register-ScheduledTask -Force -TaskName NewSubCA -User $using:DomainAdminCredentials.UserName -Password $using:DomainAdminPwd -Action $(
                New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -File `"$HOME\NewSubCAExecutionScript.ps1`""
            ) -Trigger $Trigger -Settings $(New-ScheduledTaskSettingsSet -DeleteExpiredTaskAfter 00:00:01)

            Start-Sleep -Seconds 15

            if ($(Get-ScheduledTask -TaskName 'NewSubCA').State -eq "Ready") {
                Start-ScheduledTask -TaskName "NewSubCA"
            }

            # Wait 60 minutes...
            $Counter = 0
            while ($(Get-ScheduledTask -TaskName 'NewSubCA').State  -ne 'Ready' -and $Counter -le 100) {
                $PercentComplete = [Math]::Round(($Counter/60)*100)
                Write-Progress -Activity "Running Scheduled Task 'NewSubCA'" -Status "$PercentComplete% Complete:" -PercentComplete $PercentComplete
                Start-Sleep -Seconds 60
                $Counter++
            }

            # Wait another 30 minutes for up to 2 more hours...
            $FinalCounter = 0
            while ($(Get-ScheduledTask -TaskName 'NewSubCA').State  -ne 'Ready' -and $FinalCounter -le 4) {
                $Counter = 0
                while ($(Get-ScheduledTask -TaskName 'NewSubCA').State  -ne 'Ready' -and $Counter -le 100) {
                    if ($Counter -eq 0) {Write-Host "The Scheduled Task 'NewSubCA' needs a little more time to finish..."}
                    $PercentComplete = [Math]::Round(($Counter/30)*100)
                    Write-Progress -Activity "Running Scheduled Task 'NewSubCA'" -Status "$PercentComplete% Complete:" -PercentComplete $PercentComplete
                    Start-Sleep -Seconds 60
                    $Counter++
                }
                $FinalCounter++
            }

            if ($(Get-ScheduledTask -TaskName 'NewSubCA').State  -ne 'Ready') {
                Write-Warning "The Scheduled Task 'NewSubCA' has been running for over 3 hours and has not finished! Stopping and removing..."
                Stop-ScheduledTask -TaskName "NewSubCA"
            }

            $null = Unregister-ScheduledTask -TaskName "NewSubCA" -Confirm:$False

            if (Test-Path "$HOME\SetupSubCAOutput.xml") {
                Write-Host "The Subordinate CA has been configured successfully!" -ForegroundColor Green
                Import-CliXML "$HOME\SetupSubCAOutput.xml"
            }
            elseif (Test-Path "$HOME\NewSubCATask.log") {
                Write-Warning "The Subordinate CA was NOT configured within 3 hours! Please review the below log output"
                Get-Content "$HOME\NewSubCATask.log"
            }
            else {
                Write-Warning "The Subordinate CA was NOT configured within 3 hours and no log file indicating progress was generated!"
                Write-Warning "Please review the content of the following files:"
                [array]$FilesToReview = Get-ChildItem $HOME -File | Where-Object {$_.Extension -match '\.ps1|\.log|\.xml'}
                $FilesToReview.FullName
            }
        } -ArgumentList $script:ModuleDependenciesMap
    }
    else {
        Write-Host "This will take about 1 hour...go grab a coffee..."
        $Output = SetupSubCA @SetupSubCASplatParams
    }

    $Output

    #endregion >> Do SubCA Install

    
}


<#
    .SYNOPSIS
        This function recreates the MobyLinuxVM used by Docker-For-Windows to manage Linux Containers.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER MobyLinuxVMMemoryInGB
        This parameter is OPTIONAL, however, it has a default value of 2.

        This parameter takes an integer (even numbers only) that represents the amount of Memory
        in GB to allocate to the newly recreated MobyLinuxVM.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Recreate-MobyLinuxVM
#>
function Recreate-MobyLinuxVM {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [ValidateScript({
            $(($_ % 2) -eq 0) -and $($_ -ge 2)
        })]
        [int]$MobyLinuxVMMemoryInGB = 2
    )

    if ([bool]$PSBoundParameters['MobyLinuxVMMemoryInGB']) {
        $MobyLinuxVMMemoryInMB = [Math]::Round($MobyLinuxVMMemoryInGB * 1KB)
    }

    try {
        $DockerDir = $($(Get-Command docker).Source -split "\\Docker\\Resources\\")[0] + "\Docker"
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    $MobyLinuxISOPath = $(Get-ChildItem -Path "C:\Program Files\Docker" -Recurse -File -Filter "docker-for-win.iso").FullName
    if (!$MobyLinuxISOPath) {
        Write-Error "Unable to find docker-for-win.iso! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ([bool]$(Get-VM -Name MobyLinuxVM -ErrorAction SilentlyContinue)) {
        MobyLinuxBetter -Destroy
    }

    MobyLinuxBetter -VmName MobyLinuxVM -IsoFile $MobyLinuxISOPath -Create -Memory $MobyLinuxVMMemoryInMB
}


<#
    .SYNOPSIS
        This function switches Docker-For-Windows (Docker CE) from Linux Container mode to Windows Container mode
        or visa versa.

    .DESCRIPTION
        See .SYNOPSIS

    .PARAMETER ContainerType
        This parameter is MANDATORY.

        This parameter takes a string with a value of either "Windows" or "Linux" representing the contianer
        mode that you would like to switch to.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Switch-DockerContainerType -ContainerType Windows
        
#>
function Switch-DockerContainerType {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [ValidateSet("Windows","Linux")]
        [string]$ContainerType
    )

    try {
        # Find DockerCli
        $DockerCliExePath = $(Get-ChildItem -Path "$env:ProgramFiles\Docker" -Recurse -File -Filter "*DockerCli.exe").FullName

        if (!$DockerCliExePath) {
            throw "Unable to find DockerCli.exe! Halting!"
        }
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    $DockerInfo = Get-DockerInfo

    if ($($DockerInfo.DockerServerInfo.'OS/Arch' -match "windows" -and $ContainerType -eq "Linux") -or
    $($DockerInfo.DockerServerInfo.'OS/Arch' -match "linux" -and $ContainerType -eq "Windows")) {
        & $DockerCliExePath -SwitchDaemon

        [pscustomobject]@{
            OriginalDockerServerArch    = $DockerInfo.DockerServerInfo.'OS/Arch'
            NewDockerServerArch         = $($($(docker version) -match "OS/Arch")[1] -split ":[\s]+")[1].Trim()
        }
    }
    else {
        Write-Warning "The Docker Daemon is already set to manage $ContainerType containers! No action taken."
    }
}


[System.Collections.ArrayList]$script:FunctionsForSBUse = @(
    ${Function:AddWinRMTrustLocalHost}.Ast.Extent.Text
    ${Function:ConfirmAWSVM}.Ast.Extent.Text
    ${Function:ConfirmAzureVM}.Ast.Extent.Text
    ${Function:ConfirmGoogleComputeVM}.Ast.Extent.Text
    ${Function:ConvertSize}.Ast.Extent.Text
    ${Function:DoDockerInstall}.Ast.Extent.Text
    ${Function:EnableNestedVM}.Ast.Extent.Text
    ${Function:FixNTVirtualMachinesPerms}.Ast.Extent.Text 
    ${Function:FixVagrantPrivateKeyPerms}.Ast.Extent.Text
    ${Function:GetDomainController}.Ast.Extent.Text
    ${Function:GetElevation}.Ast.Extent.Text
    ${Function:GetFileLockProcess}.Ast.Extent.Text
    ${Function:GetIPRange}.Ast.Extent.Text
    ${Function:GetModuleDependencies}.Ast.Extent.Text
    ${Function:GetNativePath}.Ast.Extent.Text
    ${Function:GetNestedVirtCapabilities}.Ast.Extent.Text
    ${Function:GetPendingReboot}.Ast.Extent.Text
    ${Function:GetVSwitchAllRelatedInfo}.Ast.Extent.Text
    ${Function:GetWinPSInCore}.Ast.Extent.Text
    ${Function:GetWorkingCredentials}.Ast.Extent.Text
    ${Function:InstallFeatureDism}.Ast.Extent.Text
    ${Function:InstallHyperVFeatures}.Ast.Extent.Text
    ${Function:InvokeModuleDependencies}.Ast.Extent.Text
    ${Function:InvokePSCompatibility}.Ast.Extent.Text
    ${Function:ManualPSGalleryModuleInstall}.Ast.Extent.Text
    ${Function:MobyLinuxBetter}.Ast.Extent.Text
    ${Function:NewUniqueString}.Ast.Extent.Text
    ${Function:PauseForWarning}.Ast.Extent.Text
    ${Function:ResolveHost}.Ast.Extent.Text
    ${Function:TestHyperVExternalvSwitch}.Ast.Extent.Text
    ${Function:TestIsValidIPAddress}.Ast.Extent.Text
    ${Function:UnzipFile}.Ast.Extent.Text
    ${Function:Add-WinRMTrustedHost}.Ast.Extent.Text
    ${Function:Create-Domain}.Ast.Extent.Text
    ${Function:Create-RootCA}.Ast.Extent.Text
    ${Function:Create-SubordinateCA}.Ast.Extent.Text
    ${Function:Create-TwoTierPKI}.Ast.Extent.Text
    ${Function:Create-TwoTierPKICFSSL}.Ast.Extent.Text
    ${Function:Deploy-HyperVVagrantBoxManually}.Ast.Extent.Text
    ${Function:Generate-Certificate}.Ast.Extent.Text
    ${Function:Get-DockerInfo}.Ast.Extent.Text
    ${Function:Get-DSCEncryptionCert}.Ast.Extent.Text
    ${Function:Get-EncryptionCert}.Ast.Extent.Text
    ${Function:Get-GuestVMAndHypervisorInfo}.Ast.Extent.Text
    ${Function:Get-VagrantBoxManualDownload}.Ast.Extent.Text
    ${Function:Get-WinOpenSSL}.Ast.Extent.Text
    ${Function:Install-Docker}.Ast.Extent.Text
    ${Function:Join-LinuxToAD}.Ast.Extent.Text
    ${Function:Manage-HyperVVM}.Ast.Extent.Text
    ${Function:Move-DockerStorage}.Ast.Extent.Text
    ${Function:New-DomainController}.Ast.Extent.Text
    ${Function:New-RootCA}.Ast.Extent.Text
    ${Function:New-Runspace}.Ast.Extent.Text
    ${Function:New-SelfSignedCertificateEx}.Ast.Extent.Text
    ${Function:New-SubordinateCA}.Ast.Extent.Text
    ${Function:Recreate-MobyLinuxVM}.Ast.Extent.Text
    ${Function:Switch-DockerContainerType}.Ast.Extent.Text
)

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUVEECNXyxrD5wCWGQEbSWHO4O
# +9qgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFIATOi4Il0es4Gz+
# QpLklNAm6f5SMA0GCSqGSIb3DQEBAQUABIIBAL6EUx0CYyLMPad3piZtib96ZoXf
# W7fLeGj+Mi+Yan8YvCUMKHi9xQ/1Y4mkXQbMZVWLKFu5ZtlhRbR01tYiQ9cdFMeG
# Iy7x04ywIRQMM5FIM3FiUwS/AKNdPj5t0TFfJF94TFbqx4yu8zX8OX+KScduNZVJ
# JZ52s1wesc90PVcWum7d7SO2Wmm2YZpFQvyCIJBCONJ1dBSSsfi09CBeOrZ5XmOD
# D3YSIGmTME28bwg4eGQLlMH7M5+m/vO6a+w7LAFcB8vKHp63wnBAE1ILUOZ4jd15
# UheovbR1sJpcfRa85R4pMSEE+5P5KuuSt6JJTumflgwLAOrLMhn54+LMeE4=
# SIG # End signature block
