[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

# Get public and private function definition files.
[array]$Public  = Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1" -ErrorAction SilentlyContinue
[array]$Private = Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" -ErrorAction SilentlyContinue

# Dot source the Private functions
foreach ($import in $Private) {
    try {
        . $import.FullName
    }
    catch {
        Write-Error -Message "Failed to import function $($import.FullName): $_"
    }
}

try {
    & "$PSScriptRoot\Install-PSDepend.ps1"
}
catch {
    Remove-Module WinSSH -ErrorAction SilentlyContinue
    Write-Error $_
    Write-Error "Installing the PSDepend Module failed! The WinSSH Module will not be loaded. Halting!"
    $global:FunctionResult = "1"
    return
}

try {
    Import-Module PSDepend
    $null = Invoke-PSDepend -Path "$PSScriptRoot\module.requirements.psd1" -Install -Import -Force
}
catch {
    Remove-Module WinSSH -ErrorAction SilentlyContinue
    Write-Error $_
    Write-Error "Problem with PSDepend Installing/Importing Module Dependencies! The WinSSH Module will not be loaded. Halting!"
    $global:FunctionResult = "1"
    return
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

    $NextHop = $(Get-NetRoute -AddressFamily IPv4 | Where-Object {$_.NextHop -ne "0.0.0.0"} | Sort-Object RouteMetric)[0].NextHop
    $PrimaryIP = $(Find-NetRoute -RemoteIPAddress $NextHop | Where-Object {$($_ | Get-Member).Name -contains "IPAddress"}).IPAddress

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

    $FunctionsForSBUse = @(
        ${Function:FixNTVirtualMachinesPerms}.Ast.Extent.Text 
        ${Function:GetDomainController}.Ast.Extent.Text
        ${Function:GetElevation}.Ast.Extent.Text
        ${Function:GetFileLockProcess}.Ast.Extent.Text
        ${Function:GetNativePath}.Ast.Extent.Text
        ${Function:GetVSwitchAllRelatedInfo}.Ast.Extent.Text
        ${Function:InstallFeatureDism}.Ast.Extent.Text
        ${Function:InstallHyperVFeatures}.Ast.Extent.Text
        ${Function:NewUniqueString}.Ast.Extent.Text
        ${Function:PauseForWarning}.Ast.Extent.Text
        ${Function:ResolveHost}.Ast.Extent.Text
        ${Function:TestIsValidIPAddress}.Ast.Extent.Text
        ${Function:UnzipFile}.Ast.Extent.Text
        ${Function:Create-TwoTierPKI}.Ast.Extent.Text
        ${Function:Deploy-HyperVVagrantBoxManually}.Ast.Extent.Text
        ${Function:Generate-Certificate}.Ast.Extent.Text
        ${Function:Get-DSCEncryptionCert}.Ast.Extent.Text
        ${Function:Get-VagrantBoxManualDownload}.Ast.Extent.Text
        ${Function:Manage-HyperVVM}.Ast.Extent.Text
        ${Function:New-DomainController}.Ast.Extent.Text
        ${Function:New-RootCA}.Ast.Extent.Text
        ${Function:New-SelfSignedCertificateEx}.Ast.Extent.Text
        ${Function:New-SubordinateCA}.Ast.Extent.Text
    )

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
        $LocalDrives = Get-WmiObject Win32_LogicalDisk | Where-Object {$_.Drivetype -eq 3} | foreach {Get-PSDrive $_.DeviceId[0] -ErrorAction SilentlyContinue}
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

        $NewVMDeploySBAsString = @"
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

`$env:Path = '$env:Path'

# Load the functions we packed up
`$args | foreach { Invoke-Expression `$_ }

`$DeployBoxSplatParams = @{
    VagrantBox                  = '$Windows2016VagrantBox'
    CPUs                        = 2
    Memory                      = 4096
    VagrantProvider             = "hyperv"
    VMName                      = '$DomainShortName' + "DC1"
    VMDestinationDirectory      = '$VMStorageDirectory'
    SkipHyperVInstallCheck      = `$True
    CopyDecompressedDirectory   = `$True
}

if (-not [string]::IsNullOrWhiteSpace('$DecompressedBoxDir')) {
    if (`$(Get-Item '$DecompressedBoxDir').PSIsContainer) {
        `$DeployBoxSplatParams.Add("DecompressedBoxDirectory",'$DecompressedBoxDir')
    }
}
if (-not [string]::IsNullOrWhiteSpace('$BoxFilePath')) {
    if (-not `$(Get-Item '$BoxFilePath').PSIsContainer) {
        `$DeployBoxSplatParams.Add("BoxFilePath",'$BoxFilePath')
    }
}

`$DeployBoxResult = Deploy-HyperVVagrantBoxManually @DeployBoxSplatParams
`$DeployBoxResult
"@
        $NewVMDeploySB = [scriptblock]::Create($NewVMDeploySBAsString)

        if (!$IPofServerToBeDomainController) {
            $DomainShortName = $($NewDomain -split "\.")[0]
            Write-Host "Deploying New Domain Controller VM '$DomainShortName`DC1'..."

            $NewDCVMDeployJobName = NewUniqueString -PossibleNewUniqueString "NewDCVM" -ArrayOfStrings $(Get-Job).Name

            $NewDCVMDeployJobSplatParams = @{
                Name            = $NewDCVMDeployJobName
                Scriptblock     = $NewVMDeploySB
                ArgumentList    = $FunctionsForSBUse
            }
            $NewDCVMDeployJobInfo = Start-Job @NewDCVMDeployJobSplatParams
        
            $NewDCVMDeployResult = Wait-Job -Job $NewDCVMDeployJobInfo | Receive-Job

            while (![bool]$(Get-VM -Name "$DomainShortName`DC1" -ErrorAction SilentlyContinue)) {
                Write-Host "Waiting for $DomainShortName`DC1 VM to be deployed..."
                Start-Sleep -Seconds 15
            }

            $IPofServerToBeDomainController = $NewDCVMDeployResult.VMIPAddress
            if (!$IPofServerToBeDomainController) {
                $IPofServerToBeDomainController = $(Get-VM -Name "$DomainShortName`DC1").NetworkAdpaters.IPAddresses | Where-Object {TestIsValidIPAddress -IPAddress $_}
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
        $null = Get-NetConnectionProfile | Where-Object {$_.NetworkCategory -eq 'Public'} | Set-NetConnectionProfile -NetworkCategory 'Private'

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
            ComputerName    = $args[0]
            Credential      = $args[1]
            ScriptBlock     = $RenameComputerSB
            ArgumentList    = $args[2],$args[1]
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
        
        $RenameDCJobName = NewUniqueString -PossibleNewUniqueString "RenameDC" -ArrayOfStrings $(Get-Job).Name

        $RenameDCArgList = @(
            $IPofServerToBeDomainController
            $PSRemotingCredentials
            $DesiredHostNameDC
        )
        $RenameDCJobSplatParams = @{
            Name            = $RenameDCJobName
            Scriptblock     = $RenameComputerJobSB
            ArgumentList    = $RenameDCArgList
        }
        $RenameDCJobInfo = Start-Job @RenameDCJobSplatParams
    }

    if ($RenameDCJobInfo) {
        $RenameDCResult = Wait-Job -Job $RenameDCJobInfo | Receive-Job

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

    Write-Host "Creating the New Domain Controller..."
    $NewDomainControllerSplatParams = @{
        DesiredHostName                         = $DesiredHostNameDC
        NewDomainName                           = $NewDomain
        NewDomainAdminCredentials               = $DomainAdminCredentials
        ServerIP                                = $IPofServerToBeDomainController
        PSRemotingLocalAdminCredentials         = $PSRemotingCredentials
        LocalAdministratorAccountCredentials    = $LocalAdministratorAccountCredentials
    }
    $NewDomainControllerResults = New-DomainController @NewDomainControllerSplatParams

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

    $NextHop = $(Get-NetRoute -AddressFamily IPv4 | Where-Object {$_.NextHop -ne "0.0.0.0"} | Sort-Object RouteMetric)[0].NextHop
    $PrimaryIP = $(Find-NetRoute -RemoteIPAddress $NextHop | Where-Object {$($_ | Get-Member).Name -contains "IPAddress"}).IPAddress

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

    $FunctionsForSBUse = @(
        ${Function:FixNTVirtualMachinesPerms}.Ast.Extent.Text 
        ${Function:GetDomainController}.Ast.Extent.Text
        ${Function:GetElevation}.Ast.Extent.Text
        ${Function:GetFileLockProcess}.Ast.Extent.Text
        ${Function:GetNativePath}.Ast.Extent.Text
        ${Function:GetVSwitchAllRelatedInfo}.Ast.Extent.Text
        ${Function:InstallFeatureDism}.Ast.Extent.Text
        ${Function:InstallHyperVFeatures}.Ast.Extent.Text
        ${Function:NewUniqueString}.Ast.Extent.Text
        ${Function:PauseForWarning}.Ast.Extent.Text
        ${Function:ResolveHost}.Ast.Extent.Text
        ${Function:TestIsValidIPAddress}.Ast.Extent.Text
        ${Function:UnzipFile}.Ast.Extent.Text
        ${Function:Create-TwoTierPKI}.Ast.Extent.Text
        ${Function:Deploy-HyperVVagrantBoxManually}.Ast.Extent.Text
        ${Function:Generate-Certificate}.Ast.Extent.Text
        ${Function:Get-DSCEncryptionCert}.Ast.Extent.Text
        ${Function:Get-VagrantBoxManualDownload}.Ast.Extent.Text
        ${Function:Manage-HyperVVM}.Ast.Extent.Text
        ${Function:New-DomainController}.Ast.Extent.Text
        ${Function:New-RootCA}.Ast.Extent.Text
        ${Function:New-SelfSignedCertificateEx}.Ast.Extent.Text
        ${Function:New-SubordinateCA}.Ast.Extent.Text
    )

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
        $LocalDrives = Get-WmiObject Win32_LogicalDisk | Where-Object {$_.Drivetype -eq 3} | foreach {Get-PSDrive $_.DeviceId[0] -ErrorAction SilentlyContinue}
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

        $NewVMDeploySBAsString = @"
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

`$env:Path = '$env:Path'

# Load the functions we packed up
`$args | foreach { Invoke-Expression `$_ }

`$DeployBoxSplatParams = @{
    VagrantBox                  = '$Windows2016VagrantBox'
    CPUs                        = 2
    Memory                      = 4096
    VagrantProvider             = "hyperv"
    VMName                      = '$DomainShortName' + "RootCA"
    VMDestinationDirectory      = '$VMStorageDirectory'
    SkipHyperVInstallCheck      = `$True
    CopyDecompressedDirectory   = `$True
}

if (-not [string]::IsNullOrWhiteSpace('$DecompressedBoxDir')) {
    if (`$(Get-Item '$DecompressedBoxDir').PSIsContainer) {
        `$DeployBoxSplatParams.Add("DecompressedBoxDirectory",'$DecompressedBoxDir')
    }
}
if (-not [string]::IsNullOrWhiteSpace('$BoxFilePath')) {
    if (-not `$(Get-Item '$BoxFilePath').PSIsContainer) {
        `$DeployBoxSplatParams.Add("BoxFilePath",'$BoxFilePath')
    }
}

`$DeployBoxResult = Deploy-HyperVVagrantBoxManually @DeployBoxSplatParams
`$DeployBoxResult
"@
        $NewVMDeploySB = [scriptblock]::Create($NewVMDeploySBAsString)

        if (!$IPofServerToBeRootCA) {
            $DomainShortName = $($ExistingDomain -split "\.")[0]

            Write-Host "Deploying New Root CA VM '$DomainShortName`RootCA'..."
            
            $NewRootCAVMDeployJobName = NewUniqueString -PossibleNewUniqueString "NewRootCAVM" -ArrayOfStrings $(Get-Job).Name

            $NewRootCAVMDeployJobSplatParams = @{
                Name            = $NewRootCAVMDeployJobName
                Scriptblock     = $NewVMDeploySB
                ArgumentList    = $FunctionsForSBUse
            }
            $NewRootCAVMDeployJobInfo = Start-Job @NewRootCAVMDeployJobSplatParams

            $NewRootCAVMDeployResult = Wait-Job -Job $NewRootCAVMDeployJobInfo | Receive-Job
            $IPofServerToBeRootCA = $NewRootCAVMDeployResult.VMIPAddress

            while (![bool]$(Get-VM -Name "$DomainShortName`RootCA" -ErrorAction SilentlyContinue)) {
                Write-Host "Waiting for $DomainShortName`RootCA VM to be deployed..."
                Start-Sleep -Seconds 15
            }

            if (!$IPofServerToBeRootCA) {
                $IPofServerToBeRootCA = $(Get-VM -Name "$DomainShortName`RootCA").NetworkAdpaters.IPAddresses | Where-Object {TestIsValidIPAddress -IPAddress $_}
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
        $null = Get-NetConnectionProfile | Where-Object {$_.NetworkCategory -eq 'Public'} | Set-NetConnectionProfile -NetworkCategory 'Private'

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
        $JoinDomainJobSB = {
            $JoinDomainSBAsString = @'
# Synchronize time with time servers
$null = W32tm /resync /rediscover /nowait

# Make sure the DNS Client points to IP of Domain Controller (and others from DHCP)
$NextHop = $(Get-NetRoute -AddressFamily IPv4 | Where-Object {$_.NextHop -ne "0.0.0.0"} | Sort-Object RouteMetric)[0].NextHop
$PrimaryIP = $(Find-NetRoute -RemoteIPAddress $NextHop | Where-Object {$($_ | Get-Member).Name -contains "IPAddress"}).IPAddress
$NetIPAddressInfo = Get-NetIPAddress -IPAddress $PrimaryIP
$NetAdapterInfo = Get-NetAdapter -InterfaceIndex $NetIPAddressInfo.InterfaceIndex
$CurrentDNSServerListInfo = Get-DnsClientServerAddress -InterfaceIndex $NetIPAddressInfo.InterfaceIndex -AddressFamily IPv4
$CurrentDNSServerList = $CurrentDNSServerListInfo.ServerAddresses
$UpdatedDNSServerList = [System.Collections.ArrayList][array]$CurrentDNSServerList
$UpdatedDNSServerList.Insert(0,$args[0])
$null = Set-DnsClientServerAddress -InterfaceIndex $NetIPAddressInfo.InterfaceIndex -ServerAddresses $UpdatedDNSServerList

$CurrentDNSSuffixSearchOrder = $(Get-DNSClientGlobalSetting).SuffixSearchList
[System.Collections.ArrayList]$UpdatedDNSSuffixList = $CurrentDNSSuffixSearchOrder
$UpdatedDNSSuffixList.Insert(0,$args[2])
Set-DnsClientGlobalSetting -SuffixSearchList $UpdatedDNSSuffixList

# Try resolving the Domain for 30 minutes
$Counter = 0
while (![bool]$(Resolve-DNSName $args[2] -ErrorAction SilentlyContinue) -and $Counter -le 120) {
    Write-Host "Waiting for DNS to resolve Domain Controller..."
    Start-Sleep -Seconds 15
    $Counter++
}
if (![bool]$(Resolve-DNSName $args[2] -ErrorAction SilentlyContinue)) {
    Write-Error "Unable to resolve Domain $($args[2])! Halting!"
    $global:FunctionResult = "1"
    return
}

# Join Domain
Rename-Computer -NewName $args[1]
Start-Sleep -Seconds 10
Add-Computer -DomainName $args[2] -Credential $args[3] -Options JoinWithNewName,AccountCreate -Force -Restart
'@
            
            $JoinDomainSB = [scriptblock]::Create($JoinDomainSBAsString)
    
            $InvCmdJoinDomainSplatParams = @{
                ComputerName    = $args[0]
                Credential      = $args[1]
                ScriptBlock     = $JoinDomainSB
                ArgumentList    = $args[2],$args[3],$args[4],$args[5]
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

            $JoinRootCAJobName = NewUniqueString -PossibleNewUniqueString "JoinRootCA" -ArrayOfStrings $(Get-Job).Name

            $JoinRootCAArgList = @(
                $IPofServerToBeRootCA
                $PSRemotingCredentials
                $IPofDomainController
                $DesiredHostNameRootCA
                $ExistingDomain
                $DomainAdminCredentials
            )
            $JoinRootCAJobSplatParams = @{
                Name            = $JoinRootCAJobName
                Scriptblock     = $JoinDomainJobSB
                ArgumentList    = $JoinRootCAArgList
            }
            $JoinRootCAJobInfo = Start-Job @JoinRootCAJobSplatParams
            
            $JoinRootCAResult = Wait-Job -Job $JoinRootCAJobInfo | Receive-Job

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

    $NextHop = $(Get-NetRoute -AddressFamily IPv4 | Where-Object {$_.NextHop -ne "0.0.0.0"} | Sort-Object RouteMetric)[0].NextHop
    $PrimaryIP = $(Find-NetRoute -RemoteIPAddress $NextHop | Where-Object {$($_ | Get-Member).Name -contains "IPAddress"}).IPAddress

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

    $FunctionsForSBUse = @(
        ${Function:FixNTVirtualMachinesPerms}.Ast.Extent.Text 
        ${Function:GetDomainController}.Ast.Extent.Text
        ${Function:GetElevation}.Ast.Extent.Text
        ${Function:GetFileLockProcess}.Ast.Extent.Text
        ${Function:GetNativePath}.Ast.Extent.Text
        ${Function:GetVSwitchAllRelatedInfo}.Ast.Extent.Text
        ${Function:InstallFeatureDism}.Ast.Extent.Text
        ${Function:InstallHyperVFeatures}.Ast.Extent.Text
        ${Function:NewUniqueString}.Ast.Extent.Text
        ${Function:PauseForWarning}.Ast.Extent.Text
        ${Function:ResolveHost}.Ast.Extent.Text
        ${Function:TestIsValidIPAddress}.Ast.Extent.Text
        ${Function:UnzipFile}.Ast.Extent.Text
        ${Function:Create-TwoTierPKI}.Ast.Extent.Text
        ${Function:Deploy-HyperVVagrantBoxManually}.Ast.Extent.Text
        ${Function:Generate-Certificate}.Ast.Extent.Text
        ${Function:Get-DSCEncryptionCert}.Ast.Extent.Text
        ${Function:Get-VagrantBoxManualDownload}.Ast.Extent.Text
        ${Function:Manage-HyperVVM}.Ast.Extent.Text
        ${Function:New-DomainController}.Ast.Extent.Text
        ${Function:New-RootCA}.Ast.Extent.Text
        ${Function:New-SelfSignedCertificateEx}.Ast.Extent.Text
        ${Function:New-SubordinateCA}.Ast.Extent.Text
    )

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
        $LocalDrives = Get-WmiObject Win32_LogicalDisk | Where-Object {$_.Drivetype -eq 3} | foreach {Get-PSDrive $_.DeviceId[0] -ErrorAction SilentlyContinue}
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

        $NewVMDeploySBAsString = @"
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

`$env:Path = '$env:Path'

# Load the functions we packed up
`$args | foreach { Invoke-Expression `$_ }

`$DeployBoxSplatParams = @{
    VagrantBox                  = '$Windows2016VagrantBox'
    CPUs                        = 2
    Memory                      = 4096
    VagrantProvider             = "hyperv"
    VMName                      = '$DomainShortName' + "SubCA"
    VMDestinationDirectory      = '$VMStorageDirectory'
    SkipHyperVInstallCheck      = `$True
    CopyDecompressedDirectory   = `$True
}

if (-not [string]::IsNullOrWhiteSpace('$DecompressedBoxDir')) {
    if (`$(Get-Item '$DecompressedBoxDir').PSIsContainer) {
        `$DeployBoxSplatParams.Add("DecompressedBoxDirectory",'$DecompressedBoxDir')
    }
}
if (-not [string]::IsNullOrWhiteSpace('$BoxFilePath')) {
    if (-not `$(Get-Item '$BoxFilePath').PSIsContainer) {
        `$DeployBoxSplatParams.Add("BoxFilePath",'$BoxFilePath')
    }
}

`$DeployBoxResult = Deploy-HyperVVagrantBoxManually @DeployBoxSplatParams
`$DeployBoxResult
"@
        $NewVMDeploySB = [scriptblock]::Create($NewVMDeploySBAsString)

        if (!$IPofServerToBeSubCA) {
            $DomainShortName = $($ExistingDomain -split "\.")[0]

            Write-Host "Deploying New Subordinate CA VM '$DomainShortName`SubCA'..."

            $NewSubCAVMDeployJobName = NewUniqueString -PossibleNewUniqueString "NewSubCAVM" -ArrayOfStrings $(Get-Job).Name

            $NewSubCAVMDeployJobSplatParams = @{
                Name            = $NewSubCAVMDeployJobName
                Scriptblock     = $NewVMDeploySB
                ArgumentList    = $FunctionsForSBUse
            }
            $NewSubCAVMDeployJobInfo = Start-Job @NewSubCAVMDeployJobSplatParams

            $NewSubCAVMDeployResult = Wait-Job -Job $NewSUbCAVMDeployJobInfo | Receive-Job
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
        $null = Get-NetConnectionProfile | Where-Object {$_.NetworkCategory -eq 'Public'} | Set-NetConnectionProfile -NetworkCategory 'Private'

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

    $JoinDomainJobSB = {
        $JoinDomainSBAsString = @'
# Synchronize time with time servers
$null = W32tm /resync /rediscover /nowait

# Make sure the DNS Client points to IP of Domain Controller (and others from DHCP)
$NextHop = $(Get-NetRoute -AddressFamily IPv4 | Where-Object {$_.NextHop -ne "0.0.0.0"} | Sort-Object RouteMetric)[0].NextHop
$PrimaryIP = $(Find-NetRoute -RemoteIPAddress $NextHop | Where-Object {$($_ | Get-Member).Name -contains "IPAddress"}).IPAddress
$NetIPAddressInfo = Get-NetIPAddress -IPAddress $PrimaryIP
$NetAdapterInfo = Get-NetAdapter -InterfaceIndex $NetIPAddressInfo.InterfaceIndex
$CurrentDNSServerListInfo = Get-DnsClientServerAddress -InterfaceIndex $NetIPAddressInfo.InterfaceIndex -AddressFamily IPv4
$CurrentDNSServerList = $CurrentDNSServerListInfo.ServerAddresses
$UpdatedDNSServerList = [System.Collections.ArrayList][array]$CurrentDNSServerList
$UpdatedDNSServerList.Insert(0,$args[0])
$null = Set-DnsClientServerAddress -InterfaceIndex $NetIPAddressInfo.InterfaceIndex -ServerAddresses $UpdatedDNSServerList

$CurrentDNSSuffixSearchOrder = $(Get-DNSClientGlobalSetting).SuffixSearchList
[System.Collections.ArrayList]$UpdatedDNSSuffixList = $CurrentDNSSuffixSearchOrder
$UpdatedDNSSuffixList.Insert(0,$args[2])
Set-DnsClientGlobalSetting -SuffixSearchList $UpdatedDNSSuffixList

# Try resolving the Domain for 30 minutes
$Counter = 0
while (![bool]$(Resolve-DNSName $args[2] -ErrorAction SilentlyContinue) -and $Counter -le 120) {
Write-Host "Waiting for DNS to resolve Domain Controller..."
Start-Sleep -Seconds 15
$Counter++
}
if (![bool]$(Resolve-DNSName $args[2] -ErrorAction SilentlyContinue)) {
Write-Error "Unable to resolve Domain $($args[2])! Halting!"
$global:FunctionResult = "1"
return
}

# Join Domain
Rename-Computer -NewName $args[1]
Start-Sleep -Seconds 10
Add-Computer -DomainName $args[2] -Credential $args[3] -Options JoinWithNewName,AccountCreate -Force -Restart
'@
        
        $JoinDomainSB = [scriptblock]::Create($JoinDomainSBAsString)

        $InvCmdJoinDomainSplatParams = @{
            ComputerName    = $args[0]
            Credential      = $args[1]
            ScriptBlock     = $JoinDomainSB
            ArgumentList    = $args[2],$args[3],$args[4],$args[5]
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

        $JoinSubCAJobName = NewUniqueString -PossibleNewUniqueString "JoinSubCA" -ArrayOfStrings $(Get-Job).Name

        $JoinSubCAArgList = @(
            $IPofServerToBeSubCA
            $PSRemotingCredentials
            $IPofDomainController
            $DesiredHostNameSubCA
            $ExistingDomain
            $DomainAdminCredentials
        )
        $JoinSubCAJobSplatParams = @{
            Name            = $JoinSubCAJobName
            Scriptblock     = $JoinDomainJobSB
            ArgumentList    = $JoinSubCAArgList
        }
        $JoinSubCAJobInfo = Start-Job @JoinSubCAJobSplatParams
        
        $JoinSubCAResult = Wait-Job -Job $JoinSubCAJobInfo | Receive-Job

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

    $NextHop = $(Get-NetRoute -AddressFamily IPv4 | Where-Object {$_.NextHop -ne "0.0.0.0"} | Sort-Object RouteMetric)[0].NextHop
    $PrimaryIP = $(Find-NetRoute -RemoteIPAddress $NextHop | Where-Object {$($_ | Get-Member).Name -contains "IPAddress"}).IPAddress

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

    $FunctionsForSBUse = @(
        ${Function:FixNTVirtualMachinesPerms}.Ast.Extent.Text 
        ${Function:GetDomainController}.Ast.Extent.Text
        ${Function:GetElevation}.Ast.Extent.Text
        ${Function:GetFileLockProcess}.Ast.Extent.Text
        ${Function:GetNativePath}.Ast.Extent.Text
        ${Function:GetVSwitchAllRelatedInfo}.Ast.Extent.Text
        ${Function:InstallFeatureDism}.Ast.Extent.Text
        ${Function:InstallHyperVFeatures}.Ast.Extent.Text
        ${Function:NewUniqueString}.Ast.Extent.Text
        ${Function:PauseForWarning}.Ast.Extent.Text
        ${Function:ResolveHost}.Ast.Extent.Text
        ${Function:TestIsValidIPAddress}.Ast.Extent.Text
        ${Function:UnzipFile}.Ast.Extent.Text
        ${Function:Create-TwoTierPKI}.Ast.Extent.Text
        ${Function:Deploy-HyperVVagrantBoxManually}.Ast.Extent.Text
        ${Function:Generate-Certificate}.Ast.Extent.Text
        ${Function:Get-DSCEncryptionCert}.Ast.Extent.Text
        ${Function:Get-VagrantBoxManualDownload}.Ast.Extent.Text
        ${Function:Manage-HyperVVM}.Ast.Extent.Text
        ${Function:New-DomainController}.Ast.Extent.Text
        ${Function:New-RootCA}.Ast.Extent.Text
        ${Function:New-SelfSignedCertificateEx}.Ast.Extent.Text
        ${Function:New-SubordinateCA}.Ast.Extent.Text
        ${Function:Create-Domain}.Ast.Extent.Text
        ${Function:Create-RootCA}.Ast.Extent.Text
        ${Function:Create-SubordinateCA}.Ast.Extent.Text
    )

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
        $LocalDrives = Get-WmiObject Win32_LogicalDisk | Where-Object {$_.Drivetype -eq 3} | foreach {Get-PSDrive $_.DeviceId[0] -ErrorAction SilentlyContinue}
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
            if (!$(Test-Path "$VMStorageDirectory\BoxDownloads\$($BoxFileItem.BaseName)")) {
                $null = New-Item -ItemType Directory -Path "$VMStorageDirectory\BoxDownloads\$($BoxFileItem.BaseName)"
            }

            # Extract the .box File
            Push-Location "$VMStorageDirectory\BoxDownloads\$($BoxFileItem.BaseName)"
            while ([bool]$(GetFileLockProcess -FilePath $BoxFilePath -ErrorAction SilentlyContinue)) {
                Write-Host "$BoxFilePath is currently being used by another process...Waiting for it to become available"
                Start-Sleep -Seconds 5
            }
            try {
                $null = & $TarCmd -xzvf $BoxFilePath 2>&1
            }
            catch {
                Write-Error $_
                #Remove-Item $BoxFilePath -Force
                $global:FunctionResult = "1"
                return
            }
            Pop-Location

            $DecompressedBoxDir = "$VMStorageDirectory\BoxDownloads\$($BoxFileItem.BaseName)"
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

        $NewVMDeploySBAsString = @"
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

`$env:Path = '$env:Path'

# Load the functions we packed up
`$args | foreach { Invoke-Expression `$_ }

`$DeployBoxSplatParams = @{
    VagrantBox                  = '$Windows2016VagrantBox'
    CPUs                        = 2
    Memory                      = 4096
    VagrantProvider             = "hyperv"
    VMName                      = '$DomainShortName' + "replaceme"
    VMDestinationDirectory      = '$VMStorageDirectory'
    SkipHyperVInstallCheck      = `$True
    CopyDecompressedDirectory   = `$True
}

if (-not [string]::IsNullOrWhiteSpace('$DecompressedBoxDir')) {
    if (`$(Get-Item '$DecompressedBoxDir').PSIsContainer) {
        `$DeployBoxSplatParams.Add("DecompressedBoxDirectory",'$DecompressedBoxDir')
    }
}
if (-not [string]::IsNullOrWhiteSpace('$BoxFilePath')) {
    if (-not `$(Get-Item '$BoxFilePath').PSIsContainer) {
        `$DeployBoxSplatParams.Add("BoxFilePath",'$BoxFilePath')
    }
}

`$DeployBoxResult = Deploy-HyperVVagrantBoxManually @DeployBoxSplatParams
`$DeployBoxResult
"@

        if ($NewDomain -and !$IPofServerToBeDomainController) {
            $DomainShortName = $($NewDomain -split "\.")[0]
            Write-Host "Deploying New Domain Controller VM '$DomainShortName`DC1'..."

            $NewDCVMDeployJobName = NewUniqueString -PossibleNewUniqueString "NewDCVM" -ArrayOfStrings $(Get-Job).Name

            $UpdatedDeployVMSBString = $NewVMDeploySBAsString -replace 'replaceme','DC1'
            $NewVMDeploySB = [scriptblock]::Create($UpdatedDeployVMSBString)

            $NewDCVMDeployJobSplatParams = @{
                Name            = $NewDCVMDeployJobName
                Scriptblock     = $NewVMDeploySB
                ArgumentList    = $FunctionsForSBUse
            }
            $NewDCVMDeployJobInfo = Start-Job @NewDCVMDeployJobSplatParams
        }
        if (!$IPofServerToBeRootCA -and !$DCIsRootCA) {
            if ($NewDomain) {
                $DomainShortName = $($NewDomain -split "\.")[0]
            }
            if ($ExistingDomain) {
                $DomainShortName = $($ExistingDomain -split "\.")[0]
            }
            Write-Host "Deploying New Root CA VM '$DomainShortName`RootCA'..."

            $NewRootCAVMDeployJobName = NewUniqueString -PossibleNewUniqueString "NewRootCAVM" -ArrayOfStrings $(Get-Job).Name

            $UpdatedDeployVMSBString = $NewVMDeploySBAsString -replace 'replaceme','RootCA'
            $NewVMDeploySB = [scriptblock]::Create($UpdatedDeployVMSBString)

            $NewRootCAVMDeployJobSplatParams = @{
                Name            = $NewRootCAVMDeployJobName
                Scriptblock     = $NewVMDeploySB
                ArgumentList    = $FunctionsForSBUse
            }
            $NewRootCAVMDeployJobInfo = Start-Job @NewRootCAVMDeployJobSplatParams
        }
        if (!$IPofServerToBeSubCA) {
            if ($NewDomain) {
                $DomainShortName = $($NewDomain -split "\.")[0]
            }
            if ($ExistingDomain) {
                $DomainShortName = $($ExistingDomain -split "\.")[0]
            }
            Write-Host "Deploying New Subordinate CA VM '$DomainShortName`SubCA'..."

            $NewSubCAVMDeployJobName = NewUniqueString -PossibleNewUniqueString "NewSubCAVM" -ArrayOfStrings $(Get-Job).Name

            $UpdatedDeployVMSBString = $NewVMDeploySBAsString -replace 'replaceme','SubCA'
            $NewVMDeploySB = [scriptblock]::Create($UpdatedDeployVMSBString)

            $NewSubCAVMDeployJobSplatParams = @{
                Name            = $NewSubCAVMDeployJobName
                Scriptblock     = $NewVMDeploySB
                ArgumentList    = $FunctionsForSBUse
            }
            $NewSubCAVMDeployJobInfo = Start-Job @NewSubCAVMDeployJobSplatParams
        }

        if ($NewDomain -and !$IPofServerToBeDomainController) {
            $NewDCVMDeployResult = Wait-Job -Job $NewDCVMDeployJobInfo | Receive-Job

            while (![bool]$(Get-VM -Name "$DomainShortName`DC1" -ErrorAction SilentlyContinue)) {
                Write-Host "Waiting for $DomainShortName`DC1 VM to be deployed..."
                Start-Sleep -Seconds 15
            }

            $IPofServerToBeDomainController = $NewDCVMDeployResult.VMIPAddress
            if (!$IPofServerToBeDomainController) {
                $IPofServerToBeDomainController = $(Get-VM -Name "$DomainShortName`DC1").NetworkAdpaters.IPAddresses | Where-Object {TestIsValidIPAddress -IPAddress $_}
            }
        }
        if (!$IPofServerToBeRootCA) {
            if ($DCIsRootCA) {
                $IPofServerToBeRootCA = $IPofServerToBeDomainController
            }

            if (!$DCIsRootCA) {
                $NewRootCAVMDeployResult = Wait-Job -Job $NewRootCAVMDeployJobInfo | Receive-Job
                $IPofServerToBeRootCA = $NewRootCAVMDeployResult.VMIPAddress
                
                while (![bool]$(Get-VM -Name "$DomainShortName`RootCA" -ErrorAction SilentlyContinue)) {
                    Write-Host "Waiting for $DomainShortName`RootCA VM to be deployed..."
                    Start-Sleep -Seconds 15
                }

                if (!$IPofServerToBeRootCA) {
                    $IPofServerToBeRootCA = $(Get-VM -Name "$DomainShortName`RootCA").NetworkAdpaters.IPAddresses | Where-Object {TestIsValidIPAddress -IPAddress $_}
                }
            }
        }
        if (!$IPofServerToBeSubCA) {
            $NewSubCAVMDeployResult = Wait-Job -Job $NewSubCAVMDeployJobInfo | Receive-Job
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
        if (!$(TestIsValidIPAddress -IPAddress $IPofServerToBeDomainController)) {
            $null = $VMsNotReportingIP.Add("$DomainShortName`DC1")
        }
        if (!$(TestIsValidIPAddress -IPAddress $IPofServerToBeRootCA)) {
            $null = $VMsNotReportingIP.Add("$DomainShortName`RootCA")
        }
        if (!$(TestIsValidIPAddress -IPAddress $IPofServerToBeSubCA)) {
            $null = $VMsNotReportingIP.Add("$DomainShortName`SubCA")
        }

        if ($VMsNotReportingIP.Count -gt 0) {
            Write-Error "The following VMs did NOT report thier IP Addresses within 30 minutes:`n$($VMsNotReportingIP -join "`n")`nHalting!"
            $global:FunctionResult = "1"
            return
        }

        Write-Host "Finished Deploying New VMs..."

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
            $null = Get-NetConnectionProfile | Where-Object {$_.NetworkCategory -eq 'Public'} | Set-NetConnectionProfile -NetworkCategory 'Private'

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
                        Write-Error "Unable to create new PSSession to '$PSSessionName' using account '$($PSRemotingCredentials.UserName)'! Halting!"
                        $global:FunctionResult = "1"
                        $DCPSRemotingFailure
                        return
                    }
                }
                $Counter++
            }
        }
        if ($DCPSRemotingFailure) {
            Write-Host "Tried to remote into DC1 with the following parameters:"
            $IPofServerToBeDomainController
            $PSRemotingCredentials
            $global:FunctionResult = "1"
            return
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
                    Write-Error "Unable to create new PSSession to '$PSSessionName' using account '$($PSRemotingCredentials.UserName)'! Halting!"
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
                    Write-Error "Unable to create new PSSession to '$PSSessionName' using account '$($PSRemotingCredentials.UserName)'! Halting!"
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

            Write-Host "Splat Params for Create-Domain are:" -ForegroundColor Yellow
            $CreateDCSplatParams
        }

        $CreateRootCASplatParams.Add("IPofServerToBeRootCA",$IPofServerToBeRootCA)
        $CreateRootCASplatParams.Add("IPofDomainController",$IPofServerToBeDomainController)
        $CreateRootCASplatParams.Add("ExistingDomain",$FinalDomainName)
        Write-Host "Splat Params for Create-RootCA are:" -ForegroundColor Yellow
        $CreateRootCASplatParams

        $CreateSubCASplatParams.Add("IPofServerToBeSubCA",$IPofServerToBeSubCA)
        $CreateSubCASplatParams.Add("IPofDomainController",$IPofServerToBeDomainController)
        $CreateSubCASplatParams.Add("IPofRootCA",$IPofServerToBeRootCA)
        $CreateSubCASplatParams.Add("ExistingDomain",$FinalDomainName)
        Write-Host "Splat Params for Create-SubordinateCA are:" -ForegroundColor Yellow
        $CreateSubCASplatParams

        
        #endregion >> Deploy New VMs
    }

    #region >> Create the Services

    # Can't Invoke-Parallel because Root CA depends on DC and SubCA Depends on Root CA...
    <#
    $ArrayOfPSObjects = @(
        [pscustomobject]@{
            Purpose             = "ForDC"
            FunctionsForSBUse   = $FunctionsForSBUse
            SplatParams         = $CreateDCSplatParams
        }
        [pscustomobject]@{
            Purpose             = "ForRootCA"
            FunctionsForSBUse   = $FunctionsForSBUse
            SplatParams         = $CreateRootCASplatParams
        }
        [pscustomobject]@{
            Purpose             = "ForSubCA"
            FunctionsForSBUse   = $FunctionsForSBUse
            SplatParams         = $CreateSubCASplatParams
        }
    )

    $ArrayOfPSObjects | Invoke-Parallel {
        # Load the functions we packed up
        foreach ($func in $_.FunctionsForSBUse) { Invoke-Expression $func }
        $SplatParams = $_.SplatParams

        if ($_.Purpose -eq "ForDC") {
            Create-Domain @SplatParams
        }
        if ($_.Purpose -eq "ForRootCA") {
            Create-RootCA @SplatParams
        }
        if ($_.Purpose -eq "ForSubCA") {
            Create-SubCA @SplatParams
        }
    }
    #>
    
    if ($NewDomain) {
        $CreateDCResult = Create-Domain @CreateDCSplatParams
    }

    $CreateRootCAResult = Create-RootCA @CreateRootCASplatParams

    $CreateSubCAResult = Create-SubordinateCA @CreateSubCASplatParams

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
    [CmdletBinding(DefaultParameterSetName='ExternalNetworkVM')]
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
        [int]$Memory = 2048,

        [Parameter(Mandatory=$True)]
        [ValidateSet(1,2)]
        [int]$CPUs = 1,

        [Parameter(Mandatory=$False)]
        [string]$TemporaryDownloadDirectory,

        [Parameter(Mandatory=$False)]
        [switch]$AllowRestarts,

        [Parameter(Mandatory=$False)]
        [switch]$SkipPreDownloadCheck,

        [Parameter(Mandatory=$False)]
        [switch]$SkipHyperVInstallCheck,

        [Parameter(Mandatory=$False)]
        [ValidateSet("Vagrant")]
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
                Write-Output "RestartNeeded"
                $global:FunctionResult = "1"
                return
            }
            else {
                Restart-Computer -Confirm:$False -Force
            }
        }
    }

    if ($($VMDestinationDirectory | Split-Path -Leaf) -eq $VMName) {
        $VMDestinationDirectory = $VMDestinationDirectory | Split-Path -Parent
    }

    if (!$TemporaryDownloadDirectory) {
        $TemporaryDownloadDirectory = "$VMDestinationDirectory\BoxDownloads"
    }

    if ($BoxFilePath -and $DecompressedBoxDirectory) {
        Write-Error "Please use *either* the -BoxFilePath *or* the -DecompressedBoxDirectory parameter (not both)! Halting!"
        $global:FunctionResult = "1"
        return
    }

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
    $NextHop = $(Get-NetRoute -AddressFamily IPv4 | Where-Object {$_.NextHop -ne "0.0.0.0"} | Sort-Object RouteMetric)[0].NextHop
    $PrimaryIP = $(Find-NetRoute -RemoteIPAddress $NextHop | Where-Object {$($_ | Get-Member).Name -contains "IPAddress"}).IPAddress
    $NicInfo = Get-NetIPAddress -IPAddress $PrimaryIP
    $NicAdapter = Get-NetAdapter -InterfaceAlias $NicInfo.InterfaceAlias

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
        while ([bool]$(GetFileLockProcess -FilePath $BoxFilePath -ErrorAction SilentlyContinue)) {
            Write-Host "$BoxFilePath is currently being used by another process...Waiting for it to become available"
            Start-Sleep -Seconds 5
        }
        try {
            $null = & $TarCmd -xzvf $BoxFilePath 2>&1
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
            Rename-Item -Path "$VMDestinationDirectory\$($DecompressedBoxDirectory | Split-Path -Leaf)" -NewName $NewVMName
        }

        # Determine the External vSwitch that is associated with the Host Machine's Primary IP
        $ExternalvSwitches = Get-VMSwitch -SwitchType External
        if ($ExternalvSwitches.Count -gt 1) {
            $NextHop = $(Get-NetRoute -AddressFamily IPv4 | Where-Object {$_.NextHop -ne "0.0.0.0"} | Sort-Object RouteMetric)[0].NextHop
            $PrimaryIP = $(Find-NetRoute -RemoteIPAddress $NextHop | Where-Object {$($_ | Get-Member).Name -contains "IPAddress"}).IPAddress
            $NicInfo = Get-NetIPAddress -IPAddress $PrimaryIP
            $NicAdapter = Get-NetAdapter -InterfaceAlias $NicInfo.InterfaceAlias

            foreach ($vSwitchName in $ExternalvSwitches.Name) {
                $AllRelatedvSwitchInfo = GetvSwitchAllRelatedInfo -vSwitchName $vSwitchName -WarningAction SilentlyContinue
                if ($($NicAdapter.MacAddress -replace "-","") -eq $AllRelatedvSwitchInfo.MacAddress) {
                    $vSwitchToUse = $AllRelatedvSwitchInfo.BasicvSwitchInfo
                }
            }
        }
        elseif ($ExternalvSwitches.Count -eq 0) {
            $null = New-VMSwitch -Name "ToExternal" -NetAdapterName $NicInfo.InterfaceAlias
            $ExternalSwitchCreated = $True
            $vSwitchToUse = Get-VMSwitch -Name "ToExternal"
        }
        else {
            $vSwitchToUse = $ExternalvSwitches[0]
        }

        # Instead of actually importing the VM, it's easier (and more reliable) to just create a new one using the existing
        # .vhd/.vhdx so we don't have to deal with potential Hyper-V Version Incompatibilities

        $SwitchName = $vSwitchToUse.Name
        if ($VagrantBox -match "Win|Windows") {
            $VMGen = 2
        }
        else {
            $VMGen = 1
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
        #FixNTVirtualMachinesPerms -DirectoryPath $VMDestinationDirectory
        Write-Host "Starting VM..."
        #Start-VM -Name $NewVMName
        $StartVMOutput = Manage-HyperVVM -VMName $NewVMName -Start
    }
    catch {
        Write-Error $_
        
        # Cleanup
        #Remove-Item $BoxFilePath -Force
        Remove-Item $DownloadedVMDir -Recurse -Force
        
        if ($(Get-VM).Name -contains $NewVMName) {
            $null = Manage-HyperVVM -VMName $NewVMname -Destroy

            if (Test-Path $VMFinalLocationDir) {
                Remove-Item $VMFinalLocationDir -Recurse -Force
            }
        }
        if ($ExternalSwitchCreated) {
            Remove-VMSwitch "ToExternal" -Force -ErrorAction SilentlyContinue
        }

        $global:FunctionResult = "1"
        return
    }

    # Wait for up to 30 minutes for the new VM to report its IP Address
    $NewVMIP = $(Get-VM -Name $NewVMName).NetworkAdapters.IPAddresses | Where-Object {TestIsValidIPAddress -IPAddress $_}
    $Counter = 0
    while (!$NewVMIP -or $Counter -le 30) {
        Write-Host "Waiting for VM $NewVMName to report its IP Address..."
        Start-Sleep -Seconds 60
        $NewVMIP = $(Get-VM -Name $NewVMName).NetworkAdapters.IPAddresses | Where-Object {TestIsValidIPAddress -IPAddress $_}
        $Counter++
    }
    if (!$NewVMIP) {
        $NewVMIP = "<$NewVMName`IPAddress>"
    }

    if ($VagrantBox -notmatch "Win|Windows") {
        if (!$(Test-Path "$HOME\.ssh")) {
            New-Item -ItemType Directory -Path "$HOME\.ssh"
        }
        if (!$(Test-Path "$HOME\.ssh\vagrant_unsecure_private_key")) {
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/hashicorp/vagrant/master/keys/vagrant" -OutFile "$HOME\.ssh\vagrant_unsecure_private_key"
        }
        if (!$(Test-Path "$HOME\.ssh\vagrant_unsecure_public_key.pub")) {
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/hashicorp/vagrant/master/keys/vagrant.pub" -OutFile "$HOME\.ssh\vagrant_unsecure_public_key.pub"
        }

        if (!$(Test-Path "$HOME\.ssh\vagrant_unsecure_private_key")) {
            Write-Warning "There was a problem downloading the Unsecure Vagrant Private Key! You must use the Hyper-V Console with username/password vagrant/vagrant!"
        }
        if (!$(Test-Path "$HOME\.ssh\vagrant_unsecure_public_key.pub")) {
            Write-Warning "There was a problem downloading the Unsecure Vagrant Public Key! You must use the Hyper-V Console with username/password vagrant/vagrant!"
        }
        
        Write-Host "To login to the Vagrant VM, use 'ssh -i `"$HOME\.ssh\vagrant_unsecure_private_key`" vagrant@$NewVMIP' OR use the Hyper-V Console GUI with username/password vagrant/vagrant"
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
            [switch]$AllowRestart
        )
    
        Write-Host "Please wait..."
    
        if (!$(Get-Module -ListAvailable -Name ActiveDirectory)) {
            $OSInfo = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
            $OSCimInfo = Get-CimInstance Win32_OperatingSystem
            $OSArchitecture = $OSCimInfo.OSArchitecture
    
            if ([version]$OSCimInfo.Version -lt [version]"6.3") {
                Write-Error "This function only handles RSAT Installation for Windows 8.1 and higher! Halting!"
                $global:FunctionResult = "1"
                return
            }
            
            if ($OSInfo.ProductName -notlike "*Server*") {
                if (![bool]$(Get-WmiObject -query 'select * from win32_quickfixengineering' | Where-Object {$_.HotFixID -eq 'KB958830' -or $_.HotFixID -eq 'KB2693643'})) {
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
                        if ([int]$OSInfo.ReleaseId -ge 1709) {
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
                Import-Module ServerManager
                if (!$(Get-WindowsFeature RSAT).Installed) {
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

    $DomainPrefix = ((gwmi Win32_ComputerSystem).Domain).Split(".") | Select-Object -Index 0
    $DomainSuffix = ((gwmi Win32_ComputerSystem).Domain).Split(".") | Select-Object -Index 1
    $Hostname = (gwmi Win32_ComputerSystem).Name
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
            [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
            $OpenSSLWinBinariesUrl = "http://wiki.overbyte.eu/wiki/index.php/ICS_Download"
            $IWRResult = Invoke-WebRequest -Uri $OpenSSLWinBinariesUrl -UseBasicParsing
            $LatestOpenSSLWinBinaryUrl = $($IWRResult.Links | Where-Object {$_.OuterHTML -match "win64\.zip"})[0].href
            $OutputFileName = $($LatestOpenSSLWinBinaryUrl -split '/')[-1]
            $OutputFilePath = "$HOME\Downloads\$OutputFileName"
            Invoke-WebRequest -Uri $LatestOpenSSLWinBinaryUrl -OutFile $OutputFilePath

            if (!$(Test-Path "$HOME\Downloads\$OutputFileName")) {
                Write-Error "Problem downloading the latest OpenSSL Windows Binary from $LatestOpenSSLWinBinaryUrl ! Halting!"
                $global:FunctionResult = "1"
                return
            }

            $OutputFileItem = Get-Item $OutputFilePath
            $ExpansionDirectory = $OutputFileItem.Directory.FullName + "\" + $OutputFileItem.BaseName
            if (!$(Test-Path $ExpansionDirectory)) {
                $null = New-Item -ItemType Directory -Path $ExpansionDirectory -Force
            }
            else {
                Remove-Item "$ExpansionDirectory\*" -Recurse -Force
            }

            $null = Expand-Archive -Path "$HOME\Downloads\$OutputFileName" -DestinationPath $ExpansionDirectory -Force

            # Add $ExpansionDirectory to $env:Path
            $CurrentEnvPathArray = $env:Path -split ";"
            if ($CurrentEnvPathArray -notcontains $ExpansionDirectory) {
                # Place $ExpansionDirectory at start so latest openssl.exe get priority
                $env:Path = "$ExpansionDirectory;$env:Path"
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
                    throw "$env:ComputerName must be restarted post RSAT install! Please restart at your earliest convenience and try the Generate-Certificate funciton again."
                }
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
        if (!$(Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-Error "Problem installing the ActiveDirectory PowerShell Module (via RSAT installation). Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($(Get-Module).Name -notcontains "ActiveDirectory") {
            try {
                Import-Module ActiveDirectory -ErrorAction Stop
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
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
            Write-Host "Successfully contacted the Issuing Certificate Authority: $IssuingCertAuth"
        }
        else {
            Write-Host "Cannot contact the Issuing Certificate Authority: $IssuingCertAuth. Halting!"
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
                $CertificateTemplateLDAPObject = Get-ADObject -SearchBase $LDAPSearchBase -Filter {cn -eq $cnForBasisTemplate}
                $AllCertificateTemplateProperties = Get-ADObject -SearchBase $LDAPSearchBase -Filter {cn -eq $cnForBasisTemplate} -Properties *
                $displayNameForBasisTemplate = $AllCertificateTemplateProperties.DisplayName
            }
            if ($ValidCertificateTemplatesByDisplayName -contains $BasisTemplate) {
                $displayNameForBasisTemplate = $BasisTemplate
                $CertificateTemplateLDAPObject = Get-ADObject -SearchBase $LDAPSearchBase -Filter {displayName -eq $displayNameForBasisTemplate}
                $AllCertificateTemplateProperties = Get-ADObject -SearchBase $LDAPSearchBase -Filter {displayName -eq $displayNameForBasisTemplate} -Properties *
                $cnForBasisTemplate = $AllCertificateTemplateProperties.CN
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
    $GenerateCertificateFileOutputHash.Add("CertificateRequestConfigFile", "$CertificateRequestConfigFile")
    $GenerateCertificateFileOutputHash.Add("CertificateRequestFile", "$CertificateRequestFile")
    $GenerateCertificateFileOutputHash.Add("CertFileOut", "$CertFileOut")
    if ($MachineKeySet -eq "FALSE") {
        $GenerateCertificateFileOutputHash.Add("PFXFileOut", "$PFXFileOut")
    }
    if (!$ADCSWebEnrollmentUrl) {
        $CertUtilResponseFile = (Get-Item "$CertGenWorking\*.rsp").Name
        $GenerateCertificateFileOutputHash.Add("CertUtilResponseFile", "$CertUtilResponseFile")

        $GenerateCertificateFileOutputHash.Add("CertificateChainOut", "$CertificateChainOut")
    }
    if ($ADCSWebEnrollmentUrl) {
        $GenerateCertificateFileOutputHash.Add("CertADCSWebResponseOutFile", "$CertADCSWebResponseOutFile")
    }
    if ($UseOpenSSL -eq "Yes") {
        $GenerateCertificateFileOutputHash.Add("AllPublicKeysInChainOut", "$AllPublicKeysInChainOut")

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
                $GenerateCertificateFileOutputHash.Add("RootCAPublicCertFile", "$RootCAPublicCertFile")
            }
            if ($SubjectType -eq "CA" -and $RootCertFlag.Matches.Success -ne $true) {
                $IntermediateCAPublicCertFile = $obj1
                $GenerateCertificateFileOutputHash.Add("IntermediateCAPublicCertFile", "$IntermediateCAPublicCertFile")
            }
            if ($SubjectType -eq "End Entity" -and $EndPointCNFlag.Matches.Success -eq $true) {
                $EndPointPublicCertFile = $obj1
                $GenerateCertificateFileOutputHash.Add("EndPointPublicCertFile", "$EndPointPublicCertFile")
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
                $GenerateCertificateFileOutputHash.Add("RootCAPublicCertFile", "$RootCAPublicCertFile")
            }
        }
        foreach ($obj1 in $AdditionalPublicKeysArray) {
            $certPrint = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $certPrint.Import("$CertGenWorking\$obj1")
            if ($certPrint.Issuer -eq $RootCASubject -and $certPrint.Subject -ne $RootCASubject) {
                $IntermediateCAPublicCertFile = $obj1
                $IntermediateCASubject = $certPrint.Subject
                $GenerateCertificateFileOutputHash.Add("IntermediateCAPublicCertFile", "$IntermediateCAPublicCertFile")
            }
        }
        foreach ($obj1 in $AdditionalPublicKeysArray) {
            $certPrint = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $certPrint.Import("$CertGenWorking\$obj1")
            if ($certPrint.Issuer -eq $IntermediateCASubject) {
                $EndPointPublicCertFile = $obj1
                $EndPointSubject = $certPrint.Subject
                $GenerateCertificateFileOutputHash.Add("EndPointPublicCertFile", "$EndPointPublicCertFile")
            }
        }
        #>

        $GenerateCertificateFileOutputHash.Add("EndPointProtectedPrivateKey", "$ProtectedPrivateKeyOut")
    }
    if ($StripPrivateKeyOfPassword -eq "Yes" -or $StripPrivateKeyOfPassword -eq "y") {
        $GenerateCertificateFileOutputHash.Add("EndPointUnProtectedPrivateKey", "$UnProtectedPrivateKeyOut")

        # Add UnProtected Private Key to $CertNamevsContentsHash
        $UnProtectedPrivateKeyContent = ((Get-Content $CertGenWorking\$UnProtectedPrivateKeyOut) -join "`n").Trim()
        $CertNamevsContentsHash.Add("EndPointUnProtectedPrivateKey", "$UnProtectedPrivateKeyContent")
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
        [ValidateSet("Vagrant")]
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
        $VersionsInOrderOfRelease = $($VagrantBoxVersionPrep.Links | Where-Object {$_.href -match "versions"}).innerText -replace 'v',''
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
        Function to control parallel processing using runspaces

    .DESCRIPTION
        Function to control parallel processing using runspaces

            Note that each runspace will not have access to variables and commands loaded in your session or in other runspaces by default.
            This behaviour can be changed with parameters.

    .PARAMETER ScriptFile
        File to run against all input objects.  Must include parameter to take in the input object, or use $args.  Optionally, include parameter to take in parameter.  Example: C:\script.ps1

    .PARAMETER ScriptBlock
        Scriptblock to run against all computers.

        You may use $Using:<Variable> language in PowerShell 3 and later.

            The parameter block is added for you, allowing behaviour similar to foreach-object:
                Refer to the input object as $_.
                Refer to the parameter parameter as $parameter

    .PARAMETER InputObject
        Run script against these specified objects.

    .PARAMETER Parameter
        This object is passed to every script block.  You can use it to pass information to the script block; for example, the path to a logging folder

            Reference this object as $parameter if using the scriptblock parameterset.

    .PARAMETER ImportVariables
        If specified, get user session variables and add them to the initial session state

    .PARAMETER ImportFunctions
        If specified, get loaded functions, add them to the initial session state

    .PARAMETER ImportModules
        If specified, get loaded modules and pssnapins, add them to the initial session state

    .PARAMETER Throttle
        Maximum number of threads to run at a single time.

    .PARAMETER SleepTimer
        Milliseconds to sleep after checking for completed runspaces and in a few other spots.  I would not recommend dropping below 200 or increasing above 500

    .PARAMETER RunspaceTimeout
        Maximum time in seconds a single thread can run.  If execution of your code takes longer than this, it is disposed.  Default: 0 (seconds)

        WARNING:  Using this parameter requires that maxQueue be set to throttle (it will be by default) for accurate timing.  Details here:
        http://gallery.technet.microsoft.com/Run-Parallel-Parallel-377fd430

    .PARAMETER NoCloseOnTimeout
        Do not dispose of timed out tasks or attempt to close the runspace if threads have timed out. This will prevent the script from hanging in certain situations where threads become non-responsive, at the expense of leaking memory within the PowerShell host.

    .PARAMETER MaxQueue
        Maximum number of powershell instances to add to runspace pool.  If this is higher than $throttle, $timeout will be inaccurate

        If this is equal or less than throttle, there will be a performance impact

        The default value is $throttle times 3, if $runspaceTimeout is not specified
        The default value is $throttle, if $runspaceTimeout is specified

    .PARAMETER LogFile
        Path to a file where we can log results, including run time for each thread, whether it completes, completes with errors, or times out.

    .PARAMETER AppendLog
        Append to existing log

    .PARAMETER Quiet
        Disable progress bar

    .EXAMPLE
        Each example uses Test-ForPacs.ps1 which includes the following code:
            param($computer)

            if(test-connection $computer -count 1 -quiet -BufferSize 16){
                $object = [pscustomobject] @{
                    Computer=$computer;
                    Available=1;
                    Kodak=$(
                        if((test-path "\\$computer\c$\users\public\desktop\Kodak Direct View Pacs.url") -or (test-path "\\$computer\c$\documents and settings\all users\desktop\Kodak Direct View Pacs.url") ){"1"}else{"0"}
                    )
                }
            }
            else{
                $object = [pscustomobject] @{
                    Computer=$computer;
                    Available=0;
                    Kodak="NA"
                }
            }

            $object

    .EXAMPLE
        Invoke-Parallel -scriptfile C:\public\Test-ForPacs.ps1 -inputobject $(get-content C:\pcs.txt) -runspaceTimeout 10 -throttle 10

            Pulls list of PCs from C:\pcs.txt,
            Runs Test-ForPacs against each
            If any query takes longer than 10 seconds, it is disposed
            Only run 10 threads at a time

    .EXAMPLE
        Invoke-Parallel -scriptfile C:\public\Test-ForPacs.ps1 -inputobject c-is-ts-91, c-is-ts-95

            Runs against c-is-ts-91, c-is-ts-95 (-computername)
            Runs Test-ForPacs against each

    .EXAMPLE
        $stuff = [pscustomobject] @{
            ContentFile = "windows\system32\drivers\etc\hosts"
            Logfile = "C:\temp\log.txt"
        }

        $computers | Invoke-Parallel -parameter $stuff {
            $contentFile = join-path "\\$_\c$" $parameter.contentfile
            Get-Content $contentFile |
                set-content $parameter.logfile
        }

        This example uses the parameter argument.  This parameter is a single object.  To pass multiple items into the script block, we create a custom object (using a PowerShell v3 language) with properties we want to pass in.

        Inside the script block, $parameter is used to reference this parameter object.  This example sets a content file, gets content from that file, and sets it to a predefined log file.

    .EXAMPLE
        $test = 5
        1..2 | Invoke-Parallel -ImportVariables {$_ * $test}

        Add variables from the current session to the session state.  Without -ImportVariables $Test would not be accessible

    .EXAMPLE
        $test = 5
        1..2 | Invoke-Parallel {$_ * $Using:test}

        Reference a variable from the current session with the $Using:<Variable> syntax.  Requires PowerShell 3 or later. Note that -ImportVariables parameter is no longer necessary.

    .FUNCTIONALITY
        PowerShell Language

    .NOTES
        Credit to Boe Prox for the base runspace code and $Using implementation
            http://learn-powershell.net/2012/05/10/speedy-network-information-query-using-powershell/
            http://gallery.technet.microsoft.com/scriptcenter/Speedy-Network-Information-5b1406fb#content
            https://github.com/proxb/PoshRSJob/

        Credit to T Bryce Yehl for the Quiet and NoCloseOnTimeout implementations

        Credit to Sergei Vorobev for the many ideas and contributions that have improved functionality, reliability, and ease of use

    .LINK
        https://github.com/RamblingCookieMonster/Invoke-Parallel
#>
function Invoke-Parallel {
    [cmdletbinding(DefaultParameterSetName='ScriptBlock')]
    Param (
        [Parameter(Mandatory=$false,position=0,ParameterSetName='ScriptBlock')]
        [System.Management.Automation.ScriptBlock]$ScriptBlock,

        [Parameter(Mandatory=$false,ParameterSetName='ScriptFile')]
        [ValidateScript({Test-Path $_ -pathtype leaf})]
        $ScriptFile,

        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [Alias('CN','__Server','IPAddress','Server','ComputerName')]
        [PSObject]$InputObject,

        [PSObject]$Parameter,

        [switch]$ImportVariables,
        [switch]$ImportModules,
        [switch]$ImportFunctions,

        [int]$Throttle = 20,
        [int]$SleepTimer = 200,
        [int]$RunspaceTimeout = 0,
        [switch]$NoCloseOnTimeout = $false,
        [int]$MaxQueue,

        [validatescript({Test-Path (Split-Path $_ -parent)})]
        [switch] $AppendLog = $false,
        [string]$LogFile,

        [switch] $Quiet = $false
    )
    begin {
        #No max queue specified?  Estimate one.
        #We use the script scope to resolve an odd PowerShell 2 issue where MaxQueue isn't seen later in the function
        if( -not $PSBoundParameters.ContainsKey('MaxQueue') ) {
            if($RunspaceTimeout -ne 0){ $script:MaxQueue = $Throttle }
            else{ $script:MaxQueue = $Throttle * 3 }
        }
        else {
            $script:MaxQueue = $MaxQueue
        }
        $ProgressId = Get-Random
        Write-Verbose "Throttle: '$throttle' SleepTimer '$sleepTimer' runSpaceTimeout '$runspaceTimeout' maxQueue '$maxQueue' logFile '$logFile'"

        #If they want to import variables or modules, create a clean runspace, get loaded items, use those to exclude items
        if ($ImportVariables -or $ImportModules -or $ImportFunctions) {
            $StandardUserEnv = [powershell]::Create().addscript({

                #Get modules, snapins, functions in this clean runspace
                $Modules = Get-Module | Select-Object -ExpandProperty Name
                $Snapins = Get-PSSnapin | Select-Object -ExpandProperty Name
                $Functions = Get-ChildItem function:\ | Select-Object -ExpandProperty Name

                #Get variables in this clean runspace
                #Called last to get vars like $? into session
                $Variables = Get-Variable | Select-Object -ExpandProperty Name

                #Return a hashtable where we can access each.
                @{
                    Variables   = $Variables
                    Modules     = $Modules
                    Snapins     = $Snapins
                    Functions   = $Functions
                }
            }).invoke()[0]

            if ($ImportVariables) {
                #Exclude common parameters, bound parameters, and automatic variables
                Function _temp {[cmdletbinding(SupportsShouldProcess=$True)] param() }
                $VariablesToExclude = @( (Get-Command _temp | Select-Object -ExpandProperty parameters).Keys + $PSBoundParameters.Keys + $StandardUserEnv.Variables )
                Write-Verbose "Excluding variables $( ($VariablesToExclude | Sort-Object ) -join ", ")"

                # we don't use 'Get-Variable -Exclude', because it uses regexps.
                # One of the veriables that we pass is '$?'.
                # There could be other variables with such problems.
                # Scope 2 required if we move to a real module
                $UserVariables = @( Get-Variable | Where-Object { -not ($VariablesToExclude -contains $_.Name) } )
                Write-Verbose "Found variables to import: $( ($UserVariables | Select-Object -expandproperty Name | Sort-Object ) -join ", " | Out-String).`n"
            }
            if ($ImportModules) {
                $UserModules = @( Get-Module | Where-Object {$StandardUserEnv.Modules -notcontains $_.Name -and (Test-Path $_.Path -ErrorAction SilentlyContinue)} | Select-Object -ExpandProperty Path )
                $UserSnapins = @( Get-PSSnapin | Select-Object -ExpandProperty Name | Where-Object {$StandardUserEnv.Snapins -notcontains $_ } )
            }
            if($ImportFunctions) {
                $UserFunctions = @( Get-ChildItem function:\ | Where-Object { $StandardUserEnv.Functions -notcontains $_.Name } )
            }
        }

        #region functions
            Function Get-RunspaceData {
                [cmdletbinding()]
                param( [switch]$Wait )
                #loop through runspaces
                #if $wait is specified, keep looping until all complete
                Do {
                    #set more to false for tracking completion
                    $more = $false

                    #Progress bar if we have inputobject count (bound parameter)
                    if (-not $Quiet) {
                        Write-Progress -Id $ProgressId -Activity "Running Query" -Status "Starting threads"`
                            -CurrentOperation "$startedCount threads defined - $totalCount input objects - $script:completedCount input objects processed"`
                            -PercentComplete $( Try { $script:completedCount / $totalCount * 100 } Catch {0} )
                    }

                    #run through each runspace.
                    Foreach($runspace in $runspaces) {

                        #get the duration - inaccurate
                        $currentdate = Get-Date
                        $runtime = $currentdate - $runspace.startTime
                        $runMin = [math]::Round( $runtime.totalminutes ,2 )

                        #set up log object
                        $log = "" | Select-Object Date, Action, Runtime, Status, Details
                        $log.Action = "Removing:'$($runspace.object)'"
                        $log.Date = $currentdate
                        $log.Runtime = "$runMin minutes"

                        #If runspace completed, end invoke, dispose, recycle, counter++
                        If ($runspace.Runspace.isCompleted) {

                            $script:completedCount++

                            #check if there were errors
                            if($runspace.powershell.Streams.Error.Count -gt 0) {
                                #set the logging info and move the file to completed
                                $log.status = "CompletedWithErrors"
                                Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                                foreach($ErrorRecord in $runspace.powershell.Streams.Error) {
                                    Write-Error -ErrorRecord $ErrorRecord
                                }
                            }
                            else {
                                #add logging details and cleanup
                                $log.status = "Completed"
                                Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                            }

                            #everything is logged, clean up the runspace
                            $runspace.powershell.EndInvoke($runspace.Runspace)
                            $runspace.powershell.dispose()
                            $runspace.Runspace = $null
                            $runspace.powershell = $null
                        }
                        #If runtime exceeds max, dispose the runspace
                        ElseIf ( $runspaceTimeout -ne 0 -and $runtime.totalseconds -gt $runspaceTimeout) {
                            $script:completedCount++
                            $timedOutTasks = $true

                            #add logging details and cleanup
                            $log.status = "TimedOut"
                            Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                            Write-Error "Runspace timed out at $($runtime.totalseconds) seconds for the object:`n$($runspace.object | out-string)"

                            #Depending on how it hangs, we could still get stuck here as dispose calls a synchronous method on the powershell instance
                            if (!$noCloseOnTimeout) { $runspace.powershell.dispose() }
                            $runspace.Runspace = $null
                            $runspace.powershell = $null
                            $completedCount++
                        }

                        #If runspace isn't null set more to true
                        ElseIf ($runspace.Runspace -ne $null ) {
                            $log = $null
                            $more = $true
                        }

                        #log the results if a log file was indicated
                        if($logFile -and $log) {
                            ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1] | out-file $LogFile -append
                        }
                    }

                    #Clean out unused runspace jobs
                    $temphash = $runspaces.clone()
                    $temphash | Where-Object { $_.runspace -eq $Null } | ForEach-Object {
                        $Runspaces.remove($_)
                    }

                    #sleep for a bit if we will loop again
                    if($PSBoundParameters['Wait']){ Start-Sleep -milliseconds $SleepTimer }

                #Loop again only if -wait parameter and there are more runspaces to process
                } while ($more -and $PSBoundParameters['Wait'])

            #End of runspace function
            }
        #endregion functions

        #region Init

            if($PSCmdlet.ParameterSetName -eq 'ScriptFile') {
                $ScriptBlock = [scriptblock]::Create( $(Get-Content $ScriptFile | out-string) )
            }
            elseif($PSCmdlet.ParameterSetName -eq 'ScriptBlock') {
                #Start building parameter names for the param block
                [string[]]$ParamsToAdd = '$_'
                if( $PSBoundParameters.ContainsKey('Parameter') ) {
                    $ParamsToAdd += '$Parameter'
                }

                $UsingVariableData = $Null

                # This code enables $Using support through the AST.
                # This is entirely from  Boe Prox, and his https://github.com/proxb/PoshRSJob module; all credit to Boe!

                if($PSVersionTable.PSVersion.Major -gt 2) {
                    #Extract using references
                    $UsingVariables = $ScriptBlock.ast.FindAll({$args[0] -is [System.Management.Automation.Language.UsingExpressionAst]},$True)

                    If ($UsingVariables) {
                        $List = New-Object 'System.Collections.Generic.List`1[System.Management.Automation.Language.VariableExpressionAst]'
                        ForEach ($Ast in $UsingVariables) {
                            [void]$list.Add($Ast.SubExpression)
                        }

                        $UsingVar = $UsingVariables | Group-Object -Property SubExpression | ForEach-Object {$_.Group | Select-Object -First 1}

                        #Extract the name, value, and create replacements for each
                        $UsingVariableData = ForEach ($Var in $UsingVar) {
                            try {
                                $Value = Get-Variable -Name $Var.SubExpression.VariablePath.UserPath -ErrorAction Stop
                                [pscustomobject]@{
                                    Name = $Var.SubExpression.Extent.Text
                                    Value = $Value.Value
                                    NewName = ('$__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                                    NewVarName = ('__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                                }
                            }
                            catch {
                                Write-Error "$($Var.SubExpression.Extent.Text) is not a valid Using: variable!"
                            }
                        }
                        $ParamsToAdd += $UsingVariableData | Select-Object -ExpandProperty NewName -Unique

                        $NewParams = $UsingVariableData.NewName -join ', '
                        $Tuple = [Tuple]::Create($list, $NewParams)
                        $bindingFlags = [Reflection.BindingFlags]"Default,NonPublic,Instance"
                        $GetWithInputHandlingForInvokeCommandImpl = ($ScriptBlock.ast.gettype().GetMethod('GetWithInputHandlingForInvokeCommandImpl',$bindingFlags))

                        $StringScriptBlock = $GetWithInputHandlingForInvokeCommandImpl.Invoke($ScriptBlock.ast,@($Tuple))

                        $ScriptBlock = [scriptblock]::Create($StringScriptBlock)

                        Write-Verbose $StringScriptBlock
                    }
                }

                $ScriptBlock = $ExecutionContext.InvokeCommand.NewScriptBlock("param($($ParamsToAdd -Join ", "))`r`n" + $Scriptblock.ToString())
            }
            else {
                Throw "Must provide ScriptBlock or ScriptFile"; Break
            }

            Write-Debug "`$ScriptBlock: $($ScriptBlock | Out-String)"
            Write-Verbose "Creating runspace pool and session states"

            #If specified, add variables and modules/snapins to session state
            $sessionstate = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
            if($ImportVariables -and $UserVariables.count -gt 0) {
                foreach($Variable in $UserVariables) {
                    $sessionstate.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Variable.Name, $Variable.Value, $null) )
                }
            }
            if ($ImportModules) {
                if($UserModules.count -gt 0) {
                    foreach($ModulePath in $UserModules) {
                        $sessionstate.ImportPSModule($ModulePath)
                    }
                }
                if($UserSnapins.count -gt 0) {
                    foreach($PSSnapin in $UserSnapins) {
                        [void]$sessionstate.ImportPSSnapIn($PSSnapin, [ref]$null)
                    }
                }
            }
            if($ImportFunctions -and $UserFunctions.count -gt 0) {
                foreach ($FunctionDef in $UserFunctions) {
                    $sessionstate.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $FunctionDef.Name,$FunctionDef.ScriptBlock))
                }
            }

            #Create runspace pool
            $runspacepool = [runspacefactory]::CreateRunspacePool(1, $Throttle, $sessionstate, $Host)
            $runspacepool.Open()

            Write-Verbose "Creating empty collection to hold runspace jobs"
            $Script:runspaces = New-Object System.Collections.ArrayList

            #If inputObject is bound get a total count and set bound to true
            $bound = $PSBoundParameters.keys -contains "InputObject"
            if(-not $bound) {
                [System.Collections.ArrayList]$allObjects = @()
            }

            #Set up log file if specified
            if( $LogFile -and (-not (Test-Path $LogFile) -or $AppendLog -eq $false)){
                New-Item -ItemType file -Path $logFile -Force | Out-Null
                ("" | Select-Object -Property Date, Action, Runtime, Status, Details | ConvertTo-Csv -NoTypeInformation -Delimiter ";")[0] | Out-File $LogFile
            }

            #write initial log entry
            $log = "" | Select-Object -Property Date, Action, Runtime, Status, Details
                $log.Date = Get-Date
                $log.Action = "Batch processing started"
                $log.Runtime = $null
                $log.Status = "Started"
                $log.Details = $null
                if($logFile) {
                    ($log | convertto-csv -Delimiter ";" -NoTypeInformation)[1] | Out-File $LogFile -Append
                }
            $timedOutTasks = $false
        #endregion INIT
    }
    process {
        #add piped objects to all objects or set all objects to bound input object parameter
        if($bound) {
            $allObjects = $InputObject
        }
        else {
            [void]$allObjects.add( $InputObject )
        }
    }
    end {
        #Use Try/Finally to catch Ctrl+C and clean up.
        try {
            #counts for progress
            $totalCount = $allObjects.count
            $script:completedCount = 0
            $startedCount = 0
            foreach($object in $allObjects) {
                #region add scripts to runspace pool
                    #Create the powershell instance, set verbose if needed, supply the scriptblock and parameters
                    $powershell = [powershell]::Create()

                    if ($VerbosePreference -eq 'Continue') {
                        [void]$PowerShell.AddScript({$VerbosePreference = 'Continue'})
                    }

                    [void]$PowerShell.AddScript($ScriptBlock).AddArgument($object)

                    if ($parameter) {
                        [void]$PowerShell.AddArgument($parameter)
                    }

                    # $Using support from Boe Prox
                    if ($UsingVariableData) {
                        Foreach($UsingVariable in $UsingVariableData) {
                            Write-Verbose "Adding $($UsingVariable.Name) with value: $($UsingVariable.Value)"
                            [void]$PowerShell.AddArgument($UsingVariable.Value)
                        }
                    }

                    #Add the runspace into the powershell instance
                    $powershell.RunspacePool = $runspacepool

                    #Create a temporary collection for each runspace
                    $temp = "" | Select-Object PowerShell, StartTime, object, Runspace
                    $temp.PowerShell = $powershell
                    $temp.StartTime = Get-Date
                    $temp.object = $object

                    #Save the handle output when calling BeginInvoke() that will be used later to end the runspace
                    $temp.Runspace = $powershell.BeginInvoke()
                    $startedCount++

                    #Add the temp tracking info to $runspaces collection
                    Write-Verbose ( "Adding {0} to collection at {1}" -f $temp.object, $temp.starttime.tostring() )
                    $runspaces.Add($temp) | Out-Null

                    #loop through existing runspaces one time
                    Get-RunspaceData

                    #If we have more running than max queue (used to control timeout accuracy)
                    #Script scope resolves odd PowerShell 2 issue
                    $firstRun = $true
                    while ($runspaces.count -ge $Script:MaxQueue) {
                        #give verbose output
                        if($firstRun) {
                            Write-Verbose "$($runspaces.count) items running - exceeded $Script:MaxQueue limit."
                        }
                        $firstRun = $false

                        #run get-runspace data and sleep for a short while
                        Get-RunspaceData
                        Start-Sleep -Milliseconds $sleepTimer
                    }
                #endregion add scripts to runspace pool
            }
            Write-Verbose ( "Finish processing the remaining runspace jobs: {0}" -f ( @($runspaces | Where-Object {$_.Runspace -ne $Null}).Count) )

            Get-RunspaceData -wait
            if (-not $quiet) {
                Write-Progress -Id $ProgressId -Activity "Running Query" -Status "Starting threads" -Completed
            }
        }
        finally {
            #Close the runspace pool, unless we specified no close on timeout and something timed out
            if ( ($timedOutTasks -eq $false) -or ( ($timedOutTasks -eq $true) -and ($noCloseOnTimeout -eq $false) ) ) {
                Write-Verbose "Closing the runspace pool"
                $runspacepool.close()
            }
            #collect garbage
            [gc]::Collect()
        }
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
        [ValidateSet("Heartbeat","Shutdown","TimeSynch","GuestServiceInterface","KeyValueExchange","VSS")]
        [string[]]$PreferredIntegrationServices = @("Heartbeat","Shutdown","TimeSynch","GuestServiceInterface","KeyValueExchange"),

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

    Write-Output "Script started at $(Get-Date -Format "HH:mm:ss.fff")"

    # Explicitly import the Modules we need for this function
    try {
        Import-Module Microsoft.PowerShell.Utility
        Import-Module Microsoft.PowerShell.Management
        Import-Module Hyper-V
        Import-Module NetAdapter
        Import-Module NetTCPIP

        Import-Module PackageManagement
        Import-Module PowerShellGet
        if ($(Get-Module -ListAvailable).Name -notcontains "NTFSSecurity") {
            Install-Module NTFSSecurity
        }

        try {
            if ($(Get-Module).Name -notcontains "NTFSSecurity") {Import-Module NTFSSecurity}
        }
        catch {
            if ($_.Exception.GetType().FullName -eq "System.Management.Automation.RuntimeException") {
                Write-Verbose "NTFSSecurity Module is already loaded..."
            }
            else {
                throw "There was a problem loading the NTFSSecurity Module! Halting!"
            }
        }
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    Write-Host "Modules loaded at $(Get-Date -Format "HH:mm:ss.fff")"

    # Hard coded for now
    $global:VhdSize = 60*1024*1024*1024  # 60GB

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
    
        $vmSwitch = Hyper-V\Get-VMSwitch $SwitchName -SwitchType Internal -ea SilentlyContinue
        $vmNetAdapter = Hyper-V\Get-VMNetworkAdapter -ManagementOS -SwitchName $SwitchName -ea SilentlyContinue
        if ($vmSwitch -and $vmNetAdapter) {
            Write-Output "Using existing Switch: $SwitchName"
        } else {
            # There seems to be an issue on builds equal to 10586 (and
            # possibly earlier) with the first VMSwitch being created after
            # Hyper-V install causing an error. So on these builds we create
            # Dummy switch and remove it.
            $buildstr = $(Get-WmiObject win32_operatingsystem).BuildNumber
            $buildNumber = [convert]::ToInt32($buildstr, 10)
            if ($buildNumber -le 10586) {
                Write-Output "Enabled workaround for Build 10586 VMSwitch issue"
    
                $fakeSwitch = Hyper-V\New-VMSwitch "DummyDesperatePoitras" -SwitchType Internal -ea SilentlyContinue
                $fakeSwitch | Hyper-V\Remove-VMSwitch -Confirm:$false -Force -ea SilentlyContinue
            }
    
            Write-Output "Creating Switch: $SwitchName..."
    
            Hyper-V\Remove-VMSwitch $SwitchName -Force -ea SilentlyContinue
            Hyper-V\New-VMSwitch $SwitchName -SwitchType Internal -ea SilentlyContinue | Out-Null
            $vmNetAdapter = Hyper-V\Get-VMNetworkAdapter -ManagementOS -SwitchName $SwitchName
    
            Write-Output "Switch created."
        }
    
        # Make sure there are no lingering net adapter
        $netAdapters = Get-NetAdapter | ? { $_.Name.StartsWith("vEthernet ($SwitchName)") }
        if (($netAdapters).Length -gt 1) {
            Write-Output "Disable and rename invalid NetAdapters"
    
            $now = (Get-Date -Format FileDateTimeUniversal)
            $index = 1
            $invalidNetAdapters =  $netAdapters | ? { $_.DeviceID -ne $vmNetAdapter.DeviceId }
    
            foreach ($netAdapter in $invalidNetAdapters) {
                $netAdapter `
                    | Disable-NetAdapter -Confirm:$false -PassThru `
                    | Rename-NetAdapter -NewName "Broken Docker Adapter ($now) ($index)" `
                    | Out-Null
    
                $index++
            }
        }
    
        # Make sure the Switch has the right IP address
        $networkAdapter = Get-NetAdapter | ? { $_.DeviceID -eq $vmNetAdapter.DeviceId }
        if ($networkAdapter | Get-NetIPAddress -IPAddress $switchAddress -ea SilentlyContinue) {
            $networkAdapter | Disable-NetAdapterBinding -ComponentID ms_server -ea SilentlyContinue
            $networkAdapter | Enable-NetAdapterBinding  -ComponentID ms_server -ea SilentlyContinue
            Write-Output "Using existing Switch IP address"
            return
        }
    
        $networkAdapter | Remove-NetIPAddress -Confirm:$false -ea SilentlyContinue
        $networkAdapter | Set-NetIPInterface -Dhcp Disabled -ea SilentlyContinue
        $networkAdapter | New-NetIPAddress -AddressFamily IPv4 -IPAddress $switchAddress -PrefixLength ($SwitchSubnetMaskSize) -ea Stop | Out-Null
        
        $networkAdapter | Disable-NetAdapterBinding -ComponentID ms_server -ea SilentlyContinue
        $networkAdapter | Enable-NetAdapterBinding  -ComponentID ms_server -ea SilentlyContinue
        Write-Output "Set IP address on switch"
    }
    
    function Remove-Switch {
        Write-Output "Destroying Switch $SwitchName..."
    
        # Let's remove the IP otherwise a nasty bug makes it impossible
        # to recreate the vswitch
        $vmNetAdapter = Hyper-V\Get-VMNetworkAdapter -ManagementOS -SwitchName $SwitchName -ea SilentlyContinue
        if ($vmNetAdapter) {
            $networkAdapter = Get-NetAdapter | ? { $_.DeviceID -eq $vmNetAdapter.DeviceId }
            $networkAdapter | Remove-NetIPAddress -Confirm:$false -ea SilentlyContinue
        }
    
        Hyper-V\Remove-VMSwitch $SwitchName -Force -ea SilentlyContinue
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
            Write-Output "Creating VM $VmName..."
            $vm = Hyper-V\New-VM -Name $VmName -Generation $VMGen -NoVHD
            $vm | Hyper-V\Set-VM -AutomaticStartAction Nothing -AutomaticStopAction ShutDown -CheckpointType Production
        }

        <#
        if ($vm.Generation -ne 2) {
                Fatal "VM $VmName is a Generation $($vm.Generation) VM. It should be a Generation 2."
        }
        #>

        if ($vm.State -ne "Off") {
            Write-Output "VM $VmName is $($vm.State). Cannot change its settings."
            return
        }

        Write-Output "Setting CPUs to $CPUs and Memory to $Memory MB"
        $Memory = ([Math]::min($Memory, ($vm | Hyper-V\Get-VMMemory).MaximumPerNumaNode))
        $vm | Hyper-V\Set-VM -MemoryStartupBytes ($Memory*1024*1024) -ProcessorCount $CPUs -StaticMemory

        if (!$NoVhd) {
            $VmVhdFile = Get-Vhd-Root
            $vhd = Get-VHD -Path $VmVhdFile -ea SilentlyContinue
            
            if (!$vhd) {
                Write-Output "Creating dynamic VHD: $VmVhdFile"
                $vhd = New-VHD -ComputerName localhost -Path $VmVhdFile -Dynamic -SizeBytes $global:VhdSize
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
                        FixNTVirtualMachinesPerms -Directorypath $DirectoryThatMayNeedPermissionsFix
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
                        FixNTVirtualMachinesPerms -DirectoryPath $DirectoryThatMayNeedPermissionsFix
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
            <#
            $PublicUserDirectoryPath = "$env:SystemDrive\Users\Public"
            $HyperVConfigDir = "$env:SystemDrive\ProgramData\Microsoft\Windows\Hyper-V"
            [System.Collections.ArrayList]$DirsToPotentiallyFix = @($PublicUserDirectoryPath,$HyperVConfigDir)
            
            foreach ($dir in $DirsToPotentiallyFix) {
                try {
                    FixNTVirtualMachinesPerms -DirectoryPath $dir
                }
                catch {
                    Write-Error $_
                    Write-Error "The FixNTVirtualMachinesPerms function failed! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
            #>

            ## END Try and Update Permissions ##

            if ($vm.HardDrives.Path -ne $VmVhdFile) {
                if ($vm.HardDrives) {
                    Write-Output "Remove existing VHDs"
                    Hyper-V\Remove-VMHardDiskDrive $vm.HardDrives -ea SilentlyContinue
                }

                Write-Output "Attach VHD $VmVhdFile"
                $vm | Hyper-V\Add-VMHardDiskDrive -Path $VmVhdFile
            }
        }

        $vmNetAdapter = $vm | Hyper-V\Get-VMNetworkAdapter
        if (!$vmNetAdapter) {
            Write-Output "Attach Net Adapter"
            $vmNetAdapter = $vm | Hyper-V\Add-VMNetworkAdapter -SwitchName $SwitchName -Passthru
        }

        Write-Output "Connect Switch $SwitchName"
        $vmNetAdapter | Hyper-V\Connect-VMNetworkAdapter -VMSwitch $(Hyper-V\Get-VMSwitch -ComputerName localhost -SwitchName $SwitchName)

        if ($IsoFile) {
            if ($vm.DVDDrives.Path -ne $IsoFile) {
                if ($vm.DVDDrives) {
                    Write-Output "Remove existing DVDs"
                    Hyper-V\Remove-VMDvdDrive $vm.DVDDrives -ea SilentlyContinue
                }

                Write-Output "Attach DVD $IsoFile"
                $vm | Hyper-V\Add-VMDvdDrive -Path $IsoFile
            }
        }

        #$iso = $vm | Hyper-V\Get-VMFirmware | select -ExpandProperty BootOrder | ? { $_.FirmwarePath.EndsWith("Scsi(0,1)") }
        #$vm | Hyper-V\Set-VMFirmware -EnableSecureBoot Off -FirstBootDevice $iso
        ##$vm | Hyper-V\Set-VMComPort -number 1 -Path "\\.\pipe\docker$VmName-com1"

        # Enable only prefered VM integration services
        [System.Collections.ArrayList]$intSvc = @()
        foreach ($integrationService in $PreferredIntegrationServices) {
            switch ($integrationService) {
                'Heartbeat'             { $null = $intSvc.Add("Microsoft:$($vm.Id)\84EAAE65-2F2E-45F5-9BB5-0E857DC8EB47") }
                'Shutdown'              { $null = $intSvc.Add("Microsoft:$($vm.Id)\9F8233AC-BE49-4C79-8EE3-E7E1985B2077") }
                'TimeSynch'             { $null = $intSvc.Add("Microsoft:$($vm.Id)\2497F4DE-E9FA-4204-80E4-4B75C46419C0") }
                'GuestServiceInterface' { $null = $intSvc.Add("Microsoft:$($vm.Id)\6C09BB55-D683-4DA0-8931-C9BF705F6480") }
                'KeyValueExchange'      { $null = $intSvc.Add("Microsoft:$($vm.Id)\2A34B1C2-FD73-4043-8A5B-DD2159BC743F") }
                'VSS'                   { $null = $intSvc.Add("Microsoft:$($vm.Id)\5CED1297-4598-4915-A5FC-AD21BB4D02A4") }
            }
        }
        
        $vm | Hyper-V\Get-VMIntegrationService | ForEach-Object {
            if ($intSvc -contains $_.Id) {
                Hyper-V\Enable-VMIntegrationService $_
                Write-Output "Enabled $($_.Name)"
            }
            else {
                Hyper-V\Disable-VMIntegrationService $_
                Write-Output "Disabled $($_.Name)"
            }
        }
        #$vm | Hyper-V\Disable-VMConsoleSupport
        $vm | Hyper-V\Enable-VMConsoleSupport

        Write-Output "VM created."
    }

    function Remove-HyperVVM {
        Write-Output "Removing VM $VmName..."

        Hyper-V\Remove-VM $VmName -Force -ea SilentlyContinue

        if (!$KeepVolume) {
            $VmVhdFile = Get-Vhd-Root
            Write-Output "Delete VHD $VmVhdFile"
            Remove-Item $VmVhdFile -ea SilentlyContinue
        }
    }

    function Start-HyperVVM {
        Write-Output "Starting VM $VmName..."
        Hyper-V\Start-VM -VMName $VmName
    }

    function Stop-HyperVVM {
        $vms = Hyper-V\Get-VM $VmName -ea SilentlyContinue
        if (!$vms) {
            Write-Output "VM $VmName does not exist"
            return
        }

        foreach ($vm in $vms) {
            Stop-VM-Force($vm)
        }
    }

    function Stop-VM-Force {
        Param($vm)

        if ($vm.State -eq 'Off') {
            Write-Output "VM $VmName is stopped"
            return
        }

        $code = {
            Param($vmId) # Passing the $vm ref is not possible because it will be disposed already

            $vm = Hyper-V\Get-VM -Id $vmId -ea SilentlyContinue
            if (!$vm) {
                Write-Output "VM with Id $vmId does not exist"
                return
            }

            $shutdownService = $vm | Hyper-V\Get-VMIntegrationService -Name Shutdown -ea SilentlyContinue
            if ($shutdownService -and $shutdownService.PrimaryOperationalStatus -eq 'Ok') {
                Write-Output "Shutdown VM $VmName..."
                $vm | Hyper-V\Stop-VM -Confirm:$false -Force -ea SilentlyContinue
                if ($vm.State -eq 'Off') {
                    return
                }
            }

            Write-Output "Turn Off VM $VmName..."
            $vm | Hyper-V\Stop-VM -Confirm:$false -TurnOff -Force -ea SilentlyContinue
        }

        Write-Output "Stopping VM $VmName..."
        $job = Start-Job -ScriptBlock $code -ArgumentList $vm.VMId.Guid
        if (Wait-Job $job -Timeout 20) { Receive-Job $job }
        Remove-Job -Force $job -ea SilentlyContinue

        if ($vm.State -eq 'Off') {
            Write-Output "VM $VmName is stopped"
            return
        }

        # If the VM cannot be stopped properly after the timeout
        # then we have to kill the process and wait till the state changes to "Off"
        for ($count = 1; $count -le 10; $count++) {
            $ProcessID = (Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_ComputerSystem -Filter "Name = '$($vm.Id.Guid)'").ProcessID
            if (!$ProcessID) {
                Write-Output "VM $VmName killed. Waiting for state to change"
                for ($count = 1; $count -le 20; $count++) {
                    if ($vm.State -eq 'Off') {
                        Write-Output "Killed VM $VmName is off"
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

            Write-Output "Kill VM $VmName process..."
            Stop-Process $ProcessID -Force -Confirm:$false -ea SilentlyContinue
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

    $NextHop = $(Get-NetRoute -AddressFamily IPv4 | Where-Object {$_.NextHop -ne "0.0.0.0"} | Sort-Object RouteMetric)[0].NextHop
    $PrimaryIP = $(Find-NetRoute -RemoteIPAddress $NextHop | Where-Object {$($_ | Get-Member).Name -contains "IPAddress"}).IPAddress
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

    # Get the needed DSC Resources in preparation for copying them to the Remote Host
    $null = Install-PackageProvider -Name Nuget -Force -Confirm:$False
    $null = Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    $NeededDSCResources = @(
        "xPSDesiredStateConfiguration"
        "xActiveDirectory"
    )
    [System.Collections.ArrayList]$FailedDSCResourceInstall = @()
    foreach ($DSCResource in $NeededDSCResources) {
        try {
            $null = Install-Module $DSCResource -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $null = $FailedDSCResourceInstall.Add($DSCResource)
            continue
        }
    }
    if ($FailedDSCResourceInstall.Count -gt 0) {
        Write-Error "Problem installing the following DSC Modules:`n$($FailedDSCResourceInstall -join "`n")"
        $global:FunctionResult = "1"
        return
    }
    $DSCModulesToTransfer = foreach ($DSCResource in $NeededDSCResources) {
        $Module = Get-Module -ListAvailable $DSCResource
        "$($($Module.ModuleBase -split $DSCResource)[0])\$DSCResource"
    }

    $PSDSCVersion = $(Get-Module -ListAvailable -Name PSDesiredStateConfiguration).Version[-1].ToString()
    $xActiveDirectoryVersion = $(Get-Module -ListAvailable -Name xActiveDirectory).Version[-1].ToString()
    $xPSDSCVersion = $(Get-Module -ListAvailable -Name xPSDesiredStateConfiguration).Version[-1].ToString()

    # Make sure WinRM in Enabled and Running on $env:ComputerName
    try {
        $null = Enable-PSRemoting -Force -ErrorAction Stop
    }
    catch {
        $null = Get-NetConnectionProfile | Where-Object {$_.NetworkCategory -eq 'Public'} | Set-NetConnectionProfile -NetworkCategory 'Private'

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

    $NewSelfSignedCertUrl = "https://raw.githubusercontent.com/pldmgg/misc-powershell/master/ThirdPartyRefactors/Functions/New-SelfSignedCertificateEx.ps1"
    Invoke-Expression $([System.Net.WebClient]::new().DownloadString($NewSelfSignedCertUrl))

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
                StoreName           = 'My'
                StoreLocation       = 'LocalMachine'
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

    #endregion >> Helper Functions

    
    #region >> Rename Computer

    $InvCmdCheckSB = {
        # Make sure the Local 'Administrator' account has its password set
        $UserAccount = Get-LocalUser -Name "Administrator"
        $UserAccount | Set-LocalUser -Password $args[0]
        $env:ComputerName
    }
    $InvCmdCheckSplatParams = @{
        ComputerName            = $ServerIP
        Credential              = $PSRemotingLocalAdminCredentials
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
            ComputerName    = $ServerIP
            Credential      = $PSRemotingLocalAdminCredentials
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
                $null = Get-NetConnectionProfile | Where-Object {$_.NetworkCategory -eq 'Public'} | Set-NetConnectionProfile -NetworkCategory 'Private'
            
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

    $NewDomainControllerConfigAsStringPrep = @'
configuration NewDomainController {
    param (
        [Parameter(Mandatory=$True)]
        [pscredential]$NewDomainAdminCredentials,

        [Parameter(Mandatory=$True)]
        [pscredential]$LocalAdministratorAccountCredentials
    )

'@ + @"

    Import-DscResource -ModuleName 'PSDesiredStateConfiguration' -ModuleVersion $PSDSCVersion
    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration' -ModuleVersion $xPSDSCVersion
    Import-DscResource -ModuleName 'xActiveDirectory' -ModuleVersion $xActiveDirectoryVersion

"@ + @'

    $NewDomainAdminUser = $($NewDomainAdminCredentials.UserName -split "\\")[-1]
    $NewDomainAdminUserBackup = $NewDomainAdminUser + "backup"
            
    Node $AllNodes.where({ $_.Purpose -eq 'Domain Controller' }).NodeName
    {
        @($ConfigurationData.NonNodeData.ADGroups).foreach({
            xADGroup $_
            {
                Ensure = 'Present'
                GroupName = $_
                DependsOn = '[xADUser]FirstUser'
            }
        })

        @($ConfigurationData.NonNodeData.OrganizationalUnits).foreach({
            xADOrganizationalUnit $_
            {
                Ensure = 'Present'
                Name = ($_ -replace '-')
                Path = ('DC={0},DC={1}' -f ($ConfigurationData.NonNodeData.DomainName -split '\.')[0], ($ConfigurationData.NonNodeData.DomainName -split '\.')[1])
                DependsOn = '[xADUser]FirstUser'
            }
        })

        @($ConfigurationData.NonNodeData.ADUsers).foreach({
            xADUser "$($_.FirstName) $($_.LastName)"
            {
                Ensure = 'Present'
                DomainName = $ConfigurationData.NonNodeData.DomainName
                GivenName = $_.FirstName
                SurName = $_.LastName
                UserName = ('{0}{1}' -f $_.FirstName, $_.LastName)
                Department = $_.Department
                Path = ("OU={0},DC={1},DC={2}" -f $_.Department, ($ConfigurationData.NonNodeData.DomainName -split '\.')[0], ($ConfigurationData.NonNodeData.DomainName -split '\.')[1])
                JobTitle = $_.Title
                Password = $NewDomainAdminCredentials
                DependsOn = "[xADOrganizationalUnit]$($_.Department)"
            }
        })

        ($Node.WindowsFeatures).foreach({
            WindowsFeature $_
            {
                Ensure = 'Present'
                Name = $_
            }
        })        
        
        xADDomain ADDomain          
        {             
            DomainName = $ConfigurationData.NonNodeData.DomainName
            DomainAdministratorCredential = $LocalAdministratorAccountCredentials
            SafemodeAdministratorPassword = $LocalAdministratorAccountCredentials
            DependsOn = '[WindowsFeature]AD-Domain-Services'
        }

        xWaitForADDomain DscForestWait
        {
            DomainName = $ConfigurationData.NonNodeData.DomainName
            DomainUserCredential = $LocalAdministratorAccountCredentials
            RetryCount = $Node.RetryCount
            RetryIntervalSec = $Node.RetryIntervalSec
            DependsOn = "[xADDomain]ADDomain"
        }

        xADUser FirstUser
        {
            DomainName = $ConfigurationData.NonNodeData.DomainName
            DomainAdministratorCredential = $LocalAdministratorAccountCredentials
            UserName = $NewDomainAdminUser
            Password = $NewDomainAdminCredentials
            Ensure = "Present"
            DependsOn = "[xWaitForADDomain]DscForestWait"
        }

        xADGroup DomainAdmins {
            GroupName = 'Domain Admins'
            MembersToInclude = $NewDomainAdminUser,$NewDomainAdminUserBackup
            DependsOn = '[xADUser]FirstUser'
        }
        
        xADGroup EnterpriseAdmins {
            GroupName = 'Enterprise Admins'
            GroupScope = 'Universal'
            MembersToInclude = $NewDomainAdminUser,$NewDomainAdminUserBackup
            DependsOn = '[xADUser]FirstUser'
        }

        xADGroup GroupPolicyOwners {
            GroupName = 'Group Policy Creator Owners'
            MembersToInclude = $NewDomainAdminUser,$NewDomainAdminUserBackup
            DependsOn = '[xADUser]FirstUser'
        }

        xADGroup SchemaAdmins {
            GroupName = 'Schema Admins'
            GroupScope = 'Universal'
            MembersToInclude = $NewDomainAdminUser,$NewDomainAdminUserBackup
            DependsOn = '[xADUser]FirstUser'
        }
    }         
}
'@

    try {
        $NewDomainControllerConfigAsString = [scriptblock]::Create($NewDomainControllerConfigAsStringPrep).ToString()
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

        try {
            Import-Module PSPKI -ErrorAction Stop
        }
        catch {
            try {
                $null = Install-PackageProvider -Name Nuget -Force -Confirm:$False
                $null = Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
                Install-Module PSPKI -ErrorAction Stop -WarningAction SilentlyContinue
                Import-Module PSPKI -ErrorAction Stop
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
        
        try {
            Import-Module ServerManager -ErrorAction Stop
        }
        catch {
            Write-Error "Problem importing the ServerManager Module! Halting!"
            $global:FunctionResult = "1"
            return
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
            $null = Get-NetConnectionProfile | Where-Object {$_.NetworkCategory -eq 'Public'} | Set-NetConnectionProfile -NetworkCategory 'Private'

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

            # Update the Local CDP
            $LocalCDP = (Get-CACrlDistributionPoint)[0]
            $null = $LocalCDP | Remove-CACrlDistributionPoint -Force
            $LocalCDP.PublishDeltaToServer = $false
            $null = $LocalCDP | Add-CACrlDistributionPoint -Force

            # Remove pre-existing ldap/http CDPs, add custom CDP
            $null = Get-CACrlDistributionPoint | Where-Object { $_.URI -like "http*" -or $_.Uri -like "ldap*" } | Remove-CACrlDistributionPoint -Force
            $null = Add-CACrlDistributionPoint -Uri $CDPUrl -AddToCertificateCdp -Force

            # Remove pre-existing ldap/http AIAs, add custom AIA
            $null = Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like "http*" -or $_.Uri -like "ldap*" } | Remove-CAAuthorityInformationAccess -Force
            $null = Add-CAAuthorityInformationAccess -Uri $AIAUrl -AddToCertificateAIA -Force

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
            $ConfigContext = $([ADSI]"LDAP://RootDSE").ConfigurationNamingContext
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
        $null = Get-CertificationAuthority -Name $env:ComputerName | Get-CATemplate | Add-CATemplate -Name $NewComputerTemplateCommonName | Set-CATemplate
        $null = Get-CertificationAuthority -Name $env:ComputerName | Get-CATemplate | Add-CATemplate -Name $NewWebServerTemplateCommonName | Set-CATemplate

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

    $NextHop = $(Get-NetRoute -AddressFamily IPv4 | Where-Object {$_.NextHop -ne "0.0.0.0"} | Sort-Object RouteMetric)[0].NextHop
    $PrimaryIP = $(Find-NetRoute -RemoteIPAddress $NextHop | Where-Object {$($_ | Get-Member).Name -contains "IPAddress"}).IPAddress

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
                $null = Get-NetConnectionProfile | Where-Object {$_.NetworkCategory -eq 'Public'} | Set-NetConnectionProfile -NetworkCategory 'Private'

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

    # Install any required PowerShell Modules...
    [array]$NeededModules = @(
        "PSPKI"
    )
    $null = Install-PackageProvider -Name Nuget -Force -Confirm:$False
    $null = Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

    [System.Collections.ArrayList]$FailedModuleInstall = @()
    foreach ($ModuleResource in $NeededModules) {
        try {
            $null = Install-Module $ModuleResource -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $null = $FailedModuleInstall.Add($ModuleResource)
            continue
        }
    }
    if ($FailedModuleInstall.Count -gt 0) {
        Write-Error "Problem installing the following DSC Modules:`n$($FailedModuleInstall -join "`n")"
        $global:FunctionResult = "1"
        return
    }

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

        # Transfer any required PowerShell Modules
        [array]$ModulesToTransfer = foreach ($ModuleResource in $NeededModules) {
            $Module = Get-Module -ListAvailable $ModuleResource
            "$($($Module.ModuleBase -split $ModuleResource)[0])\$ModuleResource"
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

        $FunctionsForRemoteUse = @(
            ${Function:GetDomainController}.Ast.Extent.Text
            ${Function:SetupRootCA}.Ast.Extent.Text
        )
        $Output = Invoke-Command -Session $RootCAPSSession -ScriptBlock {
            $using:FunctionsForRemoteUse | foreach { Invoke-Expression $_ }
            SetupRootCA @using:SetupRootCASplatParams
        }
    }
    else {
        $Output = SetupRootCA @SetupRootCASplatParams
    }

    $Output

    #endregion >> Do RootCA Install
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

        try {
            Import-Module PSPKI -ErrorAction Stop
        }
        catch {
            try {
                $null = Install-PackageProvider -Name Nuget -Force -Confirm:$False
                $null = Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
                Install-Module PSPKI -ErrorAction Stop -WarningAction SilentlyContinue
                Import-Module PSPKI -ErrorAction Stop
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }

        try {
            Import-Module ServerManager -ErrorAction Stop
        }
        catch {
            Write-Error "Problem importing the ServerManager Module! Halting!"
            $global:FunctionResult = "1"
            return
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
            $null = Get-NetConnectionProfile | Where-Object {$_.NetworkCategory -eq 'Public'} | Set-NetConnectionProfile -NetworkCategory 'Private'

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
            # Add New Cert Templates to List of Temps to Issue using the PSPKI Module
            $null = Get-CertificationAuthority -Name $env:ComputerName | Get-CATemplate | Add-CATemplate -Name $NewComputerTemplateCommonName | Set-CATemplate
            $null = Get-CertificationAuthority -Name $env:ComputerName | Get-CATemplate | Add-CATemplate -Name $NewWebServerTemplateCommonName | Set-CATemplate
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
        $inf = @"
[Version]
Signature="`$Windows NT`$"

[NewRequest]
FriendlyName = pki.$($RelevantSubCANetworkInfo.DomainName)
Subject = "CN=pki.$($RelevantSubCANetworkInfo.DomainName)"
KeyLength = 2048
HashAlgorithm = SHA256
Exportable = TRUE
KeySpec = 1
KeyUsage = 0xa0
MachineKeySet = TRUE
SMIME = FALSE
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10

[Extensions]
2.5.29.17 = "{text}"
_continue_ = "dns=pki.$($RelevantSubCANetworkInfo.DomainName)&"
_continue_ = "ipaddress=$($RelevantSubCANetworkInfo.IPAddress)&"
"@

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

            # Remove pre-existing http CDP, add custom CDP
            $null = Get-CACrlDistributionPoint | Where-Object { $_.URI -like "http#*" } | Remove-CACrlDistributionPoint -Force
            $null = Add-CACrlDistributionPoint -Uri $CDPUrl -AddToCertificateCdp -Force

            # Remove pre-existing http AIA, add custom AIA
            $null = Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like "http*" } | Remove-CAAuthorityInformationAccess -Force
            $null = Add-CAAuthorityInformationAccess -Uri $AIAUrl -AddToCertificateAIA -Force

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

    $NextHop = $(Get-NetRoute -AddressFamily IPv4 | Where-Object {$_.NextHop -ne "0.0.0.0"} | Sort-Object RouteMetric)[0].NextHop
    $PrimaryIP = $(Find-NetRoute -RemoteIPAddress $NextHop | Where-Object {$($_ | Get-Member).Name -contains "IPAddress"}).IPAddress

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
                $null = Get-NetConnectionProfile | Where-Object {$_.NetworkCategory -eq 'Public'} | Set-NetConnectionProfile -NetworkCategory 'Private'

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

    # Install any required PowerShell Modules...
    [array]$NeededModules = @(
        "PSPKI"
    )
    $null = Install-PackageProvider -Name Nuget -Force -Confirm:$False
    $null = Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

    [System.Collections.ArrayList]$FailedModuleInstall = @()
    foreach ($ModuleResource in $NeededModules) {
        try {
            $null = Install-Module $ModuleResource -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $null = $FailedModuleInstall.Add($ModuleResource)
            continue
        }
    }
    if ($FailedModuleInstall.Count -gt 0) {
        Write-Error "Problem installing the following DSC Modules:`n$($FailedModuleInstall -join "`n")"
        $global:FunctionResult = "1"
        return
    }

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

        # Transfer any required PowerShell Modules
        [array]$ModulesToTransfer = foreach ($ModuleResource in $NeededModules) {
            $Module = Get-Module -ListAvailable $ModuleResource
            "$($($Module.ModuleBase -split $ModuleResource)[0])\$ModuleResource"
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

        # Invoke-CommandAs Module looked promising, but doesn't actually work (it just hangs). Maybe in future updates...
        # For more info, see: https://github.com/mkellerman/Invoke-CommandAs
        <#
        if (![bool]$(Get-Module -ListAvailable Invoke-CommandAs -ErrorAction SilentlyContinue)) {
            try {
                Write-Host "Installing 'Invoke-CommandAs' PowerShell Module..."
                $null = Install-PackageProvider -Name Nuget -Force -Confirm:$False
                $null = Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
                Install-Module Invoke-CommandAs -ErrorAction Stop
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }

        try {
            Write-Host "Importing 'Invoke-CommandAs' PowerShell Module..."
            Import-Module Invoke-CommandAs -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        Invoke-CommandAs -Session $SubCAPSSession -ScriptBlock {
            Start-Transcript -Path "C:\NewSubCATask.log" -Append
            $using:FunctionsForRemoteUse | foreach { Invoke-Expression $_ }

            $SetupSubCASplatParams = @{
                DomainAdminCredentials              = $using:DomainAdminCredentials
                NetworkInfoPSObjects                = $using:NetworkInfoPSObjects
                CAType                              = $using:CAType
                NewComputerTemplateCommonName       = $using:NewComputerTemplateCommonName
                NewWebServerTemplateCommonName      = $using:NewWebServerTemplateCommonName
                FileOutputDirectory                 = $using:FileOutputDirectory
                CryptoProvider                      = $using:CryptoProvider
                KeyLength                           = $using:KeyLength
                HashAlgorithm                       = $using:HashAlgorithm
                KeyAlgorithmValue                   = $using:KeyAlgorithmValue
                CDPUrl                              = $using:CDPUrl
                AIAUrl                              = $using:AIAUrl
            }
            
            SetupSubCA @SetupSubCASplatParams
            Stop-Transcript

        } -As $DomainAdminCredentials
        #>

        $DomainAdminAccount = $DomainAdminCredentials.UserName
        $DomainAdminPwd = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($DomainAdminCredentials.Password))
        $Output = Invoke-Command -Session $SubCAPSSession -ScriptBlock {
            $using:FunctionsForRemoteUse | foreach { Invoke-Expression $_ }
            ${Function:GetDomainController}.Ast.Extent.Text | Out-File "$HOME\GetDomainController.ps1"
            ${Function:SetupSubCA}.Ast.Extent.Text | Out-File "$HOME\SetupSubCA.ps1"
            $using:NetworkInfoPSObjects | Export-CliXml "$HOME\NetworkInfoPSObjects.xml"
            
            $ExecutionScript = @'
Start-Transcript -Path "$HOME\NewSubCATask.log" -Append

. "$HOME\GetDomainController.ps1"
. "$HOME\SetupSubCA.ps1"
$NetworkInfoPSObjects = Import-CliXML "$HOME\NetworkInfoPSObjects.xml"

'@ + @"

`$DomainAdminPwdSS = ConvertTo-SecureString '$using:DomainAdminPwd' -AsPlainText -Force
`$DomainAdminCredentials = [pscredential]::new("$using:DomainAdminAccount",`$DomainAdminPwdSS)

"@ + @'

$SetupSubCASplatParams = @{
    DomainAdminCredentials              = $DomainAdminCredentials
    NetworkInfoPSObjects                = $NetworkInfoPSObjects

'@ + @"
    
    CAType                              = "$using:CAType"
    NewComputerTemplateCommonName       = "$using:NewComputerTemplateCommonName"
    NewWebServerTemplateCommonName      = "$using:NewWebServerTemplateCommonName"
    FileOutputDirectory                 = "$using:FileOutputDirectory"
    CryptoProvider                      = "$using:CryptoProvider"
    KeyLength                           = "$using:KeyLength"
    HashAlgorithm                       = "$using:HashAlgorithm"
    KeyAlgorithmValue                   = "$using:KeyAlgorithmValue"
    CDPUrl                              = "$using:CDPUrl"
    AIAUrl                              = "$using:AIAUrl"
}

"@ + @'

    SetupSubCA @SetupSubCASplatParams -OutVariable Output -ErrorAction SilentlyContinue -ErrorVariable NewSubCAErrs

    $Output | Export-CliXml "$HOME\SetupSubCAOutput.xml"

    if ($NewSubCAErrs) {
        Write-Warning "Ignored errors are as follows:"
        Write-Error ($NewSubCAErrs | Select-Object -Unique | Out-String)
    }

    Stop-Transcript

    # Delete this script file after it is finished running
    Remove-Item -LiteralPath $MyInvocation.MyCommand.Path -Force

'@
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
        }
    }
    else {
        Write-Host "This will take about 1 hour...go grab a coffee..."
        $Output = SetupSubCA @SetupSubCASplatParams
    }

    $Output

    #endregion >> Do SubCA Install

    
}



# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUgooRqq1ptfhOQbg9eUi7Bawp
# VNSgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFOcHuACpHwcH+Uav
# NbcAuT1tBzknMA0GCSqGSIb3DQEBAQUABIIBADkzSslEjmdE+LOkmrCdlPqkPWSx
# GAsXdzer4vOMdS0gddvXLU50s/3tBLUIFkqdQGRF8T8CbXwOP3FCJZR9RXeeJWVs
# 2MYNt582gETRf+U7cNNLOh3QcN40X96m/+J4P1LdIwPMwdse4Z7Unzp5K2UsqII6
# XHPktl6Tl45ngEqowRs76xS7Dkc9hkKhR+9p7N/nv+sJnENmjUVzz6mEy3Kj4pTO
# 0KnjVE+iWuH/yhbimBpIio9EACXzo620j3wWbE9yQ8pFT+JcC42xGrJfrphjKI/K
# CJiKlh3jeZi9X0fvE5XVVUs6+FszP2KsSplT1gg5CvQp+Ovdx5E8inf3j2I=
# SIG # End signature block
