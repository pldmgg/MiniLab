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
        $PromptMsg = "Please enter the IP Address of the existing Server that will become the new Domain Controller"
        $IPofServerToBeDomainController = Read-Host -Prompt $PromptMsg
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

    if ($PSBoundParameters['IPofServerToBeDomainController'] -and $PSBoundParameters['$IPofServerToBeRootCA']) {
        if ($IPofServerToBeDomainController -eq $IPofServerToBeRootCA) {
            $DCIsRootCA = $True
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
    )

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
        $BoxNameRegex = $($Windows2016VagrantBox -split '/')[0]
        $BoxFileAlreadyPresentCheck = Get-ChildItem "$VMStorageDirectory\BoxDownloads" -File -Filter "*.box" | Where-Object {$_.Name -match $BoxNameRegex}
        if (![bool]$BoxFileAlreadyPresentCheck) {
            $BoxFileItem = Get-VagrantBoxManualDownload -VagrantBox $Windows2016VagrantBox -VagrantProvider "hyperv" -DownloadDirectory "$VMStorageDirectory\BoxDownloads"
        }
        else {
            $BoxFileItem = $BoxFileAlreadyPresentCheck
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
            }
        }

        if ($NewDomain -and !$IPofServerToBeDomainController) {
            $DomainShortName = $($NewDomain -split "\.")[0]
            Write-Host "Deploying New Domain Controller VM '$DomainShortName`DC1'..."

            $NewDCVMDeploySB = {
                [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

                $env:Path = $args[0]

                # Load the functions we packed up
                $args[1] | foreach { Invoke-Expression $_ }

                $DeployDCBoxSplatParams = @{
                    VagrantBox              = $args[2]
                    BoxFilePath             = $args[3]
                    CPUs                    = 2
                    Memory                  = 4096
                    VagrantProvider         = "hyperv"
                    VMName                  = $args[4] + "DC1"
                    VMDestinationDirectory  = $args[5]
                    SkipHyperVInstallCheck  = $True
                }
                $DeployDCBoxResult = Deploy-HyperVVagrantBoxManually @DeployDCBoxSplatParams
                $DeployDCBoxResult
            }
            $NewDCVMDeployJobName = NewUniqueString -PossibleNewUniqueString "NewDCVM" -ArrayOfStrings $(Get-Job).Name

            $NewDCVMDeployJobSplatParams = @{
                Name            = $NewDCVMDeployJobName
                Scriptblock     = $NewDCVMDeploySB
                ArgumentList    = @($env:Path,$FunctionsForSBUse,$Windows2016VagrantBox,$BoxFileItem.FullName,$DomainShortName,$VMStorageDirectory)
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

            $NewRootCAVMDeploySB = {
                [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

                $env:Path = $args[0]

                # Load the functions we packed up
                $args[1] | foreach { Invoke-Expression $_ }

                $DeployRootCABoxSplatParams = @{
                    VagrantBox              = $args[2]
                    BoxFilePath             = $args[3]
                    CPUs                    = 2
                    Memory                  = 4096
                    VagrantProvider         = "hyperv"
                    VMName                  = $args[4] + "RootCA"
                    VMDestinationDirectory  = $args[5]
                    SkipHyperVInstallCheck  = $True
                }
                $DeployRootCABoxResult = Deploy-HyperVVagrantBoxManually @DeployRootCABoxSplatParams
                $DeployRootCABoxResult
            }
            $NewRootCAVMDeployJobName = NewUniqueString -PossibleNewUniqueString "NewRootCAVM" -ArrayOfStrings $(Get-Job).Name

            $NewRootCAVMDeployJobSplatParams = @{
                Name            = $NewRootCAVMDeployJobName
                Scriptblock     = $NewRootCAVMDeploySB
                ArgumentList    = @($env:Path,$FunctionsForSBUse,$Windows2016VagrantBox,$BoxFileItem.FullName,$DomainShortName,$VMStorageDirectory)
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

            $NewSubCAVMDeploySB = {
                [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

                $env:Path = $args[0]

                # Load the functions we packed up
                $args[1] | foreach { Invoke-Expression $_ }

                $DeploySubCABoxSplatParams = @{
                    VagrantBox              = $args[2]
                    BoxFilePath             = $args[3]
                    CPUs                    = 2
                    Memory                  = 4096
                    VagrantProvider         = "hyperv"
                    VMName                  = $args[4] + "SubCA"
                    VMDestinationDirectory  = $args[5]
                    SkipHyperVInstallCheck  = $True
                }
                $DeploySubCABoxResult = Deploy-HyperVVagrantBoxManually @DeploySubCABoxSplatParams
                $DeploySubCABoxResult
            }
            $NewSubCAVMDeployJobName = NewUniqueString -PossibleNewUniqueString "NewSubCAVM" -ArrayOfStrings $(Get-Job).Name

            $NewSubCAVMDeployJobSplatParams = @{
                Name            = $NewSubCAVMDeployJobName
                Scriptblock     = $NewSubCAVMDeploySB
                ArgumentList    = @($env:Path,$FunctionsForSBUse,$Windows2016VagrantBox,$BoxFileItem.FullName,$DomainShortName,$VMStorageDirectory)
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
            else {
                $NewRootCAVMDeployResult = Wait-Job -Job $NewRootCAVMDeployJobInfo | Receive-Job
                $IPofServerToBeRootCA = $NewRootCAVMDeployResult.VMIPAddress
            }

            while (![bool]$(Get-VM -Name "$DomainShortName`RootCA" -ErrorAction SilentlyContinue)) {
                Write-Host "Waiting for $DomainShortName`RootCA VM to be deployed..."
                Start-Sleep -Seconds 15
            }

            if (!$IPofServerToBeRootCA) {
                $IPofServerToBeRootCA = $(Get-VM -Name "$DomainShortName`RootCA").NetworkAdpaters.IPAddresses | Where-Object {TestIsValidIPAddress -IPAddress $_}
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
        if (!$(TestIsValidIPAddress -IPAddress $IPofServerToBeDomainController)) {
            $null = $VMsNotReportingIP.Add("$DomainShortName`SubCA")
        }

        if ($VMsNotReportingIP.Count -gt 0) {
            Write-Error "The following VMs did NOT report thier IP Addresses within 30 minutes:`n$($VMsNotReportingIP -join "`n")`nHalting!"
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
                Write-Error "Unable to create new PSSession to '$PSSessionName' using account '$($PSRemotingCredentials.UserName)'! Halting!"
                $global:FunctionResult = "1"
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

    #region >> Make Sure WinRM/WSMan Is Ready on the Remote Hosts
        
        
    #region >> Prep New Domain Controller

    if ($NewDomain) {
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
            Write-Error "Unable to determine if creatrion of the New Domain Controller '$DesiredHostNameDC' at '$IPofServerToBeDomainController' was successfule! Halting!"
            $global:FunctionResult = "1"
            return
        }

        #endregion >> Make the Domain Controller
    }

    #endregion >> Prep New Domain Controller


    #region >> Join the Servers to Domain And Rename If Necessary

    $FinalDomainName = if ($ExistingDomain) {$ExistingDomain} else {$NewDomain}

    $JoinDomainJobSB = {
        $JoinDomainSBAsString = @'
# Synchronize time with time servers
$null = W32tm /resync /rediscover /nowait

# Make sure the DNS Client points to $IPofServerToBeDomainController (and others from DHCP)
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

    # Check if DC and RootCA should be the same server
    if ($IPofServerToBeDomainController -ne $IPofServerToBeRootCA) {
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

        if ($RootCADomain -ne $FinalDomainName) {
            Write-Host "Joining the Root CA to the Domain..."
            $DesiredHostNameRootCA = $DomainShortName + "RootCA"

            $JoinRootCAJobName = NewUniqueString -PossibleNewUniqueString "JoinRootCA" -ArrayOfStrings $(Get-Job).Name

            $JoinRootCAArgList = @(
                $IPofServerToBeRootCA
                $PSRemotingCredentials
                $IPofServerToBeDomainController
                $DesiredHostNameRootCA
                $FinalDomainName
                $DomainAdminCredentials
            )
            $JoinRootCAJobSplatParams = @{
                Name            = $JoinRootCAJobName
                Scriptblock     = $JoinDomainJobSB
                ArgumentList    = $JoinRootCAArgList
            }
            $JoinRootCAJobInfo = Start-Job @JoinRootCAJobSplatParams
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
        $SubCADomain = Invoke-Command @InvCmdRootCADomainSplatParams
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    if ($SubCADomain -ne $FinalDomainName) {
        Write-Host "Joining the Subordinate CA to the Domain..."
        $DesiredHostNameSubCA = $DomainShortName + "SubCA"
        
        $JoinSubCAJobName = NewUniqueString -PossibleNewUniqueString "JoinSubCA" -ArrayOfStrings $(Get-Job).Name

        $JoinSubCAArgList = @(
            $IPofServerToBeSubCA
            $PSRemotingCredentials
            $IPofServerToBeDomainController
            $DesiredHostNameSubCA
            $FinalDomainName
            $DomainAdminCredentials
        )
        $JoinSubCAJobSplatParams = @{
            Name            = $JoinSubCAJobName
            Scriptblock     = $JoinDomainJobSB
            ArgumentList    = $JoinSubCAArgList
        }
        $JoinSubCAJobInfo = Start-Job @JoinSubCAJobSplatParams
    }

    # Collect Job Output
    if ($JoinRootCAJobInfo) {
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
    if ($JoinSubCAJobInfo) {
        $JoinSubCAResult = Wait-Job -Job $JoinSubCAJobInfo | Receive-Job
        
        # Verify Subordinate CA is Joined to Domain
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
            Write-Error "Unable to create a PSSession to the Root CA Server at '$IPofServerToBeSubCA' using Domain Admin Credentials $($DomainAdminCredentials.UserName)! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    #endregion >> Join the Servers to Domain And Rename If Necessary
    

    #region >> Create the Root and Subordinate CAs

    # Remove All Existing PSSessions
    Get-PSSession | Remove-PSSession

    Write-Host "Creating the New Root CA..."
    $NewRootCAResult = New-RootCA -DomainAdminCredentials $DomainAdminCredentials -RootCAIPOrFQDN $IPofServerToBeRootCA

    Write-Host "Creating the New Subordinate CA..."
    $NewSubCAResult = New-SubordinateCA -DomainAdminCredentials $DomainAdminCredentials -RootCAIPOrFQDN $IPofServerToBeRootCA -SubCAIPOrFQDN $IPofServerToBeSubCA

    #endregion >> Create the Root and Subordinate CAs

    $EndTime = Get-Date
    $TotalAllOpsTime = $EndTime - $StartTime
    Write-Host "All operations took $($TotalAllOpsTime.Hours) hours and $($TotalAllOpsTime.Minutes) minutes" -ForegroundColor Yellow
    
    $Output = @{
        NewRootCAResult         = $NewRootCAResult
        NewSubCAResult          = $NewSubCAResult
    }
    if ($NewDomainControllerResults) {
        $Output.Add("NewDomainControllerResult",$NewDomainControllerResults)
    }

    [pscustomobject]$Output
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUjzWa2BrrE1jNQfuQesoi6OM1
# ecSgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFNmOawNn9Spfgy9v
# NplOkvHH73m6MA0GCSqGSIb3DQEBAQUABIIBAALsB1bVqHAC3387Qkx6CGKlZEFp
# MDBEgVpXFF22js6inMbU+PrsMu2/TFIE0/KJ4r6U9WKX/VXqiQKKtKIpWfZee5MQ
# ZAirUfLJt2/VgIEuqUjx5mvPMjhoZps18gR3pK3TNnap7miiBEs0Svg9gifXaU/h
# RBEk3ZJj2JYzGe5gl399z9wR5Rt2XDsxlb9Doxeu/hfMRFJllwNU8bhTzH1tc9ME
# NGXA/B1srlkmiq3osZejFbkgJuvK6JCeFMZ2fQohFxutnvHTjWB6pqomlqiEu5bz
# x0PpljlaXUlH4y5V47nYwt+KBpfMkFArXmtJcZkSTT+wMFc6tMAjynkQ7eo=
# SIG # End signature block
