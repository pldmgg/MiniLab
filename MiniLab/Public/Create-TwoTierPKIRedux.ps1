function Create-TwoTierPKIRedux {
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

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUO9nhf+iJL6mHuBwvAjRZGk3U
# qsmgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFKy1vcHK1UPKhKke
# oUge9jimW6OKMA0GCSqGSIb3DQEBAQUABIIBADom+g2bWzw2+M+w+i7sQACMLHnM
# V7zfYD/zaNuftlmSelcKv+EJ3L2+F8v1Ra+JwE0YmFeA7UlCEyVratVESKbUMZFf
# v7+pl46do2FQ0PYfwCKD9vIrbIyikbdWLok3MqG61JNar3jzwpFaG+z4jTCMZKQd
# E4ZKBt0zsy1IBCkKKJF8RZMa9d7clKKsPNUewkzAXpp3mzccHBDvgd7iJpSB184M
# haD7L+8Yf/+n9EwojwcdQtVG+BaSSX5Lb0JRmwzTuyfMUqD/1Mzv9rTl8ckqo0Fq
# m66t2VeSgWtcbHmRM4VYxyrJBhpLOL/CUtUOsW6S4/igJ4BhZkyd6HhxHUo=
# SIG # End signature block
