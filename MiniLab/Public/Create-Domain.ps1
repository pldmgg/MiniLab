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

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUa4tH+A6SK75LVzH5NeciqlwT
# quegggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFLo/za/IsnSJ3Xji
# 0gCOkMRTVfH+MA0GCSqGSIb3DQEBAQUABIIBAAXec7gnUDdPq9sUC3BJcV7sFa4j
# uEIJHBWZLkfqRXR5PcMucrwrbadrkzJpTQ/8DXf3fWH38vtfWZHHmx2iuVBoiw26
# HoFNuU8CyNDY8FfZmImc62FzBzx+C5jAzcyHlHlI34robl6iqg4OXGOhCjRJ05jW
# F2hR0SZ5uODVySp8czeJlkNIHAtbM8hO79sb7SH0Fl7F5NiKBWg66mMg5xr+mkiM
# qEGPvnbXQPux01DCmzKqiPApQuiddM/zV7yFzeJC/M6Xuy50OuNMhQnUnp+RP6ZK
# fiQqReIv1BqryH4xt1cnxhcXIEXk1je+tBAbsr195c3ciMyCg6KXzlnMhYQ=
# SIG # End signature block
