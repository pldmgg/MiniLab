function Create-TwoTierPKI {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$False)]
        [switch]$CreateNewVMs,

        [Parameter(Mandatory=$False)]
        [string]$VMStorageDirectory,

        [Parameter(Mandatory=$False)]
        [string]$Windows2016VagrantBox = "StefanScherer/windows_2016",

        [Parameter(Mandatory=$False)]
        [ValidatePattern("^([a-z0-9]+(-[a-z0-9]+)*\.)+([a-z]){2,}$")]
        [string]$NewDomain,

        [Parameter(Mandatory=$False)]
        [pscredential]$DomainAdminCredentials, # If creating a New Domain, this will be a New Domain Account

        [Parameter(Mandatory=$False)]
        [pscredential]$LocalAdministratorAccountCredentials,

        [Parameter(Mandatory=$False)]
        [pscredential]$PSRemotingCredentials,

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

        [Parameter(Mandatory=$True)]
        [pscredential]$DomainAdminCredentials,

        [Parameter(Mandatory=$True)]
        [pscredential]$LocalAdminCredentials,

        [Parameter(Mandatory=$False)]
        [string]$CertDownloadDirectory = "$HOME\Downloads\DSCEncryptionCertsForCAServers"
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

    if ($IPofServerToBeDomainController -eq $IPofServerToBeRootCA) {
        $DCIsRootCA = $True
    }

    $FunctionsForSBUse = @(
        ${Function:TestIsValidIPAddress}.Ast.Extent.Text 
        ${Function:ResolveHost}.Ast.Extent.Text 
        ${Function:GetDomainController}.Ast.Extent.Text 
        ${Function:Deploy-HyperVVagrantBoxManually}.Ast.Extent.Text 
        ${Function:Get-VagrantBoxManualDownload}.Ast.Extent.Text 
        ${Function:New-DomainController}.Ast.Extent.Text 
        ${Function:New-RootCA}.Ast.Extent.Text 
        ${Function:New-SubordinateCAs}.Ast.Extent.Text
    )

    # IMPORTANT NOTE: Throughout this script, 'RootCA' refers to the HostName of the Standalone Root CA Server and
    # 'SubCA' refers to the HostName of the Enterprise Subordinate CA Server. If the HostNames of $IPofServerToBeRootCA
    # and/or $IPofServerToBeSubCA do not match $RootCAHostName and $SubCAHostName below, they will be changed.
    $RootCAHostName = "RootCA"
    $SubCAHostName = "SubCA"

    #endregion >> Prep

    # Create the new VMs if desired
    if ($CreateNewVMs) {
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

        if ($LocalDrives.Name -notcontain $VMStorageDirectoryDriveLetter) {
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

        if ($NewDomain -and !$IPofServerToBeDomainController) {
            $DomainShortName = $($NewDomain -split "\.")[0]

            $NewDCVMDeploySB = {
                # Load the functions we packed up
                $args[0] | foreach { Invoke-Expression $_ }

                $DeployDCBoxSplatParams = @{
                    VagrantBox              = $args[1]
                    CPUs                    = 2
                    Memory                  = 4096
                    VagrantProvider         = "hyperv"
                    VMName                  = $args[2] + "DC1"
                    VMDestinationDirectory  = $args[3]
                }
                $DeployDCBoxResult = Deploy-HyperVVagrantBoxManually @DeployDCBoxSplatParams
                $DeployDCBoxResult
            }
            $NewDCVMDeployJobName = NewUniqueString -PossibleNewUniqueString "NewDCVM" -ArrayOfStrings $(Get-Job).Name

            $NewDCVMDeployJobSplatParams = @{
                Name            = $NewDCVMDeployJobName
                Scriptblock     = $NewDCVMDeploySB
                ArgumentList    = @($FunctionsForSBUse,$Windows2016VagrantBox,$DomainShortName,$VMStorageDirectory)
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
            $NewRootCAVMDeploySB = {
                # Load the functions we packed up
                $args[0] | foreach { Invoke-Expression $_ }

                $DeployRootCABoxSplatParams = @{
                    VagrantBox              = $args[1]
                    CPUs                    = 2
                    Memory                  = 4096
                    VagrantProvider         = "hyperv"
                    VMName                  = $args[2] + "RootCA"
                    VMDestinationDirectory  = $args[3]
                }
                $DeployRootCABoxResult = Deploy-HyperVVagrantBoxManually @DeployRootCABoxSplatParams
                $DeployRootCABoxResult
            }
            $NewRootCAVMDeployJobName = NewUniqueString -PossibleNewUniqueString "NewRootCAVM" -ArrayOfStrings $(Get-Job).Name

            $NewRootCAVMDeployJobSplatParams = @{
                Name            = $NewRootCAVMDeployJobName
                Scriptblock     = $NewRootCAVMDeploySB
                ArgumentList    = @($FunctionsForSBUse,$Windows2016VagrantBox,$DomainShortName,$VMStorageDirectory)
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
            $NewSubCAVMDeploySB = {
                # Load the functions we packed up
                $args[0] | foreach { Invoke-Expression $_ }

                $DeploySubCABoxSplatParams = @{
                    VagrantBox              = $args[1]
                    CPUs                    = 2
                    Memory                  = 4096
                    VagrantProvider         = "hyperv"
                    VMName                  = $args[2] + "SubCA"
                    VMDestinationDirectory  = $args[3]
                }
                $DeploySubCABoxResult = Deploy-HyperVVagrantBoxManually @DeploySubCABoxSplatParams
                $DeploySubCABoxResult
            }
            $NewSubCAVMDeployJobName = NewUniqueString -PossibleNewUniqueString "NewSubCAVM" -ArrayOfStrings $(Get-Job).Name

            $NewSubCAVMDeployJobSplatParams = @{
                Name            = $NewSubCAVMDeployJobName
                Scriptblock     = $NewSubCAVMDeploySB
                ArgumentList    = @($FunctionsForSBUse,$Windows2016VagrantBox,$DomainShortName,$VMStorageDirectory)
            }
            $NewSubCAVMDeployJobInfo = Start-Job @NewSubCAVMDeployJobSplatParams
        }

        if ($NewDomain -and !$IPofServerToBeDomainController) {
            $NewDCVMDeployResult = Wait-Job -Job $NewDCVMDeployJobInfo | Receive-Job
            $IPofServerToBeDomainController = $NewDCVMDeployResult.VMIPAddress
        }
        if (!$IPofServerToBeRootCA) {
            if ($DCIsRootCA) {
                $IPofServerToBeRootCA = $IPofServerToBeDomainController
            }
            else {
                $NewRootCAVMDeployResult = Wait-Job -Job $NewRootCAVMDeployJobInfo | Receive-Job
                $IPofServerToBeRootCA = $NewRootCAVMDeployResult.VMIPAddress
            }
        }
        if (!$IPofServerToBeSubCA) {
            $NewSubCAVMDeployResult = Wait-Job -Job $NewSubCAVMDeployJobInfo | Receive-Job
            $IPofServerToBeSubCA = $NewSubCAVMDeployResult.VMIPAddress
        }

        #endregion >> Deploy New VMs
    }

    #region >> Update WinRM/WSMAN

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
        $IPofServerToBeDomainController
        $IPofServerToBeRootCA
        $IPofServerToBeSubCA
    )
    foreach ($NetItem in $ItemsToAddToWSMANTrustedHosts) {
        if ($CurrentTrustedHostsAsArray -notcontains $NetItem) {
            $null = $CurrentTrustedHostsAsArray.Add($NetItem)
        }
    }
    $UpdatedTrustedHostsString = $($CurrentTrustedHostsAsArray | Where-Object {![string]::IsNullOrWhiteSpace($_)}) -join ','
    Set-Item WSMan:\localhost\Client\TrustedHosts $UpdatedTrustedHostsString -Force

    #endregion >> Update WinRM/WSMAN
        
        
    #region >> Create Services

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

        $DesiredHostName = $DomainShortName + "DC1"

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
    
        if ($RemoteHostNameDC -ne $DesiredHostName) {
            $RenameComputerSB = {
                Rename-Computer -NewName $args[0] -LocalCredential $args[1] -Force -Restart -ErrorAction SilentlyContinue
            }

            $RenameDCJobSB = {
                $InvCmdRenameComputerSplatParams = @{
                    ComputerName    = $args[0]
                    Credential      = $args[1]
                    ScriptBlock     = $args[2]
                    ArgumentList    = $args[3],$args[4]
                    ErrorAction     = "SilentlyContinue"
                }

                try {
                    Invoke-Command @InvCmdRenameComputerSplatParams
                }
                catch {
                    Write-Error "Problem with renaming the $($args[0]) to $($args[3])! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
                Write-Host "Sleeping for 5 minutes to give the Server a chance to restart after name change..."
                Start-Sleep -Seconds 300
            }
            $RenameDCJobName = NewUniqueString -PossibleNewUniqueString "RenameDC" -ArrayOfStrings $(Get-Job).Name

            $RenameDCArgList = @(
                $IPofServerToBeDomainController
                $PSRemotingCredentials
                $RenameComputerSB
                $DesiredHostName
                $PSRemotingCredentials
            )
            $RenameDCJobSplatParams = @{
                Name            = $RenameDCJobName
                Scriptblock     = $RenameDCJobSB
                ArgumentList    = $RenameDCArgList
            }
            $RenameDCJobInfo = Start-Job @RenameDCJobSplatParams
            $RenameDCResult = Wait-Job -Job $RenameDCJobInfo | Receive-Job
        }

        #endregion >> Rename Server To Be Domain Controller If Necessary

        #region >> Create the New Domain Controller
        
        $NewDomainControllerSplatParams = @{
            DesiredHostName                         = $DesiredHostName
            NewDomainName                           = $NewDomain
            NewDomainAdminCredentials               = $DomainAdminCredentials
            ServerIP                                = $IPofServerToBeDomainController
            PSRemotingLocalAdminCredentials         = $PSRemotingCredentials # Needed for WinRM PSSessions
            LocalAdministratorAccountCredentials    = $LocalAdministratorAccountCredentials
        }
        $NewDomainControllerResults = New-DomainController @NewDomainControllerSplatParams

        #endregion >> Create the New Domain Controller
    }

    #region >> Join the Servers To Be RootCA and SubCA to Domain If Necessary

    $FinalDomainName = if ($ExistingDomain) {$ExistingDomain} else {$NewDomain}

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
            $JoinDomainSB = {
                # Synchronize time with time servers
                $null = W32tm /resync /rediscover /nowait

                # Make sure the DNS Client points to $IPofServerToBeDomainController (and others from DHCP)
                # CONTINUE HERE

                # Join Domain
                Add-Computer -ComputerName $env:ComputerName -DomainName $args[0] -Credential $args[1] -Restart -Force
            }

            $JoinDomainJobSB = {
                $InvCmdJoinDomainSplatParams = @{
                    Credential      = $args[0]
                    ScriptBlock     = $args[1]
                    ArgumentList    = $args[2],$args[3]
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
            $JoinRootCAJobName = NewUniqueString -PossibleNewUniqueString "JoinRootCA" -ArrayOfStrings $(Get-Job).Name

            $JoinRootCAArgList = @(
                $PSRemotingCredentials
                $JoinDomainSB
                $FinalDomainName
                $DomainAdminCredentials
            )
            $JoinRootCAJobSplatParams = @{
                Name            = $JoinRootCAJobName
                Scriptblock     = $JoinDomainJobSB
                ArgumentList    = $JoinRootCAArgList
            }
            $JoinRootCAJobInfo = Start-Job @RenameDCJobSplatParams
            # $JoinRootCAResult = Wait-Job -Job $JoinRootCAJobInfo | Receive-Job
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
        $JoinDomainSB = {
            # Synchronize time with time servers
            $null = W32tm /resync /rediscover /nowait
            # Join Domain
            Add-Computer -ComputerName $env:ComputerName -DomainName $args[0] -Credential $args[1] -Restart -Force
        }

        $JoinDomainJobSB = {
            $InvCmdJoinDomainSplatParams = @{
                Credential      = $args[0]
                ScriptBlock     = $args[1]
                ArgumentList    = $args[2],$args[3]
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
        $JoinSubCAJobName = NewUniqueString -PossibleNewUniqueString "JoinSubCA" -ArrayOfStrings $(Get-Job).Name

        $JoinSubCAArgList = @(
            $PSRemotingCredentials
            $JoinDomainSB
            $FinalDomainName
            $DomainAdminCredentials
        )
        $JoinSubCAJobSplatParams = @{
            Name            = $JoinSubCAJobName
            Scriptblock     = $JoinDomainJobSB
            ArgumentList    = $JoinSubCAArgList
        }
        $JoinSubCAJobInfo = Start-Job @RenameDCJobSplatParams
    }

    if ($JoinRootCAJobInfo) {
        $JoinRootCAResult = Wait-Job -Job $JoinRootCAJobInfo | Receive-Job
    }
    if ($JoinSubCAJobInfo) {
        $JoinSubCAResult = Wait-Job -Job $JoinSubCAJobInfo | Receive-Job
    }

    #endregion >> Join the Servers To Be RootCA and SubCA to Domain If Necessary
    

    #region >> Create the Root and Subordinate CAs

    $NewRootCAResult = New-RootCA -DomainAdminCredentials $DomainAdminCredentials -RootCAIPOrFQDN $IPofServerToBeRootCA

    $NewSubCAResult = New-SubordinateCA -DomainAdminCredentials $DomainAdminCredentials -RootCAIPOrFQDN $IPofServerToBeRootCA -SubCAIPOrFQDN $IPofServerToBeSubCA

    #endregion >> Create the Root and Subordinate CAs
}



# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUAx6+4JttSI3OrpiZjLS62rIA
# 0qygggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFEWsmWx3CidfUChm
# Nd6MzyY2IRDMMA0GCSqGSIb3DQEBAQUABIIBAGljw46YtOM60lDOAx9x1ro7WAp6
# BQjrNNlbC8HVDWvZWCFueZgT1b+cN6EZ2cqof4XcOYMKICxmP+Ttqt2NbE7yukkm
# SnLSVWwdUj0QYaM8YapcZwuuDOgImrmQJPlPGudfV7YSXB38i5xMKeGAJz9C+0Pk
# UPreiN13Fv4FL98O4IoW/F1LdnRMQrjqU+YDD702KuM36kHlKoffKEqPTpSoB3fT
# bU9gaJZ1a0uuyTzOYzSUL7pu3VHhbDijjMT6CcllLEVXPi8s1CfNtuaz6qEgQSTD
# t4TZUCH19PbxKmVCyb8ToYN3AOvxbHwErUDX/Ap2dW5/6YpsBU/IYK0oMis=
# SIG # End signature block
