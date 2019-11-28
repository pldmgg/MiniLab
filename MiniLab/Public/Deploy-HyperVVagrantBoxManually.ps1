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
            $DefaultSwitchCheck = $(Get-VMSwitch).Name -contains "Default Switch"
            if (!$DefaultSwitchCheck) {
                $null = New-VMSwitch -Name "ToExternal" -NetAdapterName $PrimaryInterfaceAlias
                $ExternalSwitchCreated = $True
                $vSwitchToUse = Get-VMSwitch -Name "ToExternal"
            }
            else {
                $vSwitchToUse = Get-VMSwitch -Name "Default Switch"
            }
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

# SIG # Begin signature block
# MIIMaAYJKoZIhvcNAQcCoIIMWTCCDFUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUrzriWrZSqdLWhEu2uxAxFSp2
# PuigggndMIIEJjCCAw6gAwIBAgITawAAADqEP46TDmc/hQAAAAAAOjANBgkqhkiG
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
# BDEWBBTuON5UFnQsuznV8prlqvozkn/84jANBgkqhkiG9w0BAQEFAASCAQCJl6Q2
# SwIIIGq+JjGhSjKQaEL1xbiKtoHJ3ELDhYXs7oZ+dH/bCSDT5V0LaiG9heoqoIAs
# pPAsItwXg8i3DjJQa4jR+V2b1LHrckU3fFyt2Bgr8OjmGI2s7eZSbtkhuaQhsGZg
# RhcqzLNedfoNunMRr0TWlbOS9Yn4+RHS04Z8NFwrbtm2x/La+uRivd0VOOZvdOUS
# VIzgprRSWKgyW/+g3rBVYnuQbRjvIAJ765EIzBpEutOrlkHPaAZv9rdr5zVkRnAv
# 0GJT/EWEdePJMmcMzRhRDb11kxm+3XkHrv8a5CVLKUjyF7pD2ptd1nQxoeCEF/GE
# Vj31h5s5Mv721fc5
# SIG # End signature block
