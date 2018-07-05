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
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU5eajS+Do194sm/en/2FVna5+
# Aq2gggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFBDSoNdQRxZpixaP
# UmiP2Gf4HocUMA0GCSqGSIb3DQEBAQUABIIBAEfd6sjyB7Ldx3PAVJLMrhq8YTIo
# ccN/nNpQ5ilaKmHvDxBzcnTMzyJ72MPl7lSmpcML78WfUcYlqM5R5+Y5h+zIOo0G
# Qx+b7reNi6jQtn/AoyOeSUIiCs4uB23LXL0wtfhjoH42eqltWWp+Z71v0DKWP1dQ
# J/GuYoYjn13ygsaU8vwwdygvh7nwvusrHWc1ugOlh/J2iGVl4pesmuaiWdpRtJEB
# 9msTzQLgFkgk/8lYfikpYM65ATgjLBkMxAspnw8LLzCnqkYEhklmtlMPrTPz/1Ld
# ovkLyhnsd8oBO4Nmr2T7Kn/dg4rVpWiNLTDQOOCMsfe6yktUtTRxMg072c0=
# SIG # End signature block
