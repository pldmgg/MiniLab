function InvokePSCompatibility {
    [CmdletBinding()]
    Param (
        # $InvocationMethod determines if the GetModuleDependencies function scans a file or loaded function
        [Parameter(Mandatory=$False)]
        [string]$InvocationMethod,

        [Parameter(Mandatory=$False)]
        [string[]]$RequiredModules,

        [Parameter(Mandatory=$False)]
        [switch]$InstallModulesNotAvailableLocally
    )

    #region >> Prep

    if ($PSVersionTable.PSEdition -ne "Core" -or
    $($PSVersionTable.PSEdition -ne "Core" -and $PSVersionTable.Platform -ne "Win32NT")) {
        Write-Error "This function is only meant to be used with PowerShell Core on Windows! Halting!"
        $global:FunctionResult = "1"
        return
    }

    AddWinRMTrustLocalHost

    if (!$InvocationMethod) {
        $MyInvParentScope = Get-Variable "MyInvocation" -Scope 1 -ValueOnly
        $PathToFile = $MyInvParentScope.MyCommand.Source
        $FunctionName = $MyInvParentScope.MyCommand.Name

        if ($PathToFile) {
            $InvocationMethod = $PathToFile
        }
        elseif ($FunctionName) {
            $InvocationMethod = $FunctionName
        }
        else {
            Write-Error "Unable to determine MyInvocation Source or Name! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    $AllWindowsPSModulePaths = @(
        "C:\Program Files\WindowsPowerShell\Modules"
        "$HOME\Documents\WindowsPowerShell\Modules"
        "$HOME\Documents\PowerShell\Modules"
        "C:\Program Files\PowerShell\Modules"
        "C:\Windows\System32\WindowsPowerShell\v1.0\Modules"
        "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\Modules"
    )

    # Determine all current Locally Available Modules
    $AllLocallyAvailableModules = foreach ($ModPath in $AllWindowsPSModulePaths) {
        if (Test-Path $ModPath) {
            $ModuleBases = $(Get-ChildItem -Path $ModPath -Directory).FullName

            foreach ($ModuleBase in $ModuleBases) {
                [pscustomobject]@{
                    ModuleName          = $($ModuleBase | Split-Path -Leaf)
                    ManifestFileItem    = $(Get-ChildItem -Path $ModuleBase -Recurse -File -Filter "*.psd1")
                }
            }
        }
    }

    if (![bool]$(Get-Module -ListAvailable WindowsCompatibility)) {
        try {
            Install-Module WindowsCompatibility -ErrorAction Stop
        }
        catch {
            Write-Error $_
            Write-Error "Problem installing the Windows Compatibility Module! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    if (![bool]$(Get-Module WindowsCompatibility)) {
        try {
            Import-Module WindowsCompatibility -ErrorAction Stop
        }
        catch {
            Write-Error $_
            Write-Error "Problem importing the WindowsCompatibility Module! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    # Scan Script/Function/Module to get an initial list of Required Locally Available Modules
    try {
        # Below $RequiredLocallyAvailableModules is a PSCustomObject with properties WinPSModuleDependencies
        # and PSCoreModuleDependencies - both of which are [System.Collections.ArrayList]

        # If $InvocationMethod is a file, then GetModuleDependencies can use $PSCommandPath as the value
        # for -PathToScriptFile
        $GetModDepsSplatParams = @{}

        if (![string]::IsNullOrWhitespace($InvocationMethod)) {
            if ($PathToFile -or [bool]$($InvocationMethod -match "\.ps")) {
                if (Test-Path $InvocationMethod) {
                    $GetModDepsSplatParams.Add("PathToScriptFile",$InvocationMethod)
                }
                else {
                    Write-Error "'$InvocationMethod' was not found! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
            else {
                $GetModDepsSplatParams.Add("NameOfLoadedFunction",$InvocationMethod)
            }
        }
        if ($RequiredModules -ne $null) {
            $GetModDepsSplatParams.Add("ExplicitlyNeededModules",$RequiredModules)
        }

        if ($GetModDepsSplatParams.Keys.Count -gt 0) {
            $RequiredLocallyAvailableModulesScan = GetModuleDependencies @GetModDepsSplatParams
        }
    }
    catch {
        Write-Error $_
        Write-Error "Problem with enumerating Module Dependencies using GetModuleDependencies! Halting!"
        $global:FunctionResult = "1"
        return
    }

    #$RequiredLocallyAvailableModulesScan | Export-CliXml "$HOME\InitialRequiredLocallyAvailableModules.xml" -Force

    if (!$RequiredLocallyAvailableModulesScan) {
        Write-Host "InvokePSCompatibility reports that no additional modules need to be loaded." -ForegroundColor Green
        return
    }

    if ($RequiredModules) {
        # If, for some reason, the scan conducted by GetModuleDependencies did not determine
        # that $RequiredModules should be included, manually add $RequiredModules to the output
        # (i.e.$RequiredLocallyAvailableModulesScan.WinPSModuleDependencies and/or
        # $RequiredLocallyAvailableModulesScan.PSCoreModuleDependencies)
        [System.Collections.ArrayList]$ModulesNotFoundLocally = @()
        foreach ($ModuleName in $RequiredModules) {
            # Determine if $ModuleName is a PSCore or WinPS Module
            [System.Collections.ArrayList]$ModuleInfoArray = @()
            foreach ($ModPath in $AllWindowsPSModulePaths) {
                if (Test-Path "$ModPath\$ModuleName") {
                    $ModuleBase = $(Get-ChildItem -Path $ModPath -Directory -Filter $ModuleName).FullName

                    $ModObj = [pscustomobject]@{
                        ModuleName          = $ModuleName
                        ManifestFileItem    = $(Get-ChildItem -Path $ModuleBase -Recurse -File -Filter "*.psd1")
                    }

                    $null = $ModuleInfoArray.Add($ModObj)
                }
            }

            if ($ModuleInfoArray.Count -eq 0) {
                $null = $ModulesNotFoundLocally.Add($ModuleName)
                continue
            }
            
            foreach ($ModObj in $ModuleInfoArray) {
                if ($ModObj.ManifestItem.FullName -match "\\WindowsPowerShell\\") {
                    if ($RequiredLocallyAvailableModulesScan.WinPSModuleDependencies.ManifestFileItem.FullName -notcontains
                    $ModObj.ManifestFileItem.FullName
                    ) {
                        $null = $RequiredLocallyAvailableModulesScan.WinPSModuleDependencies.Add($ModObj)
                    }
                }
                if ($ModObj.ManifestItem.FullName -match "\\PowerShell\\") {
                    if ($RequiredLocallyAvailableModulesScan.PSCoreModuleDependencies.ManifestFileItem.FullName -notcontains
                    $ModObj.ManifestFileItem.FullName
                    ) {
                        $null = $RequiredLocallyAvailableModulesScan.PSCoreModuleDependencies.Add($ModObj)
                    }
                }
            }
        }

        # If any of the $RequiredModules are not available on the localhost, install them if that's okay
        [System.Collections.ArrayList]$ModulesSuccessfullyInstalled = @()
        [System.Collections.ArrayList]$ModulesFailedInstall = @()
        if ($ModulesNotFoundLocally.Count -gt 0 -and $InstallModulesNotAvailableLocally) {
            # Since there's currently no way to know if external Modules are actually compatible with PowerShell Core
            # until we try and load them, we just need to install them under both WinPS and PSCore. We will
            # uninstall/remove later once we figure out what actually works.
            foreach ($ModuleName in $ModulesNotFoundLocally) {
                try {
                    if (![bool]$(Get-Module -ListAvailable $ModuleName) -and $InstallModulesNotAvailableLocally) {
                        $searchUrl = "https://www.powershellgallery.com/api/v2/Packages?`$filter=Id eq '$ModuleName' and IsLatestVersion"
                        $PSGalleryCheck = Invoke-RestMethod $searchUrl
                        if (!$PSGalleryCheck -or $PSGalleryCheck.Count -eq 0) {
                            $searchUrl = "https://www.powershellgallery.com/api/v2/Packages?`$filter=Id eq '$ModuleName'"
                            $PSGalleryCheck = Invoke-RestMethod $searchUrl

                            if (!$PSGalleryCheck -or $PSGalleryCheck.Count -eq 0) {
                                Write-Warning "Unable to find Module '$ModuleName' in the PSGallery! Skipping..."
                                continue
                            }

                            $PreRelease = $True
                        }

                        if ($PreRelease) {
                            ManualPSGalleryModuleInstall -ModuleName $ModuleName -DownloadDirectory "$HOME\Downloads" -PreRelease -ErrorAction Stop -WarningAction SilentlyContinue
                        }
                        else {
                            Install-Module $ModuleName -AllowClobber -Force -ErrorAction Stop -WarningAction SilentlyContinue
                        }
                        $null = $ModulesSuccessfullyInstalled.Add($ModuleName)
                    }

                    $ModObj = [pscustomobject]@{
                        ModuleName          = $ModuleName
                        ManifestFileItem    = $(Get-Item $(Get-Module -ListAvailable $ModuleName).Path)
                    }

                    $null = $RequiredLocallyAvailableModulesScan.PSCoreModuleDependencies.Add($ModObj)
                }
                catch {
                    Write-Warning $($_ | Out-String)
                    $null = $ModulesFailedInstall.Add($ModuleName)
                }

                try {
                    # Make sure the PSSession Type Accelerator exists
                    $TypeAccelerators = [psobject].Assembly.GetType("System.Management.Automation.TypeAccelerators")::get
                    if ($TypeAccelerators.Name -notcontains "PSSession") {
                        [PowerShell].Assembly.GetType("System.Management.Automation.TypeAccelerators")::Add("PSSession","System.Management.Automation.Runspaces.PSSession")
                    }

                    $ManualPSGalleryModuleFuncAsString = ${Function:ManualPSGalleryModuleInstall}.Ast.Extent.Text

                    $ManifestFileItem = Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                        if (![bool]$(Get-Module -ListAvailable $args[0]) -and $args[1]) {
                            Invoke-Expression $args[2]

                            $searchUrl = "https://www.powershellgallery.com/api/v2/Packages?`$filter=Id eq '$($args[0])' and IsLatestVersion"
                            $PSGalleryCheck = Invoke-RestMethod $searchUrl
                            if (!$PSGalleryCheck -or $PSGalleryCheck.Count -eq 0) {
                                $searchUrl = "https://www.powershellgallery.com/api/v2/Packages?`$filter=Id eq '$($args[0])'"
                                $PSGalleryCheck = Invoke-RestMethod $searchUrl

                                if (!$PSGalleryCheck -or $PSGalleryCheck.Count -eq 0) {
                                    Write-Warning "Unable to find Module '$($args[0])' in the PSGallery! Skipping..."
                                    continue
                                }

                                $PreRelease = $True
                            }

                            if ($PreRelease) {
                                ManualPSGalleryModuleInstall -ModuleName $args[0] -DownloadDirectory "$HOME\Downloads" -PreRelease
                            }
                            else {
                                Install-Module $args[0] -AllowClobber -Force
                            }
                        }
                        $(Get-Item $(Get-Module -ListAvailable $args[0]).Path)
                    } -ArgumentList $ModuleName,$InstallModulesNotAvailableLocally,$ManualPSGalleryModuleFuncAsString -ErrorAction Stop -WarningAction SilentlyContinue

                    if ($ManifestFileItem) {
                        $null = $ModulesSuccessfullyInstalled.Add($ModuleName)

                        $ModObj = [pscustomobject]@{
                            ModuleName          = $ModuleName
                            ManifestFileItem    = $ManifestFileItem
                        }

                        $null = $RequiredLocallyAvailableModulesScan.WinPSModuleDependencies.Add($ModObj)
                    }
                }
                catch {
                    Write-Warning $($_ | Out-String)
                    $null = $ModulesFailedInstall.Add($ModuleName)
                }
            }
        }

        if ($ModulesNotFoundLocally.Count -ne $ModulesSuccessfullyInstalled.Count -and !$InstallModulesNotAvailableLocally) {
            $ErrMsg = "The following Modules were not found locally, and they will NOT be installed " +
            "because the -InstallModulesNotAvailableLocally switch was not used:`n$($ModulesNotFoundLocally -join "`n")"
            Write-Error $ErrMsg
            Write-Warning "No Modules have been Imported or Installed!"
            $global:FunctionResult = "1"
            return
        }
        if ($ModulesFailedInstall.Count -gt 0) {
            if ($ModulesSuccessfullyInstalled.Count -gt 0) {
                Write-Ouptut "The following Modules were successfully installed:`n$($ModulesSuccessfullyInstalled -join "`n")"
            }
            Write-Error "The following Modules failed to install:`n$($ModulesFailedInstall -join "`n")"
            Write-Warning "No Modules have been imported!"
            $global:FunctionResult = "1"
            return
        }
    }

    #$RequiredLocallyAvailableModulesScan | Export-CliXml "$HOME\RequiredLocallyAvailableModules.xml" -Force

    # Now all required modules are available locally, so let's filter to make sure we only try
    # to import the latest versions in case things are side-by-side install
    # Do for PSCoreModules...
    $PSCoreModDeps = $RequiredLocallyAvailableModulesScan.PSCoreModuleDependencies.clone()
    foreach ($ModObj in $PSCoreModDeps) {
        $MatchingModObjs = $RequiredLocallyAvailableModulesScan.PSCoreModuleDependencies | Where-Object {
            $_.ModuleName -eq $ModObj.ModuleName
        }

        $AllVersions = $MatchingModObjs.ManifestFileItem.FullName | foreach {$(Import-PowerShellDataFile $_).ModuleVersion} | foreach {[version]$_}

        if ($AllVersions.Count -gt 1) {
            $VersionsSorted = $AllVersions | Sort-Object | Get-Unique
            $LatestVersion = $VersionsSorted[-1]

            $VersionsToRemove = $VersionsSorted[0..$($VersionsSorted.Count-2)]

            foreach ($Version in $($VersionsToRemove | foreach {$_.ToString()})) {
                [array]$ModObjsToRemove = $MatchingModObjs | Where-Object {
                    $(Import-PowerShellDataFile $_.ManifestFileItem.FullName).ModuleVersion -eq $Version -and $_.ModuleName -eq $ModObj.ModuleName
                }

                foreach ($obj in $ModObjsToRemove) {
                    $RequiredLocallyAvailableModulesScan.PSCoreModuleDependencies.Remove($obj)
                }
            }
        }
    }
    # Do for WinPSModules
    $WinModDeps = $RequiredLocallyAvailableModulesScan.WinPSModuleDependencies.clone()
    foreach ($ModObj in $WinModDeps) {
        $MatchingModObjs = $RequiredLocallyAvailableModulesScan.WinPSModuleDependencies | Where-Object {
            $_.ModuleName -eq $ModObj.ModuleName
        }

        $AllVersions = $MatchingModObjs.ManifestFileItem.FullName | foreach {$(Import-PowerShellDataFile $_).ModuleVersion} | foreach {[version]$_}

        if ($AllVersions.Count -gt 1) {
            $VersionsSorted = $AllVersions | Sort-Object | Get-Unique
            $LatestVersion = $VersionsSorted[-1]

            $VersionsToRemove = $VersionsSorted[0..$($VersionsSorted.Count-2)]

            foreach ($Version in $($VersionsToRemove | foreach {$_.ToString()})) {
                [array]$ModObjsToRemove = $MatchingModObjs | Where-Object {
                    $(Import-PowerShellDataFile $_.ManifestFileItem.FullName).ModuleVersion -eq $Version -and $_.ModuleName -eq $ModObj.ModuleName
                }

                foreach ($obj in $ModObjsToRemove) {
                    $RequiredLocallyAvailableModulesScan.WinPSModuleDependencies.Remove($obj)
                }
            }
        }
    }

    #endregion >> Prep

    $RequiredLocallyAvailableModulesScan

    #region >> Main

    #$RequiredLocallyAvailableModulesScan | Export-CliXml "$HOME\ReqModules.xml" -Force
    
    # Start Importing Modules...
    [System.Collections.ArrayList]$SuccessfulModuleImports = @()
    [System.Collections.ArrayList]$FailedModuleImports = @()
    foreach ($ModObj in $RequiredLocallyAvailableModulesScan.PSCoreModuleDependencies) {
        Write-Verbose "Attempting import of $($ModObj.ModuleName)..."
        try {
            Import-Module $ModObj.ModuleName -Scope Global -NoClobber -Force -ErrorAction Stop -WarningAction SilentlyContinue

            $ModuleInfo = [pscustomobject]@{
                ModulePSCompatibility   = "PSCore"
                ModuleName              = $ModObj.ModuleName
                ManifestFileItem        = $ModObj.ManifestFileItem
            }
            if ([bool]$(Get-Module $ModObj.ModuleName) -and
            $SuccessfulModuleImports.ManifestFileItem.FullName -notcontains $ModuleInfo.ManifestFileItem.FullName
            ) {
                $null = $SuccessfulModuleImports.Add($ModuleInfo)
            }
        }
        catch {
            Write-Verbose "Problem importing module '$($ModObj.ModuleName)'...trying via Manifest File..."

            try {
                Import-Module $ModObj.ManifestFileItem.FullName -Scope Global -NoClobber -Force -ErrorAction Stop -WarningAction SilentlyContinue

                $ModuleInfo = [pscustomobject]@{
                    ModulePSCompatibility   = "PSCore"
                    ModuleName              = $ModObj.ModuleName
                    ManifestFileItem        = $ModObj.ManifestFileItem
                }
                if ([bool]$(Get-Module $ModObj.ModuleName) -and
                $SuccessfulModuleImports.ManifestFileItem.FullName -notcontains $ModuleInfo.ManifestFileItem.FullName
                ) {
                    $null = $SuccessfulModuleImports.Add($ModuleInfo)
                }
            }
            catch {
                $ModuleInfo = [pscustomobject]@{
                    ModulePSCompatibility   = "PSCore"
                    ModuleName              = $ModObj.ModuleName
                    ManifestFileItem        = $ModObj.ManifestFileItem
                }
                if ($FailedModuleImports.ManifestFileItem.FullName -notcontains $ModuleInfo.ManifestFileItem.FullName) {
                    $null = $FailedModuleImports.Add($ModuleInfo)
                }
            }
        }
    }
    foreach ($ModObj in $RequiredLocallyAvailableModulesScan.WinPSModuleDependencies) {
        if ($SuccessfulModuleImports.ModuleName -notcontains $ModObj.ModuleName) {
            Write-Verbose "Attempting import of $($ModObj.ModuleName)..."
            try {
                Remove-Variable -Name "CompatErr" -ErrorAction SilentlyContinue
                $tempfile = [IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName())
                Import-WinModule $ModObj.ModuleName -NoClobber -Force -ErrorVariable CompatErr 2>$tempfile

                if ($CompatErr.Count -gt 0) {
                    Write-Verbose "Import of $($ModObj.ModuleName) failed..."
                    Remove-Module $ModObj.ModuleName -ErrorAction SilentlyContinue
                    Remove-Item $tempfile -Force -ErrorAction SilentlyContinue
                    throw "ModuleNotImportedCleanly"
                }

                # Make sure the PSSession Type Accelerator exists
                $TypeAccelerators = [psobject].Assembly.GetType("System.Management.Automation.TypeAccelerators")::get
                if ($TypeAccelerators.Name -notcontains "PSSession") {
                    [PowerShell].Assembly.GetType("System.Management.Automation.TypeAccelerators")::Add("PSSession","System.Management.Automation.Runspaces.PSSession")
                }
                
                Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                    Import-Module $args[0] -Scope Global -NoClobber -Force -WarningAction SilentlyContinue
                } -ArgumentList $ModObj.ModuleName -ErrorAction Stop

                $ModuleInfo = [pscustomobject]@{
                    ModulePSCompatibility   = "WinPS"
                    ModuleName              = $ModObj.ModuleName
                    ManifestFileItem        = $ModObj.ManifestFileItem
                }

                $ModuleLoadedImplictly = [bool]$(Get-Module $ModObj.ModuleName)
                $ModuleLoadedInPSSession = [bool]$(
                    Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                        Get-Module $args[0]
                    } -ArgumentList $ModObj.ModuleName -ErrorAction SilentlyContinue
                )

                if ($ModuleLoadedImplictly -or $ModuleLoadedInPSSession -and
                $SuccessfulModuleImports.ManifestFileItem.FullName -notcontains $ModuleInfo.ManifestFileItem.FullName
                ) {
                    $null = $SuccessfulModuleImports.Add($ModuleInfo)
                }
            }
            catch {
                Write-Verbose "Problem importing module '$($ModObj.ModuleName)'...trying via Manifest File..."

                try {
                    if ($_.Exception.Message -eq "ModuleNotImportedCleanly") {
                        Write-Verbose "Import of $($ModObj.ModuleName) failed..."
                        throw "FailedImport"
                    }

                    Remove-Variable -Name "CompatErr" -ErrorAction SilentlyContinue
                    $tempfile = [IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName())
                    Import-WinModule $ModObj.ManifestFileItem.FullName -NoClobber -Force -ErrorVariable CompatErr 2>$tempfile

                    if ($CompatErr.Count -gt 0) {
                        Remove-Module $ModObj.ModuleName -ErrorAction SilentlyContinue
                        Remove-Item $tempfile -Force -ErrorAction SilentlyContinue
                    }

                    # Make sure the PSSession Type Accelerator exists
                    $TypeAccelerators = [psobject].Assembly.GetType("System.Management.Automation.TypeAccelerators")::get
                    if ($TypeAccelerators.Name -notcontains "PSSession") {
                        [PowerShell].Assembly.GetType("System.Management.Automation.TypeAccelerators")::Add("PSSession","System.Management.Automation.Runspaces.PSSession")
                    }
                    
                    Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                        Import-Module $args[0] -Scope Global -NoClobber -Force -WarningAction SilentlyContinue
                    } -ArgumentList $ModObj.ManifestFileItem.FullName -ErrorAction Stop

                    $ModuleInfo = [pscustomobject]@{
                        ModulePSCompatibility   = "WinPS"
                        ModuleName              = $ModObj.ModuleName
                        ManifestFileItem        = $ModObj.ManifestFileItem
                    }

                    $ModuleLoadedImplictly = [bool]$(Get-Module $ModObj.ModuleName)
                    $ModuleLoadedInPSSession = [bool]$(
                        Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                            Get-Module $args[0]
                        } -ArgumentList $ModObj.ModuleName -ErrorAction SilentlyContinue
                    )

                    if ($ModuleLoadedImplictly -or $ModuleLoadedInPSSession -and
                    $SuccessfulModuleImports.ManifestFileItem.FullName -notcontains $ModuleInfo.ManifestFileItem.FullName
                    ) {
                        $null = $SuccessfulModuleImports.Add($ModuleInfo)
                    }
                }
                catch {
                    $ModuleInfo = [pscustomobject]@{
                        ModulePSCompatibility   = "WinPS"
                        ModuleName              = $ModObj.ModuleName
                        ManifestFileItem        = $ModObj.ManifestFileItem
                    }
                    if ($FailedModuleImports.ManifestFileItem.FullName -notcontains $ModuleInfo.ManifestFileItem.FullName) {
                        $null = $FailedModuleImports.Add($ModuleInfo)
                    }
                }
            }
        }
    }

    #$SuccessfulModuleImports | Export-CliXml "$HOME\SuccessfulModImports.xml" -Force
    #$FailedModuleImports | Export-CliXml "$HOME\FailedModuleImports.xml" -Force

    # Now that Modules have been imported, we need to figure out which version of PowerShell we should use
    # for each Module. Modules might be able to be imported to PSCore, but NOT have all of their commands
    # available. So, let's filter out, remove, and uninstall all Modules with the least number of commands
    
    # Find all Modules that were successfully imported under both WinPS and PSCore
    $DualImportModules = $SuccessfulModuleImports | Group-Object -Property ModuleName | Where-Object {
        $_.Group.ModulePSCompatibility -contains "PSCore" -and $_.Group.ModulePSCompatibility -contains "WinPS"
    }
    # NOTE: The above $DualImportModules gives you something that looks like the following for each matching ModuleName
    <#
        Count Name                      Group
        ----- ----                      -----
            2 xActiveDirectory          {@{ModulePSCompatibility=PSCore; ModuleName=xActiveDirectory; ManifestFileItem=C:\Program Files\PowerShell\Modules\xActiveDi...
    #>
    # And each Group provides...
    <#
        ModulePSCompatibility ModuleName                   ManifestFileItem
        --------------------- ----------                   ----------------
        PSCore                xActiveDirectory             C:\Program Files\PowerShell\Modules\xActiveDirectory\2.19.0.0\xActiveDirectory.psd1
        WinPS                 xActiveDirectory             C:\Program Files\WindowsPowerShell\Modules\xActiveDirectory\2.19.0.0\xActiveDirectory.psd1
    #>
    
    foreach ($ModObjGroup in $DualImportModules) {
        $ModuleName = $ModObjGroup.Name

        # Check to see how many ExportedCommands are available in PSCore
        $PSCoreCmdCount = $($(Get-Module $ModuleName).ExportedCommands.Keys | Sort-Object | Get-Unique).Count

        # Check to see how many ExportedCommands are available in WinPS
        $WinPSCmdCount = Invoke-WinCommand -ComputerName localhost -ScriptBlock {
            $($(Get-Module $args[0]).ExportedCommands.Keys | Sort-Object | Get-Unique).Count
        } -ArgumentList $ModuleName

        if ($PSCoreCmdCount -ge $WinPSCmdCount) {
            Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                Remove-Module $args[0] -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                Uninstall-Module $args[0] -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            } -ArgumentList $ModuleName

            $ObjectToRemove = $ModObjGroup.Group | Where-Object {$_.ModulePSCompatibility -eq "WinPS"}
            $null = $SuccessfulModuleImports.Remove($ObjectToRemove)
        }

        if ($PSCoreCmdCount -lt $WinPSCmdCount) {
            Remove-Module $ModuleName -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            Uninstall-Module $ModuleName -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

            $ObjectToRemove = $ModObjGroup.Group | Where-Object {$_.ModulePSCompatibility -eq "PSCore"}
            $null = $SuccessfulModuleImports.Remove($ObjectToRemove)
        }
    }

    if ($FailedModuleImports.Count -gt 0) {
        if ($PSVersionTable.PSEdition -ne "Core") {
            $AcceptableUnloadedModules = @("Microsoft.PowerShell.Core","WindowsCompatibility")
        }
        else {
            $AcceptableUnloadedModules = @()
        }

        [System.Collections.Arraylist]$UnacceptableUnloadedModules = @()
        foreach ($ModObj in $FailedModuleImports) {
            if ($AcceptableUnloadedModules -notcontains $ModObj.ModuleName -and
            $SuccessfulModuleImports.ModuleName -notcontains $ModObj.ModuleName
            ) {
                $null = $UnacceptableUnloadedModules.Add($ModObj)
            }
        }

        #$UnacceptableUnloadedModules | Export-CliXml "$HOME\UnacceptableUnloadedModules.xml" -Force

        if ($UnacceptableUnloadedModules.Count -gt 0) {
            $WrnMsgA = "The following Modules were not able to be loaded via implicit remoting:`n$($UnacceptableUnloadedModules.ModuleName -join "`n")"
            $WrnMsgB = "All code within '$InvocationMethod' that uses these Modules must be refactored similar to:`n" +
            "Invoke-WinCommand -ComputerName localhost -ScriptBlock {`n    <existing code>`n}"
            $WrnMsgC = "'$InvocationMethod' will probably *not* work in PowerShell Core!"
            Write-Warning $WrnMsgA
            Write-Warning $WrnMsgB
            Write-Warning $WrnMsgC
        }
    }

    # Uninstall the versions of Modules that don't work
    $AllLocallyAvailableModules = foreach ($ModPath in $AllWindowsPSModulePaths) {
        if (Test-Path $ModPath) {
            $ModuleBases = $(Get-ChildItem -Path $ModPath -Directory).FullName

            foreach ($ModuleBase in $ModuleBases) {
                [pscustomobject]@{
                    ModuleName          = $($ModuleBase | Split-Path -Leaf)
                    ManifestFileItem    = $(Get-ChildItem -Path $ModuleBase -Recurse -File -Filter "*.psd1")
                }
            }
        }
    }

    foreach ($ModObj in $SuccessfulModuleImports) {
        $ModulesToUninstall = $AllLocallyAvailableModules | Where-Object {
            $_.ModuleName -eq $ModObj.ModuleName -and
            $_.ManifestFileItem.FullName -ne $ModObj.ManifestFileItem.FullName
        }

        foreach ($ModObj2 in $ModulesToUninstall) {
            if ($ModObj2.ModuleManifestFileItem.FullName -match "\\PowerShell\\") {
                Remove-Module $ModObj2.ModuleName -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                Uninstall-Module $ModObj2.ModuleName -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            }
            if ($ModObj2.ModuleManifestFileItem.FullName -match "\\WindowsPowerShell\\") {
                Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                    Remove-Module $args[0] -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                    Uninstall-Module $args[0] -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                } -ArgumentList $ModObj2.ModuleName
            }
        }
    }

    [pscustomobject]@{
        SuccessfulModuleImports         = $SuccessfulModuleImports
        FailedModuleImports             = $FailedModuleImports
        UnacceptableUnloadedModules     = $UnacceptableUnloadedModules
    }
}

# SIG # Begin signature block
# MIIMaAYJKoZIhvcNAQcCoIIMWTCCDFUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUfQBMrlM9AY/1axKGvkwqwCAL
# Vd2gggndMIIEJjCCAw6gAwIBAgITawAAADqEP46TDmc/hQAAAAAAOjANBgkqhkiG
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
# BDEWBBQawIp85aFkvsDb1S82g1ZAzvO1pjANBgkqhkiG9w0BAQEFAASCAQBsDnSW
# lqVYWiwwhQ/C1dWPpBla2YyKlFSY6aq83DC/4AV2wRY/qmbLKF/pWh97ExPwWfPj
# wVzBAp2OG6FVHaF6CXl123568s7kQQ29FVGZwkXJTnmZ8gMw9sgffrJUY6EmiJmZ
# 9QmfZThwdnpowy0bPg4UCdSz2AJ2Hdp48MO4sfytpCEzkL87WSbfmjnHPPptooSA
# /5Ne74qDqBLJ4jNRz9BMf+r9ESRBE/8MAuWa6/osFoGm3llSY6ITfmjhqECefuG3
# PxoRJWAXF0YTNVkDSYawW0QZFPW1gpgUUKAfNzYfSFQsRJ6jeDsUfKhix+4vW+F1
# B2IrXVUEoGWgdY1o
# SIG # End signature block
