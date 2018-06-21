function InvokePSCompatibility {
    [CmdletBinding()]
    Param (
        # $InvocationMethod determines if the GetModuleDependencies function scans a file or loaded function
        [Parameter(Mandatory=$False)]
        [string]$InvocationMethod = $script:MyInvocation.MyCommand.Name, 

        [Parameter(Mandatory=$False)]
        [string[]]$ModulesAvailableLocally,

        [Parameter(Mandatory=$False)]
        [string[]]$ModulesAvailableExternally,

        [Parameter(Mandatory=$False)]
        [switch]$InstallModulesNotAvailableLocally = $True
    )

    #region >> Prep

    if ($PSVersionTable.PSEdition -ne "Core" -or
    $($PSVersionTable.PSEdition -ne "Core" -and $PSVersionTable.Platform -ne "Win32NT")) {
        Write-Error "This function is only meant to be used with PowerShell Core on Windows! Halting!"
        $global:FunctionResult = "1"
        return
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
        $ModuleBase = $(Get-ChildItem -Path $ModPath -Directory -Filter).FullName

        [pscustomobject]@{
            ModuleName          = $LocalModule
            ManifestFileItem    = $(Get-ChildItem -Path $ModuleBase -Recurse -File -Filter "*.psd1")
        }
    }

    if (![bool]$(Get-Module -ListAvailable WindowsCompatibility)) {
        try {
            Install-Module WindowsCompatibility -ErrorAction Stop
        }
        catch {
            Write-Error "Problem installing the Windows Compatibility Module! Halting!"
        }
    }
    if (![bool]$(Get-Module WindowsCompatibility)) {
        Import-Module WindowsCompatibility
    }

    # Scan Script/Function/Module to get an initial list of Required Locally Available Modules
    try {
        # Below $RequiredLocallyAvailableModules is a PSCustomObject with properties WinPSModuleDependencies
        # and PSCoreModuleDependencies - both of which are [System.Collections.ArrayList]

        # If $InvocationMethod is a file, then GetModuleDependencies can use $PSCommandPath as the value
        # for -PathToScriptFile

        $ExplicitlyNeededModules = $ModulesAvailableLocally + $ModulesAvailableExternally

        $GetModDepsSplatParams = @{}

        if (![string]::IsNullOrWhitespace($InvocationMethod)) {
            if ($InvocationMethod -match "\.ps") {
                if (!$(Test-Path $script:PSCommandPath)) {
                    Write-Error "The `$script:PSCommandPath '$script:PSCommandPath' was not found! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
                $GetModDepsSplatParams.Add("PathToScriptFile",$script:PSCommandPath)
            }
            else {
                $GetModDepsSplatParams.Add("NameOfLoadedFunction",$InvocationMethod)
            }
        }
        if ($ExplicitlyNeededModules -ne $null) {
            $GetModDepsSplatParams.Add("ExplicitlyNeededModules",$ExplicitlyNeededModules)
        }

        if ($GetModDepsSplatParams.Keys.Count -gt 0) {
            $GetModDepsSplatParams | Export-CliXml "$HOME\GetModDepsSplatParams.xml"
            $RequiredLocallyAvailableModulesScan = GetModuleDependencies @GetModDepsSplatParams
        }
    }
    catch {
        Write-Error $_
        Write-Error "Problem with enumerating Module Dependencies using GetModuleDependencies! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$RequiredLocallyAvailableModulesScan) {
        Write-Host "InvokePSCompatibility reports that no additional modules need to be loaded." -ForegroundColor Green
        return
    }

    # Determine whether the Modules passed to $ModulesAvailableLocally are covered by
    # $RequiredLocallyAvailableModulesScan.WinPSModuleDependencies or
    # $RequiredLocallyAvailableModulesScan.PSCoreModuleDependencies
    # If not, add them
    [System.Collections.ArrayList]$LocalModulesNotFoundLocally = @()
    foreach ($LocalModule in $ModulesAvailableLocally) {
        # Determine if $LocalModule is a PSCore or WinPS Module
        $LocalModuleInfo = foreach ($ModPath in $AllWindowsPSModulePaths) {
            $ModuleBase = $(Get-ChildItem -Path $ModPath -Directory -Filter $LocalModule).FullName

            [pscustomobject]@{
                ModuleName          = $LocalModule
                ManifestFileItem    = $(Get-ChildItem -Path $ModuleBase -Recurse -File -Filter "*.psd1")
            }
        }

        if ($LocalModuleDirectoryItems.Count -eq 0) {
            $null = $LocalModulesNotFoundLocally.Add($LocalModule)
            continue
        }
        
        foreach ($ManifestItem in $LocalModuleInfo.ManifestFileItem) {
            if ($ManifestItem.FullName -match "\\WindowsPowerShell\\") {
                if ($RequiredLocallyAvailableModulesScan.WinPSModuleDependencies.ManifestFileItem.FullName -notcontains
                $LocalModuleInfo.ManifestFileItem.FullName
                ) {
                    $null = $RequiredLocallyAvailableModulesScan.WinPSModuleDependencies.Add($LocalModuleInfo)
                }
            }
            if ($ManifestItem.FullName -match "\\PowerShell\\") {
                if ($RequiredLocallyAvailableModulesScan.PSCoreModuleDependencies.ManifestFileItem.FullName -notcontains
                $LocalModuleInfo.ManifestFileItem.FullName
                ) {
                    $null = $RequiredLocallyAvailableModulesScan.PSCoreModuleDependencies.Add($LocalModuleInfo)
                }
            }
        }
    }

    if ($LocalModulesNotFoundLocally.Count -gt 0) {
        $WrnMsg = "The following Modules specified by the user as Locally Available were not found:" +
        "`n$($LocalModulesNotFoundLocally -join "`n")"
        Write-Warning $WrnMsg
    }

    if ($LocalModulesNotFoundLocally.Count -gt 0) {
        # Since there's currently no way to know if external Modules are actually compatible with PowerShell Core
        # until we try and load them, we just need to attempt to install them under both WinPS and PSCore
        foreach ($ModuleName in $LocalModulesNotFoundLocally) {
            try {
                if (![bool]$(Get-Module -ListAvailable $ModuleName) -and $InstallModulesNotAvailableLocally) {
                    Install-Module $ModuleName -Force -ErrorAction Stop -WarningAction SilentlyContinue
                }

                $ModObj = [pscustomobject]@{
                    ModuleName          = $ModuleName
                    ManifestFileItem    = $(Get-Item $(Get-Module -ListAvailable $ModuleName).Path)
                }

                $null = $RequiredLocallyAvailableModulesScan.PSCoreModuleDependencies.Add($ModObj)
            }
            catch {
                Write-Warning $($_ | Out-String)
            }

            try {
                # Make sure the PSSession Type Accelerator exists
                $TypeAccelerators = [psobject].Assembly.GetType("System.Management.Automation.TypeAccelerators")::get
                if ($TypeAccelerators.Name -notcontains "PSSession") {
                    [PowerShell].Assembly.GetType("System.Management.Automation.TypeAccelerators")::Add("PSSession","System.Management.Automation.Runspaces.PSSession")
                }

                $ManifestFileItem = Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                    if (![bool]$(Get-Module -ListAvailable $args[0]) -and $args[1]) {
                        Install-Module $args[0] -Force
                    }
                    $(Get-Item $(Get-Module -ListAvailable $args[0]).Path)
                } -ArgumentList $ModuleName,$InstallModulesNotAvailableLocally -ErrorAction Stop -WarningAction SilentlyContinue

                if ($ManifestFileItem) {
                    $ModObj = [pscustomobject]@{
                        ModuleName          = $ModuleName
                        ManifestFileItem    = $ManifestFileItem
                    }

                    $null = $RequiredLocallyAvailableModulesScan.WinPSModuleDependencies.Add($ModObj)
                }
            }
            catch {
                Write-Warning $($_ | Out-String)
            }
        }
    }

    # Next, determine whether the Modules passed to $ModulesAvailableExternally are covered by
    # $RequiredLocallyAvailableModulesScan.WinPSModuleDependencies or
    # $RequiredLocallyAvailableModulesScan.PSCoreModuleDependencies
    # If not, install and add them
    foreach ($ModuleName in $ModulesAvailableExternally) {
        try {
            if (![bool]$(Get-Module -ListAvailable $ModuleName) -and $InstallModulesNotAvailableLocally) {
                Install-Module $ModuleName -Force -ErrorAction Stop -WarningAction SilentlyContinue
            }

            $ModObj = [pscustomobject]@{
                ModuleName          = $ModuleName
                ManifestFileItem    = $(Get-Item $(Get-Module -ListAvailable $ModuleName).Path)
            }

            if ($RequiredLocallyAvailableModulesScan.PSCoreModuleDependencies.ManifestFileItem.FullName -notcontains
            $ModObj.ManifestFileItem.FullName
            ) {
                $null = $RequiredLocallyAvailableModulesScan.PSCoreModuleDependencies.Add($ModObj)
            }
        }
        catch {
            Write-Warning $($_ | Out-String)
        }

        try {
            # Make sure the PSSession Type Accelerator exists
            $TypeAccelerators = [psobject].Assembly.GetType("System.Management.Automation.TypeAccelerators")::get
            if ($TypeAccelerators.Name -notcontains "PSSession") {
                [PowerShell].Assembly.GetType("System.Management.Automation.TypeAccelerators")::Add("PSSession","System.Management.Automation.Runspaces.PSSession")
            }

            $ManifestFileItem = Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                if (![bool]$(Get-Module -ListAvailable $args[0]) -and $args[1]) {
                    Install-Module $args[0] -Force
                }
                $(Get-Item $(Get-Module -ListAvailable $args[0]).Path)
            } -ArgumentList $ModuleName,$InstallModulesNotAvailableLocally -ErrorAction Stop -WarningAction SilentlyContinue

            if ($ManifestFileItem) {
                $ModObj = [pscustomobject]@{
                    ModuleName          = $ModuleName
                    ManifestFileItem    = $ManifestFileItem
                }

                if ($RequiredLocallyAvailableModulesScan.WinPSModuleDependencies.ManifestFileItem.FullName -notcontains
                $ModObj.ManifestFileItem.FullName
                ) {
                    $null = $RequiredLocallyAvailableModulesScan.WinPSModuleDependencies.Add($ModObj)
                }
            }
        }
        catch {
            Write-Warning $($_ | Out-String)
        }
    }

    $RequiredLocallyAvailableModulesScan | Export-CliXml "$HOME\ReqModScanPriorToFilter.xml"

    # Now all required modules are available locally, so let's filter to make sure we only try
    # to import the latest versions in case things are side-by-side install
    # Do for PSCoreModules...
    $PSCoreModDeps = $RequiredLocallyAvailableModulesScan.PSCoreModuleDependencies.clone()
    foreach ($ModObj in $PSCoreModDeps) {
        $MatchingModObjs = $RequiredLocallyAvailableModulesScan.PSCoreModuleDependencies | Where-Object {
            $_.ModuleName -eq $ModObj.ModuleName
        }

        $AllVersionsPrep = $MatchingModObjs.ManifestFileItem.FullName | Split-Path -Parent
        
        
        $AllVersions = foreach ($PotentialVersionPath in $AllVersionsPrep) {
            $PotentialVersionString = $PotentialVersionPath | Split-Path -Leaf

            $VersionCheck = [bool]$(
                try{
                    [version]$PotentialVersionString
                }
                catch{
                    Write-Verbose "'$PotentialVersionString' is not a version number..."
                }
            )

            if ($VersionCheck) {
                $PotentialVersionString
            }
        }

        if ($AllVersions.Count -gt 1) {
            $VersionsSorted = $AllVersions | Sort-Object | Get-Unique
            $LatestVersion = $VersionsSorted[-1]

            $VersionsToRemove = $VersionsSorted[0..$($VersionsSorted.Count-2)]

            foreach ($Version in $($VersionsToRemove | foreach {$_.ToString()})) {
                [array]$ModObjsToRemove = $RequiredLocallyAvailableModulesScan.PSCoreModuleDependencies | Where-Object {
                    $_.ManifestFileItem.FullName -match "\\$Version\\" -and $_.ModuleName -eq $ModObj.ModuleName
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

        $AllVersionsPrep = $MatchingModObjs.ManifestFileItem.FullName | Split-Path -Parent
        
        $AllVersions = foreach ($PotentialVersionPath in $AllVersionsPrep) {
            $PotentialVersionString = $PotentialVersionPath | Split-Path -Leaf

            $VersionCheck = [bool]$(
                try{
                    [version]$PotentialVersionString
                }
                catch{
                    Write-Verbose "'$PotentialVersionString' is not a version number..."
                }
            )

            if ($VersionCheck) {
                $PotentialVersionString
            }
        }

        if ($AllVersions.Count -gt 1) {
            $VersionsSorted = $AllVersions | Sort-Object | Get-Unique
            $LatestVersion = $VersionsSorted[-1]

            $VersionsToRemove = $VersionsSorted[0..$($VersionsSorted.Count-2)]

            foreach ($Version in $($VersionsToRemove | foreach {$_.ToString()})) {
                [array]$ModObjsToRemove = $RequiredLocallyAvailableModulesScan.WinPSModuleDependencies | Where-Object {
                    $_.ManifestFileItem.FullName -match "\\$Version\\" -and $_.ModuleName -eq $ModObj.ModuleName
                }

                foreach ($obj in $ModObjsToRemove) {
                    $RequiredLocallyAvailableModulesScan.WinPSModuleDependencies.Remove($obj)
                }
            }
        }
    }

    $RequiredLocallyAvailableModulesScan | Export-CliXml "$HOME\ReqModScan.xml"

    #endregion >> Prep


    #region >> Main
    
    # Start Importing Modules...
    [System.Collections.ArrayList]$SuccessfulModuleImports = @()
    [System.Collections.ArrayList]$FailedModuleImports = @()
    foreach ($ModObj in $RequiredLocallyAvailableModulesScan.PSCoreModuleDependencies) {
        try {
            Import-Module $ModObj.ModuleName -Scope Global -NoClobber -Force -ErrorAction Stop

            $ModuleInfo = [pscustomobject]@{
                ModulePSCompatibility   = "PSCore"
                ModuleName              = $ModObj.ModuleName
                ManifestFileItem        = $ModObj.ManifestFileItem
            }
            if ([bool]$(Get-Module $ModObj.ModuleName)) {
                $null = $SuccessfulModuleImports.Add($ModuleInfo)
            }
        }
        catch {
            Write-Verbose "Problem importing module '$($ModObj.ModuleName)'...trying via Manifest File..."

            try {
                Import-Module $ModObj.ManifestFileItem.FullName -Scope Global -NoClobber -Force -ErrorAction Stop

                $ModuleInfo = [pscustomobject]@{
                    ModulePSCompatibility   = "PSCore"
                    ModuleName              = $ModObj.ModuleName
                    ManifestFileItem        = $ModObj.ManifestFileItem
                }
                if ([bool]$(Get-Module $ModObj.ModuleName)) {
                    $null = $SuccessfulModuleImports.Add($ModuleInfo)
                }
            }
            catch {
                $ModuleInfo = [pscustomobject]@{
                    ModulePSCompatibility   = "PSCore"
                    ModuleName              = $ModObj.ModuleName
                    ManifestFileItem        = $ModObj.ManifestFileItem
                }
                $null = $FailedModuleImports.Add($ModuleInfo)
            }
        }
    }
    foreach ($ModObj in $RequiredLocallyAvailableModulesScan.WinPSModuleDependencies) {
        try {
            Remove-Variable -Name "CompatErr" -ErrorAction SilentlyContinue
            $tempfile = [IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName())
            Import-WinModule $ModObj.ModuleName -NoClobber -Force -ErrorVariable CompatErr 2>$tempfile

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
                Import-Module $args[0] -Scope Global -NoClobber -Force
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

            if ($ModuleLoadedImplictly -or $ModuleLoadedInPSSession) {
                $null = $SuccessfulModuleImports.Add($ModuleInfo)
            }
        }
        catch {
            Write-Verbose "Problem importing module '$($ModObj.ModuleName)'...trying via Manifest File..."

            try {
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
                    Import-Module $args[0] -Scope Global -NoClobber -Force
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

                if ($ModuleLoadedImplictly -or $ModuleLoadedInPSSession) {
                    $null = $SuccessfulModuleImports.Add($ModuleInfo)
                }
            }
            catch {
                $ModuleInfo = [pscustomobject]@{
                    ModulePSCompatibility   = "WinPS"
                    ModuleName              = $ModObj.ModuleName
                    ManifestFileItem        = $ModObj.ManifestFileItem
                }
                $null = $FailedModuleImports.Add($ModuleInfo)
            }
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

        if ($UnacceptableUnloadedModules.Count -gt 0) {
            Write-Warning "The following Modules were not able to be loaded:`n$($UnacceptableUnloadedModules.ModuleName -join "`n")"
            Write-Warning "'$InvocationMethod' will probably not work with PowerShell Core..."
        }
    }

    $FinalSuccessfulModuleImports = foreach ($ModObj in $SuccessfulModuleImports) {
        if ($ModObj.ModulePSCompatibility -eq "WinPS") {
            $ModObj
        }
        
        if ($ModObj.ModulePSCompatibility -eq "PSCore" -and $PSVersionTable.PSEdition -eq "Core" -and
        [bool]$(Get-Module $ModObj.ModuleName)
        ) {
            $ModObj
        }
    }

    # Uninstall the versions of Modules that don't work
    $AllLocallyAvailableModules = foreach ($ModPath in $AllWindowsPSModulePaths) {
        $ModuleBase = $(Get-ChildItem -Path $ModPath -Directory -Filter).FullName

        [pscustomobject]@{
            ModuleName          = $LocalModule
            ManifestFileItem    = $(Get-ChildItem -Path $ModuleBase -Recurse -File -Filter "*.psd1")
        }
    }
    foreach ($ModObj in $FinalSuccessfulModuleImports) {
        $ModulesToUninstall = $AllLocallyAvailableModules | Where-Object {
            $_.ModuleName -eq $ModObj.ModuleName -and
            $_.ManifestFileItem.FullName -ne $ModObj.ManifestFileItem.FullName
        }

        foreach ($ModObj2 in $ModulesToUninstall) {
            if ($ModObj2.ModuleManifestFileItem.FullName -match "\\PowerShell\\") {
                Remove-Module $ModObj2.ModuleName -Force -ErrorAction SilentlyContinue
                Uninstall-Module $ModObj2.ModuleName -Force -ErrorAction SilentlyContinue
            }
            if ($ModObj2.ModuleManifestFileItem.FullName -match "\\WindowsPowerShell\\") {
                Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                    Remove-Module $args[0] -Force -ErrorAction SilentlyContinue
                    Uninstall-Module $args[0] -Force -ErrorAction SilentlyContinue
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
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU0SPfa0M5QyDGGIYDc2TVBX3A
# Tfygggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFFuKImDl+t5VXFO9
# QTI9VmbJ/ytgMA0GCSqGSIb3DQEBAQUABIIBAJr4XKceRFkUmP2w5puzYc7lrZj6
# msh5UMxr+FdykMuf3tLz1hJBJsjMGlC0r5TLofQzzPgX7CCHAQx2cIm1FFeWlXYb
# lHLW9aNbTsdwKMsOImr+sRSnV1s4+iBB4zVH4Si88rtDmg+BxpctfGIK/ZZfRJIP
# iNm8FWg9zzg0c/oqYD8X6z6soJYZmKrdwuMOCAtcWDfdcPXC2cf97N2RlXBx1d6R
# GaHF2o5e/Yf3mirXk8LZnPWo/eSifzVtjtwhnruTAfsGCokBqV+MsglvEYDcIWBV
# GNE1uJxPCKQYNBbOPmE7ZeVY9NlCx/tzIStHfYzcWyYkZZjCyJWRMVoNdUo=
# SIG # End signature block
