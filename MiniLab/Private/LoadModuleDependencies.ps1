function LoadModuleDependencies {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        $ModuleDependencies
    )

    $ModuleDependenciesProperties = $($ModuleDependencies | Get-Member).Name
    if ($ModuleDependenciesProperties -notcontains "WinPSModuleDependencies" -and
    $ModuleDependenciesProperties -notcontains "PSCoreModuleDependencies") {
        $ErrMsg = "The object passed to the -ModuleDependencies parameter does not have Properties called" +
        "'WinPSModuleDependencies' and 'PSCoreModuleDependencies'! Halting!"
        Write-Error $ErrMsg
        $global:FunctionResult = "1"
        return
    }

    if ($ModuleDependencies.WinPSModuleDependencies.Count -gt 0 -or
    $ModuleDependencies.PSCoreModuleDependencies.Count -gt 0) {
        [System.Collections.ArrayList]$ModulesSuccessfullyLoaded = @()
        [System.Collections.ArrayList]$ModulesFailedToLoad = @()

        # If we're in PowerShell Core, we need to import all necessary WinPS Modules via Import-WinModule
        # from the WindowsCompatibility Module
        if ($PSVersionTable.PSEdition -eq "Core" -and $PSVersionTable.Platform -eq "Win32NT") {
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

            foreach ($WinPSModuleObject in $ModuleDependencies.WinPSModuleDependencies) {
                try {
                    Import-WinModule $WinPSModuleObject.ModuleName -ErrorAction Stop
                    $null = $ModulesSuccessfullyLoaded.Add($WinPSModuleObject)
                }
                catch {
                    $ModuleManifestPath = $WinPSModuleObject.ManifestFileItem.FullName
                    if (!$ModuleManifestPath) {
                        $null = $ModulesFailedToLoad.Add($WinPSModuleObject)
                        continue
                    }

                    try {
                        Import-WinModule $ModuleManifestPath -ErrorAction Stop
                        $null = $ModulesSuccessfullyLoaded.Add($WinPSModuleObject)
                    }
                    catch {
                        $null = $ModulesFailedToLoad.Add($WinPSModuleObject)
                    }
                }
            }

            foreach ($PSCoreModuleObject in $ModuleDependencies.PSCoreModuleDependencies) {
                try {
                    Import-Module $PSCoreModuleObject.ModuleName -ErrorAction Stop
                    $null = $ModulesSuccessfullyLoaded.Add($PSCoreModuleObject)
                }
                catch {
                    $ModuleManifestPath = $PSCoreModuleObject.ManifestFileItem.FullName
                    if (!$ModuleManifestPath) {
                        $null = $ModulesFailedToLoad.Add($PSCoreModuleObject)
                        continue
                    }

                    try {
                        Import-Module $ModuleManifestPath -ErrorAction Stop
                        $null = $ModulesSuccessfullyLoaded.Add($PSCoreModuleObject)
                    }
                    catch {
                        $null = $ModulesFailedToLoad.Add($PSCoreModuleObject)
                    }
                }
            }
        }

        if ($PSVersionTable.PSEdition -ne "Core") {
            foreach ($WinPSModuleObject in $ModuleDependencies.WinPSModuleDependencies) {
                try {
                    Import-Module $WinPSModuleObject.ModuleName -ErrorAction Stop
                    $null = $ModulesSuccessfullyLoaded.Add($WinPSModuleObject)
                }
                catch {
                    $ModuleManifestPath = $WinPSModuleObject.ManifestFileItem.FullName
                    if (!$ModuleManifestPath) {
                        $null = $ModulesFailedToLoad.Add($WinPSModuleObject)
                        continue
                    }

                    try {
                        Import-Module $ModuleManifestPath -ErrorAction Stop
                        $null = $ModulesSuccessfullyLoaded.Add($WinPSModuleObject)
                    }
                    catch {
                        $null = $ModulesFailedToLoad.Add($WinPSModuleObject)
                    }
                }
            }

            foreach ($PSCoreModuleObject in $ModuleDependencies.PSCoreModuleDependencies) {
                try {
                    Import-Module $PSCoreModuleObject.ModuleName -ErrorAction Stop
                    $null = $ModulesSuccessfullyLoaded.Add($PSCoreModuleObject)
                }
                catch {
                    $ModuleManifestPath = $PSCoreModuleObject.ManifestFileItem.FullName
                    if (!$ModuleManifestPath) {
                        $null = $ModulesFailedToLoad.Add($PSCoreModuleObject)
                        continue
                    }

                    try {
                        Import-Module $ModuleManifestPath -ErrorAction Stop
                        $null = $ModulesSuccessfullyLoaded.Add($PSCoreModuleObject)
                    }
                    catch {
                        $null = $ModulesFailedToLoad.Add($PSCoreModuleObject)
                    }
                }
            }
        }
    }
}