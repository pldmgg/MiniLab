function InvokePSCompatibility {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [string]$PathToPS1OrPSM1,

        [Parameter(Mandatory=$False)]
        [string[]]$ModuleDependenciesThatMayNotBeInstalled
    )

    #region >> Helper Functions

    function GetModuleDependencies {
        [CmdletBinding(DefaultParameterSetName="LoadedFunction")]
        Param (
            [Parameter(
                Mandatory=$True,
                ParameterSetName="LoadedFunction"
            )]
            [string]$NameOfLoadedFunction,

            [Parameter(
                Mandatory=$True,
                ParameterSetName="ScriptFile"    
            )]
            [string]$PathToScriptFile
        )

        if ($NameOfLoadedFunction) {
            $LoadedFunctions = Get-ChildItem Function:\
            if ($LoadedFunctions.Name -notcontains $NameOfLoadedFunction) {
                Write-Error "The function '$NameOfLoadedFunction' is not currently loaded! Halting!"
                $global:FunctionResult = "1"
                return
            }

            $FunctionOrScriptContent = Invoke-Expression $('${Function:' + $NameOfLoadedFunction + '}.Ast.Extent.Text')
        }
        if ($PathToScriptFile) {
            if (!$(Test-Path $PathToScriptFile)) {
                Write-Error "Unable to find path '$PathToScriptFile'! Halting!"
                $global:FunctionResult = "1"
                return
            }

            $FunctionOrScriptContent = Get-Content $PathToScriptFile
        }
        <#
        $ExplicitlyDefinedFunctionsInThisFunction = [Management.Automation.Language.Parser]::ParseInput($FunctionOrScriptContent, [ref]$null, [ref]$null).EndBlock.Statements.FindAll(
            [Func[Management.Automation.Language.Ast,bool]]{$args[0] -is [Management.Automation.Language.FunctionDefinitionAst]},
            $false
        ).Name
        #>

        # All Potential PSModulePaths
        $AllWindowsPSModulePaths = @(
            "C:\Program Files\WindowsPowerShell\Modules"
            "$HOME\Documents\WindowsPowerShell\Modules"
            "$HOME\Documents\PowerShell\Modules"
            "C:\Program Files\PowerShell\Modules"
            "C:\Windows\System32\WindowsPowerShell\v1.0\Modules"
            "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\Modules"
        )

        $AllModuleManifestFileItems = foreach ($ModPath in $AllWindowsPSModulePaths) {
            Get-ChildItem -Path $ModPath -Recurse -File -Filter "*.psd1"
        }

        $ModInfoFromManifests = foreach ($ManFileItem in $AllModuleManifestFileItems) {
            try {
                $ModManifestData = Import-PowerShellDataFile $ManFileItem.FullName -ErrorAction Stop
            }
            catch {
                continue
            }

            $Functions = $ModManifestData.FunctionsToExport | Where-Object {
                ![System.String]::IsNullOrWhiteSpace($_) -and $_ -ne '*'
            }
            $Cmdlets = $ModManifestData.CmdletsToExport | Where-Object {
                ![System.String]::IsNullOrWhiteSpace($_) -and $_ -ne '*'
            }

            @{
                ModuleName          = $ManFileItem.BaseName
                ManifestFileItem    = $ManFileItem
                ModuleManifestData  = $ModManifestData
                ExportedCommands    = $Functions + $Cmdlets
            }
        }
        $ModInfoFromGetCommand = Get-Command -CommandType Cmdlet,Function,Workflow

        [System.Collections.ArrayList]$AutoFunctionsInfo = @()

        foreach ($ModInfoObj in $ModInfoFromManifests) {
            if ($AutoFunctionsInfo.ModuleName -notcontains $ModInfoObj.ModuleName) {
                $PSObj = [pscustomobject]@{
                    ModuleName          = $ModInfoObj.ModuleName
                    ManifestFileItem    = $ModInfoObj.ManifestFileItem
                    ExportedCommands    = $ModInfoObj.ExportedCommands
                }
                $null = $AutoFunctionsInfo.Add($PSObj)
            }
        }
        foreach ($ModInfoObj in $ModInfoFromGetCommand) {
            $PSObj = [pscustomobject]@{
                ModuleName          = $ModInfoObj.ModuleName
                ExportedCommands    = $ModInfoObj.Name
            }
            $null = $AutoFunctionsInfo.Add($PSObj)
        }

        $FunctionRegex = "([a-zA-Z]|[0-9])+-([a-zA-Z]|[0-9])+"
        $LinesWithFunctions = $FunctionOrScriptContent -match $FunctionRegex | Where-Object {![bool]$($_ -match "[\s]+#")}
        $FinalFunctionList = $($LinesWithFunctions | Select-String -Pattern $FunctionRegex -AllMatches).Matches.Value | Sort-Object | Get-Unique
        
        [System.Collections.ArrayList]$NeededWinPSModules = @()
        [System.Collections.ArrayList]$NeededPSCoreModules = @()
        foreach ($ModObj in $AutoFunctionsInfo) {
            foreach ($Func in $FinalFunctionList) {
                if ($ModObj.ExportedCommands -contains $Func) {
                    if ($ModObj.ManifestFileItem.FullName -match "\\WindowsPowerShell\\") {
                        if ($NeededWinPSModules.ManifestFileItem.FullName -notcontains $ModObj.ManifestFileItem.FullName -and
                        $ModObj.ModuleName -notmatch "\.WinModule") {
                            $PSObj = [pscustomobject]@{
                                ModuleName          = $ModObj.ModuleName
                                ManifestFileItem    = $ModObj.ManifestFileItem
                            }
                            $null = $NeededWinPSModules.Add($PSObj)
                        }
                    }
                    elseif ($ModObj.ManifestFileItem.FullName -match "\\PowerShell\\") {
                        if ($NeededPSCoreModules.ManifestFileItem.FullName -notcontains $ModObj.ManifestFileItem.FullName -and
                        $ModObj.ModuleName -notmatch "\.WinModule") {
                            $PSObj = [pscustomobject]@{
                                ModuleName          = $ModObj.ModuleName
                                ManifestFileItem    = $ModObj.ManifestFileItem
                            }
                            $null = $NeededPSCoreModules.Add($PSObj)
                        }
                    }
                    elseif ($PSVersionTable.PSEdition -eq "Core") {
                        if ($NeededPSCoreModules.ModuleName -notcontains $ModObj.ModuleName -and
                        $ModObj.ModuleName -notmatch "\.WinModule") {
                            $PSObj = [pscustomobject]@{
                                ModuleName          = $ModObj.ModuleName
                                ManifestFileItem    = $null
                            }
                            $null = $NeededPSCoreModules.Add($PSObj)
                        }
                    }
                    else {
                        if ($NeededWinPSModules.ModuleName -notcontains $ModObj.ModuleName) {
                            $PSObj = [pscustomobject]@{
                                ModuleName          = $ModObj.ModuleName
                                ManifestFileItem    = $null
                            }
                            $null = $NeededWinPSModules.Add($PSObj)
                        }
                    }
                }
            }
        }

        [pscustomobject]@{
            WinPSModuleDependencies     = $($NeededWinPSModules | Where-Object {![string]::IsNullOrWhiteSpace($_.ModuleName)})
            PSCoreModuleDependencies    = $($NeededPSCoreModules | Where-Object {![string]::IsNullOrWhiteSpace($_.ModuleName)})
        }
    }

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
                    if ($ModulesSuccessfullyLoaded.ModuleName -notcontains $WinPSModuleObject.ModuleName) {
                        try {
                            Write-Host "Importing Module $($WinPSModuleObject.ModuleName)..."
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
                                Write-Host "Importing Module $ModuleManifestPath..."
                                Import-WinModule $ModuleManifestPath -ErrorAction Stop
                                $null = $ModulesSuccessfullyLoaded.Add($WinPSModuleObject)
                            }
                            catch {
                                $null = $ModulesFailedToLoad.Add($WinPSModuleObject)
                            }
                        }
                    }
                }

                foreach ($PSCoreModuleObject in $ModuleDependencies.PSCoreModuleDependencies) {
                    if ($ModulesSuccessfullyLoaded.ModuleName -notcontains $PSCoreModuleObject.ModuleName) {
                        try {
                            Write-Host "Importing Module $($PSCoreModuleObject.ModuleName)..."
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
                                Write-Host "Importing Module $ModuleManifestPath..."
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

            if ($PSVersionTable.PSEdition -ne "Core") {
                foreach ($WinPSModuleObject in $ModuleDependencies.WinPSModuleDependencies) {
                    try {
                        Write-Host "Importing Module $($WinPSModuleObject.ModuleName)..."
                        Import-Module $WinPSModuleObject.ModuleName -Scope Global -ErrorAction Stop
                        $null = $ModulesSuccessfullyLoaded.Add($WinPSModuleObject)
                    }
                    catch {
                        $ModuleManifestPath = $WinPSModuleObject.ManifestFileItem.FullName
                        if (!$ModuleManifestPath) {
                            $null = $ModulesFailedToLoad.Add($WinPSModuleObject)
                            continue
                        }

                        try {
                            Write-Host "Importing Module $ModuleManifestPath..."
                            Import-Module $ModuleManifestPath -Scope Global -ErrorAction Stop
                            $null = $ModulesSuccessfullyLoaded.Add($WinPSModuleObject)
                        }
                        catch {
                            $null = $ModulesFailedToLoad.Add($WinPSModuleObject)
                        }
                    }
                }

                foreach ($PSCoreModuleObject in $ModuleDependencies.PSCoreModuleDependencies) {
                    try {
                        Write-Host "Importing Module $($PSCoreModuleObject.ModuleName)..."
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
                            Write-Host "Importing Module $ModuleManifestPath..."
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

        [pscustomobject]@{
            ModulesSuccessfullyLoaded   = $ModulesSuccessfullyLoaded
            ModulesFailedToLoad         = $ModulesFailedToLoad
        }
    }

    #endregion >> Helper Functions

    #region >> Prep

    if ($PSVersionTable.PSEdition -ne "Core" -or
    $($PSVersionTable.PSEdition -ne "Core" -and $PSVersionTable.Platform -ne "Win32NT")) {
        Write-Error "This function is only meant to be used with PowerShell Core on Windows! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$(Test-Path $PathToPS1OrPSM1)) {
        Write-Error "Unable to find path '$PathToPS1OrPSM1'! Halting!"
        $global:FunctionResult = "1"
        return
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

    # Since there's currently no way to know if external Modules are actually compatible with PowerSHell Core
    # until we try and load them, we just need to install them under both Windows PowerShell 5.1 and PowerShell
    # Core CurrentUser $env:PSModulePath (i.e. $HOME\Documents\PowerShell and $HOME\Documents\WindowsPowerShell).
    # The LoadModuleDependencies function below will figure out which one actually works
    foreach ($ModuleName in $ModuleDependenciesThatMayNotBeInstalled) {
        try {
            Install-Module $ModuleName -Scope CurrentUser -ErrorAction Stop
        }
        catch {
            Write-Error $_
        }

        try {
            Invoke-WinCommand -ScriptBlock {Install-Module $args[0] -Scope CurrentUser} -ArgumentList $ModuleName -ErrorAction Stop
        }
        catch {
            Write-Error $_
        }
    }

    #endregion >> Prep

    try {
        $ModuleDependencyInfo = GetModuleDependencies -PathToScriptFile $PathToPS1OrPSM1
        $LoadModuleDependenciesResult = LoadModuleDependencies -ModuleDependencies $ModuleDependencyInfo
    }
    catch {
        Write-Error $_
        Write-Error "Problem with loading Module Dependencies for $($MyInvocation.MyCommand.Name)! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($LoadModuleDependenciesResult.ModulesFailedToLoad.Count -gt 0) {
        $AcceptableUnloadedModules = @("Microsoft.PowerShell.Core","WindowsCompatibility")

        [System.Collections.Arraylist]$UnacceptableUnloadedModules = @()
        foreach ($ModName in $LoadModuleDependenciesResult.ModulesFailedToLoad.ModuleName) {
            if ($AcceptableUnloadedModules -notcontains $ModName -and
            $LoadModuleDependenciesResult.ModulesSuccessfullyLoaded.ModuleName -notcontains $ModName) {
                $null = $UnacceptableUnloadedModules.Add($ModName)
            }
        }

        if ($UnacceptableUnloadedModules.Count -gt 0) {
            Write-Warning "The following Modules were not able to be loaded:`n$($UnacceptableUnloadedModules -join "`n")"
        }
    }

    $LoadModuleDependenciesResult
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUaWtV4pqakhMkF5EIoO2SkEzx
# jJ+gggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFHflrKrsYzjjHwBK
# +sF0V1WOXJcDMA0GCSqGSIb3DQEBAQUABIIBACRQ4ZJ826dB4duh7QrvTdoPlebZ
# 8k4Xmu5gsEppngu6kF5oWSrp4VdHe71eYFv/9EdFOCOwY6Z6QHoR8OyziasUDcMP
# GkVcrDqSXPbGQ8SSvRxnv7BTSkvWw7JUkyJVbPjLWnQ6FuK3KGWzFi3Ci2XeN5Xx
# gyfbW/9pAP7RVDzWP15NxGfow35TgIvTmpvinUSCYohE6vKRwwy2iHiH77dEYpSx
# iZDkNhsDJ1K2iC0FNe9ulknoal321goF6zX3kHPdo2TEnDQzge5qvdkGMiyn9lBX
# dH3oepJ2rWobm42fg44zOmGETOQX2WLuZV+4/cK56YJx5OLwnylKO0k39tI=
# SIG # End signature block
