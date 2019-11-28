function GetWinPSInCore {
    [CmdletBinding()]
    [Alias('shim')]
    Param (
        [Parameter(
            Mandatory=$True,
            Position=0
        )]
        [Alias("sb")]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory=$False)]
        [switch]$MirrorCurrentEnv = $True,

        [Parameter(Mandatory=$False)]
        [switch]$NoWinRM
    )

    if ($PSVersionTable.PSEdition -ne "Core" -or $PSVersionTable.Platform -ne "Win32NT") {
        Write-Error "The '$($MyInvocation.MyCommand.Name)' function is only meant to be used in PowerShell Core on Windows! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($MirrorCurrentEnv) {
        [System.Collections.ArrayList]$SetEnvStringArray = @()

        $VariablesNotToForward = @()

        $Variables = Get-Variable
        if ($PSBoundParameters['VariablesToForward'] -and $VariablesToForward -notcontains '*') {
            $Variables = foreach ($VarObj in $Variables) {
                if ($VariablesToForward -contains $VarObj.Name) {
                    $VarObj
                }
            }
        }
        $SetVarsPrep = foreach ($VarObj in $Variables) {
            if ($VariablesNotToForward -notcontains $VarObj.Name) {
                try {
                    $VarValueAsJSON = $VarObj.Value | ConvertTo-Json -Compress
                }
                catch {
                    #Write-Warning "Unable to pass the variable '$($VarObj.Name)'..."
                }

                if ($VarValueAsJSON) {
                    if ([char[]]$VarObj.Name -contains '(' -or [char[]]$VarObj.Name -contains ' ') {
                        $VarStringArr = @(
                            'try {'
                            $('    ${' + $VarObj.Name + '}' + ' = ' + 'ConvertFrom-Json ' + "@'`n$VarValueAsJSON`n'@")
                            '}'
                            'catch {'
                            "    Write-Verbose 'Unable to forward variable $($VarObj.Name)'"
                            '}'
                        )
                    }
                    else {
                        $VarStringArr = @(
                            'try {'
                            $('    $' + $VarObj.Name + ' = ' + 'ConvertFrom-Json ' + "@'`n$VarValueAsJSON`n'@")
                            '}'
                            'catch {'
                            "    Write-Verbose 'Unable to forward variable $($VarObj.Name)'"
                            '}'
                        )
                    }
                    $VarStringArr -join "`n"
                }
            }
        }
        $SetVarsString = $SetVarsPrep -join "`n"

        $null = $SetEnvStringArray.Add($SetVarsString)

        # Set Environment Variables
        $EnvVariables = Get-ChildItem Env:\
        if ($PSBoundParameters['EnvironmentVariablesToForward'] -and $EnvironmentVariablesToForward -notcontains '*') {
            $EnvVariables = foreach ($VarObj in $EnvVariables) {
                if ($EnvironmentVariablesToForward -contains $VarObj.Name) {
                    $VarObj
                }
            }
        }
        $SetEnvVarsPrep = foreach ($VarObj in $EnvVariables) {
            if ([char[]]$VarObj.Name -contains '(' -or [char[]]$VarObj.Name -contains ' ') {
                $EnvStringArr = @(
                    'try {'
                    $('    ${env:' + $VarObj.Name + '} = ' + "@'`n$($VarObj.Value)`n'@")
                    '}'
                    'catch {'
                    "    Write-Verbose 'Unable to forward environment variable $($VarObj.Name)'"
                    '}'
                )
            }
            else {
                $EnvStringArr = @(
                    'try {'
                    $('    $env:' + $VarObj.Name + ' = ' + "@'`n$($VarObj.Value)`n'@")
                    '}'
                    'catch {'
                    "    Write-Verbose 'Unable to forward environment variable $($VarObj.Name)'"
                    '}'
                )
            }
            $EnvStringArr -join "`n"
        }
        $SetEnvVarsString = $SetEnvVarsPrep -join "`n"

        $null = $SetEnvStringArray.Add($SetEnvVarsString)

        # Set Modules
        $Modules = Get-Module
        if ($PSBoundParameters['ModulesToForward'] -and $ModulesToForward -notcontains '*') {
            $Modules = foreach ($ModObj in $Modules) {
                if ($ModulesToForward -contains $ModObj.Name) {
                    $ModObj
                }
            }
        }

        $ModulesNotToForward = @('MiniLab')

        $SetModulesPrep = foreach ($ModObj in $Modules) {
            if ($ModulesNotToForward -notcontains $ModObj.Name) {
                $ModuleManifestFullPath = $(Get-ChildItem -Path $ModObj.ModuleBase -Recurse -File | Where-Object {
                    $_.Name -eq "$($ModObj.Name).psd1"
                }).FullName

                $ModStringArray = @(
                    '$tempfile = [IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName())'
                    "if (![bool]('$($ModObj.Name)' -match '\.WinModule')) {"
                    '    try {'
                    "        Import-Module '$($ModObj.Name)' -ErrorAction Stop -WarningAction SilentlyContinue 2>`$tempfile"
                    '    }'
                    '    catch {'
                    '        try {'
                    "            Import-Module '$ModuleManifestFullPath' -ErrorAction Stop -WarningAction SilentlyContinue 2>`$tempfile"
                    '        }'
                    '        catch {'
                    "            Write-Verbose 'Unable to Import-Module $($ModObj.Name)'"
                    '        }'
                    '    }'
                    '}'
                    'if (Test-Path $tempfile) {'
                    '    Remove-Item $tempfile -Force'
                    '}'
                )
                $ModStringArray -join "`n"
            }
        }
        $SetModulesString = $SetModulesPrep -join "`n"

        $null = $SetEnvStringArray.Add($SetModulesString)
    
        # Set Functions
        $Functions = Get-ChildItem Function:\ | Where-Object {![System.String]::IsNullOrWhiteSpace($_.Name)}
        if ($PSBoundParameters['FunctionsToForward'] -and $FunctionsToForward -notcontains '*') {
            $Functions = foreach ($FuncObj in $Functions) {
                if ($FunctionsToForward -contains $FuncObj.Name) {
                    $FuncObj
                }
            }
        }
        $SetFunctionsPrep = foreach ($FuncObj in $Functions) {
            $FunctionText = Invoke-Expression $('@(${Function:' + $FuncObj.Name + '}.Ast.Extent.Text)')
            if ($($FunctionText -split "`n").Count -gt 1) {
                if ($($FunctionText -split "`n")[0] -match "^function ") {
                    if ($($FunctionText -split "`n") -match "^'@") {
                        Write-Warning "Unable to forward function $($FuncObj.Name) due to heredoc string: '@"
                    }
                    else {
                        'Invoke-Expression ' + "@'`n$FunctionText`n'@"
                    }
                }
            }
            elseif ($($FunctionText -split "`n").Count -eq 1) {
                if ($FunctionText -match "^function ") {
                    'Invoke-Expression ' + "@'`n$FunctionText`n'@"
                }
            }
        }
        $SetFunctionsString = $SetFunctionsPrep -join "`n"

        $null = $SetEnvStringArray.Add($SetFunctionsString)
    }

    # Make sure we have Windows PowerShell PSModule Paths
    $PSCorePSModulePath = $env:PSModulePath
    [System.Collections.Arraylist][array]$PSCorePSModulePathArray = $env:PSModulePath -split ';'
    $WinPSPSModulePaths = @(
        'C:\Program Files\WindowsPowerShell\Modules'
        "$HOME\Documents\WindowsPowerShell\Modules"
        'C:\Windows\System32\WindowsPowerShell\v1.0\Modules'
        'C:\Windows\SysWOW64\WindowsPowerShell\v1.0\Modules'
    )
    foreach ($ModPath in $WinPSPSModulePaths) {
        if ($PSCorePSModulePathArray -notcontains $ModPath) {
            $null = $PSCorePSModulePathArray.Add($ModPath)
        }
    }
    $FinalModPathString = $PSCorePSModulePathArray -join ';'

    # Create Initialization Scripts as needed...
    $InitSBAsStringA = "`$env:PSModulePath = '$FinalModPathString'`n"
    
    if ($SetEnvStringArray.Count -gt 0) {
        # Writing $SetEnvStringArray to a file helps us avoid the byte limit associated with the
        # -args parameter of powershell.exe.
        # See: http://systemcentersynergy.com/max-script-block-size-when-passing-to-powershell-exe-or-invoke-command/
        $SetEnvStringArrayPath = "$HOME\SetEnvStringArray.xml"
        $SetEnvStringArray | Export-CliXml -Path $SetEnvStringArrayPath -Force

        $InitSBAsStringB = @(
            "`$args = Import-CliXml '$SetEnvStringArrayPath'"
            ''
            '$args | foreach {'
            '    if (![string]::IsNullOrWhiteSpace($_)) {'
            '        Invoke-Expression $_'
            '    }'
            '}'
            ''    
        )
    }

    if ($InitSBAsStringB) {
        # NOTE: $InitSBAsStringB coming before $InitSBAsStringA is important regarding $env:PSModulePath
        $FinalSBAsString = $InitSBAsStringB + $InitSBAsStringA + $ScriptBlock.ToString()
    }
    else {
        $FinalSBAsString = $InitSBAsStringA + $ScriptBlock.ToString()
    }

    try {
        $FinalSB = [scriptblock]::Create($($FinalSBAsString -join "`n"))
    }
    catch {
        Write-Error "Problem creating scriptblock `$FinalSB! Halting!"
        $global:FunctionResult = "1"
        return
    }
    

    # Output
    if ($NoWinRM) {
        powershell.exe -NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -Command $FinalSB
    }
    else {
        # Check to see if there's a PSSession open from the WindowsCompatibility Module
        <#
        if (!$global:WinPSSession) {
            $CurrentUser = $($(whoami) -split '\\')[-1]
            if ([bool]$(Get-PSSession -Name "win-$CurrentUser" -ErrorAction SilentlyContinue)) {
                $global:WinPSSession = Get-PSSession -Name "win-$CurrentUser"
            }
        }
        #>

        $WinPSSessionName = NewUniqueString -PossibleNewUniqueString "WinPSSession" -ArrayOfStrings $(Get-PSSession).Name
        $NewPSSessionSplatParams = @{
            ConfigurationName   = 'Microsoft.PowerShell'
            Name                = $WinPSSessionName
            EnableNetworkAccess = $True
        }
        $WinPSSession = New-PSSession @NewPSSessionSplatParams
        
        if (!$WinPSSession) {
            Write-Error "There was a problem creating the New-PSSession named 'WinPSSession'! Halting!"
            $global:FunctionResult = "1"
            return
        }
        else {
            Write-Host "A new PSSession called 'WinPSSession' has been created along with a Global Variable referencing it called `$global:WinPSSession." -ForegroundColor Green
        }
        Invoke-Command -Session $global:WinPSSession -ScriptBlock $FinalSB -HideComputerName
    }

    # Cleanup
    if ($SetEnvStringArrayPath) {
        if (Test-Path $SetEnvStringArrayPath) {
            #Remove-Item $SetEnvStringArrayPath -Force
        }
    }

    $WinPSSession | Remove-PSSession
}

# SIG # Begin signature block
# MIIMaAYJKoZIhvcNAQcCoIIMWTCCDFUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUs0TFGwJ8JI1l+uZtzdOv+zaf
# VCGgggndMIIEJjCCAw6gAwIBAgITawAAADqEP46TDmc/hQAAAAAAOjANBgkqhkiG
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
# BDEWBBSnvRQLhTGV9DCf4YC5noH86bVftzANBgkqhkiG9w0BAQEFAASCAQBc9CaU
# IQbB+l6pt9aZDXKfvsgEHQjlgtVgs/YSnVcMsXXa3njoqp8QjaA9CyuHOxur96PL
# Bkg4bFGm0IXGqSvSeLS3GZXN9X3W0E1qnUEpkz4LORTltoYsYukRDxabVxxkftf/
# oI59UEMaH7ogCrrmN2GqPF/il/XjqEJvN5bfoK/uif8mbcMfaki+fCCpvh3ltAg1
# 7iIZjwckxfMeCpnkK2lvFf4z7Jcoa7/JjHXebL4qRb8IxBL10XlyVKjouv5Q2Ym6
# pS+3QF5jbSgDOm4C3s6cBxxwFq7XUNMwe5fBjI5onHzUu6ORAyIt0vt8IhMnNm+Z
# SLj/j79p6p7sPavb
# SIG # End signature block
