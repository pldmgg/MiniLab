# This function ties together info about a particular Hyper-V vSwitch
# by collecting info using Get-VMNetworkAdapter, Get-VMSwitch, Get-NetAdapter,
# and Get-NetIPAddress
function GetvSwitchAllRelatedInfo {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$False)]
        [string]$vSwitchName,

        [Parameter(Mandatory=$False)]
        [string]$InterfaceAlias,

        [Parameter(Mandatory=$False)]
        [string]$IPAddress,

        [Parameter(Mandatory=$False)]
        [string]$MacAddress,

        [Parameter(Mandatory=$False)]
        [string]$DeviceId
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    $BoundParametersDictionary = $PSCmdlet.MyInvocation.BoundParameters

    if (!$vSwitchName -and !$InterfaceAlias -and !$IPAddress -and !$MacAddress -and !$DeviceId) {
        Write-Error "The Get-vSwitchRelationship function requires at least one of the following parameters: -vSwitchName, -InterfaceAlias, -IPAddress, -MacAddress, -DeviceId or any combination thereof! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($IPAddress) {
        if (![bool]$(TestIsValidIPAddress -IPAddress $IPAddress)) {
            Write-Error "$IPAddress is NOT a valid IPv4 IP Address! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($DeviceId) {
        # The $DeviceId might have prefix '{' and trailing '}', so get rid of them
        if ($DeviceId.Substring(0,1) -eq '{') {
            $DeviceId = $DeviceId.TrimStart('{')
        }
        if ($DeviceId[-1] -eq '}') {
            $DeviceId = $DeviceId.TrimEnd('}')
        }
    }

    if ($MacAddress) {
        # Standardize MacAddress string format with dashes
        if ($MacAddress -notmatch "-") {
            $MacAddress = $($MacAddress -split "([\w]{2})" | Where-Object {$_ -match "[\w]"}) -join '-'
        }
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    # Try to get $DetailedvSwitchInfo...

    [System.Collections.ArrayList]$DetailedvSwitchInfoPSObjects = @()

    if ($BoundParametersDictionary["vSwitchName"]) {
        try {
            $DetailedvSwitchInfoViavSwitchName = Get-VMNetworkAdapter -ManagementOS | Where-Object {$_.SwitchName -eq $vSwitchName}
            if (!$DetailedvSwitchInfoViavSwitchName) {
                throw "Unable to find a vSwitch with the name $vSwitchName! Halting!"
            }
            if ($DetailedvSwitchInfoViavSwitchName.Count -gt 1) {
                throw "Multiple vSwitches with the same name (i.e. $vSwitchName)! Halting!"
            }

            $BasicvSwitchInfo = Get-VMSwitch -Name $DetailedvSwitchInfoViavSwitchName.SwitchName
            $NetworkAdapterInfo = Get-NetAdapter | Where-Object {$($_.MacAddress -replace '-','') -eq $DetailedvSwitchInfoViavSwitchName.MacAddress}
            $IPAddressInfo = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $NetworkAdapterInfo.InterfaceAlias

            $vSwitchNamePSObject = @{
                ParameterUsed           = "vSwitchName"
                DetailedvSwitchInfo     = $DetailedvSwitchInfoViavSwitchName
            }

            $null = $DetailedvSwitchInfoPSObjects.Add($vSwitchNamePSObject)
        }
        catch {
            if (!$DetailedvSwitchInfoViavSwitchName -and $($BoundParametersDictionary.GetEnumerator()).Count -gt 1) {
                Write-Warning "Unable to find a vSwitch with the name $vSwitchName!"
                $BadvSwitchNameProvided = $True
            }
            else {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
    }

    if ($BoundParametersDictionary["InterfaceAlias"]) {
        try {
            $NetworkAdapterInfo = Get-NetAdapter -InterfaceAlias $InterfaceAlias -ErrorAction Stop
            $IPAddressInfo = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $NetworkAdapterInfo.InterfaceAlias

            $PotentialvSwitchesDetailedInfo = Get-VMNetworkAdapter -ManagementOS
            $MacAddressPrep = $NetworkAdapterInfo.MacAddress -replace '-',''
            $DetailedvSwitchInfoViaIPAddress = $PotentialvSwitchesDetailedInfo | Where-Object {$_.MacAddress -eq $MacAddressPrep}
            $BasicvSwitchInfo = Get-VMSwitch -Name $DetailedvSwitchInfoViaIPAddress.SwitchName

            if (!$DetailedvSwitchInfoViaIPAddress) {
                throw
            }
            else {
                $InterfaceAliasPSObject = @{
                    ParameterUsed           = "InterfaceAlias"
                    DetailedvSwitchInfo     = $DetailedvSwitchInfoViaIPAddress
                }

                $null = $DetailedvSwitchInfoPSObjects.Add($InterfaceAliasPSObject)
            }
        }
        catch {
            if (!$DetailedvSwitchInfoViaIPAddress -and $($BoundParametersDictionary.GetEnumerator()).Count -gt 1) {
                Write-Warning "Unable to find a Network Adapter with the InterfaceAlias name $InterfaceAlias!"
                $BadvInterfaceAliasProvided = $True
            }
            else {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }
        }
    }

    if ($BoundParametersDictionary["IPAddress"]) {
        if (!$DetailedvSwitchInfo) {
            try {
                $PotentialvSwitchesDetailedInfo = Get-VMNetworkAdapter -ManagementOS

                $IPAddressInfo = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $IPAddress -ErrorAction SilentlyContinue -ErrorVariable GNIPErr
                if (!$IPAddressInfo -or $GNIPErr) {throw}
                $NetworkAdapterInfo = Get-NetAdapter -InterfaceAlias $IPAddressInfo.InterfaceAlias
                $MacAddressPrep = $NetworkAdapterInfo.MacAddress -replace '-',''

                $DetailedvSwitchInfoViaIPAddress = $PotentialvSwitchesDetailedInfo | Where-Object {$_.MacAddress -eq $MacAddressPrep}
                $BasicvSwitchInfo = Get-VMSwitch -Name $DetailedvSwitchInfoViaIPAddress.SwitchName

                if (!$DetailedvSwitchInfoViaIPAddress) {
                    throw
                }
                else {
                    $IPAddressPSObject = @{
                        ParameterUsed           = "IPAddress"
                        DetailedvSwitchInfo     = $DetailedvSwitchInfoViaIPAddress
                    }
    
                    $null = $DetailedvSwitchInfoPSObjects.Add($IPAddressPSObject)
                }
            }
            catch {
                if ($($BoundParametersDictionary.GetEnumerator()).Count -gt 1) {
                    Write-Warning "Unable to find a vSwitch with the IP Address $IPAddress!"
                    $BadIPAddressProvided = $True
                }
                else {
                    Write-Error "Unable to find a vSwitch with the IP Address $IPAddress! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
    }

    if ($BoundParametersDictionary["DeviceId"]) {
        if(!$DetailedvSwitchInfo) {
            try {
                $DetailedvSwitchInfoViaDeviceId = Get-VMNetworkAdapter -ManagementOS | Where-Object {$_.DeviceId -eq "{$DeviceId}"}
                $BasicvSwitchInfo = Get-VMSwitch -Name $DetailedvSwitchInfoViaDeviceId.SwitchName
                $NetworkAdapterInfo = Get-NetAdapter | Where-Object {$($_.MacAddress -replace '-','') -eq $DetailedvSwitchInfoViaDeviceId.MacAddress}
                $IPAddressInfo = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $NetworkAdapterInfo.InterfaceAlias

                if (!$DetailedvSwitchInfoViaDeviceId) {
                    throw
                }
                else {
                    $DeviceIdPSObject = @{
                        ParameterUsed           = "DeviceId"
                        DetailedvSwitchInfo     = $DetailedvSwitchInfoViaDeviceId
                    }
    
                    $null = $DetailedvSwitchInfoPSObjects.Add($DeviceIdPSObject)
                }
            }
            catch {
                if ($($BoundParametersDictionary.GetEnumerator()).Count -gt 1) {
                    Write-Warning "Unable to find a Hyper-V vSwitch with a DeviceId matching $DeviceId!"
                    $BadDeviceIdProvided = $True
                }
                else {
                    Write-Error "Unable to find a Hyper-V vSwitch with a DeviceId matching $DeviceId! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
    }

    if ($BoundParametersDictionary["MacAddress"]) {
        if (!$DetailedvSwitchInfo) {
            try {
                $DetailedvSwitchInfoViaMacAddress = Get-VMNetworkAdapter -ManagementOS | Where-Object {$_.MacAddress -eq $($MacAddress -replace '-','')}
                $BasicvSwitchInfo = Get-VMSwitch -Name $DetailedvSwitchInfoViaMacAddress.SwitchName
                $NetworkAdapterInfo = Get-NetAdapter | Where-Object {$($_.MacAddress -replace '-','') -eq $DetailedvSwitchInfoViaMacAddress.MacAddress}
                $IPAddressInfo = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $NetworkAdapterInfo.InterfaceAlias

                if (!$DetailedvSwitchInfoViaMacAddress) {
                    throw
                }
                else {
                    $MacAddressPSObject = @{
                        ParameterUsed           = "MacAddress"
                        DetailedvSwitchInfo     = $DetailedvSwitchInfoViaMacAddress
                    }
    
                    $null = $DetailedvSwitchInfoPSObjects.Add($MacAddressPSObject)
                }
            }
            catch {
                if ($($BoundParametersDictionary.GetEnumerator()).Count -gt 1) {
                    Write-Warning "Unable to find a Hyper-V vSwitch with a MacAddress matching $($BoundParametersDictionary["MacAddress"])! Halting!"
                    $BadMacAddressProvided = $True
                }
                else {
                    Write-Error "Unable to find a Hyper-V vSwitch with a MacAddress matching $($BoundParametersDictionary["MacAddress"])! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
        }
    }

    # If we still DO NOT have $DetailedvSwitchInfoViaXXXXX one way or another, then halt
    if ($DetailedvSwitchInfoPSObjects.Count -eq 0) {
        Write-Error "Unable to find a Device using any of the parameters provided! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Start comparing each of the $DetailedvSwitchInfoPSObjects.DetailedvSwitchInfo objects to see
    # which $DetailedvSwitchInfoPSObjects.ParameterUsed get consensus for the the proper target Device.
    # Group by MacAddress and select the highest Count
    $GroupByMacAddress = $DetailedvSwitchInfoPSObjects.DetailedvSwitchInfo | Group-Object -Property MacAddress
    # It's possible that the number of parameters referencing one device equal the number of parameters that
    # reference another device. If that happens, we need to ask the user which one they want.
    if ($GroupByMacAddress.Count -gt 1) {
        if ($($GroupByMacAddress | Select-Object -ExpandProperty Count | Sort-Object | Get-Unique).Count -eq 1) {
            Write-Warning "Unable to get consensus on which Device should be targeted!"
            
            [System.Collections.ArrayList]$DeviceOptionsPSObjects = @()
            foreach ($item in $($GroupByMacAddress.Group | Sort-Object | Get-Unique)) {
                $SwitchName = $item.SwitchName
                $NetAdapterInfo = Get-NetAdapter | Where-Object {$($_.MacAddress -replace '-','') -eq $item.MacAddress}
                $IPInfo = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $NetAdapterInfo.InterfaceAlias

                $OptionPSObject = [pscustomobject]@{
                    SwitchName         = $SwitchName
                    InterfaceAlias     = $NetAdapterInfo.InterfaceAlias
                    IPAddress          = $IPInfo.IPAddress
                    MacAddress         = $item.MacAddress
                }

                $null = $DeviceOptionsPSObjects.Add($OptionPSObject)
            }

            Write-Host "`nPotential matching Devices are as follows:`n"
            for ($i=0; $i -lt $DeviceOptionsPSObjects.Count; $i++) {
                $WriteHostString = "$i) vSwitchName: $($DeviceOptionsPSObjects[$i].SwitchName); " +
                "NetworkAdapterAlias: $($DeviceOptionsPSObjects[$i].InterfaceAlias); " +
                "IPAddress: $($DeviceOptionsPSObjects[$i].IPAddress); " +
                "MacAddress: $($DeviceOptionsPSObjects[$i].MacAddress)"
                Write-Host $WriteHostString
            }
            
            $ValidChoiceNumbers = 0..$($DeviceOptionsPSObjects.Count-1)
            Write-Host ""
            $ChoiceNumber = Read-Host -Prompt "Please enter the number that corresponds to the Device you would like to gather information about. [$($ValidChoiceNumbers -join '|')]"
            while ($ValidChoiceNumbers -notcontains $ChoiceNumber) {
                Write-Host "$ChoiceNumber is NOT a valid choice number! Valid options are: $($ValidChoiceNumbers -join ', ')"
                $ChoiceNumber = Read-Host -Prompt "Please enter the number that corresponds to the Device you would like to gather information about. [$($ValidChoiceNumbers -join '|')]"
            }

            $MacAddressThatAppearsMostOften = $DeviceOptionsPSObjects[$ChoiceNumber].MacAddress
        }
    }
    else {
        $MacAddressThatAppearsMostOften = $($GroupByMacAddress | Sort-Object -Property Count)[-1].Name
    }

    [Array]$FinalDetailedvSwitchInfoPrep = $DetailedvSwitchInfoPSObjects.DetailedvSwitchInfo | Where-Object {$_.MacAddress -eq $MacAddressThatAppearsMostOften}
    # Just choose one to use since they're all the same...
    $FinalDetailedvSwitchInfo = $FinalDetailedvSwitchInfoPrep[0]
    $FinalBasicvSwitchInfo = Get-VMSwitch -Name $FinalDetailedvSwitchInfo.SwitchName
    $FinalNetworkAdapterInfo = Get-NetAdapter | Where-Object {$($_.MacAddress -replace '-','') -eq $FinalDetailedvSwitchInfo.MacAddress}
    $FinalIPAddressInfo = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias $FinalNetworkAdapterInfo.InterfaceAlias

    # Describe Parameters that WERE used in Final Output and Parameters that were IGNORED in Final Output
    [System.Collections.ArrayList][Array]$ParametersUsedToGenerateOutput = $($DetailedvSwitchInfoPSObjects | Where-Object {$_.DetailedvSwitchInfo.MacAddress -eq $MacAddressThatAppearsMostOften}).ParameterUsed
    [System.Collections.ArrayList]$ParametersIgnoredToGenerateOutput = @()
    $($DetailedvSwitchInfoPSObjects | Where-Object {$_.DetailedvSwitchInfo.MacAddress -ne $MacAddressThatAppearsMostOften}).ParameterUsed | foreach {
        if ($_ -ne $null) {
            $null = $ParametersIgnoredToGenerateOutput.Add($_)
        }
    }
    
    if ($BadvSwitchNameProvided) {
        $null = $ParametersIgnoredToGenerateOutput.Add("vSwitchName")
    }
    if ($BadvInterfaceAliasProvided) {
        $null = $ParametersIgnoredToGenerateOutput.Add("InterfaceAlias")
    }
    if ($BadIPAddressProvided) {
        $null = $ParametersIgnoredToGenerateOutput.Add("IPAddress")
    }
    if ($BadDeviceIdProvided) {
        $null = $ParametersIgnoredToGenerateOutput.Add("DeviceId")
    }
    if ($BadMacAddressProvided) {
        $null = $ParametersIgnoredToGenerateOutput.Add("MacAddress")
    }

    [pscustomobject]@{
        MacAddress                          = $FinalDetailedvSwitchInfo.MacAddress
        BasicvSwitchInfo                    = $FinalBasicvSwitchInfo
        DetailedvSwitchInfo                 = $FinalDetailedvSwitchInfo
        NetworkAdapterInfo                  = $FinalNetworkAdapterInfo
        IPAddressInfo                       = $FinalIPAddressInfo
        ParametersUsedToGenerateOutput      = $ParametersUsedToGenerateOutput
        ParametersIgnoredToGenerateOutput   = $ParametersIgnoredToGenerateOutput
        NonExistentvSwitchNameProvided      = if ($BadvSwitchNameProvided) {$True} else {$False}
        NonExistentIPAddressProvided        = if ($BadIPAddressProvided) {$True} else {$False}
        NonExistentMacAddressProvided       = if ($BadMacAddressProvided) {$True} else {$False}
        NonExistentDeviceIdProvided         = if ($BadDeviceIdProvided) {$True} else {$False}
    }

    ##### END Main Body #####
    #>
}

# SIG # Begin signature block
# MIIMaAYJKoZIhvcNAQcCoIIMWTCCDFUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUZ3rvdBpp9XUICyjSVF+k7LNA
# yVqgggndMIIEJjCCAw6gAwIBAgITawAAADqEP46TDmc/hQAAAAAAOjANBgkqhkiG
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
# BDEWBBR+EYr9XVjtjtzJ95jonGVjbXsQ6TANBgkqhkiG9w0BAQEFAASCAQBUzKvg
# +PkksJzsN4KsdKpTKlG7igT91dXzpnsHXGe7cTd6MfGZ6HtqiglUl6PMcNGAMyV/
# IpZ4DaVkNt9EdebCIWNxPoczojRFRgRi0iSgCe7NQxTd5MIsl5O8pRyKzdP31N6S
# JC5o+bvTb+LcnqIqCkq3KnfCnyue1HFRxNzC+9d2JXmEMuQ7Ofez5eKJHZV3MQlt
# 5lT5bZU0tOPx+cQpTZVrs8BfJFOhBJ8eLFteW7NiBYXcZCo5bRBVGAE/hQWjX4RN
# FJKtslwGldTpSr2iiAMbr8gQwUcexztmKIuNL4t4wsdP++2NXWG4V1J6LzOXY3fZ
# PgNbf6ZJr4UX5Av7
# SIG # End signature block
