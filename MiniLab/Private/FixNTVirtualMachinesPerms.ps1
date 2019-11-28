<#
    The function uses the NTFSSecurity Module to set "ReadAndExecute, Synchronize" permissions
    for the "NT VIRTUAL MACHINE\Virtual Machines" account on:
        - The specified $Directory,
        - All child items of $Directory via "ThisFolderSubFoldersAndFiles"; and
        - All Parent Directories of $Directory via "ThisFolderOnly" up to the root drive.
#>
function FixNTVirtualMachinesPerms {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [string]$DirectoryPath
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if (! $(Test-Path $DirectoryPath)) {
        Write-Error "The path $DirectoryPath was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($(Get-Module).Name -notcontains "PackageManagement") {
        try {
            $PMImport = Import-Module PackageManagement -ErrorAction SilentlyContinue -PassThru
            if (!$PMImport) {throw "Problem importing module PackageManagement!"}
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }
    if ($(Get-Module).Name -notcontains "PowerShellGet") {
        try {
            $PSGetImport = Import-Module PowerShellGet -ErrorAction SilentlyContinue -PassThru
            if (!$PSGetImport) {throw "Problem importing module PowerShellGet!"}
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }
    if ($(Get-Module -ListAvailable).Name -notcontains "NTFSSecurity") {
        try {
            Install-Module -Name NTFSSecurity -ErrorAction SilentlyContinue -ErrorVariable NTFSSecInstallErr
            if ($NTFSSecInstallErr) {throw "Problem installing the NTFSSecurity Module!"}
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }
    if ($(Get-Module).Name -notcontains "NTFSSecurity") {
        try {
            $NTFSSecImport = Import-Module NTFSSecurity -ErrorAction SilentlyContinue -PassThru
            if (!$NTFSSecImport) {throw "Problem importing module NTFSSecurity!"}
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    $NTFSAccessInfo = Get-NTFSAccess $DirectoryPath
    $NTFSAccessInfoVMs = $NTFSAccessInfo | Where-Object {$_.Account -eq "NT VIRTUAL MACHINE\Virtual Machines"}
    if ($NTFSAccessInfoVMs) {
        # TODO: Figure out the appropriate way to get the 'AppliesTo' Properties. The below works, but is bad.
        $NTFSAccessInfoVMsContent = $($NTFSAccessInfoVMs| Out-String) -split "`n"
        $NTFSAccessInfoHeaders = $NTFSAccessInfoVMsContent -match '-------'
        $IndexNumber = $NTFSAccessInfoVMsContent.Indexof("$NTFSAccessInfoHeaders")
        $AppliesToPrep = $NTFSAccessInfoVMsContent[$($IndexNumber+1)..$($NTFSAccessInfoVMsContent.Count-1)] | Where-Object {$_ -match "[\w]"}
        [System.Collections.ArrayList][Array]$AppliesTo = $($($($AppliesToPrep | foreach {$_ -replace "[\s]+"," "}) -split "(Allow|Deny)[\s](True|False)")[0].Trim() -split " ")[-1]
    }

    # NOTE: The below string "ThisFolderSubfolders" is not the full setting (i.e. "ThisFolderSubfoldersAndFiles").
    # I match on an incomplete string versus using the '-contains' comparison operator because I don't know the
    # appropriate way of getting the  'Applies To' property from Get-NTFSAccess output. See the above 'TODO:' comment.
    if ($NTFSAccessInfo.Account -notcontains "NT VIRTUAL MACHINE\Virtual Machines" -or
    $($NTFSAccessInfo.Account -contains "NT VIRTUAL MACHINE\Virtual Machines" -and ![bool]$($AppliesTo -match "ThisFolderSubfolders"))
    ) {
        #Add-NTFSAccess -Path $DirectoryPath -Account "NT VIRTUAL MACHINE\Virtual Machines" -AccessRights "ReadAndExecute, Synchronize" -AccessType Allow -AppliesTo ThisFolderSubfoldersAndFiles
        Add-NTFSAccess -Path $DirectoryPath -Account "NT VIRTUAL MACHINE\Virtual Machines" -AccessRights "FullControl" -AccessType Allow -AppliesTo ThisFolderSubfoldersAndFiles
    }

    $ParentDirThatNeedsPermissions = $DirectoryPath | Split-Path -Parent
    while (-not [System.String]::IsNullOrEmpty($ParentDirThatNeedsPermissions)) {
        $NTFSAccessInfo = Get-NTFSAccess $ParentDirThatNeedsPermissions
        $NTFSAccessInfoVMs = $NTFSAccessInfo | Where-Object {$_.Account -eq "NT VIRTUAL MACHINE\Virtual Machines"}
        if ($NTFSAccessInfoVMs) {
            $NTFSAccessInfoVMsContent = $($NTFSAccessInfoVMs| Out-String) -split "`n"
            $NTFSAccessInfoHeaders = $NTFSAccessInfoVMsContent -match '-------'
            $IndexNumber = $NTFSAccessInfoVMsContent.Indexof("$NTFSAccessInfoHeaders")
            $AppliesToPrep = $NTFSAccessInfoVMsContent[$($IndexNumber+1)..$($NTFSAccessInfoVMsContent.Count-1)] | Where-Object {$_ -match "[\w]"}
            [System.Collections.ArrayList][Array]$AppliesTo = $($($($AppliesToPrep | foreach {$_ -replace "[\s]+"," "}) -split "(Allow|Deny)[\s](True|False)")[0].Trim() -split " ")[-1]
        }

        if ($NTFSAccessInfo.Account -notcontains "NT VIRTUAL MACHINE\Virtual Machines" -or
        $($NTFSAccessInfo.Account -contains "NT VIRTUAL MACHINE\Virtual Machines" -and ![bool]$($AppliesTo -match "ThisFolderOnly"))
        ) {
            #Add-NTFSAccess -Path $ParentDirThatNeedsPermissions -Account "NT VIRTUAL MACHINE\Virtual Machines" -AccessRights "ReadAndExecute, Synchronize" -AccessType Allow -AppliesTo ThisFolderOnly
            Add-NTFSAccess -Path $ParentDirThatNeedsPermissions -Account "NT VIRTUAL MACHINE\Virtual Machines" -AccessRights "FullControl" -AccessType Allow -AppliesTo ThisFolderOnly
        }

        $ParentDirThatNeedsPermissions = $ParentDirThatNeedsPermissions | Split-Path -Parent
    }

    ##### END Main Body #####
}

# SIG # Begin signature block
# MIIMaAYJKoZIhvcNAQcCoIIMWTCCDFUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUM/BB/GrgjNGfQkqO15W1IzwN
# FoKgggndMIIEJjCCAw6gAwIBAgITawAAADqEP46TDmc/hQAAAAAAOjANBgkqhkiG
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
# BDEWBBT6LcU8NoZz4CnogGIucXLsGcgQEzANBgkqhkiG9w0BAQEFAASCAQC/K4xZ
# X8yxwBqoeBrLHoAUk3FD7V6l9PQbEue1Tj2Ok+qK4OAaZknKhgPQhm+JVkjogObP
# ldmWh/5Czgc1xWtBbtcPgmzZ69IW8Dg7uhsdUPG3pm+PZE10oqfHtDbj4XLEsMJ6
# 6v60s9o9gDgYKAEhG5fEMZi28SylZo86lRvH6AZT9r/Fr8EWljnWiVga9y08il+o
# +MKPH/khsa7HomkoaQboyoXthL3lu5SRzu4r2zFJeSPK913mUicv67VVj2UKsrRH
# NkE7lPDWyvg8ojPcFgQuU5vE468GGEa5aW6/VyuCqZstin8aXpad8UKqsGybybpu
# FL24nl+ewj0mi+d+
# SIG # End signature block
