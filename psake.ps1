[CmdletBinding()]
param(
    [Parameter(Mandatory=$False)]
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,

    [Parameter(Mandatory=$False)]
    [System.Collections.Hashtable]$TestResources
)

# NOTE: `Set-BuildEnvironment -Force -Path $PSScriptRoot` from build.ps1 makes the following $env: available:
<#
    $env:BHBuildSystem = "Unknown"
    $env:BHProjectPath = "U:\powershell\ProjectRepos\Sudo"
    $env:BHBranchName = "master"
    $env:BHCommitMessage = "!deploy"
    $env:BHBuildNumber = 0
    $env:BHProjectName = "Sudo"
    $env:BHPSModuleManifest = "U:\powershell\ProjectRepos\Sudo\Sudo\Sudo.psd1"
    $env:BHModulePath = "U:\powershell\ProjectRepos\Sudo\Sudo"
    $env:BHBuildOutput = "U:\powershell\ProjectRepos\Sudo\BuildOutput"
#>

# NOTE: If -TestResources was used, the folloqing resources should be available
<#
    $TestResources = @{
        UserName        = $UserName
        SimpleUserName  = $SimpleUserName
        Password        = $Password
        Creds           = $Creds
    }
#>

# PSake makes variables declared here available in other scriptblocks
# Init some things
Properties {
    $PublicScriptFiles = Get-ChildItem "$env:BHModulePath\Public" -File -Filter *.ps1 -Recurse
    $PrivateScriptFiles = Get-ChildItem -Path "$env:BHModulePath\Private" -File -Filter *.ps1 -Recurse

    $Timestamp = Get-Date -UFormat "%Y%m%d-%H%M%S"
    $PSVersion = $PSVersionTable.PSVersion.Major
    $TestFile = "TestResults_PS$PSVersion`_$TimeStamp.xml"
    $lines = '----------------------------------------------------------------------'

    $Verbose = @{}
    if ($ENV:BHCommitMessage -match "!verbose") {
        $Verbose = @{Verbose = $True}
    }

    if ($Cert) {
        # Need to Declare $Cert here in the 'Properties' block so that it's available in other script blocks
        $Cert = $Cert
    }
}

Task Default -Depends Test

Task Init -RequiredVariables  {
    $lines
    Set-Location $ProjectRoot
    "Build System Details:"
    Get-Item ENV:BH*
    "`n"
}

Task Compile -Depends Init {
    $BoilerPlateFunctionSourcing = @'
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

# Get public and private function definition files.
[array]$Public  = Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1" -ErrorAction SilentlyContinue
[array]$Private = Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" -ErrorAction SilentlyContinue
$ThisModule = $(Get-Item $PSCommandPath).BaseName

# Dot source the Private functions
foreach ($import in $Private) {
    try {
        . $import.FullName
    }
    catch {
        Write-Error -Message "Failed to import function $($import.FullName): $_"
    }
}

[System.Collections.Arraylist]$ModulesToInstallAndImport = @("Hyper-V")
if (Test-Path "$PSScriptRoot\module.requirements.psd1") {
    $ModuleManifestData = Import-PowerShellDataFile "$PSScriptRoot\module.requirements.psd1"
    $ModuleManifestData.Keys | Where-Object {$_ -ne "PSDependOptions"} | foreach {$null = $ModulesToinstallAndImport.Add($_)}
}

if ($ModulesToInstallAndImport.Count -gt 0) {
    # NOTE: If you're not sure if the Required Module is Locally Available or Externally Available,
    # add it the the -RequiredModules string array just to be certain
    $InvModDepSplatParams = @{
        RequiredModules                     = $ModulesToInstallAndImport
        InstallModulesNotAvailableLocally   = $True
        ErrorAction                         = "SilentlyContinue"
        WarningAction                       = "SilentlyContinue"
    }
    $ModuleDependenciesMap = InvokeModuleDependencies @InvModDepSplatParams
}

# Public Functions
'@

    Set-Content -Path "$env:BHModulePath\$env:BHProjectName.psm1" -Value $BoilerPlateFunctionSourcing

    ###### BEGIN Unique Additions to this Module ######
    ###### END Unique Additions to this Module ######

    [System.Collections.ArrayList]$FunctionTextToAdd = @()
    foreach ($ScriptFileItem in $PublicScriptFiles) {
        $FileContent = Get-Content $ScriptFileItem.FullName
        $SigBlockLineNumber = $FileContent.IndexOf('# SIG # Begin signature block')
        $FunctionSansSigBlock = $($($FileContent[0..$($SigBlockLineNumber-1)]) -join "`n").Trim() -split "`n"
        $null = $FunctionTextToAdd.Add("`n")
        $null = $FunctionTextToAdd.Add($FunctionSansSigBlock)
    }
    $null = $FunctionTextToAdd.Add("`n")

    Add-Content -Value $FunctionTextToAdd -Path "$env:BHModulePath\$env:BHProjectName.psm1"

    # Finally, add array the variables contained in VariableLibrary.ps1 if it exists in case we want to use this Module Remotely
    if (Test-Path "$env:BHModulePath\VariableLibrary.ps1") {
        Get-Content "$env:BHModulePath\VariableLibrary.ps1" | Add-Content "$env:BHModulePath\$env:BHProjectName.psm1"
    }

    if ($Cert) {
        # At this point the .psm1 is finalized, so let's sign it
        try {
            $SetAuthenticodeResult = Set-AuthenticodeSignature -FilePath "$env:BHModulePath\$env:BHProjectName.psm1" -cert $Cert
            if (!$SetAuthenticodeResult -or $SetAuthenticodeResult.Status -eq "HashMisMatch") {throw}
        }
        catch {
            Write-Error "Failed to sign '$env:BHProjectName.psm1' with Code Signing Certificate! Invoke-Pester will not be able to load '$env:BHProjectName.psm1'! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
}

Task Test -Depends Compile  {
    $lines
    "`n`tSTATUS: Testing with PowerShell $PSVersion"

    $PesterSplatParams = @{
        PassThru        = $True
        OutputFormat    = "NUnitXml"
        OutputFile      = "$env:BHBuildOutput\$TestFile"
    }
    if ($TestResources) {
        $ScriptParamHT = @{
            Path = "$env:BHProjectPath\Tests"
            Parameters = @{TestResources = $TestResources}
        }
        $PesterSplatParams.Add("Script",$ScriptParamHT)
    }
    else {
        $PesterSplatParams.Add("Path","$env:BHProjectPath\Tests")
    }

    # Gather test results. Store them in a variable and file
    $TestResults = Invoke-Pester @PesterSplatParams

    # Make sure Authenticode Signature has been removed
    $RemoveSignatureFilePath = $(Resolve-Path "$PSScriptRoot\*Help*\Remove-Signature.ps1").Path
    $RemoveSignatureFilePathRegex = [regex]::Escape($RemoveSignatureFilePath)
    . $RemoveSignatureFilePath
    if (![bool]$(Get-Item Function:\Remove-Signature)) {
        Write-Error "Problem dot sourcing the Remove-Signature function! Halting!"
        $global:FunctionResult = "1"
        return
    }
    [System.Collections.ArrayList][array]$HelperFilestoSign = Get-ChildItem $(Resolve-Path "$PSScriptRoot\*Help*\").Path -Recurse -File | Where-Object {
        $_.Extension -match '\.ps1|\.psm1|\.psd1|\.ps1xml' -and $_.Name -ne "Remove-Signature.ps1"
    }
    foreach ($FileItem in $HelperFilestoSign) {
        if ($(Get-AuthenticodeSignature -FilePath $FileItem.FullName) -ne "NotSigned") {
            Write-Host "Removing signature from $($FileItem.FullName)..."
            Remove-Signature -FilePath $FileItem.FullName
        }
    }

    $HelperFilesToSignNameRegex = $HelperFilestoSign.Name | foreach {[regex]::Escape($_)}

    [System.Collections.ArrayList][array]$FilesToSign = Get-ChildItem $env:BHProjectPath -Recurse -File | Where-Object {
        $_.Extension -match '\.ps1|\.psm1|\.psd1|\.ps1xml' -and
        $_.Name -notmatch "^build\.ps1$" -and
        $_.Name -notmatch $($HelperFilesToSignNameRegex -join '|') -and
        $_.Name -notmatch $RemoveSignatureFilePathRegex -and
        $_.FullName -notmatch "\\Pages\\Dynamic|\\Pages\\Static" -and
        $_.Name -notmatch "psake\.ps1" -and
        $_.Name -notmatch "Tests\.ps1"
    }
    foreach ($FileItem in $FilestoSign) {
        if ($(Get-AuthenticodeSignature -FilePath $FileItem.FullName) -ne "NotSigned") {
            Write-Host "Removing signature from $($FileItem.FullName)..."
            Remove-Signature -FilePath $FileItem.FullName
        }
    }

    # In Appveyor?  Upload our tests! #Abstract this into a function?
    if ($env:BHBuildSystem -eq 'AppVeyor') {
        (New-Object 'System.Net.WebClient').UploadFile(
            "https://ci.appveyor.com/api/testresults/nunit/$($env:APPVEYOR_JOB_ID)",
            "$env:BHBuildOutput\$TestFile" )
    }

    Remove-Item "$env:BHBuildOutput\$TestFile" -Force -ErrorAction SilentlyContinue

    # Failed tests?
    # Need to tell psake or it will proceed to the deployment. Danger!
    if ($TestResults.FailedCount -gt 0) {
        Write-Error "Failed '$($TestResults.FailedCount)' tests, build failed"
    }
    "`n"
}

Task Build -Depends Test {
    $lines
    
    # Load the module, read the exported functions, update the psd1 FunctionsToExport
    Set-ModuleFunctions

    # Bump the module version if we didn't already
    Try
    {
        [version]$GalleryVersion = Get-NextNugetPackageVersion -Name $env:BHProjectName -ErrorAction Stop
        #[version]$GalleryVersion = Get-NextPSGalleryVersion -Name $env:BHProjectName -ErrorAction Stop
        [version]$GithubVersion = Get-MetaData -Path $env:BHPSModuleManifest -PropertyName ModuleVersion -ErrorAction Stop
        if($GalleryVersion -ge $GithubVersion) {
            Update-Metadata -Path $env:BHPSModuleManifest -PropertyName ModuleVersion -Value $GalleryVersion -ErrorAction stop
        }
    }
    Catch
    {
        "Failed to update version for '$env:BHProjectName': $_.`nContinuing with existing version"
    }
}

Task Deploy -Depends Build {
    $lines

    $Params = @{
        Path = $PSScriptRoot
        Force = $true
        Recurse = $false
    }
    Invoke-PSDeploy @Verbose @Params
}

# SIG # Begin signature block
# MIIMaAYJKoZIhvcNAQcCoIIMWTCCDFUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUfc5NGHOakwvyuHBj665HeLFz
# PO6gggndMIIEJjCCAw6gAwIBAgITawAAADqEP46TDmc/hQAAAAAAOjANBgkqhkiG
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
# BDEWBBRHaqZaYt1FjoMQF3p/y7I7NBjqSjANBgkqhkiG9w0BAQEFAASCAQBJFUeO
# c7CPUI2hIEqq8rmPa3F2X1m65YyH1V9f3sbmJCMt7DE5BvfVFJO2TsK8PghencOR
# NpLS5jRaQvXfK53GUFKhgeoR4mYXNGsD2IdTHByuAty7cPyFRAzhd0gYmZlcI8YF
# xdOIP5ZEb8N6ViA7vVnpCxWzq0H6uBDga5lkc36Edz4UDpLH4Ns63PEAwkO1oFwy
# VUAzZXGwecSplZAiMbcoaAgrXnj2c8wT+nPAxFyaZGPSiJPiM32IoCK5f6bAI5wg
# Vso75GXbDIj31eWB1WyFLcLtSmVbKOyWG4sERRTI3w/XS8FmJS1cHuwNZfD5Qx9p
# HxpOwNZZ5VikZhXW
# SIG # End signature block
