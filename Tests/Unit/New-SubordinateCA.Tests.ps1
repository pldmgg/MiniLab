[CmdletBinding()]
param(
    [Parameter(Mandatory=$False)]
    [System.Collections.Hashtable]$TestResources
)
# NOTE: `Set-BuildEnvironment -Force -Path $PSScriptRoot` from build.ps1 makes the following $env: available:
<#
    $env:BHBuildSystem = "Unknown"
    $env:BHProjectPath = "U:\powershell\ProjectRepos\MiniLab"
    $env:BHBranchName = "master"
    $env:BHCommitMessage = "!deploy"
    $env:BHBuildNumber = 0
    $env:BHProjectName = "MiniLab"
    $env:BHPSModuleManifest = "U:\powershell\ProjectRepos\MiniLab\MiniLab\MiniLab.psd1"
    $env:BHModulePath = "U:\powershell\ProjectRepos\MiniLab\MiniLab"
    $env:BHBuildOutput = "U:\powershell\ProjectRepos\MiniLab\BuildOutput"
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

# placeholder