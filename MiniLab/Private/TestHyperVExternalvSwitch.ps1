function TestHyperVExternalvSwitch {
    [CmdletBinding(DefaultParameterSetName='ExternalNetworkVM')]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$DownloadDirectory = "$HOME\Downloads",

        [Parameter(Mandatory=$False)]
        [switch]$AllowRestarts,

        [Parameter(Mandatory=$False)]
        [switch]$SkipHyperVInstallCheck,

        [Parameter(Mandatory=$False)]
        [switch]$SkipPreDownloadCheck
    )

    #region >> Variable/Parameter Transforms and PreRun Prep

    Push-Location

    if (!$SkipHyperVInstallCheck) {
        try {
            $HyperVFeaturesInstallResults = InstallHyperVFeatures -ParentFunction $MyInvocation.MyCommand.Name
        }
        catch {
            Write-Error $_
            Write-Error "The InstallHyperVFeatures function (as executed by the $($MyInvocation.MyCommand.Name) function) failed! Halting!"
            $global:FunctionResult = "1"
            Pop-Location
            return
        }
        try {
            $InstallContainersFeatureDismResult = InstallFeatureDism -Feature Containers -ParentFunction $MyInvocation.MyCommand.Name
        }
        catch {
            Write-Error $_
            Write-Error "The InstallFeatureDism function (as executed by the $($MyInvocation.MyCommand.Name) function) failed! Halting!"
            $global:FunctionResult = "1"
            Pop-Location
            return
        }

        if ($HyperVFeaturesInstallResults.InstallResults.Count -gt 0) {
            if (!$AllowRestarts) {
                Write-Warning "You must restart $env:ComputerName before the TestHyperVExternalvSwitch function can proceed! Halting!"
                # IMPORTANT NOTE: The below Write-Output "RestartNeeded" is necessary
                Write-Output "RestartNeeded"
                $global:FunctionResult = "1"
                Pop-Location
                return
            }
            else {
                Restart-Computer -Confirm:$False -Force
            }
        }
    }
    else {
        if (![bool]$(Get-Module -ListAvailable -Name Hyper-V) -and ![bool]$(Get-Module -Name Hyper-V)) {
            Write-Error "Hyper-V does not appear to be installed on $env:ComputerName! Try the function again without the -SkipHyperVInstallCheck switch. Halting!"
            $global:FunctionResult = "1"
            Pop-Location
            return
        }
    }

    # Set some other variables that we will need
    <#
    $NextHop = $(Get-NetRoute -AddressFamily IPv4 | Where-Object {$_.NextHop -ne "0.0.0.0"} | Sort-Object RouteMetric)[0].NextHop
    $PrimaryIP = $(Find-NetRoute -RemoteIPAddress $NextHop | Where-Object {$($_ | Get-Member).Name -contains "IPAddress"}).IPAddress
    $NicInfo = Get-NetIPAddress -IPAddress $PrimaryIP
    $NicAdapter = Get-NetAdapter -InterfaceAlias $NicInfo.InterfaceAlias
    #>
    $PrimaryIfIndex = $(Get-CimInstance Win32_IP4RouteTable | Where-Object {
        $_.Destination -eq '0.0.0.0' -and $_.Mask -eq '0.0.0.0'
    } | Sort-Object Metric1)[0].InterfaceIndex
    $NicInfo = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object {$_.InterfaceIndex -eq $PrimaryIfIndex}
    $PrimaryIP = $NicInfo.IPAddress | Where-Object {TestIsValidIPAddress -IPAddress $_}
    $NextHop = $NicInfo.DefaultIPGateway[0]

    $HostNameBIOSInfo = Get-CimInstance Win32_BIOS
    $IntegrationServicesRegistryPath = "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters"
    $HostNameIntegrationServicesPresent = Test-Path $IntegrationServicesRegistryPath

    if ($HostNameBIOSInfo.SMBIOSBIOSVersion -match "Hyper-V|VirtualBox|VMWare|Xen" -or
    $HostNameBIOSInfo.Manufacturer -match "Hyper-V|VirtualBox|VMWare|Xen" -or
    $HostNameBIOSInfo.Name -match "Hyper-V|VirtualBox|VMWare|Xen" -or
    $HostNameBIOSInfo.SerialNumber -match "Hyper-V|VirtualBox|VMWare|Xen" -or
    $HostNameBIOSInfo.Version -match "Hyper-V|VirtualBox|VMWare|Xen|VRTUAL" -or
    $HostNameIntegrationServicesPresent) {
        $IsVirtual = $True
    }
    else {
        $IsVirtual = $False
    }

    # If there are any pre-existing running VMs using an External vSwitch, assume that External vSwitch works
    [System.Collections.ArrayList][Array]$ExternalvSwitches = Get-VMSwitch -SwitchType External
    if ($ExternalvSwitches.Count -gt 0) {
        $RunningVMs = Get-VM | Where-Object {$_.State -eq "Running"}

        if ($RunningVMs.Count -gt 0) {
            [System.Collections.ArrayList]$FoundRunningVMUsingExternalvSwitch = @()
            foreach ($VMObject in $RunningVMs) {
                if ($ExternalvSwitches.Name -contains $VMObject.NetworkAdapters.SwitchName) {
                    $null = $FoundRunningVMUsingExternalvSwitch.Add($VMObject)
                }
            }
        }
    }

    # If we're on BareMetal or if there are already Hyper-V VMs that are 'Running' that use an External vSwitch,
    # then we can assume External vSwitch works, and we're done here... 
    if ($IsVirtual -eq $False -or $FoundRunningVMUsingExternalvSwitch.Count -gt 0) {
        [pscustomobject]@{
            ExternalvSwitchWorks                = $True
            CanReachInternet                    = $True
            CanReachRouter                      = $True
            VirtualizationExtensionsExposed     = $True
            MacAddressSpoofingEnabled           = $True
        }
        return
    }

    # If we reached this point in the function, we have established that the machine that the function is being run on
    # is Virtual

    if (!$NicInfo.DHCPEnabled) {
        Write-Error "The Test-HyperVExternalvSwitch function failed because the External Network (i.e. the Host network) does not appear to have DHCP already available! Try the New-DHCPServer function! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (!$DownloadDirectory) {
        $DownloadDirectory = "$HOME\Downloads"
    }

    # Write the Universal Unsecure Vagrant Private Key to filesystem
    # From: https://github.com/hashicorp/vagrant/blob/master/keys
    $VagrantPrivKey = @"
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA6NF8iallvQVp22WDkTkyrtvp9eWW6A8YVr+kz4TjGYe7gHzI
w+niNltGEFHzD8+v1I2YJ6oXevct1YeS0o9HZyN1Q9qgCgzUFtdOKLv6IedplqoP
kcmF0aYet2PkEDo3MlTBckFXPITAMzF8dJSIFo9D8HfdOV0IAdx4O7PtixWKn5y2
hMNG0zQPyUecp4pzC6kivAIhyfHilFR61RGL+GPXQ2MWZWFYbAGjyiYJnAmCP3NO
Td0jMZEnDkbUvxhMmBYSdETk1rRgm+R4LOzFUGaHqHDLKLX+FIPKcF96hrucXzcW
yLbIbEgE98OHlnVYCzRdK8jlqm8tehUc9c9WhQIBIwKCAQEA4iqWPJXtzZA68mKd
ELs4jJsdyky+ewdZeNds5tjcnHU5zUYE25K+ffJED9qUWICcLZDc81TGWjHyAqD1
Bw7XpgUwFgeUJwUlzQurAv+/ySnxiwuaGJfhFM1CaQHzfXphgVml+fZUvnJUTvzf
TK2Lg6EdbUE9TarUlBf/xPfuEhMSlIE5keb/Zz3/LUlRg8yDqz5w+QWVJ4utnKnK
iqwZN0mwpwU7YSyJhlT4YV1F3n4YjLswM5wJs2oqm0jssQu/BT0tyEXNDYBLEF4A
sClaWuSJ2kjq7KhrrYXzagqhnSei9ODYFShJu8UWVec3Ihb5ZXlzO6vdNQ1J9Xsf
4m+2ywKBgQD6qFxx/Rv9CNN96l/4rb14HKirC2o/orApiHmHDsURs5rUKDx0f9iP
cXN7S1uePXuJRK/5hsubaOCx3Owd2u9gD6Oq0CsMkE4CUSiJcYrMANtx54cGH7Rk
EjFZxK8xAv1ldELEyxrFqkbE4BKd8QOt414qjvTGyAK+OLD3M2QdCQKBgQDtx8pN
CAxR7yhHbIWT1AH66+XWN8bXq7l3RO/ukeaci98JfkbkxURZhtxV/HHuvUhnPLdX
3TwygPBYZFNo4pzVEhzWoTtnEtrFueKxyc3+LjZpuo+mBlQ6ORtfgkr9gBVphXZG
YEzkCD3lVdl8L4cw9BVpKrJCs1c5taGjDgdInQKBgHm/fVvv96bJxc9x1tffXAcj
3OVdUN0UgXNCSaf/3A/phbeBQe9xS+3mpc4r6qvx+iy69mNBeNZ0xOitIjpjBo2+
dBEjSBwLk5q5tJqHmy/jKMJL4n9ROlx93XS+njxgibTvU6Fp9w+NOFD/HvxB3Tcz
6+jJF85D5BNAG3DBMKBjAoGBAOAxZvgsKN+JuENXsST7F89Tck2iTcQIT8g5rwWC
P9Vt74yboe2kDT531w8+egz7nAmRBKNM751U/95P9t88EDacDI/Z2OwnuFQHCPDF
llYOUI+SpLJ6/vURRbHSnnn8a/XG+nzedGH5JGqEJNQsz+xT2axM0/W/CRknmGaJ
kda/AoGANWrLCz708y7VYgAtW2Uf1DPOIYMdvo6fxIB5i9ZfISgcJ/bbCUkFrhoH
+vq/5CIWxCPp0f85R4qxxQ5ihxJ0YDQT9Jpx4TMss4PSavPaBH3RXow5Ohe+bYoQ
NE5OgEXk2wVfZczCZpigBKbKZHNYcelXtTt/nP3rsCuGcM4h53s=
-----END RSA PRIVATE KEY-----
"@

    if (!$(Test-Path "$HOME\.ssh")) {
        $null = New-Item -ItemType Directory -Path "$HOME\.ssh"
    }
    $VagrantInsecurePrivKeyPath = "$HOME\.ssh\insecure_vagrant_private_key.pem"
    if (!$(Test-Path $VagrantInsecurePrivKeyPath)) {
        $VagrantPrivKey | Out-File $VagrantInsecurePrivKeyPath -Encoding ASCII

        if ($PSVersionTable.PSEdition -eq "Core") {
            $FixVPermsAsString = ${Function:FixVagrantPrivateKeyPerms}.Ast.Extent.Text
            Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                Invoke-Expression $args[0]
                FixVagrantPrivateKeyPerms -PathToPrivateKey $args[1]
            } -ArgumentList $FixVPermsAsString,$VagrantInsecurePrivKeyPath
        }
        else {
            FixVagrantPrivateKeyPerms -PathToPrivateKey $VagrantInsecurePrivKeyPath
        }
    }

    <#
    if ([Environment]::OSVersion.Version -lt [version]"10.0.17063") {
        if (![bool]$(Get-Command curl -ErrorAction SilentlyContinue) -or 
        $(Get-Command curl -ErrorAction SilentlyContinue).CommandType -eq "Alias"
        ) {
            $InstallCurlResults = Install-Program -ProgramName curl -CommandName curl -UseChocolateyCmdLine
        }
    }
    $CurlCmd = $(Get-Command curl -CommandType Application -All).Source
    if ($CurlCmd.Count -gt 1) {
        $CurlCmd = $(Get-Command curl -CommandType Application -All | Where-Object {$_.Source -match "x64"}).Source
        if (!$CurlCmd) {
            $CurlCmd = $(Get-Command curl -CommandType Application -All).Source[-1]
        }
    }
    #>

    if (![bool]$(Get-Command ssh -ErrorAction SilentlyContinue)) {
        if (![bool]$(Get-Module -ListAvailable ProgramManagement)) {Install-Module ProgramManagement}
        if (![bool]$(Get-Module ProgramManagement)) {Import-Module ProgramManagement}
        $InstallOpenSSHResult = Install-Program -ProgramName openssh -CommandName ssh.exe -ExpectedInstallLocation "C:\Program Files\OpenSSH-Win64"

        if (![bool]$(Get-Service ssh-agent -ErrorAction SilentlyContinue)) {
            if (Test-Path "C:\Program Files\OpenSSH-Win64\install-sshd.ps1") {
                & "C:\Program Files\OpenSSH-Win64\install-sshd.ps1"
            }
            else {
                Write-Warning "Unable to find 'C:\Program Files\OpenSSH-Win64\install-sshd.ps1'! The services 'ssh-agent' and 'sshd' will NOT be installed."
            }
        }
    }

    #endregion >> Variable/Parameter Transforms and PreRun Prep


    #region >> Main Body

    $DeployVMSplatParams = @{
        VagrantBox              = "centos/7"
        VagrantProvider         = "hyperv"
        VMName                  = "CentOS7vSwitchTest"
        VMDestinationDirectory  = $DownloadDirectory
        Memory                  = 1024
        CPUs                    = 1
        ErrorAction             = "SilentlyContinue"
        ErrorVariable           = "DVMErr"
        SkipHyperVInstallCheck  = $True
    }

    try {
        $DeployVMResult = Deploy-HyperVVagrantBoxManually @DeployVMSplatParams
        if (!$DeployVMResult -or
        [bool]$($($DVMErr | Out-String) -match "one of the Hyper-V components is not running") -or
        [bool]$($($DVMErr | Out-String) -match "The operation has timed out")
        ) {
            throw "The Deploy-HyperVVagrantBoxManually function failed! Halting!"
        }
        $VMDeployed = $True
    }
    catch {
        if ([bool]$($($DVMErr | Out-String) -match "one of the Hyper-V components is not running")) {
            if ($IsVirtual) {
                $VirtualizationExtensionsExposed = $False
            }
            else {
                Write-Error "One or more Hyper-V components is not installed! Please check the Hyper-V features that are currenly enabled! Halting!"
                $global:FunctionResult = "1"
                Pop-Location
                return
            }
        }
        elseif ([bool]$($($DVMErr | Out-String) -match "The operation has timed out")) {
            Write-Warning "https://vagrantcloud.com appears to be throttling traffic. Sleeping for 5 minutes before trying again..."
            Start-Sleep -Seconds 300

            try {
                $DeployVMResult = Deploy-HyperVVagrantBoxManually @DeployVMSplatParams
                if (!$DeployVMResult -or
                [bool]$($($DVMErr | Out-String) -match "one of the Hyper-V components is not running") -or
                [bool]$($($DVMErr | Out-String) -match "The operation has timed out")
                ) {
                    throw "The Deploy-HyperVVagrantBoxManually function failed! Halting!"
                }
                $VMDeployed = $True
            }
            catch {
                if ([bool]$($($DVMErr | Out-String) -match "one of the Hyper-V components is not running")) {
                    if ($IsVirtual) {
                        $VirtualizationExtensionsExposed = $False
                    }
                    else {
                        Write-Error "One or more Hyper-V components is not installed! Please check the Hyper-V features that are currenly enabled! Halting!"
                        $global:FunctionResult = "1"
                        Pop-Location
                        return
                    }
                }
                else {
                    Write-Error $_
                    Write-Host "Errors for the Deploy-HyperVVagrantBoxManually function are as follows:"
                    Write-Error $($DVMErr | Out-String)

                    if ($DeployVMResult.VMName -ne $null) {
                        $DestroyVMOutput = Manage-HyperVVM -VmName $DeployVMResult.VMName -Destroy -ErrorAction SilentlyContinue
                    }
                    if ($DeployVMResult.ExternalSwitchCreated -eq $True) {
                        Remove-VMSwitch "ToExternal" -Force -ErrorAction SilentlyContinue
                    }
                    if ($DeployVMResult.TempHyperVVMLocation -ne $null) {
                        if (Test-Path $DeployVMResult.TempHyperVVMLocation) {
                            Remove-Item $DeployVMResult.TempHyperVVMLocation -Recurse -Force
                        }
                    }
                    if ($DeployVMResult.BoxFileLocation -ne $null) {
                        if (Test-Path $DeployVMResult.BoxFileLocation) {
                            Remove-Item $DeployVMResult.BoxFileLocation -Force
                        }
                    }
                    
                    $global:FunctionResult = "1"
                    Pop-Location
                    return
                }
            }
        }
        else {
            Write-Error $_
            Write-Host "Errors for the Deploy-HyperVVagrantBoxManually function are as follows:"
            Write-Error $($DVMErr | Out-String)

            if ($DeployVMResult.VMName -ne $null) {
                $DestroyVMOutput = Manage-HyperVVM -VmName $DeployVMResult.VMName -Destroy -ErrorAction SilentlyContinue
            }
            if ($DeployVMResult.ExternalSwitchCreated -eq $True) {
                Remove-VMSwitch "ToExternal" -Force -ErrorAction SilentlyContinue
            }
            if ($DeployVMResult.TempHyperVVMLocation -ne $null) {
                if (Test-Path $DeployVMResult.TempHyperVVMLocation) {
                    Remove-Item $DeployVMResult.TempHyperVVMLocation -Recurse -Force
                }
            }
            if ($DeployVMResult.BoxFileLocation -ne $null) {
                if (Test-Path $DeployVMResult.BoxFileLocation) {
                    Remove-Item $DeployVMResult.BoxFileLocation -Force
                }
            }
            
            $global:FunctionResult = "1"
            Pop-Location
            return
        }
    }

    if (!$VMDeployed -and $DeployVMResult -eq "RestartNeeded") {
        if (!$AllowRestarts) {
            Write-Warning "You must restart $env:ComputerName before the TestHyperVExternalvSwitch can proceed! Halting!"
            # IMPORTANT NOTE: The below Write-Output "RestartNeeded" is necessary
            Write-Output "RestartNeeded"
            $global:FunctionResult = "1"
            Pop-Location
            return
        }
        else {
            Restart-Computer -Confirm:$False -Force
        }
    }

    if ($VMDeployed) {
        try {
            $CustomCentOSVM = Get-VM -Name $DeployVMResult.VMName

            if ($CustomCentOSVM.State -eq "Running") {
                # Give the CentOS7 VM 120 seconds to report its IP
                $counter = 0
                while (!$VMIPv4Address -and $counter -le 4) {
                    $counter++
                    Write-Host "Waiting for $($CustomCentOSVM.Name) to report its IP Address..."
                    Start-Sleep -Seconds 30
                    $VMIPv4Address = $(Get-VMNetworkAdapter -VMName $CustomCentOSVM.Name).IPAddresses | Where-Object {TestIsValidIPAddress -IPAddress $_}
                }

                if ($VMIPv4Address) {
                    # If $HOME\.ssh\known_hosts already exists, make sure there is NOT a line in there already regarding $VMIPv4Address
                    # If there is, remove it
                    if (Test-Path "$HOME\.ssh\known_hosts") {
                        $KnownHostsContent = Get-Content "$HOME\.ssh\known_hosts"
                        $PotentialLineToRemove = $KnownHostsContent -match $VMIPv4Address
                        if ($PotentialLineToRemove) {
                            $UpdatedKnownHostsContent = $KnownHostsContent | Where-Object {$_ -ne $PotentialLineToRemove}
                            Set-Content -Path "$HOME\.ssh\known_hosts" -Value $UpdatedKnownHostsContent
                        }
                    }

                    # Now we can start issuing ssh commands through our CentOS7 VM to see if the External vSwitch actually works
                    # If it does, we know that MacAddress spoofing is enabled on the hypervisor and that the hypervisor is
                    # most likely Hyper-V
                    $PingRouterResult = ssh -o "StrictHostKeyChecking=no" -o "IdentitiesOnly=yes" -i "$VagrantInsecurePrivKeyPath" -t vagrant@$VMIPv4Address "ping -c 1 '$NextHop' >/dev/null && echo True" 2>$null
                    if ($PingRouterResult -eq "True") {$CanReachRouter = $True}
                    $PingInternetResult = ssh -o "StrictHostKeyChecking=no" -o "IdentitiesOnly=yes" -i "$VagrantInsecurePrivKeyPath" -t vagrant@$VMIPv4Address "ping -c 1 '8.8.8.8' >/dev/null && echo True" 2>$null
                    if ($PingInternetResult -eq $True) {$CanReachInternet = $True}

                    if (!$CanReachInternet -and !$CanReachRouter) {
                        $ExternalvSwitchWorks = $False
                    }
                    else {
                        Write-Host "External vSwitch $($(Get-VMSwitch -SwitchType External).Name) can reach the internet!" -ForegroundColor Green
                        $ExternalvSwitchWorks = $True
                    }
                }
                else {
                    $MacAddressSpoofingEnabled = $False
                }
            }
        }
        catch {
            Write-Error $_

            if ($DeployVMResult.VMName -ne $null) {
                $DestroyVMOutput = Manage-HyperVVM -VmName $DeployVMResult.VMName -Destroy -ErrorAction SilentlyContinue
            }
            if ($DeployVMResult.ExternalSwitchCreated) {
                Remove-VMSwitch "ToExternal" -Force -ErrorAction SilentlyContinue
            }
            if ($DeployVMResult.TempHyperVVMLocation -ne $null) {
                if (Test-Path $DeployVMResult.TempHyperVVMLocation) {
                    Remove-Item $DeployVMResult.TempHyperVVMLocation -Recurse -Force
                }
            }
            if ($DeployVMResult.BoxFileLocation -ne $null) {
                if (Test-Path $DeployVMResult.BoxFileLocation) {
                    Remove-Item $DeployVMResult.BoxFileLocation -Force
                }
            }

            $global:FunctionResult = "1"
            Pop-Location
            return
        }
    }

    # Cleanup
    if ($DeployVMResult.VMName -ne $null) {
        $DestroyVMOutput = Manage-HyperVVM -VmName $DeployVMResult.VMName -Destroy -ErrorAction SilentlyContinue
    }
    if ($DeployVMResult.ExternalSwitchCreated) {
        Remove-VMSwitch "ToExternal" -Force -ErrorAction SilentlyContinue
    }
    if ($DeployVMResult.TempHyperVVMLocation -ne $null) {
        if (Test-Path $DeployVMResult.TempHyperVVMLocation) {
            Remove-Item $DeployVMResult.TempHyperVVMLocation -Recurse -Force
        }
    }
    if ($DeployVMResult.BoxFileLocation -ne $null) {
        if (Test-Path $DeployVMResult.BoxFileLocation) {
            Remove-Item $DeployVMResult.BoxFileLocation -Force
        }
    }

    $Output = [ordered]@{
        ExternalvSwitchWorks    = if ($ExternalvSwitchWorks -eq $null -or $ExternalvSwitchWorks -eq $False) {$False} else {$True}
        CanReachInternet        = if ($CanReachInternet -eq $null -or $CanReachInternet -eq $False) {$False} else {$True}
        CanReachRouter          = if ($CanReachRouter -eq $null -or $CanReachRouter -eq $False) {$False} else {$True}
    }

    if ($IsVirtual) {
        if ($VMDeployed) {
            $Output.Add("VirtualizationExtensionsExposed",$True)
        }
        else {
            $Output.Add("VirtualizationExtensionsExposed",$False)
        }

        if ($MacAddressSpoofingEnabled -eq $False) {
            $Output.Add("MacAddressSpoofingEnabled",$False)
        }
        elseif ($ExternalvSwitchWorks -eq $True) {
            $Output.Add("MacAddressSpoofingEnabled",$True)
        }
        elseif ($VirtualizationExtensionsExposed -eq $False -or $VirtualizationExtensionsExposed -eq $null) {
            $Output.Add("MacAddressSpoofingEnabled","Unknown")
        }
        else {
            $Output.Add("MacAddressSpoofingEnabled",$False)
        }
    }

    [pscustomobject]$Output

    Pop-Location
    
    #endregion >> Main Body
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUu884UZ5r8KxJRcEIedc3oYGk
# lRugggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFHRrz+cu9cVpcF6I
# 3e+f0uqf8lfLMA0GCSqGSIb3DQEBAQUABIIBADfczVZ+FscAbZEag3VdCru0T+ky
# zF3JEP7DE7VEummcc9AA9qILUsab1oRbEPxz+nSKLw2v5V5sQBB6byaq4kItcFkH
# zkzQ/uVsImvCsu0lWlA5dCcqBF6EI4dtFFsBye+vaQ5AI4WOZl3WXRNC1Y0c4d1r
# b070hx6+9IAwURUSqqkhmlUcwpbJzFPlvktQ1HqEJcaUUD0N/6AJxyuP15PzHPGH
# 4pA1+ZR9qZcFo/mxm4RsvZDknlaAhMcsGTJuYx4OrRagcjino3QjOzmuJh61ZM4W
# v1WqmcexEqJYylWGIAGLIuNu6AIDpqCQhMYZLuxnYgzFxHJC0H2wxhKAqTU=
# SIG # End signature block
