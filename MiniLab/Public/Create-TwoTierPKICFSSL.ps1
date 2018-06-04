<#
    .SYNOPSIS
        This function creates a new Enterprise Root Certificate Authority and new Enterprise Subordinate/Intermediate/Issuing
        Certification Authority on a Domain. If you do not want to create the Root and Subordinate CAs on an existing
        domain, this function is capable of creating a brand new domain and deploying the CAs to that new domain.

    .DESCRIPTION
        This function is an example of 'Service Deployment' function that can be found within the MiniLab Module. A
        'Service Deployment' function is responsible for deploying as many servers as is necessary to get a particular
        service working on a domain/network. This may involve a myriad of feature/role installations and configuration
        setttings across multiple servers.

    .NOTES

    .PARAMETER CreateNewVMs
        This parameter is OPTIONAL.

        This parameter is a switch. If used, new Windows 2016 Standard Server Virtual Machines will be deployed
        to the localhost. If Hyper-V is not installed, it will be installed (and you will need to restart the localhost
        before proceeding).

    .PARAMETER VMStorageDirectory
        This parameter is OPTIONAL, but becomes MANDATORY if the -CreateNewVMs parameter is used.

        This parameter takes a string that represents the full path to a directory on a LOCAL drive that will contain all
        new VM files (configuration, vhd(x), etc.)

    .PARAMETER Windows2016VagrantBox
        This parameter is OPTIONAL, but becomes MANDATORY if the -CreateNewVMs parameter is used.

        This parameter takes a string that represents the name of a Vagrant Box that can be downloaded from
        https://app.vagrantup.com/boxes/search. Default value is "jborean93/WindowsServer2016". Another good
        Windows 2016 Server Vagrant Box is "StefanScherer/windows_2016".

        You can alternatively specify a Windows 2012 R2 Standard Server Vagrant Box if desired.

    .PARAMETER ExistingDomain
        This parameter is OPTIONAL, however, either this parameter or the -NewDomain parameter are MANDATORY.

        This parameter takes a string that represents the name of the domain that the Root and Subordinate CAs will
        join (if they aren't already).

        Example: alpha.lab

    .PARAMETER NewDomain
        This parameter is OPTIONAL, however, either this parameter or the -ExistingDomain parameter are MANDATORY.

        This parameter takes a string that represents the name of the domain that the Root and Subordinate CAs will
        join (if they aren't already).
        
        Example: alpha.lab

    .PARAMETER DomainAdminCredentials
        This parameter is MANDATORY.

        This parameter takes a PSCredential. The Domain Admin Credentials will be used to join the Subordinate CA Server to the domain
        as well as configre the new Subordinate CA. This means that the Domain Account provided to this parameter MUST be a member
        of the following Security Groups in Active Directory:
            - Domain Admins
            - Domain Users
            - Enterprise Admins
            - Group Policy Creator Owners
            - Schema Admins

        If you are creating a New Domain, these credentials will be used to create a new Domain Account that is a member of the
        aforementioned Security Groups.

    .PARAMETER PSRemotingCredentials
        This parameter is MANDATORY.

        This parameter takes a PSCredential.

        The credential provided to this parameter should correspond to a User Account that has permission to
        remote into ALL target Windows Servers. If your target servers are Vagrant Boxes (which is what will be deployed
        if you use the -CreateNewVMs switch), then the value for this parameter should be created via:

            $VagrantVMPassword = ConvertTo-SecureString 'vagrant' -AsPlainText -Force
            $VagrantVMAdminCreds = [pscredential]::new("vagrant",$VagrantVMPassword)

    .PARAMETER LocalAdministratorAccountCredentials
        This parameter is OPTIONAL, however, is you are creating a New Domain, then this parameter is MANDATORY.

        This parameter takes a PSCredential.

        The credential provided to this parameter will be applied to the Local Built-In Administrator Account on the
        target Windows Server. In other words, the pscredential provided to this parameter does NOT need to match
        the current UserName/Password of the Local Administrator Account on the target Windows Server, because the
        pscredential provided to this parameter will overwrite whatever the existing credentials are.

    .PARAMETER DCIsRootCA
        This parameter is OPTIONAL.

        This parameter is a switch. If used, the  Root CA will be installed on the Primary Domain Controller. This is not
        best practice, but if you have limited hardware resources, this could come in handy.

    .PARAMETER IPofServerToBeDomainController
        This parameter is OPTIONAL.

        This parameter takes a string that represents an IPv4 Address referring to an EXISTING Windows Server on the network
        that will become the new Primary Domain Controller.

    .PARAMETER IPOfServerToBeRootCA
        This parameter is OPTIONAL.

        This parameter takes a string that represents an IPv4 Address referring to an EXISTING Windows Server on the network
        that will become the new Root CA.
    
    .PARAMETER IPOfServerToBeSubCA
        This parameter is OPTIONAL.

        This parameter takes a string that represents an IPv4 Address referring to an EXISTING Windows Server on the network
        that will become the new Subordinate CA.

    .PARAMETER SkipHyperVInstallCheck
        This parameter is OPTIONAL.

        This parameter is a switch. If used, this function will not check to make sure Hyper-V is installed on the localhost.

    .EXAMPLE
        # Create a New Domain With 3 Servers - Primary Domain Controller, Root CA, and Subordinate CA
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> $VagrantVMPassword = ConvertTo-SecureString 'vagrant' -AsPlainText -Force
        PS C:\Users\zeroadmin> $VagrantVMAdminCreds = [pscredential]::new("vagrant",$VagrantVMPassword)
        PS C:\Users\zeroadmin> $DomainAdminCreds = [pscredential]::new("alpha\alphaadmin",$(Read-Host 'Enter Passsword' -AsSecureString))
        Enter Passsword: ************
        PS C:\Users\zeroadmin> $LocalAdminAccountCreds = [pscredential]::new("Administrator",$(Read-Host 'Enter Passsword' -AsSecureString))
        Enter Passsword: **************
        PS C:\Users\zeroadmin> $CreateTwoTierPKISplatParams = @{
        >> CreateNewVMs                            = $True
        >> VMStorageDirectory                      = "H:\VirtualMachines"
        >> NewDomain                               = "alpha.lab"
        >> PSRemotingCredentials                   = $VagrantVMAdminCreds
        >> DomainAdminCredentials                  = $DomainAdminCreds
        >> LocalAdministratorAccountCredentials    = $LocalAdminAccountCreds
        >> }
        PS C:\Users\zeroadmin> Create-TwoTierPKI @CreateTwoTierPKISplatParams

    .EXAMPLE
        # Create a New Domain With 2 Servers - Primary Domain Controller (which will also be the Root CA), and Subordinate CA
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> $VagrantVMPassword = ConvertTo-SecureString 'vagrant' -AsPlainText -Force
        PS C:\Users\zeroadmin> $VagrantVMAdminCreds = [pscredential]::new("vagrant",$VagrantVMPassword)
        PS C:\Users\zeroadmin> $DomainAdminCreds = [pscredential]::new("alpha\alphaadmin",$(Read-Host 'Enter Passsword' -AsSecureString))
        Enter Passsword: ************
        PS C:\Users\zeroadmin> $LocalAdminAccountCreds = [pscredential]::new("Administrator",$(Read-Host 'Enter Passsword' -AsSecureString))
        Enter Passsword: **************
        PS C:\Users\zeroadmin> $CreateTwoTierPKISplatParams = @{
        >> CreateNewVMs                            = $True
        >> VMStorageDirectory                      = "H:\VirtualMachines"
        >> NewDomain                               = "alpha.lab"
        >> PSRemotingCredentials                   = $VagrantVMAdminCreds
        >> DomainAdminCredentials                  = $DomainAdminCreds
        >> LocalAdministratorAccountCredentials    = $LocalAdminAccountCreds
        >> SkipHyperVInstallCheck                  = $True
        >> DCIsRootCA                              = $True
        >> }
        PS C:\Users\zeroadmin> Create-TwoTierPKI @CreateTwoTierPKISplatParams

    .EXAMPLE
        # Add Two-Tier PKI to your Existing Domain
        # IMPORTANT NOTE: If you can't resolve the -ExistingDomain from the localhost, be sure to use the -IPOfServerToBeDomainController
        # parameter with the IP Address of an EXISTING Domain Controller on the domain specified by -ExistingDomain

        PS C:\Users\zeroadmin> $VagrantVMPassword = ConvertTo-SecureString 'vagrant' -AsPlainText -Force
        PS C:\Users\zeroadmin> $VagrantVMAdminCreds = [pscredential]::new("vagrant",$VagrantVMPassword)
        PS C:\Users\zeroadmin> $DomainAdminCreds = [pscredential]::new("alpha\alphaadmin",$(Read-Host 'Enter Passsword' -AsSecureString))
        Enter Passsword: ************
        PS C:\Users\zeroadmin> $LocalAdminAccountCreds = [pscredential]::new("Administrator",$(Read-Host 'Enter Passsword' -AsSecureString))
        Enter Passsword: **************
        PS C:\Users\zeroadmin> $CreateTwoTierPKISplatParams = @{
        >> CreateNewVMs                            = $True
        >> VMStorageDirectory                      = "H:\VirtualMachines"
        >> ExistingDomain                          = "alpha.lab"
        >> PSRemotingCredentials                   = $VagrantVMAdminCreds
        >> DomainAdminCredentials                  = $DomainAdminCreds
        >> }
        PS C:\Users\zeroadmin> Create-TwoTierPKI @CreateTwoTierPKISplatParams


#>
function Create-TwoTierPKICFSSL {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$False)]
        [switch]$CreateNewVMs,

        [Parameter(Mandatory=$False)]
        [string]$VMStorageDirectory,

        [Parameter(Mandatory=$False)]
        [string]$Windows2016VagrantBox = "jborean93/WindowsServer2016", # Alternate - StefanScherer/windows_2016

        [Parameter(Mandatory=$False)]
        [ValidatePattern("^([a-z0-9]+(-[a-z0-9]+)*\.)+([a-z]){2,}$")]
        [string]$NewDomain,

        [Parameter(Mandatory=$True)]
        [pscredential]$DomainAdminCredentials, # If creating a New Domain, this will be a New Domain Account

        [Parameter(Mandatory=$False)]
        [pscredential]$LocalAdministratorAccountCredentials,

        [Parameter(Mandatory=$False)]
        [pscredential]$PSRemotingCredentials, # These credentials must grant access to ALL Servers

        [Parameter(Mandatory=$False)]
        [string]$ExistingDomain,

        [Parameter(Mandatory=$False)]
        [switch]$DCIsRootCA,

        [Parameter(Mandatory=$False)]
        [string]$IPofServerToBeDomainController,

        [Parameter(Mandatory=$False)]
        [string]$IPofServerToBeRootCA,

        [Parameter(Mandatory=$False)]
        [string]$IPofServerToBeSubCA,

        [Parameter(Mandatory=$False)]
        [switch]$SkipHyperVInstallCheck
    )

    "placeholder"
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUj9qfmI3RWxusPz7RRrx94Ao2
# IYKgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFLfDnN3G+11t4L9U
# 1m76ZUD0MSyBMA0GCSqGSIb3DQEBAQUABIIBABFxIwXq3ea587KDVLsgM0cWkB23
# kQgrnqgs/27DsrsAW+z7k528Kw00449vyWxRckYIIt72BaiDST+rGVEOzEE3pujB
# TGdJ2GAnxzHZyiI+vFwDeNEQyTox8DlCHV5ynZdqhnHfDJunGTJNENh08ng5SNKP
# FkG2hsx6VZp3xiE6Pa5Iz/1AokAUZ5377/4X25Ah08ObPYLjUnLeUklALJI9D1Pq
# BjsO8pfHPtzASFl1cBHdq+aIqSUhbsggqY7IDlL49ARfCz9lgtFvJJl5PW68a0Dh
# mou9vq7Ek4nOsKa0zYNfoxlxIcM1Y2XIGPT3h46wayh0n7S0gsBcaPd5qqA=
# SIG # End signature block
