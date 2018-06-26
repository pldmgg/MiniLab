<#
    .SYNOPSIS
        This function configures the target Windows 2012 R2 or Windows 2016 Server to be a new Enterprise Root Certification Authority.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER DomainAdminCredentials
        This parameter is MANDATORY.

        This parameter takes a PSCredential. The Domain Admin Credentials will be used to configure the new Root CA. This means that
        the Domain Account provided MUST be a member of the following Security Groups in Active Directory:
            - Domain Admins
            - Domain Users
            - Enterprise Admins
            - Group Policy Creator Owners
            - Schema Admins

    .PARAMETER RootCAIPOrFQDN
        This parameter is OPTIONAL.

        This parameter takes a string that represents an IPv4 address or DNS-Resolveable FQDN that refers to the target Windows
        Server that will become the new Enterprise Root CA. If it is NOT used, then the localhost will be configured as the
        new Enterprise Root CA.

    .PARAMETER CAType
        This parameter is OPTIONAL, however, its default value is "EnterpriseRootCA".

        This parameter takes a string that represents the type of Root Certificate Authority that the target server will become.
        Currently this parameter only accepts "EnterpriseRootCA" as a valid value. But in the future, "StandaloneRootCA" will
        also become a valid value.

    .PARAMETER NewComputerTemplateCommonName
        This parameter is OPTIONAL, however, its default value is "<DomainPrefix>" + "Computer".

        This parameter takes a string that represents the desired Common Name for the new custom Computer (Machine)
        Certificate Template. This updates some undesirable defaults that come with the default Computer (Machine)
        Certificate Template.

    .PARAMETER NewWebServerTemplateCommonName
        This parameter is OPTIONAL, however, its default value is "<DomainPrefix>" + "WebServer".

        This parameter takes a string that represents the desired Common Name for the new custom WebServer
        Certificate Template. This updates some undesirable defaults that come with the default WebServer
        Certificate Template.

    .PARAMETER FileOutputDirectory
        This parameter is OPTIONAL, however, its default value is "C:\NewRootCAOutput".

        This parameter takes a string that represents the full path to a directory that will contain all files generated
        by the New-RootCA function.

        IMPORTANT NOTE: This directory will be made available to the network (it will become an SMB Share) so that the
        Subordinate Certificate Authority can download needed files. This SMB share will only be available TEMPORARILY.
        It will NOT survive a reboot.

    .PARAMETER CryptoProvider
        This parameter is OPTIONAL, however, its default value is "Microsoft Software Key Storage Provider".

        This parameter takes a string that represents the Cryptographic Provider used by the new Root CA.
        Currently, the only valid value for this parameter is "Microsoft Software Key Storage Provider".

    .PARAMETER KeyLength
        This parameter is OPTIONAL, however, its default value is 2048.

        This parameter takes an integer with value 2048 or 4096.

    .PARAMETER HashAlgorithm
        This parameter is OPTIONAL, however, its default value is SHA256.

        This parameter takes a string with acceptable values as follows: "SHA1","SHA256","SHA384","SHA512","MD5","MD4","MD2"

    .PARAMETER KeyAlgorithmValue
        This parameter is OPTIONAL, however, its default value is RSA.

        This parameter takes a string with acceptable values: "RSA"

    .PARAMETER CDPUrl
        This parameter is OPTIONAL, however, its default value is "http://pki.$DomainName/certdata/<CaName><CRLNameSuffix>.crl"

        This parameter takes a string that represents a Certificate Distribution List Revocation URL. The current default
        configuration does not make this Url active, however, it still needs to be configured.

    .PARAMETER AIAUrl
        This parameter is OPTIONAL, however, its default value is "http://pki.$DomainName/certdata/<CaName><CertificateName>.crt"

        This parameter takes a string that represents an Authority Information Access (AIA) Url (i.e. the location where the certificate of
        of certificate's issuer can be downloaded). The current default configuration does not mahe this Url active, but it still
        needs to be configured.

    .EXAMPLE
        # Make the localhost a Root CA

        PS C:\Users\zeroadmin> $DomainAdminCreds = [pscredential]::new("alpha\alphaadmin",$(Read-Host 'Enter Passsword' -AsSecureString))
        Enter Passsword: ************
        PS C:\Users\zeroadmin> $CreateRootCASplatParams = @{
        >> DomainAdminCredentials   = $DomainAdminCreds
        >> }
        PS C:\Users\zeroadmin> $CreateRootCAResult = Create-RootCA @CreateRootCASplatParams

    .EXAMPLE
        # Make the Remote Host a Root CA

        PS C:\Users\zeroadmin> $DomainAdminCreds = [pscredential]::new("alpha\alphaadmin",$(Read-Host 'Enter Passsword' -AsSecureString))
        Enter Passsword: ************
        PS C:\Users\zeroadmin> $CreateRootCASplatParams = @{
        >> DomainAdminCredentials   = $DomainAdminCreds
        >> RootCAIPOrFQDN           = "192.168.2.112"                
        >> }
        PS C:\Users\zeroadmin> $CreateRootCAResult = Create-RootCA @CreateRootCASplatParams

#>
function New-RootCA {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [pscredential]$DomainAdminCredentials,

        [Parameter(Mandatory=$False)]
        [string]$RootCAIPOrFQDN,

        [Parameter(Mandatory=$False)]
        #[ValidateSet("EnterpriseRootCa","StandaloneRootCa")]
        [ValidateSet("EnterpriseRootCA")]
        [string]$CAType,

        [Parameter(Mandatory=$False)]
        [string]$NewComputerTemplateCommonName,

        [Parameter(Mandatory=$False)]
        [string]$NewWebServerTemplateCommonName,

        [Parameter(Mandatory=$False)]
        [string]$FileOutputDirectory,

        [Parameter(Mandatory=$False)]
        <#
        [ValidateSet("Microsoft Base Cryptographic Provider v1.0","Microsoft Base DSS and Diffie-Hellman Cryptographic Provider",
        "Microsoft Base DSS Cryptographic Provider","Microsoft Base Smart Card Crypto Provider",
        "Microsoft DH SChannel Cryptographic Provider","Microsoft Enhanced Cryptographic Provider v1.0",
        "Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider",
        "Microsoft Enhanced RSA and AES Cryptographic Provider","Microsoft RSA SChannel Cryptographic Provider",
        "Microsoft Strong Cryptographic Provider","Microsoft Software Key Storage Provider",
        "Microsoft Passport Key Storage Provider")]
        #>
        [ValidateSet("Microsoft Software Key Storage Provider")]
        [string]$CryptoProvider,

        [Parameter(Mandatory=$False)]
        [ValidateSet("2048","4096")]
        [int]$KeyLength,

        [Parameter(Mandatory=$False)]
        [ValidateSet("SHA1","SHA256","SHA384","SHA512","MD5","MD4","MD2")]
        [string]$HashAlgorithm,

        # For now, stick to just using RSA
        [Parameter(Mandatory=$False)]
        #[ValidateSet("RSA","DH","DSA","ECDH_P256","ECDH_P521","ECDSA_P256","ECDSA_P384","ECDSA_P521")]
        [ValidateSet("RSA")]
        [string]$KeyAlgorithmValue,

        [Parameter(Mandatory=$False)]
        [ValidatePattern('http.*?\/<CaName><CRLNameSuffix>\.crl$')]
        [string]$CDPUrl,

        [Parameter(Mandatory=$False)]
        [ValidatePattern('http.*?\/<CaName><CertificateName>.crt$')]
        [string]$AIAUrl
    )
    
    #region >> Helper Functions

    # NewUniqueString
    # TestIsValidIPAddress
    # ResolveHost
    # GetDomainController

    function SetupRootCA {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=$True)]
            [pscredential]$DomainAdminCredentials,

            [Parameter(Mandatory=$True)]
            [System.Collections.ArrayList]$NetworkInfoPSObjects,

            [Parameter(Mandatory=$True)]
            [ValidateSet("EnterpriseRootCA")]
            [string]$CAType,

            [Parameter(Mandatory=$True)]
            [string]$NewComputerTemplateCommonName,

            [Parameter(Mandatory=$True)]
            [string]$NewWebServerTemplateCommonName,

            [Parameter(Mandatory=$True)]
            [string]$FileOutputDirectory,

            [Parameter(Mandatory=$True)]
            [ValidateSet("Microsoft Software Key Storage Provider")]
            [string]$CryptoProvider,

            [Parameter(Mandatory=$True)]
            [ValidateSet("2048","4096")]
            [int]$KeyLength,

            [Parameter(Mandatory=$True)]
            [ValidateSet("SHA1","SHA256","SHA384","SHA512","MD5","MD4","MD2")]
            [string]$HashAlgorithm,

            [Parameter(Mandatory=$True)]
            [ValidateSet("RSA")]
            [string]$KeyAlgorithmValue,

            [Parameter(Mandatory=$True)]
            [ValidatePattern('http.*?\/<CaName><CRLNameSuffix>\.crl$')]
            [string]$CDPUrl,

            [Parameter(Mandatory=$True)]
            [ValidatePattern('http.*?\/<CaName><CertificateName>.crt$')]
            [string]$AIAUrl
        )

        #region >> Prep

        # Import any Module Dependencies
        $RequiredModules = @("PSPKI","ServerManager")
        $InvModDepSplatParams = @{
            RequiredModules                     = $RequiredModules
            InstallModulesNotAvailableLocally   = $True
            ErrorAction                         = "Stop"
        }
        $ModuleDependenciesMap = InvokeModuleDependencies @InvModDepSplatParams
        $PSPKIModuleVerCheck = $ModuleDependenciesMap.SuccessfulModuleImports | Where-Object {$_.ModuleName -eq "PSPKI"}
        $ServerManagerModuleVerCheck = $ModuleDependenciesMap.SuccessfulModuleImports | Where-Object {$_.ModuleName -eq "ServerManager"}

        # Make sure we can find the Domain Controller(s)
        try {
            $DomainControllerInfo = GetDomainController -Domain $(Get-CimInstance win32_computersystem).Domain -WarningAction SilentlyContinue
            if (!$DomainControllerInfo -or $DomainControllerInfo.PrimaryDomainController -eq $null) {throw "Unable to find Primary Domain Controller! Halting!"}
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        # Make sure time is synchronized with NTP Servers/Domain Controllers (i.e. might be using NT5DS instead of NTP)
        # See: https://giritharan.com/time-synchronization-in-active-directory-domain/
        $null = W32tm /resync /rediscover /nowait

        if (!$FileOutputDirectory) {
            $FileOutputDirectory = "C:\NewRootCAOutput"
        }
        if (!$(Test-Path $FileOutputDirectory)) {
            $null = New-Item -ItemType Directory -Path $FileOutputDirectory 
        }

        $WindowsFeaturesToAdd = @(
            "Adcs-Cert-Authority"
            "RSAT-AD-Tools"
        )
        foreach ($FeatureName in $WindowsFeaturesToAdd) {
            $SplatParams = @{
                Name    = $FeatureName
            }
            if ($FeatureName -eq "Adcs-Cert-Authority") {
                $SplatParams.Add("IncludeManagementTools",$True)
            }

            try {
                $null = Add-WindowsFeature @SplatParams
            }
            catch {
                Write-Error $_
                Write-Error "Problem with 'Add-WindowsFeature $FeatureName'! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        $RelevantRootCANetworkInfo = $NetworkInfoPSObjects | Where-Object {$_.ServerPurpose -eq "RootCA"}

        # Make sure WinRM in Enabled and Running on $env:ComputerName
        try {
            $null = Enable-PSRemoting -Force -ErrorAction Stop
        }
        catch {
            $NICsWPublicProfile = @(Get-NetConnectionProfile | Where-Object {$_.NetworkCategory -eq 0})
            if ($NICsWPublicProfile.Count -gt 0) {
                foreach ($Nic in $NICsWPublicProfile) {
                    Set-NetConnectionProfile -InterfaceIndex $Nic.InterfaceIndex -NetworkCategory 'Private'
                }
            }

            try {
                $null = Enable-PSRemoting -Force
            }
            catch {
                Write-Error $_
                Write-Error "Problem with Enabble-PSRemoting WinRM Quick Config! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }

        # If $env:ComputerName is not part of a Domain, we need to add this registry entry to make sure WinRM works as expected
        if (!$(Get-CimInstance Win32_Computersystem).PartOfDomain) {
            $null = reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
        }

        # Add the New Server's IP Addresses to $env:ComputerName's TrustedHosts
        $CurrentTrustedHosts = $(Get-Item WSMan:\localhost\Client\TrustedHosts).Value
        [System.Collections.ArrayList][array]$CurrentTrustedHostsAsArray = $CurrentTrustedHosts -split ','

        $ItemsToAddToWSMANTrustedHosts = @(
            $RelevantRootCANetworkInfo.FQDN
            $RelevantRootCANetworkInfo.HostName
            $RelevantRootCANetworkInfo.IPAddress
        )
        foreach ($NetItem in $ItemsToAddToWSMANTrustedHosts) {
            if ($CurrentTrustedHostsAsArray -notcontains $NetItem) {
                $null = $CurrentTrustedHostsAsArray.Add($NetItem)
            }
        }
        $UpdatedTrustedHostsString = $($CurrentTrustedHostsAsArray | Where-Object {![string]::IsNullOrWhiteSpace($_)}) -join ','
        Set-Item WSMan:\localhost\Client\TrustedHosts $UpdatedTrustedHostsString -Force

        #endregion >> Prep

        #region >> Install ADCSCA
        try {
            $FinalCryptoProvider = $KeyAlgorithmValue + "#" + $CryptoProvider
            $InstallADCSCertAuthSplatParams = @{
                Credential                  = $DomainAdminCredentials
                CAType                      = $CAType
                CryptoProviderName          = $FinalCryptoProvider
                KeyLength                   = $KeyLength
                HashAlgorithmName           = $HashAlgorithm
                CACommonName                = $env:ComputerName
                CADistinguishedNameSuffix   = $RelevantRootCANetworkInfo.DomainLDAPString
                DatabaseDirectory           = $(Join-Path $env:SystemRoot "System32\CertLog")
                ValidityPeriod              = "years"
                ValidityPeriodUnits         = 20
                Force                       = $True
                ErrorAction                 = "Stop"
            }
            $null = Install-AdcsCertificationAuthority @InstallADCSCertAuthSplatParams
        }
        catch {
            Write-Error $_
            Write-Error "Problem with Install-AdcsCertificationAuthority cmdlet! Halting!"
            $global:FunctionResult = "1"
            return
        }

        try {
            $null = certutil -setreg CA\\CRLPeriod "Years"
            $null = certutil -setreg CA\\CRLPeriodUnits 1
            $null = certutil -setreg CA\\CRLOverlapPeriod "Days"
            $null = certutil -setreg CA\\CRLOverlapUnits 7

            Write-Host "Done initial certutil commands..."

            # Remove pre-existing ldap/http CDPs, add custom CDP
            if ($PSPKIModuleVerCheck.ModulePSCompatibility -eq "WinPS") {
                # Update the Local CDP
                $LocalCDP = (Get-CACrlDistributionPoint)[0]
                $null = $LocalCDP | Remove-CACrlDistributionPoint -Force
                $LocalCDP.PublishDeltaToServer = $false
                $null = $LocalCDP | Add-CACrlDistributionPoint -Force

                $null = Get-CACrlDistributionPoint | Where-Object { $_.URI -like "http*" -or $_.Uri -like "ldap*" } | Remove-CACrlDistributionPoint -Force
                $null = Add-CACrlDistributionPoint -Uri $CDPUrl -AddToCertificateCdp -Force

                # Remove pre-existing ldap/http AIAs, add custom AIA
                $null = Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like "http*" -or $_.Uri -like "ldap*" } | Remove-CAAuthorityInformationAccess -Force
                $null = Add-CAAuthorityInformationAccess -Uri $AIAUrl -AddToCertificateAIA -Force
            }
            else {
                $null = Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                    # Update the Local CDP
                    $LocalCDP = (Get-CACrlDistributionPoint)[0]
                    $null = $LocalCDP | Remove-CACrlDistributionPoint -Force
                    $LocalCDP.PublishDeltaToServer = $false
                    $null = $LocalCDP | Add-CACrlDistributionPoint -Force

                    $null = Get-CACrlDistributionPoint | Where-Object { $_.URI -like "http*" -or $_.Uri -like "ldap*" } | Remove-CACrlDistributionPoint -Force
                    $null = Add-CACrlDistributionPoint -Uri $args[0] -AddToCertificateCdp -Force

                    # Remove pre-existing ldap/http AIAs, add custom AIA
                    $null = Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like "http*" -or $_.Uri -like "ldap*" } | Remove-CAAuthorityInformationAccess -Force
                    $null = Add-CAAuthorityInformationAccess -Uri $args[1] -AddToCertificateAIA -Force
                } -ArgumentList $CDPUrl,$AIAUrl
            }

            Write-Host "Done CDP and AIA cmdlets..."

            # Enable all event auditing
            $null = certutil -setreg CA\\AuditFilter 127

            Write-Host "Done final certutil command..."
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }

        try {
            $null = Restart-Service certsvc -ErrorAction Stop
        }
        catch {
            Write-Error $_
            Write-Error "Problem with 'Restart-Service certsvc'! Halting!"
            $global:FunctionResult = "1"
            return
        }

        while ($(Get-Service certsvc).Status -ne "Running") {
            Write-Host "Waiting for the 'certsvc' service to start..."
            Start-Sleep -Seconds 5
        }

        #endregion >> Install ADCSCA

        #region >> New Computer/Machine Template

        Write-Host "Creating new Machine Certificate Template..."

        while (!$WebServTempl -or !$ComputerTempl) {
            # NOTE: ADSI type accelerator does not exist in PSCore
            if ($PSVersionTable.PSEdition -ne "Core") {
                $ConfigContext = $([ADSI]"LDAP://RootDSE").ConfigurationNamingContext
            }
            else {
                $DomainSplit = $(Get-CimInstance win32_computersystem).Domain -split "\."
                $ConfigContext = "CN=Configuration," + $($(foreach ($DC in $DomainSplit) {"DC=$DC"}) -join ",")
            }

            $LDAPLocation = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"
            $ADSI = New-Object System.DirectoryServices.DirectoryEntry($LDAPLocation,$DomainAdminCredentials.UserName,$($DomainAdminCredentials.GetNetworkCredential().Password),"Secure")

            $WebServTempl = $ADSI.psbase.children | Where-Object {$_.distinguishedName -match "CN=WebServer,"}
            $ComputerTempl = $ADSI.psbase.children | Where-Object {$_.distinguishedName -match "CN=Machine,"}

            Write-Host "Waiting for Active Directory 'LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext' to contain default Machine/Computer and WebServer Certificate Templates..."
            Start-Sleep -Seconds 15
        }

        $OIDRandComp = (Get-Random -Maximum 999999999999999).tostring('d15')
        $OIDRandComp = $OIDRandComp.Insert(8,'.')
        $CompOIDValue = $ComputerTempl.'msPKI-Cert-Template-OID'
        $NewCompTemplOID = $CompOIDValue.subString(0,$CompOIDValue.length-4)+$OIDRandComp

        $NewCompTempl = $ADSI.Create("pKICertificateTemplate","CN=$NewComputerTemplateCommonName")
        $NewCompTempl.put("distinguishedName","CN=$NewComputerTemplateCommonName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext")
        $NewCompTempl.put("flags","131680")
        $NewCompTempl.put("displayName","$NewComputerTemplateCommonName")
        $NewCompTempl.put("revision","100")
        $NewCompTempl.put("pKIDefaultKeySpec","1")
        $NewCompTempl.put("pKIMaxIssuingDepth","0")
        $pkiCritExt = "2.5.29.17","2.5.29.15"
        $NewCompTempl.put("pKICriticalExtensions",$pkiCritExt)
        $ExtKeyUse = "1.3.6.1.5.5.7.3.1","1.3.6.1.5.5.7.3.2"
        $NewCompTempl.put("pKIExtendedKeyUsage",$ExtKeyUse)
        $NewCompTempl.put("pKIDefaultCSPs","1,Microsoft RSA SChannel Cryptographic Provider")
        $NewCompTempl.put("msPKI-RA-Signature","0")
        $NewCompTempl.put("msPKI-Enrollment-Flag","0")
        $NewCompTempl.put("msPKI-Private-Key-Flag","0") # Used to be "50659328"
        $NewCompTempl.put("msPKI-Certificate-Name-Flag","1")
        $NewCompTempl.put("msPKI-Minimal-Key-Size","2048")
        $NewCompTempl.put("msPKI-Template-Schema-Version","2") # This needs to be either "1" or "2" for it to show up in the ADCS Website dropdown
        $NewCompTempl.put("msPKI-Template-Minor-Revision","2")
        $NewCompTempl.put("msPKI-Cert-Template-OID","$NewCompTemplOID")
        $AppPol = "1.3.6.1.5.5.7.3.1","1.3.6.1.5.5.7.3.2"
        $NewCompTempl.put("msPKI-Certificate-Application-Policy",$AppPol)
        $NewCompTempl.Setinfo()
        # Get the last few attributes from the existing default "CN=Machine" Certificate Template
        $NewCompTempl.pKIOverlapPeriod = $ComputerTempl.pKIOverlapPeriod # Used to be $WebServTempl.pKIOverlapPeriod
        $NewCompTempl.pKIKeyUsage = $ComputerTempl.pKIKeyUsage # Used to be $WebServTempl.pKIKeyUsage
        $NewCompTempl.pKIExpirationPeriod = $ComputerTempl.pKIExpirationPeriod # Used to be $WebServTempl.pKIExpirationPeriod
        $NewCompTempl.Setinfo()

        # Set Access Rights / Permissions on the $NewCompTempl LDAP object
        $AdObj = New-Object System.Security.Principal.NTAccount("Domain Computers")
        $identity = $AdObj.Translate([System.Security.Principal.SecurityIdentifier])
        $adRights = "ExtendedRight"
        $type = "Allow"
        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity,$adRights,$type)
        $NewCompTempl.psbase.ObjectSecurity.SetAccessRule($ACE)
        $NewCompTempl.psbase.commitchanges()

        #endregion >> New Computer/Machine Template

        #region >> New WebServer Template

        Write-Host "Creating new WebServer Certificate Template..."

        $OIDRandWebServ = (Get-Random -Maximum 999999999999999).tostring('d15')
        $OIDRandWebServ = $OIDRandWebServ.Insert(8,'.')
        $WebServOIDValue = $WebServTempl.'msPKI-Cert-Template-OID'
        $NewWebServTemplOID = $WebServOIDValue.subString(0,$WebServOIDValue.length-4)+$OIDRandWebServ

        $NewWebServTempl = $ADSI.Create("pKICertificateTemplate", "CN=$NewWebServerTemplateCommonName") 
        $NewWebServTempl.put("distinguishedName","CN=$NewWebServerTemplateCommonName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext")
        $NewWebServTempl.put("flags","131649")
        $NewWebServTempl.put("displayName","$NewWebServerTemplateCommonName")
        $NewWebServTempl.put("revision","100")
        $NewWebServTempl.put("pKIDefaultKeySpec","1")
        $NewWebServTempl.put("pKIMaxIssuingDepth","0")
        $pkiCritExt = "2.5.29.15"
        $NewWebServTempl.put("pKICriticalExtensions",$pkiCritExt)
        $ExtKeyUse = "1.3.6.1.5.5.7.3.1","1.3.6.1.5.5.7.3.2"
        $NewWebServTempl.put("pKIExtendedKeyUsage",$ExtKeyUse)
        $pkiCSP = "1,Microsoft RSA SChannel Cryptographic Provider","2,Microsoft DH SChannel Cryptographic Provider"
        $NewWebServTempl.put("pKIDefaultCSPs",$pkiCSP)
        $NewWebServTempl.put("msPKI-RA-Signature","0")
        $NewWebServTempl.put("msPKI-Enrollment-Flag","0")
        $NewWebServTempl.put("msPKI-Private-Key-Flag","0") # Used to be "16842752"
        $NewWebServTempl.put("msPKI-Certificate-Name-Flag","1")
        $NewWebServTempl.put("msPKI-Minimal-Key-Size","2048")
        $NewWebServTempl.put("msPKI-Template-Schema-Version","2") # This needs to be either "1" or "2" for it to show up in the ADCS Website dropdown
        $NewWebServTempl.put("msPKI-Template-Minor-Revision","2")
        $NewWebServTempl.put("msPKI-Cert-Template-OID","$NewWebServTemplOID")
        $AppPol = "1.3.6.1.5.5.7.3.1","1.3.6.1.5.5.7.3.2"
        $NewWebServTempl.put("msPKI-Certificate-Application-Policy",$AppPol)
        $NewWebServTempl.Setinfo()
        # Get the last few attributes from the existing default "CN=WebServer" Certificate Template
        $NewWebServTempl.pKIOverlapPeriod = $WebServTempl.pKIOverlapPeriod
        $NewWebServTempl.pKIKeyUsage = $WebServTempl.pKIKeyUsage
        $NewWebServTempl.pKIExpirationPeriod = $WebServTempl.pKIExpirationPeriod
        $NewWebServTempl.Setinfo()

        #endregion >> New WebServer Template

        #region >> Finish Up

        # Add the newly created custom Computer and WebServer Certificate Templates to List of Certificate Templates to Issue
        # For this to be (relatively) painless, we need the following PSPKI Module cmdlets
        if ($PSPKIModuleVerCheck.ModulePSCompatibility -eq "WinPS") {
            $null = Get-CertificationAuthority -Name $env:ComputerName | Get-CATemplate | Add-CATemplate -Name $NewComputerTemplateCommonName | Set-CATemplate
            $null = Get-CertificationAuthority -Name $env:ComputerName | Get-CATemplate | Add-CATemplate -Name $NewWebServerTemplateCommonName | Set-CATemplate
        }
        else {
            $null = Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                $null = Get-CertificationAuthority -Name $env:ComputerName | Get-CATemplate | Add-CATemplate -Name $args[0] | Set-CATemplate
                $null = Get-CertificationAuthority -Name $env:ComputerName | Get-CATemplate | Add-CATemplate -Name $args[1] | Set-CATemplate
            } -ArgumentList $NewComputerTemplateCommonName,$NewWebServerTemplateCommonName
        }

        # Export New Certificate Templates to NewCert-Templates Directory
        $ldifdeUserName = $($DomainAdminCredentials.UserName -split "\\")[-1]
        $ldifdeDomain = $RelevantRootCANetworkInfo.DomainName
        $ldifdePwd = $DomainAdminCredentials.GetNetworkCredential().Password
        $null = ldifde -m -v -b $ldifdeUserName $ldifdeDomain $ldifdePwd -d "CN=$NewComputerTemplateCommonName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext" -f "$FileOutputDirectory\$NewComputerTemplateCommonName.ldf"
        $null = ldifde -m -v -b $ldifdeUserName $ldifdeDomain $ldifdePwd -d "CN=$NewWebServerTemplateCommonName,CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext" -f "$FileOutputDirectory\$NewWebServerTemplateCommonName.ldf"

        # Side Note: You can import Certificate Templates on another Certificate Authority via ldife.exe with:
        <#
        ldifde -i -k -f "$FileOutputDirectory\$NewComputerTemplateCommonName.ldf"
        ldifde -i -k -f "$FileOutputDirectory\$NewWebServerTemplateCommonName.ldf"
        #>

        # Generate New CRL and Copy Contents of CertEnroll to $FileOutputDirectory
        # NOTE: The below 'certutil -crl' outputs the new .crl file to "C:\Windows\System32\CertSrv\CertEnroll"
        # which happens to contain some other important files that we'll need
        $null = certutil -crl
        Copy-Item -Path "C:\Windows\System32\CertSrv\CertEnroll\*" -Recurse -Destination $FileOutputDirectory -Force
        # Convert RootCA .crt DER Certificate to Base64 Just in Case You Want to Use With Linux
        $CrtFileItem = Get-ChildItem -Path $FileOutputDirectory -File -Recurse | Where-Object {$_.Name -match "$env:ComputerName\.crt"}
        $null = certutil -encode $($CrtFileItem.FullName) $($CrtFileItem.FullName -replace '\.crt','_base64.cer')

        # Make $FileOutputDirectory a Network Share until the Subordinate CA can download the files
        # IMPORTANT NOTE: The below -CATimeout parameter should be in Seconds. So after 12000 seconds, the SMB Share
        # will no longer be available
        # IMPORTANT NOTE: The below -Temporary switch means that the SMB Share will NOT survive a reboot
        $null = New-SMBShare -Name RootCAFiles -Path $FileOutputDirectory -CATimeout 12000 -Temporary
        # Now the SMB Share  should be available
        $RootCASMBShareFQDNLocation = '\\' + $RelevantRootCANetworkInfo.FQDN + "\RootCAFiles"
        $RootCASMBShareIPLocation = '\\' + $RelevantRootCANetworkInfo.IPAddress + "\RootCAFiles"

        Write-Host "Successfully configured Root Certificate Authority" -ForegroundColor Green
        Write-Host "RootCA Files needed by the new Subordinate/Issuing/Intermediate CA Server(s) are now TEMPORARILY available at SMB Share located:`n$RootCASMBShareFQDNLocation`nOR`n$RootCASMBShareIPLocation" -ForegroundColor Green
        
        #endregion >> Finish Up

        [pscustomobject] @{
            SMBShareIPLocation = $RootCASMBShareIPLocation
            SMBShareFQDNLocation = $RootCASMBShareFQDNLocation
        }
    }

    #endregion >> Helper Functions


    #region >> Initial Prep

    $ElevationCheck = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    if (!$ElevationCheck) {
        Write-Error "You must run the build.ps1 as an Administrator (i.e. elevated PowerShell Session)! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $PrimaryIfIndex = $(Get-CimInstance Win32_IP4RouteTable | Where-Object {
        $_.Destination -eq '0.0.0.0' -and $_.Mask -eq '0.0.0.0'
    } | Sort-Object Metric1)[0].InterfaceIndex
    $NicInfo = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object {$_.InterfaceIndex -eq $PrimaryIfIndex}
    $PrimaryIP = $NicInfo.IPAddress | Where-Object {TestIsValidIPAddress -IPAddress $_}

    [System.Collections.ArrayList]$NetworkLocationObjsToResolve = @()
    if ($PSBoundParameters['RootCAIPOrFQDN']) {
        $RootCAPSObj = [pscustomobject]@{
            ServerPurpose       = "RootCA"
            NetworkLocation     = $RootCAIPOrFQDN
        }
    }
    else {
        $RootCAPSObj = [pscustomobject]@{
            ServerPurpose       = "RootCA"
            NetworkLocation     = $env:ComputerName + "." + $(Get-CimInstance win32_computersystem).Domain
        }
    }
    $null = $NetworkLocationObjsToResolve.Add($RootCAPSObj)

    [System.Collections.ArrayList]$NetworkInfoPSObjects = @()
    foreach ($NetworkLocationObj in $NetworkLocationObjsToResolve) {
        if ($($NetworkLocation -split "\.")[0] -ne $env:ComputerName -and
        $NetworkLocation -ne $PrimaryIP -and
        $NetworkLocation -ne "$env:ComputerName.$($(Get-CimInstance win32_computersystem).Domain)"
        ) {
            try {
                $NetworkInfo = ResolveHost -HostNameOrIP $NetworkLocationObj.NetworkLocation
                $DomainName = $NetworkInfo.Domain
                $FQDN = $NetworkInfo.FQDN
                $IPAddr = $NetworkInfo.IPAddressList[0]
                $DomainShortName = $($DomainName -split "\.")[0]
                $DomainLDAPString = $(foreach ($StringPart in $($DomainName -split "\.")) {"DC=$StringPart"}) -join ','

                if (!$NetworkInfo -or $DomainName -eq "Unknown" -or !$DomainName -or $FQDN -eq "Unknown" -or !$FQDN) {
                    throw "Unable to gather Domain Name and/or FQDN info about '$NetworkLocation'! Please check DNS. Halting!"
                }
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                return
            }

            # Make sure WinRM in Enabled and Running on $env:ComputerName
            try {
                $null = Enable-PSRemoting -Force -ErrorAction Stop
            }
            catch {
                $NICsWPublicProfile = @(Get-NetConnectionProfile | Where-Object {$_.NetworkCategory -eq 0})
                if ($NICsWPublicProfile.Count -gt 0) {
                    foreach ($Nic in $NICsWPublicProfile) {
                        Set-NetConnectionProfile -InterfaceIndex $Nic.InterfaceIndex -NetworkCategory 'Private'
                    }
                }

                try {
                    $null = Enable-PSRemoting -Force
                }
                catch {
                    Write-Error $_
                    Write-Error "Problem with Enabble-PSRemoting WinRM Quick Config! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }

            # If $env:ComputerName is not part of a Domain, we need to add this registry entry to make sure WinRM works as expected
            if (!$(Get-CimInstance Win32_Computersystem).PartOfDomain) {
                $null = reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
            }

            # Add the New Server's IP Addresses to $env:ComputerName's TrustedHosts
            $CurrentTrustedHosts = $(Get-Item WSMan:\localhost\Client\TrustedHosts).Value
            [System.Collections.ArrayList][array]$CurrentTrustedHostsAsArray = $CurrentTrustedHosts -split ','

            $ItemsToAddToWSMANTrustedHosts = @($IPAddr,$FQDN,$($($FQDN -split "\.")[0]))
            foreach ($NetItem in $ItemsToAddToWSMANTrustedHosts) {
                if ($CurrentTrustedHostsAsArray -notcontains $NetItem) {
                    $null = $CurrentTrustedHostsAsArray.Add($NetItem)
                }
            }
            $UpdatedTrustedHostsString = $($CurrentTrustedHostsAsArray | Where-Object {![string]::IsNullOrWhiteSpace($_)}) -join ','
            Set-Item WSMan:\localhost\Client\TrustedHosts $UpdatedTrustedHostsString -Force
        }
        else {
            $DomainName = $(Get-CimInstance win32_computersystem).Domain
            $DomainShortName = $($DomainName -split "\.")[0]
            $DomainLDAPString = $(foreach ($StringPart in $($DomainName -split "\.")) {"DC=$StringPart"}) -join ','
            $FQDN = $env:ComputerName + '.' + $DomainName
            $IPAddr = $PrimaryIP
        }

        $PSObj = [pscustomobject]@{
            ServerPurpose       = $NetworkLocationObj.ServerPurpose
            FQDN                = $FQDN
            HostName            = $($FQDN -split "\.")[0]
            IPAddress           = $IPAddr
            DomainName          = $DomainName
            DomainShortName     = $DomainShortName
            DomainLDAPString    = $DomainLDAPString
        }
        $null = $NetworkInfoPSObjects.Add($PSObj)
    }

    $RelevantRootCANetworkInfo = $NetworkInfoPSObjects | Where-Object {$_.ServerPurpose -eq "RootCA"}

    # Set some defaults if certain paramters are not used
    if (!$CAType) {
        $CAType = "EnterpriseRootCA"
    }
    if (!$NewComputerTemplateCommonName) {
        $NewComputerTemplateCommonName = $DomainShortName + "Computer"
        #$NewComputerTemplateCommonName = "Machine"
    }
    if (!$NewWebServerTemplateCommonName) {
        $NewWebServerTemplateCommonName = $DomainShortName + "WebServer"
        #$NewWebServerTemplateCommonName = "WebServer"
    }
    if (!$FileOutputDirectory) {
        $FileOutputDirectory = "C:\NewRootCAOutput"
    }
    if (!$CryptoProvider) {
        $CryptoProvider = "Microsoft Software Key Storage Provider"
    }
    if (!$KeyLength) {
        $KeyLength = 2048
    }
    if (!$HashAlgorithm) {
        $HashAlgorithm = "SHA256"
    }
    if (!$KeyAlgorithmValue) {
        $KeyAlgorithmValue = "RSA"
    }
    if (!$CDPUrl) {
        $CDPUrl = "http://pki.$($RelevantRootCANetworkInfo.DomainName)/certdata/<CaName><CRLNameSuffix>.crl"
    }
    if (!$AIAUrl) {
        $AIAUrl = "http://pki.$($RelevantRootCANetworkInfo.DomainName)/certdata/<CaName><CertificateName>.crt"
    }

    # Create SetupRootCA Helper Function Splat Parameters
    $SetupRootCASplatParams = @{
        DomainAdminCredentials              = $DomainAdminCredentials
        NetworkInfoPSObjects                = $NetworkInfoPSObjects
        CAType                              = $CAType
        NewComputerTemplateCommonName       = $NewComputerTemplateCommonName
        NewWebServerTemplateCommonName      = $NewWebServerTemplateCommonName
        FileOutputDirectory                 = $FileOutputDirectory
        CryptoProvider                      = $CryptoProvider
        KeyLength                           = $KeyLength
        HashAlgorithm                       = $HashAlgorithm
        KeyAlgorithmValue                   = $KeyAlgorithmValue
        CDPUrl                              = $CDPUrl
        AIAUrl                              = $AIAUrl
    }

    # Install any required PowerShell Modules
    <#
    # NOTE: This is handled by the MiniLab Module Import
    $RequiredModules = @("PSPKI")
    $InvModDepSplatParams = @{
        RequiredModules                     = $RequiredModules
        InstallModulesNotAvailableLocally   = $True
        ErrorAction                         = "Stop"
    }
    $ModuleDependenciesMap = InvokeModuleDependencies @InvModDepSplatParams
    #>

    #endregion >> Initial Prep


    #region >> Do RootCA Install

    if ($RelevantRootCANetworkInfo.HostName -ne $env:ComputerName) {
        $PSSessionName = NewUniqueString -ArrayOfStrings $(Get-PSSession).Name -PossibleNewUniqueString "ToRootCA"

        # Try to create a PSSession to the Root CA for 15 minutes, then give up
        $Counter = 0
        while (![bool]$(Get-PSSession -Name $PSSessionName -ErrorAction SilentlyContinue)) {
            try {
                $RootCAPSSession = New-PSSession -ComputerName $RelevantRootCANetworkInfo.IPAddress -Credential $DomainAdminCredentials -Name $PSSessionName -ErrorAction SilentlyContinue
                if (![bool]$(Get-PSSession -Name $PSSessionName -ErrorAction SilentlyContinue)) {throw}
            }
            catch {
                if ($Counter -le 60) {
                    Write-Warning "New-PSSession '$PSSessionName' failed. Trying again in 15 seconds..."
                    Start-Sleep -Seconds 15
                }
                else {
                    Write-Error "Unable to create new PSSession to '$PSSessionName' using account '$($DomainAdminCredentials.UserName)'! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
            $Counter++
        }

        if (!$RootCAPSSession) {
            Write-Error "Unable to create a PSSession to the Root CA Server at '$($RelevantRootCANetworkInfo.IPAddress)'! Halting!"
            $global:FunctionResult = "1"
            return
        }

        # Transfer any Required Modules that were installed on $env:ComputerName from an external source
        $NeededModules = @("PSPKI")
        [System.Collections.ArrayList]$ModulesToTransfer = @()
        foreach ($ModuleResource in $NeededModules) {
            $ModMapObj = $script:ModuleDependenciesMap.SuccessfulModuleImports | Where-Object {$_.ModuleName -eq $ModuleResource}
            if ($ModMapObj.ModulePSCompatibility -ne "WinPS") {
                $ModuleBase = Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                    if (![bool]$(Get-Module -ListAvailable $args[0])) {
                        Install-Module $args[0]
                    }
                    if (![bool]$(Get-Module -ListAvailable $args[0])) {
                        Write-Error $("Problem installing" + $args[0])
                    }
                    $Module = Get-Module -ListAvailable $args[0]
                    $($Module.ModuleBase -split $args[0])[0] + $args[0]
                } -ArgumentList $ModuleResource
            }
            else {
                $ModuleBase = $($ModMapObj.ManifestFileItem.FullName -split $ModuleResource)[0] + $ModuleResource
            }
            
            $null = $ModulesToTransfer.Add($ModuleBase)
        }
        
        $ProgramFilesPSModulePath = "C:\Program Files\WindowsPowerShell\Modules"
        foreach ($ModuleDirPath in $ModulesToTransfer) {
            $CopyItemSplatParams = @{
                Path            = $ModuleDirPath
                Recurse         = $True
                Destination     = "$ProgramFilesPSModulePath\$($ModuleDirPath | Split-Path -Leaf)"
                ToSession       = $RootCAPSSession
                Force           = $True
            }
            Copy-Item @CopyItemSplatParams
        }

        # Initialize the Remote Environment
        $FunctionsForRemoteUse = $script:FunctionsForSBUse
        $FunctionsForRemoteUse.Add($(${Function:SetupRootCA}.Ast.Extent.Text))
        $Output = Invoke-Command -Session $RootCAPSSession -ScriptBlock {
            $using:FunctionsForRemoteUse | foreach { Invoke-Expression $_ }
            $script:ModuleDependenciesMap = $args[0]
            SetupRootCA @using:SetupRootCASplatParams
        } -ArgumentList $script:ModuleDependenciesMap
    }
    else {
        $Output = SetupRootCA @SetupRootCASplatParams
    }

    $Output

    #endregion >> Do RootCA Install
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUIAFG8nO6lZuhdK8H2NJtJC3o
# fFygggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFEipqHODkCjAno28
# jNkMazvzJeV6MA0GCSqGSIb3DQEBAQUABIIBAGcgKJjPND9QstOqUth+JinmFYk0
# rZL7dJnaNSonNBtcToU86FzC/CQegdnCZSWHsswam/auuplSGBcMgG+iq3zJzyj0
# NoR4AEPsTzuFvqNPhRQzrLfRKq4K86t80ePqFVqpmWMioUZZsdxX/9dy14Io9m57
# jKPalHqfPKp/Hq2Fx85xOTbDfs5SVFyqgJTcqY/zfPwnCkoHoNnnpax0GWcG7Ynw
# 5C0nq1HWzX5p+pjWqD9z2wCSeYkh7JdLu4jR93H34YpXgIa5wzntstMtHT+fOOk+
# fd1Mcb7jGVY/ZcdpIHEAr2Cuki8MKzpfElnso39nRllFafXa45aDaAauUQk=
# SIG # End signature block
