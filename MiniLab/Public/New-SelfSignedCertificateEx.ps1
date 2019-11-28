<#
    .Synopsis
        This cmdlet generates a self-signed certificate.
    .Description
        This cmdlet generates a self-signed certificate with the required data.
    .NOTES
        New-SelfSignedCertificateEx.ps1
        Version 1.0
        
        Creates self-signed certificate. This tool is a base replacement
        for deprecated makecert.exe
        
        Vadims Podans (c) 2013
        http://en-us.sysadmins.lv/

    .Parameter Subject
        Specifies the certificate subject in a X500 distinguished name format.
        Example: CN=Test Cert, OU=Sandbox
    .Parameter NotBefore
        Specifies the date and time when the certificate become valid. By default previous day
        date is used.
    .Parameter NotAfter
        Specifies the date and time when the certificate expires. By default, the certificate is
        valid for 1 year.
    .Parameter SerialNumber
        Specifies the desired serial number in a hex format.
        Example: 01a4ff2
    .Parameter ProviderName
        Specifies the Cryptography Service Provider (CSP) name. You can use either legacy CSP
        and Key Storage Providers (KSP). By default "Microsoft Enhanced Cryptographic Provider v1.0"
        CSP is used.
    .Parameter AlgorithmName
        Specifies the public key algorithm. By default RSA algorithm is used. RSA is the only
        algorithm supported by legacy CSPs. With key storage providers (KSP) you can use CNG
        algorithms, like ECDH. For CNG algorithms you must use full name:
        ECDH_P256
        ECDH_P384
        ECDH_P521
        
        In addition, KeyLength parameter must be specified explicitly when non-RSA algorithm is used.
    .Parameter KeyLength
        Specifies the key length to generate. By default 2048-bit key is generated.
    .Parameter KeySpec
        Specifies the public key operations type. The possible values are: Exchange and Signature.
        Default value is Exchange.
    .Parameter EnhancedKeyUsage
        Specifies the intended uses of the public key contained in a certificate. You can
        specify either, EKU friendly name (for example 'Server Authentication') or
        object identifier (OID) value (for example '1.3.6.1.5.5.7.3.1').
    .Parameter KeyUsage
        Specifies restrictions on the operations that can be performed by the public key contained in the certificate.
        Possible values (and their respective integer values to make bitwise operations) are:
        EncipherOnly
        CrlSign
        KeyCertSign
        KeyAgreement
        DataEncipherment
        KeyEncipherment
        NonRepudiation
        DigitalSignature
        DecipherOnly
        
        you can combine key usages values by using bitwise OR operation. when combining multiple
        flags, they must be enclosed in quotes and separated by a comma character. For example,
        to combine KeyEncipherment and DigitalSignature flags you should type:
        "KeyEncipherment, DigitalSignature".
        
        If the certificate is CA certificate (see IsCA parameter), key usages extension is generated
        automatically with the following key usages: Certificate Signing, Off-line CRL Signing, CRL Signing.
    .Parameter SubjectAlternativeName
        Specifies alternative names for the subject. Unlike Subject field, this extension
        allows to specify more than one name. Also, multiple types of alternative names
        are supported. The cmdlet supports the following SAN types:
        RFC822 Name
        IP address (both, IPv4 and IPv6)
        Guid
        Directory name
        DNS name
    .Parameter IsCA
        Specifies whether the certificate is CA (IsCA = $true) or end entity (IsCA = $false)
        certificate. If this parameter is set to $false, PathLength parameter is ignored.
        Basic Constraints extension is marked as critical.
    .Parameter PathLength
        Specifies the number of additional CA certificates in the chain under this certificate. If
        PathLength parameter is set to zero, then no additional (subordinate) CA certificates are
        permitted under this CA.
    .Parameter CustomExtension
        Specifies the custom extension to include to a self-signed certificate. This parameter
        must not be used to specify the extension that is supported via other parameters. In order
        to use this parameter, the extension must be formed in a collection of initialized
        System.Security.Cryptography.X509Certificates.X509Extension objects.
    .Parameter SignatureAlgorithm
        Specifies signature algorithm used to sign the certificate. By default 'SHA1'
        algorithm is used.
    .Parameter FriendlyName
        Specifies friendly name for the certificate.
    .Parameter StoreLocation
        Specifies the store location to store self-signed certificate. Possible values are:
        'CurrentUser' and 'LocalMachine'. 'CurrentUser' store is intended for user certificates
        and computer (as well as CA) certificates must be stored in 'LocalMachine' store.
    .Parameter StoreName
        Specifies the container name in the certificate store. Possible container names are:
        AddressBook
        AuthRoot
        CertificateAuthority
        Disallowed
        My
        Root
        TrustedPeople
        TrustedPublisher
    .Parameter Path
        Specifies the path to a PFX file to export a self-signed certificate.
    .Parameter Password
        Specifies the password for PFX file.
    .Parameter AllowSMIME
        Enables Secure/Multipurpose Internet Mail Extensions for the certificate.
    .Parameter Exportable
        Marks private key as exportable. Smart card providers usually do not allow
        exportable keys.
 .Example
  # Creates a self-signed certificate intended for code signing and which is valid for 5 years. Certificate
  # is saved in the Personal store of the current user account.
  
        New-SelfsignedCertificateEx -Subject "CN=Test Code Signing" -EKU "Code Signing" -KeySpec "Signature" `
        -KeyUsage "DigitalSignature" -FriendlyName "Test code signing" -NotAfter [datetime]::now.AddYears(5)
        
        
    .Example
  # Creates a self-signed SSL certificate with multiple subject names and saves it to a file. Additionally, the
        # certificate is saved in the Personal store of the Local Machine store. Private key is marked as exportable,
        # so you can export the certificate with a associated private key to a file at any time. The certificate
  # includes SMIME capabilities.
  
  New-SelfsignedCertificateEx -Subject "CN=www.domain.com" -EKU "Server Authentication", "Client authentication" `
        -KeyUsage "KeyEcipherment, DigitalSignature" -SAN "sub.domain.com","www.domain.com","192.168.1.1" `
        -AllowSMIME -Path C:\test\ssl.pfx -Password (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force) -Exportable `
        -StoreLocation "LocalMachine"
        
    .Example
  # Creates a self-signed SSL certificate with multiple subject names and saves it to a file. Additionally, the
        # certificate is saved in the Personal store of the Local Machine store. Private key is marked as exportable,
        # so you can export the certificate with a associated private key to a file at any time. Certificate uses
        # Ellyptic Curve Cryptography (ECC) key algorithm ECDH with 256-bit key. The certificate is signed by using
  # SHA256 algorithm.
  
  New-SelfsignedCertificateEx -Subject "CN=www.domain.com" -EKU "Server Authentication", "Client authentication" `
        -KeyUsage "KeyEcipherment, DigitalSignature" -SAN "sub.domain.com","www.domain.com","192.168.1.1" `
        -StoreLocation "LocalMachine" -ProviderName "Microsoft Software Key Storae Provider" -AlgorithmName ecdh_256 `
  -KeyLength 256 -SignatureAlgorithm sha256
  
    .Example
  # Creates self-signed root CA certificate.

  New-SelfsignedCertificateEx -Subject "CN=Test Root CA, OU=Sandbox" -IsCA $true -ProviderName `
  "Microsoft Software Key Storage Provider" -Exportable
  
#>
function New-SelfSignedCertificateEx {
    [CmdletBinding(DefaultParameterSetName = '__store')]
 param (
  [Parameter(Mandatory = $true, Position = 0)]
  [string]$Subject,
  [Parameter(Position = 1)]
  [datetime]$NotBefore = [DateTime]::Now.AddDays(-1),
  [Parameter(Position = 2)]
  [datetime]$NotAfter = $NotBefore.AddDays(365),
  [string]$SerialNumber,
  [Alias('CSP')]
  [string]$ProviderName = "Microsoft Enhanced Cryptographic Provider v1.0",
  [string]$AlgorithmName = "RSA",
  [int]$KeyLength = 2048,
  [validateSet("Exchange","Signature")]
  [string]$KeySpec = "Exchange",
  [Alias('EKU')]
  [Security.Cryptography.Oid[]]$EnhancedKeyUsage,
  [Alias('KU')]
  [Security.Cryptography.X509Certificates.X509KeyUsageFlags]$KeyUsage,
  [Alias('SAN')]
  [String[]]$SubjectAlternativeName,
  [bool]$IsCA,
  [int]$PathLength = -1,
  [Security.Cryptography.X509Certificates.X509ExtensionCollection]$CustomExtension,
  [ValidateSet('MD5','SHA1','SHA256','SHA384','SHA512')]
  [string]$SignatureAlgorithm = "SHA1",
  [string]$FriendlyName,
  [Parameter(ParameterSetName = '__store')]
  [Security.Cryptography.X509Certificates.StoreLocation]$StoreLocation = "CurrentUser",
  [Parameter(ParameterSetName = '__store')]
  [Security.Cryptography.X509Certificates.StoreName]$StoreName = "My",
  [Parameter(Mandatory = $true, ParameterSetName = '__file')]
  [Alias('OutFile','OutPath','Out')]
  [IO.FileInfo]$Path,
  [Parameter(Mandatory = $true, ParameterSetName = '__file')]
  [Security.SecureString]$Password,
  [switch]$AllowSMIME,
  [switch]$Exportable
 )

 $ErrorActionPreference = "Stop"
 if ([Environment]::OSVersion.Version.Major -lt 6) {
  $NotSupported = New-Object NotSupportedException -ArgumentList "Windows XP and Windows Server 2003 are not supported!"
  throw $NotSupported
 }
 $ExtensionsToAdd = @()

    #region >> Constants
 # contexts
 New-Variable -Name UserContext -Value 0x1 -Option Constant
 New-Variable -Name MachineContext -Value 0x2 -Option Constant
 # encoding
 New-Variable -Name Base64Header -Value 0x0 -Option Constant
 New-Variable -Name Base64 -Value 0x1 -Option Constant
 New-Variable -Name Binary -Value 0x3 -Option Constant
 New-Variable -Name Base64RequestHeader -Value 0x4 -Option Constant
 # SANs
 New-Variable -Name OtherName -Value 0x1 -Option Constant
 New-Variable -Name RFC822Name -Value 0x2 -Option Constant
 New-Variable -Name DNSName -Value 0x3 -Option Constant
 New-Variable -Name DirectoryName -Value 0x5 -Option Constant
 New-Variable -Name URL -Value 0x7 -Option Constant
 New-Variable -Name IPAddress -Value 0x8 -Option Constant
 New-Variable -Name RegisteredID -Value 0x9 -Option Constant
 New-Variable -Name Guid -Value 0xa -Option Constant
 New-Variable -Name UPN -Value 0xb -Option Constant
 # installation options
 New-Variable -Name AllowNone -Value 0x0 -Option Constant
 New-Variable -Name AllowNoOutstandingRequest -Value 0x1 -Option Constant
 New-Variable -Name AllowUntrustedCertificate -Value 0x2 -Option Constant
 New-Variable -Name AllowUntrustedRoot -Value 0x4 -Option Constant
 # PFX export options
 New-Variable -Name PFXExportEEOnly -Value 0x0 -Option Constant
 New-Variable -Name PFXExportChainNoRoot -Value 0x1 -Option Constant
 New-Variable -Name PFXExportChainWithRoot -Value 0x2 -Option Constant
    #endregion >> Constants
 
    #region >> Subject Processing
 # http://msdn.microsoft.com/en-us/library/aa377051(VS.85).aspx
 $SubjectDN = New-Object -ComObject X509Enrollment.CX500DistinguishedName
 $SubjectDN.Encode($Subject, 0x0)
    #endregion >> Subject Processing

    #region >> Extensions

    #region >> Enhanced Key Usages Processing
 if ($EnhancedKeyUsage) {
  $OIDs = New-Object -ComObject X509Enrollment.CObjectIDs
  $EnhancedKeyUsage | %{
   $OID = New-Object -ComObject X509Enrollment.CObjectID
   $OID.InitializeFromValue($_.Value)
   # http://msdn.microsoft.com/en-us/library/aa376785(VS.85).aspx
   $OIDs.Add($OID)
  }
  # http://msdn.microsoft.com/en-us/library/aa378132(VS.85).aspx
  $EKU = New-Object -ComObject X509Enrollment.CX509ExtensionEnhancedKeyUsage
  $EKU.InitializeEncode($OIDs)
  $ExtensionsToAdd += "EKU"
 }
    #endregion >> Enhanced Key Usages Processing

    #region >> Key Usages Processing
 if ($KeyUsage -ne $null) {
  $KU = New-Object -ComObject X509Enrollment.CX509ExtensionKeyUsage
  $KU.InitializeEncode([int]$KeyUsage)
  $KU.Critical = $true
  $ExtensionsToAdd += "KU"
 }
    #endregion >> Key Usages Processing

    #region >> Basic Constraints Processing
 if ($PSBoundParameters.Keys.Contains("IsCA")) {
  # http://msdn.microsoft.com/en-us/library/aa378108(v=vs.85).aspx
  $BasicConstraints = New-Object -ComObject X509Enrollment.CX509ExtensionBasicConstraints
  if (!$IsCA) {$PathLength = -1}
  $BasicConstraints.InitializeEncode($IsCA,$PathLength)
  $BasicConstraints.Critical = $IsCA
  $ExtensionsToAdd += "BasicConstraints"
 }
    #endregion >> Basic Constraints Processing

    #region >> SAN Processing
 if ($SubjectAlternativeName) {
  $SAN = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
  $Names = New-Object -ComObject X509Enrollment.CAlternativeNames
  foreach ($altname in $SubjectAlternativeName) {
   $Name = New-Object -ComObject X509Enrollment.CAlternativeName
   if ($altname.Contains("@")) {
    $Name.InitializeFromString($RFC822Name,$altname)
   } else {
    try {
     $Bytes = [Net.IPAddress]::Parse($altname).GetAddressBytes()
     $Name.InitializeFromRawData($IPAddress,$Base64,[Convert]::ToBase64String($Bytes))
    } catch {
     try {
      $Bytes = [Guid]::Parse($altname).ToByteArray()
      $Name.InitializeFromRawData($Guid,$Base64,[Convert]::ToBase64String($Bytes))
     } catch {
      try {
       $Bytes = ([Security.Cryptography.X509Certificates.X500DistinguishedName]$altname).RawData
       $Name.InitializeFromRawData($DirectoryName,$Base64,[Convert]::ToBase64String($Bytes))
      } catch {$Name.InitializeFromString($DNSName,$altname)}
     }
    }
   }
   $Names.Add($Name)
  }
  $SAN.InitializeEncode($Names)
  $ExtensionsToAdd += "SAN"
 }
    #endregion >> SAN Processing

    #region >> Custom Extensions
 if ($CustomExtension) {
  $count = 0
  foreach ($ext in $CustomExtension) {
   # http://msdn.microsoft.com/en-us/library/aa378077(v=vs.85).aspx
   $Extension = New-Object -ComObject X509Enrollment.CX509Extension
   $EOID = New-Object -ComObject X509Enrollment.CObjectId
   $EOID.InitializeFromValue($ext.Oid.Value)
   $EValue = [Convert]::ToBase64String($ext.RawData)
   $Extension.Initialize($EOID,$Base64,$EValue)
   $Extension.Critical = $ext.Critical
   New-Variable -Name ("ext" + $count) -Value $Extension
   $ExtensionsToAdd += ("ext" + $count)
   $count++
  }
 }
    #endregion >> Custom Extensions

    #endregion >> Extensions

    #region >> Private Key
 # http://msdn.microsoft.com/en-us/library/aa378921(VS.85).aspx
 $PrivateKey = New-Object -ComObject X509Enrollment.CX509PrivateKey
 $PrivateKey.ProviderName = $ProviderName
 $AlgID = New-Object -ComObject X509Enrollment.CObjectId
 $AlgID.InitializeFromValue(([Security.Cryptography.Oid]$AlgorithmName).Value)
 $PrivateKey.Algorithm = $AlgID
 # http://msdn.microsoft.com/en-us/library/aa379409(VS.85).aspx
 $PrivateKey.KeySpec = switch ($KeySpec) {"Exchange" {1}; "Signature" {2}}
 $PrivateKey.Length = $KeyLength
 # key will be stored in current user certificate store
 switch ($PSCmdlet.ParameterSetName) {
  '__store' {
   $PrivateKey.MachineContext = if ($StoreLocation -eq "LocalMachine") {$true} else {$false}
  }
  '__file' {
   $PrivateKey.MachineContext = $false
  }
 }
 $PrivateKey.ExportPolicy = if ($Exportable) {1} else {0}
 $PrivateKey.Create()
    #endregion >> Private Key

 # http://msdn.microsoft.com/en-us/library/aa377124(VS.85).aspx
 $Cert = New-Object -ComObject X509Enrollment.CX509CertificateRequestCertificate
 if ($PrivateKey.MachineContext) {
  $Cert.InitializeFromPrivateKey($MachineContext,$PrivateKey,"")
 } else {
  $Cert.InitializeFromPrivateKey($UserContext,$PrivateKey,"")
 }
 $Cert.Subject = $SubjectDN
 $Cert.Issuer = $Cert.Subject
 $Cert.NotBefore = $NotBefore
 $Cert.NotAfter = $NotAfter
 foreach ($item in $ExtensionsToAdd) {$Cert.X509Extensions.Add((Get-Variable -Name $item -ValueOnly))}
 if (![string]::IsNullOrEmpty($SerialNumber)) {
  if ($SerialNumber -match "[^0-9a-fA-F]") {throw "Invalid serial number specified."}
  if ($SerialNumber.Length % 2) {$SerialNumber = "0" + $SerialNumber}
  $Bytes = $SerialNumber -split "(.{2})" | ?{$_} | %{[Convert]::ToByte($_,16)}
  $ByteString = [Convert]::ToBase64String($Bytes)
  $Cert.SerialNumber.InvokeSet($ByteString,1)
 }
 if ($AllowSMIME) {$Cert.SmimeCapabilities = $true}
 $SigOID = New-Object -ComObject X509Enrollment.CObjectId
 $SigOID.InitializeFromValue(([Security.Cryptography.Oid]$SignatureAlgorithm).Value)
 $Cert.SignatureInformation.HashAlgorithm = $SigOID
 # completing certificate request template building
 $Cert.Encode()
 
 # interface: http://msdn.microsoft.com/en-us/library/aa377809(VS.85).aspx
 $Request = New-Object -ComObject X509Enrollment.CX509enrollment
 $Request.InitializeFromRequest($Cert)
 $Request.CertificateFriendlyName = $FriendlyName
 $endCert = $Request.CreateRequest($Base64)
 $Request.InstallResponse($AllowUntrustedCertificate,$endCert,$Base64,"")
 switch ($PSCmdlet.ParameterSetName) {
  '__file' {
   $PFXString = $Request.CreatePFX(
    [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)),
    $PFXExportEEOnly,
    $Base64
   )
   Set-Content -Path $Path -Value ([Convert]::FromBase64String($PFXString)) -Encoding Byte
  }
 }
}

# SIG # Begin signature block
# MIIMaAYJKoZIhvcNAQcCoIIMWTCCDFUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQURhsJaYCETS7guyQjo9pyf0wP
# oOCgggndMIIEJjCCAw6gAwIBAgITawAAADqEP46TDmc/hQAAAAAAOjANBgkqhkiG
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
# BDEWBBTRHvfvF5R8cieJ9x0fZXff1OBMOjANBgkqhkiG9w0BAQEFAASCAQBwW32f
# zouKyC6lhKSv8DzQZB3ovFMoF88x1Ydk/n+s+8OnCuQ3lKwyrRYNZH+erjeHd+6B
# Gk8oGrMzAJ6JmW10q/UhbIB7SYe+EwCLFbfq/sKhuVj0bEDK34FRTtc7PMyhlhyb
# BPL7hcLV2U/9Aaa2B3efJeSzFYkcxDf+jFEClvp4IwCOsrC9kRrNgDmC6GzZrVGe
# BglmuN9jKTEb3+5HoIGBSgP8yRKgu8Lwzew13Y7BzbscDgZLxZY5zqpUEz7V2fbu
# JMguU77MSLnUdDkl9TEn2//inE5pUXiS7OD6/TKZit8I9BtV2iVPyrqZFw4cW2eF
# GxeuzMkfugQK+VTc
# SIG # End signature block
