<#
 .SYNOPSIS
  Gets the pending reboot status on a local or remote computer.

 .DESCRIPTION
  This function will query the registry on a local or remote computer and determine if the
  system is pending a reboot, from Microsoft updates, Configuration Manager Client SDK, Pending Computer 
  Rename, Domain Join or Pending File Rename Operations. For Windows 2008+ the function will query the 
  CBS registry key as another factor in determining pending reboot state.  "PendingFileRenameOperations" 
  and "Auto Update\RebootRequired" are observed as being consistant across Windows Server 2003 & 2008.
  
  CBServicing = Component Based Servicing (Windows 2008+)
  WindowsUpdate = Windows Update / Auto Update (Windows 2003+)
  CCMClientSDK = SCCM 2012 Clients only (DetermineIfRebootPending method) otherwise $null value
  PendComputerRename = Detects either a computer rename or domain join operation (Windows 2003+)
  PendFileRename = PendingFileRenameOperations (Windows 2003+)
  PendFileRenVal = PendingFilerenameOperations registry value; used to filter if need be, some Anti-
      Virus leverage this key for def/dat removal, giving a false positive PendingReboot

 .PARAMETER ComputerName
  A single Computer or an array of computer names.  The default is localhost ($env:COMPUTERNAME).

 .PARAMETER ErrorLog
  A single path to send error data to a log file.

 .EXAMPLE
  PS C:\> Get-PendingReboot -ComputerName (Get-Content C:\ServerList.txt) | Format-Table -AutoSize
  
  Computer CBServicing WindowsUpdate CCMClientSDK PendFileRename PendFileRenVal RebootPending
  -------- ----------- ------------- ------------ -------------- -------------- -------------
  DC01           False         False                       False                        False
  DC02           False         False                       False                        False
  FS01           False         False                       False                        False

  This example will capture the contents of C:\ServerList.txt and query the pending reboot
  information from the systems contained in the file and display the output in a table. The
  null values are by design, since these systems do not have the SCCM 2012 client installed,
  nor was the PendingFileRenameOperations value populated.

 .EXAMPLE
  PS C:\> Get-PendingReboot
  
  Computer           : WKS01
  CBServicing        : False
  WindowsUpdate      : True
  CCMClient          : False
  PendComputerRename : False
  PendFileRename     : False
  PendFileRenVal     : 
  RebootPending      : True
  
  This example will query the local machine for pending reboot information.
  
 .EXAMPLE
  PS C:\> $Servers = Get-Content C:\Servers.txt
  PS C:\> Get-PendingReboot -Computer $Servers | Export-Csv C:\PendingRebootReport.csv -NoTypeInformation
  
  This example will create a report that contains pending reboot information.

 .LINK
  Component-Based Servicing:
  http://technet.microsoft.com/en-us/library/cc756291(v=WS.10).aspx
  
  PendingFileRename/Auto Update:
  http://support.microsoft.com/kb/2723674
  http://technet.microsoft.com/en-us/library/cc960241.aspx
  http://blogs.msdn.com/b/hansr/archive/2006/02/17/patchreboot.aspx

  SCCM 2012/CCM_ClientSDK:
  http://msdn.microsoft.com/en-us/library/jj902723.aspx

 .NOTES
  Author:  Brian Wilhite
  Email:   bcwilhite (at) live.com
  Date:    29AUG2012
  PSVer:   2.0/3.0/4.0/5.0
  Updated: 27JUL2015
  UpdNote: Added Domain Join detection to PendComputerRename, does not detect Workgroup Join/Change
    Fixed Bug where a computer rename was not detected in 2008 R2 and above if a domain join occurred at the same time.
    Fixed Bug where the CBServicing wasn't detected on Windows 10 and/or Windows Server Technical Preview (2016)
    Added CCMClient property - Used with SCCM 2012 Clients only
    Added ValueFromPipelineByPropertyName=$true to the ComputerName Parameter
    Removed $Data variable from the PSObject - it is not needed
    Bug with the way CCMClientSDK returned null value if it was false
    Removed unneeded variables
    Added PendFileRenVal - Contents of the PendingFileRenameOperations Reg Entry
    Removed .Net Registry connection, replaced with WMI StdRegProv
    Added ComputerPendingRename
#>
Function GetPendingReboot {
 [CmdletBinding()]
 param(
  [Parameter(Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
  [Alias("CN","Computer")]
  [String[]]$ComputerName="$env:COMPUTERNAME",
  [String]$ErrorLog
 )

 Begin {}## End Begin Script Block
 
 Process {
  Foreach ($Computer in $ComputerName) {
   Try {
    ## Setting pending values to false to cut down on the number of else statements
    $CompPendRen,$PendFileRename,$Pending,$SCCM = $false,$false,$false,$false
        
    ## Setting CBSRebootPend to null since not all versions of Windows has this value
    $CBSRebootPend = $null
        
    ## Querying WMI for build version
    $WMI_OS = Get-WmiObject -Class Win32_OperatingSystem -Property BuildNumber, CSName -ComputerName $Computer -ErrorAction Stop

    ## Making registry connection to the local/remote computer
    $HKLM = [UInt32] "0x80000002"
    $WMI_Reg = [WMIClass] "\\$Computer\root\default:StdRegProv"
        
    ## If Vista/2008 & Above query the CBS Reg Key
    If ([Int32]$WMI_OS.BuildNumber -ge 6001) {
     $RegSubKeysCBS = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")
     $CBSRebootPend = $RegSubKeysCBS.sNames -contains "RebootPending"  
    }
         
    ## Query WUAU from the registry
    $RegWUAURebootReq = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")
    $WUAURebootReq = $RegWUAURebootReq.sNames -contains "RebootRequired"
        
    ## Query PendingFileRenameOperations from the registry
    $RegSubKeySM = $WMI_Reg.GetMultiStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\Session Manager\","PendingFileRenameOperations")
    $RegValuePFRO = $RegSubKeySM.sValue

    ## Query JoinDomain key from the registry - These keys are present if pending a reboot from a domain join operation
    $Netlogon = $WMI_Reg.EnumKey($HKLM,"SYSTEM\CurrentControlSet\Services\Netlogon").sNames
    $PendDomJoin = ($Netlogon -contains 'JoinDomain') -or ($Netlogon -contains 'AvoidSpnSet')

    ## Query ComputerName and ActiveComputerName from the registry
    $ActCompNm = $WMI_Reg.GetStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\","ComputerName")            
    $CompNm = $WMI_Reg.GetStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName\","ComputerName")

    If (($ActCompNm -ne $CompNm) -or $PendDomJoin) {
     $CompPendRen = $true
    }
        
    ## If PendingFileRenameOperations has a value set $RegValuePFRO variable to $true
    If ($RegValuePFRO) {
     $PendFileRename = $true
    }

    ## Determine SCCM 2012 Client Reboot Pending Status
    ## To avoid nested 'if' statements and unneeded WMI calls to determine if the CCM_ClientUtilities class exist, setting EA = 0
    $CCMClientSDK = $null
    $CCMSplat = @{
     NameSpace='ROOT\ccm\ClientSDK'
     Class='CCM_ClientUtilities'
     Name='DetermineIfRebootPending'
     ComputerName=$Computer
     ErrorAction='Stop'
    }
    ## Try CCMClientSDK
    Try {
     $CCMClientSDK = Invoke-WmiMethod @CCMSplat
    } Catch [System.UnauthorizedAccessException] {
     $CcmStatus = Get-Service -Name CcmExec -ComputerName $Computer -ErrorAction SilentlyContinue
     If ($CcmStatus.Status -ne 'Running') {
      Write-Warning "$Computer`: Error - CcmExec service is not running."
      $CCMClientSDK = $null
     }
    } Catch {
     $CCMClientSDK = $null
    }

    If ($CCMClientSDK) {
     If ($CCMClientSDK.ReturnValue -ne 0) {
      Write-Warning "Error: DetermineIfRebootPending returned error code $($CCMClientSDK.ReturnValue)"          
     }
     If ($CCMClientSDK.IsHardRebootPending -or $CCMClientSDK.RebootPending) {
      $SCCM = $true
     }
    }
     
    Else {
     $SCCM = $null
    }

    ## Creating Custom PSObject and Select-Object Splat
    $SelectSplat = @{
     Property=(
      'Computer',
      'CBServicing',
      'WindowsUpdate',
      'CCMClientSDK',
      'PendComputerRename',
      'PendFileRename',
      'PendFileRenVal',
      'RebootPending'
                    )}
                    
    $PendFileRenameVal = $RegValuePFRO | Where-Object {$_ -match "[\w]" -and $_ -notmatch [regex]::Escape("C:\Windows\system32\spool\V4Dirs") -and $_ -notmatch "ChocolateyPrototype"}
    New-Object -TypeName PSObject -Property @{
     Computer=$WMI_OS.CSName
     CBServicing=$CBSRebootPend
     WindowsUpdate=$WUAURebootReq
     CCMClientSDK=$SCCM
     PendComputerRename=$CompPendRen
     PendFileRename=$PendFileRename
     PendFileRenVal=$PendFileRenameVal
     RebootPending=($CompPendRen -or $CBSRebootPend -or $WUAURebootReq -or $SCCM -or $($PendFileRename -and $PendFileRenameVal -ne $null))
    } | Select-Object @SelectSplat

   } Catch {
    Write-Warning "$Computer`: $_"
    ## If $ErrorLog, log the file to a user specified location/path
    If ($ErrorLog) {
     Out-File -InputObject "$Computer`,$_" -FilePath $ErrorLog -Append
    }    
   }   
  }## End Foreach ($Computer in $ComputerName)
 }## End Process

 End {}## End End

}## End Function GetPendingReboot

# SIG # Begin signature block
# MIIMaAYJKoZIhvcNAQcCoIIMWTCCDFUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUPvNbkLdPZx818KHylKyI5KD9
# fYygggndMIIEJjCCAw6gAwIBAgITawAAADqEP46TDmc/hQAAAAAAOjANBgkqhkiG
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
# BDEWBBQFU0CADgm3UApwG7Wuus9GG5k6/jANBgkqhkiG9w0BAQEFAASCAQBHC/0c
# 0IhXKLLZQEJLAhNgj+o3ehgpc7hDEUPqb5mjAz7MPquNI58na/YPRXhLeagE6Wh9
# kq3zqmwuVvP6iF/KEoNeYagbDZDDPNSYIVTDYjLe0Q2MKyp8EVi8x81x+sa0F447
# N49kNQA/FQquET9m5qJMEkm0PdpHamHCkTHmR2NBBE8CcuA9i+JMJzVtkRT0lQwB
# TKWnhcY+Nw66yfc3pCHl7R1BTIAQVhbtuur+/emS5Sog2CCG3FqI0drigBkiI1JA
# Z2FjfvPc23jTmPekLo9Vl+di+Dmk3DUMVyReeBzvrGtXZADBD1iVUdhZuLYPjziI
# HIl9nG96lpoq7bco
# SIG # End signature block
