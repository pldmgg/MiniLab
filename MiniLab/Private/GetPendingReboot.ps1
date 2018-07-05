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
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUojksfguOY0VO6zP8VQTMeGfP
# 8CKgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFDzsV+6fXcmazF1o
# mg8qrqtI1nh6MA0GCSqGSIb3DQEBAQUABIIBAB/93saGdIh1lmHpH4jUnl43hI++
# BIEXDKOBg2h61QYzRIwggTEdLiW2YDjXIYzMX0eFGZEm71H2whSnQrMxxvH1q04y
# fKuEIlYFTtYLjsYsHyVpu5HBNtjuZL4+dgBeVEvNt5tGNfoWTYBz7q7/4kgXAWUO
# 0gHNK+bzReqzBret77lX9eJtA0Hpvx3pJQjqXDzySi6M8cikQpU2wofdvJocTcZO
# aciYBlLauO90xzZjqJXmr5sYw88ji2GlCcQ5aTFcXaEsQ8Yf84uoGQ11BV1CbTuY
# IPT8/Fhz5CmUeQm/m4bb+hRMwKdgtb8/aDoNBxNhI7uo9QAMA19Nejz3tOw=
# SIG # End signature block
