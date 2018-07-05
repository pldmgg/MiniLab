function ConfirmAzureVM {
    $source = @"
using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Net.NetworkInformation;

namespace Microsoft.WindowsAzure.Internal
{
    /// <summary>
    /// A simple DHCP client.
    /// </summary>
    public class DhcpClient : IDisposable
    {
        public DhcpClient()
        {
            uint version;
            int err = NativeMethods.DhcpCApiInitialize(out version);
            if (err != 0)
                throw new Win32Exception(err);
        }

        public void Dispose()
        {
            NativeMethods.DhcpCApiCleanup();
        }

        /// <summary>
        /// Gets the available interfaces that are enabled for DHCP.
        /// </summary>
        /// <remarks>
        /// The operational status of the interface is not assessed.
        /// </remarks>
        /// <returns></returns>
        public static IEnumerable<NetworkInterface> GetDhcpInterfaces()
        {
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.NetworkInterfaceType != NetworkInterfaceType.Ethernet) continue;
                if (!nic.Supports(NetworkInterfaceComponent.IPv4)) continue;
                IPInterfaceProperties props = nic.GetIPProperties();
                if (props == null) continue;
                IPv4InterfaceProperties v4props = props.GetIPv4Properties();
                if (v4props == null) continue;
                if (!v4props.IsDhcpEnabled) continue;

                yield return nic;
            }
        }

        /// <summary>
        /// Requests DHCP parameter data.
        /// </summary>
        /// <remarks>
        /// Windows serves the data from a cache when possible.  
        /// With persistent requests, the option is obtained during boot-time DHCP negotiation.
        /// </remarks>
        /// <param name="optionId">the option to obtain.</param>
        /// <param name="isVendorSpecific">indicates whether the option is vendor-specific.</param>
        /// <param name="persistent">indicates whether the request should be persistent.</param>
        /// <returns></returns>
        public byte[] DhcpRequestParams(string adapterName, uint optionId)
        {
            uint bufferSize = 1024;
        Retry:
            IntPtr buffer = Marshal.AllocHGlobal((int)bufferSize);
            try
            {
                NativeMethods.DHCPCAPI_PARAMS_ARRAY sendParams = new NativeMethods.DHCPCAPI_PARAMS_ARRAY();
                sendParams.nParams = 0;
                sendParams.Params = IntPtr.Zero;

                NativeMethods.DHCPCAPI_PARAMS recv = new NativeMethods.DHCPCAPI_PARAMS();
                recv.Flags = 0x0;
                recv.OptionId = optionId;
                recv.IsVendor = false;
                recv.Data = IntPtr.Zero;
                recv.nBytesData = 0;

                IntPtr recdParamsPtr = Marshal.AllocHGlobal(Marshal.SizeOf(recv));
                try
                {
                    Marshal.StructureToPtr(recv, recdParamsPtr, false);

                    NativeMethods.DHCPCAPI_PARAMS_ARRAY recdParams = new NativeMethods.DHCPCAPI_PARAMS_ARRAY();
                    recdParams.nParams = 1;
                    recdParams.Params = recdParamsPtr;

                    NativeMethods.DhcpRequestFlags flags = NativeMethods.DhcpRequestFlags.DHCPCAPI_REQUEST_SYNCHRONOUS;

                    int err = NativeMethods.DhcpRequestParams(
                        flags,
                        IntPtr.Zero,
                        adapterName,
                        IntPtr.Zero,
                        sendParams,
                        recdParams,
                        buffer,
                        ref bufferSize,
                        null);

                    if (err == NativeMethods.ERROR_MORE_DATA)
                    {
                        bufferSize *= 2;
                        goto Retry;
                    }

                    if (err != 0)
                        throw new Win32Exception(err);

                    recv = (NativeMethods.DHCPCAPI_PARAMS) 
                        Marshal.PtrToStructure(recdParamsPtr, typeof(NativeMethods.DHCPCAPI_PARAMS));

                    if (recv.Data == IntPtr.Zero)
                        return null;

                    byte[] data = new byte[recv.nBytesData];
                    Marshal.Copy(recv.Data, data, 0, (int)recv.nBytesData);
                    return data;
                }
                finally
                {
                    Marshal.FreeHGlobal(recdParamsPtr);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        ///// <summary>
        ///// Unregisters a persistent request.
        ///// </summary>
        //public void DhcpUndoRequestParams()
        //{
        //    int err = NativeMethods.DhcpUndoRequestParams(0, IntPtr.Zero, null, this.ApplicationID);
        //    if (err != 0)
        //        throw new Win32Exception(err);
        //}

        #region Native Methods
    }

    internal static partial class NativeMethods
    {
        public const uint ERROR_MORE_DATA = 124;

        [DllImport("dhcpcsvc.dll", EntryPoint = "DhcpRequestParams", CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern int DhcpRequestParams(
            DhcpRequestFlags Flags,
            IntPtr Reserved,
            string AdapterName,
            IntPtr ClassId,
            DHCPCAPI_PARAMS_ARRAY SendParams,
            DHCPCAPI_PARAMS_ARRAY RecdParams,
            IntPtr Buffer,
            ref UInt32 pSize,
            string RequestIdStr
            );

        [DllImport("dhcpcsvc.dll", EntryPoint = "DhcpUndoRequestParams", CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern int DhcpUndoRequestParams(
            uint Flags,
            IntPtr Reserved,
            string AdapterName,
            string RequestIdStr);

        [DllImport("dhcpcsvc.dll", EntryPoint = "DhcpCApiInitialize", CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern int DhcpCApiInitialize(out uint Version);

        [DllImport("dhcpcsvc.dll", EntryPoint = "DhcpCApiCleanup", CharSet = CharSet.Unicode, SetLastError = false)]
        public static extern int DhcpCApiCleanup();

        [Flags]
        public enum DhcpRequestFlags : uint
        {
            DHCPCAPI_REQUEST_PERSISTENT = 0x01,
            DHCPCAPI_REQUEST_SYNCHRONOUS = 0x02,
            DHCPCAPI_REQUEST_ASYNCHRONOUS = 0x04,
            DHCPCAPI_REQUEST_CANCEL = 0x08,
            DHCPCAPI_REQUEST_MASK = 0x0F
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct DHCPCAPI_PARAMS_ARRAY
        {
            public UInt32 nParams;
            public IntPtr Params;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct DHCPCAPI_PARAMS
        {
            public UInt32 Flags;
            public UInt32 OptionId;
            [MarshalAs(UnmanagedType.Bool)] 
            public bool IsVendor;
            public IntPtr Data;
            public UInt32 nBytesData;
        }
        #endregion
    }
}
"@

    $CurrentlyLoadedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies()
    $detected = $False

    if (![bool]$($CurrentlyLoadedAssemblies -match "Microsoft.WindowsAzure.Internal")) {
        Add-Type -TypeDefinition $source
    }
    if (![bool]$($CurrentlyLoadedAssemblies -match "System.Serviceprocess")) {
        [void][System.Reflection.Assembly]::LoadWithPartialName('System.Serviceprocess')
    }

	$vmbus = [System.ServiceProcess.ServiceController]::GetDevices() | where {$_.Name -eq 'vmbus'}

	If($vmbus.Status -eq 'Running')
	{
		$client = New-Object Microsoft.WindowsAzure.Internal.DhcpClient
		try {
			[Microsoft.WindowsAzure.Internal.DhcpClient]::GetDhcpInterfaces() | % { 
				$val = $client.DhcpRequestParams($_.Id, 245)
				if($val -And $val.Length -eq 4) {
					$detected = $True
                }
			}
		} finally {
			$client.Dispose()
		}	
    }
    
	$detected
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUP0fVnCxnZ5VmGM147EcHemQE
# 1Iqgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFAMj7d+O3P00L7R4
# gD2fCjzFx06VMA0GCSqGSIb3DQEBAQUABIIBAL513qsRVcob6r3kNXbMgXT5OJru
# 4kEOfAR4gzYxhmrM2SgLYGvdJfOW1iYi9eZKggNSJ1X3PTqYmrm4W8FXmUdPQ0oG
# qr9ylWBkSlMb8954ZRZoWKvJz/O12lmLk08NfFNuCPleyN12p9wj/d7e+WWpHYGk
# gcpI4Cafe3z3Wm6CLSwgktL+/dKPg3m4PUBVbB5W8eKi3FeBzcPCLvrcPo88KWks
# rTAk7xGyi8ixIUGgR8wdP69x4a9EDSqQzzRixMQrUwWeCjPe6hW3RRTGgGwa3o6X
# QVZeUz3igloh9ED6XFfHyWh6NH1kFax+Asb9AVdSG+0i8+3BBWoM00TuxY4=
# SIG # End signature block
