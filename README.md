[![Build status](https://ci.appveyor.com/api/projects/status/github/pldmgg/=master&svg=true)](https://ci.appveyor.com/project/pldmgg/minilab/branch/master)


# MiniLab
<Synopsis>

## Getting Started

```powershell
# One time setup
    # Download the repository
    # Unblock the zip
    # Extract the MiniLab folder to a module path (e.g. $env:USERPROFILE\Documents\WindowsPowerShell\Modules\)
# Or, with PowerShell 5 or later or PowerShellGet:
    Install-Module MiniLab

# Import the module.
    Import-Module MiniLab    # Alternatively, Import-Module <PathToModuleFolder>

# Get commands in the module
    Get-Command -Module MiniLab

# Get help
    Get-Help <MiniLab Function> -Full
    Get-Help about_MiniLab
```

## Examples

### Create a New Domain

On your local machine, make sure you have at least 35GB of Hard Drive Space and 4GB of Memory readily available and
create a new Primary Domain Controller...

```powershell
$VagrantVMPassword = ConvertTo-SecureString 'vagrant' -AsPlainText -Force
$VagrantVMAdminCreds = [pscredential]::new("vagrant",$VagrantVMPassword)
$DomainAdminCreds = [pscredential]::new("alpha\alphaadmin",$(Read-Host 'Enter Passsword' -AsSecureString))
Enter Passsword: ************
$LocalAdminAccountCreds = [pscredential]::new("Administrator",$(Read-Host 'Enter Passsword' -AsSecureString))
Enter Passsword: ****************
$CreateDomainSplatParams = @{
    CreateNewVMs                            = $True
    VMStorageDirectory                      = "H:\VirtualMachines"
    NewDomain                               = "alpha.lab"
    PSRemotingCredentials                   = $VagrantVMAdminCreds
    DomainAdminCredentials                  = $DomainAdminCreds
    LocalAdministratorAccountCredentials    = $LocalAdminAccountCreds
}
$CreateDomainResult = Create-Domain @CreateDomainSplatParams
```

### Create a New Domain with Two-Tier PKI (i.e. Root and Subordinate/Issuing/Intermediate Certificate Authorities)

On your local machine, make sure you have at least 100GB of Hard Drive Space and 12GB of Memory readily available and...

```powershell
$VagrantVMPassword = ConvertTo-SecureString 'vagrant' -AsPlainText -Force
$VagrantVMAdminCreds = [pscredential]::new("vagrant",$VagrantVMPassword)
$DomainAdminCreds = [pscredential]::new("alpha\alphaadmin",$(Read-Host 'Enter Passsword' -AsSecureString))
Enter Passsword: ************
$LocalAdminAccountCreds = [pscredential]::new("Administrator",$(Read-Host 'Enter Passsword' -AsSecureString))
Enter Passsword: **************
$CreateTwoTierPKISplatParams = @{
    CreateNewVMs                            = $True
    VMStorageDirectory                      = "H:\VirtualMachines"
    NewDomain                               = "alpha.lab"
    PSRemotingCredentials                   = $VagrantVMAdminCreds
    DomainAdminCredentials                  = $DomainAdminCreds
    LocalAdministratorAccountCredentials    = $LocalAdminAccountCreds
}
Create-TwoTierPKI @CreateTwoTierPKISplatParams
```

### Add Two-Tier PKI to Your Existing Domain
On your local machine, make sure you have at least 70GB of Hard Drive Space and 8GB of Memory readily available and...

```powershell
$VagrantVMPassword = ConvertTo-SecureString 'vagrant' -AsPlainText -Force
$VagrantVMAdminCreds = [pscredential]::new("vagrant",$VagrantVMPassword)
$DomainAdminCreds = [pscredential]::new("alpha\alphaadmin",$(Read-Host 'Enter Passsword' -AsSecureString))
Enter Passsword: ************
$LocalAdminAccountCreds = [pscredential]::new("Administrator",$(Read-Host 'Enter Passsword' -AsSecureString))
Enter Passsword: **************
$CreateTwoTierPKISplatParams = @{
    CreateNewVMs                            = $True
    VMStorageDirectory                      = "H:\VirtualMachines"
    ExistingDomain                          = "alpha.lab"
    PSRemotingCredentials                   = $VagrantVMAdminCreds
    DomainAdminCredentials                  = $DomainAdminCreds
}
Create-TwoTierPKI @CreateTwoTierPKISplatParams
```

## Notes

* PSGallery: 
