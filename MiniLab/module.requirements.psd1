@{
    # Some defaults for all dependencies
    PSDependOptions = @{
        Target = 'C:\Users\zeroadmin\Documents\PowerShell\Modules'
        AddToPath = $True
    }

    # Grab some modules without depending on PowerShellGet
    'ProgramManagement' = @{
        DependencyType  = 'PSGalleryModule'
        Version         = 'Latest'
    }
    'NTFSSecurity' = @{
        DependencyType  = 'PSGalleryModule'
        Version         = 'Latest'
    }
}
