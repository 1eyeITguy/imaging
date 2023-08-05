<#
.SYNOPSIS
    Download the latest OneDriveSetup.exe on the production ring, replace built-in version, and initiate per-machine OneDrive setup.

.DESCRIPTION
    This script will download the latest OneDriveSetup.exe from the production ring, replace the built-in executable, initiate the 
    per-machine install which will result in the latest version of OneDrive always being installed, and synchronization can begin right away.

.PARAMETER DownloadPath
    Specify a path for where OneDriveSetup.exe will be temporarily downloaded to.

.EXAMPLE
    .\Invoke-OneDriveSetupUpdate.ps1

.NOTES
    FileName:    Invoke-OneDriveSetupUpdate.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2021-01-18
    Updated:     2021-01-18

    Version history:
    1.0.0 - (2021-01-18) Script created
#>

param (
    [parameter(Mandatory = $false, HelpMessage = "Specify a path for where OneDriveSetup.exe will be temporarily downloaded to.")]
    [ValidateNotNullOrEmpty()]
    [string]$DownloadPath = (Join-Path -Path $env:windir -ChildPath "Temp")
)

# Install required modules for script execution
$Modules = @("NTFSSecurity")
foreach ($Module in $Modules) {
    try {
        $CurrentModule = Get-InstalledModule -Name $Module -ErrorAction Stop -Verbose:$false
        if ($CurrentModule -ne $null) {
            $LatestModuleVersion = (Find-Module -Name $Module -ErrorAction Stop -Verbose:$false).Version
            if ($LatestModuleVersion -gt $CurrentModule.Version) {
                $UpdateModuleInvocation = Update-Module -Name $Module -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
            }
        }
    } catch [System.Exception] {
        try {
            # Install NuGet package provider
            $PackageProvider = Install-PackageProvider -Name NuGet -Force -Verbose:$false
        
            # Install current missing module
            Install-Module -Name $Module -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
        } catch [System.Exception] {
            Write-Warning -Message "An error occurred while attempting to install $($Module) module. Error message: $($_.Exception.Message)"
        }
    }
}

try {
    # Attempt to remove existing OneDriveSetup.exe in the temporary location
    $OneDriveSetupFile = Join-Path -Path $env:windir -ChildPath "SysWOW64\OneDriveSetup.exe"
    if (Test-Path -Path $OneDriveSetupFile) {
        Write-Host "Found existing 'OneDriveSetup.exe' in the temporary download path, removing it"
        Remove-Item -Path $OneDriveSetupFile -Force -ErrorAction Stop
    }

    # Download the OneDriveSetup.exe file to the temporary location
    $OneDriveSetupURL = "https://go.microsoft.com/fwlink/p/?LinkId=248256"
    Write-Host "Attempting to download the latest OneDriveSetup.exe file from the Microsoft download page to the temporary download path: $DownloadPath"
    Write-Host "Using URL for download: $OneDriveSetupURL"
    $OneDriveSetupFilePath = Join-Path -Path $DownloadPath -ChildPath "OneDriveSetup.exe"
    Invoke-WebRequest -Uri $OneDriveSetupURL -OutFile $OneDriveSetupFilePath -ErrorAction Stop

    # Validate OneDriveSetup.exe file has been successfully downloaded to the temporary location
    if (Test-Path -Path $OneDriveSetupFilePath) {
        Write-Host "Detected 'OneDriveSetup.exe' in the temporary download path"

        try {
            # Use icacls to grant FullControl access to SYSTEM on the OneDriveSetup executable
            Write-Host "Granting FullControl access to SYSTEM on file: $OneDriveSetupFile"
            icacls $OneDriveSetupFile /grant "NT AUTHORITY\SYSTEM:(F)" /T /C /Q /L

            try {
                # Replace the built-in OneDriveSetup executable with the downloaded version
                Write-Host "Replacing built-in 'OneDriveSetup.exe' with the downloaded version"
                Copy-Item -Path $OneDriveSetupFilePath -Destination $OneDriveSetupFile -Force -ErrorAction Stop

                try {
                    # Initiate updated built-in OneDriveSetup.exe and install as per-machine
                    Write-Host "Initiating per-machine OneDrive setup installation, this process could take some time"
                    Start-Process -FilePath $OneDriveSetupFile -ArgumentList "/allusers /update" -Wait -ErrorAction Stop
                    Write-Host "Successfully installed OneDrive as per-machine"
                } catch [System.Exception] {
                    Write-Host "Failed to install OneDrive as per-machine. Error message: $($_.Exception.Message)"
                }
            } catch [System.Exception] {
                Write-Host "Failed to copy '$OneDriveSetupFilePath' to the default location. Error message: $($_.Exception.Message)"
            }
        } catch [System.Exception] {
            Write-Host "Failed to grant FullControl access to SYSTEM on file: $OneDriveSetupFile. Error message: $($_.Exception.Message)"
        }
    } else {
        Write-Host "Unable to locate the download path '$DownloadPath', ensure the directory exists."
    }
} catch [System.Exception] {
    Write-Host "Failed to download OneDriveSetup.exe file. Error message: $($_.Exception.Message)"
}
