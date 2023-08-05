# Define the URL for the OneDrive installer
$OneDriveURL = "https://go.microsoft.com/fwlink/p/?LinkID=2182910"

# Define the path where the installer will be downloaded
$DownloadPath = "C:\temp\onedrive\OneDriveSetup.exe"

# Create the target directory if it doesn't exist
$targetDirectory = Split-Path $DownloadPath -Parent
New-Item -ItemType Directory -Force -Path $targetDirectory

# Download the OneDrive installer
Invoke-WebRequest -Uri $OneDriveURL -OutFile $DownloadPath

# Run the installer with desired parameters (e.g., /allusers /update)
$InstallerArgs = "/allusers /update"
Write-Host "Installing OneDrive for all users..."
Start-Process -FilePath $DownloadPath -ArgumentList $InstallerArgs -Wait
Write-host "Successful"
