<#
.SYNOPSIS
  Script to update and install OneDrive 64bit in Machine context

.DESCRIPTION
    Script to update and install OneDrive 64bit in Machine context

.EXAMPLE
    .\InstallOneDrivex64.ps1

.NOTES
    Version:        1.0
    Creation Date:  08.05.2023
    Version history:
        1.0.0 - (2022-23-10) Script released 
#>

# Define global variables
$LogFileName = "OneDriveSetup.log"
$SetupFolder = "$($env:SystemRoot)\Temp\OneDriveSetup"
$SetupFileName = "OneDriveSetup.exe"
$OneDriveVersion = ""

#region Functions

function Write-LogEntry {
    param (
        [parameter(Mandatory = $true, HelpMessage = "Value added to the log file.")]
        [ValidateNotNullOrEmpty()]
        [string]$Value,

        [parameter(Mandatory = $true, HelpMessage = "Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("1", "2", "3")]
        [string]$Severity,

        [parameter(Mandatory = $false, HelpMessage = "Name of the log file that the entry will be written to.")]
        [ValidateNotNullOrEmpty()]
        [string]$FileName = $LogFileName
    )

    # Determine log file location
    $LogFilePath = Join-Path -Path $env:SystemRoot -ChildPath "Temp\$FileName"

    # Construct time stamp for log entry
    $Time = -join @((Get-Date -Format "HH:mm:ss.fff"), " ", (Get-WmiObject -Class Win32_TimeZone | Select-Object -ExpandProperty Bias))

    # Construct date for log entry
    $Date = (Get-Date -Format "MM-dd-yyyy")

    # Construct context for log entry
    $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)

    # Construct final log entry
    $LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""$($LogFileName)"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"

    # Add value to log file
    try {
        Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
        if ($Severity -eq "1") {
            Write-Verbose -Message $Value
        } elseif ($Severity -eq "3") {
            Write-Warning -Message $Value
        }
    } catch [System.Exception] {
        Write-Warning -Message "Unable to append log entry to $LogFileName.log file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
    }
}

function Start-DownloadFile {
    param (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$URL,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

    Begin {
        # Construct WebClient object
        $WebClient = New-Object -TypeName System.Net.WebClient
    }
    Process {
        # Create path if it doesn't exist
        if (-not (Test-Path -Path $Path)) {
            New-Item -Path $Path -ItemType Directory -Force | Out-Null
        }

        # Start download of file
        $WebClient.DownloadFile($URL, (Join-Path -Path $Path -ChildPath $Name))
    }
    End {
        # Dispose of the WebClient object
        $WebClient.Dispose()
    }
}

function Invoke-FileCertVerification {
    param (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath
    )

    # Get a X590Certificate2 certificate object for a file
    $Cert = (Get-AuthenticodeSignature -FilePath $FilePath).SignerCertificate
    $CertStatus = (Get-AuthenticodeSignature -FilePath $FilePath).Status

    if ($Cert) {
        # Verify signed by Microsoft and Validity
        if ($cert.Subject -match "O=Microsoft Corporation" -and $CertStatus -eq "Valid") {
            # Verify Chain and check if Root is Microsoft
            $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
            $chain.Build($cert) | Out-Null
            $RootCert = $chain.ChainElements | ForEach-Object { $_.Certificate } | Where-Object { $PSItem.Subject -match "CN=Microsoft Root" }
            if (-not [string]::IsNullOrEmpty($RootCert)) {
                # Verify root certificate exists in local Root Store
                $TrustedRoot = Get-ChildItem -Path "Cert:\LocalMachine\Root" -Recurse | Where-Object { $PSItem.Thumbprint -eq $RootCert.Thumbprint }
                if (-not [string]::IsNullOrEmpty($TrustedRoot)) {
                    Write-LogEntry -Value "Verified setup file signed by: $($Cert.Issuer)" -Severity 1
                    Return $True
                } else {
                    Write-LogEntry -Value "No trust found to root cert - aborting" -Severity 2
                    Return $False
                }
            } else {
                Write-LogEntry -Value "Certificate chain not verified to Microsoft - aborting" -Severity 2
                Return $False
            }
        } else {
            Write-LogEntry -Value "Certificate not valid or not signed by Microsoft - aborting" -Severity 2
            Return $False
        }
    } else {
        Write-LogEntry -Value "Setup file not signed - aborting" -Severity 2
        Return $False
    }
}

function Install-OneDrive {
    param (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SetupFilePath
    )

    Try {
        # Running OneDrive installer
        Write-LogEntry -Value "Starting install OneDrive as per-machine" -Severity 1
        $OneDriveInstall = Start-Process $SetupFilePath -ArgumentList "/allusers /update" -Wait -PassThru -ErrorAction Stop
    } catch [System.Exception] {
        Write-LogEntry -Value "Error installing OneDrive as per-machine. ErrorMessage: $($_.Exception.Message)" -Severity 3
    }
}

function Clean-Up {
    # Cleanup temporary files and folder
    if (Test-Path $SetupFolder) {
        Remove-Item -Path $SetupFolder -Recurse -Force -ErrorAction SilentlyContinue
    }
}

#endregion Functions

#region Initializations

#Initiate Install
Write-LogEntry -Value "Initiating OneDrive setup process" -Severity 1

# Cleanup any previous setup files
Clean-Up

try {
    # Download latest OneDrive setup.exe
    $OneDriveSetupURL = "https://go.microsoft.com/fwlink/p/?LinkID=2182910"
    Write-LogEntry -Value "Attempting to download the latest OneDrive setup executable" -Severity 1
    Start-DownloadFile -URL $OneDriveSetupURL -Path $SetupFolder -Name $SetupFileName

    # Verify the downloaded setup file's certificate
    $SetupFilePath = Join-Path -Path $SetupFolder -ChildPath $SetupFileName
    if (-Not (Test-Path $SetupFilePath)) {
        Throw "Error: Setup file not found"
    }
    Write-LogEntry -Value "Setup file ready at $SetupFilePath" -Severity 1

    # Get the version of the current OneDrive setup file
    $OneDriveVersion = (Get-Item $SetupFilePath).VersionInfo.FileVersion
    Write-LogEntry -Value "OneDrive setup is running version $OneDriveVersion" -Severity 1

    if (Invoke-FileCertVerification -FilePath $SetupFilePath) {
        # Starting OneDrive Setup
        Install-OneDrive -SetupFilePath $SetupFilePath
    } else {
        Throw "Error: Unable to verify the setup file's signature"
    }
} catch [System.Exception] {
    Write-LogEntry -Value "Error during the setup process. ErrorMessage: $($_.Exception.Message)" -Severity 3
}

# Cleanup temporary files
Clean-Up

Write-LogEntry -Value "OneDrive setup completed" -Severity 1
