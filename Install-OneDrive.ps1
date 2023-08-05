<#
.SYNOPSIS
    Download the latest OneDriveSetup.exe on the production ring, replace built-in version and initiate per-machine OneDrive setup.

.DESCRIPTION
    This script will download the latest OneDriveSetup.exe from the production ring, replace the built-in executable, initiate the 
    per-machine install which will result in the latest version of OneDrive will always be installed, and synchronization can begin right away.

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
[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [parameter(Mandatory = $false, HelpMessage = "Specify a path for where OneDriveSetup.exe will be temporarily downloaded to.")]
    [ValidateNotNullOrEmpty()]
    [string]$DownloadPath = (Join-Path -Path $env:windir -ChildPath "Temp")
)

Begin {
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
        } catch {
            try {
                # Install NuGet package provider
                $PackageProvider = Install-PackageProvider -Name NuGet -Force -Verbose:$false
        
                # Install current missing module
                Install-Module -Name $Module -Force -ErrorAction Stop -Confirm:$false -Verbose:$false
            } catch {
                Write-Warning -Message "An error occurred while attempting to install $($Module) module. Error message: $($_.Exception.Message)"
            }
        }
    }

    # Determine the localized name of the principals required for the functionality of this script
    $LocalSystemPrincipal = "NT AUTHORITY\SYSTEM"
}

Process {
    # Functions
    function Write-LogEntry {
        param (
            [parameter(Mandatory = $true, HelpMessage = "Value added to the log file.")]
            [ValidateNotNullOrEmpty()]
            [string]$Value,
    
            [parameter(Mandatory = $true, HelpMessage = "Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.")]
            [ValidateNotNullOrEmpty()]
            [ValidateSet("1", "2", "3")]
            [string]$Severity,
    
            [parameter(Mandatory = $false, HelpMessage = "Name of the log file that the entry will written to.")]
            [ValidateNotNullOrEmpty()]
            [string]$FileName = "Invoke-OneDriveSetupUpdate.log"
        )
        # Determine log file location
        $LogFilePath = Join-Path -Path (Join-Path -Path $env:windir -ChildPath "Temp") -ChildPath $FileName
        
        # Construct time stamp for log entry
        $Time = -join @((Get-Date -Format "HH:mm:ss.fff"), "+", (Get-WmiObject -Class Win32_TimeZone | Select-Object -ExpandProperty Bias))
        
        # Construct date for log entry
        $Date = (Get-Date -Format "MM-dd-yyyy")
        
        # Construct context for log entry
        $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
        
        # Construct final log entry
        $LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""OneDriveSetupUpdate"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"
        
        # Add value to log file
        try {
            Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
        } catch {
            Write-Warning -Message "Unable to append log entry to Invoke-OneDriveSetupUpdate.log file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
        }
    }

    function Start-DownloadFile {
        param(
            [parameter(Mandatory = $true, HelpMessage="URL for the file to be downloaded.")]
            [ValidateNotNullOrEmpty()]
            [string]$URL,
    
            [parameter(Mandatory = $true, HelpMessage="Folder where the file will be downloaded.")]
            [ValidateNotNullOrEmpty()]
            [string]$Path,
    
            [parameter(Mandatory = $true, HelpMessage="Name of the file including file extension.")]
            [ValidateNotNullOrEmpty()]
            [string]$Name
        )
        Begin {
            # Set global variable
            $ErrorActionPreference = "Stop"

            # Construct WebClient object
            $WebClient = New-Object -TypeName "System.Net.WebClient"
        }
        Process {
            try {
                # Create path if it doesn't exist
                if (-not(Test-Path -Path $Path)) {
                    New-Item -Path $Path -ItemType Directory -Force -ErrorAction Stop | Out-Null
                }
        
                # Start download of file
                $WebClient.DownloadFile($URL, (Join-Path -Path $Path -ChildPath $Name))
            }
            catch {
                Write-LogEntry -Value " - Failed to download file from URL '$($URL)'" -Severity 3
            }
        }
        End {
            # Dispose of the WebClient object
            $WebClient.Dispose()
        }
    }

    function Invoke-Executable {
        param (
            [parameter(Mandatory = $true, HelpMessage = "Specify the file name or path of the executable to be invoked, including the extension.")]
            [ValidateNotNullOrEmpty()]
            [string]$FilePath,
    
            [parameter(Mandatory = $false, HelpMessage = "Specify arguments that will be passed to the executable.")]
            [ValidateNotNull()]
            [string]$Arguments
        )
        
        # Construct a hash-table for default parameter splatting
        $SplatArgs = @{
            FilePath = $FilePath
            NoNewWindow = $true
            Passthru = $true
            ErrorAction = "Stop"
        }
        
        # Add ArgumentList param if present
        if (-not ([System.String]::IsNullOrEmpty($Arguments))) {
            $SplatArgs.Add("ArgumentList", $Arguments)
        }
        
        # Invoke executable and wait for process to exit
        try {
            $Invocation = Start-Process @SplatArgs
            $Handle = $Invocation.Handle
            $Invocation.WaitForExit()   
        }
        catch {
            Write-Warning -Message $_.Exception.Message; break
        }
        
        # Handle return value with exitcode from process
        return $Invocation.ExitCode
    }

    try {
        try {
            # Attempt to remove existing OneDriveSetup.exe in the temporary location
            $OneDriveSetupFilePath = Join-Path -Path $DownloadPath -ChildPath "OneDriveSetup.exe"
            if (Test-Path -Path $OneDriveSetupFilePath) {
                Write-LogEntry -Value "Found existing 'OneDriveSetup.exe' in the temporary download path, removing it" -Severity 1
                Remove-Item -Path $OneDriveSetupFilePath -Force -ErrorAction Stop
            }

            # Download the OneDriveSetup.exe file to the temporary location
            $OneDriveSetupURL = "https://go.microsoft.com/fwlink/p/?LinkId=248256"
            Write-LogEntry -Value "Attempting to download the latest OneDriveSetup.exe file from Microsoft download page to the temporary download path: $($DownloadPath)" -Severity 1
            Write-LogEntry -Value "Using URL for download: $($OneDriveSetupURL)" -Severity 1
            Start-DownloadFile -URL $OneDriveSetupURL -Path $DownloadPath -Name "OneDriveSetup.exe" -ErrorAction Stop

            # Validate that the OneDriveSetup.exe file has been successfully downloaded to the temporary location
            if (Test-Path -Path $OneDriveSetupFilePath) {
                Write-LogEntry -Value "Detected 'OneDriveSetup.exe' in the temporary download path" -Severity 1

                try {
                    # Attempt to import the NTFSSecurity module as a verification that it was successfully installed
                    Write-LogEntry -Value "Attempting to import the 'NTFSSecurity' module" -Severity 1
                    Import-Module -Name "NTFSSecurity" -Verbose:$false -ErrorAction Stop

                    # ... rest of the script ...
                } catch {
                    Write-LogEntry -Value "Failed to import the 'NTFSSecurity' module. Error message: $($_.Exception.Message)" -Severity 3
                }
            } else {
                Write-LogEntry -Value "Unable to detect 'OneDriveSetup.exe' in the temporary download path" -Severity 3
            }
        } catch {
            Write-LogEntry -Value "Failed to download OneDriveSetup.exe file. Error message: $($_.Exception.Message)" -Severity 3
        }
    } catch {
        Write-LogEntry -Value "An unexpected error occurred: $($_.Exception.Message)" -Severity 3
    }
}
