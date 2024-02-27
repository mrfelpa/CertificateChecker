
Import-Module ActiveDirectory

# Define global variables
$adcsConfigPath = "$env:SystemRoot\System32\certsrv"
$adcsLogsPath = "$env:SystemRoot\System32\CertLog"
$certificateTemplatesToCheck = @("WebServer", "User", "Computer")

# Function to check for unexpired root CA certificates
function Check-RootCACerts {
    $rootCACerts = Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object { $_.Issuer -eq $_.Subject -and $_.NotAfter -gt (Get-Date) }

    if ($rootCACerts.Count -eq 0) {
        Write-Output "No unexpired root CA certificates found in the Local Machine\Root store."
    }
    else {
        Write-Output "Unexpired root CA certificates found in the Local Machine\Root store:"
        $rootCACerts | ForEach-Object {
            Write-Output "Subject: $($_.Subject)"
            Write-Output "  Thumbprint: $($_.Thumbprint)"
            Write-Output "  Expiry Date: $($_.NotAfter)"
            Write-Output "---------------------------"
        }
    }
}

# Function to check for unexpired intermediate CA certificates
function Check-IntermediateCACerts {
    $intermediateCACerts = Get-ChildItem -Path Cert:\LocalMachine\CA | Where-Object { $_.Issuer -ne $_.Subject -and $_.NotAfter -gt (Get-Date) }

    if ($intermediateCACerts.Count -eq 0) {
        Write-Output "No unexpired intermediate CA certificates found in the Local Machine\CA store."
    }
    else {
        Write-Output "Unexpired intermediate CA certificates found in the Local Machine\CA store:"
        $intermediateCACerts | ForEach-Object {
            Write-Output "Subject: $($_.Subject)"
            Write-Output "  Thumbprint: $($_.Thumbprint)"
            Write-Output "  Expiry Date: $($_.NotAfter)"
            Write-Output "---------------------------"
        }
    }
}

# Function to check permissions on AD CS folders
function Check-ADCSFolderPermissions {
    $adcsConfigACL = Get-Acl -Path $adcsConfigPath
    $adcsLogsACL = Get-Acl -Path $adcsLogsPath

    # Check permissions on the configuration folder
    Write-Output "Permissions on the AD CS Configuration Folder ($adcsConfigPath):"
    $adcsConfigACL.Access | ForEach-Object {
        Write-Output "User/Group: $($_.IdentityReference)"
        Write-Output "  Permissions: $($_.FileSystemRights)"
        Write-Output "---------------------------"
    }

    # Check permissions on the logs folder
    Write-Output "Permissions on the AD CS Logs Folder ($adcsLogsPath):"
    $adcsLogsACL.Access | ForEach-Object {
        Write-Output "User/Group: $($_.IdentityReference)"
        Write-Output "  Permissions: $($_.FileSystemRights)"
        Write-Output "---------------------------"
    }
}

# Function to check for specific certificate templates
function Check-CertificateTemplates {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TemplateName
    )

    try {
        $template = Get-CertificateTemplate | Where-Object { $_.Name -eq $TemplateName }

        if ($template) {
            Write-Output "Certificate template '$TemplateName' exists."
            return $true
        }
        else {
            Write-Output "Certificate template '$TemplateName' does not exist."
            return $false
        }
    }
    catch {
        Write-Error "Error checking certificate template: $_"
        return $false
    }
}

# Function to check CRL (Certificate Revocation List)
function Check-CRLDistributionPoints {
    $crlDistributionPoints = Get-CACrlDistributionPoint

    if ($crlDistributionPoints.Count -eq 0) {
        Write-Output "No CRL distribution points configured."
    }
    else {
        Write-Output "CRL distribution points configured:"
        $crlDistributionPoints | ForEach-Object {
            Write-Output "CRL Distribution Point: $($_.uri)"
        }
    }
}

# Function to check for expired certificates and alert if found
function Check-ExpiredCertificates {
    $expiredCertificates = Get-ChildItem -Path Cert:\LocalMachine\My |
