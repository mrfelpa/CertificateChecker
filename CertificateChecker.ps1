function Test-CertificateTemplate {
    [CmdletBinding()]
    param (
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

$adcsInstalled = Get-WindowsFeature -Name ADCS-Cert-Authority -ErrorAction SilentlyContinue

if ($adcsInstalled -eq $null) {
    Write-Output "AD CS role is not installed on this server."
    return
}

# Check for unexpired root CA certificates
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

# Check for unexpired intermediate CA certificates
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

# Check permissions on AD CS folders
$adcsConfigPath = "$env:SystemRoot\System32\certsrv"
$adcsLogsPath = "$env:SystemRoot\System32\CertLog"

try {
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
catch {
    Write-Error "Error checking permissions: $_"
}

# Check for specific certificate templates
$certificateTemplatesToCheck = @("WebServer", "User", "Computer")

foreach ($templateName in $certificateTemplatesToCheck) {
    Test-CertificateTemplate -TemplateName $templateName
}

# Check CRL (Certificate Revocation List) 
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

# Check for expired certificates and alert if found
$expiredCertificates = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.NotAfter -lt (Get-Date) }

if ($expiredCertificates.Count -gt 0) {
    Write-Output "Expired certificates found in the Local Machine\My store:"
    $expiredCertificates | ForEach-Object {
        Write-Output "Subject: $($_.Subject)"
        Write-Output "  Thumbprint: $($_.Thumbprint)"
        Write-Output "  Expiry Date: $($_.NotAfter)"
        Write-Output "---------------------------"
    }
}

# Check if auditing is enabled for AD CS events
try {
    $auditPolicy = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration" -ErrorAction Stop | Select-Object -ExpandProperty AuditFilter
    
    if ($auditPolicy -eq "0x0") {
        Write-Output "Auditing for AD CS events is not enabled."
    }
    else {
        Write-Output "Auditing for AD CS events is enabled. AuditFilter: $auditPolicy"
    }
}
catch {
    Write-Error "Error checking auditing settings: $_"
}
