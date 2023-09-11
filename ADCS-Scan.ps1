
# Function to check if a specific certificate template exists
function Test-CertificateTemplate {
    param (
        [string]$templateName
    )
    
    $template = Get-CATemplate | Where-Object { $_.Name -eq $templateName }
    
    if ($template) {
        Write-Host "Certificate template '$templateName' exists."
        return $true
    }
    else {
        Write-Host "Certificate template '$templateName' does not exist."
        return $false
    }
}

# Check if the AD CS role is installed
$adcsInstalled = Get-WindowsFeature -Name ADCS-Cert-Authority -ErrorAction SilentlyContinue

if ($adcsInstalled -eq $null) {
    Write-Host "AD CS role is not installed on this server."
    exit
}

# Check for unexpired root CA certificates
$rootCACerts = Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object { $_.Issuer -eq $_.Subject -and $_.NotAfter -gt (Get-Date) }

if ($rootCACerts.Count -eq 0) {
    Write-Host "No unexpired root CA certificates found in the Local Machine\Root store."
}
else {
    Write-Host "Unexpired root CA certificates found in the Local Machine\Root store:"
    $rootCACerts | ForEach-Object {
        Write-Host "Subject: $($_.Subject)"
        Write-Host "  Thumbprint: $($_.Thumbprint)"
        Write-Host "  Expiry Date: $($_.NotAfter)"
        Write-Host "---------------------------"
    }
}

# Check for unexpired intermediate CA certificates
$intermediateCACerts = Get-ChildItem -Path Cert:\LocalMachine\CA | Where-Object { $_.Issuer -ne $_.Subject -and $_.NotAfter -gt (Get-Date) }

if ($intermediateCACerts.Count -eq 0) {
    Write-Host "No unexpired intermediate CA certificates found in the Local Machine\CA store."
}
else {
    Write-Host "Unexpired intermediate CA certificates found in the Local Machine\CA store:"
    $intermediateCACerts | ForEach-Object {
        Write-Host "Subject: $($_.Subject)"
        Write-Host "  Thumbprint: $($_.Thumbprint)"
        Write-Host "  Expiry Date: $($_.NotAfter)"
        Write-Host "---------------------------"
    }
}

# Check permissions on AD CS folders
$adcsConfigPath = "C:\Windows\System32\certsrv"
$adcsLogsPath = "C:\Windows\System32\CertLog"

$adcsConfigACL = Get-Acl -Path $adcsConfigPath
$adcsLogsACL = Get-Acl -Path $adcsLogsPath

# Check permissions on the configuration folder
Write-Host "Permissions on the AD CS Configuration Folder ($adcsConfigPath):"
$adcsConfigACL.Access | ForEach-Object {
    Write-Host "User/Group: $($_.IdentityReference)"
    Write-Host "  Permissions: $($_.FileSystemRights)"
    Write-Host "---------------------------"
}

# Check permissions on the logs folder
Write-Host "Permissions on the AD CS Logs Folder ($adcsLogsPath):"
$adcsLogsACL.Access | ForEach-Object {
    Write-Host "User/Group: $($_.IdentityReference)"
    Write-Host "  Permissions: $($_.FileSystemRights)"
    Write-Host "---------------------------"
}

# Check for specific certificate templates
$certificateTemplatesToCheck = @("WebServer", "User", "Computer")

foreach ($templateName in $certificateTemplatesToCheck) {
    Test-CertificateTemplate -templateName $templateName
}

# Check CRL (Certificate Revocation List) distribution points
$crlDistributionPoints = Get-CACrlDistributionPoint

if ($crlDistributionPoints.Count -eq 0) {
    Write-Host "No CRL distribution points configured."
}
else {
    Write-Host "CRL distribution points configured:"
    $crlDistributionPoints | ForEach-Object {
        Write-Host "CRL Distribution Point: $($_.uri)"
    }
}

# Additional security checks
# Check for expired certificates and alert if found
$expiredCertificates = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.NotAfter -lt (Get-Date) }

if ($expiredCertificates.Count -gt 0) {
    Write-Host "Expired certificates found in the Local Machine\My store:"
    $expiredCertificates | ForEach-Object {
        Write-Host "Subject: $($_.Subject)"
        Write-Host "  Thumbprint: $($_.Thumbprint)"
        Write-Host "  Expiry Date: $($_.NotAfter)"
        Write-Host "---------------------------"
    }
}

# Check if auditing is enabled for AD CS events
$auditPolicy = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration" | Select-Object -ExpandProperty AuditFilter

if ($auditPolicy -eq "0x0") {
    Write-Host "Auditing for AD CS events is not enabled."
}
else {
    Write-Host "Auditing for AD CS events is enabled. AuditFilter: $auditPolicy"
}
