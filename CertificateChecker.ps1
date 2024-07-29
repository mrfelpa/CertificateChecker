Import-Module ActiveDirectory

$adcsConfigPath = "$env:SystemRoot\System32\certsrv"
$adcsLogsPath = "$env:SystemRoot\System32\CertLog"
$certificateTemplatesToCheck = @("WebServer", "User", "Computer")

function Check-RootCACerts {
    $rootCACerts = Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object { $_.Issuer -eq $_.Subject -and $_.NotAfter -gt (Get-Date) }

    if ($rootCACerts.Count -eq 0) {
        Write-Output "No unexpired root CA certificates found in the Local Machine\Root store." -ForegroundColor Yellow
    }
    else {
        Write-Output "Unexpired root CA certificates found in the Local Machine\Root store:" -ForegroundColor Green
        $rootCACerts | ForEach-Object {
            Write-Output "Subject: $($_.Subject)" -ForegroundColor White
            Write-Output "  Thumbprint: $($_.Thumbprint)" -ForegroundColor White
            Write-Output "  Expiry Date: $($_.NotAfter)" -ForegroundColor White
            Write-Output "---------------------------"
        }
    }
}

function Check-IntermediateCACerts {
    $intermediateCACerts = Get-ChildItem -Path Cert:\LocalMachine\CA | Where-Object { $_.Issuer -ne $_.Subject -and $_.NotAfter -gt (Get-Date) }

    if ($intermediateCACerts.Count -eq 0) {
        Write-Output "No unexpired intermediate CA certificates found in the Local Machine\CA store." -ForegroundColor Yellow
    }
    else {
        Write-Output "Unexpired intermediate CA certificates found in the Local Machine\CA store:" -ForegroundColor Green
        $intermediateCACerts | ForEach-Object {
            Write-Output "Subject: $($_.Subject)" -ForegroundColor White
            Write-Output "  Thumbprint: $($_.Thumbprint)" -ForegroundColor White
            Write-Output "  Expiry Date: $($_.NotAfter)" -ForegroundColor White
            Write-Output "---------------------------"
        }
    }
}

function Check-ADCSFolderPermissions {
    if (Test-Path -Path $adcsConfigPath) {
        $adcsConfigACL = Get-Acl -Path $adcsConfigPath
        Write-Output "Permissions on the AD CS Configuration Folder ($adcsConfigPath):" -ForegroundColor Cyan
        $adcsConfigACL.Access | ForEach-Object {
            Write-Output "User/Group: $($_.IdentityReference)" -ForegroundColor White
            Write-Output "  Permissions: $($_.FileSystemRights)" -ForegroundColor White
            Write-Output "---------------------------"
        }
    } else {
        Write-Error "The directory $adcsConfigPath does not exist."
    }

    if (Test-Path -Path $adcsLogsPath) {
        $adcsLogsACL = Get-Acl -Path $adcsLogsPath
        Write-Output "Permissions on the AD CS Logs Folder ($adcsLogsPath):" -ForegroundColor Cyan
        $adcsLogsACL.Access | ForEach-Object {
            Write-Output "User/Group: $($_.IdentityReference)" -ForegroundColor White
            Write-Output "  Permissions: $($_.FileSystemRights)" -ForegroundColor White
            Write-Output "---------------------------"
        }
    } else {
        Write-Error "The directory $adcsLogsPath does not exist."
    }
}

function Check-CertificateTemplates {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$TemplateName
    )

    try {
        $template = Get-CertificateTemplate | Where-Object { $_.Name -eq $TemplateName }

        if ($template) {
            Write-Output "Certificate template '$TemplateName' exists." -ForegroundColor Green
            return $true
        }
        else {
            Write-Output "Certificate template '$TemplateName' does not exist." -ForegroundColor Yellow
            return $false
        }
    }
    catch {
        Write-Error "Error checking certificate template: $_"
        return $false
    }
}

function Check-CRLDistributionPoints {
    $crlDistributionPoints = Get-CACrlDistributionPoint

    if ($crlDistributionPoints.Count -eq 0) {
        Write-Output "No CRL distribution points configured." -ForegroundColor Yellow
    }
    else {
        Write-Output "CRL distribution points configured:" -ForegroundColor Green
        $crlDistributionPoints | ForEach-Object {
            Write-Output "CRL Distribution Point: $($_.uri)" -ForegroundColor White
        }
    }
}

function Check-ExpiredCertificates {
    $expiredCertificates = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.NotAfter -lt (Get-Date) }

    if ($expiredCertificates.Count -eq 0) {
        Write-Output "No expired certificates found in the Local Machine\My store." -ForegroundColor Yellow
    }
    else {
        Write-Output "Expired certificates found in the Local Machine\My store:" -ForegroundColor Green
        $expiredCertificates | ForEach-Object {
            Write-Output "Subject: $($_.Subject)" -ForegroundColor White
            Write-Output "  Thumbprint: $($_.Thumbprint)" -ForegroundColor White
            Write-Output "  Expiry Date: $($_.NotAfter)" -ForegroundColor White
            Write-Output "---------------------------"
        }
    }
}

function Show-MainMenu {
    Clear-Host
    Write-Host "===============================" -ForegroundColor DarkCyan
    Write-Host "      AD CS Checker Tool       " -ForegroundColor Yellow
    Write-Host "===============================" -ForegroundColor DarkCyan
    Write-Host "1. Check for unexpired Root CA certificates" -ForegroundColor White
    Write-Host "2. Check for unexpired Intermediate CA certificates" -ForegroundColor White
    Write-Host "3. Check AD CS folder permissions" -ForegroundColor White
    Write-Host "4. Check specific Certificate Template" -ForegroundColor White
    Write-Host "5. Check CRL Distribution Points" -ForegroundColor White
    Write-Host "6. Check for expired certificates" -ForegroundColor White
    Write-Host "0. Exit" -ForegroundColor Red
    Write-Host "===============================" -ForegroundColor DarkCyan
}

function Get-UserChoice {
    $choice = Read-Host -Prompt "Please enter your choice"
    return $choice
}

do {
    Show-MainMenu
    $userChoice = Get-UserChoice

    switch ($userChoice) {
        '1' { Check-RootCACerts }
        '2' { Check-IntermediateCACerts }
        '3' { Check-ADCSFolderPermissions }
        '4' {
            $templateName = Read-Host -Prompt "Enter the Certificate Template name"
            Check-CertificateTemplates -TemplateName $templateName
        }
        '5' { Check-CRLDistributionPoints }
        '6' { Check-ExpiredCertificates }
        '0' { Write-Host "Exiting..." -ForegroundColor Green; break }
        default { Write-Host "Invalid choice. Please try again." -ForegroundColor Red }
    }

    if ($userChoice -ne '0') {
        Read-Host -Prompt "Press Enter to return to the main menu..."
    }
} while ($true)
