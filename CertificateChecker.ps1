
Import-Module ActiveDirectory

$adcsConfigPath = "$env:SystemRoot\System32\certsrv"
$adcsLogsPath = "$env:SystemRoot\System32\CertLog"
$logFilePath = ".\ADCSChecker.log"

# Add the necessary assemblies
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName Microsoft.VisualBasic  # Add the Visual Basic assembly

function Display-Certificates {
    param (
        [Parameter(Mandatory = $true)]
        [array]$Certificates,
        [string]$StoreType
    )

    if ($Certificates.Count -eq 0) {
        return "No unexpired $StoreType certificates found."
    } else {
        $output = "Unexpired $StoreType certificates found:`n"
        foreach ($cert in $Certificates) {
            $output += "Subject: $($cert.Subject)`n"
            $output += "  Thumbprint: $($cert.Thumbprint)`n"
            $output += "  Expiry Date: $($cert.NotAfter)`n"
            $output += "---------------------------`n"
        }
        return $output
    }
}

function Check-RootCACerts {
    $rootCACerts = Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object { $_.Issuer -eq $_.Subject -and $_.NotAfter -gt (Get-Date) }
    return Display-Certificates -Certificates $rootCACerts -StoreType "Root CA"
}

function Check-IntermediateCACerts {
    $intermediateCACerts = Get-ChildItem -Path Cert:\LocalMachine\CA | Where-Object { $_.Issuer -ne $_.Subject -and $_.NotAfter -gt (Get-Date) }
    return Display-Certificates -Certificates $intermediateCACerts -StoreType "Intermediate CA"
}

function Check-ADCSFolderPermissions {
    function Get-FolderPermissions {
        param (
            [string]$path
        )
        if (Test-Path -Path $path) {
            return Get-Acl -Path $path | Select-Object -ExpandProperty Access
        } else {
            throw "The directory $path does not exist."
        }
    }

    try {
        $configPermissions = Get-FolderPermissions -path $adcsConfigPath
        $logsPermissions = Get-FolderPermissions -path $adcsLogsPath
        
        return @(
            "Permissions on the AD CS Configuration Folder ($adcsConfigPath):",
            ($configPermissions | ForEach-Object { "User/Group: $_.IdentityReference, Permissions: $_.FileSystemRights" }),
            "Permissions on the AD CS Logs Folder ($adcsLogsPath):",
            ($logsPermissions | ForEach-Object { "User/Group: $_.IdentityReference, Permissions: $_.FileSystemRights" })
        ) -join "`n"  
    } catch {
        return "Error: $_"
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
            return "Certificate template '$TemplateName' exists."
        } else {
            return "Certificate template '$TemplateName' does not exist."
        }
    } catch {
        return "Error checking certificate template: $_"
    }
}

function Check-CRLDistributionPoints {
    try {
        if (-not (Get-Command Get-CACrlDistributionPoint -ErrorAction SilentlyContinue)) {
            return "The cmdlet 'Get-CACrlDistributionPoint' is not available in this environment."
        }

        $crlDistributionPoints = Get-CACrlDistributionPoint

        if ($crlDistributionPoints.Count -eq 0) {
            return "No CRL distribution points configured."
        } else {
            return @("CRL distribution points configured:", ($crlDistributionPoints | ForEach-Object { "CRL Distribution Point: $_.Uri" })) -join "`n" 
        }
    } catch {
        return "Error retrieving CRL distribution points: $_"
    }
}

function Check-ExpiredCertificates {
    $expiredCertificates = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.NotAfter -lt (Get-Date) }
    
    if ($expiredCertificates.Count -eq 0) {
        return 
    }

    return Display-Certificates -Certificates $expiredCertificates -StoreType 
}

# Create the graphical interface
$form = New-Object System.Windows.Forms.Form
$form.Text = 'AD CS Checker Tool'
$form.Size = New-Object System.Drawing.Size(500, 400)

# Create button to check Root CA Certificates
$btnRootCA = New-Object System.Windows.Forms.Button
$btnRootCA.Text = 'Check Root CA Certificates'
$btnRootCA.Location = New-Object System.Drawing.Point(10, 10)
$btnRootCA.Size = New-Object System.Drawing.Size(200, 30)
$form.Controls.Add($btnRootCA)

# Create button to check Intermediate CA Certificates
$btnIntermediateCA = New-Object System.Windows.Forms.Button
$btnIntermediateCA.Text = 'Check Intermediate CA Certificates'
$btnIntermediateCA.Location = New-Object System.Drawing.Point(10, 50)
$btnIntermediateCA.Size = New-Object System.Drawing.Size(200, 30)
$form.Controls.Add($btnIntermediateCA)

# Create button to check AD CS Folder Permissions
$btnFolderPermissions = New-Object System.Windows.Forms.Button
$btnFolderPermissions.Text = 'Check AD CS Folder Permissions'
$btnFolderPermissions.Location = New-Object System.Drawing.Point(10, 90)
$btnFolderPermissions.Size = New-Object System.Drawing.Size(200, 30)
$form.Controls.Add($btnFolderPermissions)

# Create button to check Certificate Templates
$btnTemplateCheck = New-Object System.Windows.Forms.Button
$btnTemplateCheck.Text = 'Check Certificate Template'
$btnTemplateCheck.Location = New-Object System.Drawing.Point(10, 130)
$btnTemplateCheck.Size = New-Object System.Drawing.Size(200, 30)
$form.Controls.Add($btnTemplateCheck)

# Create button to check CRL Distribution Points
$btnCRLCheck = New-Object System.Windows.Forms.Button
$btnCRLCheck.Text = 'Check CRL Distribution Points'
$btnCRLCheck.Location = New-Object System.Drawing.Point(10, 170)
$btnCRLCheck.Size = New-Object System.Drawing.Size(200, 30)
$form.Controls.Add($btnCRLCheck)

# Create button to check Expired Certificates
$btnExpiredCertsCheck = New-Object System.Windows.Forms.Button
$btnExpiredCertsCheck.Text = 'Check Expired Certificates'
$btnExpiredCertsCheck.Location = New-Object System.Drawing.Point(10, 210)
$btnExpiredCertsCheck.Size = New-Object System.Drawing.Size(200, 30)
$form.Controls.Add($btnExpiredCertsCheck)

# Create text box to display results
$resultBox = New-Object System.Windows.Forms.TextBox
$resultBox.Multiline = $true
$resultBox.ScrollBars = 'Vertical'
$resultBox.Location = New-Object System.Drawing.Point(220, 10)
$resultBox.Size = New-Object System.Drawing.Size(250, 340)
$form.Controls.Add($resultBox)

# Button click event handlers
$btnRootCA.Add_Click({
    $resultBox.Text += Check-RootCACerts + "`n`n"
})

$btnIntermediateCA.Add_Click({
    $resultBox.Text += Check-IntermediateCACerts + "`n`n"
})

$btnFolderPermissions.Add_Click({
    try {
        $permissionsResult = Check-ADCSFolderPermissions 
        foreach ($line in $permissionsResult) {
            $resultBox.Text += "$line`n"
        }
    } catch {
        $resultBox.Text += "Error: $_`n"
    }
})

$btnTemplateCheck.Add_Click({

    $templateNameInputBox = [Microsoft.VisualBasic.Interaction]::InputBox("Enter the Certificate Template name", "Certificate Template Check", "")
    
    if (-not [string]::IsNullOrWhiteSpace($templateNameInputBox)) {
    
        $resultBox.Text += Check-CertificateTemplates -TemplateName $templateNameInputBox + "`n`n"
    } else {
        [System.Windows.Forms.MessageBox]::Show("Template name cannot be empty.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
})

$btnCRLCheck.Add_Click({
    $resultBox.Text += Check-CRLDistributionPoints + "`n`n"
})

$btnExpiredCertsCheck.Add_Click({
    
    $resultBox.Text += Check-ExpiredCertificates + "`n`n"
})

$form.ShowDialog()
