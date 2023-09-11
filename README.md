***A PowerShell script that provides various security checks for Active Directory Certificate Services (AD CS) in a Windows environment***

# Installation

Cloning this GitHub repository to your local machine using the following command:

      git clone https://github.com/yourusername/ADCS-Scan.git


Change your working directory to the repository's root folder:

      cd ADCS-Scan

Run the ***ADCS-Scan.ps1*** PowerShell script.

If you encounter an execution policy error, you may need to temporarily modify the PowerShell execution policy.

Run PowerShell as an administrator and use the following command:

      Set-ExecutionPolicy Bypass -Scope Process

      .\ADCS-Scan.ps1


Execute the script:

      .\ADCS-Scan.ps1

The script will perform various security checks and display the results on your console.

# Usage

The AD CS Scan script is designed to run with minimal configuration. By default, it checks for the following:

    Installation of the AD CS role.
    Unexpired root CA certificates in the Local Machine\Root store.
    Unexpired intermediate CA certificates in the Local Machine\CA store.
    Permissions on AD CS configuration and logs folders.
    Specific certificate templates (you can customize the list).
    CRL (Certificate Revocation List) distribution points.

To run the script, simply execute it in a PowerShell session as described in the Installation section.


The script includes the following security checks:

    AD CS Role Check: Verifies if the AD CS role is installed.

    Root CA Certificates: Lists unexpired root CA certificates in the Local Machine\Root store.

    Intermediate CA Certificates: Lists unexpired intermediate CA certificates in the Local Machine\CA store.

    Folder Permissions: Checks permissions on AD CS configuration and logs folders.

    Certificate Templates: Checks for specific certificate templates (you can customize the list).

    CRL Distribution Points: Lists CRL distribution points configured.

    Expired Certificates: Identifies expired certificates in the Local Machine\My store.

    Auditing: Checks if auditing is enabled for AD CS events.


# Customization

You can customize the script to meet your needs:

Modify the list of certificate templates to check in the ***$certificateTemplatesToCheck array***.

Add additional security checks based on your organization's requirements.
