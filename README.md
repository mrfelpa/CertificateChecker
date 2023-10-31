
- This script performs various checks, including:

- Checking the existence of specific certificate templates.

- Verifying the presence of ***unexpired root and intermediate CA certificates***.

- Checking permissions on AD CS configuration and logs folders.

- Verifying the presence of ***CRL (Certificate Revocation List) distribution points***.

- Identifying any expired certificates in the ***Local Machine\My store***.

- Checking if auditing is enabled for ***AD CS events***.


# Installation


- Clone or download the repository.


- Open a PowerShell session with administrative privileges.


- Navigate to the directory where the script is located.


- Run the following command to set the execution policy to allow running the script:

        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
  

- Run the script by executing the following command:

        .\CertificateChecker.ps1

# Possible Errors and Troubleshooting

- ***Error: Execution of scripts is disabled on this system.***

- ***Solution:*** This error occurs when the execution policy does not allow running PowerShell scripts. To resolve this, open a PowerShell session with administrative privileges and run the following command:

        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
  

- ***Error:*** AD CS role is not installed on this server.

- ***Solution:*** This error indicates that the server does not have the AD CS role installed. Install the AD CS role using Server Manager or PowerShell before running the script.

-***Error:*** Error checking certificate.

- ***Solution:*** This error occurs when there is an issue while checking the certificate template. Check that the AD CS role is installed and running correctly. Ensure that the user running the script has the necessary permissions to access and query the AD CS configuration.

- ***Error:*** Error checking permissions.

- ***Solution:*** This error indicates that there was an issue while checking permissions on the AD CS folders. Ensure that the user running the script has sufficient privileges to access and query the permissions on the AD CS configuration and logs folders.

- ***Error:*** Error checking auditing settings.

- ***Solution:*** This error occurs when there is an issue while checking the auditing settings for AD CS events. Check that the user running the script has sufficient privileges to read the auditing settings in the Windows registry.
