# Create a High Availabilty SharePoint Farm with 9 VMs using the Powershell DSC Extension

This template will create a SQL Server 2014 Always On Availability Group using the PowerShell DSC Extension it creates the following resources:

+	A Virtual Network
+	A Storage Account
+	Two external and one internal load balancer
+	A NAT Rule to allow RDP to one VM which can be used as a jumpbox, a load balancer rule for ILB for a SQL Listener and a load balancer rule for HTTP traffic on port 80 for SharePoint
+ 	Two public IP addresses
+	Two VMs as Domain Controllers for a new Forest and Domain
+	Three VMs in a Windows Server Cluster, two VMs run SQL Server 2014 with a common availability group and the third is a File Share Witness for the Cluster
+	Two SharePoint App Servers
+	Two SharePoint Web Servers
+	Four Availability Sets one for the AD VMs, one for the SQL and Witness VMs, one for the SharePoint App Servers and one for the SharePoint Web Servers the second Availability Set is configured with three Update Domains and three Fault Domains.

There are a number of issues\workarounds in this template and the associated DSC Script:

1. This template is entirely serial due to some issues between the platform agent and the DSC extension which cause problems when multiple VM and\or extension resources are deployed concurrently, this will be fixed in the future

Click the button below to deploy

<a href="https://azuredeploy.net" target="_blank">
    <img src="http://azuredeploy.net/deploybutton.png"/>
</a>

Below are the parameters that the template expects

| Name   | Description    |
|:--- |:---|
| newStorageAccountName    | Name of the storage account to create    |
| storageAccountType      | Type of the storage account <br> <ul>**Allowed Values**<li>Standard_LRS **(default)**</li><li>Standard_GRS</li><li>"Standard_ZRS"</li></ul> |
| deploymentLocation  | Location where to deploy the resource <br><ul>**Allowed Values**<li>West US</li><li>East US</li><li>**West Europe (default)**</li><li>East Asia</li><li>Southeast Asia</li>|
| virtualNetworkName | Name of the Virtual Network |
| virtualNetworkAddressRange | Virtual Network Address Range <br> <ul><li>10.0.0.0/16 **(default)**</li></ul> |
| staticSubnet | Address prefix for subnet that Static IP addresses are taken from <br> <ul><li>10.0.0.0/24 **(default)**</li></ul> |
| sqlSubnet | Address prefix for subnet that SQL Server and Witness IP addresses are taken from <br> <ul><li>10.0.1.0/24 **(default)**</li></ul> |
| spwebSubnet | Address prefix for subnet that SharePoint Web Server addresses are taken from <br> <ul><li>10.0.2.0/24 **(default)**</li></ul> |
| spAppSubnet | Address prefix for subnet that SharePoint App Server  are taken from <br> <ul><li>10.0.3.0/24 **(default)**</li></ul> |
| adPDCNicIPAddress | The IP address of the new AD PDC  <br> <ul><li>**10.0.0.4 (default)**</li></ul> |
| adBDCNicIPAddress | The IP address of the new AD BDC  <br> <ul><li>**10.0.0.5 (default)**</li></ul> |
| sqlLBNicIPAddress | The IP address of the ILB used for SQL Listener  <br> <ul><li>**10.0.0.6 (default)**</li></ul> |
| publicIPAddressType | Type of Public IP Address <br> <ul>**Allowed Values**<li>Dynamic **(default)**</li><li>Static</li></ul>|
| adVMPrefix | The Prefix of the AD VM names |
| sqlVMPrefix | The Prefix of the SQL VM names |
| spVMPrefix | The Prefix of the SharePoint VM names |
| adminUsername | Admin username for the VM **This will also be used as the domain admin user name**|
| adminPassword | Admin password for the VM **This will also be used as the domain admin password and the SafeMode password ** |
| adVMSize | Size of the AD VMs <br> <ul>**Allowed Values**<li>Standard_A0 </li><li>Standard_A1**(default)**</li><li>Standard_A2</li><li>Standard_A3</li><li>Standard_A4</li></ul>|
| sqlVMSize | Size of the SQL VMs<br> <ul>**Allowed Values**<li>Standard_A0 </li><li>Standard_A1**(default)**</li><li>Standard_A2</li><li>Standard_A3</li><li>Standard_A4</li></ul>|
| witnessVMSize | Size of the Witness VM<br> <ul>**Allowed Values**<li>Standard_A0 </li><li>Standard_A1**(default)**</li><li>Standard_A2</li><li>Standard_A3</li><li>Standard_A4</li></ul>|
| spVMSize | Size of the SharePoint VMs<br> <ul>**Allowed Values**<li>Standard_A0 </li><li>Standard_A1**(default)**</li><li>Standard_A2</li><li>Standard_A3</li><li>Standard_A4</li></ul>|
| adImageName | Name of image to use for the AD VMs <br> <ul><li>a699494373c04fc0bc8f2bb1389d6106__Windows-Server-2012-R2-201503.01-en.us-127GB.vhd **(default)**</li></ul>|
| sqlImageName | Name of image to use for the SQL VMs <br> <ul><li>fb83b3509582419d99629ce476bcb5c8__SQL-Server-2014-RTM-12.0.2048.0-Ent-ENU-Win2012R2-cy15su04 **(default)**</li></ul>|
| witnessImageName | Name of image to use for the witness VM <br> <ul><li>a699494373c04fc0bc8f2bb1389d6106__Windows-Server-2012-R2-201503.01-en.us-127GB.vhd **(default)**</li></ul>|
| spImageName | Name of image to use for the SharePoint VMs <br> <ul><li>c6e0f177abd8496e934234bd27f46c5d__SharePoint-2013-Trial-1-20-2015**(default)**</li></ul>|
| vmContainerName | The container name in the storage account where VM disks are stored|
| domainName | The FQDN of the AD Domain created |
| dnsPrefix | The DNS prefix for the public IP address used by the Load Balancer for SharePoint Web site access |
| rdpDNSPrefix | The DNS prefix for the public IP address used by the Load Balancer for RDP Access|
| rdpPort | The public RDP port for first VM |
| AssetLocation | The location of resources such as templates and DSC modules that the script is dependent <br> <ul><li> **https://raw.githubusercontent.com/azurermtemplates/azurermtemplates/master/sharepoint-server-farm-ha (default)**</li></ul>
| sqlServerServiceAccountUserName | The SQL Server Service account name |
| sqlServerServiceAccountPassword | The SQL Server Service account password |
| sharePointSetupUserAccountUserName | The Sharepoint Setup account name|
| sharePointSetupUserAccountPassword |The Sharepoint Setup account password |
| sharePointFarmAccountUserName | The Sharepoint Farm account name |
| sharePointFarmAccountPassword | The Sharepoint Farm account password |
| sharePointFarmPassphrasePassword | The Sharepoint Farm Passphrase |
| configDatabaseName | The Sharepoint Configuration Database Name|
| administrationContentDatabaseName | The Sharepoint Admin Site Database Name |
| contentDatabaseName | The Sharepoint Content Database Name|
| spSiteTemplateName | The Sharepoint Content Site Template Name |



