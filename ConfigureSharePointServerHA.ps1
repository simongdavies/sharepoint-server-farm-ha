#
# Copyright="© Microsoft Corporation. All rights reserved."
#

configuration ConfigureSharePointServerHA
{

    param
    (
        [Parameter(Mandatory)]
        [String]$DomainName,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$Admincreds,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$SharePointSetupUserAccountcreds,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$SharePointFarmAccountcreds,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$SharePointFarmPassphrasecreds,
        
        [parameter(Mandatory)]
        [String]$DatabaseName,

        [parameter(Mandatory)]
        [String]$AdministrationContentDatabaseName,

        [parameter(Mandatory)]
        [String]$DatabaseServer,
        
        [parameter(Mandatory)]
        [String]$Configuration,

        [String]$SqlAlwaysOnAvailabilityGroupName,
        
        [String[]]$DatabaseNames,
        
        [String]$PrimaryReplica,
        
        [String]$SecondaryReplica,
        
        [System.Management.Automation.PSCredential]$SQLServiceCreds,

        [String]$DomainNetbiosName=(Get-NetBIOSName -DomainName $DomainName),

        [Int]$RetryCount=30,
        [Int]$RetryIntervalSec=60
    )

        Write-Verbose "AzureExtensionHandler loaded continuing with configuration"

        [System.Management.Automation.PSCredential ]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${DomainName}\$($Admincreds.UserName)", $Admincreds.Password)
        [System.Management.Automation.PSCredential ]$FarmCreds = New-Object System.Management.Automation.PSCredential ("${DomainName}\$($SharePointFarmAccountcreds.UserName)", $SharePointFarmAccountcreds.Password)
        [System.Management.Automation.PSCredential ]$SPsetupCreds = New-Object System.Management.Automation.PSCredential ("${DomainName}\$($SharePointSetupUserAccountcreds.UserName)", $SharePointSetupUserAccountcreds.Password)
        [System.Management.Automation.PSCredential]$SQLCreds = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($SQLServiceCreds.UserName)", $SQLServiceCreds.Password)
   
        # Install Sharepoint Module
        $ModuleFilePath="$PSScriptRoot\SharePointServer.psm1"
        $ModuleName = "SharepointServer"
        $PSModulePath = $Env:PSModulePath -split ";" | Select -Index 1
        $ModuleFolder = "$PSModulePath\$ModuleName"
        if (-not (Test-Path  $ModuleFolder -PathType Container)) {
            mkdir $ModuleFolder
        }
        Copy-Item $ModuleFilePath $ModuleFolder -Force

        Enable-CredSSPNTLM -DomainName $DomainName

        $SQLCLRPath="${PSScriptRoot}\SQLSysClrTypes.msi"
        $SMOPath="${PSScriptRoot}\SharedManagementObjects.msi"
        $SQLPSPath="${PSScriptRoot}\PowerShellTools.msi"

        Import-DscResource -ModuleName xComputerManagement, xActiveDirectory, xDisk, cConfigureSharepoint, xCredSSP, cDisk,xNetworking,xSQL
    
        Node localhost
        {

           xWaitforDisk Disk2
            {
                DiskNumber = 2
                RetryIntervalSec =$RetryIntervalSec
                RetryCount = $RetryCount
            }
            cDiskNoRestart SPDataDisk
            {
                DiskNumber = 2
                DriveLetter = "F"
                DependsOn = "[xWaitforDisk]Disk2"
            }
            xCredSSP Server 
            { 
                Ensure = "Present" 
                Role = "Server" 
            } 
            xCredSSP Client 
            { 
                Ensure = "Present" 
                Role = "Client" 
                DelegateComputers = "*.$Domain", "localhost"
            }
            WindowsFeature ADPS
            {
                Name = "RSAT-AD-PowerShell"
                Ensure = "Present"
                DependsOn = "[cDiskNoRestart]SPDataDisk"
            }

            xWaitForADDomain DscForestWait 
            { 
                DomainName = $DomainName 
                DomainUserCredential= $DomainCreds
                RetryCount = $RetryCount 
                RetryIntervalSec = $RetryIntervalSec 
                DependsOn = "[WindowsFeature]ADPS"      
            }

            xComputer DomainJoin
            {
                Name = $env:COMPUTERNAME
                DomainName = $DomainName
                Credential = $DomainCreds
                DependsOn = "[xWaitForADDomain]DscForestWait" 
            }

            Group AddSetupUserAccountToLocalAdminsGroup
            {
                GroupName = "Administrators"
                Credential = $DomainCreds
                MembersToInclude = "${DomainName}\$($SharePointSetupUserAccountcreds.UserName)"
                Ensure="Present"
                DependsOn = "[xComputer]DomainJoin"
            }

            xADUser CreateFarmAccount
            {
                DomainAdministratorCredential = $DomainCreds
                DomainName = $DomainName
                UserName = $SharePointFarmAccountcreds.UserName
                Password =$FarmCreds
                Ensure = "Present"
                DependsOn = "[WindowsFeature]ADPS", "[xComputer]DomainJoin"
            }
        
            cConfigureSharepoint ConfigureSharepointServer
            {
                DomainName=$DomainName
                DomainAdministratorCredential=$DomainCreds
                DatabaseName=$DatabaseName
                AdministrationContentDatabaseName=$AdministrationContentDatabaseName
                DatabaseServer=$DatabaseServer
                SetupUserAccountCredential=$SPsetupCreds
                FarmAccountCredential=$SharePointFarmAccountcreds
                FarmPassphrase=$SharePointFarmPassphrasecreds
                Configuration=$Configuration
                DependsOn = "[xADUser]CreateFarmAccount", "[Group]AddSetupUserAccountToLocalAdminsGroup"
            }

            # These packages should really only be installed on one server but they only take seconds to install and dont require a reboot

            Package SQLCLRTypes
            {
                Ensure = 'Present' 
                Path  =  $SQLCLRPath
                Name = 'Microsoft System CLR Types for SQL Server 2012 (x64)'
                ProductId = 'F1949145-EB64-4DE7-9D81-E6D27937146C'
                Credential= $Admincreds
            } 
            Package SharedManagementObjects
            {
                Ensure = 'Present' 
                Path  = $SMOPath
                Name = 'Microsoft SQL Server 2012 Management Objects  (x64)'
                ProductId = 'FA0A244E-F3C2-4589-B42A-3D522DE79A42'
                Credential = $Admincreds
            }

            # This does nothing if Databasenames is null

            xSqlNewAGDatabase SQLAGDatabases
            {
                SqlAlwaysOnAvailabilityGroupName = $SqlAlwaysOnAvailabilityGroupName
                DatabaseNames = $DatabaseNames
                PrimaryReplica = $PrimaryReplica
                SecondaryReplica = $SecondaryReplica
                SqlAdministratorCredential = $SQLCreds
            }
            SAMPLE_cConfigureSPSDBDFailover UpdateSPFailover
            {
                DatabaseNames = $DatabaseNames
                SecondaryReplica = $SecondaryReplica
            }
            LocalConfigurationManager 
            {
              ActionAfterReboot = 'StopConfiguration'
            }
        }
   
}
function Get-NetBIOSName
{ 
    [OutputType([string])]
    param(
        [string]$DomainName
    )

    if ($DomainName.Contains('.')) {
        $length=$DomainName.IndexOf('.')
        if ( $length -ge 16) {
            $length=15
        }
        return $DomainName.Substring(0,$length)
    }
    else {
        if ($DomainName.Length -gt 15) {
            return $DomainName.Substring(0,15)
        }
        else {
            return $DomainName
        }
    }
}
function Update-SPFailOverInstance
{
    param(
        [Parameter(Mandatory=$true)]
        [string]$DatabaseName
    )
    
    try 
    {
        Get-SPDatabase | ForEach-Object 
        {
            If ($_.Name -eq $DatabaseName)
            {
                $_.AddFailoverServiceInstance($FailoverServerInstance)
                $_.Update()
                Write-Verbose -Message "Updated database failover instance for '$($_.Name)'."                
            }
        }
    }
    catch
    {
            Write-Verbose -Message "FAILED: Updating database failover instance for '$($_.Name)'."  
    }
}
function Enable-CredSSPNTLM
{ 
    param(
        [Parameter(Mandatory=$true)]
        [string]$DomainName
    )
    
    # This is needed for the case where NTLM authentication is used

    Write-Verbose 'STARTED:Setting up CredSSP for NTLM'
   
    Enable-WSManCredSSP -Role client -DelegateComputer localhost, *.$DomainName -Force -ErrorAction SilentlyContinue
    Enable-WSManCredSSP -Role server -Force -ErrorAction SilentlyContinue

    if(-not (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -ErrorAction SilentlyContinue))
    {
        New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows -Name '\CredentialsDelegation' -ErrorAction SilentlyContinue
    }

    if( -not (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -Name 'AllowFreshCredentialsWhenNTLMOnly' -ErrorAction SilentlyContinue))
    {
        New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -Name 'AllowFreshCredentialsWhenNTLMOnly' -value '1' -PropertyType dword -ErrorAction SilentlyContinue
    }

    if (-not (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -Name 'ConcatenateDefaults_AllowFreshNTLMOnly' -ErrorAction SilentlyContinue))
    {
        New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -Name 'ConcatenateDefaults_AllowFreshNTLMOnly' -value '1' -PropertyType dword -ErrorAction SilentlyContinue
    }

    if(-not (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -ErrorAction SilentlyContinue))
    {
        New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -Name 'AllowFreshCredentialsWhenNTLMOnly' -ErrorAction SilentlyContinue
    }

    if (-not (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name '1' -ErrorAction SilentlyContinue))
    {
        New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name '1' -value "wsman/$env:COMPUTERNAME" -PropertyType string -ErrorAction SilentlyContinue
    }

    if (-not (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name '2' -ErrorAction SilentlyContinue))
    {
        New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name '2' -value "wsman/localhost" -PropertyType string -ErrorAction SilentlyContinue
    }

    if (-not (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name '3' -ErrorAction SilentlyContinue))
    {
        New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name '3' -value "wsman/*.$DomainName" -PropertyType string -ErrorAction SilentlyContinue
    }

    Write-Verbose "DONE:Setting up CredSSP for NTLM"
}

