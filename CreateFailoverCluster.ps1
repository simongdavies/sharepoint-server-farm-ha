#
# Copyright="© Microsoft Corporation. All rights reserved."
#

configuration CreateFailoverCluster
{
    param
    (
        [Parameter(Mandatory)]
        [String]$DomainName,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$Admincreds,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$SQLServiceCreds,

        [Parameter(Mandatory)]
        [String]$ClusterName,

        [Parameter(Mandatory)]
        [String]$SharePath,

        [Parameter(Mandatory)]
        [String[]]$Nodes,

        [Parameter(Mandatory)]
        [String]$SqlAlwaysOnAvailabilityGroupName,

        [Parameter(Mandatory)]
        [String]$SqlAlwaysOnAvailabilityGroupListenerName,

        [UInt32]$SqlAlwaysOnAvailabilityGroupListenerPort,

        [Parameter(Mandatory)]
        [String]$LBName,

        [Parameter(Mandatory)]
        [String]$LBAddress,

        [Parameter(Mandatory)]
        [String]$PrimaryReplica,

        [Parameter(Mandatory)]
        [String]$SecondaryReplica,

        [Parameter(Mandatory)]
        [String]$SqlAlwaysOnEndpointName,

        [UInt32]$DatabaseEnginePort = 1433,

        [String]$DomainNetbiosName=(Get-NetBIOSName -DomainName $DomainName),

        [String[]]$DatabaseNames,
        [Int]$RetryCount=20,
        [Int]$RetryIntervalSec=30

    )

    Import-DscResource -ModuleName xComputerManagement, xFailOverCluster,CDisk,xActiveDirectory,XDisk,xSqlPs,xNetworking, xSql, xSQLServer
    [System.Management.Automation.PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($Admincreds.UserName)", $Admincreds.Password)
    [System.Management.Automation.PSCredential]$SQLCreds = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($SQLServiceCreds.UserName)", $SQLServiceCreds.Password)
    
    WaitForSqlSetup

    Node localhost
    {

        xWaitforDisk Disk2
        {
             DiskNumber = 2
             RetryIntervalSec =$RetryIntervalSec
             RetryCount = $RetryCount
        }

        cDiskNoRestart DataDisk
        {
            DiskNumber = 2
            DriveLetter = "F"
        }

        xWaitforDisk Disk3
        {
             DiskNumber = 3
             RetryIntervalSec =$RetryIntervalSec
             RetryCount = $RetryCount
        }

        cDiskNoRestart LogDisk
        {
            DiskNumber = 3
            DriveLetter = "G"
        }

        WindowsFeature FC
        {
            Name = "Failover-Clustering"
            Ensure = "Present"
        }

        WindowsFeature FCPS
        {
            Name = "RSAT-Clustering-PowerShell"
            Ensure = "Present"
        }

        WindowsFeature ADPS
        {
            Name = "RSAT-AD-PowerShell"
            Ensure = "Present"
        }
        xWaitForADDomain DscForestWait 
        { 
            DomainName = $DomainName 
            DomainUserCredential= $DomainCreds
            RetryCount = $RetryCount 
            RetryIntervalSec = $RetryIntervalSec 
        }
        xComputer DomainJoin
        {
            Name = $env:COMPUTERNAME
            DomainName = $DomainName
            Credential = $DomainCreds
        }
        xCluster FailoverCluster
        {
            Name = $ClusterName
            DomainAdministratorCredential = $DomainCreds
            Nodes = $Nodes
        }

        xWaitForFileShareWitness WaitForFSW
        {
            SharePath = $SharePath
            DomainAdministratorCredential = $DomainCreds
        }

        xClusterQuorum FailoverClusterQuorum
        {
            Name = $ClusterName
            SharePath = $SharePath
            DomainAdministratorCredential = $DomainCreds
        }

        xFirewall DatabaseEngineFirewallRule
        {
            Direction = "Inbound"
            Name = "SQL-Server-Database-Engine-TCP-In"
            DisplayName = "SQL Server Database Engine (TCP-In)"
            Description = "Inbound rule for SQL Server to allow TCP traffic for the Database Engine."
            DisplayGroup = "SQL Server"
            State = "Enabled"
            Access = "Allow"
            Protocol = "TCP"
            LocalPort = $DatabaseEnginePort -as [String]
            Ensure = "Present"
        }

        xFirewall DatabaseMirroringFirewallRule
        {
            Direction = "Inbound"
            Name = "SQL-Server-Database-Mirroring-TCP-In"
            DisplayName = "SQL Server Database Mirroring (TCP-In)"
            Description = "Inbound rule for SQL Server to allow TCP traffic for the Database Mirroring."
            DisplayGroup = "SQL Server"
            State = "Enabled"
            Access = "Allow"
            Protocol = "TCP"
            LocalPort = "5022"
            Ensure = "Present"
        }

        xFirewall ListenerFirewallRule
        {
            Direction = "Inbound"
            Name = "SQL-Server-Availability-Group-Listener-TCP-In"
            DisplayName = "SQL Server Availability Group Listener (TCP-In)"
            Description = "Inbound rule for SQL Server to allow TCP traffic for the Availability Group listener."
            DisplayGroup = "SQL Server"
            State = "Enabled"
            Access = "Allow"
            Protocol = "TCP"
            LocalPort = "59999"
            Ensure = "Present"
        }

        xSqlLogin AddDomainAdminAccountToSysadminServerRole
        {
            Name = $DomainCreds.UserName
            LoginType = "WindowsUser"
            ServerRoles = "sysadmin"
            Enabled = $true
            Credential = $Admincreds
        }

        xADUser CreateSqlServerServiceAccount
        {
            DomainAdministratorCredential = $DomainCreds
            DomainName = $DomainName
            UserName = $SQLServicecreds.UserName
            Password = $SQLServicecreds
            Ensure = "Present"
            DependsOn = "[xSqlLogin]AddDomainAdminAccountToSysadminServerRole"
        }

        xSqlLogin AddSqlServerServiceAccountToSysadminServerRole
        {
            Name = $SQLCreds.UserName
            LoginType = "WindowsUser"
            ServerRoles = "sysadmin"
            Enabled = $true
            Credential = $Admincreds
            DependsOn = "[xADUser]CreateSqlServerServiceAccount"
        }

        xSqlServer ConfigureSqlServerWithAlwaysOn
        {
            InstanceName = $env:COMPUTERNAME
            SqlAdministratorCredential = $Admincreds
            ServiceCredential = $SQLCreds
            Hadr = "Enabled"
            MaxDegreeOfParallelism = 1
            FilePath = "F:\DATA"
            LogPath = "G:\LOG"
            DomainAdministratorCredential = $DomainCreds
            DependsOn = "[xSqlLogin]AddSqlServerServiceAccountToSysadminServerRole"
        }

        xSqlEndpoint SqlAlwaysOnEndpoint
        {
            InstanceName = $env:COMPUTERNAME
            Name = $SqlAlwaysOnEndpointName
            PortNumber = 5022
            AllowedUser = $SQLServiceCreds.UserName
            SqlAdministratorCredential = $Domaincreds
            DependsOn = "[xSqlServer]ConfigureSqlServerWithAlwaysOn"
        }

        xSqlServer ConfigureSqlServerSecondaryWithAlwaysOn
        {
            InstanceName = $SecondaryReplica
            SqlAdministratorCredential = $Admincreds
            Hadr = "Enabled"
        }

        xSqlEndpoint SqlSecondaryAlwaysOnEndpoint
        {
            InstanceName = $SecondaryReplica
            Name = $SqlAlwaysOnEndpointName
            PortNumber = 5022
            AllowedUser = $SQLServiceCreds.UserName
            SqlAdministratorCredential = $Domaincreds
        }
        
        xSqlAvailabilityGroup SqlAG
        {
            Name = $SqlAlwaysOnAvailabilityGroupName
            ClusterName = $ClusterName
            InstanceName = $env:COMPUTERNAME
            PortNumber = 5022
            DomainCredential =$DomainCreds
            SqlAdministratorCredential = $Admincreds
        }
        WindowsFeature DNSPS
        {
            Name = "RSAT-DNS-Server"
            Ensure = "Present"
        } 
        
        Script UpdateDNS
        {
            SetScript = "Add-DnsServerResourceRecordA -Name $LBName -ZoneName $DomainName -IPv4Address $LBAddress -ErrorAction 'continue'"
            TestScript = "Get-DnsServerResourceRecord -Name $LBName -ZoneName $DomainName -ErrorAction 'silentlycontinue'"
            GetScript = "@{LBAddress=$LBAddress}"   
        }

        xSqlAvailabilityGroupListener SqlAGListener
        {
            Name = $SqlAlwaysOnAvailabilityGroupListenerName
            AvailabilityGroupName = $SqlAlwaysOnAvailabilityGroupName
            DomainNameFqdn = $DomainNameFqdn
            ListenerPortNumber = $SqlAlwaysOnAvailabilityGroupListenerPort
            ProbePortNumber = 59999
            InstanceName = $env:COMPUTERNAME
            DomainCredential =$DomainCreds
            SqlAdministratorCredential = $Admincreds
            DependsOn = "[xSqlAvailabilityGroup]SqlAG"
        }
        
        Script ConfigureDatabases
        {
            SetScript = "Configure-Databases -DatabaseNames $DatabaseNames -SqlAdministratorCredential $SQLCreds -PrimaryReplica $PrimaryReplica -SecondaryReplica $SecondaryReplica -SqlAlwaysOnAvailabilityGroupName $SqlAlwaysOnAvailabilityGroupName"
            TestScript = "Test-Databases -DatabaseNames $DatabaseNames -SqlAdministratorCredential $SQLCreds -PrimaryReplica $PrimaryReplica -SecondaryReplica $SecondaryReplica -SqlAlwaysOnAvailabilityGroupName $SqlAlwaysOnAvailabilityGroupName"
            GetScript = "@{DatabaseNames=$DatabaseNames}"   
            DependsOn = "[xSqlAvailabilityGroupListener]SqlAGListener" 
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
function Test-Databases
{
    param(
        [String[]]$DatabaseNames,
        [PSCredential]$SqlAdministratorCredential,
        [string]$PrimaryReplica,
        [string]$SecondaryReplica,
        [string]$SqlAlwaysOnAvailabilityGroupName
    )

    # Required SQL managability modules
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.Smo") | Out-Null
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended") | Out-Null
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") | Out-Null
    
    if ($null -ne $DatabaseNames) {
        # Primamry Replica connection
        $primaryServer = Get-SqlServer $PrimaryReplica -SqlAdministratorCredential $SqlAdministratorCredential
        $replicaServer = Get-SqlServer $SecondaryReplica -SqlAdministratorCredential $SqlAdministratorCredential
        $primaryAG = $primaryServer.AvailabilityGroups | where { $_.Name -eq $SqlAlwaysOnAvailabilityGroupName }
        $secondaryAG = $replicaServer.AvailabilityGroups | where { $_.Name -eq $SqlAlwaysOnAvailabilityGroupName }

        foreach ($database in $DatabaseNames)
        {
            if($null -ne $Server.Databases[$DatabaseName] ) {

                if (($secondaryAG.AvailabilityDatabases | Where-Object { $_.Name -eq $database }).IsJoined) {
                    continue
                }
                else {
                    return $false
                }
                 
            }
            else {
                return $false
            }
        } 
    }

    return $true
}
function Configure-Databases
{
    param(
        [String[]]$DatabaseNames,
        [PSCredential]$SqlAdministratorCredential,
        [string]$PrimaryReplica,
        [string]$SecondaryReplica,
        [string]$SqlAlwaysOnAvailabilityGroupName


    )
    
    # Required SQL managability modules
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.Smo") | Out-Null
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended") | Out-Null


    #If there are databases specified, then we create them, backup them up and add them to the specified AG replicas
    if ($null -ne $DatabaseNames)
    {
        
        # Primamry Replica connection
        $primaryServer = Get-SqlServer $PrimaryReplica -SqlAdministratorCredential $SqlAdministratorCredential

        #create database on the primary, then add them to all replicas and sync them
        foreach ($database in $DatabaseNames)
        {
            Write-Verbose -Message "Creating sample database '$($database)' ..."
            Create-SqlAlwaysOnDatabase -DatabaseName $database -Server $primaryServer

            #synchronize existing availability group replicas
            Update-SqlAlwaysOnAvailabilityGroupDatabases -SqlAlwaysOnAvailabilityGroupName $SqlAlwaysOnAvailabilityGroupName -PrimaryReplica $PrimaryReplica -SecondaryReplica $SecondaryReplica -SqlAdministratorCredential $SqlAdministratorCredential
        }

        Write-Verbose -Message "Adding databases Availability Group '$SqlAlwaysOnAvailabilityGroupName' completed."
    }
    else
    {
        Write-Verbose -Message "No databases were specified to add to Availability Group '$SqlAlwaysOnAvailabilityGroupName'."
    }
}

function Update-SqlAlwaysOnAvailabilityGroupDatabases([String]$SqlAlwaysOnAvailabilityGroupName, [String]$PrimaryReplica, [String]$SecondaryReplica, [PSCredential]$SqlAdministratorCredential)
{
    # Required SQL managability modules
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.Smo") | Out-Null
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SmoExtended") | Out-Null

    # Primamry Replica connection
    $primaryServer = Get-SqlServer $PrimaryReplica -SqlAdministratorCredential $SqlAdministratorCredential

    # Secondary Replica connection
    $replicaServer = Get-SqlServer $SecondaryReplica -SqlAdministratorCredential $SqlAdministratorCredential

    # AG on primary
    $primaryAG = $primaryServer.AvailabilityGroups | where { $_.Name -eq $SqlAlwaysOnAvailabilityGroupName }

    # AG on secondary
    $secondaryAG = $replicaServer.AvailabilityGroups | where { $_.Name -eq $SqlAlwaysOnAvailabilityGroupName }

    # Prepare the backup share
    $backupFolder = [guid]::NewGuid().ToString()
    $backupPath = "$env:TEMP\$backupFolder"
    $backupShare = "\\$env:COMPUTERNAME\$backupFolder"
    Create-SqlAlwaysOnBackupShare -BackupShare $backupFolder -BackupPath $backupPath -ServiceAccount $primaryServer.ServiceAccount

    # Sync existing primary and secondary databases
    $databases = $primaryServer.Databases | where { $_.IsSystemObject -eq $false }

    foreach ($database in $databases)
    {
        # Skip any databases joined to the availability group on the secondary replica.
        if (($secondaryAG.AvailabilityDatabases | Where-Object { $_.Name -eq $Database.Name }).IsJoined)
        {
            Write-Verbose -Message "Database '$($database.Name)' already joined to availability group '$($secondaryAG.Name)', skipping ..."
            continue
        }

        # Backup the database and log from the primary replica.
        $device = "$backupShare\$($database.Name).bak"
        Write-Verbose -Message "Backing up database '$($database.Name)' from '$($PrimaryServer.Name)' to '$($device)' ..."
        $backup = New-Object Microsoft.SqlServer.Management.Smo.Backup
        $backup.Database = $database.Name
        $backup.Action = [Microsoft.SqlServer.Management.Smo.BackupActionType]::Database
        $backup.Initialize = $true
        $backup.Devices.AddDevice($device, [Microsoft.SqlServer.Management.Smo.DeviceType]::File)
        $backup.SqlBackup($PrimaryServer)
        Write-Verbose -Message "Successfully backed up database '$($database.Name)'."

        $device = "$backupShare\$($database.Name).log"
        Write-Verbose -Message "Backing up log for database '$($database.Name)' from '$($PrimaryServer.Name)' to '$($device)' ..."
        $backup = New-Object Microsoft.SqlServer.Management.Smo.Backup
        $backup.Database = $database.Name
        $backup.Action = [Microsoft.SqlServer.Management.Smo.BackupActionType]::Log
        $backup.Initialize = $true
        $backup.Devices.AddDevice($device, [Microsoft.SqlServer.Management.Smo.DeviceType]::File)
        $backup.SqlBackup($PrimaryServer)
        Write-Verbose -Message "Successfully backed up log for database '$($database.Name)'."

        # Restore the database and log to the secondary replica.
        $device = "$backupShare\$($database.Name).bak"
        Write-Verbose -Message "Restoring database '$($database.Name)' from '$($device)' to '$($PrimaryServer.Name)' ..."
        $restore = New-Object Microsoft.SqlServer.Management.Smo.Restore
        $restore.Database = $database.Name
        $restore.Action = [Microsoft.SqlServer.Management.Smo.RestoreActionType]::Database
        $restore.Devices.AddDevice($device, [Microsoft.SqlServer.Management.Smo.DeviceType]::File)
        $restore.NoRecovery = $true
        $restore.SqlRestore($replicaServer)
        Write-Verbose -Message "Successfully restored database '$($database.Name)'."

        $device = "$backupShare\$($database.Name).log"
        Write-Verbose -Message "Restoring log for database '$($database.Name)' from '$($device)' to '$($PrimaryServer.Name)' ..."
        $restore = New-Object Microsoft.SqlServer.Management.Smo.Restore
        $restore.Database = $database.Name
        $restore.Action = [Microsoft.SqlServer.Management.Smo.RestoreActionType]::Log
        $restore.Devices.AddDevice($device, [Microsoft.SqlServer.Management.Smo.DeviceType]::File)
        $restore.NoRecovery = $true
        $restore.SqlRestore($replicaServer)
        Write-Verbose -Message "Successfully restored database '$($database.Name)'."

        # Add the database to the availability group.
        if (-not ($primaryAG.AvailabilityDatabases | Where-Object { $_.Name -eq $Database.Name }))
        {
            Write-Verbose -Message "Adding database '$($database.Name)' to availability group '$($primaryAG.Name)' ..."
            $adb = New-Object Microsoft.SqlServer.Management.Smo.AvailabilityDatabase $primaryAG,$database.Name
            $primaryAG.AvailabilityDatabases.Add($adb)
            $adb.Create()
            $primaryAG.Alter()
            Write-Verbose -Message "Successfully added database '$($database.Name)' to availability group."
        }

        # It can take some time before the database shows up in the availability group on the secondary replica.
        while ($true)
        {
            $secondaryAG.AvailabilityDatabases.Refresh()
            $databaseOnSecondary = $secondaryAG.AvailabilityDatabases | Where-Object { $_.Name -eq $Database.Name }
            if ($databaseOnSecondary)
            {
                break
            }

            Write-Verbose -Message "Waiting for database '$($database.Name)' to be available ..."
            Start-Sleep -Seconds 20
        }

        # Join the database to availabiliy group on secondary replica.
        if (-not $databaseOnSecondary.IsJoined)
        {
            Write-Verbose -Message "Joining database '$($databaseOnSecondary.Name)' to availability group '$($secondaryAG.Name)' ..."
            $databaseOnSecondary.JoinAvailablityGroup()
            Write-Verbose -Message "Successfully joined database '$($databaseOnSecondary.Name)' to availability group."
        }
    }

    # AG Replica
    $primaryAG.AvailabilityReplicas.Refresh()
    $secondaryAGReplica = $primaryAG.AvailabilityReplicas | where { $_.Name -eq $SecondaryReplica }

    # Verify the replica is in read only mode. If not, then set it
    if($secondaryAGReplica.ConnectionModeInSecondaryRole -ne [Microsoft.SqlServer.Management.Smo.AvailabilityReplicaConnectionModeInSecondaryRole]::AllowReadIntentConnectionsOnly)
    {
        Write-Verbose -Message "Setting replica $SecondaryReplica read only mode"

        $secondaryAGReplica.ConnectionModeInSecondaryRole = [Microsoft.SqlServer.Management.Smo.AvailabilityReplicaConnectionModeInSecondaryRole]::AllowReadIntentConnectionsOnly
        $secondaryAGReplica.Alter()

        Write-Verbose -Message "Set replica $SecondaryReplica read only mode completed!"
    }
    else
    {
        Write-Verbose -Message "Replica $SecondaryReplica is already in read only mode"
    }

    Write-Verbose -Message "Cleaning up backups ..."
    Remove-SmbShare -Name $backupFolder -Force | Out-Null

    Write-Verbose -Message "Removed share '$($backupShare)'."
    Remove-Item -Path $backupPath -Recurse -Force | Out-Null
    Write-Verbose -Message "Removed directory '$($backupPath)'."
}


# Create a database on a SQL Server instance if the database does not already exists. The user can provide a custom location of the database
# Data and Log files or accept the default by not setting the corresponding variables.
function Create-SqlAlwaysOnDatabase([string]$DatabaseName, [string]$DataPath, [string]$LogPath, [Microsoft.SqlServer.Management.Smo.Server]$Server)
{
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") | Out-Null
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO") | Out-Null

    if($null -eq $Server.Databases[$DatabaseName] )
    {
        #create the database
        $db = new-object ('Microsoft.SqlServer.Management.Smo.Database') ($Server, $DatabaseName)


        # if a location for data and log is provided then use the user provided. Otherwise, we create it using the default ones
        if($DataPath -and $LogPath)
        {
            if (!(Test-Path -path $DataPath))
            {
                #create the flder
                New-Item $DataPath -Type Directory
            }

            if (!(Test-Path -path $LogPath))
            {
                #create the flder
                New-Item $LogPath -Type Directory
            }

            $sysfg = new-object ('Microsoft.SqlServer.Management.Smo.FileGroup') ($db, 'PRIMARY')

            $db.FileGroups.Add($sysfg)

            $appfg = new-object ('Microsoft.SqlServer.Management.Smo.FileGroup') ($db, 'AppFileGroup')

            $db.FileGroups.Add($appfg)

            $syslogname = $DatabaseName + '_SysData'

            $dbdsysfile = new-object ('Microsoft.SqlServer.Management.Smo.DataFile') ($sysfg, $syslogname)

            # Create the file for the raw data
            $sysfg.Files.Add($dbdsysfile)
            $dbdsysfile.FileName = $DataPath + '\' + $syslogname + '.mdf'
            $dbdsysfile.Size = [double](5.0 * 1024.0)
            $dbdsysfile.GrowthType = 'None'
            $dbdsysfile.IsPrimaryFile = 'True'

            # Create the file for the Application tables
            $applogname = $DatabaseName + '_AppData'
            $dbdappfile = new-object ('Microsoft.SqlServer.Management.Smo.DataFile') ($appfg, $applogname)
            $appfg.Files.Add($dbdappfile)
            $dbdappfile.FileName = $DataPath + '\' + $applogname + '.ndf'
            $dbdappfile.Size = [double](25.0 * 1024.0)
            $dbdappfile.GrowthType = 'Percent'
            $dbdappfile.Growth = 25.0
            $dbdappfile.MaxSize = [double](100.0 * 1024.0)

            # Create the file for the log
            $loglogname = $DatabaseName + '_Log'
            $dblfile = new-object ('Microsoft.SqlServer.Management.Smo.LogFile') ($db, $loglogname)
            $db.LogFiles.Add($dblfile)
            $dblfile.FileName = $LogPath + '\' + $loglogname + '.ldf'
            $dblfile.Size = [double](10.0 * 1024.0)
            $dblfile.GrowthType = 'Percent'
            $dblfile.Growth = 25.0
        }

        # Create the database
        $db.Create()

        $createDate = $db.CreateDate
        Write-Verbose -Message "Created database '$DatabaseName' on '$createDate'"

        #refresh the server connection
        $Server.Refresh()
    }
    else
    {
        Write-Verbose -Message "Database '$DatabaseName' already exists."
    }
}

# create a folder and share it for AlwaysOn backup.
# If the folder already exists, then we don't create it again
# If the folder already shared, then we don't modify sharing settings
# Otherwise, the function creates and share the folder
function Create-SqlAlwaysOnBackupShare([string]$BackupShare, [string]$BackupPath, [string]$ServiceAccount)
{
    Write-Verbose -Message "Creating directory '$($BackupFolder)' ..."

    # create folder if it does not exist
    if (!(Test-Path -path $BackupPath))
    {
        #create the flder
        New-Item $BackupPath -Type Directory
    }

    # always ACL it for service account
    icacls.exe "$BackupPath" /grant:r ($ServiceAccount + ":(OI)(CI)F") | Out-Null

    # escape '\'
    $WMIFolderPath = $BackupPath -replace '\\','\\'

    # if the directory is not shared, then share it
    if(Get-CimInstance -Query "SELECT * FROM Win32_Share WHERE Path='$WMIFolderPath'")
    {
          Write-Verbose  -Message "Folder $WMIFolderPath already shared"
    }
    else
    {
        New-SmbShare -Name $BackupShare -Path $BackupPath -FullAccess $ServiceAccount -Temporary | Out-Null

        Write-Verbose  -Message "Shared folder $BackupPath as $BackupShare"
    }
}

# Create SQL Server SMO object using provided isntance name and credentials
function Get-SqlServer([string]$InstanceName, [PSCredential]$SqlAdministratorCredential)
{
    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.ConnectionInfo") | Out-Null
    $sc = New-Object Microsoft.SqlServer.Management.Common.ServerConnection

    $list = $InstanceName.Split("\")
    if ($list.Count -gt 1 -and $list[1] -eq "MSSQLSERVER")
    {
        $sc.ServerInstance = $list[0]
    }
    else
    {
        $sc.ServerInstance = $InstanceName
    }

    $sc.ConnectAsUser = $true
    if ($SqlAdministratorCredential.GetNetworkCredential().Domain -and $SqlAdministratorCredential.GetNetworkCredential().Domain -ne $env:COMPUTERNAME)
    {
        $sc.ConnectAsUserName = "$($SqlAdministratorCredential.GetNetworkCredential().UserName)@$($SqlAdministratorCredential.GetNetworkCredential().Domain)"
    }
    else
    {
        $sc.ConnectAsUserName = $SqlAdministratorCredential.GetNetworkCredential().UserName
    }
    $sc.ConnectAsUserPassword = $SqlAdministratorCredential.GetNetworkCredential().Password

    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.Smo") | Out-Null

    $s = New-Object Microsoft.SqlServer.Management.Smo.Server $sc

    $s
}

