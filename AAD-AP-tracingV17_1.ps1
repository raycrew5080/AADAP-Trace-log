############################################################################################################
# AADAP troubleshooting scripts
# Supported versions: Windows Server 2012 R2, Windows Server 2016, Windows Server 2019
# version 17.1 - 29/12/2022
# Written by mudeeb@microsoft.com & arpadg@microsoft.com
# Contributor: mozmaili@microsoft.com
############################################################################################################

param (
    [Parameter(Mandatory=$true)]
    [string] $Path,
    [switch] $ServiceTraceOn = $true,
    [switch] $Perfmon = $false
)

##########################################################################

$ScriptVersion = "17.1"

Write-host "Script version: $ScriptVersion"

#region Parameters

# Is the service installed?

$IsServiceInstalled = $False

If ((Get-WmiObject -Class Win32_Service -Filter "Name='WAPCSvc'").Name -eq "WAPCSvc") {$IsServiceInstalled = $True}

# AppProxyTrace integration 

$AppProxyFileDir = Get-Location
$AppProxyTraceOn = "AppProxyTrace.cmd -start -noise -cir 500"
$AppProxyTraceOff = "AppProxyTrace.cmd -stop" 

$WinVer = (Get-WmiObject win32_operatingsystem).version

$isdomainjoined = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain

$Global:FormatEnumerationLimit = -1

# Event logs

$ServicesDebugEvents = "Microsoft-Windows-CAPI2/Operational"

$AADAPDebugEvents = "Microsoft-AadApplicationProxy-Connector/Session","Microsoft-AadApplicationProxy-Updater/Session"

$ServicesExportEvents = 'System','Application','Security','Microsoft-Windows-CAPI2/Operational'

$AADAPExportEvents = 'Microsoft-AadApplicationProxy-Connector/Session','Microsoft-AadApplicationProxy-Updater/Session','Microsoft-AadApplicationProxy-Updater/Admin','Microsoft-AadApplicationProxy-Connector/Admin'

$DbgLvl = 5


if ($isdomainjoined -eq $True)
  {    

   #Definition Netlogon Debug Logging

   $setDBFlag = 'DBFlag'
   $setvaltype = [Microsoft.Win32.RegistryValueKind]::String
   $setvalue = "0x2fffffff"

   # Netlogon increase size to 100MB = 102400000Bytes = 0x61A8000)
   $setNLMaxLogSize = 'MaximumLogFileSize'
   $setvaltype2 = [Microsoft.Win32.RegistryValueKind]::DWord
   $setvalue2 = 0x061A8000

   # Store the original values to revert the config after collection
   $orgdbflag = (get-itemproperty -PATH "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters").$setDBFlag
   $orgNLMaxLogSize = (get-itemproperty -PATH "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters").$setNLMaxLogSize 
  
  }
  

#Collection for Additional Files     

$LogmanOn = 'logman.exe create trace "schannel" -ow -o .\%COMPUTERNAME%-schannel.etl -p {37D2C3CD-C5D4-4587-8531-4696C44244C8} 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 2048 -ets',`
'netsh trace start scenario=internetClient capture=yes report=no overwrite=yes maxsize=800 tracefile=.\%COMPUTERNAME%-HTTP-network.etl',`
'ipconfig /flushdns'

$LogmanOff = 'logman stop "schannel" -ets',`
'netsh trace stop'

$others = 'ipconfig /flushdns > %COMPUTERNAME%-ipconfig-flushdns-BEFORE.txt',`
'netstat -naob > %COMPUTERNAME%-netstat-nao-BEFORE.txt'
  
$Filescollector = 'ipconfig /all > %COMPUTERNAME%-ipconfig-all-AFTER.txt',`
'netstat -naob > %COMPUTERNAME%-netstat-nao-AFTER.txt',`
'copy %WINDIR%\system32\drivers\etc\hosts %COMPUTERNAME%-hosts.txt',`
'copy %SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config %COMPUTERNAME%-machine.config.txt',`
'set > %COMPUTERNAME%-environment-variables-AFTER.txt',`
'route print > %COMPUTERNAME%-route-print-AFTER.txt',`
'sc query  > %COMPUTERNAME%-services-config-AFTER.txt',`
'tasklist > %COMPUTERNAME%-tasklist-AFTER.txt',`
'if defined USERDNSDOMAIN (nslookup %USERDNSDOMAIN% > %COMPUTERNAME%-nslookup-USERDNSDOMAIN-AFTER.txt)',`
'certutil -v -store my > %COMPUTERNAME%-certutil-v-store-my.txt',`
'certutil -v -store ca > %COMPUTERNAME%-certutil-v-store-ca.txt',`
'certutil -v -store root > %COMPUTERNAME%-certutil-v-store-root.txt',`
'netsh int ipv4 show dynamicport tcp > %COMPUTERNAME%-netsh-int-ipv4-show-dynamicport-tcp.txt',`
'netsh int ipv4 show dynamicport udp > %COMPUTERNAME%-netsh-int-ipv4-show-dynamicport-udp.txt',`
'netsh int ipv6 show dynamicport tcp > %COMPUTERNAME%-netsh-int-ipv6-show-dynamicport-tcp.txt',`
'netsh int ipv6 show dynamicport udp > %COMPUTERNAME%-netsh-int-ipv6-show-dynamicport-udp.txt',`
'netsh winhttp show proxy > %COMPUTERNAME%-winhttp-proxy.txt',`
'netsh http show ssl > %COMPUTERNAME%-http-Binding.txt',` # SSL Binding 
'wmic qfe list full /format:htable > %COMPUTERNAME%-WindowsPatches.htm',`
'GPResult /f /h %COMPUTERNAME%-GPReport.html',`
'Msinfo32 /nfo %COMPUTERNAME%-msinfo32-AFTER.nfo',`
'regedit /e %COMPUTERNAME%-reg-RPC-ports-and-general-config.txt HKEY_LOCAL_MACHINE\Software\Microsoft\Rpc',`
'regedit /e %COMPUTERNAME%-reg-NETLOGON-port-and-other-params.txt HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\parameters',`
'regedit /e %COMPUTERNAME%-reg-cipher-Suit.txt HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002',`
'regedit /e %COMPUTERNAME%-reg-MSDOTNet4.txt HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319',`
'reg EXPORT "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" %COMPUTERNAME%-WinHTTPRegistry.txt',`
'regedit /e %COMPUTERNAME%-reg-schannel.txt HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL',`
'reg EXPORT "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Microsoft AAD App Proxy Connector" %COMPUTERNAME%-reg-AADConServConfig.txt',`
'reg EXPORT "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft AAD App Proxy Connector Updater" %COMPUTERNAME%-reg-AADUpConfig.txt',`
'reg EXPORT "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft AAD App Proxy Connector" %COMPUTERNAME%-reg-AADConfig.txt',`
'reg EXPORT "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" %COMPUTERNAME%-NET-version.txt'


if ($isdomainjoined -eq $True)
  {    

   $LogmanOn = $LogmanOn + ' ,logman create trace "dcloc" -ow -o .\%COMPUTERNAME%-dcloc.etl -p "Microsoft-Windows-DCLocator" 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 2048 -ets',`
   'logman update trace "dcloc" -p {6B510852-3583-4E2D-AFFE-A67F9F223438} 0xffffffffffffffff 0xff -ets',`
   'logman update trace "dcloc" -p {5BBB6C18-AA45-49B1-A15F-085F7ED0AA90} 0xffffffffffffffff 0xff -ets',`
   'logman create trace "ds_security" -ow -o .\%COMPUTERNAME%-ds_security.etl -p {BBA3ADD2-C229-4CDB-AE2B-57EB6966B0C4} 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets',`
   'logman update trace "ds_security" -p {BBA3ADD2-C229-4CDB-AE2B-57EB6966B0C4} 0xffffffffffffffff 0xff -ets'
   
   $LogmanOff = $LogmanOff + ', logman stop "dcloc" -ets',`
   'logman stop "ds_security" -ets'

    $others = $others + ', nltest /dsgetdc:%USERDNSDOMAIN% > %COMPUTERNAME%-nltest-dsgetdc-USERDNSDOMAIN-BEFORE.txt'
   
    $Filescollector = $Filescollector + ', nltest /dsgetdc:%USERDNSDOMAIN% > %COMPUTERNAME%-nltest-dsgetdc-USERDNSDOMAIN-AFTER.txt',`
    'copy /y %windir%\debug\netlogon.* %Computername%-netlogon.* '
    
   }
    


#endregion

##########################################################################
#region Functions

#New functions
    function AddDebugToConfig ([string] $configFile, [string] $global:logFilePath, [string] $AgentLogFileName) 
    {
        $config = [xml](Get-Content $configFile)
        $systemDiagnostics = $config.configuration["system.diagnostics"]

        if(!$systemDiagnostics)
        {
            $systemNet =  $config.CreateElement("system.diagnostics")
            $config.configuration.AppendChild($systemNet)
            $systemDiagnostics = $config.configuration["system.diagnostics"]
        }

        if(!$systemDiagnostics["trace"])
        {
            $trace = $config.CreateElement("trace")
            $systemDiagnostics.AppendChild($trace)
        }
        
         $systemDiagnostics["trace"].SetAttribute("autoflush", $True)
         $systemDiagnostics["trace"].SetAttribute("indentsize", 4)

        if(!$systemDiagnostics["trace"]["listeners"])
        {
            $listeners = $config.CreateElement("listeners")
            $systemDiagnostics["trace"].AppendChild($listeners)
        }

        if(!$systemDiagnostics["trace"]["listeners"]["add"])
        {
            $add = $config.CreateElement("add")
            $systemDiagnostics["trace"]["listeners"].AppendChild($add)
        }

                   
         $systemDiagnostics["trace"]["listeners"]["add"].SetAttribute("name", "textWriterListener")
         $systemDiagnostics["trace"]["listeners"]["add"].SetAttribute("type", "System.Diagnostics.TextWriterTraceListener")
        

         $systemDiagnostics["trace"]["listeners"]["add"].SetAttribute("initializeData", $global:logFilePath+$AgentLogFileName)

        if(!$systemDiagnostics["trace"]["listeners"]["remove"])
        {
            $remove = $config.CreateElement("remove")
            $systemDiagnostics["trace"]["listeners"].AppendChild($remove)
        }

        $systemDiagnostics["trace"]["listeners"]["remove"].SetAttribute("name", "Default")
           
        $config.Save($configFile)

        Write-Host ("")
        Write-Host -ForegroundColor:Green ("The log is stored: "+$global:logFilePath+$AgentLogFileName +". Restarting the service.")
        Write-Host ("")

    }

    function RemoveDebugFromConfig ([string] $configFile) 
    {
        $config = [xml](Get-Content $configFile)
        $systemDiagnostics = $config.configuration["system.diagnostics"]

        if($systemDiagnostics)
        {
            $config.configuration.RemoveChild($systemDiagnostics)
            $config.Save($configFile)

            Write-Host ("")
            Write-Host -ForegroundColor:Green ("Debug logging is turned off. Restarting the service.")
            Write-Host ("")
        }
             
    }

    function QueryCurrentConfig ([string] $configFile, [string] $AgentServiceName) 
    {
        $config = [xml](Get-Content $configFile)
        $systemDiagnostics = $config.configuration["system.diagnostics"]

        if(!$systemDiagnostics)
        {
            Write-Host ("")
            Write-Host -ForegroundColor:Green ("Debug logging is turned off.")
            Write-Host ("")
        }
        elseif (!$systemDiagnostics["trace"]["listeners"]["add"])
         {
            Write-Host ("")
            Write-Host -ForegroundColor:Green ("The configuration file seems to be corrupt. Please run the script with the -Off parameter.")
            Write-Host ("")
         }
        else 
         {

            Write-Host ("")
            Write-Host -ForegroundColor:Green ("The connector debug logging is configured. Parameters:")
            Write-Host ("")
            Write-Host ("name: " + $systemDiagnostics["trace"]["listeners"]["add"].GetAttribute("name"))
            Write-Host ("type: " + $systemDiagnostics["trace"]["listeners"]["add"].GetAttribute("type"))
            Write-Host ("initializeData: " + $systemDiagnostics["trace"]["listeners"]["add"].GetAttribute("initializeData"))
            Write-Host ("")


            $tempPathFile=$systemDiagnostics["trace"]["listeners"]["add"].GetAttribute("initializeData")
            
            
            if ($tempPathFile -ne $null)
              {  
                if ((Test-Path $tempPathFile) -eq $False)    
                 {
                   Write-Host ("")
                   Write-Host -ForegroundColor:Red "The debug log does not exist."
                   Write-Host ("")
                 }
                else
                 {
                   Write-Host ("")
                   Write-Host -ForegroundColor:Green "The debug log exist."
                   Write-Host ("")
                 }
              }              

            $connectorService = Get-Service -Name $AgentServiceName

            if($connectorService.Status -ne "Running")
             {
               Write-Host ("")
               Write-Host -ForegroundColor:Red "The $AgentServiceName Service is not running."
               Write-Host ("")
             }
        
            if($connectorService.Status -eq "Running")
             {
               Write-Host ("")
               Write-Host -ForegroundColor:Green "The $AgentServiceName Service is running."
               Write-Host ("")
             }
         }
   }

   function VerifyACLonPath([string] $global:logFilePath)
    {
    
     $objSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-20")
     $objUser = $objSID.Translate( [System.Security.Principal.NTAccount])
     
     $aclFolder = Get-Acl $global:logFilePath 
     
     If ($aclFolder -ne $null) 
      {
     
        $tempFileSystemRights= " "
        $tempInheritanceFlags= " "        

        foreach ($item in $aclFolder.Access)
         {
          if (($item.AccessControlType -eq "Allow") -and ($item.IdentityReference -eq $objUser.value))
           {
             $tempFileSystemRights= $tempFileSystemRights + $item.FileSystemRights
             $tempInheritanceFlags= $tempInheritanceFlags + $item.InheritanceFlags        
           }
         }

         If (($tempFileSystemRights.IndexOf("FullControl") -gt -1) -or (($tempFileSystemRights.IndexOf("Read") -gt -1) -and ($tempFileSystemRights.IndexOf("Write") -gt -1)))
              {
                if ($tempInheritanceFlags.IndexOf("ObjectInherit") -gt -1) {Return $True}
              }
       }    
      Return $False  
    }

   function Information([String] $AgentServiceName, [string] $global:logFilePath, [string] $AgentLogFileName) 
    {
        Write-Host ("")
        Write-Host ("This script can be used to activate / deactivate debug logging for the $AgentServiceName service.")
        Write-Host ("")
        Write-Host ("Use the switch -On to turn on the debug logging.")
        Write-Host ("Use the switch -Off to turn off the debug logging.")
        Write-Host ("Use the parameter -logFilePath to specify a directory other than the default. (example: -logFilePath C:\MSLOG\)")
        Write-Host ("Use the parameter -QueryConfig to see the current debug configuration.")
        Write-Host ("")
        Write-Host ("By default the log is stored: "+$global:logFilePath+$AgentLogFileName)
        Write-Host ("")
        Write-Host -ForegroundColor:Yellow ("Before you activate the debug logging with a non-default logFilePath, please ensure the following:")
        Write-Host ("")
        Write-Host ("The log folder does exists.")
        Write-Host ("The Network Service account has at least read & write permission in the folder.")
        Write-Host ("")
        Write-Host -ForegroundColor:Red ("Please note that the script with parameters -On/-Off restarts the $AgentServiceName service.")
        Write-Host ("")            
    }
     
    function RestartService ([string] $AgentServiceName)
    {
     Restart-Service -Name $AgentServiceName
    
     $connectorService = Get-Service -Name $AgentServiceName
    
     if($connectorService.Status -ne "Running")
      {
        Write-Host ("")
        Write-Host -ForegroundColor:Red "The $AgentServiceName Service did not start properly. Please restart the Service"
        Write-Host ("")
      }
        
     if($connectorService.Status -eq "Running")
      {
        Write-Host ("")
        Write-Host -ForegroundColor:Green "The operation has been completed successfully. The $AgentServiceName Service is running."
        Write-Host ("")
      }
    }


    Function ConfigureAgentLogging([bool] $On){
    Clear-Host
    $AgentConfigFile = "C:\Program Files\Microsoft AAD App Proxy Connector\ApplicationProxyConnectorService.exe.config"
    $AgentDefaultLogFolder = "Microsoft AAD Application Proxy Connector"
    $AgentServiceName = "Microsoft AAD Application Proxy Connector"
    $AgentLogFileName = "AzureADApplicationProxyConnectorTrace.log"

     $global:logFilePath=$Env:ALLUSERSPROFILE+"\Microsoft\"+$AgentDefaultLogFolder+"\"

       if ($On -eq $True) 
        {
          if (( VerifyACLonPath $global:logFilePath) -eq $True)    
             {
             AddDebugToConfig $AgentConfigFile $global:logFilePath $AgentLogFileName
             RestartService $AgentServiceName
             }
          else    
             {
               Write-Host ("")
               Write-Host -ForegroundColor:Red "The NETWORK SERVICE has no appropriate permissions on the log folder $global:logFilePath . Please fix it and try it again."
               Write-Host -ForegroundColor:White "Please note: The script checks only explicit rights assignement. Rights based on group membership are not checked."
               Write-Host ("")
               Information $AgentServiceName $global:logFilePath $AgentLogFileName
             }  
         }     
        else
         {
         RemoveDebugFromConfig $AgentConfigFile
         RestartService $AgentServiceName
         }
}

##New functions


Function EnableDebugEvents ($events)
{
	ForEach ($evt in $events)
	{
		$TraceLog = New-Object System.Diagnostics.Eventing.Reader.EventlogConfiguration $evt
		$TraceLog.IsEnabled = $false
		$TraceLog.SaveChanges()

		if ($TraceLog.LogName -like "*Session*")
		{       
			$TraceLog.IsEnabled = $true
			$TraceLog.SaveChanges()
		} 
		elseif($TraceLog.IsEnabled -eq $false) 
		{
			$tracelog.MaximumSizeInBytes = '40000000'
			$TraceLog.IsEnabled = $true
			$TraceLog.SaveChanges()
		} 
	}
}


Function StartWindowsInstallerLogging
{

       Push-Location $TraceDir

       Set-Location -Path "HKLM:\Software\Policies\Microsoft\Windows"

       if (-not(Test-Path -Path ".\Installer"))
       {
       
          New-Item "Installer"
       }
       
       
       If (Test-RegistryValue -Name "Logging" -Path "HKLM:\Software\Policies\Microsoft\Windows\Installer")
       {
       
        Remove-ItemProperty -Path .\Installer -Name "Logging" 
    
       }
       
       New-ItemProperty -Path .\Installer -Name "Logging" -Value "voicewarmupx"  -PropertyType "String"       

       Pop-Location     
 
       return $ReturnValue

}

Function StopWindowsInstallerLogging
{
   
     Push-Location $TraceDir

     Set-Location -Path "HKLM:\Software\Policies\Microsoft\Windows"
     Remove-Item -Path ".\Installer" -Recurse

     Set-Location -Path "HKLM:\Software\Policies\Microsoft\Windows"
        
     Pop-Location     
}

Function Test-RegistryValue {
    param(
        [Alias("PSPath")]
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [String]$Path
        ,
        [Parameter(Position = 1, Mandatory = $true)]
        [String]$Name
    ) 

    process {
        if (Test-Path $Path) {
            $Key = Get-Item -LiteralPath $Path
            if ($Key.GetValue($Name, $null) -ne $null) {
                    $true
            } else {
                $false
            }
        } else {
            $false
        }
    }
}



Function AppProxyTraceStart
{

       Push-Location $TraceDir
       Set-Location $AppProxyFileDir
       cmd /c $AppProxyTraceOn  
       Pop-Location

}

Function ServiceTraceStart
{

       if ($ServiceTraceOn -eq $True) 
         {
           Push-Location $TraceDir
           Set-Location $AppProxyFileDir
           #Powershell.exe -File ConfigureAgentLogging.ps1 -On
           ConfigureAgentLogging -On $True
           Pop-Location
         }
}

Function FlushKerberosCache
{
       Get-WmiObject Win32_LogonSession | Where-Object {$_.AuthenticationPackage -ne 'NTLM'} | ForEach-Object {klist.exe purge -li ([Convert]::ToString($_.LogonId, 16))} | Out-Null
}


Function LogManStart
{
	ForEach ($ets in $LogmanOn)
	{
		Push-Location $TraceDir
        cmd /c $ets
		Pop-Location
	} 

        Push-Location $TraceDir
        Get-Process | Format-Table Name, Id, Description, FileVersion, Company, CPU, HandleCount, NPM, PM, WS, VM, Path | Out-String -Width 4096 | Out-File $env:ComputerName"-Process-Details-Before.txt"
        Pop-Location
}

Function EnableNetlogonDebug
{
    $key = (get-item -PATH "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon")
    $subkey = $key.OpenSubKey("Parameters",$true)
    Write-host "Enabling Netlogon Debug Logging"

    $subkey.SetValue($setDBFlag,$setvalue,$setvaltype)

    Write-host "Increasing Netlogon Debug Size to 100 MB"
    $subkey.SetValue($setNLMaxLogSize,$setvalue2,$setvaltype2)

    #cleanup and close the write  handle
    $key.Close()
}
  
Function AllOtherLogs
{
	ForEach ($o in $others) 
	{
		Push-Location $TraceDir
		cmd.exe /c $o
		Pop-Location
	}
}


Function AppProxyTraceStop
{
  
       Push-Location $TraceDir
       Set-Location $AppProxyFileDir
       cmd /c $AppProxyTraceOff  
       Pop-Location
}


Function PerfmonStart
{
 Push-Location $TraceDir

 $CreateAADAPPerf = 'Logman.exe create counter AADAPPerf -o ".\%COMPUTERNAME%_AADAPPerf.blg" -f bincirc -max 512 -v mmddhhmm -c "\Microsoft AAD App Proxy Connector\*" "\LogicalDisk(*)\*" "\Memory\*" "\Process(*)\*" "\Processor(*)\*" "\TCPv4\*" "\Network Adapter\*" "\IPv4\*" -si 0:00:05'
 $StartAADAPPerf = 'Logman.exe start AADAPPerf'

 cmd.exe /c $CreateAADAPPerf
 cmd.exe /c $StartAADAPPerf
 

 Pop-Location
}

Function PerfmonStop
{
 Push-Location $TraceDir
 
 $DisableAADAPPerf = 'Logman.exe stop AADAPPerf'
 $DeleteAADAPPerf  = 'Logman.exe delete AADAPPerf'

 cmd.exe /c $DisableAADAPPerf
 cmd.exe /c $DeleteAADAPPerf
  
 Pop-Location
}

Function LogManStop
{
  
       Push-Location $TraceDir
       
       Get-Process | Format-Table Name, Id, Description, FileVersion, Company, CPU, HandleCount, NPM, PM, WS, VM, Path | Out-String -Width 4096 | Out-File $env:ComputerName"-Process-Details-After.txt"
       
       Set-Location $AppProxyFileDir
       cmd /c $AppProxyTraceOff  
       Pop-Location
 
    ForEach ($log in $LogmanOff) 
    {
		Push-Location $TraceDir
		cmd.exe /c $log
		Pop-Location
    }

}

Function ServiceTraceStop
{
           Push-Location $TraceDir
           Set-Location $AppProxyFileDir
           #Powershell.exe -File ConfigureAgentLogging.ps1 -Off
           ConfigureAgentLogging -On $false

           Pop-Location
}

Function DisableNetlogonDebug
{
    $key = (get-item -PATH "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon")
    $subkey = $key.OpenSubKey("Parameters",$true)

    # Configure Keys based on initial configuration; if the keys did not exist we are also removing the keys again. else we set the old value
    if ([string]::IsNullOrEmpty($orgdbflag))
	{ 
        $subkey.deleteValue($setDBFlag)
	}
    else 
	{
        $subkey.SetValue($setDBFlag,$orgdbflag,$setvaltype)
	}

    if ([string]::IsNullOrEmpty($orgNLMaxLogSize))
	{ 
        $subkey.deleteValue($setNLMaxLogSize)
	}
    else 
	{
        $subkey.SetValue($setNLMaxLogSize,$orgNLMaxLogSize,$setvaltype2) 
	}

    $key.Close()
}

Function NetshTraceFix
{

   $LogFix = 'netsh trace start capture=yes scenario=NetConnection capturetype=physical traceFile=.\%COMPUTERNAME%-HTTP-network.etl correlation=no report=disabled maxSize=1 fileMode=circular overwrite=yes >NUL 2>&1',`
   'netsh trace stop >NUL 2>&1'

   
   ForEach ($ets in $LogFix)
	  {
		Push-Location $TraceDir
		cmd /c $ets
		Pop-Location
	  }

}

Function DisableDebugEvents ($events)
{
    ForEach ($evt in $events)
    {
		$TraceLog = New-Object System.Diagnostics.Eventing.Reader.EventlogConfiguration $evt
		if ($TraceLog.IsEnabled -eq $true) 
        {
			$TraceLog.IsEnabled = $false
			$TraceLog.SaveChanges()
        } 
    }
}

Function ExportEventLogs ($events)
{
    ForEach ($evts in $events) 
    {
		Push-Location $TraceDir
		# Replace slashes in the event filename before building the export paths
		$evtx = [regex]::Replace($evts,"/","-")
		$evttarget = $TraceDir +"\"+ $env:ComputerName + "-" + $evtx+".evtx"
		$evttarget
		$EventSession = New-Object System.Diagnostics.Eventing.Reader.EventLogSession
		$EventSession.ExportLogAndMessages($evts,'Logname','*',$evttarget)
		Pop-Location
    }
}

Function GatherTheRest
{
    ForEach ($logfile in $Filescollector) 
    {
		Push-Location $TraceDir
		cmd.exe /c $logfile 
		Pop-Location
    }

        $SecEdit = "secedit /export /cfg " + $TraceDir + "\" + $env:ComputerName + "-" + "secpolicy.inf /log "+ $TraceDir + "\" + $env:ComputerName + "-" + "secpolicy.log"

		Push-Location $TraceDir
		cmd.exe /c $SecEdit 
		Pop-Location  
}

Function GetAADAPConfig

{
        Push-Location $TraceDir   
	
        Write-host "Exporting certs..."

	    dir Cert:\LocalMachine\My | format-list * | Out-file $env:ComputerName"-PS-Certs-LocalMachine-MY.txt"
	    dir Cert:\LocalMachine\CA | format-list * | Out-file $env:ComputerName"-PS-Certs-LocalMachine-Intermediate.txt"
	    dir Cert:\LocalMachine\ROOT | format-list * | Out-file $env:ComputerName"-PS-Certs-LocalMachine-Root.txt"

        # Export connector Computer Object Attributes
        
        Write-host "Retrieving Connector-server computer attributes from Active Directory..."

        if ($isdomainjoined -eq $True )
          {    
           
           ([adsisearcher]"(&(name=$env:computername)(objectClass=computer))").findall().Properties | fl | Out-file $env:ComputerName"-AD-Attributes.txt"
  
          }
         
        Write-host "Copying connector debug logs..."

        Copy-Item -Path $env:ProgramData"\Microsoft\Microsoft AAD Application Proxy Connector\" -Destination .\debug\ -Recurse -Filter *.*

        Write-host "Copying connector install logs..."

        Copy-Item -Path $env:Temp -Destination .\install\ -Filter Microsoft_Azure_Active_Directory_Application_Proxy_Connector*.*

        Pop-Location
}

Function GetAADAPConfig2
{

        Push-Location $TraceDir   

        Copy-Item  -Path $env:WinDir\debug\AppProxylog.bin -Destination $env:ComputerName-AppProxyLog.bin
        Copy-Item  -Path $env:ProgramFiles'\Microsoft AAD App Proxy Connector Updater\ApplicationProxyConnectorUpdaterService.exe.config' -Destination $env:ComputerName-ApplicationProxyConnectorUpdaterService.exe.config
        Copy-Item  -Path $env:ProgramFiles'\Microsoft AAD App Proxy Connector\ApplicationProxyConnectorService.exe.config' -Destination $env:ComputerName-ApplicationProxyConnectorService.exe.config

        
        $FileVersionCheck = $env:ProgramFiles + "\Microsoft AAD App Proxy Connector\ApplicationProxyConnectorService.exe"
        $FileVersionOut =   $env:ComputerName + "-ConnectorVersion.txt"
        [System.Diagnostics.FileVersionInfo]::GetVersionInfo($FileVersionCheck).FileVersion | Out-File -FilePath .\$FileVersionOut
 
        Pop-Location
}



Function EndOfCollection
{
    $date = get-date -Format yyyy-dd-MM_hh-mm
    $computername = (Get-Childitem env:computername).value
    $zip = $computername + "_AADAP_traces_"+$date
    $datafile = "$(Join-Path -Path $path -ChildPath $zip).zip"

    Write-host "Creating Archive File"
    Add-Type -Assembly "System.IO.Compression.FileSystem" ;
    [System.IO.Compression.ZipFile]::CreateFromDirectory($TraceDir, $datafile)

    Write-host "Archive File created in $datafile"

    # Cleanup the Temporary Folder (if error retain the temp files)
    if(Test-Path -Path $Path)
    {
		Write-host "Removing Temporary Files"
		Remove-Item -Path $TraceDir -Force -Recurse | Out-Null
    }
    else
    {
		Write-host "The Archive could not be created. Keeping Temporary Folder $TraceDir" -ForegroundColor Red
		New-Item -ItemType directory -Path $Path -Force | Out-Null
    }

    	Write-host "The data collection has been finished." -ForegroundColor Green

}

Function Eula
{
  Write-host ""
  Write-host ""
  Write-host "IMPORTANT - PLEASE READ IT - IMPORTANT" -ForegroundColor Red
  Write-host ""
  Write-host "The purpose of the Data Collector Script is to collect all the data that might be required to troubleshoot the issue you reported to" -ForegroundColor Green
  Write-host "the Microsoft Customer Support Services (CSS) on an efficient way. This Data Collector Script collects the following information:" -ForegroundColor Green
  Write-host ""

  Write-host "- Registry hives (SCHANNEL, WinHTTP, Azure AD Application Proxy connector and updater services)"
  Write-host "- Azure AD Application Proxy service trace"
  Write-host "- Network Capture, information about the network configuration like IPCONFIG /ALL etc."
  Write-host "- MSInfo32"
  Write-host "- Extended Traces (WinHttp, Schannel, DCLoc, Kerberos/Ntlm)"
  Write-host "- Eventlogs (System, Security, Application, Azure AD Application Proxy related logs, CAPI)"
  Write-host "- List of certificates in the certificate stores"
  Write-host "- Group policy results"
  Write-host "- Information about the patch level of the server"
  Write-host "- Adding the -Perfmon parameter starts log collection for specific performance counters"
  Write-host "- Adding the -ServiceTraceOn parameter, the service trace will be collected. This restarts the service!"
  Write-host ""
  Write-host "The collected data may contain Personally Identifiable Information (PII) and/or sensitive data, such as (but not limited to) IP addresses, Device names, and User names." -ForegroundColor Red
  Write-host ""
  Write-host "Once the tracing and data collection has completed, the script will create a compressed file called COMPUTERNAME__AADAP_traces__DATEANDTIME.zip." -ForegroundColor Green
  Write-host "This file is not automatically sent to Microsoft. You can send it to Microsoft CSS using a secure workspace. The link is provided by your Support Engineer." -ForegroundColor Green
  Write-host ""
  Write-host "If you have any concerns or would like to know more details about the data the script collects, please don't hesitate to contact us" -ForegroundColor Red
  Write-host "and don't start the data collection (or don't send the data to us)." -ForegroundColor Red
  Write-host ""
  Write-host "Microsoft Privacy Statement: https://privacy.microsoft.com/en-us/privacy" -ForegroundColor Green
}


#endregion

##########################################################################
#region Execution

#Checks if the user is in the administrator group. Warns and stops if the user is not.

if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
   {
     Write-Warning "You are not running this as local administrator. Run it again in an elevated prompt."
     Break
   }

if ($psISE -ne $null)
   {
     Write-Warning "You cannot run this script in Powershell ISE. Run it again in a 64-bit Powershell."
     Break
   }

if ([intptr]::Size -eq 4)
   {
     Write-Warning "You cannot run the script in Windows Powershell (x86). Run it again in a 64-bit Powershell."
     Break
   }

if($Path -NotLike '*:\*') {
       Write-Host "The path $Path seems to be incorrect. Please use an absolute path like C:\TempData ." -ForegroundColor Red
       Break;
}


if ($ServiceTraceOn -eq $True) 
{
        if ($IsServiceInstalled -eq $False)
         {
           Write-Host "Warning: The script has been started with the parameter ServiceTraceOn.`n The script terminates, because the Azure AD Application Proxy service is not installed on this computer..." -ForegroundColor Red
           Break;
         }             
        else
         {
           Write-Host "Warning: The script has been started with the parameter ServiceTraceOn.`n This will restart the Azure AD Application Proxy Service.`n Please press y or Y, in case we can continue..." -ForegroundColor Red
           $silencer = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

           If ($silencer.Character -ne "y" -and $silencer.Character -ne "Y")
           {
           Break;
	       }

          $fileToCheck = "$env:ProgramData\Microsoft\Microsoft AAD Application Proxy Connector\AzureADApplicationProxyConnectorTrace.log"

          if (Test-Path $fileToCheck -PathType leaf)
           {
            
             $extendedFileName = "AzureADApplicationProxyConnectorTrace.log" + (Get-Date).Year + (Get-Date).Month + (Get-Date).Day + (Get-Date).Hour + (Get-Date).Minute
             Rename-Item -Path $fileToCheck -NewName $extendedFileName

           }
           
          }
}


if(Test-Path -Path $Path)
{  
 Write-host "Your folder: $Path already exists. Starting Data Collection..."
}
else
{
Write-host "Your Logfolder: $Path does not exist. Creating Folder"


Try
  {
    New-Item -ItemType directory -Path $Path -Force -ErrorAction Stop | Out-Null
  }
Catch
  {
    Write-Warning "The directory could not be created. The script must be terminated."
    Break;
  }
}

$TraceDir = $Path +"\temporary"
# Save execution output to file
Start-Transcript -Path "$TraceDir\$env:ComputerName-output.txt" -Append -IncludeInvocationHeader 

Write-host "Script version: $ScriptVersion"

Write-host "Execution date and time: "
Get-Date


Write-host "The computer is domain joined: " $isdomainjoined
Write-host "The Azure AD Application Proxy Connector service is installed on the computer: " $IsServiceInstalled

if ($ServiceTraceOn -eq $True) 
{
 Write-host "Switch -ServiceTraceOn was set."
}
else
{
 Write-host "Switch -ServiceTraceOn was not set."
}

if ($Perfmon -eq $True) 
{
 Write-host "Switch -Perfmon was set."
}
else
{
 Write-host "Switch -Perfmon was not set."
}


$MyInvocation.MyCommand.Name

Write-host "Creating Temporary Folder in $path"


New-Item -ItemType directory -Path $TraceDir -Force | Out-Null


# start&stop a dummy NETSH trace first time to make sure network sniff works correct

NetshTraceFix

# 

Write-Host " Data Collection is ready to start`n Prepare other computers to start collecting data.`n When ready, press any key to start the collection..." -ForegroundColor Green
$silencer = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

Write-host "Repro start date and time: "
Get-Date

if ($isdomainjoined -eq $True)
  {    
   Write-host "The computer is domain joined."
  }  


Write-host "Configuring Event Logging"

EnableDebugEvents $ServicesDebugEvents

If ($IsServiceInstalled-eq $True) 
   {
     EnableDebugEvents $AADAPDebugEvents
   }

Write-host "Configuring Additional Debug Logging"
LogManStart

Write-host "Starting AppProxyTrace"

If ($IsServiceInstalled-eq $True) 
   {
     AppProxyTraceStart
   }

if ($ServiceTraceOn -eq $True) 
      {
        Write-host "Starting Service Trace"
        ServiceTraceStart
      }


if ($isdomainjoined -eq $True)
  {    
   Write-host "Flushing Kerberos cache"
   FlushKerberosCache

   Write-host "Configuring Netlogon Debug Logging"
   EnableNetlogonDebug
  }

Write-host "Collecting Early Data..."
AllOtherLogs

If ($IsServiceInstalled-eq $False) 
   {
     Write-host "Starting Windows Installer Logging"
     StartWindowsInstallerLogging
   }

if ($Perfmon -eq $True) 
      {

      if ($IsServiceInstalled -eq $True)
       {
         Write-host "Starting Performance data collection."
         PerfmonStart
       }
       else
       {
         Write-host "Service is not installed. Perfmon won't be started."
         $Perfmon = $False     
       }
   
      }  

Write-Host " Data Collection started`n Proceed reproducing the problem.`n Press any key to stop the collection..." -ForegroundColor Green
Write-Host " Furthermore the data collection will be stopped, when the script detects the file stop.txt in the directory $Path"  -ForegroundColor Green


$notpressed = $true
$startDateTime = Get-Date
$checkInterval = 20
$checkPath = $Path + "\stop.txt" 


While( $notpressed )
 {

     if([console]::KeyAvailable)
       {
         Write-host "Keypress detected, stopping the trace" -ForegroundColor Yellow
         $notpressed = $false    
       }    
      else
       {

         $CurrentDateTime = Get-Date

         if ($CurrentDateTime -gt $startDateTime.AddSeconds($checkInterval))
          {

            $startDateTime = $CurrentDateTime

            if (Test-Path -Path $checkPath)
             {
               Write-host "stop.txt detected, stopping the trace" -ForegroundColor Yellow
               $notpressed = $false
             }

          }
        }
 }

Write-host "Repro stop date and time: "
Get-Date

Write-host "Stopping Event Debug Logging"

if ($Perfmon -eq $True) 
      {
       Write-host "Stopping Performance data collection."
       PerfmonStop
      }  

DisableDebugEvents $ServicesDebugEvents

If ($IsServiceInstalled-eq $True) 
   {
     DisableDebugEvents $AADAPDebugEvents
   }

if ($isdomainjoined -eq $True)
  {    
   Write-host "Disabling Netlogon Debug Logging"
   DisableNetlogonDebug
  }

If ($IsServiceInstalled-eq $False) 
   {
     Write-host "Stopping Windows Installer Logging"
     StopWindowsInstallerLogging
   }

If ($IsServiceInstalled-eq $True) 
   {
     Write-host "Stopping AppProxyTrace"
     AppProxyTraceStop
   }

Write-host "Stopping Additional Debug Logging"
LogManStop

if ($ServiceTraceOn -eq $True) 
      {
       Write-host "Stopping Service Trace"
       ServiceTraceStop
      }  

Write-host "Exporting Event Logs"

ExportEventLogs $ServicesExportEvents

If ($IsServiceInstalled-eq $True) 
   {
     ExportEventLogs $AADAPExportEvents
   }

Write-host "Consolidating Logfiles"

Write-host "Collecting operating system logs" 

GatherTheRest

Write-host "Collecting Azure Ad Application Proxy related logs" 

GetAADAPConfig

If ($IsServiceInstalled-eq $True) 
   {
     Write-host "Collecting debug logs, traces" 
     GetAADAPConfig2
   }

Stop-Transcript

Write-host "Execution stop date and time: "
Get-Date

Write-host "Almost done. We are compressing all Files. This may take some minutes"
EndOfCollection
Eula

Start $Path

#endregion