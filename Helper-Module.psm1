Function Remove-IllegalCharactersFromString {
    param(
        [Parameter(Mandatory=$True)]
        [string]$String
    )

    $String = $String.Replace(" ","")
    $String = $String.Replace("-","")
    $String = $String.Replace("_","")
    $String = $String.Replace("*","")
    $String = $String.Replace("<","")
    $String = $String.Replace(">","")
    $String = $String.Replace("^","")
    $String = $String.Replace("'","")

    return $String
}

Function Get-AzureRmWebAppPublishingCredentials {
    param(
        [Parameter(Mandatory=$True)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory=$True)]
        [string]$WebAppName,

        [Parameter(Mandatory=$False)]
        [string]$SlotName = $null
    )

	If ([string]::IsNullOrWhiteSpace($SlotName)) {
		$resourceType = "Microsoft.Web/sites/config"
		$resourceName = "$WebAppName/publishingcredentials"
	}
	Else{
		$resourceType = "Microsoft.Web/sites/slots/config"
		$resourceName = "$WebAppName/$SlotName/publishingcredentials"
	}

	$publishingCredentials = Invoke-AzureRmResourceAction -ResourceGroupName $ResourceGroupName -ResourceType $resourceType -ResourceName $resourceName -Action list -ApiVersion 2015-08-01 -Force

    return $publishingCredentials
}

Function Get-KuduApiAuthorisationHeaderValue {
    param(
        [Parameter(Mandatory=$True)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory=$True)]
        [string]$WebAppName,

        [Parameter(Mandatory=$False)]
        [string]$SlotName = $null
    )

    $publishingCredentials = Get-AzureRmWebAppPublishingCredentials $ResourceGroupName $WebAppName $SlotName
    return ("Basic {0}" -f [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $publishingCredentials.Properties.PublishingUserName, $publishingCredentials.Properties.PublishingPassword))))
}

Function Remove-FilesFromWebApp {
    param(
        [Parameter(Mandatory=$True)]
        [string]$WebAppName,

        [Parameter(Mandatory=$True)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory=$False)]
        [string]$Timeout = "600"
    )

    $AuthorisationToken = Get-KuduApiAuthorisationHeaderValue -ResourceGroupName $ResourceGroupName -WebAppName $WebAppName

    $commandBody = @{
        command = "del /S /F /Q .\\"
        dir = "site\\wwwroot"
    }

    $apiUrl = "https://$ResourceGroupName.$($ConfigurationData.GlobalConfiguration.KuduAPI.URI)$($ConfigurationData.GlobalConfiguration.KuduAPI.Command)/"

    Invoke-RestMethod -Uri $apiUrl -Headers @{"Authorization"=$AuthorisationToken;"If-Match"="*"} -Method POST -ContentType "application/json" -Body (ConvertTo-Json $commandBody) -TimeoutSec $Timeout | Out-Null
}

Function Set-FileToWebApp {
    param(
        [Parameter(Mandatory=$True)]
        [string]$WebAppName,

        [Parameter(Mandatory=$True)]
        [string]$ResourceGroupName,

        [Parameter(Mandatory=$True)]
        [string]$FileName
    )

    $AuthorisationToken = Get-KuduApiAuthorisationHeaderValue -ResourceGroupName $ResourceGroupName -WebAppName $WebAppName

    $apiUrl = "https://$ResourceGroupName.$($ConfigurationData.GlobalConfiguration.KuduAPI.URI)$($ConfigurationData.GlobalConfiguration.KuduAPI.Zip)/"

    $Result = Invoke-RestMethod -Uri $apiUrl -Headers @{"Authorization"=$AuthorisationToken;"If-Match"="*"} -UserAgent "powershell/1.0" -Method PUT -InFile $FileName -ContentType "multipart/form-data"

    Return $Result
}

Function Get-ConfigurationDataAsObject
{
    [CmdletBinding()]
    [OutputType([hashtable])]
    Param (
        [Parameter(Mandatory)]
        [Microsoft.PowerShell.DesiredStateConfiguration.ArgumentToConfigurationDataTransformation()]
        [hashtable] $ConfigurationData
    )

    return $ConfigurationData
}

Function Get-RequiredModules
{
    param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullorEmpty()]
        $Modules
    )

    [bool]$hasErrors = $False

    ForEach ($Module in $Modules)
    {
        $cModule = Get-Module -ListAvailable -Name $Module.Name | Sort-Object -Descending | Select -First 1
        If (!$cModule) {
            Write-Warning "Module $($Module.Name) is not installed."
            Write-Warning "`tInstall-Module -Name $($Module.Name)"
            Try { Invoke-Logger -Message "Module $($Module.Name) is not installed" -Severity W -Category "PSModule" } Catch {}
            $hasErrors = $True
        } Else {
            If ($cModule.Version -lt $Module.MinimumVersion) {
                Write-Warning "Module $($Module.Name) must be updated."
                Write-Warning "`tInstall-Module -Name $($Module.Name) -AllowClobber -Force"
                Try { Invoke-Logger -Message "Module $($Module.Name) must be updated" -Severity W -Category "PSModule" } Catch {}
                $hasErrors = $True
            } Else {
                Write-Host "Module $($Module.Name) version $($cModule.Version) is valid."
                Try { Invoke-Logger -Message "Module $($Module.Name) version $($cModule.Version) is valid" -Severity I -Category "PSModule" } Catch {}
            }
        }
    }

    Return $hasErrors
}

Function Get-RecursiveHashTable {
    param
    (
        [Parameter(Mandatory=$true)]
        $Object,

        [Parameter(Mandatory=$True)]
        [ValidateNotNullorEmpty()]
        [String]$Category
    )
    $date = [datetime]::UtcNow
    ForEach ($prop in $Object.Keys)
    {
        If ($prop) {
            If (($($Object.$prop).GetType()).Name -eq "Hashtable") {
                Get-RecursiveHashTable -Object ($Object.$prop) -Category $Category
            }
            Else {
                If (($prop -eq "aad_ClientSecret") -or ($prop -eq "Password") -or ($prop -eq "StorageConnection") -or ($prop -eq "KeyValueStorageConnection") -or ($prop -eq "ConnectionString")) {
                    Write-Log -Message "[$(Get-Date $date -UFormat '%Y-%m-%dT%T%Z')] [INFO] [$($Category)] [$($prop): *****]"
                }
                Else {
                    Write-Log -Message "[$(Get-Date $date -UFormat '%Y-%m-%dT%T%Z')] [INFO] [$($Category)] [$($prop): $($Object.$prop)]"
                }
            }
        }
    }
}

Function Get-RecursivePSObject {
    param
    (
        [Parameter(Mandatory=$true)]
        $Object,

        [Parameter(Mandatory=$True)]
        [ValidateNotNullorEmpty()]
        [String]$Category
    )
    $date = [datetime]::UtcNow
    ForEach ($prop in $Message.PSObject.Properties)
    {
        If ($prop.Value) {
            If ($prop.Value.GetType() -is [PSObject])
            {
                Get-RecursivePSObject -Object ($prop.Value) -Category $Category
            }
            Else
            {
                If (($prop.Name -eq "aad_ClientSecret") -or ($prop.Name -eq "Password") -or ($prop.Name -eq "StorageConnection") -or ($prop.Name -eq "KeyValueStorageConnection") -or ($prop.Name -eq "ConnectionString")) {
                    Write-Log -Message "[$(Get-Date $date -UFormat '%Y-%m-%dT%T%Z')] [$($Severity)] [$($Category)] [$($prop.Name): *****]"
                }
                Else {
                    Write-Log -Message "[$(Get-Date $date -UFormat '%Y-%m-%dT%T%Z')] [$($Severity)] [$($Category)] [$($prop.Name): $($prop.Value)]"
                }
            }
        }
    $i++
    }
}

Function Invoke-Logger
{
    param(
        [String]$Severity,

        [Parameter(Mandatory=$True)]
        [ValidateNotNullorEmpty()]
        [String]$Category,

        $Message,

        $Error
    )

    Switch ($Severity) 
    { 
        "I"     { $Severity = "INFO" }
        "D"     { $Severity = "DEBUG" }
        "W"     { $Severity = "WARNING" }
        "E"     { $Severity = "ERROR"}
        default { $Severity = "INFO" }
    }

    $date = [datetime]::UtcNow

    If ($Error)
    {
        ForEach ($Line in $Message)
        {
            Write-Log -Message "[$(Get-Date $date -UFormat '%Y-%m-%dT%T%Z')] [$($Severity)] [$($Category)] [$($Line)]"
        }
        If ($Error.Exception.Message) { Write-Log -Message "[$(Get-Date $date -UFormat '%Y-%m-%dT%T%Z')] [$($Severity)] [$($Category)] [$($Error.Exception.Message)]" }
        If ($Error.Exception.Innerexception) { Write-Log -Message "[$(Get-Date $date -UFormat '%Y-%m-%dT%T%Z')] [$($Severity)] [$($Category)] [$($Error.Exception.Innerexception)]" }
        If ($Error.InvocationInfo.PositionMessage) {
            ForEach ($Line in $Error.InvocationInfo.PositionMessage.Split("`n"))
            {
                Write-Log -Message "[$(Get-Date $date -UFormat '%Y-%m-%dT%T%Z')] [$($Severity)] [$($Category)] [$($Line)]"
            }
        }
    }
    Else
    {
        If ($Message)
        {
            If (($Message.GetType()).Name -eq "Hashtable")
            {
                Get-RecursiveHashTable -Object $Message -Category $Category
            }
            ElseIf ($Message -is [PSObject])
            {
                Get-RecursivePSObject -Object $Message -Category $Category
            }
            Else
            {
                ForEach ($Line in $Message)
                {
                    If ($Line) {
                        Write-Log -Message "[$(Get-Date $date -UFormat '%Y-%m-%dT%T%Z')] [$($Severity)] [$($Category)] [$($Line)]"
                    }
                }
            }
        }
    }

}

Function Write-Log
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullorEmpty()]
        $Message
    )
    Out-File -FilePath $LogFile -InputObject $Message -Encoding utf8 -Append -NoClobber
}

Export-ModuleMember -Function "Get-*", "Set-*", "Remove-*", "Upload-*", "Invoke-*", "Write-*"