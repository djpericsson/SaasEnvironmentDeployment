#Remove undesired characters from string
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

#Create a hash from string
Function Get-TruncatedStringHash
{ 
    Param
    (
        [ValidateNotNullOrEmpty()]
        [String]
        $String,

        [ValidateNotNullOrEmpty()]
        [String]
        $HashName = "SHA512",

        [ValidateNotNullOrEmpty()]
        [int]
        $Length = 21
    )
    $StringBuilder = New-Object System.Text.StringBuilder 
    [System.Security.Cryptography.HashAlgorithm]::Create($HashName).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String))|%{ 
        [Void]$StringBuilder.Append($_.ToString("x2"))
    } 
    $StringBuilder.ToString().Substring(0,$Length)
}

#Get Web App publishing credentials
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

#Get KuduAPI authentication header
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

#Remove existing files from Web App
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

    $apiUrl = "https://$WebAppName.$($ConfigurationData.GlobalConfiguration.KuduAPI.URI)$($ConfigurationData.GlobalConfiguration.KuduAPI.Command)/"

    Invoke-RestMethod -Uri $apiUrl -Headers @{"Authorization"=$AuthorisationToken;"If-Match"="*"} -Method POST -ContentType "application/json" -Body (ConvertTo-Json $commandBody) -TimeoutSec $Timeout | Out-Null
}

#Set new files to Web App
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

    $apiUrl = "https://$WebAppName.$($ConfigurationData.GlobalConfiguration.KuduAPI.URI)$($ConfigurationData.GlobalConfiguration.KuduAPI.Zip)/"

    $Result = Invoke-RestMethod -Uri $apiUrl -Headers @{"Authorization"=$AuthorisationToken;"If-Match"="*"} -UserAgent "powershell/1.0" -Method PUT -InFile $FileName -ContentType "multipart/form-data"

    Return $Result
}

#Properly converted HashTable for import
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

#Verify PowerShell modules versions
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
            Write-Warning "`tInstall-Module -Name $($Module.Name) -RequiredVersion $($Module.RequiredVersion)"
            Try { Invoke-Logger -Message "Module $($Module.Name) is not installed" -Severity W -Category "PSModule" } Catch {}
            $hasErrors = $True
        } Else {
            If ($cModule.Version -lt $Module.RequiredVersion) {
                Write-Warning "Module $($Module.Name) version $($cModule.Version) must be updated."
                Write-Warning "`tInstall-Module -Name $($Module.Name) -RequiredVersion $($Module.RequiredVersion) -AllowClobber -Force"
                Try { Invoke-Logger -Message "Module $($Module.Name) must be updated" -Severity W -Category "PSModule" } Catch {}
                $hasErrors = $True
            } ElseIf ($cModule.Version -eq $Module.RequiredVersion) {
                Write-Host "Module $($Module.Name) version $($cModule.Version) is valid."
                Try { Invoke-Logger -Message "Module $($Module.Name) version $($cModule.Version) is valid" -Severity I -Category "PSModule" } Catch {}
            } Else {
                Write-Warning "Module $($Module.Name) version $($cModule.Version) must be downgraded."
                Write-Warning "`tInstall-Module -Name $($Module.Name) -RequiredVersion $($Module.RequiredVersion) -AllowClobber -Force"
                Try { Invoke-Logger -Message "Module $($Module.Name) must be updated" -Severity W -Category "PSModule" } Catch {}
                $hasErrors = $True
            }
        }
    }

    Return $hasErrors
}

function CreateAzureRunAsAccount
{     
    Param (
        [Parameter(Mandatory=$true)]
        [String] $ResourceGroup,

        [Parameter(Mandatory=$true)]
        [String] $AutomationAccountName,

        [Parameter(Mandatory=$true)]
        [String] $ApplicationDisplayName,

        [Parameter(Mandatory=$true)]
        [String] $SubscriptionId,

        [Parameter(Mandatory=$true)]
        [Boolean] $CreateClassicRunAsAccount,

        [Parameter(Mandatory=$true)]
        [String] $SelfSignedCertPlainPassword,

        [Parameter(Mandatory=$true)]
        [String]$CertificateAssetName,

        [Parameter(Mandatory=$false)]
        [String] $EnterpriseCertPathForRunAsAccount,

        [Parameter(Mandatory=$false)]
        [String] $EnterpriseCertPlainPasswordForRunAsAccount,

        [Parameter(Mandatory=$false)]
        [String] $EnterpriseCertPathForClassicRunAsAccount,

        [Parameter(Mandatory=$false)]
        [String] $EnterpriseCertPlainPasswordForClassicRunAsAccount,

        [Parameter(Mandatory=$false)]
        [ValidateSet("AzureCloud","AzureUSGovernment")]
        [string]$EnvironmentName="AzureCloud",

        [Parameter(Mandatory=$false)]
        [int] $SelfSignedCertNoOfMonthsUntilExpired = 12
    )

    function CreateSelfSignedCertificate([string] $keyVaultName, [string] $certificateName, [string] $selfSignedCertPlainPassword,
 							            [string] $certPath, [string] $certPathCer, [string] $selfSignedCertNoOfMonthsUntilExpired ) {

        $Cert = ""
        If (([environment]::OSVersion.Version).Major -eq "6") {
            $Cert = New-SelfSignedCertificate -DnsName $certificateName -CertStoreLocation cert:\LocalMachine\My
        }
        Else {
            $Cert = New-SelfSignedCertificate -DnsName $certificateName -CertStoreLocation cert:\LocalMachine\My `
 	            -KeyExportPolicy Exportable -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" `
 	            -NotAfter (Get-Date).AddMonths($selfSignedCertNoOfMonthsUntilExpired)
        }

        $CertPassword = ConvertTo-SecureString $selfSignedCertPlainPassword -AsPlainText -Force

        Export-PfxCertificate -Cert ("Cert:\localmachine\my\" + $Cert.Thumbprint) -FilePath $certPath -Password $CertPassword -Force | Write-Verbose
        Export-Certificate -Cert ("Cert:\localmachine\my\" + $Cert.Thumbprint) -FilePath $certPathCer -Type CERT | Write-Verbose
    }

    function CreateServicePrincipal([System.Security.Cryptography.X509Certificates.X509Certificate2] $PfxCert, [string] $applicationDisplayName) {  
        $CurrentDate = Get-Date
        $keyValue = [System.Convert]::ToBase64String($PfxCert.GetRawCertData())
        $KeyId = (New-Guid).Guid

        $azureRmModuleVersion = Get-Module -ListAvailable -Name AzureRm | Sort-Object -Descending | Select -First 1

        $KeyCredential = $null
        If ("$($azureRmModuleVersion.Version.Major).$($azureRmModuleVersion.Version.Minor).$($azureRmModuleVersion.Version.Build)" -le "4.2.0") {
            $KeyCredential = New-Object Microsoft.Azure.Commands.Resources.Models.ActiveDirectory.PSADPasswordCredential
        }
        Else {
            $KeyCredential = New-Object Microsoft.Azure.Graph.RBAC.Version1_6.ActiveDirectory.PSADKeyCredential
        }

        #$KeyCredential = New-Object Microsoft.Azure.Graph.RBAC.Version1_6.ActiveDirectory.PSADKeyCredential
        #$KeyCredential = New-Object Microsoft.Azure.Commands.Resources.Models.ActiveDirectory.PSADKeyCredential

        $KeyCredential.StartDate = $CurrentDate
        $KeyCredential.EndDate= [DateTime]$PfxCert.GetExpirationDateString()
        $KeyCredential.EndDate = $KeyCredential.EndDate.AddDays(-1)
        $KeyCredential.KeyId = $KeyId
        $KeyCredential.CertValue  = $keyValue

        # Use key credentials and create an Azure AD application
        $Application = New-AzureRmADApplication -DisplayName $ApplicationDisplayName -HomePage ("http://" + $applicationDisplayName) -IdentifierUris ("http://" + $KeyId) -KeyCredentials $KeyCredential

        If (-not(Get-AzureRmADServicePrincipal -SearchString $Application.ApplicationId -ErrorAction SilentlyContinue)) {
        $ServicePrincipal = New-AzureRMADServicePrincipal -ApplicationId $Application.ApplicationId
        Start-Sleep -Seconds 30
        }

        $GetServicePrincipal = Get-AzureRmADServicePrincipal -ObjectId $ServicePrincipal.Id

        # Sleep here for a few seconds to allow the service principal application to become active (ordinarily takes a few seconds)
        Sleep -s 15

        $NewRole = New-AzureRMRoleAssignment -RoleDefinitionName Contributor -ServicePrincipalName $Application.ApplicationId -ErrorAction SilentlyContinue

        $Retries = 0;
        While ($NewRole -eq $null -and $Retries -le 6)
        {
 	    Sleep -s 10
 	    New-AzureRMRoleAssignment -RoleDefinitionName Contributor -ServicePrincipalName $Application.ApplicationId | Write-Verbose -ErrorAction SilentlyContinue
 	    $NewRole = Get-AzureRMRoleAssignment -ServicePrincipalName $Application.ApplicationId -ErrorAction SilentlyContinue
 	    $Retries++;
        }

        return $Application.ApplicationId.ToString();
    }

    function CreateAutomationCertificateAsset ([string] $resourceGroup, [string] $automationAccountName, [string] $CertificateAssetName,[string] $certPath, [string] $certPlainPassword, [Boolean] $Exportable) {
        $CertPassword = ConvertTo-SecureString $certPlainPassword -AsPlainText -Force   
        Remove-AzureRmAutomationCertificate -ResourceGroupName $resourceGroup -AutomationAccountName $automationAccountName -Name $CertificateAssetName -ErrorAction SilentlyContinue
        New-AzureRmAutomationCertificate -ResourceGroupName $resourceGroup -AutomationAccountName $automationAccountName -Path $certPath -Name $CertificateAssetName -Password $CertPassword -Exportable:$Exportable  | write-verbose
    }

    function CreateAutomationConnectionAsset ([string] $resourceGroup, [string] $automationAccountName, [string] $connectionAssetName, [string] $connectionTypeName, [System.Collections.Hashtable] $connectionFieldValues ) {
        Remove-AzureRmAutomationConnection -ResourceGroupName $resourceGroup -AutomationAccountName $automationAccountName -Name $connectionAssetName -Force -ErrorAction SilentlyContinue
        New-AzureRmAutomationConnection -ResourceGroupName $ResourceGroup -AutomationAccountName $automationAccountName -Name $connectionAssetName -ConnectionTypeName $connectionTypeName -ConnectionFieldValues $connectionFieldValues
    }

    Import-Module AzureRM.Profile
    Import-Module AzureRM.Resources

    $AzureRMProfileVersion= (Get-Module AzureRM.Profile).Version
    if (!(($AzureRMProfileVersion.Major -ge 3 -and $AzureRMProfileVersion.Minor -ge 0) -or ($AzureRMProfileVersion.Major -gt 3))) {
    Write-Error -Message "Please install the latest Azure PowerShell and retry. Relevant doc url : https://docs.microsoft.com/powershell/azureps-cmdlets-docs/ "
    return
    }

    #Login-AzureRmAccount -Environment $EnvironmentName 
    $Subscription = Select-AzureRmSubscription -SubscriptionId $SubscriptionId

    $ConnectionAssetName  = "$($CertificateAssetName)Connection"
    $ConnectionTypeName   = "AzureServicePrincipal"
    $CertificateAssetName = "$($CertificateAssetName)Certificate"

    # Create a Run As account by using a service principal
    #$CertificateAssetName = "AzureRunAsCertificate"
    #$ConnectionAssetName = "AzureRunAsConnection"
    #$ConnectionTypeName = "AzureServicePrincipal"

    if ($EnterpriseCertPathForRunAsAccount -and $EnterpriseCertPlainPasswordForRunAsAccount) {
        $PfxCertPathForRunAsAccount = $EnterpriseCertPathForRunAsAccount
        $PfxCertPlainPasswordForRunAsAccount = $EnterpriseCertPlainPasswordForRunAsAccount
    }
    else {
        $CertificateName = $AutomationAccountName+$CertificateAssetName
        $PfxCertPathForRunAsAccount = Join-Path $env:TEMP ($CertificateName + ".pfx")
        $PfxCertPlainPasswordForRunAsAccount = $SelfSignedCertPlainPassword
        $CerCertPathForRunAsAccount = Join-Path $env:TEMP ($CertificateName + ".cer")

        CreateSelfSignedCertificate $KeyVaultName $CertificateName $PfxCertPlainPasswordForRunAsAccount $PfxCertPathForRunAsAccount $CerCertPathForRunAsAccount $SelfSignedCertNoOfMonthsUntilExpired
    }

    # Create a service principal
    $PfxCert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($PfxCertPathForRunAsAccount, $PfxCertPlainPasswordForRunAsAccount)
    $ApplicationId=CreateServicePrincipal $PfxCert $ApplicationDisplayName

    # Create the Automation certificate asset
    CreateAutomationCertificateAsset $ResourceGroup $AutomationAccountName $CertificateAssetName $PfxCertPathForRunAsAccount $PfxCertPlainPasswordForRunAsAccount $true

    # Populate the ConnectionFieldValues
    $SubscriptionInfo = Get-AzureRmSubscription -SubscriptionId $SubscriptionId
    $TenantID = $SubscriptionInfo | Select TenantId -First 1
    $Thumbprint = $PfxCert.Thumbprint
    $ConnectionFieldValues = @{"ApplicationId" = $ApplicationId; "TenantId" = $TenantID.TenantId; "CertificateThumbprint" = $Thumbprint; "SubscriptionId" = $SubscriptionId}

    # Create an Automation connection asset named AzureRunAsConnection in the Automation account. This connection uses the service principal.
    CreateAutomationConnectionAsset $ResourceGroup $AutomationAccountName $ConnectionAssetName $ConnectionTypeName $ConnectionFieldValues

    if ($CreateClassicRunAsAccount) {
        # Create a Run As account by using a service principal
        $ClassicRunAsAccountCertifcateAssetName = "AzureClassicRunAsCertificate"
        $ClassicRunAsAccountConnectionAssetName = "AzureClassicRunAsConnection"
        $ClassicRunAsAccountConnectionTypeName = "AzureClassicCertificate "
        $UploadMessage = "Please upload the .cer format of #CERT# to the Management store by following the steps below." + [Environment]::NewLine +
 		        "Log in to the Microsoft Azure Management portal (https://manage.windowsazure.com) and select Settings -> Management Certificates." + [Environment]::NewLine +
 		        "Then click Upload and upload the .cer format of #CERT#"

        if ($EnterpriseCertPathForClassicRunAsAccount -and $EnterpriseCertPlainPasswordForClassicRunAsAccount ) {
            $PfxCertPathForClassicRunAsAccount = $EnterpriseCertPathForClassicRunAsAccount
            $PfxCertPlainPasswordForClassicRunAsAccount = $EnterpriseCertPlainPasswordForClassicRunAsAccount
            $UploadMessage = $UploadMessage.Replace("#CERT#", $PfxCertPathForClassicRunAsAccount)
            }
        else {
 	        $ClassicRunAsAccountCertificateName = $AutomationAccountName+$ClassicRunAsAccountCertifcateAssetName
 	        $PfxCertPathForClassicRunAsAccount = Join-Path $env:TEMP ($ClassicRunAsAccountCertificateName + ".pfx")
 	        $PfxCertPlainPasswordForClassicRunAsAccount = $SelfSignedCertPlainPassword
 	        $CerCertPathForClassicRunAsAccount = Join-Path $env:TEMP ($ClassicRunAsAccountCertificateName + ".cer")
 	        $UploadMessage = $UploadMessage.Replace("#CERT#", $CerCertPathForClassicRunAsAccount)

 	        CreateSelfSignedCertificate $KeyVaultName $ClassicRunAsAccountCertificateName $PfxCertPlainPasswordForClassicRunAsAccount $PfxCertPathForClassicRunAsAccount $CerCertPathForClassicRunAsAccount $SelfSignedCertNoOfMonthsUntilExpired
        }

        # Create the Automation certificate asset
        CreateAutomationCertificateAsset $ResourceGroup $AutomationAccountName $ClassicRunAsAccountCertifcateAssetName $PfxCertPathForClassicRunAsAccount $PfxCertPlainPasswordForClassicRunAsAccount $false

        # Populate the ConnectionFieldValues
        $SubscriptionName = $subscription.Subscription.Name
        $ClassicRunAsAccountConnectionFieldValues = @{"SubscriptionName" = $SubscriptionName; "SubscriptionId" = $SubscriptionId; "CertificateAssetName" = $ClassicRunAsAccountCertifcateAssetName}

        # Create an Automation connection asset named AzureRunAsConnection in the Automation account. This connection uses the service principal.
        CreateAutomationConnectionAsset $ResourceGroup $AutomationAccountName $ClassicRunAsAccountConnectionAssetName $ClassicRunAsAccountConnectionTypeName $ClassicRunAsAccountConnectionFieldValues

        Write-Host -ForegroundColor red $UploadMessage
    }

    Remove-Item Cert:\LocalMachine\My\$Thumbprint -Force -ErrorAction SilentlyContinue
}

#Get recursive properties from HashTable
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
                If (($prop -eq "aad_ClientSecret") -or ($prop -eq "Password") -or ($prop -eq "StorageConnection") -or ($prop -eq "KeyValueStorageConnection") -or ($prop -eq "ConnectionString") -or ($prop -eq "StorageAccountKey")) {
                    Write-Log -Message "[$(Get-Date $date -UFormat '%Y-%m-%dT%T%Z')] [INFO] [$($Category)] [$($prop): *****]"
                }
                Else {
                    if ($($Object.$prop).Value -match "`n")
                    {
                        $values = $($Object.$prop).Value.Split("`n")
                        foreach ($value in $values) {
                            if (![string]::IsNullOrWhitespace($value)) { Write-Log -Message "[$(Get-Date $date -UFormat '%Y-%m-%dT%T%Z')] [$($Severity)] [$($Category)] [$($prop): $($value)]" }
                        }
                    } else {
                        Write-Log -Message "[$(Get-Date $date -UFormat '%Y-%m-%dT%T%Z')] [INFO] [$($Category)] [$($prop): $($Object.$prop)]"
                    }  
                }
            }
        }
    }
}

#Get recursive properties from PSObject
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
                If (($prop.Name -eq "aad_ClientSecret") -or ($prop.Name -eq "Password") -or ($prop.Name -eq "StorageConnection") -or ($prop.Name -eq "KeyValueStorageConnection") -or ($prop.Name -eq "ConnectionString") -or ($prop.Name -eq "StorageAccountKey")) {
                    Write-Log -Message "[$(Get-Date $date -UFormat '%Y-%m-%dT%T%Z')] [$($Severity)] [$($Category)] [$($prop.Name): *****]"
                }
                Else {
                    if ($prop.Value -match "`n")
                    {
                        $values = $prop.Value.Split("`n")
                        foreach ($value in $values) {
                            if (![string]::IsNullOrWhitespace($value)) { Write-Log -Message "[$(Get-Date $date -UFormat '%Y-%m-%dT%T%Z')] [$($Severity)] [$($Category)] [$($prop.Name): $($value)]" }
                        }
                    } else {
                        Write-Log -Message "[$(Get-Date $date -UFormat '%Y-%m-%dT%T%Z')] [$($Severity)] [$($Category)] [$($prop.Name): $($prop.Value)]"
                    }
                }
            }
        }
    $i++
    }
}

#Invoke logger function
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
                        If (($Line.GetType()).Name -eq "ErrorRecord") {
                            [string]$nLine = $Line
                            if ($nLine -match "`n")
                            {
                                $values = $nLine.Split("`n")
                                foreach ($value in $values) {
                                    if (![string]::IsNullOrWhitespace($value)) { Write-Log -Message "[$(Get-Date $date -UFormat '%Y-%m-%dT%T%Z')] [$($Severity)] [$($Category)] [$($value)]" }
                                }
                            } else {
                                Write-Log -Message "[$(Get-Date $date -UFormat '%Y-%m-%dT%T%Z')] [$($Severity)] [$($Category)] [$($nLine)]"
                            } 
                        } else {
                            Write-Log -Message "[$(Get-Date $date -UFormat '%Y-%m-%dT%T%Z')] [$($Severity)] [$($Category)] [$($Line)]"
                        }
                    }
                }
            }
        }
    }

}

#Write stream to disk
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

#Export functions
Export-ModuleMember -Function "Get-*", "Set-*", "Remove-*", "Upload-*", "Invoke-*", "Write-*", "CreateAzureRunAsAccount"