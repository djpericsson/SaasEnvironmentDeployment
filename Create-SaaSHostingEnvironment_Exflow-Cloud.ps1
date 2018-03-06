Clear-Host

#$psISE.CurrentFile.Editor.ToggleOutliningExpansion()

#Start measuring time to complete script
$Measure = [System.Diagnostics.Stopwatch]::StartNew()

[string]$Header = "--------------------------------------------------------------------------------"

#region Import script parameters and variables from a configuration data file
Write-Output "$Header`nGet-ConfigurationDataAsObject`n$Header"

Import-Module "$PSScriptRoot\Helper-Module.psm1" -Force

#Get configuration data
[hashtable]$ConfigurationData = Get-ConfigurationDataAsObject -ConfigurationData "$PSScriptRoot\ConfigurationData_Exflow-Cloud.psd1"

[String]$LogFile = "$($ConfigurationData.GlobalConfiguration.LocalPath)\$($ConfigurationData.GlobalConfiguration.LogFile)"
#Remove-Item -Path $LogFile -Force -Confirm:$False

Write-Output "Helper-Module: $PSScriptRoot\Helper-Module.ps1"
Write-Output "ConfigurationData: $PSScriptRoot\ConfigurationData.psd1"
Write-Host ""
Write-Host "LogFile: $LogFile" -ForegroundColor Green
Write-Host ""

Invoke-Logger -Message "Helper-Module: $PSScriptRoot/Helper-Module.ps1" -Severity I -Category "Helper-Module"
Invoke-Logger -Message "ConfigurationData.psd1: $PSScriptRoot/ConfigurationData.psd1" -Severity I -Category "ConfigurationData"

Invoke-Logger -Message $ConfigurationData -Severity I -Category "ConfigurationData"
#endregion

#[void](Read-Host 'Press Enter to continue…')

#region Checking PowerShell version and modules
Write-Output "$Header`nChecking PowerShell version and modules`n$Header"

#Call function to verify installed modules and versions against configuration data file
$hasErrors = Get-RequiredModules -Modules $ConfigurationData.GlobalConfiguration.Prerequisites.Modules

#Verify installed PowerShell version against the configuration data file
if ($PSVersionTable.PSVersion -lt $ConfigurationData.PowerShell.Version) {
    $Message = "PowerShell must be updated to at least $($ConfigurationData.GlobalConfiguration.Prerequisites.PowerShell.Version)."
    Write-Warning $Message
    Invoke-Logger -Message $Message -Severity W -Category "PowerShell"
    $hasErrors = $True
}
else {
    $Message = "PowerShell version $($PSVersionTable.PSVersion) is valid."
    Write-Host $Message
    Invoke-Logger -Message $Message -Severity I -Category "PowerShell"
    Write-Host ""
}

if ($hasErrors) {
    break
}
#endregion

#region Login in to AzureRm
[bool]$BoolAzureRmLogon = $True

try { $azureRmContext = Get-AzureRmContext -ErrorAction Stop  }
catch [System.Management.Automation.PSInvalidOperationException] {
    $BoolAzureRmLogon = $False
}
if ($null -eq $azureRmContext) {
    $BoolAzureRmLogon = $False
}
elseif ($null -eq $azureRmContext.Account) {
    $BoolAzureRmLogon = $False
}

if (!$BoolAzureRmLogon) {
    Write-Output "$Header`nLogin-AzureRmAccount`n$Header"

    Invoke-Logger -Message "Login-AzureRmAccount -SubscriptionId $($ConfigurationData.GlobalConfiguration.SubscriptionId)" -Severity I -Category "AzureRmAccount"

    try {
        Login-AzureRmAccount -SubscriptionId $ConfigurationData.GlobalConfiguration.SubscriptionId -ErrorAction Stop

        Write-Output ""

        $azureRmContext = Get-AzureRmContext

        Invoke-Logger -Message $azureRmContext -Severity I -Category "AzureRmAccount"

        Write-Output $azureRmContext
    }
    catch {
        Invoke-Logger -Message $_ -Severity E -Category "AzureRmAccount"

        Write-Error $_
    }
}

if ($azureRmContext.Subscription.Id -eq $null) { break }
#endregion

#Set tenant variables based on logged on session
if ($azureRmContext.Account.Id) {
    $SignInName = $azureRmContext.Account.Id
    $Subscription = "/subscriptions/$($azureRmContext.Subscription.Id)"
}
else {
    $SignInName = $azureRmContext.Context.Account.Id
    $Subscription = "/subscriptions/$($azureRmContext.Context.Subscription.Id)"
}

#region Verify AzureRmRoleAssignment to logged on user
if ($ConfigurationData.GlobalConfiguration.Prerequisites.AzureRmRoleAssignmentValidation) {
    Write-Output "$Header`nValidating AzureRmRoleAssignment`n$Header"

    Invoke-Logger -Message "Get-AzureRmRoleAssignment -Scope '/subscriptions/$($azureRmContext.Subscription.Id)' | Where-Object { (`$_.SignInName -eq $SignInName) -or (`$_.SignInName -like '$(($SignInName).Replace('@','_'))*')" -Severity I -Category "AzureRmRoleAssignment"

    $RoleAssignment = Get-AzureRmRoleAssignment -Scope "/subscriptions/$($azureRmContext.Subscription.Id)" | Where-Object { ($_.SignInName -eq $SignInName) -or ($_.SignInName -like "$(($SignInName).Replace("@","_"))*") }

    #Get AzureRmRoleAssignment for currently logged on user
    $AzureRmRoleAssignment = ($RoleAssignment).RoleDefinitionName

    $AzureRmRoleAssignment

    Invoke-Logger -Message $AzureRmRoleAssignment -Severity I -Category "AzureRmRoleAssignment"

    Write-Output ""

    #Determine that the currently logged on user has appropriate permissions to run the script in their Azure subscription
    if (-not ($AzureRmRoleAssignment -contains "Owner") -and -not ($AzureRmRoleAssignment -contains "Contributor")) {
        Write-Host ""
        Write-Warning "Owner or contributor permissions could not be verified for your subscription."
        Write-Host ""

        try { Invoke-Logger -Message "Owner or contributor permissions could not be verified for your subscription" -Severity W -Category "AzureRmRoleAssignment" } catch {}

        return
    }
}
#endregion

#region Create SaaS Resource Group
Write-Output "$Header`nAzureRmResourceGroup: $($ConfigurationData.SaaSService.ResourceGroup)`n$Header"
Write-Output ""

if (-not($SaaSAzureRmResourceGroup = $AzureRmResourceGroup = Get-cAzureRmResource -Type AzureRmResourceGroup -Name $ConfigurationData.SaaSService.ResourceGroup -ErrorAction SilentlyContinue)) {

    $params = @{
        Name     = $ConfigurationData.SaaSService.ResourceGroup
        Location = $ConfigurationData.SaaSService.Location
        Tag      = $configurationData.SaaSService.Tags
    }

    $SaaSAzureRmResourceGroup = New-cAzureRmResource -Type AzureRmResourceGroup -Parameters $params
}
if ($SaaSAzureRmResourceGroup) { Write-Output $SaaSAzureRmResourceGroup } else { break }
#endregion

#region Create Azure Key Vault
if ($ConfigurationData.SaaSService.KeyVault) {

    $params = @{
        VaultName = $ConfigurationData.SaaSService.KeyVault.Name.Replace("[ResourceGroup]", $ConfigurationData.SaaSService.ResourceGroup)
    }

    if (($SaaSAzureRmResourceGroup) -and -not($AzureRmKeyVault = Get-cAzureRmResource -Type AzureRMKeyVault -Parameters $params -ErrorAction SilentlyContinue)) {
        Write-Output "$Header`nNew-AzureRmKeyVault`n$Header"

        $params = @{
            VaultName         = $AzureRmKeyVaultName
            ResourceGroupName = $ConfigurationData.SaaSService.ResourceGroup
            Location          = $ConfigurationData.SaaSService.Location
            Sku               = $ConfigurationData.SaaSService.KeyVault.SKU
            Tags              = $ConfigurationData.SaaSService.Tags
        }

        $AzureRmKeyVault = New-cAzureRmResource -Type AzureRmKeyVault -Parameters $params

        Write-Output $AzureRmKeyVault
    }
    if ($AzureRmKeyVault) { Write-Output $AzureRmKeyVault } else { break }
}
#endregion

#region Create Azure Key Vault Secret
if ($ConfigurationData.SaaSService.KeyVault.Secrets) {
    foreach ($Type in $ConfigurationData.SaaSService.KeyVault.Secrets.Keys) {

        $params = @{
            VaultName = $AzureRmKeyVaultName
            Name      = $Type
        }

        if (-not($AzureKeyVaultSecret = (Get-cAzureRmResource -Type AzureKeyVaultSecret -Parameters $params -ErrorAction SilentlyContinue).SecretValueText)) {
            Write-Output "Set-AzureKeyVaultSecret`n$Header"

            #Define Secret properties
            $Secret = @{}
            foreach ($variable in $ConfigurationData.SaaSService.KeyVault.Secrets.$Type.Keys) {
                $value = $ConfigurationData.SaaSService.KeyVault.Secrets.$Type.$variable
                New-Variable -Name $variable -Value "`$ConfigurationData.$value" -Force
                $value = $value.Replace("[ResourceGroup]", $ConfigurationData.SaaSService.ResourceGroup)
                $value = $value.Replace("[Key]", $Keys[0].Value)
                $Secret.add($variable, $value)
            }

            $params = @{
                Name        = $Type
                SecretValue = (ConvertTo-SecureString $(ConvertTo-Json $Secret) -AsPlainText -Force)
                ContentType = $Type
                VaultName   = $AzureRmKeyVaultName
            }

            $AzureKeyVaultSecret = Set-cAzureRmResource -Type AzureKeyVaultSecret -Parameters $params -ErrorAction Stop
        }
        if ($AzureKeyVaultSecret) { Write-Output $AzureKeyVaultSecret } else { break }
    }
}
#endregion

#region Create Automation account if it doesnt exist
$params = @{
    ResourceGroupName = $ConfigurationData.SaaSService.ResourceGroup
    Name              = $ConfigurationData.SaaSService.ResourceGroup
}

if ($SaaSAzureRmResourceGroup -and -not($AzureRmAutomationAccount = Get-cAzureRmResource -Type AzureRmAutomationAccount -Parameters $params -ErrorAction SilentlyContinue)) {
    Write-Output ""
    Write-Output "$Header`nCreating AzureRmAutomationAccount`n$Header"

    $params = @{
        ResourceGroupName = $ConfigurationData.SaaSService.ResourceGroup
        Name              = $ConfigurationData.SaaSService.ResourceGroup
        Location          = $ConfigurationData.SaaSService.Location
        Tags              = $configurationData.Tags
    }

    $AzureRmAutomationAccount = New-cAzureRmResource -Type AzureRmAutomationAccount -Parameters $params -ErrorAction Stop
}
if ($AzureRmAutomationAccount) { Write-Output $AzureRmAutomationAccount } else { break }
#endregion

#region Create Azure Automation Certificate
foreach ($AutomationCertificate in $ConfigurationData.SaaSService.AzureRmAutomationCertificate) {
    $params = @{
        AutomationAccountName = $ConfigurationData.SaaSService.ResourceGroup
        ResourceGroupName     = $ConfigurationData.SaaSService.ResourceGroup
        Name                  = "$($AutomationCertificate.CertificateAssetName)Certificate"
    }

    if ($AzureRmAutomationAccount -and -not ($null = Get-cAzureRmResource -Type AzureRmAutomationCertificate -Parameters $params -ErrorAction SilentlyContinue)) {
        Write-Output ""
        Write-Output "$Header`nCreating AzureRmAutomationCertificate`n$Header"

        $params = @{
            ResourceGroup               = $($ConfigurationData.SaaSService.ResourceGroup)
            AutomationAccountName       = $($ConfigurationData.SaaSService.ResourceGroup)
            SubscriptionId              = $azureRmContext.Subscription.Id
            ApplicationDisplayName      = "$($ConfigurationData.SaaSService.ResourceGroup)-$($AutomationCertificate.CertificateAssetName)"
            SelfSignedCertPlainPassword = $( -join ([char[]](65..90 + 97..122) * 100 | Get-Random -Count 19) + "!")
            CreateClassicRunAsAccount   = $false
            CertificateAssetName        = $AutomationCertificate.CertificateAssetName
        }

        try {
            Invoke-Logger -Message "CreateAzureRunAsAccount -$($params.Keys.foreach({"$_ '$($params.$_)'"}) -join ' -')" -Severity I -Category "AzureRmAutomationCertificate"
            $CreateAzureRunAsAccount = CreateAzureRunAsAccount @params -ErrorAction Stop
            Invoke-Logger -Message $CreateAzureRunAsAccount -Severity I -Category "AzureRmAutomationCertificate"
            Write-Output $CreateAzureRunAsAccount
        }
        catch {
            Invoke-Logger -Message $_ -Severity E -Category "AzureRmAutomationCertificate"
            Write-Error $_
        }
    }
}
#endregion

#region Create an Azure Automation Account
foreach ($AutomationAccount in $ConfigurationData.SaaSService.AzureRmAutomationAccount) {
    $params = @{
        AutomationAccountName = $ConfigurationData.SaaSService.ResourceGroup
        ResourceGroupName     = $ConfigurationData.SaaSService.ResourceGroup
        Name                  = $AutomationAccount.Name
    }

    if ($AzureRmAutomationAccount -and -not ($AzureRmAutomationCredential = Get-cAzureRmResource -Type AzureRmAutomationCredential -Parameters $params -ErrorAction SilentlyContinue)) {
        Write-Output "$Header`nAdding AzureRmAutomationCredential`n$Header"

        $pw = ConvertTo-SecureString $( -join ([char[]](65..90 + 97..122) * 100 | Get-Random -Count 19) + "!") -AsPlainText -Force

        try {
            Invoke-Logger -Message "New-Object –TypeName System.Management.Automation.PSCredential –ArgumentList $($AutomationAccount.Name)" -Severity I -Category "AzureRmAutomationCredential"
            $AzureRmAutomationCredential = New-Object –TypeName System.Management.Automation.PSCredential –ArgumentList $AutomationAccount.Name, $pw

            $params = @{
                AutomationAccountName = $ConfigurationData.SaaSService.ResourceGroup
                ResourceGroupName     = $ConfigurationData.SaaSService.ResourceGroup
                Name                  = $AutomationAccount.Name
                Description           = $AutomationAccount.Description
                Value                 = $AzureRmAutomationCredential
            }

            $nAzureRmAutomationCredential = New-cAzureRmResource -Type AzureRmAutomationCredential -Parameters $params -ErrorAction Stop
            Write-Output $nAzureRmAutomationCredential
        }
        catch {
            Invoke-Logger -Message $_ -Severity E -Category "AzureRmAutomationCredential"
            Write-Error $_
        }
    }
}
#endregion

#region Register Microsoft.Network for Azure DNS Services
$params = @{
    ProviderNamespace = "Microsoft.Network"
}

if (-not($AzureRmResourceProvider = Get-cAzureRmResource -Type AzureRmResourceProvider -Parameters $params -Log $false -ErrorAction SilentlyContinue)) {
    Write-Output "$Header`nRegister-AzureRmResourceProvider`n$Header"

    Invoke-Logger -Message "Register-AzureRmResourceProvider -ProviderNamespace Microsoft.Network" -Severity I -Category "AzureRmResourceProvider"

    try {
        $AzureRmResourceProvider = Register-AzureRmResourceProvider -ProviderNamespace Microsoft.Network -ErrorAction Stop

        Write-Output ""
    }
    catch {
        Invoke-Logger -Message $_ -Severity E -Category "AzureRmResourceProvider"

        Write-Error $_
    }
}
if (!$AzureRmResourceProvider) { break }
#endregion

#region Create DNS Zone
$AzureRmDnsZoneName = $ConfigurationData.GlobalConfiguration.TenantDomain

$params = @{
    Name              = $AzureRmDnsZoneName
    ResourceGroupName = $ConfigurationData.SaaSService.ResourceGroup
}

if (-not($AzureRmDnsZone = Get-cAzureRmResource -Type AzureRmDnsZone -Parameters $params -ErrorAction SilentlyContinue)) {
    Write-Output "$Header`nNew-AzureRmDnsZone`n$Header"

    $params = @{
        Name              = $AzureRmDnsZoneName
        ResourceGroupName = $ConfigurationData.SaaSService.ResourceGroup
        Tag               = $ConfigurationData.SaaSService.Tags
    }

    $AzureRmDnsZone = New-cAzureRmResource -Type AzureRmDnsZone -Parameters $params -ErrorAction Stop
}
if ($AzureRmDnsZone) { Write-Output $AzureRmDnsZone } else { break }
#endregion

#region Create Resource Group
foreach ($ResourceGroup in $ConfigurationData.ResourceGroups.Keys) {

    #Verify AzureRmResourceGroup
    Write-Output "$Header`nAzureRmResourceGroup: $($ResourceGroup)`n$Header"
    Write-Output ""

    if (-not($AzureRmResourceGroup = Get-cAzureRmResource -Type AzureRmResourceGroup -Name $ResourceGroup -ErrorAction SilentlyContinue)) {
        Write-Output "New-AzureRmResourceGroup`n$Header"

        $params = @{
            Name     = $ResourceGroup
            Location = $ConfigurationData.ResourceGroups.$ResourceGroup.Location
            Tag      = $ConfigurationData.ResourceGroups.$ResourceGroup.Tags
        }

        $AzureRmResourceGroup = New-cAzureRmResource -Type AzureRmResourceGroup -Parameters $params -ErrorAction Stop
    }
    if ($AzureRmResourceGroup) { Write-Output $AzureRmResourceGroup } else { break }

    #Verify AzureRmStorageAccount
    if ($ConfigurationData.ResourceGroups.$ResourceGroup.Storage) {
        $AzureRmStorageAccountName = Remove-IllegalCharactersFromString -String ($ResourceGroup.Storage.Name.Replace("[ResourceGroup]", $ResourceGroup)).ToLower()

        $params = @{
            Name              = $AzureRmStorageAccountName
            ResourceGroupName = $ResourceGroup
        }      

        if ($AzureRmResourceGroup -and -not ($AzureRmStorageAccount = Get-cAzureRmResource -Type AzureRmStorageAccount -Parameters $params -ErrorAction SilentlyContinue)) {
            Write-Output "New-AzureRmStorageAccount`n$Header"
            Write-Output "This process may take several minutes..."

            if ($ResourceGroup.Storage.GlobalConfiguration) {  
                $params = @{
                    Name              = $AzureRmStorageAccountName
                    ResourceGroupName = $ResourceGroup
                    Type              = $ConfigurationData.GlobalConfiguration.Storage.Type
                    Location          = $ResourceGroup.Location
                    Tag               = $ResourceGroup.Tags
                }
            }
            else {
                $params = @{
                    Name              = $AzureRmStorageAccountName
                    ResourceGroupName = $ResourceGroup
                    Type              = $ResourceGroup.Storage.Type
                    Location          = $ResourceGroup.Location
                    Tag               = $ResourceGroup.Tags
                }
            }

            $AzureRmStorageAccount = New-cAzureRmResource -Type AzureRmStorageAccount -Parameters $params -ErrorAction Stop

            if ($AzureRmStorageAccount) { Write-Output $AzureRmStorageAccount } else { break }

            $params = @{
                Name              = $AzureRmStorageAccountName
                ResourceGroupName = $ResourceGroup
            }

            $Keys = Get-cAzureRmResource -Type AzureRmStorageAccountKey -Parameters $params

            $params = @{
                StorageAccountName = $AzureRmStorageAccountName
                StorageAccountKey  = $Keys[0].Value
            }

            $StorageContext = New-cAzureRmResource -Type AzureStorageContext -Parameters $params
        }
        else {
            $params = @{
                Name              = $AzureRmStorageAccountName
                ResourceGroupName = $ResourceGroup
            }

            $Keys = Get-cAzureRmResource -Type AzureRmStorageAccountKey -Parameters $params

            $params = @{
                StorageAccountName = $AzureRmStorageAccountName
                StorageAccountKey  = $Keys[0].Value
            }

            $StorageContext = New-cAzureRmResource -Type AzureStorageContext -Parameters $params
        }

        #Verify CORS rules
        if ($StorageContext) {
            $params = @{
                ServiceType = "Blob"
                Context     = $StorageContext
            }

            $cRules = Get-cAzureRmResource -Type AzureStorageCORSRule -Parameters $params

            $cUpdate = $False
            if ($ResourceGroup.CorsRules.GlobalConfiguration) {
                foreach ($CorsRule in $ConfigurationData.GlobalConfiguration.CorsRules.Keys) {
                    if (!([string]$cRules.$CorsRule -eq [string]$ConfigurationData.GlobalConfiguration.CorsRules.$CorsRule)) {
                        $cUpdate = $True
                        Break
                    }
                }
            }
            else {
                foreach ($CorsRule in $ResourceGroup.CorsRules.Keys) {
                    if (!([string]$cRules.$CorsRule -eq [string]$ResourceGroup.CorsRules.$CorsRule)) {
                        $cUpdate = $True
                        Break
                    }
                }
            }

            if ($cUpdate) {
                Write-Output "Set-AzureStorageCORSRule`n$Header"

                if ($ResourceGroup.CorsRules.GlobalConfiguration) {
                    $params = @{
                        ServiceType = "Blob"
                        Context     = $StorageContext
                        CorsRules   = $ConfigurationData.GlobalConfiguration.CorsRules
                    }
                }
                else {
                    $params = @{
                        ServiceType = "Blob"
                        Context     = $StorageContext
                        CorsRules   = $ResourceGroup.CorsRules
                    }
                }

                $StorageContext = Set-cAzureRmResource -Type AzureStorageCORSRule -Parameters $params

                $params = @{
                    ServiceType = "Blob"
                    Context     = $StorageContext
                }

                Set-cAzureRmResource -Type AzureStorageCORSRule -Parameters $params -ErrorAction Stop

                $GetAzureStorageCORSRule = Get-AzureStorageCORSRule -ServiceType Blob -Context $StorageContext

                Write-Host $GetAzureStorageCORSRule

                Write-Output ""
            }
        }

        #Verify AzureStorageContainer
        $AzureStorageContainerHeader = $True

        $Containers = $null
        if ($ResourceGroup.Storage.GlobalConfiguration) {
            $Containers = $ConfigurationData.GlobalConfiguration.Storage.Containers
        }
        else {
            $Containers = $ResourceGroup.Storage.Containers
        }

        foreach ($Container in $Containers) {
            $params = @{
                Name    = $Container
                Context = $StorageContext
            }

            if ($AzureRmResourceGroup -and $AzureRmStorageAccount -and -not($AzureStorageContainer = Get-cAzureRmResource -Type AzureStorageContainer -Parameters $params -ErrorAction SilentlyContinue)) {
                Write-Output "New-AzureStorageContainer`n$Header"

                $params = @{
                    Name       = $Container
                    Permission = "Off"
                    Context    = $StorageContext
                }

                $AzureStorageContainer = Set-cAzureRmResource -Type AzureStorageContainer -Parameters $params

                Write-Output $AzureStorageContainer
            }
        }
    }

    #Verify AzureRmAutomationAccount
    if ($ResourceGroup.AzureRmAutomationAccount.Name) {

        $AzureRmAutomationAccountName = $ResourceGroup.AzureRmAutomationAccount.Name.Replace("[ResourceGroup]", $ResourceGroup)

        $params = @{
            Name              = $AzureRmAutomationAccountName
            ResourceGroupName = $ResourceGroup
        }

        if ($AzureRmResourceGroup -and -not($AzureRmAutomationAccount = Get-cAzureRmResource -Type AzureRmAutomationAccount -Parameters $params -ErrorAction SilentlyContinue)) {
            Write-Output "New-AzureRmAutomationAccount`n$Header"

            $params = @{
                ResourceGroupName = $ResourceGroup
                Location          = $ResourceGroup.Location
                Name              = $AzureRmAutomationAccountName
                Tags              = $ResourceGroup.Tags
            }

            $AzureRmAutomationAccount = New-cAzureRmResource -Type AzureRmAutomationAccount -Parameters $params

            Write-Output $AzureRmAutomationAccount
        }

        #Verify AzureRmAutomationCredential
        foreach ($AutomationCredential in $ResourceGroup.AzureRmAutomationAccount.AzureRmAutomationCredential) {

            $AutomationCredentialName = $AutomationCredential.Name.Replace("[ResourceGroup]", $ResourceGroup)

            $params = @{
                AutomationAccountName = $AzureRmAutomationAccountName
                Name                  = $AutomationCredentialName
                ResourceGroupName     = $ResourceGroup
            }

            if (-not ($AzureRmAutomationCredential = Get-cAzureRmResource -Type AzureRmAutomationCredential -Parameters $params -ErrorAction SilentlyContinue)) {
                Write-Output "New-AzureRmAutomationCredential`n$Header"

                $pw = ConvertTo-SecureString $( -join ([char[]](65..90 + 97..122) * 100 | Get-Random -Count 19) + "!") -AsPlainText -Force
                $AzureRmAutomationCredential = New-Object –TypeName System.Management.Automation.PSCredential –ArgumentList $AutomationCredentialName, $pw

                $params = @{
                    AutomationAccountName = $AzureRmAutomationAccountName
                    Name                  = $AutomationCredentialName
                    Description           = $AutomationCredential.Description
                    ResourceGroupName     = $ResourceGroup
                    Value                 = $AzureRmAutomationCredential
                }

                $AzureRmAutomationCredential = New-cAzureRmResource -Type AzureRmAutomationCredential -Parameters $params

                Write-Output $AzureRmAutomationCredential
            }
        }

        #Verify AzureRmAutomationVariable
        foreach ($AutomationVariable in $ResourceGroup.AzureRmAutomationAccount.AzureRmAutomationVariable) {
            $params = @{
                AutomationAccountName = $AzureRmAutomationAccountName
                Name                  = $AutomationVariable.Name
                ResourceGroupName     = $ResourceGroup
            }
            
            if (-not (Get-cAzureRmResource -Type AzureRmAutomationVariable -Parameters $params -ErrorAction SilentlyContinue)) {
                Write-Output "New-AzureRmAutomationVariable`n$Header"

                $params = @{
                    AutomationAccountName = $AzureRmAutomationAccountName
                    Name                  = $AutomationVariable.Name
                    Value                 = $AutomationVariable.Value
                    Encrypted             = $AutomationVariable.Encrypted
                    ResourceGroupName     = $ResourceGroup
                }

                $AzureRmAutomationVariable = New-cAzureRmResource -Type AzureRmAutomationVariable -Parameters $params

                Write-Output $AzureRmAutomationVariable
            }
        }
    }

    #Verify Relay Namespace
    if ($ConfigurationData.ResourceGroups.$ResourceGroup.HybridConnection.Enabled) {
        $params = @{
            Name              = $ConfigurationData.ResourceGroups.$ResourceGroup.HybridConnection.Namespace
            ResourceGroupName = $ResourceGroup
        }

        if (!($AzureRmRelayNamespace = Get-cAzureRmResource -Type AzureRmRelayNamespace -Parameters $params -ErrorAction SilentlyContinue)) {
            $params = @{
                Name              = $ConfigurationData.ResourceGroups.$ResourceGroup.HybridConnection.Namespace
                ResourceGroupName = $ResourceGroup
                Location          = $ConfigurationData.ResourceGroups.$ResourceGroup.Location
            }

            $AzureRmRelayNamespace = New-cAzureRmResource -Type AzureRmRelayNamespace -Parameters $params

            Write-Output $AzureRmRelayNamespace
        }

        #Verify Hybrid Connection
        $params = @{
            Name              = $ConfigurationData.ResourceGroups.$ResourceGroup.HybridConnection.Name
            ResourceGroupName = $ResourceGroup
            Namespace         = $ConfigurationData.ResourceGroups.$ResourceGroup.HybridConnection.Namespace
        }

        if (!($AzureRmRelayHybridConnection = Get-cAzureRmResource -Type AzureRmRelayHybridConnection -Parameters $params -ErrorAction SilentlyContinue)) {
            $params = @{
                Name                        = $ConfigurationData.ResourceGroups.$ResourceGroup.HybridConnection.Name
                ResourceGroupName           = $ResourceGroup
                Namespace                   = $ConfigurationData.ResourceGroups.$ResourceGroup.HybridConnection.Namespace
                RequiresClientAuthorization = $True
            }

            $AzureRmRelayHybridConnection = New-cAzureRmResource -Type AzureRmRelayHybridConnection -Parameters $params

            Write-Output $AzureRmRelayNamespace
        }
    }

    #Verify App Service Plan
    foreach ($AzureRmAppServicePlan in $ConfigurationData.ResourceGroups.$ResourceGroup.AppServicePlan.Keys) {
        $AzureRmAppServicePlanName = $AzureRmAppServicePlan.Replace("[ResourceGroup]", $ResourceGroup)

        $AzureRmAppServicePlanName = Remove-IllegalCharactersFromString -String $AzureRmAppServicePlanName.ToLower()
        if ($AzureRmAppServicePlanName.Length -lt $configurationData.GlobalConfiguration.ShortNameCharacters) {
            $AzureRmAppServicePlanName = "$AzureRmAppServicePlanName$(Get-TruncatedStringHash -String $AzureRmAppServicePlanName -Length ($configurationData.GlobalConfiguration.ShortNameCharacters - $AzureRmAppServicePlanName.Length))"
        }
        else {
            $AzureRmAppServicePlanName = $AzureRmAppServicePlanName.SubString(0, $configurationData.GlobalConfiguration.ShortNameCharacters)
        }

        $params = @{
            Name              = $AzureRmAppServicePlanName
            ResourceGroupName = $ResourceGroup
        }

        if (-not($GetAzureRmAppServicePlan = Get-cAzureRmResource -Type AzureRmAppServicePlan -Parameters $params -ErrorAction SilentlyContinue)) {
            Write-Output "New-AzureRmAppServicePlan`n$Header"

            $params = @{
                Name              = $AzureRmAppServicePlanName
                Location          = $ConfigurationData.ResourceGroups.$ResourceGroup.Location
                ResourceGroupName = $ResourceGroup
                Tier              = $ConfigurationData.ResourceGroups.$ResourceGroup.AppServicePlan.$AzureRmAppServicePlan.Tier
            }

            $AzureRmAppServicePlan = New-cAzureRmResource -Type AzureRmAppServicePlan -Parameters $params

            Write-Output $AzureRmAppServicePlan
        }
        else {
            [bool]$ChangeAzureRmAppServicePlan = $False
            if ($GetAzureRmAppServicePlan.Sku.Tier -ne $ConfigurationData.ResourceGroups.$ResourceGroup.AppServicePlan.$AzureRmAppServicePlan.Tier) {
                Write-Output "Set-AzureRmAppServicePlan`n$Header"

                $params = @{
                    Name              = $AzureRmAppServicePlanName
                    ResourceGroupName = $ResourceGroup
                    Tier              = $ConfigurationData.ResourceGroups.$ResourceGroup.AppServicePlan.$AzureRmAppServicePlan.Tier
                }

                $AzureRmAppServicePlan = Set-cAzureRmResource -Type AzureRmAppServicePlan -Parameters $params

                if ($AzureRmAppServicePlan) { $ChangeAzureRmAppServicePlan = $True }

                Write-Output $AzureRmAppServicePlan

                if ($ChangeAzureRmAppServicePlan) {

                    [bool]$RestartWebApps = $true
                    if ($configurationData.GlobalConfiguration.Confirm) {
                        Write-host "A change of the AzureRmAppServicePlan requires a restart of all associated Web Applications" -ForegroundColor Green
                        Write-host "Would you like to restart all '$AzureRmAppServicePlanName' associated Web Applications? (Default is No)" -ForegroundColor Yellow
                    
                        $Readhost = Read-Host " ( y / n ) " 
                        Switch ($ReadHost) { 
                            Y {       $RestartWebApps = $true } 
                            N {       $RestartWebApps = $false } 
                            Default { $RestartWebApps = $false } 
                        }
                    }

                    if ($RestartWebApps) {
                        $AzureRmAppServicePlanWebApps = Get-AzureRmWebApp -ResourceGroupName $ConfigurationData.Customers.$Customer.ResourceGroup | Where-Object { $_.ServerFarmId -eq $GetAzureRmAppServicePlan.Id }

                        foreach ($AzureRmAppServicePlanWebApp in $AzureRmAppServicePlanWebApps) {
                            Write-Output ""
                            Write-Output "Restart-AzureRmWebApp`n$Header"
                            Write-Output $AzureRmAppServicePlanWebApp.Name
                            Write-Output ""

                            Invoke-Logger -Message "Restart-AzureRmWebApp -ResourceGroupName $($ConfigurationData.Customers.$Customer.ResourceGroup) -Name $($AzureRmAppServicePlanWebApp.Name)" -Severity I -Category "AzureRmWebApp"

                            try {
                                $RestartAzureRmWebApp = Restart-AzureRmWebApp -ResourceGroupName $ConfigurationData.Customers.$Customer.ResourceGroup -Name $AzureRmAppServicePlanWebApp.Name

                                Invoke-Logger -Message $RestartAzureRmWebApp -Severity I -Category "AzureRmWebApp"
                            }
                            catch {
                                Invoke-Logger -Message $_ -Severity E -Category "AzureRmWebApp"

                                Write-Error $_
                            }
                        }
                    }
                }
            }
        }
        if (!$AzureRmAppServicePlan) { break }
    }

    $AzureRmKeyVaultName = $ResourceGroup

    #Verify Key Vault
    $params = @{
        VaultName = $AzureRmKeyVaultName
    }

    if ((Get-cAzureRmResource -Type AzureRmResourceGroup -Name $ConfigurationData.SaaSService.ResourceGroup -ErrorAction SilentlyContinue) -and -not($AzureRmKeyVault = Get-cAzureRmResource -Type AzureRMKeyVault -Parameters $params -ErrorAction SilentlyContinue)) {
        Write-Output "New-AzureRmKeyVault`n$Header"

        $params = @{
            VaultName         = $AzureRmKeyVaultName
            ResourceGroupName = $ConfigurationData.SaaSService.ResourceGroup
            Location          = $ConfigurationData.ResourceGroups.$ResourceGroup.Location
            Sku               = $ConfigurationData.ResourceGroups.$ResourceGroup.KeyVault.SKU
            Tags              = $ConfigurationData.ResourceGroups.$ResourceGroup.Tags
        }

        $AzureRmKeyVault = New-cAzureRmResource -Type AzureRmKeyVault -Parameters $params

        Write-Output $AzureRmKeyVault
    }
    if (!$AzureRmKeyVault) { break }
}
#endregion

#region Create Customer
foreach ($Customer in $ConfigurationData.Customers.Keys) {

    #Verify AzureRmResourceGroup
    Write-Output "$Header`nCustomer: $($Customer)`n$Header"
    Write-Output "" 

    if ($AzureRmResourceGroup = Get-cAzureRmResource -Type AzureRmResourceGroup -Name $ConfigurationData.Customers.$Customer.ResourceGroup -ErrorAction SilentlyContinue) {

        $CustomerName = (Remove-IllegalCharactersFromString -String $Customer).ToLower()

        $DnsRecordSetName = $CustomerName
        if ($DnsRecordSetName.Length -lt $configurationData.GlobalConfiguration.ShortNameCharacters) {
            $DnsRecordSetName = "$DnsRecordSetName$(Get-TruncatedStringHash -String $DnsRecordSetName -Length ($configurationData.GlobalConfiguration.ShortNameCharacters - $DnsRecordSetName.Length))"
        }
        else {
            $DnsRecordSetName = $DnsRecordSetName.SubString(0, $configurationData.GlobalConfiguration.ShortNameCharacters)
        }
        $CustomerName = $DnsRecordSetName

        #Verify AzureRmStorageAccount
        $params = @{
            Name              = $CustomerName
            ResourceGroupName = $ConfigurationData.Customers.$Customer.ResourceGroup
        }

        if (-not ($AzureRmStorageAccount = Get-cAzureRmResource -Type AzureRmStorageAccount -Parameters $params -ErrorAction SilentlyContinue)) {
            Write-Output "New-AzureRmStorageAccount`n$Header"
            Write-Output "This process may take several minutes..."

            if ($ConfigurationData.Customers.$Customer.Storage.GlobalConfiguration) {  
                $params = @{
                    Name              = $CustomerName
                    ResourceGroupName = $ConfigurationData.Customers.$Customer.ResourceGroup
                    Type              = $ConfigurationData.GlobalConfiguration.Storage.Type
                    Location          = $ConfigurationData.Customers.$Customer.Location
                    Tag               = $ConfigurationData.Customers.$Customer.Tags
                }
            }
            else {
                $params = @{
                    Name              = $CustomerName
                    ResourceGroupName = $ConfigurationData.Customers.$Customer.ResourceGroup
                    Type              = $ConfigurationData.Customers.$Customer.Storage.Type
                    Location          = $ConfigurationData.Customers.$Customer.Location
                    Tag               = $ConfigurationData.Customers.$Customer.Tags
                }
            }

            $AzureRmStorageAccount = New-cAzureRmResource -Type AzureRmStorageAccount -Parameters $params -ErrorAction Stop

            if ($AzureRmStorageAccount) { Write-Output $AzureRmStorageAccount } else { break }

            $params = @{
                Name              = $CustomerName
                ResourceGroupName = $ConfigurationData.Customers.$Customer.ResourceGroup
            }

            $Keys = Get-cAzureRmResource -Type AzureRmStorageAccountKey -Parameters $params

            $params = @{
                StorageAccountName = $CustomerName
                StorageAccountKey  = $Keys[0].Value
            }

            $StorageContext = New-cAzureRmResource -Type AzureStorageContext -Parameters $params -ErrorAction Stop
        }
        else {
            $params = @{
                Name              = $CustomerName
                ResourceGroupName = $ConfigurationData.Customers.$Customer.ResourceGroup
            }

            $Keys = Get-cAzureRmResource -Type AzureRmStorageAccountKey -Parameters $params

            $params = @{
                StorageAccountName = $CustomerName
                StorageAccountKey  = $Keys[0].Value
            }

            $StorageContext = New-cAzureRmResource -Type AzureStorageContext -Parameters $params -ErrorAction Stop
        }

        if (-not($StorageContext)) { break }

        #Verify CORS rules
        $params = @{
            ServiceType = "Blob"
            Context     = $StorageContext
        }

        $cRules = Get-cAzureRmResource -Type AzureStorageCORSRule -Parameters $params

        $cUpdate = $False
        if ($ConfigurationData.Customers.$Customer.CorsRules.GlobalConfiguration) {
            foreach ($CorsRule in $ConfigurationData.GlobalConfiguration.CorsRules.Keys) {
                if (!([string]$cRules.$CorsRule -eq [string]$ConfigurationData.GlobalConfiguration.CorsRules.$CorsRule)) {
                    $cUpdate = $True
                    Break
                }
            }
        }
        else {
            foreach ($CorsRule in $ConfigurationData.Customers.$Customer.CorsRules.Keys) {
                if (!([string]$cRules.$CorsRule -eq [string]$ConfigurationData.Customers.$Customer.CorsRules.$CorsRule)) {
                    $cUpdate = $True
                    Break
                }
            }
        }

        if ($cUpdate) {
            Write-Output "Set-AzureStorageCORSRule`n$Header"

            if ($ConfigurationData.Customers.$Customer.CorsRules.GlobalConfiguration) {
                $params = @{
                    ServiceType = "Blob"
                    Context     = $StorageContext
                    CorsRules   = $ConfigurationData.GlobalConfiguration.CorsRules
                }
            }
            else {
                $params = @{
                    ServiceType = "Blob"
                    Context     = $StorageContext
                    CorsRules   = $ConfigurationData.Customers.$Customer.CorsRules
                }
            }

            Set-cAzureRmResource -Type AzureStorageCORSRule -Parameters $params

            $params = @{
                ServiceType = "Blob"
                Context     = $StorageContext
            }

            $GetAzureStorageCORSRule = Get-cAzureRmResource -Type AzureStorageCORSRule -Parameters $params

            Write-Host $GetAzureStorageCORSRule

            Write-Output ""
        }

        #Verify AzureStorageContainer
        $AzureStorageContainerHeader = $True

        $Containers = $null
        if ($ConfigurationData.Customers.$Customer.Storage.GlobalConfiguration) {
            $Containers = $ConfigurationData.GlobalConfiguration.Storage.Containers
        }
        else {
            $Containers = $ConfigurationData.Customers.$Customer.Storage.Containers
        }

        foreach ($Container in $Containers) {
            $params = @{
                Name    = $Container
                Context = $StorageContext
            }

            if ($AzureRmStorageAccount -and -not($AzureStorageContainer = Get-cAzureRmResource -Type AzureStorageContainer -Parameters $params -ErrorAction SilentlyContinue)) {
                Write-Output "New-AzureStorageContainer`n$Header"

                $params = @{
                    Name       = $Container
                    Permission = "Off"
                    Context    = $StorageContext
                }

                $AzureStorageContainer = New-cAzureRmResource -Type AzureStorageContainer -Parameters $params

                Write-Output $AzureStorageContainer
            }
        }
        
        #Verify AzureRmDnsRecordSet
        if ($ConfigurationData.Customers.$Customer.DnsRecordSet.GlobalConfiguration) {
            $RecordType = $ConfigurationData.GlobalConfiguration.DnsRecordSet.RecordType
            $Ttl = $ConfigurationData.GlobalConfiguration.DnsRecordSet.Ttl
            $DnsRecords = $ConfigurationData.GlobalConfiguration.DnsRecordSet.DnsRecords
        }
        else {
            $RecordType = $ConfigurationData.Customers.$Customer.DnsRecordSet.RecordType
            $Ttl = $ConfigurationData.Customers.$Customer.DnsRecordSet.Ttl
            $DnsRecords = $ConfigurationData.Customers.$Customer.DnsRecordSet.DnsRecords
        }

        $params = @{
            Name              = (Remove-IllegalCharactersFromString -String $Customer).ToLower()
            RecordType        = $RecordType
            ZoneName          = $AzureRmDnsZoneName
            ResourceGroupName = $ConfigurationData.SaaSService.ResourceGroup
        }

        if (-not($AzureRmDnsRecordSet = Get-cAzureRmResource -Type AzureRmDnsRecordSet -Parameters $params -ErrorAction SilentlyContinue)) {
            Write-Output "New-AzureRmDnsRecordSet`n$Header"

            if ($RecordType -eq "CNAME") {
                $DnsRecordsValue = $DnsRecords.Replace("[ResourceGroup]", $DnsRecordSetName)
                $DnsRecords = (New-AzureRmDnsRecordConfig -Cname $DnsRecordsValue)
            }
            else {
                $DnsRecords = (New-AzureRmDnsRecordConfig -IPv4Address $DnsRecordSet.DnsRecords)
            }

            $params = @{
                Name              = (Remove-IllegalCharactersFromString -String $Customer).ToLower()
                RecordType        = $RecordType
                ZoneName          = $AzureRmDnsZoneName
                ResourceGroupName = $ConfigurationData.SaaSService.ResourceGroup
                Ttl               = $Ttl
                DnsRecords        = $DnsRecords
            }

            $AzureRmDnsRecordSet = New-cAzureRmResource -Type AzureRmDnsRecordSet -Parameters $params

            Write-Output $AzureRmDnsRecordSet
        }

        #Verify Key Vault Secret
        $params = @{
            VaultName = $ConfigurationData.Customers.$Customer.ResourceGroup
        }

        $params2 = @{
            VaultName = $ConfigurationData.Customers.$Customer.ResourceGroup
            Name      = (Remove-IllegalCharactersFromString -String $Customer).ToLower()
        }

        if (($AzureRmKeyVault = Get-cAzureRmResource -Type AzureRMKeyVault -Parameters $params -ErrorAction SilentlyContinue) -and -not($AzureKeyVaultSecret = (Get-cAzureRmResource -Type AzureKeyVaultSecret -Parameters $params2 -ErrorAction SilentlyContinue).SecretValueText)) {
            Write-Output "$Header`nSet-AzureKeyVaultSecret`n$Header"

            #Define Secret properties
            $Secret = @{}
            if ($ConfigurationData.Customers.$Customer.KeyVaultSecret.GlobalConfiguration) {
                foreach ($variable in $ConfigurationData.GlobalConfiguration.KeyVault.Secrets.AppSettings.Keys) {
                    $value = $ConfigurationData.GlobalConfiguration.KeyVault.Secrets.AppSettings.$variable
                    New-Variable -Name $variable -Value "`$ConfigurationData.$value" -Force
                    $value = $value.Replace("[ResourceGroup]", $ConfigurationData.Customers.$Customer.ResourceGroup)
                    $value = $value.Replace("[Key]", $Keys[0].Value)
                    $Secret.add($variable, $value)
                }
            }
            else {
                foreach ($variable in $ConfigurationData.Customers.$Customer.KeyVaultSecret.Keys) {
                    $value = $ConfigurationData.Customers.$Customer.KeyVaultSecret.$variable
                    New-Variable -Name $variable -Value "`$ConfigurationData.$value" -Force
                    $value = $value.Replace("[ResourceGroup]", $ConfigurationData.Customers.$Customer.ResourceGroup)
                    $value = $value.Replace("[Key]", $Keys[0].Value)
                    $Secret.add($variable, $value)
                }
            }

            $params = @{
                Name        = (Remove-IllegalCharactersFromString -String $Customer).ToLower()
                SecretValue = (ConvertTo-SecureString $(ConvertTo-Json $Secret) -AsPlainText -Force)
                ContentType = "AppSettings"
                VaultName   = $ConfigurationData.Customers.$Customer.ResourceGroup
            }

            $AzureKeyVaultSecret = Set-cAzureRmResource -Type AzureKeyVaultSecret -Parameters $params

            Write-Output $Secret.Keys
        }
        Elseif ($AzureKeyVaultSecret) {

            #Define Secret properties from configuration file
            $Secret = @{}
            if ($ConfigurationData.Customers.$Customer.KeyVaultSecret.GlobalConfiguration) {
                foreach ($variable in $ConfigurationData.GlobalConfiguration.KeyVault.Secrets.AppSettings.Keys) {
                    $value = $ConfigurationData.GlobalConfiguration.KeyVault.Secrets.AppSettings.$variable
                    New-Variable -Name $variable -Value "`$ConfigurationData.$value" -Force
                    $value = $value.Replace("[ResourceGroup]", $ConfigurationData.Customers.$Customer.ResourceGroup)
                    $value = $value.Replace("[Key]", $Keys[0].Value)
                    $Secret.add($variable, $value)
                }
            }
            else {
                foreach ($variable in $ConfigurationData.Customers.$Customer.KeyVaultSecret.Keys) {
                    $value = $ConfigurationData.Customers.$Customer.KeyVaultSecret.$variable
                    New-Variable -Name $variable -Value "`$ConfigurationData.$value" -Force
                    $value = $value.Replace("[ResourceGroup]", $ConfigurationData.Customers.$Customer.ResourceGroup)
                    $value = $value.Replace("[Key]", $Keys[0].Value)
                    $Secret.add($variable, $value)
                }
            }

            #Compare configuration file to Key Vault Secret
            if ($AzureKeyVaultSecret -ne $(ConvertTo-Json $Secret)) {
                Write-Output "Set-AzureKeyVaultSecret`n$Header"

                $params = @{
                    Name        = (Remove-IllegalCharactersFromString -String $Customer).ToLower()
                    SecretValue = (ConvertTo-SecureString $(ConvertTo-Json $Secret) -AsPlainText -Force)
                    ContentType = "AppSettings"
                    VaultName   = $ConfigurationData.Customers.$Customer.ResourceGroup
                }

                $AzureKeyVaultSecret = Set-cAzureRmResource -Type AzureKeyVaultSecret -Parameters $params

                Write-Output $Secret.Keys
            }

        }

        #Verify Web Applications
        foreach ($WebApp in $ConfigurationData.Customers.$Customer.WebApp.Keys) {

            $AzureRmWebAppName = (Remove-IllegalCharactersFromString -String $WebApp.Replace("[Customer]", $Customer)).ToLower()

            if ($AzureRmWebAppName.Length -lt $configurationData.GlobalConfiguration.ShortNameCharacters) {
                $AzureRmWebAppName = "$AzureRmWebAppName$(Get-TruncatedStringHash -String $AzureRmWebAppName -Length ($configurationData.GlobalConfiguration.ShortNameCharacters - $AzureRmWebAppName.Length))"
            }
            else {
                $AzureRmWebAppName = $AzureRmWebAppName.SubString(0, $configurationData.GlobalConfiguration.ShortNameCharacters)
            } 

            Write-Output "Verify Web App: $AzureRmWebAppName`n$Header"
            Write-Output ""

            #Verify App Service Plan
            $AzureRmAppServicePlanName = (Remove-IllegalCharactersFromString -String $ConfigurationData.Customers.$Customer.WebApp.$WebApp.AppServicePlan.Name.Replace("[ResourceGroup]", $ResourceGroup)).ToLower()
            $AzureRmAppServicePlanName = $AzureRmAppServicePlanName.Replace("[customer]", $CustomerName)

            if ($AzureRmAppServicePlanName.Length -lt $configurationData.GlobalConfiguration.ShortNameCharacters) {
                $AzureRmAppServicePlanName = "$AzureRmAppServicePlanName$(Get-TruncatedStringHash -String $AzureRmAppServicePlanName -Length ($configurationData.GlobalConfiguration.ShortNameCharacters - $AzureRmAppServicePlanName.Length))"
            }
            else {
                $AzureRmAppServicePlanName = $AzureRmAppServicePlanName.SubString(0, $configurationData.GlobalConfiguration.ShortNameCharacters)
            }

            #Define App Service Plan Tier
            [string]$Tier = ""
            if ($ConfigurationData.Customers.$Customer.WebApp.$WebApp.AppServicePlan.Tier) {
                $Tier = $ConfigurationData.Customers.$Customer.WebApp.$WebApp.AppServicePlan.Tier
            }
            else {
                $Tier = $ConfigurationData.ResourceGroups.$($ConfigurationData.Customers.$Customer.ResourceGroup).AppServicePlan.$($ConfigurationData.Customers.$Customer.WebApp.$WebApp.AppServicePlan.Name).Tier
            }

            #Verify App Service Plan
            $params = @{
                Name              = $AzureRmAppServicePlanName
                ResourceGroupName = $ConfigurationData.Customers.$Customer.ResourceGroup
            }

            if (-not($GetAzureRmAppServicePlan = Get-cAzureRmResource -Type AzureRmAppServicePlan -Parameters $params -ErrorAction SilentlyContinue)) {
                Write-Output "New-AzureRmAppServicePlan`n$Header"

                $params = @{
                    Name              = $AzureRmAppServicePlanName
                    Location          = $ConfigurationData.Customers.$Customer.Location
                    ResourceGroupName = $ConfigurationData.Customers.$Customer.ResourceGroup
                    Tier              = $Tier
                }

                $AzureRmAppServicePlan = New-cAzureRmResource -Type AzureRmAppServicePlan -Parameters $params

                Write-Output $AzureRmAppServicePlan
            }
            else {
                [bool]$ChangeAzureRmAppServicePlan = $False
                if ($GetAzureRmAppServicePlan.Sku.Tier -ne $Tier) {
                    Write-Output "Set-AzureRmAppServicePlan`n$Header"

                    $params = @{
                        Name              = $AzureRmAppServicePlanName
                        ResourceGroupName = $ConfigurationData.Customers.$Customer.ResourceGroup
                        Tier              = $Tier
                    }

                    $AzureRmAppServicePlan = Set-cAzureRmResource -Type AzureRmAppServicePlan -Parameters $params

                    if ($AzureRmAppServicePlan) { $ChangeAzureRmAppServicePlan = $True }

                    Write-Output $AzureRmAppServicePlan

                    #Restart Web Applications
                    if ($ChangeAzureRmAppServicePlan) {

                        [bool]$RestartWebApps = $true
                        if ($configurationData.GlobalConfiguration.Confirm) {
                            Write-host "A change of the AzureRmAppServicePlan requires a restart of all associated Web Applications" -ForegroundColor Green
                            Write-host "Would you like to restart all '$AzureRmAppServicePlanName' associated Web Applications? (Default is No)" -ForegroundColor Yellow
                    
                            $Readhost = Read-Host " ( y / n ) " 
                            Switch ($ReadHost) { 
                                Y {       $RestartWebApps = $true } 
                                N {       $RestartWebApps = $false } 
                                Default { $RestartWebApps = $false } 
                            }
                        }

                        if ($RestartWebApps) {
                            $AzureRmAppServicePlanWebApps = Get-AzureRmWebApp -ResourceGroupName $ConfigurationData.Customers.$Customer.ResourceGroup | Where-Object { $_.ServerFarmId -eq $GetAzureRmAppServicePlan.Id }

                            foreach ($AzureRmAppServicePlanWebApp in $AzureRmAppServicePlanWebApps) {
                                Write-Output ""
                                Write-Output "Restart-AzureRmWebApp`n$Header"
                                Write-Output $AzureRmAppServicePlanWebApp.Name
                                Write-Output ""

                                Invoke-Logger -Message "Restart-AzureRmWebApp -ResourceGroupName $($ConfigurationData.Customers.$Customer.ResourceGroup) -Name $($AzureRmAppServicePlanWebApp.Name)" -Severity I -Category "AzureRmWebApp"

                                try {
                                    $RestartAzureRmWebApp = Restart-AzureRmWebApp -ResourceGroupName $ConfigurationData.Customers.$Customer.ResourceGroup -Name $AzureRmAppServicePlanWebApp.Name

                                    Invoke-Logger -Message $RestartAzureRmWebApp -Severity I -Category "AzureRmWebApp"
                                }
                                catch {
                                    Invoke-Logger -Message $_ -Severity E -Category "AzureRmWebApp"

                                    Write-Error $_
                                }
                            }
                        }
                    }
                }
            }

            #Verify Web Applications
            $NewAzureRmWebApp = $False          

            [bool]$AzureRmWebAppChange = $False

            $params = @{
                Name              = $AzureRmWebAppName
                ResourceGroupName = $ConfigurationData.Customers.$Customer.ResourceGroup
            }

            if (-not($AzureRmWebApp = Get-cAzureRmResource -Type AzureRmWebApp -Parameters $params -ErrorAction SilentlyContinue)) {
                Write-Output "New-AzureRmWebApp`n$Header"

                $NewAzureRmWebApp = $True

                $params = @{
                    Name              = $AzureRmWebAppName
                    Location          = $ConfigurationData.Customers.$Customer.Location
                    ResourceGroupName = $ConfigurationData.Customers.$Customer.ResourceGroup
                    AppServicePlan    = $AzureRmAppServicePlanName
                }

                $AzureRmWebApp = New-cAzureRmResource -Type AzureRmWebApp -Parameters $params -ErrorAction Stop

                Write-Output $AzureRmWebApp

                Start-Sleep 30
            }
            else {
                Invoke-Logger -Message $AzureRmWebApp -Severity I -Category "AzureRmWebApp"

                if ($GetAzureRmAppServicePlan.Id -ne $AzureRmWebApp.ServerFarmId) {
                    Write-Output "Set-AzureRmWebApp`n$Header"

                    $NewAzureRmWebApp = $True

                    $params = @{
                        Name              = $AzureRmWebAppName
                        ResourceGroupName = $ConfigurationData.Customers.$Customer.ResourceGroup
                        AppServicePlan    = $AzureRmAppServicePlanName
                    }

                    $AzureRmWebApp = Set-cAzureRmResource -Type AzureRmWebApp -Parameters $params -ErrorAction Stop

                    $AzureRmWebAppChange = $True

                    Write-Output $AzureRmWebApp    

                    Start-Sleep 30
                }
            }

            if (!$AzureRmWebApp) { break }

            #Update Web Application Custom Domains
            if ($Tier -ne "Free") {
                if (!($AzureRmWebApp.HostNames -like "*$AzureRmWebAppName.$($ConfigurationData.GlobalConfiguration.TenantDomain)*")) {
                    Write-Output "Set-AzureRmWebApp`n$Header"

                    $params = @{
                        Name              = $AzureRmWebAppName
                        ResourceGroupName = $ConfigurationData.Customers.$Customer.ResourceGroup
                        HostNames         = @("$((Remove-IllegalCharactersFromString -String $Customer).ToLower()).$($ConfigurationData.GlobalConfiguration.TenantDomain)", "$AzureRmWebAppName.azurewebsites.net")
                    }

                    $AzureRmWebApp = Set-cAzureRmResource -Type AzureRmWebApp -Parameters $params -ErrorAction Stop

                    Write-Output $SetAzureRmWebApp
                }
            }

            #Update Web APplication Binaries
            if ($NewAzureRmWebApp -or $ConfigurationData.Customers.$Customer.WebApp.$WebApp.AlwaysUpdate) {
                #Upload Zip binaries
                For ($x = 1; $x -le 9; $x++) {
                    try {
                        $UrlStatusCode = (Invoke-WebRequest -Uri "https://$AzureRmWebAppName.$($ConfigurationData.GlobalConfiguration.KuduAPI.URI)" -UseBasicParsing -DisableKeepAlive).StatusCode
                        if ($UrlStatusCode -ne "200") {
                            Start-Sleep 5
                        }
                        else { break }
                    }
                    catch { Start-Sleep 5 }
                }

                if (-not ($NewAzureRmWebApp)) {
                    Write-Output "Remove-FilesFromWebApp`n$Header"

                    Remove-FilesFromWebApp -WebAppName $AzureRmWebAppName -ResourceGroupName $ResourceGroup -Verbose
        
                    Write-Output ""
                }

                Write-Output "Set-FileToWebApp`n$Header"

                if ($ConfigurationData.Customers.$Customer.WebApp.$WebApp.GlobalConfiguration) {
                    $FileName = $ConfigurationData.GlobalConfiguration.WebApp.SourceRepo
                }
                else {
                    $FileName = $ConfigurationData.Customers.$Customer.WebApp.$WebApp.SourceRepo
                }

                $params = @{
                    WebAppName        = $AzureRmWebAppName
                    FileName          = $FileName
                    ResourceGroupName = $ConfigurationData.Customers.$Customer.ResourceGroup
                }

                $FileToWebApp = Set-cAzureRmResource -Type FileToWebApp -Parameters $params -Verbose

                Write-Output $FileToWebApp
            }

            #Define App Settings properties
            $AppSettings = @{}
            if ($ConfigurationData.Customers.$Customer.WebApp.$WebApp.AppSettings.GlobalConfiguration) {
                foreach ($variable in $ConfigurationData.GlobalConfiguration.WebApp.AppSettings.Keys) {
                    $value = $ConfigurationData.GlobalConfiguration.WebApp.AppSettings.$variable
                    New-Variable -Name $value -Value "`$ConfigurationData.$value" -Force
                    $value = $value.Replace("[WebApp]", $AzureRmWebAppName)
                    $value = $value.Replace("[Key]", $Keys[0].Value)
                    $AppSettings.add($variable, $value)
                }
            }
            else {
                if ($ConfigurationData.Customers.$Customer.WebApp.$WebApp.AppSettings.Keys) {
                    foreach ($variable in $ConfigurationData.Customers.$Customer.WebApp.$WebApp.AppSettings.Keys) {
                        New-Variable -Name $value -Value "`$ConfigurationData.$value" -Force
                        $value = $value.Replace("[WebApp]", $AzureRmWebAppName)
                        $value = $value.Replace("[Key]", $Keys[0].Value)
                        $AppSettings.add($variable, $value)
                    }
                }
            }

            #Verify App Settings
            $params = @{
                Name              = $AzureRmWebAppName
                ResourceGroupName = $ConfigurationData.Customers.$Customer.ResourceGroup
            }

            $MyAzureRmWebApp = Get-cAzureRmResource -Type AzureRmWebApp -Parameters $params | Select-Object -ExpandProperty SiteConfig | Select-Object -ExpandProperty AppSettings

            [hashtable]$cAppSettings = @{}
            foreach ($item in $MyAzureRmWebApp) {
                $cAppSettings.Add($item.Name, $item.Value)
            }

            [bool]$AppSettingsUpdate = $False

            foreach ($Item in $AppSettings.Keys) {
                if ($cAppSettings.$Item -ne $AppSettings.$Item) {
                    $AppSettingsUpdate = $True
                    break
                }
            }

            foreach ($Item in $cAppSettings.Keys) {
                if ($AppSettings.$Item -ne $cAppSettings.$Item) {
                    $AppSettingsUpdate = $True
                    break
                }
            }

            #Update App Settings
            if ($AppSettingsUpdate) {
                Write-Output "Set-AzureRmWebApp`n$Header"

                $params = @{
                    Name              = $AzureRmWebAppName
                    ResourceGroupName = $ConfigurationData.Customers.$Customer.ResourceGroup
                    AppSettings       = $AppSettings
                }

                $null = Set-cAzureRmResource -Type AzureRmWebApp -Parameters $params

                Write-Output $SetAzureRmWebAppParams.AppSettings.Keys
            }
        }
    }
}
#endregion

$Measure.Stop()

Write-Output ""
Write-Output $Header
Write-Output "Completed in $(($Measure.Elapsed).TotalSeconds) seconds"
Invoke-Logger -Message "Completed in $(($Measure.Elapsed).TotalSeconds) seconds" -Severity I -Category "TotalSeconds"