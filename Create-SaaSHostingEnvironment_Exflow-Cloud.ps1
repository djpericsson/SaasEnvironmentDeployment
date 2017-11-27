Clear-Host

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

if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message "Helper-Module: $PSScriptRoot/Helper-Module.ps1" -Severity I -Category "Helper-Module" } Catch {} }
if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message "ConfigurationData.psd1: $PSScriptRoot/ConfigurationData.psd1" -Severity I -Category "ConfigurationData" } Catch {} }

if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $ConfigurationData -Severity I -Category "ConfigurationData" } Catch {} }
#endregion

#[void](Read-Host 'Press Enter to continue…')

#region Checking PowerShell version and modules
Write-Output "$Header`nChecking PowerShell version and modules`n$Header"

#Call function to verify installed modules and versions against configuration data file
$hasErrors = Get-RequiredModules -Modules $ConfigurationData.GlobalConfiguration.Prerequisites.Modules

#Verify installed PowerShell version against the configuration data file
If ($PSVersionTable.PSVersion -lt $ConfigurationData.PowerShell.Version) {
    $Message = "PowerShell must be updated to at least $($ConfigurationData.GlobalConfiguration.Prerequisites.PowerShell.Version)."
    Write-Warning $Message
    if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $Message -Severity W -Category "PowerShell" } Catch {} }
    $hasErrors = $True
} Else {
    $Message = "PowerShell version $($PSVersionTable.PSVersion) is valid."
    Write-Host $Message
    if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $Message -Severity I -Category "PowerShell" } Catch {} }
    Write-Host ""
}

If ($hasErrors) {
    break
}
#endregion

#region Login in to AzureRm
[bool]$BoolAzureRmLogon = $True

Try { $azureRmContext = Get-AzureRmContext -ErrorAction Stop  }
Catch [System.Management.Automation.PSInvalidOperationException]{
    $BoolAzureRmLogon = $False
}
if ($null -eq $azureRmContext) {
    $BoolAzureRmLogon = $False
}
elseif ($null -eq $azureRmContext.Account) {
    $BoolAzureRmLogon = $False
}

If (!$BoolAzureRmLogon) {
    Write-Output "$Header`nLogin-AzureRmAccount`n$Header"

    if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message "Login-AzureRmAccount" -Severity I -Category "AzureRmAccount" } Catch {} }

    Try {
        Login-AzureRmAccount -ErrorAction Stop

        Write-Output ""

        $azureRmContext = Get-AzureRmContext

        if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $azureRmContext -Severity I -Category "AzureRmAccount" } Catch {} }

        Write-Output $azureRmContext
    }
    Catch {
        if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $_ -Severity E -Category "AzureRmAccount" } Catch {} }

        Write-Error $_
    }
}

If ($azureRmContext.Subscription.Id -eq $null) { Break }
#endregion

#region Get Directory Name
Write-Output "$Header`nGet-AzureRmTenant`n$Header"

if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message "Get-AzureRmTenant | Where-Object { $($_).Id -eq $($azureRmContext.Tenant.Id) }).Directory" -Severity I -Category "Directory" } Catch {} }
$Directory = (Get-AzureRmTenant | Where-Object { $_.Id -eq $azureRmContext.Tenant.Id }).Directory

if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $Directory -Severity I -Category "Directory" } Catch {} }

Write-Output $Directory
Write-Output ""

If (!$Directory) { Break }
#endregion

#region Create SaaS Resource Group
Write-Output "$Header`nAzureRmResourceGroup: $($ConfigurationData.SaaSService.ResourceGroup)`n$Header"
Write-Output ""

If (-not($SaaSAzureRmResourceGroup = Get-AzureRmResourceGroup -Name $ConfigurationData.SaaSService.ResourceGroup -ErrorAction SilentlyContinue)) {

    Write-Output "$Header`nNew-AzureRmResourceGroup`n$Header"
    
    $SaaSAzureRmResourceGroupParams = @{
        Name     = $ConfigurationData.SaaSService.ResourceGroup
        Location = $ConfigurationData.SaaSService.Location
        Tag      = $configurationData.SaaSService.Tags
    }

    if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message "New-AzureRmResourceGroup -$($SaaSAzureRmResourceGroupParams.Keys.ForEach({"$_ '$($SaaSAzureRmResourceGroupParams.$_)'"}) -join ' -')" -Severity I -Category "SaaSAzureRmResourceGroup" } Catch {} }

    Try {
        $SaaSAzureRmResourceGroup = New-AzureRmResourceGroup @SaaSAzureRmResourceGroupParams -ErrorAction Stop

        if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $SaaSAzureRmResourceGroup -Severity I -Category "SaaSAzureRmResourceGroup" } Catch {} }

        Write-Output $SaaSAzureRmResourceGroup
    }
    Catch {
        if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $_ -Severity E -Category "SaaSAzureRmResourceGroup" } Catch {} }

        Write-Error $_
    }
}
Else {
    if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $SaaSAzureRmResourceGroup -Severity I -Category "SaaSAzureRmResourceGroup" } Catch {} }

    Write-Output $SaaSAzureRmResourceGroup
}
#endregion

#region Create Azure Key Vault
$AzureRmKeyVaultName = $ConfigurationData.SaaSService.KeyVault.Name.Replace("[ResourceGroup]",$ConfigurationData.SaaSService.ResourceGroup)

If ((Get-AzureRmResourceGroup -Name $ConfigurationData.SaaSService.ResourceGroup -ErrorAction SilentlyContinue) -and -not($AzureRmKeyVault = Get-AzureRMKeyVault -VaultName $AzureRmKeyVaultName -ErrorAction SilentlyContinue)) {
    Write-Output "$Header`nNew-AzureRmKeyVault`n$Header"

    $AzureRmKeyVaultParams = @{
        VaultName         = $AzureRmKeyVaultName
        ResourceGroupName = $ConfigurationData.SaaSService.ResourceGroup
        Location          = $ConfigurationData.SaaSService.Location
        Sku               = $ConfigurationData.SaaSService.KeyVault.SKU
        Tags              = $ConfigurationData.SaaSService.Tags
    }

    if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message "New-AzureRmKeyVault -$($AzureRmKeyVaultParams.Keys.ForEach({"$_ '$($AzureRmKeyVaultParams.$_)'"}) -join ' -')" -Severity I -Category "AzureRmKeyVault" } Catch {} }

    Try {
        $AzureRmKeyVault = New-AzureRmKeyVault @AzureRmKeyVaultParams -ErrorAction Stop

        if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $AzureRmKeyVault -Severity I -Category "AzureRmKeyVault" } Catch {} }

        Write-Output $AzureRmKeyVault
    }
    Catch {
        if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $_ -Severity E -Category "AzureRmKeyVault" } Catch {} }

        Write-Error $_
    }
}
Else {
    if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $AzureRmKeyVault -Severity I -Category "AzureRmKeyVault" } Catch {} }
}
If (!$AzureRmKeyVault) { Break }
#endregion

#region Create Azure Key Vault Secret
ForEach ($Secret in $ConfigurationData.SaaSService.KeyVault.Secrets.Keys) {
    ForEach ($Value in $ConfigurationData.SaaSService.KeyVault.Secrets.$Secret.Keys) {
        $cleanValue = $Value
        @("_","-") | ForEach-Object { $cleanValue = $cleanValue.Replace($_,"") }
        If (-not($AzureKeyVaultSecret = (Get-AzureKeyVaultSecret -VaultName $AzureRmKeyVaultName -Name $cleanValue -ErrorAction SilentlyContinue).SecretValueText)) {
            Write-Output "$Header`nSet-AzureKeyVaultSecret`n$Header"

            $AzureKeyVaultSecretParams = @{
                Name        = $cleanValue
                SecretValue = (ConvertTo-SecureString $($ConfigurationData.SaaSService.KeyVault.Secrets.$Secret.$Value) -AsPlainText -Force)
                ContentType = $Secret
                VaultName   = $AzureRmKeyVaultName
            }

            if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message "Set-AzureKeyVaultSecret -$($AzureKeyVaultSecretParams.Keys.ForEach({"$_ '$($AzureKeyVaultSecretParams.$_)'"}) -join ' -')" -Severity I -Category "AzureKeyVaultSecret" } Catch {} }

            Try {
                $AzureKeyVaultSecret = Set-AzureKeyVaultSecret @AzureKeyVaultSecretParams -ErrorAction Stop

                if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $AzureKeyVaultSecret -Severity I -Category "AzureKeyVaultSecret" } Catch {} }

                Write-Output $AzureKeyVaultSecret
            }
            Catch {
                if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $_ -Severity E -Category "AzureKeyVaultSecret" } Catch {} }

                Write-Error $_
            }
        }
    }
}
#endregion

# Create Automation account if it doesnt exist
if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message "Get-AzureRmAutomationAccount -ResourceGroupName $($ConfigurationData.SaaSService.ResourceGroup) -Name $($ConfigurationData.SaaSService.ResourceGroup) -ErrorAction SilentlyContinue" -Severity I -Category "AzureRmAutomationAccount" } Catch {} }
If ($SaaSAzureRmResourceGroup -and -not($AzureRmAutomationAccount = Get-AzureRmAutomationAccount -ResourceGroupName $($ConfigurationData.SaaSService.ResourceGroup) -Name $($ConfigurationData.SaaSService.ResourceGroup) -ErrorAction SilentlyContinue)) {
    Write-Output ""
    Write-Output "$Header`nCreating AzureRmAutomationAccount`n$Header"

    try {
        if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message "New-AzureRmAutomationAccount -ResourceGroupName $($($ConfigurationData.SaaSService.ResourceGroup)) -Location $($ConfigurationData.SaaSService.Location) -Name $($($ConfigurationData.SaaSService.ResourceGroup)) -Tags $($configurationData.Tags)" -Severity I -Category "AzureRmAutomationAccount" } Catch {} }
        $AzureRmAutomationAccount = New-AzureRmAutomationAccount -ResourceGroupName $($($ConfigurationData.SaaSService.ResourceGroup)) -Location $($ConfigurationData.SaaSService.Location) -Name $($($ConfigurationData.SaaSService.ResourceGroup)) -Tags $configurationData.Tags -ErrorAction Stop
        if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $AzureRmAutomationAccount -Severity I -Category "AzureRmAutomationAccount" } Catch {} }
        Write-Output $AzureRmAutomationAccount
    } catch {
        if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $_ -Severity E -Category "AzureRmAutomationAccount" } Catch {} }
        Write-Error $_
    }
} Else { if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $AzureRmAutomationAccount -Severity I -Category "AzureRmAutomationAccount" } Catch {} } }

# Create Azure Automation run as account
if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message "Get-AzureRmAutomationCertificate -AutomationAccountName $($ConfigurationData.SaaSService.ResourceGroup) -ResourceGroupName $($ConfigurationData.SaaSService.ResourceGroup) -Name AzureRunAsCertificate -ErrorAction SilentlyContinue" -Severity I -Category "AzureRmAutomationCertificate" } Catch {} }
If ($AzureRmAutomationAccount -and -not ($AzureRmAutomationCertificate = Get-AzureRmAutomationCertificate -AutomationAccountName $($ConfigurationData.SaaSService.ResourceGroup) -ResourceGroupName $($ConfigurationData.SaaSService.ResourceGroup) -Name "AzureRunAsCertificate" -ErrorAction SilentlyContinue)) {
    $createRunasAccountParams = @{
        ResourceGroup               = $($ConfigurationData.SaaSService.ResourceGroup)
        AutomationAccountName       = $($ConfigurationData.SaaSService.ResourceGroup)
        SubscriptionId              = $azureRmContext.Subscription.Id
        ApplicationDisplayName      = "$($ConfigurationData.SaaSService.ResourceGroup)-AutomationRunAs"
        SelfSignedCertPlainPassword = $(-join ([char[]](65..90+97..122)*100 | Get-Random -Count 19) + "!")
        CreateClassicRunAsAccount   = $false
    }
    
    try {
        if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message "CreateAzureRunAsAccount -$($createRunasAccountParams.Keys.ForEach({"$_ '$($createRunasAccountParams.$_)'"}) -join ' -')" -Severity I -Category "AzureRunAsAccount" } Catch {} }
        $CreateAzureRunAsAccount = CreateAzureRunAsAccount @createRunasAccountParams -ErrorAction Stop
        if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $CreateAzureRunAsAccount -Severity I -Category "CreateAzureRunAsAccount" } Catch {} }
        Write-Output $CreateAzureRunAsAccount
    } catch {
        if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $_ -Severity E -Category "AzureRunAsAccount" } Catch {} }
        Write-Error $_
    }
} Else { if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $AzureRmAutomationCertificate -Severity I -Category "AzureRmAutomationCertificate" } Catch {} } }

# Create an Azure Automation Account
if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message "Get-AzureRmAutomationCredential -AutomationAccountName $($ConfigurationData.SaaSService.ResourceGroup) -Name $($ConfigurationData.GlobalConfiguration.AzureRmAutomationAccount.Name) -ResourceGroupName $($ConfigurationData.SaaSService.ResourceGroup) -ErrorAction SilentlyContinue" -Severity I -Category "AzureRmAutomationCredential" } Catch {} }
If ($AzureRmAutomationAccount -and -not ($AzureRmAutomationCredential = Get-AzureRmAutomationCredential -AutomationAccountName $($ConfigurationData.SaaSService.ResourceGroup) -Name $ConfigurationData.GlobalConfiguration.AzureRmAutomationAccount.Name -ResourceGroupName $($ConfigurationData.SaaSService.ResourceGroup) -ErrorAction SilentlyContinue))
{
    Write-Output "$Header`nAdding AzureRmAutomationCredential`n$Header"

    $pw = ConvertTo-SecureString $(-join ([char[]](65..90+97..122)*100 | Get-Random -Count 19) + "!") -AsPlainText -Force

    try {
        if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message "New-Object –TypeName System.Management.Automation.PSCredential –ArgumentList $($ConfigurationData.GlobalConfiguration.AzureRmAutomationAccount.Name)" -Severity I -Category "AzureRmAutomationCredential" } Catch {} }
        $AzureRmAutomationCredential = New-Object –TypeName System.Management.Automation.PSCredential –ArgumentList $ConfigurationData.GlobalConfiguration.AzureRmAutomationAccount.Name, $pw
        if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message "New-AzureRmAutomationCredential -AutomationAccountName $($ConfigurationData.SaaSService.ResourceGroup) -Name $($ConfigurationData.GlobalConfiguration.AzureRmAutomationAccount.Name) -Description $($ConfigurationData.AzureRmAutomationAccount.Description) -Value $AzureRmAutomationCredential -ResourceGroupName $($ConfigurationData.SaaSService.ResourceGroup)" -Severity I -Category "AzureRmAutomationCredential" } Catch {} }
        $nAzureRmAutomationCredential = New-AzureRmAutomationCredential -AutomationAccountName $($ConfigurationData.SaaSService.ResourceGroup) -Name $ConfigurationData.GlobalConfiguration.AzureRmAutomationAccount.Name -Description $ConfigurationData.AzureRmAutomationAccount.Description -Value $AzureRmAutomationCredential -ResourceGroupName $($ConfigurationData.SaaSService.ResourceGroup) -ErrorAction Stop
        if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $nAzureRmAutomationCredential -Severity I -Category "AzureRmAutomationCredential" } Catch {} }
        Write-Output $nAzureRmAutomationCredential
    } catch {
        if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $_ -Severity E -Category "AzureRmAutomationCredential" } Catch {} }
        Write-Error $_
    }
} Else { if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $AzureRmAutomationCredential -Severity I -Category "AzureRmAutomationCredential" } Catch {} } }

#region Register Microsoft.Network for Azure DNS Services
If (-not($AzureRmResourceProvider = Get-AzureRmResourceProvider -ProviderNamespace Microsoft.Network -ErrorAction SilentlyContinue)) {
    Write-Output "$Header`nRegister-AzureRmResourceProvider`n$Header"

    if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message "Register-AzureRmResourceProvider -ProviderNamespace Microsoft.Network" -Severity I -Category "AzureRmResourceProvider" } Catch {} }

    Try {
        $AzureRmResourceProvider = Register-AzureRmResourceProvider -ProviderNamespace Microsoft.Network -ErrorAction Stop -WhatIf

        Write-Output ""
    }
    Catch {
        if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $_ -Severity E -Category "AzureRmResourceProvider" } Catch {} }

        Write-Error $_
    }
}
If (!$AzureRmResourceProvider) { Break }
#endregion

#region Create DNS Zone
$AzureRmDnsZoneName = $Directory
If (-not($AzureRmDnsZone = Get-AzureRmDnsZone -Name $AzureRmDnsZoneName –ResourceGroupName $ConfigurationData.SaaSService.ResourceGroup -ErrorAction SilentlyContinue)) {
    Write-Output "$Header`nNew-AzureRmDnsZone`n$Header"

    $AzureRmDnsZoneParams = @{
        Name              = $AzureRmDnsZoneName
        ResourceGroupName = $ConfigurationData.SaaSService.ResourceGroup
        Tag               = $ConfigurationData.SaaSService.Tags
    }

    if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message "New-AzureRmDnsZone -$($AzureRmDnsZoneParams.Keys.ForEach({"$_ '$($AzureRmDnsZoneParams.$_)'"}) -join ' -')" -Severity I -Category "AzureRmDnsZone" } Catch {} }

    Try {
        $AzureRmDnsZone = New-AzureRmDnsZone @AzureRmDnsZoneParams -ErrorAction Stop

        if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $AzureRmDnsZone -Severity I -Category "AzureRmDnsZone" } Catch {} }

        Write-Output $AzureRmDnsZone
    }
    Catch {
        if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $_ -Severity E -Category "AzureRmDnsZone" } Catch {} }

        Write-Error $_
    }
}
Else {
    if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $AzureRmDnsZone -Severity I -Category "AzureRmDnsZone" } Catch {} }
}
If (!$AzureRmDnsZone) { Break }
#endregion

#region Create Resource Group
ForEach ($ResourceGroup in $ConfigurationData.ResourceGroups) {

    #Verify AzureRmResourceGroup
    Write-Output "$Header`nAzureRmResourceGroup: $($ResourceGroup.Name)`n$Header"
    Write-Output ""

    If (-not($AzureRmResourceGroup = Get-AzureRmResourceGroup -Name $ResourceGroup.Name -ErrorAction SilentlyContinue)) {

        Write-Output "New-AzureRmResourceGroup`n$Header"

        $AzureRmResourceGroupParams = @{
            Name     = $ResourceGroup.Name
            Location = $ResourceGroup.Location
            Tag      = $ResourceGroup.Tags
        }

        if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message "New-AzureRmResourceGroup -$($AzureRmResourceGroupParams.Keys.ForEach({"$_ '$($AzureRmResourceGroupParams.$_)'"}) -join ' -')" -Severity I -Category "AzureRmResourceGroup" } Catch {} }

        Try {
            $AzureRmResourceGroup = New-AzureRmResourceGroup @AzureRmResourceGroupParams -ErrorAction Stop

            if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $AzureRmResourceGroup -Severity I -Category "AzureRmResourceGroup" } Catch {} }

            Write-Output $AzureRmResourceGroup
        }
        Catch {
            if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $_ -Severity E -Category "AzureRmResourceGroup" } Catch {} }

            Write-Error $_
        }
    }
    Else {
        if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $AzureRmResourceGroup -Severity I -Category "AzureRmResourceGroup" } Catch {} }
        
        Write-Output $AzureRmResourceGroup
    }

    If (!$AzureRmResourceGroup) { Break }

    #Verify AzureRmStorageAccount
    $AzureRmStorageAccountName = Remove-IllegalCharactersFromString -String ($ResourceGroup.Storage.Name.Replace("[ResourceGroup]",$ResourceGroup.Name)).ToLower()

    If ($AzureRmResourceGroup -and -not ($AzureRmStorageAccount = Get-AzureRmStorageAccount -ResourceGroupName $ResourceGroup.Name -Name $AzureRmStorageAccountName -ErrorAction SilentlyContinue))
    {
        Write-Output "New-AzureRmStorageAccount`n$Header"
        Write-Output "This process may take several minutes..."

        If ($ResourceGroup.Storage.GlobalConfiguration) {  
            $AzureRmStorageAccountParams = @{
                Name              = $AzureRmStorageAccountName
                ResourceGroupName = $ResourceGroup.Name
                Type              = $ConfigurationData.GlobalConfiguration.Storage.Type
                Location          = $ResourceGroup.Location
                Tag               = $ResourceGroup.Tags
            }
        }
        Else {
            $AzureRmStorageAccountParams = @{
                Name              = $AzureRmStorageAccountName
                ResourceGroupName = $ResourceGroup.Name
                Type              = $ResourceGroup.Storage.Type
                Location          = $ResourceGroup.Location
                Tag               = $ResourceGroup.Tags
            }
        }

        if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message "New-AzureRmStorageAccount -$($AzureRmStorageAccountParams.Keys.ForEach({"$_ '$($AzureRmStorageAccountParams.$_)'"}) -join ' -')" -Severity I -Category "AzureRmStorageAccount" } Catch {} }

        Try {
            $AzureRmStorageAccount = New-AzureRmStorageAccount @AzureRmStorageAccountParams -ErrorAction Stop

            if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $AzureRmStorageAccount -Severity I -Category "AzureRmStorageAccount" } Catch {} }

            Write-Output $AzureRmStorageAccount
        } Catch {
            if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $_ -Severity E -Category "AzureRmStorageAccount" } Catch {} }

            Write-Error $_
        }

        If (!$AzureRmStorageAccount) { Break }

        $Keys = Get-AzureRmStorageAccountKey -ResourceGroupName $ResourceGroup.Name -Name $AzureRmStorageAccountName
        $StorageContext = New-AzureStorageContext -StorageAccountName $AzureRmStorageAccountName -StorageAccountKey $Keys[0].Value

        if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $Keys -Severity I -Category "AzureRmStorageAccount" } Catch {} }
        if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $StorageContext -Severity I -Category "AzureRmStorageAccount" } Catch {} }
    }
    Else
    {
        $Keys = Get-AzureRmStorageAccountKey -ResourceGroupName $ResourceGroup.Name -Name $AzureRmStorageAccountName
        $StorageContext = New-AzureStorageContext -StorageAccountName $AzureRmStorageAccountName $Keys[0].Value

        if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $Keys -Severity I -Category "AzureRmStorageAccount" } Catch {} }
        if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $StorageContext -Severity I -Category "AzureRmStorageAccount" } Catch {} }
    }

    #Verify CORS rules
    If ($StorageContext) {
        $cRules = Get-AzureStorageCORSRule -ServiceType Blob -Context $StorageContext

        $cUpdate = $False
        If ($ResourceGroup.CorsRules.GlobalConfiguration) {
            ForEach ($CorsRule in $ConfigurationData.GlobalConfiguration.CorsRules.Keys)
            {
                If (!([string]$cRules.$CorsRule -eq [string]$ConfigurationData.GlobalConfiguration.CorsRules.$CorsRule))
                {
                    $cUpdate = $True
                    Break
                }
            }
        }
        Else {
            ForEach ($CorsRule in $ResourceGroup.CorsRules.Keys)
            {
                If (!([string]$cRules.$CorsRule -eq [string]$ResourceGroup.CorsRules.$CorsRule))
                {
                    $cUpdate = $True
                    Break
                }
            }
        }

        If ($cUpdate)
        {
            Write-Output "Set-AzureStorageCORSRule`n$Header"

            If ($ResourceGroup.CorsRules.GlobalConfiguration) {
                $AzureStorageCORSRuleParams = @{
                    ServiceType = "Blob"
                    Context     = $StorageContext
                    CorsRules   = $ConfigurationData.GlobalConfiguration.CorsRules
                }
            }
            Else {
                $AzureStorageCORSRuleParams = @{
                    ServiceType = "Blob"
                    Context     = $StorageContext
                    CorsRules   = $ResourceGroup.CorsRules
                }
            }

            if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message "Set-AzureStorageCORSRule -$($AzureStorageCORSRuleParams.Keys.ForEach({"$_ '$($AzureStorageCORSRuleParams.$_)'"}) -join ' -')" -Severity I -Category "AzureStorageCORSRule" } Catch {} }

            Try {
                Set-AzureStorageCORSRule @AzureStorageCORSRuleParams -ErrorAction Stop

                $GetAzureStorageCORSRule = Get-AzureStorageCORSRule -ServiceType Blob -Context $StorageContext

                if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $GetAzureStorageCORSRule -Severity I -Category "AzureStorageCORSRule" } Catch {} }

                Write-Host $GetAzureStorageCORSRule

                Write-Output ""
            }
            Catch {
                if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $_ -Severity E -Category "AzureStorageCORSRule" } Catch {} }

                Write-Error $_
            }
        }
    }

    #Verify AzureStorageContainer
    $AzureStorageContainerHeader = $True

    $Containers = $null
    If ($ResourceGroup.Storage.GlobalConfiguration) {
        $Containers = $ConfigurationData.GlobalConfiguration.Storage.Containers
    }
    Else {
        $Containers = $ResourceGroup.Storage.Containers
    }

    ForEach ($Container in $Containers) {
        If ($AzureRmResourceGroup -and $AzureRmStorageAccount -and -not($AzureStorageContainer = Get-AzureStorageContainer -Name $Container -Context $StorageContext -ErrorAction SilentlyContinue))
        {
            Write-Output "New-AzureStorageContainer`n$Header"

            $AzureStorageContainerParams = @{
                Name       = $Container
                Permission = "Off"
                Context    = $StorageContext
            }

            if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message "New-AzureStorageContainer -$($AzureStorageContainerParams.Keys.ForEach({"$_ '$($AzureStorageContainerParams.$_)'"}) -join ' -')" -Severity I -Category "AzureStorageContainer" } Catch {} }

            Try {
                $AzureStorageContainer = New-AzureStorageContainer @AzureStorageContainerParams -ErrorAction Stop

                if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $AzureStorageContainer -Severity I -Category "AzureStorageContainer" } Catch {} }

                Write-Output $AzureStorageContainer
            }
            Catch {
                if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $_ -Severity E -Category "AzureStorageContainer" } Catch {} }

                Write-Error $_
            }
        }
        Else {
            if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $AzureStorageContainer -Severity I -Category "AzureStorageContainer" } Catch {} }
        }
    }

    #Verify AzureRmAutomationAccount
    If ($ResourceGroup.AzureRmAutomationAccount.Name) {

        $AzureRmAutomationAccountName = $ResourceGroup.AzureRmAutomationAccount.Name.Replace("[ResourceGroup]",$ResourceGroup.Name)

        If ($AzureRmResourceGroup -and -not($AzureRmAutomationAccount = Get-AzureRmAutomationAccount -ResourceGroupName $ResourceGroup.Name -Name $AzureRmAutomationAccountName -ErrorAction SilentlyContinue)) {
            Write-Output "New-AzureRmAutomationAccount`n$Header"

            $AzureRmAutomationAccountParams = @{
                ResourceGroupName = $ResourceGroup.Name
                Location          = $ResourceGroup.Location
                Name              = $AzureRmAutomationAccountName
                Tags              = $ResourceGroup.Tags
            }

            if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message "New-AzureRmAutomationAccount -$($AzureRmAutomationAccountParams.Keys.ForEach({"$_ '$($AzureRmAutomationAccountParams.$_)'"}) -join ' -')" -Severity I -Category "AzureRmAutomationAccount" } Catch {} }

            Try {
                $AzureRmAutomationAccount = New-AzureRmAutomationAccount @AzureRmAutomationAccountParams -ErrorAction Stop

                if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $AzureRmAutomationAccount -Severity I -Category "AzureRmAutomationAccount" } Catch {} }

                Write-Output $AzureRmAutomationAccount
            }
            Catch {
                if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $_ -Severity E -Category "AzureRmAutomationAccount" } Catch {} }

                Write-Error $_
            }
        }
        Else {
            if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $AzureRmAutomationAccount -Severity I -Category "AzureRmResourceGroup" } Catch {} }
        }

        #Verify AzureRmAutomationCredential
        ForEach ($AutomationCredential in $ResourceGroup.AzureRmAutomationAccount.AzureRmAutomationCredential) {

            $AutomationCredentialName = $AutomationCredential.Name.Replace("[ResourceGroup]",$ResourceGroup.Name)

            If (-not ($AzureRmAutomationCredential = Get-AzureRmAutomationCredential -AutomationAccountName $AzureRmAutomationAccountName -Name $AutomationCredentialName -ResourceGroupName $ResourceGroup.Name -ErrorAction SilentlyContinue))
            {
                Write-Output "New-AzureRmAutomationCredential`n$Header"

                $pw = ConvertTo-SecureString $(-join ([char[]](65..90+97..122)*100 | Get-Random -Count 19) + "!") -AsPlainText -Force
                $AzureRmAutomationCredential = New-Object –TypeName System.Management.Automation.PSCredential –ArgumentList $AutomationCredentialName, $pw

                $AzureRmAutomationCredentialParams = @{
                    AutomationAccountName = $AzureRmAutomationAccountName
                    Name                  = $AutomationCredentialName
                    Description           = $AutomationCredential.Description
                    ResourceGroupName     = $ResourceGroup.Name
                    Value                 = $AzureRmAutomationCredential
                }

                if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message "New-AzureRmAutomationCredential -$($AzureRmAutomationCredentialParams.Keys.ForEach({"$_ '$($AzureRmAutomationCredentialParams.$_)'"}) -join ' -')" -Severity I -Category "AzureRmAutomationCredential" } Catch {} }
        
                Try {
                    $AzureRmAutomationCredential = New-AzureRmAutomationCredential @AzureRmAutomationCredentialParams -ErrorAction Stop

                    if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $AzureRmAutomationCredential -Severity I -Category "AzureRmAutomationCredential" } Catch {} }

                    Write-Output $AzureRmAutomationCredential
                }
                Catch {
                    if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $_ -Severity E -Category "AzureRmAutomationCredential" } Catch {} }

                    Write-Error $_
                }
            }
        }

        #Verify AzureRmAutomationVariable
        ForEach ($AutomationVariable in $ResourceGroup.AzureRmAutomationAccount.AzureRmAutomationVariable) {
            If (-not (Get-AzureRmAutomationVariable -AutomationAccountName $AzureRmAutomationAccountName -Name $AutomationVariable.Name -ResourceGroupName $ResourceGroup.Name -ErrorAction SilentlyContinue))
            {
                Write-Output "New-AzureRmAutomationVariable`n$Header"

                $AzureRmAutomationVariableRedistPathParams = @{
                    AutomationAccountName = $AzureRmAutomationAccountName
                    Name                  = $AutomationVariable.Name
                    Value                 = $AutomationVariable.Value
                    Encrypted             = $AutomationVariable.Encrypted
                    ResourceGroupName     = $ResourceGroup.Name
                }

                if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message "New-AzureRmAutomationVariable -$($AzureRmAutomationVariableRedistPathParams.Keys.ForEach({"$_ '$($AzureRmAutomationVariableRedistPathParams.$_)'"}) -join ' -')" -Severity I -Category "AzureRmAutomationVariable" } Catch {} }
        
                Try {
                    $AzureRmAutomationVariable = New-AzureRmAutomationVariable @AzureRmAutomationVariableRedistPathParams -ErrorAction Stop

                    if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $AzureRmAutomationVariable -Severity I -Category "AzureRmAutomationVariable" } Catch {} }

                    Write-Output $AzureRmAutomationVariable
                }
                Catch {
                    if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $_ -Severity E -Category "AzureRmAutomationVariable" } Catch {} }

                    Write-Error $_
                }
            }
        }
    }

    #Verify Relay Namespace
    If (!($AzureRmRelayNamespace = Get-AzureRmRelayNamespace -ResourceGroupName $ResourceGroup.Name -Name $ResourceGroup.HybridConnection.Namespace -ErrorAction SilentlyContinue)) {
        if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message "New-AzureRmRelayNamespace -ResourceGroupName $($ResourceGroup.Name) -Name $($ResourceGroup.HybridConnection.Namespace) -Location $($ResourceGroup.Location)" -Severity I -Category "AzureRmRelayNamespace" } Catch {} }
        Try {
            $AzureRmRelayNamespace = New-AzureRmRelayNamespace -ResourceGroupName $ResourceGroup.Name -Name $ResourceGroup.HybridConnection.Namespace -Location $ResourceGroup.Location -ErrorAction Stop

            if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $AzureRmRelayNamespace -Severity I -Category "AzureRmRelayNamespace" } Catch {} }

            Write-Output $AzureRmRelayNamespace
        }
        Catch {
            if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $_ -Severity E -Category "AzureRmRelayNamespace" } Catch {} }

            Write-Error $_
        }
    } Else {
        if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $AzureRmRelayNamespace -Severity I -Category "AzureRmRelayNamespace" } Catch {} }
    }

    #Verify Hybrid Connection
    If (!($AzureRmRelayHybridConnection = Get-AzureRmRelayHybridConnection -ResourceGroupName $ResourceGroup.Name -Name $ResourceGroup.HybridConnection.Name -Namespace $ResourceGroup.HybridConnection.Namespace -ErrorAction SilentlyContinue)) {
        if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message "New-AzureRmRelayHybridConnection -ResourceGroupName $($ResourceGroup.Name) -Namespace $($ResourceGroup.HybridConnection.Namespace) -Name $($ResourceGroup.HybridConnection.Names) -RequiresClientAuthorization $True" -Severity I -Category "AzureRmRelayHybridConnection" } Catch {} }
        Try {
            $AzureRmRelayHybridConnection = New-AzureRmRelayHybridConnection -ResourceGroupName $ResourceGroup.Name -Namespace $ResourceGroup.HybridConnection.Namespace -Name $ResourceGroup.HybridConnection.Name -RequiresClientAuthorization $True

            if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $AzureRmRelayHybridConnection -Severity I -Category "AzureRmRelayHybridConnection" } Catch {} }

            Write-Output $AzureRmRelayNamespace
        }
        Catch {
            if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $_ -Severity E -Category "AzureRmRelayHybridConnection" } Catch {} }

            Write-Error $_
        }
    } Else {
        if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $AzureRmRelayHybridConnection -Severity I -Category "AzureRmRelayHybridConnection" } Catch {} }
    }

    #Verify App Service Plan
    $AzureRmAppServicePlanName = $ResourceGroup.AppServicePlan.Name.Replace("[ResourceGroup]",$ResourceGroup.Name)

    $AzureRmAppServicePlanName = Remove-IllegalCharactersFromString -String $AzureRmAppServicePlanName.ToLower()
    If ($AzureRmAppServicePlanName.Length -lt $configurationData.GlobalConfiguration.ShortNameCharacters) {
        $AzureRmAppServicePlanName = "$AzureRmAppServicePlanName$(Get-TruncatedStringHash -String $AzureRmAppServicePlanName -Length ($configurationData.GlobalConfiguration.ShortNameCharacters - $AzureRmAppServicePlanName.Length))"
    } else {
        $AzureRmAppServicePlanName = $AzureRmAppServicePlanName.SubString(0,$configurationData.GlobalConfiguration.ShortNameCharacters)
    }

    If (-not($AzureRmAppServicePlan = Get-AzureRmAppServicePlan -Name $AzureRmAppServicePlanName -ResourceGroupName $ResourceGroup.Name -ErrorAction SilentlyContinue)) {
        
        Write-Output "New-AzureRmAppServicePlan`n$Header"

        $AzureRmAppServicePlanParams = @{
            Name              = $AzureRmAppServicePlanName
            Location          = $ResourceGroup.Location
            ResourceGroupName = $ResourceGroup.Name
            Tier              = $ResourceGroup.AppServicePlan.Tier
        }

        if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message "New-AzureRmAppServicePlan -$($AzureRmAppServicePlanParams.Keys.ForEach({"$_ '$($AzureRmAppServicePlanParams.$_)'"}) -join ' -')" -Severity I -Category "AzureRmAppServicePlan" } Catch {} }

        Try {
            $AzureRmAppServicePlan = New-AzureRmAppServicePlan @AzureRmAppServicePlanParams -ErrorAction Stop

            if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $AzureRmAppServicePlan -Severity I -Category "AzureRmAppServicePlan" } Catch {} }

            Write-Output $AzureRmAppServicePlan
        }
        Catch {
            if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $_ -Severity E -Category "AzureRmAppServicePlan" } Catch {} }

            Write-Error $_
        }
    }
    Else {
        if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $AzureRmAppServicePlan -Severity I -Category "AzureRmAppServicePlan" } Catch {} }
    }
    If (!$AzureRmAppServicePlan) { Break }

    #Verify Web App
    ForEach ($AzureRmWebAppKeys in $ResourceGroup.WebApp.Keys) {
        $AzureRmWebAppName = $AzureRmWebAppKeys.Replace("[ResourceGroup]",$ResourceGroup.Name)

        $AzureRmWebAppName = Remove-IllegalCharactersFromString -String $AzureRmWebAppName.ToLower()
        If ($AzureRmWebAppName.Length -lt $configurationData.GlobalConfiguration.ShortNameCharacters) {
            $AzureRmWebAppName = "$AzureRmWebAppName$(Get-TruncatedStringHash -String $AzureRmWebAppName -Length ($configurationData.GlobalConfiguration.ShortNameCharacters - $AzureRmWebAppName.Length))"
        } else {
            $AzureRmWebAppName = $AzureRmWebAppName.SubString(0,$configurationData.GlobalConfiguration.ShortNameCharacters)
        }

        #Verify AzureRmDnsRecordSet
        $DnsRecordSetName = $AzureRmWebAppName

        If ($ResourceGroup.DnsRecordSet.GlobalConfiguration) {
            $RecordType = $ConfigurationData.GlobalConfiguration.DnsRecordSet.RecordType
            $Ttl        = $ConfigurationData.GlobalConfiguration.DnsRecordSet.Ttl
            $DnsRecords = $ConfigurationData.GlobalConfiguration.DnsRecordSet.DnsRecords
        }
        Else {
            $RecordType = $ResourceGroup.DnsRecordSet.RecordType
            $Ttl        = $ResourceGroup.DnsRecordSet.Ttl
            $DnsRecords = $ResourceGroup.DnsRecordSet.DnsRecords
        }

        If (-not($AzureRmDnsRecordSet = Get-AzureRmDnsRecordSet -Name $DnsRecordSetName -RecordType $RecordType -ZoneName $AzureRmDnsZoneName -ResourceGroupName $ConfigurationData.SaaSService.ResourceGroup -ErrorAction SilentlyContinue)) {
            Write-Output "New-AzureRmDnsRecordSet`n$Header"

            $AzureRmDnsRecordSetParams = $null

            If ($RecordType -eq "CNAME") {
                $DnsRecordsValue = $DnsRecords.Replace("[ResourceGroup]",$DnsRecordSetName)
                $DnsRecords = (New-AzureRmDnsRecordConfig -Cname $DnsRecordsValue)
            }
            Else {
                $DnsRecords = (New-AzureRmDnsRecordConfig -IPv4Address $DnsRecordSet.DnsRecords)
            }

            $AzureRmDnsRecordSetParams = @{
                Name                   = $DnsRecordSetName
                RecordType             = $RecordType
                ZoneName               = $AzureRmDnsZoneName
                ResourceGroupName      = $ConfigurationData.SaaSService.ResourceGroup
                Ttl                    = $Ttl
                DnsRecords             = $DnsRecords
            }

            if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message "New-AzureRmDnsRecordSet -$($AzureRmDnsRecordSetParams.Keys.ForEach({"$_ '$($AzureRmDnsRecordSetParams.$_)'"}) -join ' -')" -Severity I -Category "AzureRmDnsRecordSet" } Catch {} }

            Try {
                $AzureRmDnsRecordSet = New-AzureRmDnsRecordSet @AzureRmDnsRecordSetParams -ErrorAction Stop

                if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $AzureRmDnsRecordSet -Severity I -Category "AzureRmDnsRecordSet" } Catch {} }

                Write-Output $AzureRmDnsRecordSet
            }
            Catch {
                if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $_ -Severity E -Category "AzureRmDnsRecordSet" } Catch {} }

                Write-Error $_
            }
        }
        If (!$AzureRmDnsRecordSet) { Break }

        $NewAzureRmWebApp = $False

        If (-not($AzureRmWebApp = Get-AzureRmWebApp -Name $AzureRmWebAppName -ResourceGroupName $ResourceGroup.Name -ErrorAction SilentlyContinue)) {
            Write-Output "New-AzureRmWebApp`n$Header"

            $NewAzureRmWebApp = $True

            $AzureRmWebAppParams = @{
                Name              = $AzureRmWebAppName
                Location          = $ResourceGroup.Location
                ResourceGroupName = $ResourceGroup.Name
                AppServicePlan    = $AzureRmAppServicePlanName
            }

            if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message "New-AzureRmWebApp -$($AzureRmWebAppParams.Keys.ForEach({"$_ '$($AzureRmWebAppParams.$_)'"}) -join ' -')" -Severity I -Category "AzureRmWebApp" } Catch {} }

            Try {
                $AzureRmWebApp = New-AzureRmWebApp @AzureRmWebAppParams -ErrorAction Stop

                if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $AzureRmWebApp -Severity I -Category "AzureRmWebApp" } Catch {} }

                Write-Output $AzureRmWebApp

                Start-Sleep 30
            }
            Catch {
                if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $_ -Severity E -Category "AzureRmWebApp" } Catch {} }

                Write-Error $_
            }
        }
        Else {
            if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $AzureRmWebApp -Severity I -Category "AzureRmWebApp" } Catch {} }
        }

        If (!$AzureRmWebApp) { Break }

        If ($ResourceGroup.AppServicePlan.Tier -ne "Free") {
            If (!($AzureRmWebApp.HostNames -like "*$AzureRmWebAppName.$Directory*")) {
                Write-Output "Set-AzureRmWebApp`n$Header"

                $SetAzureRmWebAppParams = @{
                    Name              = $AzureRmWebAppName
                    ResourceGroupName = $ResourceGroup.Name
                    HostNames         = @("$AzureRmWebAppName.$Directory","$AzureRmWebAppName.azurewebsites.net")
                }

                if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message "Set-AzureRmWebApp -$($SetAzureRmWebAppParams.Keys.ForEach({"$_ '$($SetAzureRmWebAppParams.$_)'"}) -join ' -')" -Severity I -Category "AzureRmWebApp" } Catch {} }
            
                Try {
                    $SetAzureRmWebApp = Set-AzureRmWebApp @SetAzureRmWebAppParams -ErrorAction Stop

                    if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $SetAzureRmWebApp -Severity I -Category "AzureRmWebApp" } Catch {} }

                    Write-Output $SetAzureRmWebApp
                }
                Catch {
                    if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $_ -Severity E -Category "AzureRmWebApp" } Catch {} }

                    Write-Error $_
                }
            }
        }

        If ($NewAzureRmWebApp -or $ResourceGroup.WebApp.$AzureRmWebAppKeys.AlwaysUpdate) {
            #Upload Zip binaries
            For ($x=1; $x -le 9; $x++)
            {
                Try {
                    $UrlStatusCode = (Invoke-WebRequest -Uri "https://$AzureRmWebAppName.$($ConfigurationData.GlobalConfiguration.KuduAPI.URI)" -UseBasicParsing -DisableKeepAlive).StatusCode
                    If ($UrlStatusCode -ne "200") {
                        Start-Sleep 5
                    } Else { Break }
                }
                Catch { Start-Sleep 5 }
            }

            Write-Output "Remove-FilesFromWebApp`n$Header"

            Remove-FilesFromWebApp -WebAppName $AzureRmWebAppName -ResourceGroupName $ResourceGroup.Name -Verbose
        
            Write-Output ""

            Write-Output "Set-FileToWebApp`n$Header"

            $FileToWebAppParams = @{
                WebAppName        = $AzureRmWebAppName
                FileName          = $ResourceGroup.WebApp.$AzureRmWebAppKeys.SourceRepo
                ResourceGroupName = $ResourceGroup.Name
            }

            if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message "New-AzureRmWebApp -$($FileToWebAppParams.Keys.ForEach({"$_ '$($FileToWebAppParams.$_)'"}) -join ' -')" -Severity I -Category "FileToWebApp" } Catch {} }

            Try {
                $FileToWebApp = Set-FileToWebApp @FileToWebAppParams -Verbose
    
                if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $FileToWebApp -Severity I -Category "FileToWebApp" } Catch {} }

                Write-Output $FileToWebApp
            }
            Catch {
                if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $_ -Severity E -Category "FileToWebApp" } Catch {} }

                Write-Error $_
            }
        }

        #Define App Settings properties
        $AppSettings = @{}
        If ($ResourceGroup.WebApp.$AzureRmWebAppKeys.AppSettings.Keys) {
            ForEach ($variable in $ResourceGroup.WebApp.$AzureRmWebAppKeys.AppSettings.Keys) {
                $value = $ResourceGroup.WebApp.$AzureRmWebAppKeys.AppSettings.$variable
                @("[","]") | ForEach-Object { $value = $value.Replace($_,"") }
                $prop = $value.Split(".")[-1]
                @("_","-") | ForEach-Object { $prop = $prop.Replace($_,"") }
                New-Variable -Name $value -Value "`$ConfigurationData.$value" -Force
                If (($AzureKeyVaultSecret = (Get-AzureKeyVaultSecret $AzureRmKeyVaultName -Name $prop).SecretValueText) -ne $value) {
                    $value = $AzureKeyVaultSecret
                }
                $value = $value.Replace("[ResourceGroup]",$ResourceGroup.Name)
                $value = $value.Replace("[Key]",$Keys[0].Value)
                $AppSettings.add($variable,$value)
            }
        }
        Else {
            If ($ResourceGroup.WebApp.$AzureRmWebAppKeys.GlobalConfiguration) {
                If ($ConfigurationData.SaaSService.KeyVault.Secrets.AppSettings.Keys) {
                    ForEach ($variable in $ConfigurationData.SaaSService.KeyVault.Secrets.AppSettings.Keys) {
                        $value = $ConfigurationData.SaaSService.KeyVault.Secrets.AppSettings.$variable
                        @("[","]") | ForEach-Object { $value = $value.Replace($_,"") }
                        $prop = $variable
                        @("_","-") | ForEach-Object { $prop = $prop.Replace($_,"") }
                        New-Variable -Name $value -Value "`$ConfigurationData.$value" -Force
                        If (($AzureKeyVaultSecret = (Get-AzureKeyVaultSecret $AzureRmKeyVaultName -Name $prop).SecretValueText) -ne $value) {
                            $value = $AzureKeyVaultSecret
                        }
                        $value = $value.Replace("[ResourceGroup]",$ResourceGroup.Name)
                        $value = $value.Replace("[Key]",$Keys[0].Value)
                        $AppSettings.add($variable,$value)
                    }
                }
            }
        }

        $MyAzureRmWebApp = Get-AzureRmWebApp -Name $AzureRmWebAppName -ResourceGroupName $ResourceGroup.Name | Select -ExpandProperty SiteConfig | Select -ExpandProperty AppSettings

        [hashtable]$cAppSettings = @{}
        ForEach ($item in $MyAzureRmWebApp) {
            $cAppSettings.Add($item.Name,$item.Value)
        }

        [bool]$AppSettingsUpdate = $False

        ForEach ($Item in $AppSettings.Keys) {
            If ($cAppSettings.$Item -ne $AppSettings.$Item) {
                $AppSettingsUpdate = $True
                break
            }
        }

        ForEach ($Item in $cAppSettings.Keys) {
            If ($AppSettings.$Item -ne $cAppSettings.$Item) {
                $AppSettingsUpdate = $True
                break
            }
        }

        If ($AppSettingsUpdate) {
            $SetAzureRmWebAppParams = @{
                Name              = $AzureRmWebAppName
                ResourceGroupName = $ResourceGroup.Name
                AppSettings       = $AppSettings
            }

            Write-Output "Set-AzureRmWebApp`n$Header"

            if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message "Set-AzureRmWebApp -$($SetAzureRmWebAppParams.Keys.ForEach({"$_ '$($SetAzureRmWebAppParams.$_)'"}) -join ' -')" -Severity I -Category "AzureRmWebAppSettings" } Catch {} }

            Try {
                $null = Set-AzureRmWebApp @SetAzureRmWebAppParams -ErrorAction Stop

                if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $SetAzureRmWebAppParams.AppSettings -Severity I -Category "AzureRmWebAppSettings" } Catch {} }

                Write-Output $SetAzureRmWebAppParams.AppSettings.Keys
            }
            Catch {
                if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message $_ -Severity E -Category "AzureRmWebAppSettings" } Catch {} }

                Write-Error $_
            }
        }
    }
}
#endregion

$Measure.Stop()

Write-Output ""
Write-Output $Header
Write-Output "Completed in $(($Measure.Elapsed).TotalSeconds) seconds"
if ($configurationData.GlobalConfiguration.LogEnabled) { Try { Invoke-Logger -Message "Completed in $(($Measure.Elapsed).TotalSeconds) seconds" -Severity I -Category "TotalSeconds" } Catch {} }