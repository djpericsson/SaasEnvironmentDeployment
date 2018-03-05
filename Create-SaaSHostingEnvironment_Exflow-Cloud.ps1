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
If ($PSVersionTable.PSVersion -lt $ConfigurationData.PowerShell.Version) {
    $Message = "PowerShell must be updated to at least $($ConfigurationData.GlobalConfiguration.Prerequisites.PowerShell.Version)."
    Write-Warning $Message
    Invoke-Logger -Message $Message -Severity W -Category "PowerShell"
    $hasErrors = $True
} Else {
    $Message = "PowerShell version $($PSVersionTable.PSVersion) is valid."
    Write-Host $Message
    Invoke-Logger -Message $Message -Severity I -Category "PowerShell"
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

    Invoke-Logger -Message "Login-AzureRmAccount -SubscriptionId $($ConfigurationData.GlobalConfiguration.SubscriptionId)" -Severity I -Category "AzureRmAccount"

    Try {
        Login-AzureRmAccount -SubscriptionId $ConfigurationData.GlobalConfiguration.SubscriptionId -ErrorAction Stop

        Write-Output ""

        $azureRmContext = Get-AzureRmContext

        Invoke-Logger -Message $azureRmContext -Severity I -Category "AzureRmAccount"

        Write-Output $azureRmContext
    }
    Catch {
        Invoke-Logger -Message $_ -Severity E -Category "AzureRmAccount"

        Write-Error $_
    }
}

If ($azureRmContext.Subscription.Id -eq $null) { Break }
#endregion

#Set tenant variables based on logged on session
If ($azureRmContext.Account.Id) {
    $SignInName   = $azureRmContext.Account.Id
    $Subscription = "/subscriptions/$($azureRmContext.Subscription.Id)"
}
Else {
    $SignInName   = $azureRmContext.Context.Account.Id
    $Subscription = "/subscriptions/$($azureRmContext.Context.Subscription.Id)"
}

#region Verify AzureRmRoleAssignment to logged on user
If ($ConfigurationData.GlobalConfiguration.Prerequisites.AzureRmRoleAssignmentValidation) {
    Write-Output "$Header`nValidating AzureRmRoleAssignment`n$Header"

    Invoke-Logger -Message "Get-AzureRmRoleAssignment -Scope '/subscriptions/$($azureRmContext.Subscription.Id)' | Where-Object { (`$_.SignInName -eq $SignInName) -or (`$_.SignInName -like '$(($SignInName).Replace('@','_'))*')" -Severity I -Category "AzureRmRoleAssignment"

    $RoleAssignment = Get-AzureRmRoleAssignment -Scope "/subscriptions/$($azureRmContext.Subscription.Id)" | Where-Object { ($_.SignInName -eq $SignInName) -or ($_.SignInName -like "$(($SignInName).Replace("@","_"))*") }

    #Get AzureRmRoleAssignment for currently logged on user
    $AzureRmRoleAssignment = ($RoleAssignment).RoleDefinitionName

    $AzureRmRoleAssignment

    Invoke-Logger -Message $AzureRmRoleAssignment -Severity I -Category "AzureRmRoleAssignment"

    Write-Output ""

    #Determine that the currently logged on user has appropriate permissions to run the script in their Azure subscription
    If (-not ($AzureRmRoleAssignment -contains "Owner") -and -not ($AzureRmRoleAssignment -contains "Contributor")) {
        Write-Host ""
        Write-Warning "Owner or contributor permissions could not be verified for your subscription."
        Write-Host ""

        Try { Invoke-Logger -Message "Owner or contributor permissions could not be verified for your subscription" -Severity W -Category "AzureRmRoleAssignment" } Catch {}

        return
    }
}
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

    Invoke-Logger -Message "New-AzureRmResourceGroup -$($SaaSAzureRmResourceGroupParams.Keys.ForEach({"$_ '$($SaaSAzureRmResourceGroupParams.$_)'"}) -join ' -')" -Severity I -Category "SaaSAzureRmResourceGroup"

    Try {
        $SaaSAzureRmResourceGroup = New-AzureRmResourceGroup @SaaSAzureRmResourceGroupParams -ErrorAction Stop

        Invoke-Logger -Message $SaaSAzureRmResourceGroup -Severity I -Category "SaaSAzureRmResourceGroup"

        Write-Output $SaaSAzureRmResourceGroup
    }
    Catch {
        Invoke-Logger -Message $_ -Severity E -Category "SaaSAzureRmResourceGroup"

        Write-Error $_
    }
}
Else {
    Invoke-Logger -Message $SaaSAzureRmResourceGroup -Severity I -Category "SaaSAzureRmResourceGroup"

    Write-Output $SaaSAzureRmResourceGroup
}
#endregion

#region Create Azure Key Vault
If ($ConfigurationData.SaaSService.KeyVault) {
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

        Invoke-Logger -Message "New-AzureRmKeyVault -$($AzureRmKeyVaultParams.Keys.ForEach({"$_ '$($AzureRmKeyVaultParams.$_)'"}) -join ' -')" -Severity I -Category "AzureRmKeyVault"

        Try {
            $AzureRmKeyVault = New-AzureRmKeyVault @AzureRmKeyVaultParams -ErrorAction Stop

            Invoke-Logger -Message $AzureRmKeyVault -Severity I -Category "AzureRmKeyVault"

            Write-Output $AzureRmKeyVault
        }
        Catch {
            Invoke-Logger -Message $_ -Severity E -Category "AzureRmKeyVault"

            Write-Error $_
        }
    }
    Else {
        Invoke-Logger -Message $AzureRmKeyVault -Severity I -Category "AzureRmKeyVault"
    }
    If (!$AzureRmKeyVault) { Break }
}
#endregion

#region Create Azure Key Vault Secret
If ($ConfigurationData.SaaSService.KeyVault.Secrets) {
    ForEach ($Secret in $ConfigurationData.SaaSService.KeyVault.Secrets.Keys) {
        ForEach ($Value in $ConfigurationData.SaaSService.KeyVault.Secrets.$Secret.Keys) {
            $cleanValue = $Value
            @("_","-") | ForEach-Object { $cleanValue = $cleanValue.Replace($_,"") }
            If (-not($AzureKeyVaultSecret = (Get-AzureKeyVaultSecret -VaultName $AzureRmKeyVaultName -Name $cleanValue -ErrorAction SilentlyContinue).SecretValueText)) {
                Write-Output "Set-AzureKeyVaultSecret`n$Header"

                $AzureKeyVaultSecretParams = @{
                    Name        = $cleanValue
                    SecretValue = (ConvertTo-SecureString $($ConfigurationData.SaaSService.KeyVault.Secrets.$Secret.$Value) -AsPlainText -Force)
                    ContentType = $Secret
                    VaultName   = $AzureRmKeyVaultName
                }

                Invoke-Logger -Message "Set-AzureKeyVaultSecret -$($AzureKeyVaultSecretParams.Keys.ForEach({"$_ '$($AzureKeyVaultSecretParams.$_)'"}) -join ' -')" -Severity I -Category "AzureKeyVaultSecret"

                Try {
                    $AzureKeyVaultSecret = Set-AzureKeyVaultSecret @AzureKeyVaultSecretParams -ErrorAction Stop

                    Invoke-Logger -Message $AzureKeyVaultSecret -Severity I -Category "AzureKeyVaultSecret"

                    Write-Output $AzureKeyVaultSecret
                }
                Catch {
                    Invoke-Logger -Message $_ -Severity E -Category "AzureKeyVaultSecret"

                    Write-Error $_
                }
            }
        }
    }
}
#endregion

# Create Automation account if it doesnt exist
Invoke-Logger -Message "Get-AzureRmAutomationAccount -ResourceGroupName $($ConfigurationData.SaaSService.ResourceGroup) -Name $($ConfigurationData.SaaSService.ResourceGroup) -ErrorAction SilentlyContinue" -Severity I -Category "AzureRmAutomationAccount"
If ($SaaSAzureRmResourceGroup -and -not($AzureRmAutomationAccount = Get-AzureRmAutomationAccount -ResourceGroupName $($ConfigurationData.SaaSService.ResourceGroup) -Name $($ConfigurationData.SaaSService.ResourceGroup) -ErrorAction SilentlyContinue)) {
    Write-Output ""
    Write-Output "$Header`nCreating AzureRmAutomationAccount`n$Header"

    try {
        Invoke-Logger -Message "New-AzureRmAutomationAccount -ResourceGroupName $($($ConfigurationData.SaaSService.ResourceGroup)) -Location $($ConfigurationData.SaaSService.Location) -Name $($($ConfigurationData.SaaSService.ResourceGroup)) -Tags $($configurationData.Tags)" -Severity I -Category "AzureRmAutomationAccount"
        $AzureRmAutomationAccount = New-AzureRmAutomationAccount -ResourceGroupName $($($ConfigurationData.SaaSService.ResourceGroup)) -Location $($ConfigurationData.SaaSService.Location) -Name $($($ConfigurationData.SaaSService.ResourceGroup)) -Tags $configurationData.Tags -ErrorAction Stop
        Invoke-Logger -Message $AzureRmAutomationAccount -Severity I -Category "AzureRmAutomationAccount"
        Write-Output $AzureRmAutomationAccount
    } catch {
        Invoke-Logger -Message $_ -Severity E -Category "AzureRmAutomationAccount"
        Write-Error $_
    }
} Else { Invoke-Logger -Message $AzureRmAutomationAccount -Severity I -Category "AzureRmAutomationAccount" }

# Create Azure Automation Certificate
ForEach ($AutomationCertificate in $ConfigurationData.SaaSService.AzureRmAutomationCertificate) {
    Invoke-Logger -Message "Get-AzureRmAutomationCertificate -AutomationAccountName $($ConfigurationData.SaaSService.ResourceGroup) -ResourceGroupName $($ConfigurationData.SaaSService.ResourceGroup) -Name '$($AutomationCertificate.CertificateAssetName)Certificate' -ErrorAction SilentlyContinue" -Severity I -Category "AzureRmAutomationCertificate"
    If ($AzureRmAutomationAccount -and -not ($AzureRmAutomationCertificate = Get-AzureRmAutomationCertificate -AutomationAccountName $($ConfigurationData.SaaSService.ResourceGroup) -ResourceGroupName $($ConfigurationData.SaaSService.ResourceGroup) -Name "$($AutomationCertificate.CertificateAssetName)Certificate" -ErrorAction SilentlyContinue)) {

        Write-Output ""
        Write-Output "$Header`nCreating AzureRmAutomationCertificate`n$Header"

        $createRunasAccountParams = @{
            ResourceGroup               = $($ConfigurationData.SaaSService.ResourceGroup)
            AutomationAccountName       = $($ConfigurationData.SaaSService.ResourceGroup)
            SubscriptionId              = $azureRmContext.Subscription.Id
            ApplicationDisplayName      = "$($ConfigurationData.SaaSService.ResourceGroup)-$($AutomationCertificate.CertificateAssetName)"
            SelfSignedCertPlainPassword = $(-join ([char[]](65..90+97..122)*100 | Get-Random -Count 19) + "!")
            CreateClassicRunAsAccount   = $false
            CertificateAssetName        = $AutomationCertificate.CertificateAssetName
        }
    
        try {
            Invoke-Logger -Message "CreateAzureRunAsAccount -$($createRunasAccountParams.Keys.ForEach({"$_ '$($createRunasAccountParams.$_)'"}) -join ' -')" -Severity I -Category "AzureRmAutomationCertificate"
            $CreateAzureRunAsAccount = CreateAzureRunAsAccount @createRunasAccountParams -ErrorAction Stop
            Invoke-Logger -Message $CreateAzureRunAsAccount -Severity I -Category "AzureRmAutomationCertificate"
            Write-Output $CreateAzureRunAsAccount
        } catch {
            Invoke-Logger -Message $_ -Severity E -Category "AzureRmAutomationCertificate"
            Write-Error $_
        }
    } Else { Invoke-Logger -Message $AzureRmAutomationCertificate -Severity I -Category "AzureRmAutomationCertificate" }
}

# Create an Azure Automation Account
ForEach ($AutomationAccount in $ConfigurationData.SaaSService.AzureRmAutomationAccount) {
    Invoke-Logger -Message "Get-AzureRmAutomationCredential -AutomationAccountName $($ConfigurationData.SaaSService.ResourceGroup) -Name $($AutomationAccount.Name) -ResourceGroupName $($ConfigurationData.SaaSService.ResourceGroup) -ErrorAction SilentlyContinue" -Severity I -Category "AzureRmAutomationCredential"
    If ($AzureRmAutomationAccount -and -not ($AzureRmAutomationCredential = Get-AzureRmAutomationCredential -AutomationAccountName $($ConfigurationData.SaaSService.ResourceGroup) -Name $AutomationAccount.Name -ResourceGroupName $($ConfigurationData.SaaSService.ResourceGroup) -ErrorAction SilentlyContinue))
    {
        Write-Output "$Header`nAdding AzureRmAutomationCredential`n$Header"

        $pw = ConvertTo-SecureString $(-join ([char[]](65..90+97..122)*100 | Get-Random -Count 19) + "!") -AsPlainText -Force

        try {
            Invoke-Logger -Message "New-Object –TypeName System.Management.Automation.PSCredential –ArgumentList $($AutomationAccount.Name)" -Severity I -Category "AzureRmAutomationCredential"
            $AzureRmAutomationCredential = New-Object –TypeName System.Management.Automation.PSCredential –ArgumentList $AutomationAccount.Name, $pw
            Invoke-Logger -Message "New-AzureRmAutomationCredential -AutomationAccountName $($ConfigurationData.SaaSService.ResourceGroup) -Name $($AutomationAccount.Name) -Description $($AutomationAccount.Description) -Value $AzureRmAutomationCredential -ResourceGroupName $($ConfigurationData.SaaSService.ResourceGroup)" -Severity I -Category "AzureRmAutomationCredential"
            $nAzureRmAutomationCredential = New-AzureRmAutomationCredential -AutomationAccountName $($ConfigurationData.SaaSService.ResourceGroup) -Name $AutomationAccount.Name -Description $AutomationAccount.Description -Value $AzureRmAutomationCredential -ResourceGroupName $($ConfigurationData.SaaSService.ResourceGroup) -ErrorAction Stop
            Invoke-Logger -Message $nAzureRmAutomationCredential -Severity I -Category "AzureRmAutomationCredential"
            Write-Output $nAzureRmAutomationCredential
        } catch {
            Invoke-Logger -Message $_ -Severity E -Category "AzureRmAutomationCredential"
            Write-Error $_
        }
    } Else { Invoke-Logger -Message $AzureRmAutomationCredential -Severity I -Category "AzureRmAutomationCredential" }
}

#region Register Microsoft.Network for Azure DNS Services
If (-not($AzureRmResourceProvider = Get-AzureRmResourceProvider -ProviderNamespace Microsoft.Network -ErrorAction SilentlyContinue)) {
    Write-Output "$Header`nRegister-AzureRmResourceProvider`n$Header"

    Invoke-Logger -Message "Register-AzureRmResourceProvider -ProviderNamespace Microsoft.Network" -Severity I -Category "AzureRmResourceProvider"

    Try {
        $AzureRmResourceProvider = Register-AzureRmResourceProvider -ProviderNamespace Microsoft.Network -ErrorAction Stop -WhatIf

        Write-Output ""
    }
    Catch {
        Invoke-Logger -Message $_ -Severity E -Category "AzureRmResourceProvider"

        Write-Error $_
    }
}
If (!$AzureRmResourceProvider) { Break }
#endregion

#region Create DNS Zone
$AzureRmDnsZoneName = $ConfigurationData.GlobalConfiguration.TenantDomain
If (-not($AzureRmDnsZone = Get-AzureRmDnsZone -Name $AzureRmDnsZoneName –ResourceGroupName $ConfigurationData.SaaSService.ResourceGroup -ErrorAction SilentlyContinue)) {
    Write-Output "$Header`nNew-AzureRmDnsZone`n$Header"

    $AzureRmDnsZoneParams = @{
        Name              = $AzureRmDnsZoneName
        ResourceGroupName = $ConfigurationData.SaaSService.ResourceGroup
        Tag               = $ConfigurationData.SaaSService.Tags
    }

    Invoke-Logger -Message "New-AzureRmDnsZone -$($AzureRmDnsZoneParams.Keys.ForEach({"$_ '$($AzureRmDnsZoneParams.$_)'"}) -join ' -')" -Severity I -Category "AzureRmDnsZone"

    Try {
        $AzureRmDnsZone = New-AzureRmDnsZone @AzureRmDnsZoneParams -ErrorAction Stop

        Invoke-Logger -Message $AzureRmDnsZone -Severity I -Category "AzureRmDnsZone"

        Write-Output $AzureRmDnsZone
    }
    Catch {
        Invoke-Logger -Message $_ -Severity E -Category "AzureRmDnsZone"

        Write-Error $_
    }
}
Else {
    Invoke-Logger -Message $AzureRmDnsZone -Severity I -Category "AzureRmDnsZone"
}
If (!$AzureRmDnsZone) { Break }
#endregion

#region Create Resource Group
ForEach ($ResourceGroup in $ConfigurationData.ResourceGroups.Keys) {

    #Verify AzureRmResourceGroup
    Write-Output "$Header`nAzureRmResourceGroup: $($ResourceGroup)`n$Header"
    Write-Output ""

    If (-not($AzureRmResourceGroup = Get-AzureRmResourceGroup -Name $ResourceGroup -ErrorAction SilentlyContinue)) {

        Write-Output "New-AzureRmResourceGroup`n$Header"

        $AzureRmResourceGroupParams = @{
            Name     = $ResourceGroup
            Location = $ConfigurationData.ResourceGroups.$ResourceGroup.Location
            Tag      = $ConfigurationData.ResourceGroups.$ResourceGroup.Tags
        }

        Invoke-Logger -Message "New-AzureRmResourceGroup -$($AzureRmResourceGroupParams.Keys.ForEach({"$_ '$($AzureRmResourceGroupParams.$_)'"}) -join ' -')" -Severity I -Category "AzureRmResourceGroup"

        Try {
            $AzureRmResourceGroup = New-AzureRmResourceGroup @AzureRmResourceGroupParams -ErrorAction Stop

            Invoke-Logger -Message $AzureRmResourceGroup -Severity I -Category "AzureRmResourceGroup"

            Write-Output $AzureRmResourceGroup
        }
        Catch {
            Invoke-Logger -Message $_ -Severity E -Category "AzureRmResourceGroup"

            Write-Error $_
        }
    }
    Else {
        Invoke-Logger -Message $AzureRmResourceGroup -Severity I -Category "AzureRmResourceGroup"
        
        Write-Output $AzureRmResourceGroup
    }

    If (!$AzureRmResourceGroup) { Break }

    #Verify AzureRmStorageAccount
    If ($ConfigurationData.ResourceGroups.$ResourceGroup.Storage) {
        $AzureRmStorageAccountName = Remove-IllegalCharactersFromString -String ($ResourceGroup.Storage.Name.Replace("[ResourceGroup]",$ResourceGroup)).ToLower()

        If ($AzureRmResourceGroup -and -not ($AzureRmStorageAccount = Get-AzureRmStorageAccount -ResourceGroupName $ResourceGroup -Name $AzureRmStorageAccountName -ErrorAction SilentlyContinue))
        {
            Write-Output "New-AzureRmStorageAccount`n$Header"
            Write-Output "This process may take several minutes..."

            If ($ResourceGroup.Storage.GlobalConfiguration) {  
                $AzureRmStorageAccountParams = @{
                    Name              = $AzureRmStorageAccountName
                    ResourceGroupName = $ResourceGroup
                    Type              = $ConfigurationData.GlobalConfiguration.Storage.Type
                    Location          = $ResourceGroup.Location
                    Tag               = $ResourceGroup.Tags
                }
            }
            Else {
                $AzureRmStorageAccountParams = @{
                    Name              = $AzureRmStorageAccountName
                    ResourceGroupName = $ResourceGroup
                    Type              = $ResourceGroup.Storage.Type
                    Location          = $ResourceGroup.Location
                    Tag               = $ResourceGroup.Tags
                }
            }

            Invoke-Logger -Message "New-AzureRmStorageAccount -$($AzureRmStorageAccountParams.Keys.ForEach({"$_ '$($AzureRmStorageAccountParams.$_)'"}) -join ' -')" -Severity I -Category "AzureRmStorageAccount"

            Try {
                $AzureRmStorageAccount = New-AzureRmStorageAccount @AzureRmStorageAccountParams -ErrorAction Stop

                Invoke-Logger -Message $AzureRmStorageAccount -Severity I -Category "AzureRmStorageAccount"

                Write-Output $AzureRmStorageAccount
            } Catch {
                Invoke-Logger -Message $_ -Severity E -Category "AzureRmStorageAccount"

                Write-Error $_
            }

            If (!$AzureRmStorageAccount) { Break }

            $Keys = Get-AzureRmStorageAccountKey -ResourceGroupName $ResourceGroup -Name $AzureRmStorageAccountName
            $StorageContext = New-AzureStorageContext -StorageAccountName $AzureRmStorageAccountName -StorageAccountKey $Keys[0].Value

            Invoke-Logger -Message $Keys -Severity I -Category "AzureRmStorageAccount"
            Invoke-Logger -Message $StorageContext -Severity I -Category "AzureRmStorageAccount"
        }
        Else
        {
            $Keys = Get-AzureRmStorageAccountKey -ResourceGroupName $ResourceGroup -Name $AzureRmStorageAccountName
            $StorageContext = New-AzureStorageContext -StorageAccountName $AzureRmStorageAccountName $Keys[0].Value

            Invoke-Logger -Message $Keys -Severity I -Category "AzureRmStorageAccount"
            Invoke-Logger -Message $StorageContext -Severity I -Category "AzureRmStorageAccount"
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

                Invoke-Logger -Message "Set-AzureStorageCORSRule -$($AzureStorageCORSRuleParams.Keys.ForEach({"$_ '$($AzureStorageCORSRuleParams.$_)'"}) -join ' -')" -Severity I -Category "AzureStorageCORSRule"

                Try {
                    Set-AzureStorageCORSRule @AzureStorageCORSRuleParams -ErrorAction Stop

                    $GetAzureStorageCORSRule = Get-AzureStorageCORSRule -ServiceType Blob -Context $StorageContext

                    Invoke-Logger -Message $GetAzureStorageCORSRule -Severity I -Category "AzureStorageCORSRule"

                    Write-Host $GetAzureStorageCORSRule

                    Write-Output ""
                }
                Catch {
                    Invoke-Logger -Message $_ -Severity E -Category "AzureStorageCORSRule"

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

                Invoke-Logger -Message "New-AzureStorageContainer -$($AzureStorageContainerParams.Keys.ForEach({"$_ '$($AzureStorageContainerParams.$_)'"}) -join ' -')" -Severity I -Category "AzureStorageContainer"

                Try {
                    $AzureStorageContainer = New-AzureStorageContainer @AzureStorageContainerParams -ErrorAction Stop

                    Invoke-Logger -Message $AzureStorageContainer -Severity I -Category "AzureStorageContainer"

                    Write-Output $AzureStorageContainer
                }
                Catch {
                    Invoke-Logger -Message $_ -Severity E -Category "AzureStorageContainer"

                    Write-Error $_
                }
            }
            Else {
                Invoke-Logger -Message $AzureStorageContainer -Severity I -Category "AzureStorageContainer"
            }
        }
    }

    #Verify AzureRmAutomationAccount
    If ($ResourceGroup.AzureRmAutomationAccount.Name) {

        $AzureRmAutomationAccountName = $ResourceGroup.AzureRmAutomationAccount.Name.Replace("[ResourceGroup]",$ResourceGroup)

        If ($AzureRmResourceGroup -and -not($AzureRmAutomationAccount = Get-AzureRmAutomationAccount -ResourceGroupName $ResourceGroup -Name $AzureRmAutomationAccountName -ErrorAction SilentlyContinue)) {
            Write-Output "New-AzureRmAutomationAccount`n$Header"

            $AzureRmAutomationAccountParams = @{
                ResourceGroupName = $ResourceGroup
                Location          = $ResourceGroup.Location
                Name              = $AzureRmAutomationAccountName
                Tags              = $ResourceGroup.Tags
            }

            Invoke-Logger -Message "New-AzureRmAutomationAccount -$($AzureRmAutomationAccountParams.Keys.ForEach({"$_ '$($AzureRmAutomationAccountParams.$_)'"}) -join ' -')" -Severity I -Category "AzureRmAutomationAccount"

            Try {
                $AzureRmAutomationAccount = New-AzureRmAutomationAccount @AzureRmAutomationAccountParams -ErrorAction Stop

                Invoke-Logger -Message $AzureRmAutomationAccount -Severity I -Category "AzureRmAutomationAccount"

                Write-Output $AzureRmAutomationAccount
            }
            Catch {
                Invoke-Logger -Message $_ -Severity E -Category "AzureRmAutomationAccount"

                Write-Error $_
            }
        }
        Else {
            Invoke-Logger -Message $AzureRmAutomationAccount -Severity I -Category "AzureRmResourceGroup"
        }

        #Verify AzureRmAutomationCredential
        ForEach ($AutomationCredential in $ResourceGroup.AzureRmAutomationAccount.AzureRmAutomationCredential) {

            $AutomationCredentialName = $AutomationCredential.Name.Replace("[ResourceGroup]",$ResourceGroup)

            If (-not ($AzureRmAutomationCredential = Get-AzureRmAutomationCredential -AutomationAccountName $AzureRmAutomationAccountName -Name $AutomationCredentialName -ResourceGroupName $ResourceGroup -ErrorAction SilentlyContinue))
            {
                Write-Output "New-AzureRmAutomationCredential`n$Header"

                $pw = ConvertTo-SecureString $(-join ([char[]](65..90+97..122)*100 | Get-Random -Count 19) + "!") -AsPlainText -Force
                $AzureRmAutomationCredential = New-Object –TypeName System.Management.Automation.PSCredential –ArgumentList $AutomationCredentialName, $pw

                $AzureRmAutomationCredentialParams = @{
                    AutomationAccountName = $AzureRmAutomationAccountName
                    Name                  = $AutomationCredentialName
                    Description           = $AutomationCredential.Description
                    ResourceGroupName     = $ResourceGroup
                    Value                 = $AzureRmAutomationCredential
                }

                Invoke-Logger -Message "New-AzureRmAutomationCredential -$($AzureRmAutomationCredentialParams.Keys.ForEach({"$_ '$($AzureRmAutomationCredentialParams.$_)'"}) -join ' -')" -Severity I -Category "AzureRmAutomationCredential"
        
                Try {
                    $AzureRmAutomationCredential = New-AzureRmAutomationCredential @AzureRmAutomationCredentialParams -ErrorAction Stop

                    Invoke-Logger -Message $AzureRmAutomationCredential -Severity I -Category "AzureRmAutomationCredential"

                    Write-Output $AzureRmAutomationCredential
                }
                Catch {
                    Invoke-Logger -Message $_ -Severity E -Category "AzureRmAutomationCredential"

                    Write-Error $_
                }
            }
        }

        #Verify AzureRmAutomationVariable
        ForEach ($AutomationVariable in $ResourceGroup.AzureRmAutomationAccount.AzureRmAutomationVariable) {
            If (-not (Get-AzureRmAutomationVariable -AutomationAccountName $AzureRmAutomationAccountName -Name $AutomationVariable.Name -ResourceGroupName $ResourceGroup -ErrorAction SilentlyContinue))
            {
                Write-Output "New-AzureRmAutomationVariable`n$Header"

                $AzureRmAutomationVariableRedistPathParams = @{
                    AutomationAccountName = $AzureRmAutomationAccountName
                    Name                  = $AutomationVariable.Name
                    Value                 = $AutomationVariable.Value
                    Encrypted             = $AutomationVariable.Encrypted
                    ResourceGroupName     = $ResourceGroup
                }

                Invoke-Logger -Message "New-AzureRmAutomationVariable -$($AzureRmAutomationVariableRedistPathParams.Keys.ForEach({"$_ '$($AzureRmAutomationVariableRedistPathParams.$_)'"}) -join ' -')" -Severity I -Category "AzureRmAutomationVariable"
        
                Try {
                    $AzureRmAutomationVariable = New-AzureRmAutomationVariable @AzureRmAutomationVariableRedistPathParams -ErrorAction Stop

                    Invoke-Logger -Message $AzureRmAutomationVariable -Severity I -Category "AzureRmAutomationVariable"

                    Write-Output $AzureRmAutomationVariable
                }
                Catch {
                    Invoke-Logger -Message $_ -Severity E -Category "AzureRmAutomationVariable"

                    Write-Error $_
                }
            }
        }
    }

    #Verify Relay Namespace
    If ($ConfigurationData.ResourceGroups.$ResourceGroup.HybridConnection.Enabled) {
        If (!($AzureRmRelayNamespace = Get-AzureRmRelayNamespace -ResourceGroupName $ResourceGroup -Name $ConfigurationData.ResourceGroups.$ResourceGroup.HybridConnection.Namespace -ErrorAction SilentlyContinue)) {
            Invoke-Logger -Message "New-AzureRmRelayNamespace -ResourceGroupName $($ResourceGroup) -Name $($ConfigurationData.ResourceGroups.$ResourceGroup.HybridConnection.Namespace) -Location $($ConfigurationData.ResourceGroups.$ResourceGroup.Location)" -Severity I -Category "AzureRmRelayNamespace"
            Try {
                $AzureRmRelayNamespace = New-AzureRmRelayNamespace -ResourceGroupName $ResourceGroup -Name $ConfigurationData.ResourceGroups.$ResourceGroup.HybridConnection.Namespace -Location $ConfigurationData.ResourceGroups.$ResourceGroup.Location -ErrorAction Stop

                Invoke-Logger -Message $AzureRmRelayNamespace -Severity I -Category "AzureRmRelayNamespace"

                Write-Output $AzureRmRelayNamespace
            }
            Catch {
                Invoke-Logger -Message $_ -Severity E -Category "AzureRmRelayNamespace"

                Write-Error $_
            }
        } Else {
            Invoke-Logger -Message $AzureRmRelayNamespace -Severity I -Category "AzureRmRelayNamespace"
        }

        #Verify Hybrid Connection
        If (!($AzureRmRelayHybridConnection = Get-AzureRmRelayHybridConnection -ResourceGroupName $ResourceGroup -Name $ConfigurationData.ResourceGroups.$ResourceGroup.HybridConnection.Name -Namespace $ConfigurationData.ResourceGroups.$ResourceGroup.HybridConnection.Namespace -ErrorAction SilentlyContinue)) {
            Invoke-Logger -Message "New-AzureRmRelayHybridConnection -ResourceGroupName $($ResourceGroup) -Namespace $($ConfigurationData.ResourceGroups.$ResourceGroup.HybridConnection.Namespace) -Name $($ConfigurationData.ResourceGroups.$ResourceGroup.HybridConnection.Names) -RequiresClientAuthorization $True" -Severity I -Category "AzureRmRelayHybridConnection"
            Try {
                $AzureRmRelayHybridConnection = New-AzureRmRelayHybridConnection -ResourceGroupName $ResourceGroup -Namespace $ConfigurationData.ResourceGroups.$ResourceGroup.HybridConnection.Namespace -Name $ConfigurationData.ResourceGroups.$ResourceGroup.HybridConnection.Name -RequiresClientAuthorization $True

                Invoke-Logger -Message $AzureRmRelayHybridConnection -Severity I -Category "AzureRmRelayHybridConnection"

                Write-Output $AzureRmRelayNamespace
            }
            Catch {
                Invoke-Logger -Message $_ -Severity E -Category "AzureRmRelayHybridConnection"

                Write-Error $_
            }
        } Else {
            Invoke-Logger -Message $AzureRmRelayHybridConnection -Severity I -Category "AzureRmRelayHybridConnection"
        }
    }

    #Verify App Service Plan
    ForEach ($AzureRmAppServicePlan in $ConfigurationData.ResourceGroups.$ResourceGroup.AppServicePlan.Keys) {
        $AzureRmAppServicePlanName = $AzureRmAppServicePlan.Replace("[ResourceGroup]",$ResourceGroup)

        $AzureRmAppServicePlanName = Remove-IllegalCharactersFromString -String $AzureRmAppServicePlanName.ToLower()
        If ($AzureRmAppServicePlanName.Length -lt $configurationData.GlobalConfiguration.ShortNameCharacters) {
            $AzureRmAppServicePlanName = "$AzureRmAppServicePlanName$(Get-TruncatedStringHash -String $AzureRmAppServicePlanName -Length ($configurationData.GlobalConfiguration.ShortNameCharacters - $AzureRmAppServicePlanName.Length))"
        } else {
            $AzureRmAppServicePlanName = $AzureRmAppServicePlanName.SubString(0,$configurationData.GlobalConfiguration.ShortNameCharacters)
        }

        If (-not($GetAzureRmAppServicePlan = Get-AzureRmAppServicePlan -Name $AzureRmAppServicePlanName -ResourceGroupName $ResourceGroup -ErrorAction SilentlyContinue)) {
        
            Write-Output "New-AzureRmAppServicePlan`n$Header"

            $AzureRmAppServicePlanParams = @{
                Name              = $AzureRmAppServicePlanName
                Location          = $ConfigurationData.ResourceGroups.$ResourceGroup.Location
                ResourceGroupName = $ResourceGroup
                Tier              = $ConfigurationData.ResourceGroups.$ResourceGroup.AppServicePlan.$AzureRmAppServicePlan.Tier
            }

            Invoke-Logger -Message "New-AzureRmAppServicePlan -$($AzureRmAppServicePlanParams.Keys.ForEach({"$_ '$($AzureRmAppServicePlanParams.$_)'"}) -join ' -')" -Severity I -Category "AzureRmAppServicePlan"

            Try {
                $AzureRmAppServicePlan = New-AzureRmAppServicePlan @AzureRmAppServicePlanParams -ErrorAction Stop

                Invoke-Logger -Message $AzureRmAppServicePlan -Severity I -Category "AzureRmAppServicePlan"

                Write-Output $AzureRmAppServicePlan
            }
            Catch {
                Invoke-Logger -Message $_ -Severity E -Category "AzureRmAppServicePlan"

                Write-Error $_
            }
        }
        Else {
            Invoke-Logger -Message $AzureRmAppServicePlan -Severity I -Category "AzureRmAppServicePlan"

            [bool]$ChangeAzureRmAppServicePlan = $False
            If ($GetAzureRmAppServicePlan.Sku.Tier -ne $ConfigurationData.ResourceGroups.$ResourceGroup.AppServicePlan.$AzureRmAppServicePlan.Tier) {

                Write-Output "Set-AzureRmAppServicePlan`n$Header"

                $AzureRmAppServicePlanParams = @{
                    Name              = $AzureRmAppServicePlanName
                    ResourceGroupName = $ResourceGroup
                    Tier              = $ConfigurationData.ResourceGroups.$ResourceGroup.AppServicePlan.$AzureRmAppServicePlan.Tier
                }

                Invoke-Logger -Message "Set-AzureRmAppServicePlan -$($AzureRmAppServicePlanParams.Keys.ForEach({"$_ '$($AzureRmAppServicePlanParams.$_)'"}) -join ' -')" -Severity I -Category "AzureRmAppServicePlan"

                Try {
                    $AzureRmAppServicePlan = Set-AzureRmAppServicePlan @AzureRmAppServicePlanParams -ErrorAction Stop

                    $ChangeAzureRmAppServicePlan = $True

                    Invoke-Logger -Message $AzureRmAppServicePlan -Severity I -Category "AzureRmAppServicePlan"

                    Write-Output $AzureRmAppServicePlan
                }
                Catch {
                    Invoke-Logger -Message $_ -Severity E -Category "AzureRmAppServicePlan"

                    Write-Error $_
                }

                If ($ChangeAzureRmAppServicePlan) {

                    [bool]$RestartWebApps = $true
                    If ($configurationData.GlobalConfiguration.Confirm) {
                        Write-host "A change of the AzureRmAppServicePlan requires a restart of all associated Web Applications" -ForegroundColor Green
                        Write-host "Would you like to restart all '$AzureRmAppServicePlanName' associated Web Applications? (Default is No)" -ForegroundColor Yellow
                    
                        $Readhost = Read-Host " ( y / n ) " 
                        Switch ($ReadHost) 
                        { 
                            Y {       $RestartWebApps = $true } 
                            N {       $RestartWebApps = $false } 
                            Default { $RestartWebApps = $false } 
                        }
                    }

                    If ($RestartWebApps) {
                        $AzureRmAppServicePlanWebApps = Get-AzureRmWebApp -ResourceGroupName $ConfigurationData.Customers.$Customer.ResourceGroup | Where-Object { $_.ServerFarmId -eq $GetAzureRmAppServicePlan.Id }

                        ForEach ($AzureRmAppServicePlanWebApp in $AzureRmAppServicePlanWebApps) {
                            Write-Output ""
                            Write-Output "Restart-AzureRmWebApp`n$Header"
                            Write-Output $AzureRmAppServicePlanWebApp.Name
                            Write-Output ""

                            Invoke-Logger -Message "Restart-AzureRmWebApp -ResourceGroupName $($ConfigurationData.Customers.$Customer.ResourceGroup) -Name $($AzureRmAppServicePlanWebApp.Name)" -Severity I -Category "AzureRmWebApp"

                            Try {
                                $RestartAzureRmWebApp = Restart-AzureRmWebApp -ResourceGroupName $ConfigurationData.Customers.$Customer.ResourceGroup -Name $AzureRmAppServicePlanWebApp.Name

                                Invoke-Logger -Message $RestartAzureRmWebApp -Severity I -Category "AzureRmWebApp"
                            }
                            Catch {
                                Invoke-Logger -Message $_ -Severity E -Category "AzureRmWebApp"

                                Write-Error $_
                            }
                        }
                    }
                }
            }
        }
        If (!$AzureRmAppServicePlan) { Break }
    }

    $AzureRmKeyVaultName = $ResourceGroup

    #Verify Key Vault
    If ((Get-AzureRmResourceGroup -Name $ConfigurationData.SaaSService.ResourceGroup -ErrorAction SilentlyContinue) -and -not($AzureRmKeyVault = Get-AzureRMKeyVault -VaultName $AzureRmKeyVaultName -ErrorAction SilentlyContinue)) {
        Write-Output "New-AzureRmKeyVault`n$Header"

        $AzureRmKeyVaultParams = @{
            VaultName         = $AzureRmKeyVaultName
            ResourceGroupName = $ConfigurationData.SaaSService.ResourceGroup
            Location          = $ConfigurationData.ResourceGroups.$ResourceGroup.Location
            Sku               = $ConfigurationData.ResourceGroups.$ResourceGroup.KeyVault.SKU
            Tags              = $ConfigurationData.ResourceGroups.$ResourceGroup.Tags
        }

        Invoke-Logger -Message "New-AzureRmKeyVault -$($AzureRmKeyVaultParams.Keys.ForEach({"$_ '$($AzureRmKeyVaultParams.$_)'"}) -join ' -')" -Severity I -Category "AzureRmKeyVault"

        Try {
            $AzureRmKeyVault = New-AzureRmKeyVault @AzureRmKeyVaultParams -ErrorAction Stop

            Invoke-Logger -Message $AzureRmKeyVault -Severity I -Category "AzureRmKeyVault"

            Write-Output $AzureRmKeyVault
        }
        Catch {
            Invoke-Logger -Message $_ -Severity E -Category "AzureRmKeyVault"

            Write-Error $_
        }
    }
    Else {
        Invoke-Logger -Message $AzureRmKeyVault -Severity I -Category "AzureRmKeyVault"
    }
    If (!$AzureRmKeyVault) { Break }
}
#endregion

#region Create Customer
ForEach ($Customer in $ConfigurationData.Customers.Keys) {

    #Verify AzureRmResourceGroup
    Write-Output "$Header`nCustomer: $($Customer)`n$Header"
    Write-Output "" 

    If ($AzureRmResourceGroup = Get-AzureRmResourceGroup -Name $ConfigurationData.Customers.$Customer.ResourceGroup -ErrorAction SilentlyContinue) {

        $CustomerName = (Remove-IllegalCharactersFromString -String $Customer).ToLower()

        $DnsRecordSetName = $CustomerName
        If ($DnsRecordSetName.Length -lt $configurationData.GlobalConfiguration.ShortNameCharacters) {
            $DnsRecordSetName = "$DnsRecordSetName$(Get-TruncatedStringHash -String $DnsRecordSetName -Length ($configurationData.GlobalConfiguration.ShortNameCharacters - $DnsRecordSetName.Length))"
        } else {
            $DnsRecordSetName = $DnsRecordSetName.SubString(0,$configurationData.GlobalConfiguration.ShortNameCharacters)
        }
        $CustomerName = $DnsRecordSetName

        #Verify AzureRmStorageAccount
        If (-not ($AzureRmStorageAccount = Get-AzureRmStorageAccount -ResourceGroupName $ConfigurationData.Customers.$Customer.ResourceGroup -Name $CustomerName -ErrorAction SilentlyContinue))
        {
            Write-Output "New-AzureRmStorageAccount`n$Header"
            Write-Output "This process may take several minutes..."

            If ($ConfigurationData.Customers.$Customer.Storage.GlobalConfiguration) {  
                $AzureRmStorageAccountParams = @{
                    Name              = $CustomerName
                    ResourceGroupName = $ConfigurationData.Customers.$Customer.ResourceGroup
                    Type              = $ConfigurationData.GlobalConfiguration.Storage.Type
                    Location          = $ConfigurationData.Customers.$Customer.Location
                    Tag               = $ConfigurationData.Customers.$Customer.Tags
                }
            }
            Else {
                $AzureRmStorageAccountParams = @{
                    Name              = $CustomerName
                    ResourceGroupName = $ConfigurationData.Customers.$Customer.ResourceGroup
                    Type              = $ConfigurationData.Customers.$Customer.Storage.Type
                    Location          = $ConfigurationData.Customers.$Customer.Location
                    Tag               = $ConfigurationData.Customers.$Customer.Tags
                }
            }

            Invoke-Logger -Message "New-AzureRmStorageAccount -$($AzureRmStorageAccountParams.Keys.ForEach({"$_ '$($AzureRmStorageAccountParams.$_)'"}) -join ' -')" -Severity I -Category "AzureRmStorageAccount"

            Try {
                $AzureRmStorageAccount = New-AzureRmStorageAccount @AzureRmStorageAccountParams -ErrorAction Stop

                Invoke-Logger -Message $AzureRmStorageAccount -Severity I -Category "AzureRmStorageAccount"

                Write-Output $AzureRmStorageAccount
            } Catch {
                Invoke-Logger -Message $_ -Severity E -Category "AzureRmStorageAccount"

                Write-Error $_
            }

            If (!$AzureRmStorageAccount) { Break }

            $Keys = Get-AzureRmStorageAccountKey -ResourceGroupName $ConfigurationData.Customers.$Customer.ResourceGroup -Name $CustomerName
            $StorageContext = New-AzureStorageContext -StorageAccountName $CustomerName -StorageAccountKey $Keys[0].Value

            Invoke-Logger -Message $Keys -Severity I -Category "AzureRmStorageAccount"
            Invoke-Logger -Message $StorageContext -Severity I -Category "AzureRmStorageAccount"
        }
        Else
        {
            $Keys = Get-AzureRmStorageAccountKey -ResourceGroupName $ConfigurationData.Customers.$Customer.ResourceGroup -Name $CustomerName
            $StorageContext = New-AzureStorageContext -StorageAccountName $CustomerName $Keys[0].Value

            Invoke-Logger -Message $Keys -Severity I -Category "AzureRmStorageAccount"
            Invoke-Logger -Message $StorageContext -Severity I -Category "AzureRmStorageAccount"
        }

        #Verify CORS rules
        If ($StorageContext) {
            $cRules = Get-AzureStorageCORSRule -ServiceType Blob -Context $StorageContext

            $cUpdate = $False
            If ($ConfigurationData.Customers.$Customer.CorsRules.GlobalConfiguration) {
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
                ForEach ($CorsRule in $ConfigurationData.Customers.$Customer.CorsRules.Keys)
                {
                    If (!([string]$cRules.$CorsRule -eq [string]$ConfigurationData.Customers.$Customer.CorsRules.$CorsRule))
                    {
                        $cUpdate = $True
                        Break
                    }
                }
            }

            If ($cUpdate)
            {
                Write-Output "Set-AzureStorageCORSRule`n$Header"

                If ($ConfigurationData.Customers.$Customer.CorsRules.GlobalConfiguration) {
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
                        CorsRules   = $ConfigurationData.Customers.$Customer.CorsRules
                    }
                }

                Invoke-Logger -Message "Set-AzureStorageCORSRule -$($AzureStorageCORSRuleParams.Keys.ForEach({"$_ '$($AzureStorageCORSRuleParams.$_)'"}) -join ' -')" -Severity I -Category "AzureStorageCORSRule"

                Try {
                    Set-AzureStorageCORSRule @AzureStorageCORSRuleParams -ErrorAction Stop

                    $GetAzureStorageCORSRule = Get-AzureStorageCORSRule -ServiceType Blob -Context $StorageContext

                    Invoke-Logger -Message $GetAzureStorageCORSRule -Severity I -Category "AzureStorageCORSRule"

                    Write-Host $GetAzureStorageCORSRule

                    Write-Output ""
                }
                Catch {
                    Invoke-Logger -Message $_ -Severity E -Category "AzureStorageCORSRule"

                    Write-Error $_
                }
            }
        }

        #Verify AzureStorageContainer
        $AzureStorageContainerHeader = $True

        $Containers = $null
        If ($ConfigurationData.Customers.$Customer.Storage.GlobalConfiguration) {
            $Containers = $ConfigurationData.GlobalConfiguration.Storage.Containers
        }
        Else {
            $Containers = $ConfigurationData.Customers.$Customer.Storage.Containers
        }

        ForEach ($Container in $Containers) {
            If ($AzureRmStorageAccount -and -not($AzureStorageContainer = Get-AzureStorageContainer -Name $Container -Context $StorageContext -ErrorAction SilentlyContinue))
            {
                Write-Output "New-AzureStorageContainer`n$Header"

                $AzureStorageContainerParams = @{
                    Name       = $Container
                    Permission = "Off"
                    Context    = $StorageContext
                }

                Invoke-Logger -Message "New-AzureStorageContainer -$($AzureStorageContainerParams.Keys.ForEach({"$_ '$($AzureStorageContainerParams.$_)'"}) -join ' -')" -Severity I -Category "AzureStorageContainer"

                Try {
                    $AzureStorageContainer = New-AzureStorageContainer @AzureStorageContainerParams -ErrorAction Stop

                    Invoke-Logger -Message $AzureStorageContainer -Severity I -Category "AzureStorageContainer"

                    Write-Output $AzureStorageContainer
                }
                Catch {
                    Invoke-Logger -Message $_ -Severity E -Category "AzureStorageContainer"

                    Write-Error $_
                }
            }
            Else {
                Invoke-Logger -Message $AzureStorageContainer -Severity I -Category "AzureStorageContainer"
            }
        }

        #Verify AzureRmDnsRecordSet
        If ($ConfigurationData.Customers.$Customer.DnsRecordSet.GlobalConfiguration) {
            $RecordType = $ConfigurationData.GlobalConfiguration.DnsRecordSet.RecordType
            $Ttl        = $ConfigurationData.GlobalConfiguration.DnsRecordSet.Ttl
            $DnsRecords = $ConfigurationData.GlobalConfiguration.DnsRecordSet.DnsRecords
        }
        Else {
            $RecordType = $ConfigurationData.Customers.$Customer.DnsRecordSet.RecordType
            $Ttl        = $ConfigurationData.Customers.$Customer.DnsRecordSet.Ttl
            $DnsRecords = $ConfigurationData.Customers.$Customer.DnsRecordSet.DnsRecords
        }

        If (-not($AzureRmDnsRecordSet = Get-AzureRmDnsRecordSet -Name (Remove-IllegalCharactersFromString -String $Customer).ToLower() -RecordType $RecordType -ZoneName $AzureRmDnsZoneName -ResourceGroupName $ConfigurationData.SaaSService.ResourceGroup -ErrorAction SilentlyContinue)) {
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
                Name                   = (Remove-IllegalCharactersFromString -String $Customer).ToLower()
                RecordType             = $RecordType
                ZoneName               = $AzureRmDnsZoneName
                ResourceGroupName      = $ConfigurationData.SaaSService.ResourceGroup
                Ttl                    = $Ttl
                DnsRecords             = $DnsRecords
            }

            Invoke-Logger -Message "New-AzureRmDnsRecordSet -$($AzureRmDnsRecordSetParams.Keys.ForEach({"$_ '$($AzureRmDnsRecordSetParams.$_)'"}) -join ' -')" -Severity I -Category "AzureRmDnsRecordSet"

            Try {
                $AzureRmDnsRecordSet = New-AzureRmDnsRecordSet @AzureRmDnsRecordSetParams -ErrorAction Stop

                Invoke-Logger -Message $AzureRmDnsRecordSet -Severity I -Category "AzureRmDnsRecordSet"

                Write-Output $AzureRmDnsRecordSet
            }
            Catch {
                Invoke-Logger -Message $_ -Severity E -Category "AzureRmDnsRecordSet"

                Write-Error $_
            }
        }

        #Verify Key Vault Secret
        If (($AzureRmKeyVault = Get-AzureRMKeyVault -VaultName $ConfigurationData.Customers.$Customer.ResourceGroup -ErrorAction SilentlyContinue) -and -not($AzureKeyVaultSecret = (Get-AzureKeyVaultSecret -VaultName $ConfigurationData.Customers.$Customer.ResourceGroup -Name (Remove-IllegalCharactersFromString -String $Customer).ToLower() -ErrorAction SilentlyContinue).SecretValueText)) {
            Write-Output "$Header`nSet-AzureKeyVaultSecret`n$Header"

            #Define Secret properties
            $Secret = @{}
            If ($ConfigurationData.Customers.$Customer.KeyVaultSecret.GlobalConfiguration) {
                ForEach ($variable in $ConfigurationData.GlobalConfiguration.KeyVault.Secrets.AppSettings.Keys) {
                    $value = $ConfigurationData.GlobalConfiguration.KeyVault.Secrets.AppSettings.$variable
                    New-Variable -Name $variable -Value "`$ConfigurationData.$value" -Force
                    $value = $value.Replace("[ResourceGroup]",$ConfigurationData.Customers.$Customer.ResourceGroup)
                    $value = $value.Replace("[Key]",$Keys[0].Value)
                    $Secret.add($variable,$value)
                }
            } Else {
                ForEach ($variable in $ConfigurationData.Customers.$Customer.KeyVaultSecret.Keys) {
                    $value = $ConfigurationData.Customers.$Customer.KeyVaultSecret.$variable
                    New-Variable -Name $variable -Value "`$ConfigurationData.$value" -Force
                    $value = $value.Replace("[ResourceGroup]",$ConfigurationData.Customers.$Customer.ResourceGroup)
                    $value = $value.Replace("[Key]",$Keys[0].Value)
                    $Secret.add($variable,$value)
                }
            }

            $AzureKeyVaultSecretParams = @{
                Name        = (Remove-IllegalCharactersFromString -String $Customer).ToLower()
                SecretValue = (ConvertTo-SecureString $(ConvertTo-Json $Secret) -AsPlainText -Force)
                ContentType = "AppSettings"
                VaultName   = $ConfigurationData.Customers.$Customer.ResourceGroup
            }

            Invoke-Logger -Message "Set-AzureKeyVaultSecret -$($AzureKeyVaultSecretParams.Keys.ForEach({"$_ '$($AzureKeyVaultSecretParams.$_)'"}) -join ' -')" -Severity I -Category "AzureKeyVaultSecret"

            Try {
                $AzureKeyVaultSecret = Set-AzureKeyVaultSecret @AzureKeyVaultSecretParams -ErrorAction Stop

                Invoke-Logger -Message $AzureKeyVaultSecretParams -Severity I -Category "AzureKeyVaultSecret"

                Write-Output $Secret.Keys
                Write-Output ""
            }
            Catch {
                Invoke-Logger -Message $_ -Severity E -Category "AzureKeyVaultSecret"

                Write-Error $_
            }
        }
        ElseIf ($AzureKeyVaultSecret) {

            #Define Secret properties from configuration file
            $Secret = @{}
            If ($ConfigurationData.Customers.$Customer.KeyVaultSecret.GlobalConfiguration) {
                ForEach ($variable in $ConfigurationData.GlobalConfiguration.KeyVault.Secrets.AppSettings.Keys) {
                    $value = $ConfigurationData.GlobalConfiguration.KeyVault.Secrets.AppSettings.$variable
                    New-Variable -Name $variable -Value "`$ConfigurationData.$value" -Force
                    $value = $value.Replace("[ResourceGroup]",$ConfigurationData.Customers.$Customer.ResourceGroup)
                    $value = $value.Replace("[Key]",$Keys[0].Value)
                    $Secret.add($variable,$value)
                }
            } Else {
                ForEach ($variable in $ConfigurationData.Customers.$Customer.KeyVaultSecret.Keys) {
                    $value = $ConfigurationData.Customers.$Customer.KeyVaultSecret.$variable
                    New-Variable -Name $variable -Value "`$ConfigurationData.$value" -Force
                    $value = $value.Replace("[ResourceGroup]",$ConfigurationData.Customers.$Customer.ResourceGroup)
                    $value = $value.Replace("[Key]",$Keys[0].Value)
                    $Secret.add($variable,$value)
                }
            }

            #Compare configuration file to Key Vault Secret
            If ($AzureKeyVaultSecret -ne $(ConvertTo-Json $Secret)) {
                Write-Output "Set-AzureKeyVaultSecret`n$Header"

                $AzureKeyVaultSecretParams = @{
                    Name        = (Remove-IllegalCharactersFromString -String $Customer).ToLower()
                    SecretValue = (ConvertTo-SecureString $(ConvertTo-Json $Secret) -AsPlainText -Force)
                    ContentType = "AppSettings"
                    VaultName   = $ConfigurationData.Customers.$Customer.ResourceGroup
                }

                Invoke-Logger -Message "Set-AzureKeyVaultSecret -$($AzureKeyVaultSecretParams.Keys.ForEach({"$_ '$($AzureKeyVaultSecretParams.$_)'"}) -join ' -')" -Severity I -Category "AzureKeyVaultSecret"

                Try {
                    $AzureKeyVaultSecret = Set-AzureKeyVaultSecret @AzureKeyVaultSecretParams -ErrorAction Stop

                    Invoke-Logger -Message $AzureKeyVaultSecretParams -Severity I -Category "AzureKeyVaultSecret"

                    Write-Output $Secret.Keys
                    Write-Output ""
                }
                Catch {
                    Invoke-Logger -Message $_ -Severity E -Category "AzureKeyVaultSecret"

                    Write-Error $_
                }
            }

        }

        #Verify Web Applications
        ForEach ($WebApp in $ConfigurationData.Customers.$Customer.WebApp.Keys){

            $AzureRmWebAppName = (Remove-IllegalCharactersFromString -String $WebApp.Replace("[Customer]",$Customer)).ToLower()

            If ($AzureRmWebAppName.Length -lt $configurationData.GlobalConfiguration.ShortNameCharacters) {
                $AzureRmWebAppName = "$AzureRmWebAppName$(Get-TruncatedStringHash -String $AzureRmWebAppName -Length ($configurationData.GlobalConfiguration.ShortNameCharacters - $AzureRmWebAppName.Length))"
            } else {
                $AzureRmWebAppName = $AzureRmWebAppName.SubString(0,$configurationData.GlobalConfiguration.ShortNameCharacters)
            } 

            Write-Output "Verify Web App: $AzureRmWebAppName`n$Header"
            Write-Output ""

            #Verify App Service Plan
            $AzureRmAppServicePlanName = (Remove-IllegalCharactersFromString -String $ConfigurationData.Customers.$Customer.WebApp.$WebApp.AppServicePlan.Name.Replace("[ResourceGroup]",$ResourceGroup)).ToLower()
            $AzureRmAppServicePlanName = $AzureRmAppServicePlanName.Replace("[customer]",$CustomerName)

            If ($AzureRmAppServicePlanName.Length -lt $configurationData.GlobalConfiguration.ShortNameCharacters) {
                $AzureRmAppServicePlanName = "$AzureRmAppServicePlanName$(Get-TruncatedStringHash -String $AzureRmAppServicePlanName -Length ($configurationData.GlobalConfiguration.ShortNameCharacters - $AzureRmAppServicePlanName.Length))"
            } else {
                $AzureRmAppServicePlanName = $AzureRmAppServicePlanName.SubString(0,$configurationData.GlobalConfiguration.ShortNameCharacters)
            }

            #Define App Service Plan Tier
            [string]$Tier = ""
            If ($ConfigurationData.Customers.$Customer.WebApp.$WebApp.AppServicePlan.Tier) {
                $Tier = $ConfigurationData.Customers.$Customer.WebApp.$WebApp.AppServicePlan.Tier
            } Else {
                $Tier = $ConfigurationData.ResourceGroups.$($ConfigurationData.Customers.$Customer.ResourceGroup).AppServicePlan.$($ConfigurationData.Customers.$Customer.WebApp.$WebApp.AppServicePlan.Name).Tier
            }

            #Verify App Service Plan
            If (-not($GetAzureRmAppServicePlan = Get-AzureRmAppServicePlan -Name $AzureRmAppServicePlanName -ResourceGroupName $ConfigurationData.Customers.$Customer.ResourceGroup -ErrorAction SilentlyContinue)) {
        
                Write-Output "New-AzureRmAppServicePlan`n$Header"

                $AzureRmAppServicePlanParams = @{
                    Name              = $AzureRmAppServicePlanName
                    Location          = $ConfigurationData.Customers.$Customer.Location
                    ResourceGroupName = $ConfigurationData.Customers.$Customer.ResourceGroup
                    Tier              = $Tier
                }

                Invoke-Logger -Message "New-AzureRmAppServicePlan -$($AzureRmAppServicePlanParams.Keys.ForEach({"$_ '$($AzureRmAppServicePlanParams.$_)'"}) -join ' -')" -Severity I -Category "AzureRmAppServicePlan"

                Try {
                    $AzureRmAppServicePlan = New-AzureRmAppServicePlan @AzureRmAppServicePlanParams -ErrorAction Stop

                    Invoke-Logger -Message $AzureRmAppServicePlan -Severity I -Category "AzureRmAppServicePlan"

                    Write-Output $AzureRmAppServicePlan
                }
                Catch {
                    Invoke-Logger -Message $_ -Severity E -Category "AzureRmAppServicePlan"

                    Write-Error $_
                }
            }
            Else {
                Invoke-Logger -Message $GetAzureRmAppServicePlan -Severity I -Category "AzureRmAppServicePlan"

                [bool]$ChangeAzureRmAppServicePlan = $False
                If ($GetAzureRmAppServicePlan.Sku.Tier -ne $Tier) {

                    Write-Output "Set-AzureRmAppServicePlan`n$Header"

                    $AzureRmAppServicePlanParams = @{
                        Name              = $AzureRmAppServicePlanName
                        ResourceGroupName = $ConfigurationData.Customers.$Customer.ResourceGroup
                        Tier              = $Tier
                    }

                    Invoke-Logger -Message "Set-AzureRmAppServicePlan -$($AzureRmAppServicePlanParams.Keys.ForEach({"$_ '$($AzureRmAppServicePlanParams.$_)'"}) -join ' -')" -Severity I -Category "AzureRmAppServicePlan"

                    Try {
                        $AzureRmAppServicePlan = Set-AzureRmAppServicePlan @AzureRmAppServicePlanParams -ErrorAction Stop

                        $ChangeAzureRmAppServicePlan = $True

                        Invoke-Logger -Message $AzureRmAppServicePlan -Severity I -Category "AzureRmAppServicePlan"

                        Write-Output $AzureRmAppServicePlan
                    }
                    Catch {
                        Invoke-Logger -Message $_ -Severity E -Category "AzureRmAppServicePlan"

                        Write-Error $_
                    }

                    #Restart Web Applications
                    If ($ChangeAzureRmAppServicePlan) {

                        [bool]$RestartWebApps = $true
                        If ($configurationData.GlobalConfiguration.Confirm) {
                            Write-host "A change of the AzureRmAppServicePlan requires a restart of all associated Web Applications" -ForegroundColor Green
                            Write-host "Would you like to restart all '$AzureRmAppServicePlanName' associated Web Applications? (Default is No)" -ForegroundColor Yellow
                    
                            $Readhost = Read-Host " ( y / n ) " 
                            Switch ($ReadHost) 
                            { 
                                Y {       $RestartWebApps = $true } 
                                N {       $RestartWebApps = $false } 
                                Default { $RestartWebApps = $false } 
                            }
                        }

                        If ($RestartWebApps) {
                            $AzureRmAppServicePlanWebApps = Get-AzureRmWebApp -ResourceGroupName $ConfigurationData.Customers.$Customer.ResourceGroup | Where-Object { $_.ServerFarmId -eq $GetAzureRmAppServicePlan.Id }

                            ForEach ($AzureRmAppServicePlanWebApp in $AzureRmAppServicePlanWebApps) {
                                Write-Output ""
                                Write-Output "Restart-AzureRmWebApp`n$Header"
                                Write-Output $AzureRmAppServicePlanWebApp.Name
                                Write-Output ""

                                Invoke-Logger -Message "Restart-AzureRmWebApp -ResourceGroupName $($ConfigurationData.Customers.$Customer.ResourceGroup) -Name $($AzureRmAppServicePlanWebApp.Name)" -Severity I -Category "AzureRmWebApp"

                                Try {
                                    $RestartAzureRmWebApp = Restart-AzureRmWebApp -ResourceGroupName $ConfigurationData.Customers.$Customer.ResourceGroup -Name $AzureRmAppServicePlanWebApp.Name

                                    Invoke-Logger -Message $RestartAzureRmWebApp -Severity I -Category "AzureRmWebApp"
                                }
                                Catch {
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
            If (-not($AzureRmWebApp = Get-AzureRmWebApp -Name $AzureRmWebAppName -ResourceGroupName $ConfigurationData.Customers.$Customer.ResourceGroup -ErrorAction SilentlyContinue)) {
                Write-Output "New-AzureRmWebApp`n$Header"

                $NewAzureRmWebApp = $True

                $AzureRmWebAppParams = @{
                    Name              = $AzureRmWebAppName
                    Location          = $ConfigurationData.Customers.$Customer.Location
                    ResourceGroupName = $ConfigurationData.Customers.$Customer.ResourceGroup
                    AppServicePlan    = $AzureRmAppServicePlanName
                }

                Invoke-Logger -Message "New-AzureRmWebApp -$($AzureRmWebAppParams.Keys.ForEach({"$_ '$($AzureRmWebAppParams.$_)'"}) -join ' -')" -Severity I -Category "AzureRmWebApp"

                Try {
                    $AzureRmWebApp = New-AzureRmWebApp @AzureRmWebAppParams -ErrorAction Stop

                    Invoke-Logger -Message $AzureRmWebApp -Severity I -Category "AzureRmWebApp"

                    Write-Output $AzureRmWebApp

                    Start-Sleep 30
                }
                Catch {
                    Invoke-Logger -Message $_ -Severity E -Category "AzureRmWebApp"

                    Write-Error $_
                }
            }
            Else {
                Invoke-Logger -Message $AzureRmWebApp -Severity I -Category "AzureRmWebApp"

                If ($GetAzureRmAppServicePlan.Id -ne $AzureRmWebApp.ServerFarmId) {
                    Write-Output "Set-AzureRmWebApp`n$Header"

                    $NewAzureRmWebApp = $True

                    $AzureRmWebAppParams = @{
                        Name              = $AzureRmWebAppName
                        ResourceGroupName = $ConfigurationData.Customers.$Customer.ResourceGroup
                        AppServicePlan    = $AzureRmAppServicePlanName
                    }

                    Invoke-Logger -Message "Set-AzureRmWebApp -$($AzureRmWebAppParams.Keys.ForEach({"$_ '$($AzureRmWebAppParams.$_)'"}) -join ' -')" -Severity I -Category "AzureRmWebApp"
                    
                    Try {
                        $AzureRmWebApp = Set-AzureRmWebApp @AzureRmWebAppParams -ErrorAction Stop

                        Invoke-Logger -Message $AzureRmWebApp -Severity I -Category "AzureRmWebApp"

                        $AzureRmWebAppChange = $True

                        Write-Output $AzureRmWebApp    

                        Start-Sleep 30
                    }
                    Catch {
                        Invoke-Logger -Message $_ -Severity E -Category "AzureRmWebApp"

                        Write-Error $_
                    }
                }
            }

            If (!$AzureRmWebApp) { Break }

            #Update Web Application Custom Domains
            If ($Tier -ne "Free") {
                If (!($AzureRmWebApp.HostNames -like "*$AzureRmWebAppName.$($ConfigurationData.GlobalConfiguration.TenantDomain)*")) {
                    Write-Output "Set-AzureRmWebApp`n$Header"

                    $SetAzureRmWebAppParams = @{
                        Name              = $AzureRmWebAppName
                        ResourceGroupName = $ConfigurationData.Customers.$Customer.ResourceGroup
                        HostNames         = @("$((Remove-IllegalCharactersFromString -String $Customer).ToLower()).$($ConfigurationData.GlobalConfiguration.TenantDomain)","$AzureRmWebAppName.azurewebsites.net")
                    }

                    Invoke-Logger -Message "Set-AzureRmWebApp -$($SetAzureRmWebAppParams.Keys.ForEach({"$_ '$($SetAzureRmWebAppParams.$_)'"}) -join ' -')" -Severity I -Category "AzureRmWebApp"
            
                    Try {
                        $SetAzureRmWebApp = Set-AzureRmWebApp @SetAzureRmWebAppParams -ErrorAction Stop

                        Invoke-Logger -Message $SetAzureRmWebApp -Severity I -Category "AzureRmWebApp"

                        Write-Output $SetAzureRmWebApp
                    }
                    Catch {
                        Invoke-Logger -Message $_ -Severity E -Category "AzureRmWebApp"

                        Write-Error $_
                    }
                }
            }

            #Update Web APplication Binaries
            If ($NewAzureRmWebApp -or $ConfigurationData.Customers.$Customer.WebApp.$WebApp.AlwaysUpdate) {
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

                If (-not ($NewAzureRmWebApp)) {
                    Write-Output "Remove-FilesFromWebApp`n$Header"

                    Remove-FilesFromWebApp -WebAppName $AzureRmWebAppName -ResourceGroupName $ResourceGroup -Verbose
        
                    Write-Output ""
                }

                Write-Output "Set-FileToWebApp`n$Header"

                If ($ConfigurationData.Customers.$Customer.WebApp.$WebApp.GlobalConfiguration) {
                    $FileName = $ConfigurationData.GlobalConfiguration.WebApp.SourceRepo
                } Else {
                    $FileName = $ConfigurationData.Customers.$Customer.WebApp.$WebApp.SourceRepo
                }

                $FileToWebAppParams = @{
                    WebAppName        = $AzureRmWebAppName
                    FileName          = $FileName
                    ResourceGroupName = $ConfigurationData.Customers.$Customer.ResourceGroup
                }

                Invoke-Logger -Message "New-AzureRmWebApp -$($FileToWebAppParams.Keys.ForEach({"$_ '$($FileToWebAppParams.$_)'"}) -join ' -')" -Severity I -Category "FileToWebApp"

                Try {
                    $FileToWebApp = Set-FileToWebApp @FileToWebAppParams -Verbose
    
                    Invoke-Logger -Message $FileToWebApp -Severity I -Category "FileToWebApp"

                    Write-Output $FileToWebApp
                }
                Catch {
                    Invoke-Logger -Message $_ -Severity E -Category "FileToWebApp"

                    Write-Error $_
                }
            }

            #Define App Settings properties
            $AppSettings = @{}
            If ($ConfigurationData.Customers.$Customer.WebApp.$WebApp.AppSettings.GlobalConfiguration) {
                ForEach ($variable in $ConfigurationData.GlobalConfiguration.WebApp.AppSettings.Keys) {
                    $value = $ConfigurationData.GlobalConfiguration.WebApp.AppSettings.$variable
                    New-Variable -Name $value -Value "`$ConfigurationData.$value" -Force
                    $value = $value.Replace("[WebApp]",$AzureRmWebAppName)
                    $value = $value.Replace("[Key]",$Keys[0].Value)
                    $AppSettings.add($variable,$value)
                }
            }
            Else {
                If ($ConfigurationData.Customers.$Customer.WebApp.$WebApp.AppSettings.Keys) {
                    ForEach ($variable in $ConfigurationData.Customers.$Customer.WebApp.$WebApp.AppSettings.Keys) {
                        New-Variable -Name $value -Value "`$ConfigurationData.$value" -Force
                        $value = $value.Replace("[WebApp]",$AzureRmWebAppName)
                        $value = $value.Replace("[Key]",$Keys[0].Value)
                        $AppSettings.add($variable,$value)
                    }
                }
            }

            #Verify App Settings
            $MyAzureRmWebApp = Get-AzureRmWebApp -Name $AzureRmWebAppName -ResourceGroupName $ConfigurationData.Customers.$Customer.ResourceGroup | Select -ExpandProperty SiteConfig | Select -ExpandProperty AppSettings

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

            #Update App Settings
            If ($AppSettingsUpdate) {
                $SetAzureRmWebAppParams = @{
                    Name              = $AzureRmWebAppName
                    ResourceGroupName = $ConfigurationData.Customers.$Customer.ResourceGroup
                    AppSettings       = $AppSettings
                }

                Write-Output "Set-AzureRmWebApp`n$Header"

                Invoke-Logger -Message "Set-AzureRmWebApp -$($SetAzureRmWebAppParams.Keys.ForEach({"$_ '$($SetAzureRmWebAppParams.$_)'"}) -join ' -')" -Severity I -Category "AzureRmWebAppSettings"

                Try {
                    $null = Set-AzureRmWebApp @SetAzureRmWebAppParams -ErrorAction Stop

                    Invoke-Logger -Message $SetAzureRmWebAppParams.AppSettings -Severity I -Category "AzureRmWebAppSettings"

                    Write-Output $SetAzureRmWebAppParams.AppSettings.Keys
                }
                Catch {
                    Invoke-Logger -Message $_ -Severity E -Category "AzureRmWebAppSettings"

                    Write-Error $_
                }
            }
            #>

        }
    }

}
#endregion

$Measure.Stop()

Write-Output ""
Write-Output $Header
Write-Output "Completed in $(($Measure.Elapsed).TotalSeconds) seconds"
Invoke-Logger -Message "Completed in $(($Measure.Elapsed).TotalSeconds) seconds" -Severity I -Category "TotalSeconds"