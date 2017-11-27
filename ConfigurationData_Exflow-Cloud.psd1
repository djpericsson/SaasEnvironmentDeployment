@{
    SaaSService = @{
        ResourceGroup = "SignUp-SAAS-Services"
        Location      = "West Europe"
        KeyVault = @{
            Name      = "[ResourceGroup]"
            SKU       = "Standard"
            Secrets   = @(
                @{     
                    "AppSettings" = @{
                        aad_PostLogoutRedirectUri = "https://[ResourceGroup].azurewebsites.net/close.aspx?signedout=yes"
                        aad_ExternalApiId         = "https://axtestdynamics365aos-addlevel.cloudax.dynamics.com"
                        StorageConnection         = "DefaultEndpointsProtocol=https;AccountName=[ResourceGroup];AccountKey=[Key];"
                        KeyValueStorageConnection = "DefaultEndpointsProtocol=https;AccountName=[ResourceGroup];AccountKey=[Key];"
                    }
                }
            )
        };
        Tags = @{
            Customer  = "SignUp"
            Solution  = "Exflow Cloud"
            Project   = "SaaS"
        };
    };

    ResourceGroups = @(
        @{
            Name                    = "SignUp-xfw-prod-rg"
            Location                = "West Europe"

            Storage = @{   
                Name                = "[ResourceGroup]"
                GlobalConfiguration = $True
            }

            CorsRules = @{
                GlobalConfiguration = $True
            }

            HybridConnection = @{
                Name                = "SignUp-navlabexflowcloud"
                Namespace           = "SignUp-navlabexflowcloudbus"
            }

            AppServicePlan = @{
                Name                = "[ResourceGroup]" 
                Tier                = "Free"
            }

            WebApp = @(
                @{     
                    "[ResourceGroup]" = @{
                        SourceRepo          = "C:\temp\alis.zip"
                        GlobalConfiguration = $True
                        AlwaysUpdate        = $True
                    }
                }

            )

            DnsRecordSet = @{
                Name                = "[ResourceGroup]"
                GlobalConfiguration = $True
            }

            AzureRmAutomationAccount = @{
                Name                 = "[ResourceGroup]"
                AzureRmAutomationCredential = @(
                    @{
                        Name         = "[ResourceGroup]"
                        Description  = "Used for Exflow SaaS Azure Automation"
                    }
                )

                AzureRmAutomationVariable = @(
                    @{
                        Name        = "RedistPath"
                        Value       = "https://github.com/djpericsson/AzureWebAppDeploy/raw/master"
                        Encrypted   = $False
                    }
                    @{
                        Name        = "PackageURL"
                        Value       = "https://exflowpackagemanager.azurewebsites.net"
                        Encrypted   = $False
                    }
                )
            }

            Tags = @{
                Customer = "SignUp"
                Solution = "Exflow Cloud"
                Project  = "SaaS"
            }
        }
    )

    GlobalConfiguration = @{

        RedistPath                      = "https://github.com/djpericsson/AzureWebAppDeploy/raw/master"
        PackageURL                      = "https://exflowpackagemanager.azurewebsites.net"

        LocalPath                       = $env:TEMP
        LogFile                         = "SaaS-RegistrationDeployment.log"
        LogEnabled                      = $True

        ShortNameCharacters             = "19"

        Prerequisites = @{
            AzureRmRoleAssignmentValidation = $True
            PowerShellVersion               = "5.0.0"
            Modules = @(
                @{
                    Name                    = "AzureRM"
                    RequiredVersion         = "4.4.1"
                }
            )
        }

        AzureRmAutomationAccount =
        @(
            @{
                Name               = 'AzureRmRunAsAccount'
                Description        = 'Used for Azure Automation'
            }
        )

        Storage = @{   
            Type       = "Standard_LRS"
            Containers = @(
                            "attachments"
                            "documents"
                            "exflowdiagnostics"
                         )
        }

        CorsRules = @{
            AllowedHeaders  = @("x-ms-meta-abc","Content-Encoding","Content-Range","Accept-Ranges","x-ms-meta-data*","x-ms-meta-target*")
            AllowedOrigins  = @("http://signup.exflow.debug","https://signup.exflow.cloud")
            MaxAgeInSeconds = 0
            ExposedHeaders  = @("Accept-Ranges","Content-Range","Content-Encoding","Content-Length","Content-Type")
            AllowedMethods  = @("Get")
        }

        DnsRecordSet = @{
                RecordType = "CNAME"
                Ttl        = "3600"
                DnsRecords = "[ResourceGroup].azurewebsites.net"
        }

        KuduAPI = @{
            URI                         = "scm.azurewebsites.net"
            Command                     = "/api/command"
            Zip                         = "/api/zip/site/wwwroot"
        }
    }
}

<#
AppSettings = @(
    @{
        aad_PostLogoutRedirectUri = "[SaaSService.KeyVault.Secrets.AppSettings.aad_PostLogoutRedirectUri]"
        aad_ExternalApiId         = "[SaaSService.KeyVault.Secrets.AppSettings.aad_ExternalApiId]"
        StorageConnection         = "[SaaSService.KeyVault.Secrets.AppSettings.StorageConnection]"
        KeyValueStorageConnection = "[SaaSService.KeyVault.Secrets.AppSettings.KeyValueStorageConnection]"
    }
)
#>