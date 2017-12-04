@{
    SaaSService = @{
        ResourceGroup = "SignUp-SAAS-Services"
        Location      = "West Europe"

        Tags = @{
            Customer  = "SignUp"
            Solution  = "Exflow Cloud"
            Project   = "SaaS"
        }
    }

    ResourceGroups = @(
        @{     
            "SignUp-xfw-prod-rg" = @{
                Location = "West Europe"

                AppServicePlan = @(
                    @{     
                        "[ResourceGroup]" = @{
                            Name = "[ResourceGroup]" 
                            Tier = "Free"
                        }
                    }

                )

                KeyVault = @{
                    Name = "[ResourceGroup]"
                    SKU  = "Standard"
                }

                AzureRmAutomationAccount = @{
                    Name                 = "[ResourceGroup]"
                    AzureRmAutomationCredential = @(
                        @{
                            Name        = "[ResourceGroup]"
                            Description = "Used for Exflow SaaS Azure Automation"
                        }
                    )

                    AzureRmAutomationVariable = @(
                        @{
                            Name      = "RedistPath"
                            Value     = "https://github.com/djpericsson/AzureWebAppDeploy/raw/master"
                            Encrypted = $False
                        }
                    )
                }

                HybridConnection = @{
                    Enabled   = $False
                    Name      = "SignUp-navlabexflowcloud"
                    Namespace = "SignUp-navlabexflowcloudbus"
                }

                Tags = @{
                    Customer = "SignUp"
                    Solution = "Exflow Cloud"
                    Project  = "SaaS"
                }
            }
        }
    )

    Customers = @(
        @{     
            "Addlevel3" = @{
                Location                = "West Europe"

                ResourceGroup           = "SignUp-xfw-prod-rg"

                Storage = @{   
                    GlobalConfiguration = $True
                }

                CorsRules = @{
                    GlobalConfiguration = $True
                }

                DnsRecordSet = @{
                    GlobalConfiguration = $True
                }

                WebApp = @(
                    @{     
                        "[Customer]" = @{
                            GlobalConfiguration     = $True
                            AlwaysUpdate            = $True
                            AppSettings = @{
                                GlobalConfiguration = $True
                            }
                            AppServicePlan = @{
                                Name                = "[ResourceGroup]"
                            }
                        }
                    }

                )

                KeyVaultSecret = @{
                    GlobalConfiguration = $True
                }

                Tags = @{
                    Customer            = "Addlevel"
                    Solution            = "Exflow Cloud"
                    Project             = "SaaS"
                }
            }
        }
    )

    GlobalConfiguration = @{

        RedistPath                          = "https://github.com/djpericsson/AzureWebAppDeploy/raw/master"
        PackageURL                          = "https://exflowpackagemanager.azurewebsites.net"
                                            
        LocalPath                           = $env:TEMP
        LogFile                             = "SaaS-RegistrationDeployment.log"
        LogEnabled                          = $True
                                            
        ShortNameCharacters                 = "19"

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
                Name        = 'AzureRmRunAsAccount'
                Description = 'Used for Azure Automation'
            }
        )

        Storage = @{   
            Type            = "Standard_LRS"
            Containers      = @(
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
                RecordType  = "CNAME"
                Ttl         = "3600"
                DnsRecords  = "[ResourceGroup].azurewebsites.net"
        }

        WebApp = @{
            SourceRepo      = "C:\temp\alis.zip"
        }

        AppSettings = @{
            "ApplicationInsightsInstrumentationKey"      = "72d119d9-a1cc-4eb1-b669-7af55d540c0d"
            "Startup.DeploymentName"                     = "[WebApp]"
            "Startup.KeyVaultCredentialConnectionString" = "RunAs=App; TenantId=dedd0f01-f944-4b39-a6a8-3a46f9ed225a; AppId=f3a53516-b366-401f-a211-b987b645e3eb; AppKey=[Key]"
            "offline_"                                   = "85.24.197.82"
        }

        KeyVault = @{
            Name      = "[ResourceGroup]"
            SKU       = "Standard"
            Secrets   = @(
                @{     
                    "AppSettings" = @{
                        AppControlMergeFile               = "App.NAV.WS.xml?{DebugLog}=false;{FormsTestSite}=true;{PurchaseDisabled}=true;{UseNAVSSOEmailing}=false"
                        aad_AADInstance                   = ""
                        aad_ClientId                      = ""
                        aad_ClientSecret                  = ""
                        aad_TenantId                      = ""
                        FormsTestSitePassword             = "2"
                        aad_PostLogoutRedirectUri         = "https://navlab.exflow.cloud/ExFlowDynamics/close.aspx?signedout=yes"
                        userName                          = "ADMUSR"
                        password                          = "******"
                        address                           = "https://sd0-nav06:7347/CH_NAVUSERPASS/WS/ReplaceWithAPercentEncodedCompanyName/Codeunit/EXFWEB"
                        endpointName                      = "ExFlowSSL20170921_Port"
                        security_TicketFormsTestSiteUsers = "none@nowhere.no"
                        dynamicsChannel                   = ""
                        clientTypeName                    = "ExFlow.Logic.NAVServiceReference20170921.EXFWEB_PortClient,ExFlow.Logic"
                        company                           = "Test Company"
                        security_Admins                   = "BB,CC"
                        StorageConnection                 = "DefaultEndpointsProtocol=https;AccountName=[ResourceGroup];AccountKey=[Key];EndpointSuffix=core.windows.net"
                        KeyValueStorageConnection         = "DefaultEndpointsProtocol=https;AccountName=[ResourceGroup];AccountKey=[Key];EndpointSuffix=core.windows.net"
                    }
                }
            )
        }

        KuduAPI = @{
            URI     = "scm.azurewebsites.net"
            Command = "/api/command"
            Zip     = "/api/zip/site/wwwroot"
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