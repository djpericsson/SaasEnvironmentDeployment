@{
    #Global/shared configuration
    GlobalConfiguration = @{
        
        #Azure tenant information
        SubscriptionId      = '37c95fbb-6ced-4692-b3f4-474b16b766ad'
        TenantDomain        = 'exflowdev.cloud'
        
        #Web Application package information                    
        RedistPath          = 'https://github.com/djpericsson/AzureWebAppDeploy/raw/master'
        PackageURL          = 'https://exflowpackagemanager.azurewebsites.net'
        
        #Log file configuration                    
        LocalPath           = $env:TEMP
        LogFile             = 'SaaS-RegistrationDeployment.log'
        LogEnabled          = $True

        #Confirm restart Web Applications
        Confirm             = $False
        
        #Numbers of characters for resources                    
        ShortNameCharacters = '19'

        #Requirements for script to run
        Prerequisites = @{

            #Verify Owner/Contributor permissions to Azure Subscription
            AzureRmRoleAssignmentValidation = $True

            #Determine PowerShell version
            PowerShellVersion               = '5.0.0'

            #PowerShell module version requirements
            Modules = @(
                @{
                    Name                    = 'AzureRM'
                    RequiredVersion         = '4.4.1'
                }
            )
        }

        #Default storage parameters
        Storage = @{   
            Type            = 'Standard_LRS'

            #Containers/blob storage
            Containers      = @(
                                 'attachments'
                                 'documents'
                                 'exflowdiagnostics'
                              )
        }

        #Default Cors rules parameters
        CorsRules = @{
            AllowedHeaders  = @('x-ms-meta-abc','Content-Encoding','Content-Range','Accept-Ranges','x-ms-meta-data*','x-ms-meta-target*')
            AllowedOrigins  = @('http://signup.exflow.debug','https://signup.exflowdev.cloud')
            MaxAgeInSeconds = 0
            ExposedHeaders  = @('Accept-Ranges','Content-Range','Content-Encoding','Content-Length','Content-Type')
            AllowedMethods  = @('Get')
        }

        #Default DNS record parameters
        DnsRecordSet = @{
                RecordType  = 'CNAME'
                Ttl         = '3600'
                DnsRecords  = '[ResourceGroup].azurewebsites.net'
        }

        #Default Web Application parameters
        WebApp = @{
            SourceRepo      = 'C:\temp\alis.zip'

            #Application Settings
            AppSettings = @{
                'ApplicationInsightsInstrumentationKey'      = '72d119d9-a1cc-4eb1-b669-7af55d540c0d'
                'Startup.DeploymentName'                     = '[WebApp]'
                'Startup.KeyVaultCredentialConnectionString' = 'RunAs=App; TenantId=dedd0f01-f944-4b39-a6a8-3a46f9ed225a; AppId=f3a53516-b366-401f-a211-b987b645e3eb; AppKey=[Key]'
                'offline_'                                   = '85.24.197.82'
            }
        }

        #Default Key Vault parameters
        KeyVault = @{
            Name      = '[ResourceGroup]'
            SKU       = 'Standard'

            #Key Vault Secrets
            Secrets   = @(
                @{     
                    'AppSettings' = @{
                        AppControlMergeFile               = 'App.NAV.WS.xml?{DebugLog}=false;{FormsTestSite}=true;{PurchaseDisabled}=true;{UseNAVSSOEmailing}=false'
                        aad_AADInstance                   = ''
                        aad_ClientId                      = ''
                        aad_ClientSecret                  = ''
                        aad_TenantId                      = ''
                        FormsTestSitePassword             = '2'
                        aad_PostLogoutRedirectUri         = 'https://navlab.exflowdev.cloud/ExFlowDynamics/close.aspx?signedout=yes'
                        userName                          = 'ADMUSR'
                        password                          = '******'
                        address                           = 'https://sd0-nav06:7347/CH_NAVUSERPASS/WS/ReplaceWithAPercentEncodedCompanyName/Codeunit/EXFWEB'
                        endpointName                      = 'ExFlowSSL20170921_Port'
                        security_TicketFormsTestSiteUsers = 'none@nowhere.no'
                        dynamicsChannel                   = ''
                        clientTypeName                    = 'ExFlow.Logic.NAVServiceReference20170921.EXFWEB_PortClient,ExFlow.Logic'
                        company                           = 'My Test Company AB'
                        security_Admins                   = 'BB,CC'
                        StorageConnection                 = 'DefaultEndpointsProtocol=https;AccountName=[ResourceGroup];AccountKey=[Key];EndpointSuffix=core.windows.net'
                        KeyValueStorageConnection         = 'DefaultEndpointsProtocol=https;AccountName=[ResourceGroup];AccountKey=[Key];EndpointSuffix=core.windows.net'
                    }
                }
            )
        }

        #Default KuduAPI parameters
        KuduAPI = @{
            URI     = 'scm.azurewebsites.net'
            Command = '/api/command'
            Zip     = '/api/zip/site/wwwroot'
        }
    }

    #SaaS Resource Group configuration
    SaaSService = @{

        #Resource Group name and configuration
        ResourceGroup = 'SAAS-Services'
        Location      = 'West Europe'

        #Automation account credential parameters
        AzureRmAutomationAccount =
        @(
            @{
                Name        = 'AzureRmRunAsAccount'
                Description = 'Used for Azure Automation'
            }
        )

        #Automation certificate parameters
        AzureRmAutomationCertificate =
        @(
            @{
                CertificateAssetName = 'AzureRunAs'
                Description          = ''
            }
        )

        #Service Tags
        Tags = @{
            Customer  = 'SignUp'
            Solution  = 'Exflow DEV Cloud'
            Project   = 'SaaS'
        }
    }

    #Resource Groups configurations
    ResourceGroups = @(
        @{

            #Resource Group Name
            'DEV-xfw-prod-rg' = @{
                Location = 'West Europe'

                #App Service Plan parameters
                AppServicePlan = @(
                    @{     
                        '[ResourceGroup]' = @{
                            Name = '[ResourceGroup]' 
                            Tier = 'Basic'
                        }
                    }

                )

                #Key Vault parameters
                KeyVault = @{
                    Name = '[ResourceGroup]'
                    SKU  = 'Standard'
                }

                #Azure Automation parameters
                AzureRmAutomationAccount = @{
                    Name                 = '[ResourceGroup]'

                    #Automation credential parameters
                    AzureRmAutomationCredential = @(
                        @{
                            Name        = '[ResourceGroup]'
                            Description = 'Used for ExflowDEV SaaS Azure Automation'
                        }
                    )

                    #Automation variables parameters
                    AzureRmAutomationVariable = @(
                        @{
                            Name      = 'RedistPath'
                            Value     = 'https://github.com/djpericsson/AzureWebAppDeploy/raw/master'
                            Encrypted = $False
                        }
                    )
                }

                #Hybrid Connection parameters
                HybridConnection = @{
                    Enabled   = $False
                    Name      = 'navlabexflowdevcloud'
                    Namespace = 'navlabexflowdevcloudbus'
                }

                #Service Tags
                Tags = @{
                    Customer = 'SignUp'
                    Solution = 'Exflow DEV Cloud'
                    Project  = 'SaaS'
                }
            }
        }
    )

    #Customer configurations
    Customers = @(
        @{

            #Customer name
            'Addlevel AB' = @{

                #Resource Group belongings
                ResourceGroup           = 'DEV-xfw-prod-rg'
                Location                = 'West Europe'

                #Storage parameters
                Storage = @{   
                    GlobalConfiguration = $True
                }

                #Cors Rule parameters
                CorsRules = @{
                    GlobalConfiguration = $True
                }

                #DNS record parameters
                DnsRecordSet = @{
                    GlobalConfiguration = $True
                }

                #Web Application parameters
                WebApp = @(
                    @{     
                        '[Customer]' = @{

                            #Read configuration from global scope
                            GlobalConfiguration     = $True

                            #Always update binaries when running script
                            AlwaysUpdate            = $False

                            #App Settings parameters
                            AppSettings = @{

                                #Read configuration from global scope
                                GlobalConfiguration = $True
                            }

                            #App Service Plan parameters
                            AppServicePlan = @{
                                Name                = '[ResourceGroup]'
                            }
                        }
                    }

                )

                #Key Vault Secret parameters
                KeyVaultSecret = @{
                    GlobalConfiguration = $True
                }

                #Service Tags
                Tags = @{
                    Customer = 'Addlevel AB'
                    Solution = 'Exflow DEV Cloud'
                    Project  = 'SaaS'
                }
            }
        }
    )
}