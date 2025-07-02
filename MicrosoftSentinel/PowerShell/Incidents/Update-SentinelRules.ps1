#Requires -Version 5.0
<#
    .SYNOPSIS
    
    Microsoft Sentinel Alert Rule Management
    Sentinel Alert Rules Management with Add / Update / Remove & Alert Rule Action automation
    Please see blog-post for detailed walkthrough of the script https://mortenknudsen.net/?p=525

    .MORE INFORMATION
    https://learn.microsoft.com/en-us/rest/api/securityinsights/preview/data-connectors/list?tabs=HTTP

    .NOTES
    VERSION: 2301

    .COPYRIGHT
    @mortenknudsendk on Twitter
    Blog: https://mortenknudsen.net
    
    .LICENSE
    Licensed under the MIT license.

    .WARRANTY
    Use at your own risk, no warranty given!
#>


########################################
# VARIABLES
########################################

    #############################################################################
    # LogAnalytics Workspaces
    #############################################################################

    $global:MainLogAnalyticsWorkspaceName                           = "<WorkspaceName>"
    $global:MainLogAnalyticsWorkspaceSubId                          = "<SubscriptionId>"
    $global:MainLogAnalyticsWorkspaceResourceGroup                  = "<ResourceGroupName>"


    #############################################################################
    # Sentinel
    #############################################################################

    $global:Sentinel_DataConnectors_ExcludeAlertRules               = @(
                                                                        "AIVectraStream"
                                                                        "AWS"
                                                                        "AWSS3"
                                                                        "Barracuda"
                                                                        "CEF"
                                                                        "CheckPoint"
                                                                        "CiscoASA"
                                                                        "CiscoUmbrellaDataConnector"
                                                                        "Corelight"
                                                                        "Dynamics365"
                                                                        "F5"
                                                                        "Fortinet"
                                                                        "GCPDNSDataConnector"
                                                                        "InfobloxNIOS"
                                                                        "IoT"
                                                                        "MicrosoftSysmonForLinux"
                                                                        "NXLogDnsLogs"
                                                                        "PaloAltoNetworks"
                                                                        "ProofpointPOD"
                                                                        "PulseConnectSecure"
                                                                        "QualysVulnerabilityManagement"
                                                                        "SquidProxy"
                                                                        "Syslog"
                                                                        "ThreatIntelligence"
                                                                        "ThreatIntelligenceTaxii"
                                                                        "TrendMicro"
                                                                        "WAF"
                                                                        "Zscaler"                                                                        
                                                                        )

    # Sentinel Alert Management
    $global:Sentinel_DeleteExcludedAlertRulesFromTemplateIfFound    = $false
    $global:Sentinel_DeleteDupletAlertsRulesIfFound                 = $false
    $global:Sentinel_CreateUpdateAlertRulesWithNoDataConnectorReq   = $true

    # Sentinel Alert Rule Action (default)
    $global:SentinelAlertingEnableLogicAppAction                    = $true
    $global:SentinelAlertingForceSetExistingRules                   = $true

    $global:SentinelAlertingLogicAppActionName                      = "SendEmail"
    $global:SentinelAlertingLogicAppActionRG                        = "<ResourceGroupName>"
    $global:SentinelAlertingLogicAppActionTriggerName               = "When_a_response_to_an_Azure_Sentinel_alert_is_triggered"

    # Sentinel Alert Rule management logging
    $global:Sentinel_Issues_List                                    = "D:\SCRIPTS\OUTPUT\SENTINEL_AlertRules_Issues_List.txt"
    $global:Sentinel_Issues_Detailed                                = "D:\SCRIPTS\OUTPUT\SENTINEL_AlertRules_Issues_Detailed.txt"


################################################################################
# MODULES
################################################################################

    # Install-module Az.SecurityInsights
    # Import-module Az.SecurityInsights


################################################################################
# CONNECT
################################################################################

    Connect-AzAccount

    $AccessToken = Get-AzAccessToken -ResourceUrl https://management.azure.com/
    $AccessToken = $AccessToken.Token
 
    $Header = @{
                    "Authorization"="Bearer $($AccessToken)"
                    "Content-Type"="application/json"
               }

    Set-AzContext -Subscription $global:MainLogAnalyticsWorkspaceSubId -Tenant $global:AzureTenantID


################################################################################
# INITIALIZATION
################################################################################

    # Log-files
    If (Test-Path $global:Sentinel_Issues_List)
        {
                Remove-Item $global:Sentinel_Issues_List
        }
    If (Test-Path $global:Sentinel_Issues_Detailed)
        {
                Remove-Item $global:Sentinel_Issues_Detailed
        }


################################################################################
# DATA CONNECTORS BASED ON ALL TEMPLATES
################################################################################

    # Connector-list - Must be run to see if new connectors have been added, which should be added to exclude & include list
    $baseUri = "/subscriptions/$($global:MainLogAnalyticsWorkspaceSubId)/resourceGroups/$($global:MainLogAnalyticsWorkspaceResourceGroup)/providers/Microsoft.OperationalInsights/workspaces/$($global:MainLogAnalyticsWorkspaceName)"
    $Uri = "$baseUri/providers/Microsoft.SecurityInsights/alertRuleTemplates/?api-version=2022-12-01-preview"

    $AllAlertRuleFromTemplatesApi = (Invoke-AzRestMethod -Path $Uri -Method GET).Content | ConvertFrom-Json
    $AllAlertRuleFromTemplates = $AllAlertRuleFromTemplatesApi.value
    $CompleteConnectorList = $AllAlertRuleFromTemplates.properties.RequiredDataConnectors.ConnectorId | Sort-Object -Unique

    Write-Output "Complete list of Data Connectors defined in alert rules templates"
    $CompleteConnectorList

   

################################################################################
# DATA CONNECTORS CURRENTLY IN USE - NOT USED AS DATA-SET IS INCOMPLETE !!
################################################################################

<#
    # Method 1 (PS) - incomplete data-set
    $ConnectorsInUse = Get-AzSentinelDataConnector -ResourceGroupName $global:MainLogAnalyticsWorkspaceResourceGroup -workspaceName $global:MainLogAnalyticsWorkspaceName
    $ConnectorsInUseList = $ConnectorsInUse.kind | Sort-Object -Unique

    # Method 2 (API preview 2022-12-01-preview) - incomplete data-set
    $baseUri = "/subscriptions/$($global:MainLogAnalyticsWorkspaceSubId)/resourceGroups/$($global:MainLogAnalyticsWorkspaceResourceGroup)/providers/Microsoft.OperationalInsights/workspaces/$($global:MainLogAnalyticsWorkspaceName)"
    $connectedDataConnectorsUri = "$baseUri/providers/Microsoft.SecurityInsights/dataConnectors/?api-version=2022-12-01-preview"

    $ConnectorsInUse = (Invoke-AzRestMethod -Path $connectedDataConnectorsUri -Method GET).Content | ConvertFrom-Json			
    $ConnectorsInUseList = $ConnectorsInUse.value
#>

################################################################################
# TEMPLATE SCOPING FOR ALERT RULES
################################################################################

    $RulesWithoutRequiredConnectors  = $AllAlertRuleFromTemplates | Where-Object {$_.properties.RequiredDataConnectors -eq $null }
    $RulesWithRequiredConnectors     = $AllAlertRuleFromTemplates | Where-Object {$_.properties.RequiredDataConnectors}

    $ExcludedAlertRulesFromTemplates = @()
    $IncludedAlertRulesFromTemplates = @()

    # Loop through all templates, which are NOT part of excluded (non-existing) connectors
    ForEach ($Rule in $RulesWithRequiredConnectors)
        {
            $Connectors = $Rule.properties.RequiredDataConnectors.ConnectorId
            $ConnectorsCount = $Connectors.count

            If ($Connectors)
                {
                    $Exclude = $false
                    ForEach ($Connector in $Connectors)
                        {
                            # Only exclude alert rules with explicit requirement for a single data connector, which is excluded
                            # This will enable alert rules, which includes many data connectors, where soe of them are excluded
                            # this way the alert rule will be enabled for the remaining connectors inside the rule.
                            If ( ( $ConnectorsCount -eq 1) -and ($Connector -in $global:Sentinel_DataConnectors_ExcludeAlertRules) -and ($Exclude -eq $false) )
                                {
                                    $Exclude = $true
                                    $ExcludedAlertRulesFromTemplates += $Rule
                                }
                        }
                    
                    If ($Exclude -eq $false) # Fall-back using alert rules, which is not excluded
                        {
                            $IncludedAlertRulesFromTemplates += $Rule
                        }
                }
        }

    If ($global:Sentinel_CreateUpdateAlertRulesWithNoDataConnectorReq)
        {
            $RulesTargetCount = ($RulesWithoutRequiredConnectors.count) + ($IncludedAlertRulesFromTemplates.count)
        }
    Else
        {
            $RulesTargetCount = ($IncludedAlertRulesFromTemplates.count)
        }


    Write-Output ""
    Write-Output "Alert Rules with requirement for Data Connector"
    Write-Output "Number of Alert Rules from Included templates                : $($IncludedAlertRulesFromTemplates.count)"
    Write-Output "Number of Alert Rules from Excluded templates                : $($ExcludedAlertRulesFromTemplates.count)"
    Write-Output ""
    Write-Output "Alert Rules without requirement for Data Connector"
    Write-Output "Number of Alert Rules without requirement for Data Connector : $($RulesWithoutRequiredConnectors.count)"

    Write-Output ""
    Write-Output "Target alert rules                                           : $($RulesTargetCount)"


################################################################################
# BUILD LISTS OF CURRENT ANALYTICS RULES
################################################################################

    # Get all existing Alert Rules
    $baseUri = "/subscriptions/$($global:MainLogAnalyticsWorkspaceSubId)/resourceGroups/$($global:MainLogAnalyticsWorkspaceResourceGroup)/providers/Microsoft.OperationalInsights/workspaces/$($global:MainLogAnalyticsWorkspaceName)"
    $Uri = "$baseUri/providers/Microsoft.SecurityInsights/alertRules/?api-version=2022-12-01-preview"

    $CurrentAlertRulesApi = (Invoke-AzRestMethod -Path $Uri -Method GET).Content | ConvertFrom-Json			
    $CurrentAlertRules = $CurrentAlertRulesApi.value

    Write-Output ""
    Write-Output "Number of existing Alert Rules found in Sentinel             : $($CurrentAlertRules.count)"


#########################################################################################
# BUILD LISTS OF ANALYTICS RULES - UpdatePending, Missing, Installed, Remove (clean-up)
#########################################################################################

    $UpdatePendingAlertRuleArray = @()
    $MissingAlertRuleArray       = @()
    $InstalledAlertRuleArray     = @()
    $RemoveAlertRuleArray        = @()

    # Alert Rules with Requirement for Data Connector
    ForEach ($TemplateAlertRule in $IncludedAlertRulesFromTemplates)
        {
            # Checking the status of the alert rule
            $CurrentAlertRule = $CurrentAlertRules | Where-Object { $_.properties.AlertRuleTemplateName -eq $TemplateAlertRule.name }

            If ($CurrentAlertRule -eq $null)
                {
                    $MissingAlertRuleArray += $TemplateAlertRule
                }
            Else
                {
                    # Template version Info
                    $LastModifiedUtcTemplate = (Get-date $TemplateAlertRule.properties.lastUpdatedDateUTC -format u)

                    # Alert Rule version info
                    Try
                        {
                            $LastModifiedUtcCurrentAlertRule = (Get-date $CurrentAlertRule.properties.LastModifiedUtc -format u)
                        }
                    Catch
                        {
                            # Sometimes last modified is empty
                            $LastModifiedUtcCurrentAlertRule = $null
                        }

                    If ( $LastModifiedUtcCurrentAlertRule -ge $LastModifiedUtcTemplate )
                        {
                            $InstalledAlertRuleArray += $TemplateAlertRule
                        }
                    ElseIf ( ($LastModifiedUtcCurrentAlertRule) -lt ($LastModifiedUtcTemplate) -or ($LastModifiedUtcCurrentAlertRule -eq $null) )
                        {
                            $UpdatePendingAlertRuleArray += $TemplateAlertRule
                        }
                }
        }


    # Alert Rules without Requirement for Data Connector, looks like a mistake in definition
    If ($global:Sentinel_CreateUpdateAlertRulesWithNoDataConnectorReq)
        {
            ForEach ($TemplateAlertRule in $RulesWithoutRequiredConnectors)
                {
                    # Checking the status of the alert rule
                    $CurrentAlertRule = $CurrentAlertRules | Where-Object { $_.properties.AlertRuleTemplateName -eq $TemplateAlertRule.name }

                    If ($CurrentAlertRule -eq $null)
                        {
                            $MissingAlertRuleArray += $TemplateAlertRule
                        }
                    Else
                        {
                            # Template version Info
                            $LastModifiedUtcTemplate = (Get-date $TemplateAlertRule.properties.lastUpdatedDateUTC -format u)

                            # Alert Rule version info
                            Try
                                {
                                    $LastModifiedUtcCurrentAlertRule = (Get-date $CurrentAlertRule.properties.LastModifiedUtc -format u)
                                }
                            Catch
                                {
                                    # Sometimes last modified is empty
                                    $LastModifiedUtcCurrentAlertRule = $null
                                }

                            If ( $LastModifiedUtcCurrentAlertRule -ge $LastModifiedUtcTemplate )
                                {
                                    $InstalledAlertRuleArray += $TemplateAlertRule
                                }
                            ElseIf ( ($LastModifiedUtcCurrentAlertRule) -lt ($LastModifiedUtcTemplate) -or ($LastModifiedUtcCurrentAlertRule -eq $null) )
                                {
                                    $UpdatePendingAlertRuleArray += $TemplateAlertRule
                                }
                        }
                }
        }

    # Summary List
    $CreateOrUpdateAlertRuleArray = @()
    $CreateOrUpdateAlertRuleArray += $UpdatePendingAlertRuleArray
    $CreateOrUpdateAlertRuleArray += $MissingAlertRuleArray

    $RemoveAlertRuleArray = $CurrentAlertRules | Where-Object { $_.properties.alertRuleTemplateName -in $ExcludedAlertRulesFromTemplates.name }

    Write-Output ""
    Write-Output "Number of Alert Rules OK                                     : $($InstalledAlertRuleArray.count)"
    Write-Output "Number of Alert Rules to Create                              : $($MissingAlertRuleArray.count)"
    Write-Output "Number of Alert Rules to Update                              : $($UpdatePendingAlertRuleArray.count)"
    Write-Output "Number of Alert Rules to Remove                              : $($RemoveAlertRuleArray.count)"


################################################################################
# CREATE AND UPDATE ANALYTICS RULES
################################################################################

    $AlertsRulesCreatedUpdated = @()
    $AlertsRulesWithIssues     = @()

     ForEach ($AlertRule in $CreateOrUpdateAlertRuleArray)
        {
            Write-Output ""
            Write-Output "-------------------------------------------------------------------------------------"
            Write-Output ""

            $CurrentAlertRule = $CurrentAlertRules | Where-Object { $_.properties.AlertRuleTemplateName -eq $AlertRule.name } 

            If ($CurrentAlertRule)             # Update existing alert rule
                {
                    $CurrentAlertRule = $CurrentAlertRule[0]
                    Write-Output ""
                    Write-Output "Updating Analytics rule ($($AlertRule.kind)): $($AlertRule.properties.displayName)"
                    # Use existing rule name
                    $uri = "https://management.azure.com$baseUri/providers/Microsoft.SecurityInsights/alertRules/$($CurrentAlertRule.name)?api-version=2022-12-01-preview"

                    # Get existing status
                    $AlertRuleEnabled = $CurrentAlertRule.properties.Enabled[0]
                }
            Else
                {
                    Write-Output ""
                    Write-Output "Creating Analytics rule ($($AlertRule.kind)): $($AlertRule.properties.displayName)"
                
                    # Get new GUID
                    $Guid = New-Guid
                    $uri = "https://management.azure.com$baseUri/providers/Microsoft.SecurityInsights/alertRules/$($Guid.Guid)?api-version=2022-12-01-preview"
                    $AlertRuleEnabled = $True
                }

            # Mandatory values, which might be missing from templates
            If (!($AlertRule.properties.suppressionDuration)) {$AlertRule.properties | Add-Member -NotePropertyName suppressionDuration -NotePropertyValue "PT12H" -Force}
            If (!($AlertRule.properties.suppressionEnabled))  {$AlertRule.properties | Add-Member -NotePropertyName suppressionEnabled -NotePropertyValue $false -Force}

            $AlertRule.properties | Add-Member -NotePropertyName enabled -NotePropertyValue $AlertRuleEnabled -Force

            # Adding extra information
            $AlertRule.properties | Add-Member -NotePropertyName alertRuleTemplateName -NotePropertyValue $AlertRule.name -Force
            $AlertRule.properties | Add-Member -NotePropertyName alertRuleVersion -NotePropertyValue $AlertRule.properties.version -Force
            $AlertRule.properties | Add-Member -NotePropertyName alertRuleLastUpdatedUtc -NotePropertyValue $AlertRule.properties.lastUpdatedDateUTC -Force

            # Removing template info
            $AlertRule.PSObject.Properties.Remove('id')
            $AlertRule.PSObject.Properties.Remove('name')
            $AlertRule.PSObject.Properties.Remove('type')

            $BodyJson = $AlertRule | ConvertTo-Json -Depth 100

            Try
                {
                    $RuleUpdateOrCreate = Invoke-RestMethod $uri -Body $Bodyjson -Method PUT -Headers $Header -ContentType "application/json"
                    $RuleUpdateOrCreate
                }
            Catch
                {
                    Write-Output $_

                    Add-Content -Path $global:Sentinel_Issues_Detailed -Value "DISPLAYNAME -> $($AlertRule.properties.displayName)"
                    Add-Content -Path $global:Sentinel_Issues_Detailed -Value "---- ERROR ----"
                    Add-Content -Path $global:Sentinel_Issues_Detailed -Value $_
                    Add-Content -Path $global:Sentinel_Issues_Detailed -Value "---- ALERT RULE ----"
                    Add-Content -Path $global:Sentinel_Issues_Detailed -Value $BodyJson
                    Add-Content -Path $global:Sentinel_Issues_Detailed -Value "---------------------------------------------"
                }

            #########################
            # Control | Verification
            #########################
            Try
                {
                    $RuleChk = Invoke-RestMethod $uri -Method GET -Headers $Header -ContentType "application/json" 

                    If ($RuleChk)
                        {
                            Write-Output "SUCCESS"

                            # Add result to array
                            $AlertsRulesCreatedUpdated += $RuleUpdateOrCreate
                        }
                }
            Catch
                {
                    Write-Output ""
                    Write-Output "ERROR. Something went wrong. Probaly a missing column or table. See log-file for more info."

                    # Add result to array
                    $AlertsRulesWithIssues += $RuleUpdateOrCreate

                    Add-Content -Path $global:Sentinel_Issues_List -Value "$($AlertRule.properties.displayName)"
                }
        }



################################################################################
# DELETE ANALYTICS RULES
################################################################################

If ($global:Sentinel_DeleteExcludedAlertRulesFromTemplateIfFound)
    {
         ForEach ($AlertRule in $RemoveAlertRuleArray)
            {
                Write-Output ""
                Write-Output "Deleting Analytics rule ($($AlertRule.kind)): $($AlertRule.properties.displayName)"
                
                # Use existing rule name
                $uri = "https://management.azure.com$baseUri/providers/Microsoft.SecurityInsights/alertRules/$($AlertRule.name)?api-version=2022-12-01-preview"
                
                Try
                    {
                        $RuleDelete = Invoke-RestMethod $uri -Method DELETE -Headers $Header -ContentType "application/json"
                    }
                Catch
                    {
                        Write-Output ""
                        Write-Output "ERROR. Something went wrong trying to delete the alert rule."
                    }
            }
    }
Else
    {
        Write-Output "Existing Alert Rules was found that should be considered for deletion as the template has been excluded:"
        $RemoveAlertRuleArray.properties.displayName
    }


################################################################################
# DELETE DUPLETS OF ANALYTICS RULES WITH SAME DISPLAYNAME
################################################################################

    $RemoveDupletsAlertRuleArray = @()

    Write-Output ""
    Write-Output "Building list of current analytics rules to detect duplets ... Please Wait !"

    # Get all existing Alert Rules
    $baseUri = "/subscriptions/$($global:MainLogAnalyticsWorkspaceSubId)/resourceGroups/$($global:MainLogAnalyticsWorkspaceResourceGroup)/providers/Microsoft.OperationalInsights/workspaces/$($global:MainLogAnalyticsWorkspaceName)"
    $Uri = "$baseUri/providers/Microsoft.SecurityInsights/alertRules/?api-version=2022-12-01-preview"

    $CurrentAlertRulesApi = (Invoke-AzRestMethod -Path $Uri -Method GET).Content | ConvertFrom-Json			
    $CurrentAlertRules = $CurrentAlertRulesApi.value

    $CurrentAlertRulesDistinct = $CurrentAlertRules | Select-Object -ExpandProperty Properties | Sort-Object -Property displayName -Unique
    $CurrentAlertRulesDistinctDisplayName = $CurrentAlertRulesDistinct.displayName

    ForEach ($Rule in $CurrentAlertRulesDistinctDisplayName)
        {
            $Entries = $CurrentAlertRules | Where-Object { $_.properties.displayName -eq $Rule }
            $EntriesCount = $Entries.count

            If ($EntriesCount -gt 1)
                {
                    $RemoveDupletsAlertRuleArray += $Entries[$EntriesCount-1]
                }
        }

    If ($global:Sentinel_DeleteDupletAlertsRulesIfFound)
        {
             ForEach ($AlertRule in $RemoveDupletsAlertRuleArray)
                {
                    Write-Output ""
                    Write-Output "Deleting duplet Analytics rule ($($AlertRule.kind)): $($AlertRule.properties.displayName)"
                    # Use existing rule name
                    $uri = "https://management.azure.com$baseUri/providers/Microsoft.SecurityInsights/alertRules/$($AlertRule.name)?api-version=2022-12-01-preview"
                
                    Try
                        {
                            $RuleDelete = Invoke-RestMethod $uri -Method DELETE -Headers $Header -ContentType "application/json"
                        }
                    Catch
                        {
                            Write-Error $_ -ErrorAction Continue
                        }
                }
        }
    Else
        {
            Write-Output "The following duplet rules were found - consider to manually delete these:"
            $RemoveDupletsAlertRuleArray.properties.displayName
        }


#################################################################################
# ACTION - Set action on NEW and UPDATED alert rules (if defined in parameter)
#################################################################################

    If ( ($global:SentinelAlertingForceSetExistingRules) -and ($global:SentinelAlertingEnableLogicAppAction) -and ($global:SentinelAlertingLogicAppActionName) -and ($global:SentinelAlertingLogicAppActionRG) )
        {
            # Get logic app info
            $LogicAppResourceId = Get-AzLogicApp -ResourceGroupName $global:SentinelAlertingLogicAppActionRG  -Name $global:SentinelAlertingLogicAppActionName
            $LogicAppTriggerUri = Get-AzLogicAppTriggerCallbackUrl -ResourceGroupName $global:SentinelAlertingLogicAppActionRG  -Name $global:SentinelAlertingLogicAppActionName -TriggerName $global:SentinelAlertingLogicAppActionTriggerName

            # Get all existing Alert Rules
            $baseUri = "/subscriptions/$($global:MainLogAnalyticsWorkspaceSubId)/resourceGroups/$($global:MainLogAnalyticsWorkspaceResourceGroup)/providers/Microsoft.OperationalInsights/workspaces/$($global:MainLogAnalyticsWorkspaceName)"
            $connectedDataConnectorsUri = "$baseUri/providers/Microsoft.SecurityInsights/alertRules/?api-version=2022-12-01-preview"

            $CurrentAlertRulesApi = (Invoke-AzRestMethod -Path $connectedDataConnectorsUri -Method GET).Content | ConvertFrom-Json			
            $CurrentAlertRules = $CurrentAlertRulesApi.value

            # Get all Active Alert Rules
            $AlertRules_Active = $CurrentAlertRules | Where-Object {$_.properties.Enabled -eq $true}

            ForEach ($RuleInfo in $AlertRules_Active)
                {
                    $AlertRuleActions = Get-AzSentinelAlertRuleAction -ResourceGroupName $global:MainLogAnalyticsWorkspaceResourceGroup -WorkspaceName $global:MainLogAnalyticsWorkspaceName -RuleId $RuleInfo.name
                    If ($AlertRuleActions)
                        {
                            If ($LogicAppResourceId.Id -in $AlertRuleActions.LogicAppResourceId)
                                {
                                    Write-Output ""
                                    Write-Output "OK - Action on alert rule already set ... Skipping !"
                                    Write-Output "$($RuleInfo.properties.DisplayName)"
                                }
                            Else
                                {
                                    Write-Output ""
                                    Write-Output "Setting alert rule action on alert rule"
                                    Write-Output "$($RuleInfo.properties.DisplayName)"
                                    $AlertRuleAction = New-AzSentinelAlertRuleAction -ResourceGroupName $global:MainLogAnalyticsWorkspaceResourceGroup -WorkspaceName $global:MainLogAnalyticsWorkspaceName -RuleId $RuleInfo.Name -LogicAppResourceId ($LogicAppResourceId.Id) -TriggerUri ($LogicAppTriggerUri.Value)
                                }
                        }
                    Else
                        {
                            Write-Output ""
                            Write-Output "Setting alert rule action on alert rule"
                            Write-Output "$($RuleInfo.properties.DisplayName)"
                            $AlertRuleAction = New-AzSentinelAlertRuleAction -ResourceGroupName $global:MainLogAnalyticsWorkspaceResourceGroup -WorkspaceName $global:MainLogAnalyticsWorkspaceName -RuleId $RuleInfo.Name -LogicAppResourceId ($LogicAppResourceId.Id) -TriggerUri ($LogicAppTriggerUri.Value)
                        }
                }
        }


#################################################################################
# ACTION - Set action on NEW and UPDATED alert rules (if defined in parameter)
#################################################################################

    If ($AlertsRulesCreatedUpdated)
        {
            If ( ($global:SentinelAlertingEnableLogicAppAction) -and ($global:SentinelAlertingLogicAppActionName) -and ($global:SentinelAlertingLogicAppActionRG) )
                {
                    ForEach ($RuleInfo in $AlertsRulesCreatedUpdated)
                        {
                            $AlertRuleActions = Get-AzSentinelAlertRuleAction -ResourceGroupName $global:MainLogAnalyticsWorkspaceResourceGroup -WorkspaceName $global:MainLogAnalyticsWorkspaceName -RuleId $RuleInfo.Name
                            If ($AlertRuleActions)
                                {
                                    If ($LogicAppResourceId.Id -in $AlertRuleActions.LogicAppResourceId)
                                        {
                                            Write-Output ""
                                            Write-Output "OK - Action on alert rule already set ... Skipping !"
                                            Write-Output "$($RuleInfo.properties.DisplayName)"
                                        }
                                    Else
                                        {
                                            Write-Output ""
                                            Write-Output "Setting alert rule action on alert rule"
                                            Write-Output "$($RuleInfo.properties.DisplayName)"
                                            $AlertRuleAction = New-AzSentinelAlertRuleAction -ResourceGroupName $global:MainLogAnalyticsWorkspaceResourceGroup -WorkspaceName $global:MainLogAnalyticsWorkspaceName -RuleId $RuleInfo.Name -LogicAppResourceId ($LogicAppResourceId.Id) -TriggerUri ($LogicAppTriggerUri.Value)
                                        }
                                }
                            Else
                                {
                                    Write-Output ""
                                    Write-Output "Setting alert rule action on alert rule"
                                    Write-Output "$($RuleInfo.properties.DisplayName)"
                                    $AlertRuleAction = New-AzSentinelAlertRuleAction -ResourceGroupName $global:MainLogAnalyticsWorkspaceResourceGroup -WorkspaceName $global:MainLogAnalyticsWorkspaceName -RuleId $RuleInfo.Name -LogicAppResourceId ($LogicAppResourceId.Id) -TriggerUri ($LogicAppTriggerUri.Value)
                                }
                        }
                }
        }