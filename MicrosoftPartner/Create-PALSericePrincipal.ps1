#Requires -Version 3
#Requires -Modules Az.Resources
#Requires -Modules Az.ManagementPartner

<#
.SYNOPSIS
Create service principal with self-signed certificate to be used to link with Azure Lighthouse ARM Template
.DESCRIPTION
It uses New-AzADServicePrincipal to create a service principal with a self-signed certificate, and uses New-AzRoleAssignment 
    to assign the Reader role to the service principal. The role assignment is scoped to your currently selected Azure subscription.

Once the Service Principal has been created associate with the ThirdSpace PAL:
    Connect-AzAccount -ServicePrincipal -ApplicationId $servicePrincipalId -Tenant $tenantId -CertificateThumbprint <thumbprint>
    New-AzManagementPartner -PartnerId 576272 
.EXAMPLE
Connect-AzAccount
.\aadServicePrincipal.ps1
.OUTPUTS
Creates a Service Principal named "ThirdSpaceSOC-PAL"
.NOTES
  Version:          0.1
  Author:           noodlemctwoodle
  Creation Date:    01/07/2021
.LINK
https://docs.microsoft.com/en-us/azure/lighthouse/how-to/partner-earned-credit
https://docs.microsoft.com/en-us/azure/cost-management-billing/manage/link-partner-id#link-to-a-partner-id
https://portal.azure.com/#create/Microsoft.Template
#>

$cert = New-SelfSignedCertificate -CertStoreLocation "cert:\CurrentUser\My" `
  -Subject "CN=Microsoft-PAL" `
  -KeySpec KeyExchange
$keyValue = [System.Convert]::ToBase64String($cert.GetRawCertData())

$sp = New-AzADServicePrincipal -DisplayName "Microsoft-PAL" `
  -CertValue $keyValue `
  -EndDate $cert.NotAfter `
  -StartDate $cert.NotBefore
Start-Sleep 20
New-AzRoleAssignment -RoleDefinitionName Reader -ServicePrincipalName $sp.ApplicationId
