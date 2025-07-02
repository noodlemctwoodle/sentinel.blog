#Requires -Version 3
#Requires -Modules Az.Resources
#Requires -Modules Az.ManagementPartner

<#
.SYNOPSIS
Create service principal with self-signed certificate to be used to link with Microsoft Sentinel Deployments and CI/CD

.DESCRIPTION
It uses New-AzADServicePrincipal to create a service principal with a self-signed certificate, and uses New-AzRoleAssignment 
    to assign the Contributor role to the service principal. The role assignment is scoped to your currently selected Azure subscription.

.EXAMPLE
Connect-AzureAd
.\Create-SericePrincipal.ps1 -ServicePrincipalName "DevOpsPipeline" -ServicePrincipalRole "Contributor"
.OUTPUTS
Creates a Service Principal named "ThirdSpaceSOC-PAL"

.NOTES
  Version:          0.1
  Author:           noodlemctwoodle
  Creation Date:    09/11/2021

#>
param (
    [Parameter(Position=0,mandatory=$true)]
    [string]$ServicePrincipalName,
    [Parameter(Position=1,mandatory=$true)]
    [string]$ServicePrincipalRole
  )

$Subject ='CN=$ServicePrincipalName'

$cert = New-SelfSignedCertificate -CertStoreLocation "cert:\CurrentUser\My" `
  -Subject $Subject `
  -KeySpec KeyExchange
$keyValue = [System.Convert]::ToBase64String($cert.GetRawCertData())

$sp = New-AzADServicePrincipal -DisplayName $ServicePrincipalName `
  -CertValue $keyValue `
  -EndDate $cert.NotAfter `
  -StartDate $cert.NotBefore
Start-Sleep 20
New-AzRoleAssignment -RoleDefinitionName $ServicePrincipalRole -ServicePrincipalName $sp.ApplicationId
