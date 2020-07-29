<#
    .DESCRIPTION
        Obtains a certificate from Let's Encrypt and stores it in an Azure KeyVault

    .PARAMETER KeyvaultName
        The name of the Azure Keyvault that you want the certificate to be stored in
    
    .PARAMETER Rootdomain
        The domain (DNS Zone) that you own 
        Eg. azdemo.co.uk 
    
    .PARAMETER Alias
        The subdomain that you're wanting to obtain a certificate for.
        Eg. mywebapp or *

    .PARAMETER RegistrationEmail
        Used by Let's Encrypt for ownership.  
        Must resolve to a valid address with a valid MX domain.

    .NOTES
        AUTHOR: Gordon Byers
        LASTEDIT: July 9, 2018
        DEPENDENCIES: Dependant on v2.5 of module Posh-ACME. https://github.com/rmbolger/Posh-ACME
#>

param (
    [parameter(Mandatory=$true)]
	[String] $KeyvaultName = "BicLookup",
    [parameter(Mandatory=$true)]
	[String] $Rootdomain = "biclookup.com",
    [parameter(Mandatory=$true)]
	[String] $Alias = "*",
    [parameter(Mandatory=$true)]
	[String] $RegistrationEmail
)

$connectionName = "AzureRunAsConnection"
try
{
    # Get the connection "AzureRunAsConnection "
    $servicePrincipalConnection=Get-AutomationConnection -Name $connectionName         

    "Logging in to Azure..."
    Add-AzureRmAccount `
        -ServicePrincipal `
        -TenantId $servicePrincipalConnection.TenantId `
        -ApplicationId $servicePrincipalConnection.ApplicationId `
        -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint 
}
catch {
    if (!$servicePrincipalConnection)
    {
        $ErrorMessage = "Connection $connectionName not found."
        throw $ErrorMessage
    } else{
        Write-Error -Message $_.Exception
        throw $_.Exception
    }
}
#Connect-AzureRmAccount

function CreateRandomPassword() {
    Write-Host "Creating random password"
    $bytes = New-Object Byte[] 32
    $rand = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rand.GetBytes($bytes)
    $rand.Dispose()
    $password = [System.Convert]::ToBase64String($bytes)
    return $password
}

Function Get-SPAccessToken() {
    param(
        [parameter(Mandatory=$true)][string]$spApplicationId
    )

    $cache = (Get-AzureRmContext).tokencache
    $cacheItem = $cache.ReadItems() | Where-Object { $_.ClientId -eq $spApplicationId } | Select-Object -First 1

    return $cacheItem.AccessToken
}

Function Get-AccessToken() {
    $tenantId = (Get-AzureRmContext).Tenant.Id

    $cache = (Get-AzureRmContext).tokencache
    $cacheItem = $cache.ReadItems() | Where-Object { $_.TenantId -eq $tenantId } | Select-Object -First 1

    return $cacheItem.AccessToken
}

#Setting varaibles up with better naming conventions
$vaultcertificateName=$alias.Replace("*", "star")  + $Rootdomain.replace(".","")
$pfxFile = Join-Path $pwd "tempcert.pfx"

#Getting an alternative alias ready, for use with Azure Web Apps
if ($alias -ne "*") {
    $aliases = @("$alias.$rootdomain", "$alias-az.$rootdomain")
}
else {
    $aliases = @("$rootdomain", "*.$rootdomain", "*.scm.$rootdomain")
}

#Making sure that Azure is managing your DNS
$dnsZone = Get-AzureRmDnsZone | ? {$_.Name -eq $rootdomain}
if($dnsZone -eq $null) {
    Write-Error "Dns Zone $rootdomain not found in Azure.  Is Azure managing your DNS Name Server (managing your DNS)?"
    break;
}

#Lets Encrypt uses the ACME protocol for verification. 
Set-PAServer LE_PROD #LE_STAGE

#Set up parameters we need to use the Posh-ACME DnsPlugin for Azure
$subId = (Get-AzureRmContext).Subscription.Id
$token = if($servicePrincipalConnection -eq $null) {Get-AccessToken} else {Get-SPAccessToken -spApplicationId $servicePrincipalConnection.ApplicationId} 
$azureParams = @{AZSubscriptionId=$subId;AZAccessToken=$token;}

if($token -eq $null) {
    Write-Error "Authentication token not populated.  Check how you are authenticating."
    break;
}

#Create a random password for the PFX file
$randomPw = CreateRandomPassword
$securepfxpwd = ConvertTo-SecureString –String $randomPw –AsPlainText –Force

#Request a certificate
$cert = New-PACertificate -Domain $aliases -Contact $RegistrationEmail -AcceptTOS -DnsPlugin Azure -PluginArgs $azureParams -DNSSleep 5 -PfxPass $randomPw -Verbose -force
Copy-Item $cert.PfxFile $pfxFile

#Checking file exists
$pfxFileExists = test-path($pfxFile)

if(!$pfxFileExists) {
    Write-Error "PFX $pfxFile does not exist [$pfxFileExists]"
    break;
}
else  {
    Write-Output "PFX saved to $pfxFile.  File Exists [$pfxFileExists]"

    #Update certificate in key-vault
    $existingCert=Get-AzureKeyVaultSecret -VaultName $keyvaultName -Name $vaultcertificateName -ErrorAction SilentlyContinue
    if(!$existingCert -eq $null) {
        Write-Host "Certificate last updated : $($existingCert.Updated)"
    }

    Write-Output "Importing Certificate from ($pfxFile)"
    $cert = Import-AzureKeyVaultCertificate -VaultName $keyvaultName -Name $vaultcertificateName -FilePath $pfxFile -Password $securepfxpwd

    Write-Output "Storing password for cert in Keyvault as secret"
    Set-AzureKeyVaultSecret -VaultName $KeyvaultName -Name "$vaultcertificateName-pw" -SecretValue $securepfxpwd

    $newCert=Get-AzureKeyVaultSecret -VaultName $keyvaultName -Name $vaultcertificateName 
    Write-Output "$vaultcertificateName Certificate imported.  Last Updated : $($newCert.Updated)"
}

#Cleanup
Remove-Item $pfxFile


