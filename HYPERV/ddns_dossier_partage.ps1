<#
.SYNOPSIS
    Met à jour automatiquement la configuration VPN client-to-site Omada en fonction des IP DNS et des WAN actifs. Le tout grâce à l'OpenAPI d'Omada.

.DESCRIPTION
    - Récupère les IP des domaines VPN
    - Compare les IP avec un état précédent
    - Met à jour la configuration VPN si nécessaire
    - Se connecte via un partage réseau et l’API Omada

.AUTEUR
    Baptiste COCHET
#>

if ($PSVersionTable.PSVersion.Major -lt 7) {
    try {
        Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        Write-Host "[INFO] SSL verification bypassed (PowerShell < 7)"
    } catch {
        Write-Warning "Could not override SSL verification: $_"
    }
}

$ipStateOldFile = "ip_state_old.json"
# Informations pour accès réseau sécurisé
$ipStateDir = "\\IP_SERVER\Shared\VM"
$ipStateFile = Join-Path $ipStateDir "ip_state.json"
$utilisateur = "IP_SERVER\USER_SHARED"
$motDePasse = "PASSWORD_USER_SHARED"


if (-not (Test-Path $ipStateOldFile)) {
    Write-Warning "[WARN] $ipStateOldFile introuvable, initialisation à partir de $ipStateFile..."
    try {
        Copy-Item -Path $ipStateFile -Destination $ipStateOldFile -Force
        Write-Host "[INFO] Copie de $ipStateFile vers $ipStateOldFile réussie."
    } catch {
        Write-Error "[ERROR] Impossible de copier $ipStateFile vers $ipStateOldFile : $_"
        "{}" | Set-Content $ipStateOldFile  # fallback vide si erreur
    }
}

# Établir connexion réseau (uniquement si non déjà connectée)
try {
    Write-Host "[INFO] Vérification des connexions réseau existantes..."
    net use * /delete /y | Out-Null
    $networkShare = Split-Path $ipStateFile -Parent
    net use $networkShare /user:$utilisateur $motDePasse | Out-Null

    Write-Host "[INFO] Connexion réseau établie vers $ipStateFile"
} catch {
    Write-Error "[ERREUR] Échec de la connexion réseau : $_"
    exit 1
}


function Load-JsonFile {
    param([string]$Path)
    try {
        return Get-Content -Path $Path -Raw | ConvertFrom-Json
    } catch {
        Write-Error "[ERROR] Can't read $Path : $_"
        return @{}
    }
}

function Save-JsonFile {
    param([string]$Path, [object]$Content)
    try {
        $Content | ConvertTo-Json -Depth 10 | Set-Content -Path $Path
        Write-Host "[SAVE] IP state saved in $Path"
    } catch {
        Write-Error "[ERROR] Failed to save in $Path : $_"
    }
}

function Get-AccessToken {
    param($BaseUrl, $ClientId, $OmadacId, $ClientSecret)

    Write-Host "[INFO] Authenticating..."
    $url = "$BaseUrl/openapi/authorize/token?grant_type=client_credentials"
    $body = @{
        omadacId     = $OmadacId
        client_id    = $ClientId
        client_secret = $ClientSecret
    } | ConvertTo-Json -Depth 3

    try {
        $response = Invoke-RestMethod -Uri $url -Method Post -Body $body -Headers @{ "Content-Type" = "application/json" } 
        return @($response.result.accessToken, $response.result.refreshToken)
    } catch {
        Write-Error "[ERROR] Auth failed: $_"
        return @($null, $null)
    }
}

function Get-SiteId {
    param($BaseUrl, $OmadacId, $AccessToken)
    Write-Host "[INFO] Retrieving site ID..."

    $url = "$BaseUrl/openapi/v1/$OmadacId/sites?pageSize=1&page=1"
    $headers = @{
        Authorization = "AccessToken=$AccessToken"
        "Content-Type" = "application/json"
    }

    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers 
        $site = $response.result.data[0]
        Write-Host "[SUCCESS] Site ID retrieved: $($site.siteId)"
        return $site.siteId
    } catch {
        Write-Error "[ERROR] Failed to retrieve site ID: $_"
        return $null
    }
}
function Get-VpnDetails {
    param($BaseUrl, $OmadacId, $SiteId, $VpnId, $AccessToken)

    $url = "$BaseUrl/openapi/v1/$OmadacId/sites/$SiteId/vpn/client-to-site-vpn-servers/$VpnId"
    $headers = @{
        Authorization = "AccessToken=$AccessToken"
        "Content-Type" = "application/json"
    }

    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers
#        Write-Host "[DEBUG] VPN details for $VpnId :"
#        $response | ConvertTo-Json -Depth 10 | Write-Host
        return $response.result
    } catch {
        Write-Error "[ERROR] Failed to get VPN details for $VpnId : $_"
        return $null
    }
}


function Get-ActiveWanIps {
    param($BaseUrl, $OmadacId, $SiteId, $GatewayMac, $AccessToken)
    Write-Host "[CHECK] Checking WAN port status..."
    $url = "$BaseUrl/openapi/v1/$OmadacId/sites/$SiteId/gateways/$GatewayMac/wan-status"
    $headers = @{
        Authorization = "AccessToken=$AccessToken"
        "Content-Type" = "application/json"
    }

    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers 
        $activeWans = @()
        foreach ($wan in $response.result) {
            $ip = $wan.wanPortIpv4Config.ip
            if ($wan.status -eq 1 -and $wan.internetState -eq 1 -and $ip -ne "0.0.0.0") {
                $activeWans += @{
                    name = $wan.name
                    port = $wan.port
                    ip   = $ip
                }
            }
        }
        Write-Host "[SUCCESS] Active WANs: $($activeWans.name -join ', ')"
        return $activeWans
    } catch {
        Write-Error "[ERROR] Failed to collect WAN state: $_"
        return @()
    }
}

  # on prend le premier s'il y en a plusieurs

function Update-VpnWan {
    param(
        $BaseUrl,
        $OmadacId,
        $SiteId,
        $VpnId,
        $AccessToken,
        $NewWanId,
        $VpnName,
        $VpnPort,
        $VpnPool,
        $NetworkListId
    )

    $headers = @{
        Authorization = "AccessToken=$AccessToken"
        "Content-Type" = "application/json"
    }

    $url = "$BaseUrl/openapi/v1/$OmadacId/sites/$SiteId/vpn/client-to-site-vpn-servers/$VpnId"

    try {
        Write-Host "[INFO] Fetching current VPN config for '$VpnName'..."
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get 
        $vpn = $response.result
        $currentWan = $vpn.wan[0]

        if ($currentWan -eq $NewWanId) {
            Write-Host "[INFO] VPN '$VpnName' is already using WAN $NewWanId."
            return $true
        }

        # Reconstruire le body avec les valeurs actuelles
        $vpnBody = @{
            id            = $vpn.id
            name          = $VpnName
            status        = $vpn.status
            tunnelMode    = $vpn.tunnelMode
            openVpnMode   = $vpn.openVpnMode
            networkType   = $vpn.networkType
            networkList   = @($NetworkListId)
            wan           = @($NewWanId)
            clientVpnType = $vpn.clientVpnType
            ipPool        = $VpnPool
            primaryDns    = $vpn.primaryDns
            serviceType   = $vpn.serviceType
            servicePort   = $VpnPort
            authMode      = $vpn.authMode
        }



        $jsonBody = $vpnBody | ConvertTo-Json -Depth 10

        Write-Host "[PATCH] Updating VPN '$VpnName' to new WAN: $NewWanId..."
        $patchResponse = Invoke-RestMethod -Uri $url -Method Patch -Headers $headers -Body $jsonBody

        if ($patchResponse.errorCode -eq 0) {
            Write-Host "[SUCCESS] VPN '$VpnName' updated to WAN $NewWanId."
            return $true
        } else {
            Write-Error "[ERROR] Failed to patch VPN '$VpnName' : $($patchResponse.message)"
            return $false
        }

    } catch {
        Write-Error "[ERROR] Exception in Update-VpnWan: $_"
        return $false
    }
}

function Compare-IpStates {
    param($Now, $Old)
    $changes = @()
    foreach ($domain in $Now.PSObject.Properties.Name) {
        $newIp = $Now.$domain.ip
        $oldIp = $Old.$domain.ip
        if ($newIp -ne $oldIp) {
            Write-Host "[INFO] IP changed for ${domain}: $oldIp → $newIp"
            $changes += $domain
        } else {
            Write-Host "[INFO] IP unchanged for $domain ($newIp)"
        }
    }
    return $changes
}

# ========================== EXECUTION ===========================

$config = Load-JsonFile "conf/config.json"
$baseUrl = $config.omada.base_url
$clientId = $config.omada.client_id
$omadacId = $config.omada.omadac_id
$clientSecret = $config.omada.client_secret
$gatewayMac = $config.omada.gateway_mac
$vpnDefinitions = $config.vpn.definitions
$ipNow = Load-JsonFile $ipStateFile
$ipOld = Load-JsonFile $ipStateOldFile
$domainsChanged = Compare-IpStates -Now $ipNow -Old $ipOld

if (-not $domainsChanged) {
    Write-Host "[INFO] No IP changes detected. Forcing check."
    $domainsChanged = $vpnDefinitions | ForEach-Object { $_.domaine }
}

$tokens = Get-AccessToken -BaseUrl $baseUrl -ClientId $clientId -OmadacId $omadacId -ClientSecret $clientSecret
$accessToken = $tokens[0]
if (-not $accessToken) { exit 1 }

$siteId = Get-SiteId -BaseUrl $baseUrl -OmadacId $omadacId -AccessToken $accessToken
if (-not $siteId) { exit 1 }

# Sélectionne ici le réseau par nom, ou prends le premier si tu veux par défaut :

$activeWans = Get-ActiveWanIps -BaseUrl $baseUrl -OmadacId $omadacId -SiteId $siteId -GatewayMac $gatewayMac -AccessToken $accessToken
$activeWanNames = $activeWans | ForEach-Object { $_.name }

foreach ($vpn in $vpnDefinitions) {
    $domaine = $vpn.domaine
    $vpnName = $vpn.vpn_name
    $vpnId = $vpn.vpn_id
    $wans = $vpn.wans
    $vpnPort = $vpn.port
    $vpnPool = $vpn.ip_pool

    try {
        $resolvedIp = [System.Net.Dns]::GetHostAddresses($domaine)[0].IPAddressToString
        Write-Host "[DNS] Domain $domaine resolved: $resolvedIp"
    } catch {
        Write-Error "[ERROR] DNS resolution failed for $domaine"
        continue
    }

    $matchedWan = $wans | Where-Object { $_.ip -eq $resolvedIp }
    $wanIdResolved = $matchedWan.id

    $getUrl = "$baseUrl/openapi/v1/$omadacId/sites/$siteId/vpn/client-to-site-vpn-servers/$vpnId"
    $headers = @{ Authorization = "AccessToken=$accessToken"; "Content-Type" = "application/json" }
    $vpnDetails = Get-VpnDetails $baseUrl $omadacId $siteId $vpnId $accessToken
    if (-not $vpnDetails) {
        Write-Warning "[WARN] VPN details not retrieved for $vpnName"
        continue
    }

    $networkListId = $vpnDetails.networkList[0]
    $currentWan = $vpnDetails.wan[0]

    if ($matchedWan -and ($activeWanNames -contains $matchedWan.name.Trim())) {
        if ($currentWan -ne $matchedWan.id) {
            Write-Host "[UPDATE] Switching '$vpnName' to matched WAN (via IP DNS): $($matchedWan.name)"
            Update-VpnWan $baseUrl $omadacId $siteId $vpnId $accessToken $matchedWan.id $vpnName $vpnPort $vpnPool $networkListId
        } else {
            Write-Host "[INFO] '$vpnName' already using matched WAN $($matchedWan.name)"
        }
        continue
    }

#    Write-Host "[DEBUG] ip_pool for $vpnName :" ($vpnPool | ConvertTo-Json -Depth 3)

        $activeBackupWan = $wans |
        Where-Object { $activeWanNames -contains $_.name.Trim() } |
        Sort-Object priority |
        Select-Object -First 1

    if (-not $activeBackupWan) {
        Write-Error "[ERROR] No active WAN available for $vpnName"
        continue
    }

    if ($currentWan -ne $activeBackupWan.id) {
        Write-Host "[UPDATE] Switching '$vpnName' to WAN: $($activeBackupWan.name) (priority $($activeBackupWan.priority))"
        Update-VpnWan $baseUrl $omadacId $siteId $vpnId $accessToken $activeBackupWan.id $vpnName $vpnPort $vpnPool $networkListId
    } else {
        Write-Host "[INFO] '$vpnName' already using WAN $($activeBackupWan.name) (priority $($activeBackupWan.priority))"
    }

}

Save-JsonFile -Path $ipStateOldFile -Content $ipNow
