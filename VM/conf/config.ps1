<#
.SYNOPSIS
    Génére automatiquement un fichier `config.json` complet à partir d’un `config.partial.json`
    en interrogeant l’API Omada pour récupérer les VPN et WAN actifs.

.DESCRIPTION
    Utilise les credentials et métadonnées contenus dans `config.partial.json` pour :
      - Authentifier via client_credentials
      - Obtenir le siteId et la liste des VPNs
      - Récupérer les WANs actifs et leur configuration
      - Associer les VPNs à leurs WANs disponibles avec priorité
      - Exporter la configuration enrichie dans `config.json`

.INPUTS
    - config.partial.json

.OUTPUTS
    - config.json

.AUTEUR
    Baptiste COCHET
#>


if ($PSVersionTable.PSVersion.Major -lt 7) {
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    add-type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) {
                return true;
            }
        }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
} else {
    # PowerShell 7+
    $PSDefaultParameterValues['Invoke-RestMethod:SkipCertificateCheck'] = $true
}

# Désactivation des vérifications SSL
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

function Load-Config($path) {
    Write-Host "[INFO] Loaded : $path"
    return Get-Content -Path $path -Raw | ConvertFrom-Json
}

function Save-Config($path, $data) {
    $data | ConvertTo-Json -Depth 10 | Set-Content -Path $path -Encoding UTF8
    Write-Host "[INFO] Saved : $path"
}

function Get-AccessToken($cfg) {
    Write-Host "[INFO] Authentification..."
    $url = "$($cfg.omada.base_url)/openapi/authorize/token?grant_type=client_credentials"
    $payload = @{
        omadacId      = $cfg.omada.omadac_id
        client_id     = $cfg.omada.client_id
        client_secret = $cfg.omada.client_secret
    } | ConvertTo-Json

    $response = Invoke-RestMethod -Uri $url -Method Post -Body $payload -ContentType 'application/json'
    return $response.result.accessToken
}

function Get-WanBasicInfo($cfg, $siteId, $headers) {
    $url = "$($cfg.omada.base_url)/openapi/v1/$($cfg.omada.omadac_id)/sites/$siteId/internet/basic-info"
    $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers
    Write-Host "[INFO] WAN basic-info result: $(ConvertTo-Json $response -Depth 10)"
    return $response.result.portList
}

function Get-SiteId($cfg, $headers) {
    $url = "$($cfg.omada.base_url)/openapi/v1/$($cfg.omada.omadac_id)/sites?pageSize=100&page=1"
    $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers
    Write-Host "[INFO] Result Site : $(ConvertTo-Json $response -Depth 10)"
    return $response.result.data[0].siteId
}

function Get-VpnServers($cfg, $siteId, $headers) {
    Write-Host "[INFO] Collecting VPN policies..."
    $url = "$($cfg.omada.base_url)/openapi/v1/$($cfg.omada.omadac_id)/sites/$siteId/vpn/client-to-site-vpn-servers"
    $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers
    Write-Host "[INFO] Result API : $(ConvertTo-Json $response -Depth 10)"
    return $response.result
}

function Get-VpnDetails($cfg, $siteId, $vpnId, $headers) {
    $url = "$($cfg.omada.base_url)/openapi/v1/$($cfg.omada.omadac_id)/sites/$siteId/vpn/client-to-site-vpn-servers/$vpnId"
    $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers
    return $response.result
}

function Get-WanStatus($cfg, $siteId, $headers) {
    Write-Host "[INFO] Collecting WAN status..."
    $url = "$($cfg.omada.base_url)/openapi/v1/$($cfg.omada.omadac_id)/sites/$siteId/gateways/$($cfg.omada.gateway_mac)/wan-status"
    $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers
    Write-Host "[INFO] WAN Result : $(ConvertTo-Json $response -Depth 10)"

    $wanInfos = @{}
    foreach ($wan in $response.result) {
        $port = $wan.port
        $name = if ($wan.name) { $wan.name } else { "WAN$port" }
        $ip = if ($wan.wanPortIpv4Config.ip) { $wan.wanPortIpv4Config.ip } else { "0.0.0.0" }

        $fakeId = "port$port"

        $wanInfos[$port] = @{
            port = $port
            name = $name
            ip   = $ip
            id   = $fakeId
        }
    }
    return $wanInfos
}

function Build-CompleteConfig($partialCfg) {
    $accessToken = Get-AccessToken $partialCfg
    $headers = @{
        "Authorization" = "AccessToken=$accessToken"
        "Content-Type"  = "application/json"
    }

    $siteId = Get-SiteId $partialCfg $headers
    $vpnServersData = Get-VpnServers $partialCfg $siteId $headers
    $vpnServers = $vpnServersData.data
    $wanInfos = Get-WanStatus $partialCfg $siteId $headers
    $wanBasicInfo = Get-WanBasicInfo $partialCfg $siteId $headers

    $validWans = @{}
    foreach ($wan in $wanBasicInfo) {
        try {
            $portId = $wan.portId
            $port = [int]($portId -split "_")[0]
            if ($wan.portMode -eq 0) {
                $validWans[$port] = @{
                    id   = $portId
                    name = $wan.portName
                }
            }
        } catch {
            Write-Warning "[WARN] Failed to parse WAN from basic-info: $_"
        }
    }

    $completeCfg = @{
        omada = $partialCfg.omada
        vpn   = @{ definitions = @() }
    }

    foreach ($defn in $partialCfg.vpn.definitions) {
        $domain = $defn.domaine
        $vpnName = $defn.vpn_name

        $matching = $vpnServers | Where-Object { $_.name -eq $vpnName } | Select-Object -First 1
        if (-not $matching) {
            Write-Warning "[ERROR] Policy VPN '$vpnName' introuvable."
            continue
        }

        try {
            $resolvedIp = [System.Net.Dns]::GetHostAddresses($domain)[0].IPAddressToString
            Write-Host "[INFO] Domain $domain resolved $resolvedIp"
        } catch {
            Write-Warning "[ERROR] Can't resolve $domain : $_"
            $resolvedIp = $null
        }

        $vpnDetails = Get-VpnDetails $partialCfg $siteId $matching.id $headers
        $ipPool = $vpnDetails.ipPool
        $ipPoolIp = if ($ipPool.ip) { $ipPool.ip } else { "192.168.100.0" }
        $ipPoolMask = if ($ipPool.mask) { $ipPool.mask } else { 24 }

        $wansFormatted = @()

        # Ajoute explicitement TOUS les WAN avec portMode = 0 pour CHAQUE policy VPN
        foreach ($port in $validWans.Keys) {
            $wanId = $validWans[$port].id
            $wanName = $validWans[$port].name
            $wanIp = if ($wanInfos.ContainsKey($port)) { $wanInfos[$port].ip } else { "0.0.0.0" }

            $entry = @{
                name = $wanName
                ip   = $wanIp
                id   = $wanId
            }

            $wansFormatted += $entry
        }

	# Ajoute la priorité explicitement selon l'ordre (1 = le plus prioritaire)
	$priority = 1
	foreach ($wan in $wansFormatted) {
    		$wan.priority = $priority
    		$priority++
	}

        $completeCfg.vpn.definitions += @{
            domaine  = $domain
            vpn_name = $vpnName
            vpn_id   = $matching.id
            port     = $matching.servicePort
            ip_pool  = @{
                ip   = $ipPoolIp
                mask = $ipPoolMask
            }
            wans     = $wansFormatted
        }
    }
    # Ajoute explicitement TOUS les WAN avec portMode = 0 dans la configuration finale
    $completeCfg.wans_valides = @()

    foreach ($wan in $wanBasicInfo) {
        if ($wan.portMode -eq 0) {
            $entry = @{
                id   = $wan.portId
                name = $wan.portName
                port = [int]($wan.portId -split "_")[0]
            }
            $completeCfg.wans_valides += $entry
        }
    }

    return $completeCfg
}

# MAIN
$partialConfigPath = "config.partial.json"
$completeConfigPath = "config.json"

$partialCfg = Load-Config $partialConfigPath
$completeCfg = Build-CompleteConfig $partialCfg
Write-Host "[INFO] Creating / Loading : $completeConfigPath"
Save-Config $completeConfigPath $completeCfg
$completeCfg
