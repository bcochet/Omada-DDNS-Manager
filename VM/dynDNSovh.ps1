$WORK_DIR = $PSScriptRoot
$configFile = "$WORK_DIR\conf\ovh_ddns_config.txt"
$ipStateFile = "$WORK_DIR\ip_state.json"
$logFile = "$WORK_DIR\ip_changes.log"  # <--- Nouveau fichier log

Write-Host "[INFO] Script OVH DDNS lancé"

if (-Not (Test-Path $configFile)) {
    Write-Host "[ERROR] Fichier ovh_ddns_config.txt introuvable."
    exit 1
}

# Obtenir l'IP publique
$url = "http://ip.kernel.fr/"
try {
    $webclient = New-Object System.Net.WebClient
    $WANIP = $webclient.DownloadString($url).Trim()
    Write-Host "[INFO] IP publique détectée : $WANIP"
}
catch {
    Write-Host "[ERROR] Impossible de récupérer l'IP publique : $_"
    exit 1
}

# Charger ancienne IP si elle existe
$oldIP = $null
if (Test-Path $ipStateFile) {
    try {
        $json = Get-Content $ipStateFile -Raw | ConvertFrom-Json
        $firstDomain = ($json.PSObject.Properties | Select-Object -First 1).Name
        $oldIP = $json.$firstDomain.ip
        Write-Host "[INFO] Ancienne IP : $oldIP"
    }
    catch {
        Write-Host "[WARN] Fichier d'état invalide, IP précédente ignorée."
    }
}

# Comparer l'IP et écrire le log si elle a changé
if ($oldIP -ne $WANIP -and $oldIP) {
    $timestamp = Get-Date -Format "yyyy-MM-dd-HH-mm-ss"
    $logEntry = "[$timestamp] $oldIP -> $WANIP"
    Add-Content -Path $logFile -Value $logEntry
    Write-Host "[INFO] Changement d'IP détecté. Log : $logEntry"
}
elseif (-not $oldIP) {
    Write-Host "[INFO] Aucune IP précédente trouvée, aucune comparaison faite."
}
else {
    Write-Host "[INFO] IP inchangée, aucun log écrit."
}

# Initialiser le dictionnaire d'état
$state = @{}

# Traitement de chaque domaine
Get-Content $configFile | ForEach-Object {
    $line = $_.Trim()

    if ($line -match "^#|^$") { return }

    $parts = $line.Split(":")
    if ($parts.Length -ne 3) {
        Write-Host "[WARN] Ligne invalide : $line"
        return
    }

    $URL_OVH = $parts[0]
    $LOGIN_OVH = $parts[1]
    $PWD_OVH = $parts[2]

    $majurl = "https://${LOGIN_OVH}:${PWD_OVH}@www.ovh.com/nic/update?myip=${WANIP}&hostname=${URL_OVH}&system=dyndns"
    $wc = New-Object System.Net.WebClient
    $wc.Credentials = New-Object System.Net.NetworkCredential($LOGIN_OVH, $PWD_OVH)

    try {
        $result = $wc.DownloadString($majurl)
        Write-Host "[INFO] OVH response for ${URL_OVH}: $result"
    }
    catch {
        Write-Host "[ERROR] Erreur OVH pour ${URL_OVH}: $_"
    }

    $state[$URL_OVH] = @{ ip = "$WANIP" }
}

# Sauvegarde JSON
$utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $false
try {
    [System.IO.File]::WriteAllText($ipStateFile, ($state | ConvertTo-Json -Depth 2), $utf8NoBomEncoding)
    Write-Host "[INFO] Écrit dans $ipStateFile"
}
catch {
    Write-Host "[ERROR] Impossible d'écrire le fichier $ipStateFile : $_"
    exit 1
}

Write-Host "[INFO] Script terminé."
