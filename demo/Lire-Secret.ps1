# Tout ce qu'une intégration demande. Le reste du fichier est du commentaire.
Clear-Host

$Nom = "router_admin"

$serveur = "https://synsec.synacksys.fr"
$jeton   = (Get-Content "jeton.txt" -Raw).Trim()

# PowerShell 5.1 négocie encore du TLS 1.0, que le serveur refuse.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

try
{
    $s = Invoke-RestMethod "$serveur/api/v1/secrets/value?name=$Nom" -Headers @{ Authorization = "Bearer $jeton" }
    Write-Host ""
    Write-Host "  $($s.name) = $($s.value)" -ForegroundColor Green
    Write-Host ""
} catch {
    Write-Host ""
    Write-Host "  $Nom : refuse (HTTP $([int] $_.Exception.Response.StatusCode))" -ForegroundColor Red
    Write-Host ""
}
