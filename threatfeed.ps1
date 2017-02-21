[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$null = Add-Type -AssemblyName System.Web
$threatTable =
@{e={$_.link}; l = 'Link'},
@{e={$_.timestamp}; l = 'Timestamp'},
@{e={$_.score}; l = 'Score'},
@{e={$_.Description}; l = 'Description'},
@{e={$_.tags}; l = 'Tags'},
@{e={$_.id}; l = 'ID'},
@{e={$_.iocs.query}; l = 'Query'}
function Get-ThreatFeed {
  param(
    [string[]]$Search
  )
  $threatQuery = Invoke-RestMethod -Method Get -Uri https://portal.secureworks.com/cb/v1/alliance-feed.json?name=threatsquery -CertificateThumbprint 2FA110A4FD1E1EE107F59EBFD1E6C05E672170C2
  $threatQuery.Reports | Select-Object -Property $threatTable | Where-Object {$_.ID -match $Search}
}