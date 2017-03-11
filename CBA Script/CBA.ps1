  Add-Type -TypeDefinition @'
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
'@
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  [System.Net.ServicePointManager]::CertificatePolicy = New-Object -TypeName TrustAllCertsPolicy
Set-Alias -Name scb -Value Search-CarbonBlackAppliance -Description 'Queries Carbon Black Appliances'
function Search-CarbonBlackAppliance {
  [CmdletBinding()]
  param(
    [switch]$Process,
    [switch]$Binary,
    [switch]$Sensor,
    [switch]$Blacklist,
    [switch]$Watchlist,
    [switch]$Feed,
    [switch]$HostInfo,
    [switch]$Alert,
    [switch]$License,
    [string]$URL,
    [string]$Key,
    [string]$Search
  )
  if($key -eq $null)
  {
    Write-Warning 'No API Key was specified, please enter an API key'
    Write-Host 'Here is an example:'
    Write-Host 'C:\Users\asinno> $key = "somekey"'
    Write-Host 'This will make the key reusable until you specify another one...' -ForegroundColor Red
  }
  if($URL -eq $null)
  {
    $URL ="https://localhost:$LPort"
  }
  if ($Process)
  {
      $queryType = Get-QueryType -userinput Process
      Invoke-RestMethod -uri $URL$queryType$Search -Headers @{'X-Auth-Token' = $Key}
  }
  if ($Binary -eq $true)
  {
      $queryType = Get-QueryType -userinput Binary
      Invoke-RestMethod -uri $URL$queryType$Search -Headers @{'X-Auth-Token' = $Key}
  }

  if ($Sensor -eq $true)
  {
      $queryType = Get-QueryType -userinput Sensor
      Invoke-RestMethod -uri $url$queryType -Headers @{'X-Auth-Token' = $Key}
  }

  if ($Blacklist -eq $true)
  {
      $queryType = Get-QueryType -userinput Blacklist
      Invoke-RestMethod -uri $url$queryType -Headers @{'X-Auth-Token' = $Key}
  }

  if ($Watchlist -eq $true)
  {
      $queryType = Get-QueryType -userinput Watchlist
      Invoke-RestMethod -uri $url$queryType -Headers @{'X-Auth-Token' = $Key}
  }
  if ($Feed -eq $true)
  {
      $queryType = Get-QueryType -userinput Feed
      Invoke-RestMethod -uri $url$queryType -Headers @{'X-Auth-Token' = $Key}
  }
  if ($HostInfo -eq $true)
  {
      $queryType = Get-QueryType -userinput HostInfo
      Invoke-RestMethod -uri $url$queryType$Search -Headers @{'X-Auth-Token' = $Key} |
      Select-Object -Property $SensorInformation
  }
  if ($Alert -eq $true)
  {
      $queryType = Get-QueryType -userinput Alert
      Invoke-RestMethod -uri $url$queryType -Headers @{'X-Auth-Token' = $Key}
  }
  if ($License -eq $true)
  {
      $queryType = Get-QueryType -userinput License
      Invoke-RestMethod -uri $url$queryType -Headers @{'X-Auth-Token' = $Key}
  }
}
function Test-CBQuery {
  param(
    [string]$QueryToTest
  )
  Start-MultipleConnections
  Write-Host 'Testing Carbon Black Query, please wait...' -ForegroundColor Green
  $dellCso1Query = Search-CarbonBlackAppliance -Process -Search $QueryToTest -URL 'https://localhost:8081' -Key '1c1039fd73fcd6d3f520c2907146046d29be748f'
  $dellCso2Query = Search-CarbonBlackAppliance -Process -Search $QueryToTest -URL 'https://localhost:8082' -Key '28e153cbd4deca38b6c1553a72d10f9568c8593c'
  $dellCso3Query = Search-CarbonBlackAppliance -Process -Search $QueryToTest -URL 'https://localhost:8083' -Key 'd7035103c53f95d89aa78152507e89a68c44abe5'
  $kelloggQuery = Search-CarbonBlackAppliance -Process -Search $QueryToTest -URL 'https://localhost:8084' -Key 'ff95f473ec105b82950a1468bbda74b27a263d95'
  $bainQuery = Search-CarbonBlackAppliance -Process -Search $QueryToTest -URL 'https://localhost:8085' -Key 'd61e2adc8567aa467fad74cb7717fbf20425136d'
  $aramcoQuery = Search-CarbonBlackAppliance -Process -Search $QueryToTest -URL 'https://localhost:8086' -Key '870f89817600b21d736a9354ba892a688f8a6ab0'
  $allenOvery1Query = Search-CarbonBlackAppliance -Process -Search $QueryToTest -URL 'https://localhost:8087' -Key '6655a1bc72c1c1ae709e016a7414f121ade6a040'
  $unionBankQuery = Search-CarbonBlackAppliance -Process -Search $QueryToTest -URL 'https://localhost:8088' -Key 'd289c677aff8869d7dac3763d9004a0a3333cba4'
  $newYorkJetsQuery = Search-CarbonBlackAppliance -Process -Search $QueryToTest -URL 'https://localhost:8089' -Key '8b28fec88d2bd1c6da6ae94855fa6b89bb845378'
  $uOfAQuery = Search-CarbonBlackAppliance -Process -Search $QueryToTest -URL 'https://localhost:8090' -Key '2b8f86fc18f7c138c53a0f5a4c8cc12a36a4ce81'
  # Generate Calculated Properties
  $watchlistResults =
  @{e={$_.start}
  Label='Start'},
  @{e={$_.elapsed}
  l='Elapsed'},
  @{e={$_.terms}
  Label='Terms'},
  @{e={$_.total_results}
  l='Total Results'}
  # Create PSObject
  New-Object -TypeName PSObject -Property @{
    'Dell CSO 1'= $dellCso1Query | Select-Object $watchlistResults
    'Dell CSO 2'= $dellCso2Query | Select-Object $watchlistResults
    'Dell CSO 3'= $dellCso3Query | Select-Object $watchlistResults
    'Kellogg Brown & Root LLC' = $kelloggQuery | Select-Object $watchlistResults
    'Bain Capital, LP, Boston'= $bainQuery | Select-Object $watchlistResults
    'Aramco'= $aramcoQuery | Select-Object $watchlistResults
    'Allen & Overy LLP, London 1'=$allenOvery1Query | Select-Object $watchlistResults
    'Union Bank'= $unionBankQuery | Select-Object $watchlistResults
    'New York Jets'= $newYorkJetsQuery | Select-Object $watchlistResults
    'University of Alabama'=$uOfAQuery | Select-Object $watchlistResults
  } | ForEach-Object { # Enumerate Values
    foreach ($p in $_.PSObject.Properties) {
      $p.Value | Select-Object @{n='Client';e={$p.Name}},*
    }
  }
}