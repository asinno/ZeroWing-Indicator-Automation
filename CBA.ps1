$TlsAccept = @(
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
  [System.Net.ServicePointManager]::CertificatePolicy = New-Object -TypeName TrustAllCertsPolicy
  )
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
  $Lport = Get-CurrentHostAddress
  if($URL -eq $null)
  {
    $URL ="https://localhost:$LPort"
  }
  if ($Process -eq $true)
  {
      $queryType = Get-QueryType -userinput Process
      Invoke-RestMethod -uri $url$queryType$Search -Headers @{'X-Auth-Token' = $Key}
  }
  if ($Binary -eq $true)
  {
      $queryType = Get-QueryType -userinput Binary
      Invoke-RestMethod -uri $url$queryType$Search -Headers @{'X-Auth-Token' = $Key}
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
  Write-Warning -Message 'Connecting to remote Carbon Black Servers'
  Start-MultipleConnections
  Search-CarbonBlackAppliance -Process -Search $QueryToTest -URL https://localhost:8081 -Key
  Search-CarbonBlackAppliance -Process -Search $QueryToTest -URL https://localhost:8082 -Key
  Search-CarbonBlackAppliance -Process -Search $QueryToTest -URL https://localhost:8083 -Key
  Search-CarbonBlackAppliance -Process -Search $QueryToTest -URL https://localhost:8084 -Key
  Search-CarbonBlackAppliance -Process -Search $QueryToTest -URL https://localhost:8085 -Key
  Search-CarbonBlackAppliance -Process -Search $QueryToTest -URL https://localhost:8086 -Key
  Search-CarbonBlackAppliance -Process -Search $QueryToTest -URL https://localhost:8087 -Key
  Search-CarbonBlackAppliance -Process -Search $QueryToTest -URL https://localhost:8088 -Key
  Search-CarbonBlackAppliance -Process -Search $QueryToTest -URL https://localhost:8089 -Key
  Search-CarbonBlackAppliance -Process -Search $QueryToTest -URL https://localhost:8090 -Key
}