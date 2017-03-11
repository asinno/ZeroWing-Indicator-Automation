$uname= [Environment]::UserName

function Connect-ToCAJ {
$SessionStatus = Get-SessionStatus
    if ($SessionStatus.Length -eq 0)
    {
      Write-Warning -Message 'Establishing SSH Connection...'
      $creds = Get-Credential -Credential $uname
      New-SSHSession -ComputerName atl1isensorcaj01.srv.secureworks.net -Credential $creds | Format-List
    }
  }
function Get-SessionStatus
{
  Get-SSHSession |
  Where-Object {$_.Host -eq 'atl1isensorcaj01.srv.secureworks.net'} | 
  Select-Object -Property Connected | 
  %{ $_.Connected }
  }
function Connect-ToEndPoint {
  param(
    [Parameter(Mandatory=$true,HelpMessage='Please enter the IP for the Carbon Black Appliance')][string]$EndPoint,
    [Parameter(Mandatory=$true,HelpMessage='Please select a non-conflicting port above 1025')][string]$LocalPort,
    [string]$RemotePort,
    [string]$Index
  )
  $SessionStatus = Get-SessionStatus
  if ($SessionStatus.Length -eq 0)
  {
    Connect-ToCAJ
  }
  if($Index -eq $null)
  {
    $Index = '0'
  }
  Write-Verbose -Message 'Forwarding Port from CAJ Tunnel to Carbon Black Appliance'
  if($RemotePort.Length -eq 0)
  {
    Write-Warning -Message 'Appliance port not specified, setting to 8443 by default'
    $RemotePort = 8443
  }
  New-SSHLocalPortForward -Index $Index -BoundHost 127.0.0.1 -BoundPort $LocalPort -RemoteAddress $EndPoint -RemotePort $RemotePort
}
function Get-ListOfConnections {
  Write-Host
  Write-Host 'List of Open Connections:' -ForegroundColor Green
  Write-Host '=========================' -ForegroundColor Green
  $lport = Get-CurrentHostPort
  Foreach($p in $lport)
  {
    Write-Host "https://localhost:$p"
  }
  Write-Host
}
function Get-CurrentHostPort {
  param(
    [string]$Index
  )
  if ($Index -eq $null)
  {
    $Index = '0'
  }
  Get-SSHPortForward -Index $Index | 
  Where-Object {$_.IsStarted -eq 'True'} | 
  Select-Object -Property BoundPort | 
  %{ $_.BoundPort }
  }
function Stop-PortFowardConnections {
  $bPort = Get-SSHPortForward -Index 0 | 
  Where-Object {$_.IsStarted -eq 'True'} | 
  Select-Object -Property BoundPort | 
  %{ $_.BoundPort }
 foreach($p in $bPort)
 {Stop-SSHPortForward -Index 0 -BoundPort $p -BoundHost '127.0.0.1'}
}
function Start-MultipleConnections {
  Connect-ToCAJ $ErrorActionPreference = 'Stop'
  # DELL CSO1
  Write-Warning -Message 'Connecting to Dell CSO 1'
  Connect-ToEndPoint -EndPoint 10.188.31.73  -LocalPort 8081
  # DELL CSO2
  Write-Warning -Message 'Connecting to Dell CSO 2'
  Connect-ToEndPoint -EndPoint 10.188.31.74  -LocalPort 8082
  # DELL CSO3
  Write-Warning -Message 'Connecting to Dell CSO 3'
  Connect-ToEndPoint -EndPoint 10.188.32.111 -LocalPort 8083
  # KELLOGG
  Write-Warning -Message 'Connecting to Kellogg'
  Connect-ToEndPoint -EndPoint 10.188.25.231 -LocalPort 8084
  # BAIN
  Write-Warning -Message 'Connecting to Bain'
  Connect-ToEndPoint -EndPoint 10.188.28.1 -LocalPort 8085
  # ARAMCO
  Write-Warning -Message 'Connecting to Aramco'
  Connect-ToEndPoint -EndPoint 10.188.36.31 -LocalPort 8086
  # ALLEN & OVERY 1
  Write-Warning -Message 'Connecting to Allen and Overy 1'
  Connect-ToEndPoint -EndPoint 10.188.26.87 -LocalPort 8087
  # Union Bank
  Write-Warning -Message 'Connecting to Union Bank'
  Connect-ToEndPoint -EndPoint 10.188.28.75 -LocalPort 8088
  # New York Jets
  Connect-ToEndPoint -EndPoint 10.188.31.226 -LocalPort 8089
  Write-Warning -Message 'Connecting to the New York Jets'
  # University of Alabama
  Connect-ToEndPoint -EndPoint 10.188.19.173 -LocalPort 8090
  Write-Warning -Message 'Connecting to University of Alabama'
  Write-Warning -Message 'Connections Established'
  Get-ListOfConnections
}