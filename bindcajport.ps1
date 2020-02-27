$uname= [Environment]::UserName

function Connect-ToCAJ {
$SessionStatus = Get-SessionStatus
    if ($SessionStatus.Length -eq 0)
    {
      Write-Warning -Message 'Establishing SSH Connection...'
      $creds = Get-Credential -Credential $uname
      New-SSHSession -ComputerName #(SETJUMPSEVERHERE) -Credential $creds | Format-List
    }
  }
function Get-SessionStatus
{
  Get-SSHSession |
  Where-Object {$_.Host -eq #(SETJUMPSEVERHERE)} | 
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
