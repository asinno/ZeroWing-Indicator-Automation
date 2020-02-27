function Get-CredVault {
  param(
    [switch]$AddCred,
    [switch]$Getcred,
    [switch]$RemoveCred,
    [switch]$Find
  )
  # Calls .Net Type
  $vaultAssembly = 
  @([void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
  $vault=New-Object Windows.Security.Credentials.PasswordVault)
  if($AddCred -eq $true){
    $vaultAssembly
    # Get Details
    $ClientID = Read-Host 'Enter Client ID'
    $APIKey = Read-Host 'Enter API key'
    $URL = Read-Host 'Enter URL for API Endpoint'
    # Create Vault Object
    $credToAdd = New-Object Windows.Security.Credentials.PasswordCredential($URL, $ClientID, $APIKey)
    # Add creds
    $vault.Add($credToAdd)
  }
    if ($Getcred -eq $true){
    $vaultAssembly
    # Changle Table Formatting
    $format= 
    @{e ={$_.UserName};l = 'ClientID'},
    @{e ={$_.password};l = 'APIKey'},
    @{e ={$_.resource};l = 'APIEndpoint'}
    # Calls Table
    if (!($Find -eq $true))
    {
    (new-object Windows.Security.Credentials.PasswordVault).RetrieveAll() | % { $_.RetrievePassword(); $_ } | Select-Object $format
    }
    if ($Find -eq $true)
    {
    $ClientID = Read-Host 'Please enter an ID'
    # Calls Table
    (new-object Windows.Security.Credentials.PasswordVault).RetrieveAll() | % { $_.RetrievePassword(); $_ } | Where-Object {$_.UserName -eq $ClientID } | Select-Object $format
    }
  }
  if ($RemoveCred -eq $true){
    $vaultAssembly
    $ClientID = Read-Host 'Enter Client ID'
    $credToRemove = (new-object Windows.Security.Credentials.PasswordVault).RetrieveAll() |
    % { $_.RetrievePassword(); $_ } |
    Where-Object {$_.UserName -eq $ClientID }
    $vault.Remove($credToRemove)
  }
}
function Get-APIKey {
  param(
    [string]$ClientID
  )
  $creds = Get-CredVault -Getcred |
  Where-Object {$_.ClientID -eq $ClientID } | 
  Select-Object -Property APIKey
  $creds.psobject.Members | ? {$_.Membertype -eq "noteproperty"} | 
  %{ $_.Value }
}
function Get-ClientEndPoint {
  param(
    [string]$ClientID
  )
  $endPoint = Get-CredVault -Getcred |
  Where-Object {$_.ClientID -eq $ClientID } | 
  Select-Object -Property APIEndpoint
  $endPoint.psobject.Members | ? {$_.Membertype -eq "noteproperty"} | 
  %{ $_.Value }
}
# Still being built
function Add-BulkCreds{
  $vaultAssembly
    Write-Host 'AddCreds)' -ForegroundColor Yellow -NoNewline
    $x = Read-Host
    $first,$second,$third = $x -split '\s',3
    $x -replace ",", "`n"
    $vault = New-Object Windows.Security.Credentials.PasswordVault
    $cred = New-Object Windows.Security.Credentials.PasswordCredential($second, $third, $first)
    $vault.Add($cred)
}
