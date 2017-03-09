$apiTree = New-Object psobject
Add-Member -InputObject $apiTree -MemberType NoteProperty -Name Process -Value "/api/v1/process?q="
Add-Member -InputObject $apiTree -MemberType NoteProperty -Name Binary -Value "/api/v1/binary/$userinput/summary"
Add-Member -InputObject $apiTree -MemberType NoteProperty -Name Sensor -Value "/api/v1/sensor"
Add-Member -InputObject $apiTree -MemberType NoteProperty -Name Blacklist -Value "/api/v1/banning/blacklist"
Add-Member -InputObject $apiTree -MemberType NoteProperty -Name Watchlist -Value "/api/v1/watchlist"
Add-Member -InputObject $apiTree -MemberType NoteProperty -Name Feed -Value "/api/v1/feed"
Add-Member -InputObject $apiTree -MemberType NoteProperty -Name HostInfo -Value "/api/v1/sensor?hostname=$userinput"
Add-Member -InputObject $apiTree -MemberType NoteProperty -Name Alert -Value "/api/v1/alert"
Add-Member -InputObject $apiTree -MemberType NoteProperty -Name License -Value "/api/v1/license"

function Get-QueryType {
  param(
    $userinput
  )
  $apiTree.psobject.Members |
  Where-Object {$_.Name -eq $userinput } |
  ? {$_.Membertype -eq "noteproperty"} | 
  %{ $_.Value }
}