function Test-Something {
  $Hello = @("One","Two")
  $Hello
}
function Other-Function
{
  $Results = Test-Something
  Foreach($p in $Results)
  {
    Write-Host 'Number' $p
  }
}