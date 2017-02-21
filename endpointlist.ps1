function Get-EndPointList {
  $TlsAccept
  Invoke-RestMethod https://atl1socsvcs01.srv.secureworks.net/~bschmitt/aetd_jumpzone.html
}