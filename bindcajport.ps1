﻿$uname= [Environment]::UserName
$sessionstatus = Get-SSHSession |
Where-Object {$_.Host -eq 'atl1isensorcaj01.srv.secureworks.net'} | 
Select-Object -Property Connected | 
%{ $_.Connected }
function Connect-ToCAJ {
  if($sessionstatus -ne 'True')
  {
    Write-Warning -Message 'Establishing SSH Connection...'
    $creds = Get-Credential -Credential $uname
    New-SSHSession -ComputerName atl1isensorcaj01.srv.secureworks.net -Credential $creds | Format-List
  }
}
function Connect-ToEndPoint {
  param(
    [Parameter(Mandatory=$true,HelpMessage='Please enter the IP for the Carbon Black Appliance')][string]$EndPoint,
    [Parameter(Mandatory=$true,HelpMessage='Please select a non-conflicting port above 1025')][string]$LocalPort
  )
  Connect-ToCAJ
  Write-Verbose -Message 'Forwarding Port from CAJ Tunnel to Carbon Black Appliance'
  New-SSHLocalPortForward -Index 0 -BoundHost 127.0.0.1 -BoundPort $LocalPort -RemoteAddress $EndPoint -RemotePort 8443
  $lport = Get-SSHPortForward -Index 0 |
  Where-Object {$_.IsStarted -eq 'True'} | 
  Select-Object -Property BoundPort | 
  %{ $_.BoundPort }
  Write-Host 'Web interface address:'"https://localhost:$LPort" -ForegroundColor Green
}
function Get-CurrentHostPort {
  Get-SSHPortForward -Index 0 | 
  Where-Object {$_.IsStarted -eq 'True'} | 
  Select-Object -Property BoundPort | 
  %{ $_.BoundPort }
  }
function Stop-PortFowardConnections {
  $bPort = Get-SSHPortForward -Index 0 | 
  Where-Object {$_.IsStarted -eq 'True'} | 
  Select-Object -Property BoundPort | 
  %{ $_.BoundPort }
  $bHost = Get-SSHPortForward -Index 0 | 
  Where-Object {$_.IsStarted -eq 'True'} | 
  Select-Object -Property BoundHost | 
  %{ $_.BoundHost }
  Stop-SSHPortForward -Index 0 -BoundPort $bPort -BoundHost $bHost
}
# SIG # Begin signature block
# MIITxAYJKoZIhvcNAQcCoIITtTCCE7ECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUz/ovZwJY+a/AcWppIzeZLHrn
# qyuggg3JMIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
# AQUFADCBizELMAkGA1UEBhMCWkExFTATBgNVBAgTDFdlc3Rlcm4gQ2FwZTEUMBIG
# A1UEBxMLRHVyYmFudmlsbGUxDzANBgNVBAoTBlRoYXd0ZTEdMBsGA1UECxMUVGhh
# d3RlIENlcnRpZmljYXRpb24xHzAdBgNVBAMTFlRoYXd0ZSBUaW1lc3RhbXBpbmcg
# Q0EwHhcNMTIxMjIxMDAwMDAwWhcNMjAxMjMwMjM1OTU5WjBeMQswCQYDVQQGEwJV
# UzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFu
# dGVjIFRpbWUgU3RhbXBpbmcgU2VydmljZXMgQ0EgLSBHMjCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBALGss0lUS5ccEgrYJXmRIlcqb9y4JsRDc2vCvy5Q
# WvsUwnaOQwElQ7Sh4kX06Ld7w3TMIte0lAAC903tv7S3RCRrzV9FO9FEzkMScxeC
# i2m0K8uZHqxyGyZNcR+xMd37UWECU6aq9UksBXhFpS+JzueZ5/6M4lc/PcaS3Er4
# ezPkeQr78HWIQZz/xQNRmarXbJ+TaYdlKYOFwmAUxMjJOxTawIHwHw103pIiq8r3
# +3R8J+b3Sht/p8OeLa6K6qbmqicWfWH3mHERvOJQoUvlXfrlDqcsn6plINPYlujI
# fKVOSET/GeJEB5IL12iEgF1qeGRFzWBGflTBE3zFefHJwXECAwEAAaOB+jCB9zAd
# BgNVHQ4EFgQUX5r1blzMzHSa1N197z/b7EyALt0wMgYIKwYBBQUHAQEEJjAkMCIG
# CCsGAQUFBzABhhZodHRwOi8vb2NzcC50aGF3dGUuY29tMBIGA1UdEwEB/wQIMAYB
# Af8CAQAwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NybC50aGF3dGUuY29tL1Ro
# YXd0ZVRpbWVzdGFtcGluZ0NBLmNybDATBgNVHSUEDDAKBggrBgEFBQcDCDAOBgNV
# HQ8BAf8EBAMCAQYwKAYDVR0RBCEwH6QdMBsxGTAXBgNVBAMTEFRpbWVTdGFtcC0y
# MDQ4LTEwDQYJKoZIhvcNAQEFBQADgYEAAwmbj3nvf1kwqu9otfrjCR27T4IGXTdf
# plKfFo3qHJIJRG71betYfDDo+WmNI3MLEm9Hqa45EfgqsZuwGsOO61mWAK3ODE2y
# 0DGmCFwqevzieh1XTKhlGOl5QGIllm7HxzdqgyEIjkHq3dlXPx13SYcqFgZepjhq
# IhKjURmDfrYwggSjMIIDi6ADAgECAhAOz/Q4yP6/NW4E2GqYGxpQMA0GCSqGSIb3
# DQEBBQUAMF4xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3Jh
# dGlvbjEwMC4GA1UEAxMnU3ltYW50ZWMgVGltZSBTdGFtcGluZyBTZXJ2aWNlcyBD
# QSAtIEcyMB4XDTEyMTAxODAwMDAwMFoXDTIwMTIyOTIzNTk1OVowYjELMAkGA1UE
# BhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMTQwMgYDVQQDEytT
# eW1hbnRlYyBUaW1lIFN0YW1waW5nIFNlcnZpY2VzIFNpZ25lciAtIEc0MIIBIjAN
# BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAomMLOUS4uyOnREm7Dv+h8GEKU5Ow
# mNutLA9KxW7/hjxTVQ8VzgQ/K/2plpbZvmF5C1vJTIZ25eBDSyKV7sIrQ8Gf2Gi0
# jkBP7oU4uRHFI/JkWPAVMm9OV6GuiKQC1yoezUvh3WPVF4kyW7BemVqonShQDhfu
# ltthO0VRHc8SVguSR/yrrvZmPUescHLnkudfzRC5xINklBm9JYDh6NIipdC6Anqh
# d5NbZcPuF3S8QYYq3AhMjJKMkS2ed0QfaNaodHfbDlsyi1aLM73ZY8hJnTrFxeoz
# C9Lxoxv0i77Zs1eLO94Ep3oisiSuLsdwxb5OgyYI+wu9qU+ZCOEQKHKqzQIDAQAB
# o4IBVzCCAVMwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAO
# BgNVHQ8BAf8EBAMCB4AwcwYIKwYBBQUHAQEEZzBlMCoGCCsGAQUFBzABhh5odHRw
# Oi8vdHMtb2NzcC53cy5zeW1hbnRlYy5jb20wNwYIKwYBBQUHMAKGK2h0dHA6Ly90
# cy1haWEud3Muc3ltYW50ZWMuY29tL3Rzcy1jYS1nMi5jZXIwPAYDVR0fBDUwMzAx
# oC+gLYYraHR0cDovL3RzLWNybC53cy5zeW1hbnRlYy5jb20vdHNzLWNhLWcyLmNy
# bDAoBgNVHREEITAfpB0wGzEZMBcGA1UEAxMQVGltZVN0YW1wLTIwNDgtMjAdBgNV
# HQ4EFgQURsZpow5KFB7VTNpSYxc/Xja8DeYwHwYDVR0jBBgwFoAUX5r1blzMzHSa
# 1N197z/b7EyALt0wDQYJKoZIhvcNAQEFBQADggEBAHg7tJEqAEzwj2IwN3ijhCcH
# bxiy3iXcoNSUA6qGTiWfmkADHN3O43nLIWgG2rYytG2/9CwmYzPkSWRtDebDZw73
# BaQ1bHyJFsbpst+y6d0gxnEPzZV03LZc3r03H0N45ni1zSgEIKOq8UvEiCmRDoDR
# EfzdXHZuT14ORUZBbg2w6jiasTraCXEQ/Bx5tIB7rGn0/Zy2DBYr8X9bCT2bW+IW
# yhOBbQAuOA2oKY8s4bL0WqkBrxWcLC9JG9siu8P+eJRRw4axgohd8D20UaF5Mysu
# e7ncIAkTcetqGVvP6KUwVyyJST+5z3/Jvz4iaGNTmr1pdKzFHTx/kuDDvBzYBHUw
# ggUsMIIEFKADAgECAgECMA0GCSqGSIb3DQEBBAUAMIGuMR8wHQYDVQQDDBZNU1Mt
# U0EtU0lBIENvZGVzaWduIENBMQswCQYDVQQGDAJVUzEQMA4GA1UECAwHR2Vvcmdp
# YTEQMA4GA1UEBwwHQXRsYW50YTEaMBgGA1UECgwRU2VjdXJld29ya3MsIEluYy4x
# EzARBgNVBAsMCk1TUy1TQS1TSUExKTAnBgkqhkiG9w0BCQEWGm1zcy1zYS1zaWFA
# c2VjdXJld29ya3MuY29tMB4XDTE3MDEyNTIxMzExMVoXDTE5MDEyNTIxMzExMVow
# gaQxCzAJBgNVBAYTAlVTMRAwDgYDVQQIDAdHZW9yZ2lhMRAwDgYDVQQHDAdBdGxh
# bnRhMRQwEgYDVQQKDAtTZWN1cmVXb3JrczETMBEGA1UECwwKTVNTLVNBLVNJQTEb
# MBkGA1UEAwwSQ1RBQyBDb2Rlc2lnbiBDZXJ0MSkwJwYJKoZIhvcNAQkBFhptc3Mt
# c2Etc2lhQHNlY3VyZXdvcmtzLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBALpO5pFANpLZbuBA5mXbuhlSPbJl0HBzGjPoZAV8VeBO1w6EAe/2qF+K
# HmqPE89kBsnSnT74zLvTY+wL2OsfrqR0TfgpQPvCTx/NBFwD0FP0zYucvt5tWYqQ
# BJvHO0bPTdk4PIN73cQeI4WrZuyCHj2XsaL1qY3+kuzb7/3/v0RMA7KMae87lr9b
# 67XozZaAQVTdSJpAY5cXCUtXBjasxpFMnN8dsgnnvafjb0so2Sx1Nmo9ALSJ0rI8
# kx/VbdoKX72RtM4tpjAiZ3nU0BYjQ/y6LY+6CVd7DOncqNIDRszVhfc3nwPdycP3
# Vw/zleKXwE1w3xm3dZDNz8QxHtSZCFL9enjZGbKivIwChcgFm3RfPN7DJrFmqYWM
# V8/PKg2e5ghgvJ0fTF3PnEkgSBBWwLG5fdgMD1BJjaGxRuKJjl4kE54W2aOdLAhl
# T5KEBnCs2/GoP6rDq60fciF/SfhUXhDSQetXIJGAJKStphX/VqhtlL8r/mvxqv6v
# +Iwywh+NxmW8xmMwGZk9DNpHZY17WRd4NeU+9LZbCQuQM4JuFm+ebr1wmH4JJQsu
# 3FEX7zOJhL8yEGT47mgJZ4fnEvQvdiVa/RxZoP7o+xZJfXXdMVgNVf6RqMK4zdFj
# D8cV7bagesUJDSX+tmjBlt+41hXwueME1kHaVMz50UZGZ+N5OLFdAgMBAAGjXTBb
# MAkGA1UdEwQCMAAwCwYDVR0PBAQDAgXgMC4GA1UdJQEB/wQkMCIGCCsGAQUFBwMD
# BgorBgEEAYI3AgEVBgorBgEEAYI3AgEWMBEGCWCGSAGG+EIBAQQEAwIEsDANBgkq
# hkiG9w0BAQQFAAOCAQEAbzUJxWQWH5l9GUUcvsOHVWOJZVr1EG8iE9sCieDUGNsC
# iQDEjGjcfczbFNrAn4M4G/MJ71ng2/YBEKeA1N+uZ7RtMJDs+K0skyfCqE8rq7w3
# xyFnXN4EVwgS32FGlCy5Mz9CgLZmPAJObMmWaKlqru1ZFLcmO/GZQF5WRwZN2bhH
# MPQGllxK4ZzCfFzVAiX0wsBaNwIPvp4I73LZDtTUotO2uz8QB6Ne45rufiV2GUhN
# rVHGoGvwUoDlx0cHf5BADyi8CNOdQql+HhOTgrayabvOIdxDBftOmQ/4R88Lay+z
# kCu12Rtq29++3GmzY1Z0ViBarG3P7+VzffgwihvnTzGCBWUwggVhAgEBMIG0MIGu
# MR8wHQYDVQQDDBZNU1MtU0EtU0lBIENvZGVzaWduIENBMQswCQYDVQQGDAJVUzEQ
# MA4GA1UECAwHR2VvcmdpYTEQMA4GA1UEBwwHQXRsYW50YTEaMBgGA1UECgwRU2Vj
# dXJld29ya3MsIEluYy4xEzARBgNVBAsMCk1TUy1TQS1TSUExKTAnBgkqhkiG9w0B
# CQEWGm1zcy1zYS1zaWFAc2VjdXJld29ya3MuY29tAgECMAkGBSsOAwIaBQCgeDAY
# BgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3
# AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEWMCMGCSqGSIb3DQEJBDEW
# BBSDtVk6meB57jsF/PAyqUOa0DI5XDANBgkqhkiG9w0BAQEFAASCAgBBgNwxUIh0
# mlQIwuuoB77Mr9/DHHkNj5OODAiblZG6j7YFr6bkrJR5LcuzYJQAAAzSqfQqnRXX
# wNbd6ndHgNAIbtrDMg6ARqxTsHtJMXI1m10k/0G3r5amwZ2TC4IqSNEglWlnN12c
# 26fcztoB4dul1MzgoDK2EILaumtUFM4QB7ktZOxU/ozJ4PjXpAx5igLKqeq/j3Rr
# FpDl2Mqrq8+RH9I38Pmmqh3TIoj2XizbckUt7+j4WXONrgbQ07KZsTkUrKNPefW8
# WC3JRTdDLFVPnbKxnKMF7hA6vAoNanAUZTLeR2KaoysAiHwisvPJ6S93pYVJVTZi
# XxgEVFD6O+QQYR9YDIPLkrfhUNChGZ2E4Mpiqma4Tq/PtQe2ZxkVV7TESDbIijjO
# IXhVq2KxjyKEhGMUyMKveY6ItmJEnJUdrc/exNgi0RbQxIvxsiqNHk3owagYJpba
# pZ8huLmpiRZwLZ6qQFxf01YTRd3QVKOM3m53g5V4n2ebkyUaOcbchh+ErEk39e0D
# Z62yKGY/OZLP6jimZNEF6bvh2WwQvsw7o7bjC7UgUFPfqNsEmou/DqRASzJaa3sF
# fEm7tEId/sjCTn3s10G8TeenWVCmZbAKQ01OVMXTvmUrHuNZwxjaLElcZ7kxEgnp
# 6o+cWvkrb5wPmbI/XBb0JbBUL4O4n4JmXqGCAgswggIHBgkqhkiG9w0BCQYxggH4
# MIIB9AIBATByMF4xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jw
# b3JhdGlvbjEwMC4GA1UEAxMnU3ltYW50ZWMgVGltZSBTdGFtcGluZyBTZXJ2aWNl
# cyBDQSAtIEcyAhAOz/Q4yP6/NW4E2GqYGxpQMAkGBSsOAwIaBQCgXTAYBgkqhkiG
# 9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xNzAyMjExNjExMDZa
# MCMGCSqGSIb3DQEJBDEWBBSMStK1jHrQWMg5l03uaol3GsSLnDANBgkqhkiG9w0B
# AQEFAASCAQA4ZjC30G2szvNjeal+oF9tc49qjDex37BN+UER74yfeJvr0M4RshSe
# qHgTGrNJF6+JSAfKAlapVipPmM1PqWXBSixK+hdRdX07xv/p0lET0wuJCT2h1lwI
# J2w00a16uh5bFbT4BWKHmGm+NiHMHhT+zYvhiSuKCPpiH6cFQ737q3wCv2aHiYFn
# RRzCf88kqil6yTx084mxcdPoIdjHWHZmHHPR7FUkuqCfztwq8v1z7dBoBqu33GVB
# 4oAFy6a5g4Kg4icOgsDxrxij8fC8ltq5hnYdSEHDviZ0L4RtFz2wWADt0TJtwQkE
# QpcPP4sl1SWjeBBe4oXWGW23hAO9QB5b
# SIG # End signature block