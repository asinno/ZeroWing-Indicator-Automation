 $html = Get-Content C:\Users\asinno\Desktop\bshtml.html  | Select-String -AllMatches 'ct0'
 $html = $html -replace "<(img|a)[^>]*>(?<content>[^<]*)<" -replace "(<tr>|<td>|</tr>|</td>|<a>|</a>|a>|\/|<table>|<br>|</br>|</table>|<table|<html>|<table>|<head>)" -replace ".+(?=ct0)"
 $html