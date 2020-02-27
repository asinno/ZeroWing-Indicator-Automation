Write-Warning -Message 'Installing Module: Posh-SSH'
Copy-Item '\\Server\DIR\Posh-SSH' -Destination $home\Documents\WindowsPowerShell\Modules\Posh-SSH -Recurse -Force
Copy-Item '\\Server\Carbon Black\bindcajport' -Destination $home\Documents\WindowsPowerShell\Modules\bindcajport -Recurse -Force
Import-Module -Name $home\Documents\WindowsPowerShell\Modules\Posh-SSH -Verbose
Import-Module -Name $home\Documents\WindowsPowerShell\Modules\bindcajport -Verbose
