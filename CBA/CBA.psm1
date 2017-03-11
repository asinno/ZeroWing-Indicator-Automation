 # Trust all certs
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
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  [System.Net.ServicePointManager]::CertificatePolicy = New-Object -TypeName TrustAllCertsPolicy
 # Begin Function Search CB 
 function Search-CarbonBlackAppliance {
   [CmdletBinding()]
   param(
     [CmdletBinding(SupportsShouldProcess=$True)]
     [ValidateSet('Process', 'Binary', 'Sensor','Blacklist','Watchlist','Feed','HostInfo','Alert','License','Benchmark')]
     [Parameter()]
     [string]$QueryType,
     [Parameter(Mandatory=$true)]
     [string]$URL,
     [Parameter(Mandatory=$true)]
     [string]$Key,
     [string]$Search
   )
   # Hash Table to build URLs
   $hashTableUrl = @{
     'Process'   = ('/api/v1/process?q={0}' -f $Search)
     'Benchmark' = ('/api/v1/process?q={0}' -f $Search)
     'Binary'    = ('/api/v1/binary/{0}/summary' -f $Search)
     'Sensor'    = '/api/v1/sensor'     'Blacklist' = '/api/v1/banning/blacklist'
     'Watchlist' = '/api/v1/watchlist'
     'Feed'      = '/api/v1/feed'
     'HostInfo'  = ('/api/v1/sensor?hostname={0}' -f $Search)
     'Alert'     = '/api/v1/alert'
     'License'   = '/api/v1/license'
   }
   # Hash Table For Calculated Properties
 #  $hashTableCalculatedProperties = @{
 #    'Process'   = ''
 #    'Binary'    = ''
 #    'Sensor'    =  "$SensorInformation" #    'Blacklist' = ''
 #    'Watchlist' = ''
 #    'Feed'      = ''
 #    'HostInfo'  = ''
 #    'Alert'     = ''
 #    'License'   = ''
 #  }
 #     $TableFormat = $hashTableCalculatedProperties[$QueryType]
      $fullPath = $hashTableUrl[$queryType]
      # Query EndPoint
      $Query = Invoke-RestMethod -uri $URL$fullPath -Headers @{'X-Auth-Token' = $Key}
      $Query
 }
 function Test-CBQuery {
   [CmdletBinding()]
   param(
     [string]$QueryToTest
   )
   # Query All Devices
   Write-Host 'Testing Carbon Black Query, please wait...' -ForegroundColor Green
   $dellCso1Query    = Search-CarbonBlackAppliance -QueryType Benchmark -Search $QueryToTest -URL 'https://localhost:8081' -Key '1c1039fd73fcd6d3f520c2907146046d29be748f'
   $dellCso2Query    = Search-CarbonBlackAppliance -QueryType Benchmark -Search $QueryToTest -URL 'https://localhost:8082' -Key '28e153cbd4deca38b6c1553a72d10f9568c8593c'
   $dellCso3Query    = Search-CarbonBlackAppliance -QueryType Benchmark -Search $QueryToTest -URL 'https://localhost:8083' -Key 'd7035103c53f95d89aa78152507e89a68c44abe5'
   $kelloggQuery     = Search-CarbonBlackAppliance -QueryType Benchmark -Search $QueryToTest -URL 'https://localhost:8084' -Key 'ff95f473ec105b82950a1468bbda74b27a263d95'
   $bainQuery        = Search-CarbonBlackAppliance -QueryType Benchmark -Search $QueryToTest -URL 'https://localhost:8085' -Key 'd61e2adc8567aa467fad74cb7717fbf20425136d'
   $aramcoQuery      = Search-CarbonBlackAppliance -QueryType Benchmark -Search $QueryToTest -URL 'https://localhost:8086' -Key '870f89817600b21d736a9354ba892a688f8a6ab0'
   $allenOvery1Query = Search-CarbonBlackAppliance -QueryType Benchmark -Search $QueryToTest -URL 'https://localhost:8087' -Key '6655a1bc72c1c1ae709e016a7414f121ade6a040'
   $unionBankQuery   = Search-CarbonBlackAppliance -QueryType Benchmark -Search $QueryToTest -URL 'https://localhost:8088' -Key 'd289c677aff8869d7dac3763d9004a0a3333cba4'
   $newYorkJetsQuery = Search-CarbonBlackAppliance -QueryType Benchmark -Search $QueryToTest -URL 'https://localhost:8089' -Key '8b28fec88d2bd1c6da6ae94855fa6b89bb845378'
   $uOfAQuery        = Search-CarbonBlackAppliance -QueryType Benchmark -Search $QueryToTest -URL 'https://localhost:8090' -Key '2b8f86fc18f7c138c53a0f5a4c8cc12a36a4ce81'
  
   # Generate Calculated Properties
   $watchlistResults =
   @{e={$_.terms}
   Label='Terms'},
   @{e={$_.start}
   Label='Start'},
   @{e={$_.elapsed}
   l='Elapsed'},
   @{e={$_.total_results}
   l='Total Results'}
   
   # Create PSObject 
   New-Object -TypeName PSObject -Property @{
     'Dell CSO 1'                  = $dellCso1Query | Select-Object $watchlistResults
     'Dell CSO 2'                  = $dellCso2Query | Select-Object $watchlistResults
     'Dell CSO 3'                  = $dellCso3Query | Select-Object $watchlistResults
     'Kellogg Brown & Root LLC'    = $kelloggQuery | Select-Object $watchlistResults
     'Bain Capital, LP, Boston'    = $bainQuery | Select-Object $watchlistResults
     'Aramco'                      = $aramcoQuery | Select-Object $watchlistResults
     'Allen & Overy LLP, London 1' = $allenOvery1Query | Select-Object $watchlistResults
     'Union Bank'                  = $unionBankQuery | Select-Object $watchlistResults
     'New York Jets'               = $newYorkJetsQuery | Select-Object $watchlistResults
     'University of Alabama'       = $uOfAQuery | Select-Object $watchlistResults
   } | ForEach-Object { # Enumerate Values
     foreach ($p in $_.PSObject.Properties) {
       $p.Value | Select-Object @{n='Client';e={$p.Name}},*
     }
   }
 }
 # Create Calculated Properties
 $SensorInformation =
 @{e={$_.systemvolume_total_size}
 l = 'Volume Size'},
 @{e={$_.emet_telemetry_path}
 l = 'Telemetry Path'},
 @{e={$_.os_environment_display_string}
 l = 'Operating System'},
 @{e={$_.emet_version}
 l = 'Emet Version'},              
 @{e={$_.emet_dump_flags}
 l = 'Emet Dump Flags'},             
 @{e={$_.clock_delta}
 l = 'Clock Delta'},                
 @{e={$_.supports_cblr}
 l = 'Supports CBLR'},               
 @{e={$_.sensor_uptime}
 l = 'Sensor Uptime'},                 
 @{e={$_.last_update}
 l = 'Last Update'},                 
 @{e={$_.physical_memory_size}
 l = 'Physical Memory Size'} ,         
 @{e={$_.build_id}
 l = 'Build ID'},           
 @{e={$_.uptime}
 l = 'Uptime'},             
 @{e={$_.is_isolating}
 l = 'Isolated'},               
 @{e={$_.event_log_flush_time}
 l = 'Event Log Flush Time'},       
 @{e={$_.computer_dns_name}
 l = 'Computer DNS Name'},         
 @{e={$_.emet_report_setting}
 l = 'Emet Report Setting'},           
 @{e={$_.id}
 l = 'ID'},           
 @{e={$_.emet_process_count}
 l = 'Emet Process Count'}, 
 @{e={$_.emet_is_gpo}
 l = 'Emet is GPO'},            
 @{e={$_.power_state}
 l = 'Power State'},                    
 @{e={$_.network_isolation_enabled}
 l = 'Network Isolation Enabled'},   
 @{e={$_.uninstalled}
 l = 'Uninstalled'},         
 @{e={$_.systemvolume_free_size}
 l = 'System Free Size'},
 @{e={$_.status}
 l = 'Status'},
 @{e={$_.num_eventlog_bytes}
 l = 'Number Event Log Bytes'},
 @{e={$_.sensor_health_message}
 l = 'Sensor Health'},
 @{e={$_.build_version_string}
 l = 'Build Version String'},       
 @{e={$_.computer_sid}
 l = 'Computer SID'},          
 @{e={$_.next_checkin_time}
 l = 'Next Checkin Time'},             
 @{e={$_.node_id}
 l = 'Node ID'},             
 @{e={$_.cookie}
 l = 'Cookie'},         
 @{e={$_.emet_exploit_action}
 l = 'Emet Exploit Action'},     
 @{e={$_.computer_name}
 l = 'Computer Name'},           
 @{e={$_.license_expiration}
 l = 'License Expiration'},      
 @{e={$_.supports_isolation}
 l = 'Supports Isolation'},          
 @{e={$_.parity_host_id}
 l = 'Parity Host ID'},             
 @{e={$_.supports_2nd_gen_modloads}
 l = 'Supports 2nd Gen Modloads'},  
 @{e={$_.network_adapters}
 l = 'Network Adapters'},     
 @{e={$_.sensor_health_status}
 l = 'Sensor Health Status'},
 @{e={$_.registration_time}
 l = 'Registration Time'},            
 @{e={$_.restart_queued}
 l = 'Restart Queued'},             
 @{e={$_.notes}
 l = 'Notes'},                
 @{e={$_.num_storefiles_bytes}
 l = 'Number Storefiles in Bytes'},        
 @{e={$_.os_environment_id}
 l = 'OS Environment ID'},    
 @{e={$_.shard_id}
 l = 'Shard ID'},             
 @{e={$_.boot_id}
 l = 'Boot ID'},                      
 @{e={$_.last_checkin_time}
 l = 'Last Checkin Time'},            
 @{e={$_.os_type}
 l = 'OS Type'},             
 @{e={$_.group_id}
 l = 'Group ID'},                      
 @{e={$_.display}
 l = 'Display'},                      
 @{e={$_.uninstall}
 l = 'Uninstall'}