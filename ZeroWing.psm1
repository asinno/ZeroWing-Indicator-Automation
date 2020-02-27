########################################################

#                    Retribution Menu                  #

########################################################

function TestMenu {

    if ($Feed -eq $True) {

        Get-AsciiArt -ZeroWing
        Write-Host '+ 0       - AlienVault                   '
        Write-Host '+ 1       - AttackerDB                   '
        Write-Host '+ 2       - CTP Threats Baseline         '
        Write-Host '+ Exit    - exits from the script        '  
        Write-Host '+ Credits - Authors                      '
    }

    elseif ($SingleQuery -eq $True) {

        Get-AsciiArt -ZeroWing

        Write-Host '+ Start   - begins the testing script      '

        Write-Host '+ Show    - enumarate connected clients    '

        Write-Host '+ Exit    - exits from the script          '

        Write-Host '+ Credits - Authors                        '

        Write-Host

    }

}

# Loading Web Assemblies

[Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null


#Trust all certs

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

 

##############################################################

#               Carbon Black Query Validation Set            #

##############################################################

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::CertificatePolicy = New-Object -TypeName TrustAllCertsPolicy
$Prompt =

"Write-Host '<=Zer' -ForegroundColor Yellow -NoNewline; Write-Host 'oW' -ForegroundColor Red -NoNewline; Write-Host 'ing=>' -ForegroundColor Blue -NoNewline"
$CountConnections = 0
$BinaryDecision = @('y', 'n')
#Begin Function Search CB
function Search-CarbonBlackAppliance {
    [CmdletBinding()]

    param(
        [CmdletBinding(SupportsShouldProcess = $True)]
        [ValidateSet('Process', 'Binary', 'Sensor', 'Blacklist', 'Watchlist', 'Feed', 'HostInfo', 'Alert', 'License', 'Benchmark')]
        [Parameter()]
        [string]$QueryType,
        [Parameter(Mandatory = $true)]
        [string]$URL,
        [Parameter(Mandatory = $true)]
        [string]$Key,
        [string]$Search
   )

    #Hash Table to build URLs

    $hashTableUrl = @{

        'Process' = ('/api/v1/process?q={0}' -f $Search)

        'Benchmark' = ('/api/v1/process?q={0}' -f $Search)

        'Binary' = ('/api/v1/binary/{0}/summary' -f $Search)

        'Sensor' = '/api/v1/sensor'

        'Blacklist' = '/api/v1/banning/blacklist'

        'Watchlist' = '/api/v1/watchlist'

        'Feed' = '/api/v1/feed'

        'HostInfo' = ('/api/v1/sensor?hostname={0}' -f $Search)

        'Alert' = '/api/v1/alert'

        'License' = '/api/v1/license'

    }

    $fullPath = $hashTableUrl[$QueryType]

  

    #Query EndPoint

    $Query = Invoke-RestMethod -uri $URL$fullPath -Headers @{'X-Auth-Token' = $Key}

  

    #HashTable for Templates

    $hashTableFormat = @{

        'Process' = $Query.results | Select-Object -Property $ProcessInformation

        'Binary' = $Query

        'Benchmark' = $Query | Select-Object -Property $watchlistResults

        'Sensor' = $Query

        'Blacklist' = $Query

        'Watchlist' = $Query

        'Feed' = $Query

        'HostInfo' = $Query

        'Alert' = $Query

        'License' = $Query

    }

    $hashTableFormat[$QueryType]

}

 

################################################################################

#             Query Testing Function for Feeds and single queries              #

################################################################################

 

function Test-CBQuery {

    #Main CB Tester Script

    param(

        [Switch]$SingleQuery,

        [Switch]$Feed

    )

    Write-Host '====================================' -ForegroundColor Yellow

    Write-Host '        Attention Gentlemen!        ' -ForegroundColor Red

    Write-Host '====================================' -ForegroundColor Yellow

    Write-Host

    Write-Host 'Please be mindful of client confidentiality, polution and availability. This script was meant to benefit the team, however, carelessness will not be tolerated.'

    $Agreement = Read-Host 'Please type [Y/y] to acknowledge this warning.'

    if ($Agreement -ine 'y') {

        break

    }

  

    #Outer Most Loop

    :StartLoop while ($true) {

        if ($Query -ne $null) {

        }

        Clear-Host

 

        # Connect to devices list in KeePass database

    

        Write-Host 'Please enter the KeePass password' -ForegroundColor Yellow

        Write-Host

        try {

            $AllClients = Connect-ToKeePass

        }

        catch {

            if ($error.Exception -match "CommandNotFoundException") {
                Write-Error "You are not connected to the ZeroWing server!"
            }

            else {
                Clear-Host
                Write-Host 'In order to proceed we must connect you to the ZeroWing StarShip!' -ForegroundColor Red
                Read-Host 'Press Enter to Connect'
                go
                Continue StartLoop

            }

        }

        finally {

 

        }

        if ($AllClients.Client -eq $null) {

            Write-Warning -Message 'Terminating script: There is no client data to make connections'

            Start-Sleep -Seconds 2

            continue StartLoop

        }

 

        if(($AllClients.'NAT IP'| Group-Object | Where-Object { $_.Count -gt 1 } | Select-Object -ExpandProperty Name) -gt 0)

        {

            Write-Host 'Warning the KeePass database contains duplicate entries..... TERMINATING ZEROWING...GG' -ForegroundColor Red

            break StartLoop

        }

 

        $NewClientTable = @()

 

        #Create Client Table and insert IP addresses as well as releveant information

        foreach ($Client in $AllClients.Client) {

            $IPAsObject = $AllClients.'NAT IP'[$CountConnections]

            $IPAsString = $IPAsObject | Out-String

            #Connect to Carbon Black Appliances here

            #try {

                Write-Host "Connecting to $Client"

 

                Connect-ToEndPoint -EndPoint $IPAsString -LocalPort 9999  -ErrorAction Stop

 

            #}

            #catch {

               # if ($error.Exception -match "denied") {

              #      Write-Error "Please enter a correct CAJ PIN and Token."

             #   }

            #    Read-Host

           #     continue StartLoop

          #  }

 

            #Enumerate the BoundHostValue

            $FullAddress = Get-SSHPortForward -Index 0 |

                Select-Object -Property BoundHost |

                Where-Object {$_.Host -eq $IP }

 

            #Check tunneled connections

            $ClientConnectionIP = $FullAddress.BoundHost

 

            #$IndexedIP =

            #if ($CountConnections -eq 0 ) {

            #    $ClientConnectionIP |

            #        Select-Object -First 1

            #}

            #else {

            #    $ClientConnectionIP[$CountConnections]

            #}

            #Create PSOBJECT Table

 

          $NewClientTable += New-Object -TypeName PSObject -Property @{

                'Client' = $AllClients.Client[$CountConnections];

                'URL' = "{0}{1}{2}" -f 'https://', $ClientConnectionIP[$CountConnections], ":9999";

                'API' = $AllClients.API[$CountConnections];

            }

            $CountConnections++

        }

 

        $OpenConnections = $NewClientTable.Client.Count

        if ($OpenConnections = 0) {

            Write-Warning -Message 'There are no open connections'

            break

        }

        :outer while ($true) {

            Clear-Host

            $NewTotal = 0

            $QueryCounter = 0

            $TermViolations = New-Object  -TypeName psobject -Property @{

                'Parenthetical Negation' = '-('

            }

            $FeedList = New-Object  -TypeName psobject -Property @{

                'SecureWorks CTP' = '\*'

            }

            #Start a menu for guiding the user

            TestMenu

            "Currently there are {0} clients connected" -f $NewClientTable.Client.Count

            :menuloop while ($true) {

                #Creates switch specific to feeds or indicator testing

                if ($feed -eq $true) {

                    Invoke-Expression ($Prompt)

                    $UserDecision = Read-Host

                    switch ($UserDecision) {

                        start {break menuloop}

                        show {$AllClients | Format-Table}

                        0 {

                            $ScoreRange = Read-Host 'Please enter your threat score range. For example "1 to 100"'

                            $Query = "alliance_score_alienvault:[$ScoreRange]"

                            break menuloop

                        }

                        1 {}

                        2 {}

                        3 {}

                        show {$AllClients | Format-Table}

                        exit {break StartLoop}

                        credits {Start-DialogueZW}

                    }

                }

                else {

                    Invoke-Expression ($Prompt)

                    $UserDecision = Read-Host

                    switch ($UserDecision) {

                        start {break menuloop}

                        show {$AllClients | Format-Table}

                        ? {Write-Host 'What are you so confused about?'}

                        #cm         {if($Query -ne $null){Clear-Variable Query}; Clear-Host; Start-ConverterPrompt}

                        syntax {$TermViolations | Format-List}

                        exit {break StartLoop}

                        credits {Start-DialogueZW}

                    }

                }

            }

            if ($SingleQuery -eq $true) {

                #Capture query for testing, then iterate through all open connections

                Write-Host '=============================================='

                Write-Host 'Type "exit" to return to menu or enter a query'

                Write-Host '=============================================='

                Invoke-Expression ($Prompt)

                $Query = Read-Host ' Please enter your query'

                if ($Query -ieq 'exit') {

                    continue outer

                }

            }

            while ($Query -eq $null) {

                Invoke-Expression ($Prompt)

                $Query = Read-Host ' Please enter a query that is not null'

            }

            #Dynamically build PowerShell collections Object for API keys and URLs

            $CollectionOfClients = @()

            $ResultCollection = @()

            $JobCounter = 0

 

            #Clear Job Slate

            Remove-Job *

 

            #Begin to iterate and test clients - test loop

            foreach ($Client in $NewClientTable.Client) {

                $URL = $NewClientTable.URL[$QueryCounter]

                $API = $NewClientTable.API[$QueryCounter]

                $QueryTime = 0

        

                #URL Encode the Query

                [Reflection.Assembly]::LoadWithPartialName("System.Web") | Out-Null

                $EncodedQuery = [System.Web.HttpUtility]::UrlEncode("$Query")

            

                #Begin Query to Carbon Black device

                if ($SingleQuery -eq $true) {

 

                    Write-Host "[Processing '$Client']" -ForegroundColor Green

                    # Execute the jobs in parallel

                    $ScriptBlock = {

                        param(

                            [string]$URL,

                            [string]$EncodedQuery,

                            [string]$API,

                            [string]$Client

                        )

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

                       #Allows powershell to trust all certs

                        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

                        [System.Net.ServicePointManager]::CertificatePolicy = New-Object -TypeName TrustAllCertsPolicy

 

                        #Prioritize Jobs in background

                        [System.Threading.Thread]::CurrentThread.Priority = 'AboveNormal'

                        ([System.Diagnostics.Process]::GetCurrentProcess()).PriorityClass = 'AboveNormal'

 

                        #Makes Web request for data

                        Invoke-WebRequest -Uri "$url/api/v1/process?q=$EncodedQuery" -Headers @{'X-Auth-Token' = "$api"} | ConvertFrom-Json

                       

                        #Communicate to end user that job has been completed

                        Write-Host "[Client '$Client' completed]" -ForegroundColor Green

                    }

                    Start-Job -Name $Client $ScriptBlock -ArgumentList $URL, $EncodedQuery, $API , $Client | Out-Null

                }

                $QueryCounter++

               

                #Process at 10 jobs

                if ($JobCounter -gt 9) {

                    $StopCounter = 0

                    While ((Get-Job -State "Running").Count -gt 8) {

                        Start-Sleep -Seconds 1

                        $StopCounter++

                        if ($StopCounter -eq 10) {

                            #Inform user which clients are taking a long time to finish

                            $RunningJobs = (Get-Job -State Running).Name -join ', '

                            Write-Warning -Message "Client(s) '$RunningJobs' is/are taking a long time and will terminate shortly if they do not finish in 10 seconds."

                            Clear-Variable RunningJobs

                        }

                        # Stop jobs that have been taking longer than 20 seconds

                        if ($StopCounter -eq 20) {

                            $RunningJobs = (Get-Job -State Running).Name -join ', '

                            Write-Host "Terminating job(s) '$RunningJobs'" -ForegroundColor Red

                            Stop-Job -State Running

                        }

                    }

                    $JobCounter = 0

                }

                $JobCounter++

            }

            $StopCounter = 0

            #Check for straggler jobs still running

            While (Get-Job -State "Running") {

               

                if ($StopCounter -eq 0) {

                    Write-Host '[Finishing up the last couple of jobs]' -ForegroundColor Yellow

                    (Get-Job -State Running).Name

                }

                Start-Sleep -Seconds 1

                $StopCounter++

                if ($StopCounter -eq 10) {

                    #Inform user which clients are taking a long time to finish

                    $RunningJobs = (Get-Job -State Running).Name -join ' ,'

                    Write-Warning -Message "Client(s) '$RunningJobs' is/are taking a long time and will terminate shortly if they do not finish in 10 seconds."

                    Clear-Variable RunningJobs

                }

                # Stop jobs that have been taking longer than 20 seconds

                if ($StopCounter -eq 20) {

                    $RunningJobs = (Get-Job -State Running).Name -join ' ,'

                    Write-Host "Terminating job(s) '$RunningJobs'" -ForegroundColor Red

                    Stop-Job -State Running

                }

            }

   

 

            #Obtain list of completed jobs to store in psobject

            Write-Host '[Compiling list of succesful jobs]' -ForegroundColor Green

            $AllJobNames = @()

            $JobCompleteList = Get-Job -State Completed

            foreach ($JobName in $JobCompleteList.Name) {

                $AllJobNames += New-Object -TypeName psobject -Property @{

                    "Name" = $JobName

                }

            }

            Write-Host '[List of succesfully completed jobs are below]' -ForegroundColor Yellow

            #Retrieve Job Results

            $Results = Get-Job | Receive-Job

            Write-Host '[Storing values into PowerShell objects for formating]' -ForegroundColor Green

           $ClientCounter = 0

            foreach ($Job in $Results) {

                #Build Object containing results

                $CollectionOfClients += New-Object  -TypeName psobject -Property @{

                    "Client" = $AllJobNames.Name[$ClientCounter];                  

                    "Terms" = $Job.terms -join ',';      

                    "Start" = $Job.Start;       

                    "Elapsed" = $Job.Elapsed;     

                    "Total" = $Job.total_results;

                }

                $TotalResults = $Job.total_results

 

                foreach ($Result in $Job.Results) {

                    $ResultCollection += New-Object -TypeName psobject -Property @{

                        "Client" = $AllJobNames.Name[$ClientCounter];

                        "Process Md5" = $Result.process_md5;

                        "Sensor" = $Result.sensor_id;

                        "Modloads" = $Result.modload_count;

                        "File Mods" = $Result.filemod_count;

                        "Child Processes" = $Result.childproc_count;

                        "Regmods" = $Result.regmod_count;

                        "Virus Total" = $Result.alliance_link_virustotal;

                        "Process Name" = $Result.process_name;

                        "Parent Process" = $Result.parent_name;

                        "Parent MD5" = $Result.parent_md5;

                        "cmdline" = $Result.cmdline;

                        "Group" = $Result.group;

                        "Hostname" = $Result.hostname;

                        "Username" = $Result.username;

                        "ID" = $Result.unique_id;

                    }

                }

                #Counter for array index

                $ClientCounter++

                $NewTotal += $TotalResults

            }

       

 

            #Begin analyzing results as a psobject for manipulation

            :DisplayLoop while ($true) {

                Write-Host "There are currently $NewTotal result(s)" -ForegroundColor Yellow

                Invoke-Expression ($Prompt)

                $DecisionArray = @('c', 'g', 't', "")

                $UserDecision = Read-Host ' Export-Csv[C] - GridView [G] - Format-Table [T]'

 

                #Check for correct arguments in client collection object

                while ($DecisionArray -notcontains $UserDecision) {

                    Invoke-Expression ($Prompt)

                    $UserDecision = Read-Host ' Please select a proper format [C][G][T]'

                }

       

                #Begin decision switch for analysis review

                switch ($UserDecision) {

                    c {

                        Invoke-Expression ($Prompt)

                        $filename = Read-Host ' Please specify a file name. CSVs are automatically saved to your desktop.'

                        $CollectionOfClients |

                            Export-Csv -Path $env:USERPROFILE\Desktop\$filename

                    }

                    g {

                        $CollectionOfClients |

                            Out-GridView -Title 'Collection Of Client Results'

                    }

                    t {

                        $CollectionOfClients |

                            Select-Object -Property Client, Terms, Start, Elapsed, Total | Sort-Object -Property Total -Descending |

                            Format-Table

                    }

                }

      

                #Give analyst capability to review the same psobject to manipulate in a different format type

                Invoke-Expression ($Prompt)

                $DecisionContinue = Read-Host " Continue analyzing these results? [Y][N]"

                if ($DecisionContinue -ieq 'n') {

                    break DisplayLoop

                }

            }

 

            #Allow analyst to check individual results to detect false positives

            if ($NewTotal -eq '0') {

                $Timer = 0

                while ($Timer -ne 5) {

                    Read-Host ' Press enter to clear host and go back to main menu!'

                    Clear-Host

                    Write-Warning -Message 'There are no results found for this indicator, sending you to query menu momentarily...'

                    Start-Sleep -Seconds 1

                    $Timer++

                    continue outer

                }

            }

            else {

                :DetailedLoop while ($true) {

                    Invoke-Expression ($Prompt)

                    $ResultDecision = Read-Host ' Examine results in-depth? [Y][N]'

      

                    #Detect if user entered a correct argument

                    while ($BinaryDecision -notcontains $ResultDecision) {

                        Invoke-Expression ($Prompt)

                        $ResultDecision = Read-Host ' Please enter an acceptable argument [Y][N]'

                    }

                    if ($ResultDecision -ieq 'y') {

                        Invoke-Expression ($Prompt)

                        $DecisionArray = @('c', 'g', 't', "")

                        $UserDecision = Read-Host ' Export-Csv[C] - GridView [G] - Format-Table [T]'

 

                        #Check for correct arguments in client collection object

                        while ($DecisionArray -notcontains $UserDecision) {

                            Invoke-Expression ($Prompt)

                            $UserDecision = Read-Host ' Please select a proper format [C][G][T]'

                        }

 

                        #Begin decision switch for analysis review

                        switch ($UserDecision) {

                            c {

                                Invoke-Expression ($Prompt)

                                $filename = Read-Host ' Please specify a file name. CSVs are automatically saved to your desktop.'

                                $ResultCollection |

                                    Export-Csv -Path $env:USERPROFILE\Desktop\$filename

                            }

                            g {

                                $ResultCollection |

                                    Out-GridView -Title 'Collection Of Client Results'

                            }

                            t {

                                $ResultCollection |

                                    Select-Object -Property "Client", "Process Md5", "Process Name", "Parent Process", "Parent MD5", "cmdline", "Modloads", "Regmods", "Child Processes", "File Mods", "Virus Total", "Group", "Hostname", "Username", "Sensor", "ID" |

                                    Format-Table

                            }

 

                        }

                        Invoke-Expression ($Prompt)

                        $DecisionContinue = Read-Host " Continue analyzing these results? [Y][N]"

                        if ($DecisionContinue -ieq 'n') {

                            break DetailedLoop

                            continue menuloop

                        }

                    }

                    elseif ($ResultDecision -ieq 'n') {

                        break DetailedLoop

                        continue menuloop

                    }

                }

                if ($Feed -eq $true) {

                    continue StartLoop

                }

            }

        }

    }

}

 


###################################################################

#                  Carbon Black Ticket Analyzer                   #

###################################################################


#$Ticket = Read-Host '<==ZeroWing==>'

##2 User must select date range for ticket search:

#$ClientQuery = Invoke-RestMethod "https://analysis.secureworks.net/~akilinc/api/tickets/?id=$Ticket&search=hash"

##4 Displays relevant surrounding ticket data along with close codes etc.

##5 User can decide to connect to Carbon Black device or Retrieve RC data and begin analysis

 

#Auto connect

function Start-CBAutoConnect {

    if ($ClientQuery.device_data.types -imatch 'Carbon') {

  

        #Enumerate the BoundHostValue

        $FullAddress =

        Get-SSHPortForward -Index 0 |

            Where-Object {$_.Host -eq $ClientQuery.device_data.ip.internal_ip }

    

        #If the device is not currently connected, we simply connect it...

        if ($FullAddress.BoundHost -eq $null) {

            # Connect to device

            Connect-ToEndPoint -EndPoint $ClientQuery.device_data.ip.internal_ip -LocalPort 9999

            #Enumerate the BoundHostValue

            $FullAddress = Get-SSHPortForward -Index 0 |

                Where-Object {$_.Host -eq $ClientQuery.device_data.ip.internal_ip }

        }

    

        #Convert IP Address to variable

        $IPAddress = "https://{0}:9999" -f $FullAddress.BoundHost

    

        #Open Default Browser:

        start "$IPAddress"

    

        #Automatically fetch creds

        Get-DeviceCredentials -Device $ClientQuery.device_data.ct_name

    }

}

 

function Start-CBInvestigation {

    $Hostname = $ClientQuery.cds_data.subject -ireplace ("^.*(?=(on))" + "on ")

    Write-Host '<==ZeroWing==>' -NoNewline -ForegroundColor Red

    $API = Read-Host 'Please enter the API key'

    $Start = $ClientQuery.cds_data.SYSTEM_MODIFIED_DATE -replace ' [0-9]{2}:[0-9]{2}:[0-9]{2}', 'T00:00:00'

    $End = $ClientQuery.cds_data.SYSTEM_MODIFIED_DATE -replace ' [0-9]{2}:[0-9]{2}:[0-9]{2}', 'T23:59:00'

    Search-CarbonBlackAppliance -QueryType Process -URL $IPAddress -Key $API -Search "hostname:$Hostname &cb.q.start=-1440m&rows=10000"

}

##########################################################

#                ZeroWing Audit                      #

##########################################################

 

Set-alias -Name audit -Value Start-ZeroWingAudit

function Start-ZeroWingAudit {

 

#Obtain List of devices from database

$ClientNames = Invoke-RestMethod -Uri 'https://analysis.secureworks.net/~akilinc/api/AETDCB_devices/'

 

#Create PowerShell collection object for all clients

$ClientCollection = @()

foreach($Client in $ClientNames.clients | Select-Object -Unique){

$ClientCollection +=  New-Object -SizeLimit 2000 -TypeName psobject -Property @{

 "Client" = $Client;

}

}

#Obtain KeyPass Clients

$KeePassClients = Connect-ToKeePass

 

#Create PowerShell collection object for KeePass clients

$ClientCollectionKeePass = @()

foreach($KeePassClient in $KeePassClients.client | Select-Object -Unique){

$ClientCollectionKeePass +=  New-Object -SizeLimit 2000 -TypeName psobject -Property @{

 "KeePassClient" = $KeePassClient;

}

}

 

#Obtain Totals from each object

$KeePassTotal = $ClientCollectionKeePass.KeePassClient.Count

$TotalMissing = $ClientCollection.clients.Count

 

#Compare Objects

Compare-Object -ReferenceObject $ClientCollectionKeePass -DifferenceObject $ClientCollection -Property KeePassClient,Client

 

#Print Totals Comparison

Write-Host "There are currently $totalmissing client(s) missing and $KeePassTotal in the database" -ForegroundColor Red

Write-Host

}

 

##########################################################

#                     ZeroWing Dialogue                  #

##########################################################


function Start-DialogueZW {

    Clear-Host

    Get-AsciiArt -ZeroWingPressAny

    Read-Host

    Clear-Host

    Write-Host "     In A.D. 2101" -ForegroundColor DarkMagenta

    Start-Sleep -Seconds 3

    Clear-Host

    Write-Host "     War was beginning." -ForegroundColor DarkMagenta

    Start-Sleep -Seconds 3

    Clear-Host

    Write-Host "     Captain: What happen?" -ForegroundColor Green

    Start-Sleep -Seconds 3

    Clear-Host

    Write-Host "     Mechanic: Somebody set up us the bomb." -ForegroundColor Yellow

    Start-Sleep -Seconds 3

    Clear-Host

    Write-Host "     Operator: We get signal." -ForegroundColor Yellow

    Start-Sleep -Seconds 3

    Clear-Host

    Write-Host "     Captain: What !" -ForegroundColor Green

    Start-Sleep -Seconds 3

    Clear-Host

    Write-Host "     Operator: Main screen turn on." -ForegroundColor Yellow

    Start-Sleep -Seconds 3

    Clear-Host

    Write-Host "     Captain: It's You !!" -ForegroundColor Green

    Start-Sleep -Seconds 3

    Clear-Host

    Write-Host "     Cats: How are you gentlemen !!" -ForegroundColor Red

    Start-Sleep -Seconds 3

    Clear-Host

    Write-Host "     Cats: All your base are belong to us." -ForegroundColor Red

    Start-Sleep -Seconds 3

    Clear-Host

    Write-Host "     Cats: You are on the way to destruction." -ForegroundColor Red

    Start-Sleep -Seconds 3

    Clear-Host

    Write-Host "     Captain: What you say !!" -ForegroundColor Green

    Start-Sleep -Seconds 3

    Clear-Host

    Write-Host "     Cats: You have no chance to survive make your time." -ForegroundColor Red

    Start-Sleep -Seconds 3

    Clear-Host

    Write-Host "     Cats: HA HA HA HA ...." -ForegroundColor Red

    Start-Sleep -Seconds 3

    Clear-Host

    Write-Host "     Captain: Take off every 'zig' !!" -ForegroundColor Green

    Start-Sleep -Seconds 3

    Clear-Host

    Write-Host "     Captain: You know what you doing." -ForegroundColor Green

    Start-Sleep -Seconds 3

    Clear-Host

    Write-Host "     Captain: Move 'zig'. " -ForegroundColor Green

    Start-Sleep -Seconds 3

    Clear-Host

    Write-Host "     Captain: For great justice." -ForegroundColor Green

    Start-Sleep -Seconds 3

    Clear-Host

    Write-Host '     Let the mission begin......' -ForegroundColor DarkMagenta

    Clear-Host

    Get-AsciiArt -ZeroWing

    Write-Host '     John Drafke | Ahmet Kilinc | Don Mizutani           '

    Write-Host '========================================================='

    Write-Host '+ Start - begins the testing script              '

    Write-Host '+ Show  - enumarate connected clients            '

    Write-Host '+ ?     - show restricted terms                  '

    Write-Host '+ Exit  - exits from the script                  '

    Write-Host '+ Credits - Authors                              '

}

 

#########################################################################

#                  Below are the Calculated Properties                  #

#########################################################################


# Create Calculated Properties

$ProcessInformation =

@{e = {$_.start}

    l = 'Start Time'

},

@{e = {$_.hostname}

    l = 'Hostname'

},

@{e = {$_.username }

    l = 'Username'

},

@{e = {$_.parent_name }

    l = 'Parent Process'

},

@{e = {$_.process_name }

    l = 'Process Name'

},

@{e = {$_.cmdline }

    l = 'Command Line Arguments'

},

@{e = {$_.process_md5 }

    l = 'MD5'

}

 

  

# Generate Calculated Properties

$watchlistResults =

@{e = {$TestResultsParsed.terms}

    Label = 'Terms'

},

@{e = {$TestResultsParsed.start}

    Label = 'Start'

},

@{e = {$TestResultsParsed.elapsed}

    l = 'Elapsed'

},

@{e = {$TestResultsParsed.total_results}

    l = 'Total Results'

}


# Create Calculated Properties

$ProcessInformation =

@{e = {$_.start}

    l = 'Start Time'

},

@{e = {$_.hostname}

    l = 'Hostname'

},

@{e = {$_.username }

    l = 'Username'

},

@{e = {$_.parent_name }

    l = 'Parent Process'

},

@{e = {$_.process_name }

    l = 'Process Name'

},

@{e = {$_.cmdline }

    l = 'Command Line Arguments'

}

 

$SensorInformation =

@{e = {$_.systemvolume_total_size}

    l = 'Volume Size'

},

@{e = {$_.emet_telemetry_path}

    l = 'Telemetry Path'

},

@{e = {$_.os_environment_display_string}

    l = 'Operating System'

},

@{e = {$_.emet_version}

    l = 'Emet Version'

},             

@{e = {$_.emet_dump_flags}

    l = 'Emet Dump Flags'

},            

@{e = {$_.clock_delta}

    l = 'Clock Delta'

},               

@{e = {$_.supports_cblr}

    l = 'Supports CBLR'

},              

@{e = {$_.sensor_uptime}

    l = 'Sensor Uptime'

},                 

@{e = {$_.last_update}

    l = 'Last Update'

},                

@{e = {$_.physical_memory_size}

    l = 'Physical Memory Size'

} ,        

@{e = {$_.build_id}

    l = 'Build ID'

},          

@{e = {$_.uptime}

    l = 'Uptime'

},            

@{e = {$_.is_isolating}

    l = 'Isolated'

},              

@{e = {$_.event_log_flush_time}

    l = 'Event Log Flush Time'

},      

@{e = {$_.computer_dns_name}

    l = 'Computer DNS Name'

},        

@{e = {$_.emet_report_setting}

    l = 'Emet Report Setting'

},          

@{e = {$_.id}

    l = 'ID'

},          

@{e = {$_.emet_process_count}

    l = 'Emet Process Count'

},

@{e = {$_.emet_is_gpo}

    l = 'Emet is GPO'

},           

@{e = {$_.power_state}

    l = 'Power State'

},                   

@{e = {$_.network_isolation_enabled}

    l = 'Network Isolation Enabled'

},  

@{e = {$_.uninstalled}

    l = 'Uninstalled'

},        

@{e = {$_.systemvolume_free_size}

    l = 'System Free Size'

},

@{e = {$_.status}

    l = 'Status'

},

@{e = {$_.num_eventlog_bytes}

    l = 'Number Event Log Bytes'

},

@{e = {$_.sensor_health_message}

    l = 'Sensor Health'

},

@{e = {$_.build_version_string}

    l = 'Build Version String'

},      

@{e = {$_.computer_sid}

    l = 'Computer SID'

},         

@{e = {$_.next_checkin_time}

    l = 'Next Checkin Time'

},            

@{e = {$_.node_id}

    l = 'Node ID'

},            

@{e = {$_.cookie}

    l = 'Cookie'

},        

@{e = {$_.emet_exploit_action}

    l = 'Emet Exploit Action'

},    

@{e = {$_.computer_name}

    l = 'Computer Name'

},          

@{e = {$_.license_expiration}

    l = 'License Expiration'

},     

@{e = {$_.supports_isolation}

    l = 'Supports Isolation'

},         

@{e = {$_.parity_host_id}

    l = 'Parity Host ID'

},             

@{e = {$_.supports_2nd_gen_modloads}

    l = 'Supports 2nd Gen Modloads'

}, 

@{e = {$_.network_adapters}

    l = 'Network Adapters'

},    

@{e = {$_.sensor_health_status}

    l = 'Sensor Health Status'

},

@{e = {$_.registration_time}

    l = 'Registration Time'

},           

@{e = {$_.restart_queued}

    l = 'Restart Queued'

},            

@{e = {$_.notes}

    l = 'Notes'

},               

@{e = {$_.num_storefiles_bytes}

    l = 'Number Storefiles in Bytes'

},       

@{e = {$_.os_environment_id}

    l = 'OS Environment ID'

},   

@{e = {$_.shard_id}

    l = 'Shard ID'

},            

@{e = {$_.boot_id}

    l = 'Boot ID'

},                     

@{e = {$_.last_checkin_time}

    l = 'Last Checkin Time'

},           

@{e = {$_.os_type}

    l = 'OS Type'

},            

@{e = {$_.group_id}

    l = 'Group ID'

},                     

@{e = {$_.display}

    l = 'Display'

},                     

@{e = {$_.uninstall}

    l = 'Uninstall'

}
