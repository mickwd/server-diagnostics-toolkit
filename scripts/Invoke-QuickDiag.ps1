<#
.SYNOPSIS
    Diagnóstico rápido de un servidor Windows, sin dependencias (PowerShell 5.1+).

.DESCRIPTION
    Versión en PowerShell puro del toolkit sysdiag, pensada para servidores donde
    no hay Python instalado. Corre una batería de checks (disco, memoria, CPU,
    uptime, reinicio pendiente, servicios, DNS, puertos TCP, ping, certificados
    TLS, errores del Event Log y actualizaciones pendientes) y devuelve un JSON
    listo para adjuntar a un ticket.

    El exit code refleja el peor estado: 0 OK, 1 WARN, 2 CRIT, 3 ERROR.

.PARAMETER OutFile
    Ruta donde guardar el JSON. Si se omite, se escribe por stdout.

.PARAMETER SkipUpdates
    Omite la consulta a Windows Update (puede tardar varios minutos).

.EXAMPLE
    .\Invoke-QuickDiag.ps1 -OutFile C:\Temp\diag.json

.EXAMPLE
    .\Invoke-QuickDiag.ps1 -TcpTargets 'sql01:1433','dc01:389' -Services 'MSSQLSERVER','W3SVC' -SkipUpdates
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '',
    Justification = 'Los parámetros se usan dentro de los scriptblocks que recibe Invoke-Check.')]
[CmdletBinding()]
param(
    [string[]]$DnsNames = @('google.com', 'github.com'),
    [string[]]$TcpTargets = @('github.com:443', '1.1.1.1:53'),
    [string[]]$PingHosts = @('8.8.8.8', '1.1.1.1'),
    [string[]]$CertHosts = @('github.com', 'www.google.com'),
    [string[]]$Services = @('EventLog', 'Dnscache', 'W32Time', 'LanmanServer'),
    [ValidateRange(1, 100)][int]$DiskWarnPct = 80,
    [ValidateRange(1, 100)][int]$DiskCritPct = 90,
    [ValidateRange(1, 100)][int]$MemoryWarnPct = 85,
    [ValidateRange(1, 100)][int]$MemoryCritPct = 95,
    [int]$CertWarnDays = 30,
    [int]$CertCritDays = 7,
    [ValidateRange(1, 720)][int]$EventHours = 24,
    [int]$TimeoutMs = 3000,
    [switch]$SkipUpdates,
    [string]$OutFile
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:Severity = @{ OK = 0; WARN = 1; ERROR = 2; CRIT = 3 }
$script:ExitCodes = @{ OK = 0; WARN = 1; CRIT = 2; ERROR = 3 }

function Get-WorstStatus {
    param([string[]]$Status)
    $worst = 'OK'
    foreach ($item in $Status) {
        if ($script:Severity[$item] -gt $script:Severity[$worst]) { $worst = $item }
    }
    return $worst
}

function Get-ThresholdStatus {
    param([double]$Value, [double]$Warn, [double]$Crit, [switch]$LowerIsWorse)
    if ($LowerIsWorse) {
        if ($Value -le $Crit) { return 'CRIT' }
        if ($Value -le $Warn) { return 'WARN' }
        return 'OK'
    }
    if ($Value -ge $Crit) { return 'CRIT' }
    if ($Value -ge $Warn) { return 'WARN' }
    return 'OK'
}

function Invoke-Check {
    <# Ejecuta un check midiendo la duración; si tira una excepción el resultado es ERROR. #>
    param([string]$Name, [string]$Category, [scriptblock]$Body)
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $result = & $Body
    }
    catch {
        $result = @{ Status = 'ERROR'; Message = $_.Exception.Message; Details = @{} }
    }
    $watch.Stop()
    return [ordered]@{
        name        = $Name
        category    = $Category
        status      = $result.Status
        message     = $result.Message
        details     = $result.Details
        duration_ms = [math]::Round($watch.Elapsed.TotalMilliseconds, 1)
    }
}

function Split-Target {
    param([string]$Target, [int]$DefaultPort = 0)
    $parts = $Target.Split(':')
    if ($parts.Count -eq 2) { return @($parts[0], [int]$parts[1]) }
    if ($DefaultPort -gt 0) { return @($Target, $DefaultPort) }
    throw "Target sin puerto: $Target"
}

# --- Checks de sistema -------------------------------------------------------

function Test-Disk {
    param([int]$WarnPct, [int]$CritPct)
    $items = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
            $pct = if ($_.Size) { [math]::Round(100 * ($_.Size - $_.FreeSpace) / $_.Size, 1) } else { 0 }
            [ordered]@{
                mountpoint = $_.DeviceID
                status     = Get-ThresholdStatus -Value $pct -Warn $WarnPct -Crit $CritPct
                percent    = $pct
                free_gib   = [math]::Round($_.FreeSpace / 1GB, 1)
                total_gib  = [math]::Round($_.Size / 1GB, 1)
            }
        })
    if ($items.Count -eq 0) { return @{ Status = 'ERROR'; Message = 'No se encontraron discos fijos'; Details = @{} } }
    $fullest = $items | Sort-Object { $_.percent } -Descending | Select-Object -First 1
    return @{
        Status  = Get-WorstStatus ($items | ForEach-Object { $_.status })
        Message = "$($fullest.mountpoint) al $($fullest.percent)% ($($fullest.free_gib) GiB libres)"
        Details = @{ items = $items }
    }
}

function Test-Memory {
    param([int]$WarnPct, [int]$CritPct)
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $pct = [math]::Round(100 * ($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / $os.TotalVisibleMemorySize, 1)
    return @{
        Status  = Get-ThresholdStatus -Value $pct -Warn $WarnPct -Crit $CritPct
        Message = "Memoria al $pct%"
        Details = @{
            percent       = $pct
            total_gib     = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
            available_gib = [math]::Round($os.FreePhysicalMemory / 1MB, 1)
        }
    }
}

function Test-Cpu {
    $load = (Get-CimInstance -ClassName Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
    $load = [math]::Round([double]$load, 1)
    return @{
        Status  = Get-ThresholdStatus -Value $load -Warn 85 -Crit 95
        Message = "CPU al $load%"
        Details = @{ percent = $load; cores = [Environment]::ProcessorCount }
    }
}

function Test-Uptime {
    $boot = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
    $span = (Get-Date) - $boot
    $human = '{0}d {1}h {2}m' -f $span.Days, $span.Hours, $span.Minutes
    $status = 'OK'
    $message = "Uptime $human"
    if ($span.TotalMinutes -lt 15) { $status = 'WARN'; $message = "Reinicio reciente: uptime $human" }
    elseif ($span.TotalDays -gt 90) { $status = 'WARN'; $message = "Sin reiniciar hace $human" }
    return @{ Status = $status; Message = $message; Details = @{ boot_time = $boot.ToString('o'); human = $human } }
}

function Test-PendingReboot {
    # Claves de registro que indican un reinicio pendiente (updates, CBS, renombres de archivos).
    $reasons = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
        $reasons += 'CBS'
    }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        $reasons += 'WindowsUpdate'
    }
    $session = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction SilentlyContinue
    if ($session -and ($session.PSObject.Properties.Name -contains 'PendingFileRenameOperations')) {
        $reasons += 'PendingFileRename'
    }
    if ($reasons.Count -gt 0) {
        return @{ Status = 'WARN'; Message = "Reinicio pendiente ($($reasons -join ', '))"; Details = @{ reasons = $reasons } }
    }
    return @{ Status = 'OK'; Message = 'Sin reinicio pendiente'; Details = @{ reasons = @() } }
}

function Test-ServiceState {
    param([string[]]$NameList)
    $items = @(foreach ($name in $NameList) {
            $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
            if (-not $svc) {
                [ordered]@{ service = $name; status = 'WARN'; state = 'no existe' }
            }
            else {
                $state = $svc.Status.ToString()
                [ordered]@{ service = $svc.Name; status = $(if ($state -eq 'Running') { 'OK' } else { 'CRIT' }); state = $state }
            }
        })
    $bad = @($items | Where-Object { $_.status -ne 'OK' } | ForEach-Object { "$($_.service) ($($_.state))" })
    $message = if ($bad.Count) { "Servicios con problemas: $($bad -join ', ')" } else { "$($items.Count) servicios corriendo" }
    return @{ Status = Get-WorstStatus ($items | ForEach-Object { $_.status }); Message = $message; Details = @{ items = $items } }
}

# --- Checks de red -------------------------------------------------------------

function Test-DnsResolution {
    param([string[]]$NameList)
    $items = @(foreach ($name in $NameList) {
            $watch = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                $addresses = [System.Net.Dns]::GetHostAddresses($name) | ForEach-Object { $_.IPAddressToString }
                [ordered]@{ name = $name; status = 'OK'; addresses = @($addresses); ms = $watch.ElapsedMilliseconds }
            }
            catch {
                [ordered]@{ name = $name; status = 'CRIT'; addresses = @(); ms = $watch.ElapsedMilliseconds; error = $_.Exception.GetBaseException().Message }
            }
        })
    $failed = @($items | Where-Object { $_.status -ne 'OK' } | ForEach-Object { $_.name })
    $message = if ($failed.Count) { "No resuelven: $($failed -join ', ')" } else { "$($items.Count) nombres resueltos correctamente" }
    return @{ Status = Get-WorstStatus ($items | ForEach-Object { $_.status }); Message = $message; Details = @{ items = $items } }
}

function Test-TcpPort {
    param([string[]]$TargetList, [int]$TimeoutMs)
    $items = @(foreach ($target in $TargetList) {
            $hostName, $port = Split-Target -Target $target
            $client = New-Object System.Net.Sockets.TcpClient
            $watch = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                $task = $client.ConnectAsync($hostName, $port)
                if (-not $task.Wait($TimeoutMs)) {
                    [ordered]@{ target = $target; status = 'CRIT'; result = 'timeout (posible firewall)'; ms = $watch.ElapsedMilliseconds }
                }
                else {
                    [ordered]@{ target = $target; status = 'OK'; result = 'abierto'; ms = $watch.ElapsedMilliseconds }
                }
            }
            catch {
                $inner = $_.Exception.GetBaseException()
                $text = if ($inner -is [System.Net.Sockets.SocketException] -and $inner.SocketErrorCode -eq 'ConnectionRefused') {
                    'rechazado (servicio no escucha)'
                }
                else { $inner.Message }
                [ordered]@{ target = $target; status = 'CRIT'; result = $text; ms = $watch.ElapsedMilliseconds }
            }
            finally {
                $client.Dispose()
            }
        })
    $bad = @($items | Where-Object { $_.status -ne 'OK' } | ForEach-Object { "$($_.target) ($($_.result))" })
    $message = if ($bad.Count) { "Sin acceso: $($bad -join '; ')" } else { "$($items.Count) puertos accesibles" }
    return @{ Status = Get-WorstStatus ($items | ForEach-Object { $_.status }); Message = $message; Details = @{ items = $items } }
}

function Test-Ping {
    param([string[]]$HostList)
    $pinger = New-Object System.Net.NetworkInformation.Ping
    $items = @(foreach ($target in $HostList) {
            $times = @()
            $sent = 4
            for ($i = 0; $i -lt $sent; $i++) {
                try {
                    $reply = $pinger.Send($target, 1000)
                    if ($reply.Status -eq 'Success') { $times += $reply.RoundtripTime }
                }
                catch {
                    Write-Verbose "Ping a $target falló: $($_.Exception.Message)"
                }
            }
            $loss = [math]::Round(100 * ($sent - $times.Count) / $sent, 1)
            $avg = if ($times.Count) { [math]::Round(($times | Measure-Object -Average).Average, 1) } else { $null }
            $status = Get-ThresholdStatus -Value $loss -Warn 10 -Crit 50
            if ($null -ne $avg) { $status = Get-WorstStatus @($status, (Get-ThresholdStatus -Value $avg -Warn 100 -Crit 300)) }
            [ordered]@{ host = $target; status = $status; loss_pct = $loss; rtt_avg = $avg }
        })
    $pinger.Dispose()
    $parts = $items | ForEach-Object {
        if ($null -ne $_.rtt_avg) { "$($_.host) $($_.rtt_avg) ms/$($_.loss_pct)% loss" } else { "$($_.host) sin respuesta" }
    }
    return @{ Status = Get-WorstStatus ($items | ForEach-Object { $_.status }); Message = ($parts -join '; '); Details = @{ items = $items } }
}

function Test-TlsCertificate {
    param([string[]]$HostList, [int]$WarnDays, [int]$CritDays, [int]$TimeoutMs)
    $items = @(foreach ($target in $HostList) {
            $hostName, $port = Split-Target -Target $target -DefaultPort 443
            $client = New-Object System.Net.Sockets.TcpClient
            try {
                $task = $client.ConnectAsync($hostName, $port)
                if (-not $task.Wait($TimeoutMs)) { throw "timeout conectando a ${hostName}:$port" }
                $ssl = New-Object System.Net.Security.SslStream($client.GetStream(), $false)
                try {
                    # PowerShell 5.1 (.NET Framework) no negocia TLS 1.2 por defecto en todos los equipos.
                    $protocols = [System.Security.Authentication.SslProtocols]::Tls12
                    $ssl.AuthenticateAsClient($hostName, $null, $protocols, $false)
                    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
                    $days = [math]::Round(($cert.NotAfter.ToUniversalTime() - (Get-Date).ToUniversalTime()).TotalDays, 1)
                    [ordered]@{
                        host      = $target
                        status    = Get-ThresholdStatus -Value $days -Warn $WarnDays -Crit $CritDays -LowerIsWorse
                        days_left = $days
                        expires   = $cert.NotAfter.ToString('yyyy-MM-dd')
                        issuer    = $cert.GetNameInfo('SimpleName', $true)
                    }
                }
                catch [System.Security.Authentication.AuthenticationException] {
                    # Vencido, autofirmado o el nombre no coincide.
                    [ordered]@{ host = $target; status = 'CRIT'; days_left = $null; error = $_.Exception.GetBaseException().Message }
                }
                finally {
                    $ssl.Dispose()
                }
            }
            catch {
                [ordered]@{ host = $target; status = 'ERROR'; days_left = $null; error = $_.Exception.GetBaseException().Message }
            }
            finally {
                $client.Dispose()
            }
        })
    $bad = @($items | Where-Object { $_.status -ne 'OK' } | ForEach-Object {
            if ($_.Contains('error')) { "$($_.host) ($($_.error))" } else { "$($_.host) vence en $($_.days_left) días" }
        })
    $message = if ($bad.Count) { $bad -join '; ' } else { "$($items.Count) certificados vigentes" }
    return @{ Status = Get-WorstStatus ($items | ForEach-Object { $_.status }); Message = $message; Details = @{ items = $items } }
}

# --- Eventos y actualizaciones -----------------------------------------------

function Test-RecentError {
    param([int]$Hours)
    $filter = @{ LogName = @('System', 'Application'); Level = 1, 2; StartTime = (Get-Date).AddHours(-$Hours) }
    try {
        $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 200 -ErrorAction Stop)
    }
    catch {
        # "No se encontraron eventos" no es un error; cualquier otra cosa (ej. EventLog detenido) sí.
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
        $events = @()
    }
    if ($events.Count -eq 0) {
        return @{ Status = 'OK'; Message = "Sin errores en las últimas $Hours h"; Details = @{ total = 0 } }
    }
    $top = @($events | Group-Object -Property ProviderName | Sort-Object Count -Descending | Select-Object -First 10 |
            ForEach-Object { [ordered]@{ source = $_.Name; count = $_.Count } })
    $latest = @($events | Select-Object -First 20 | ForEach-Object {
            $msg = if ($_.Message) { ($_.Message -replace '\s+', ' ') } else { '' }
            if ($msg.Length -gt 300) { $msg = $msg.Substring(0, 297) + '...' }
            [ordered]@{
                timestamp = $_.TimeCreated.ToUniversalTime().ToString('o')
                level     = $(if ($_.Level -eq 1) { 'critical' } else { 'error' })
                source    = $_.ProviderName
                event_id  = $_.Id
                log       = $_.LogName
                message   = $msg
            }
        })
    return @{
        Status  = Get-ThresholdStatus -Value $events.Count -Warn 1 -Crit 25
        Message = "$($events.Count) errores en las últimas $Hours h (más frecuente: $($top[0].source) x$($top[0].count))"
        Details = @{ total = $events.Count; top_sources = $top; items = $latest }
    }
}

function Test-PendingUpdate {
    $session = New-Object -ComObject Microsoft.Update.Session
    $result = $session.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
    $items = @(foreach ($update in $result.Updates) {
            $categories = @($update.Categories | ForEach-Object { $_.Name }) -join ', '
            [ordered]@{
                name     = $update.Title
                kb       = (@($update.KBArticleIDs) | ForEach-Object { "KB$_" }) -join ','
                security = [bool]($update.MsrcSeverity -or $categories -match 'Security|seguridad')
            }
        })
    $security = @($items | Where-Object { $_.security }).Count
    $status = if ($security -gt 0) { 'CRIT' } elseif ($items.Count -gt 0) { 'WARN' } else { 'OK' }
    $message = if ($items.Count) { "$($items.Count) actualizaciones pendientes ($security de seguridad)" } else { 'Sistema al día' }
    return @{ Status = $status; Message = $message; Details = @{ pending = $items.Count; security = $security; items = $items } }
}

# --- Ejecución -----------------------------------------------------------------

$started = Get-Date
$results = @(
    Invoke-Check -Name 'dns' -Category 'network' -Body { Test-DnsResolution -NameList $DnsNames }
    Invoke-Check -Name 'tcp_ports' -Category 'network' -Body { Test-TcpPort -TargetList $TcpTargets -TimeoutMs $TimeoutMs }
    Invoke-Check -Name 'ping' -Category 'network' -Body { Test-Ping -HostList $PingHosts }
    Invoke-Check -Name 'tls_certs' -Category 'tls' -Body { Test-TlsCertificate -HostList $CertHosts -WarnDays $CertWarnDays -CritDays $CertCritDays -TimeoutMs $TimeoutMs }
    Invoke-Check -Name 'disk' -Category 'system' -Body { Test-Disk -WarnPct $DiskWarnPct -CritPct $DiskCritPct }
    Invoke-Check -Name 'memory' -Category 'system' -Body { Test-Memory -WarnPct $MemoryWarnPct -CritPct $MemoryCritPct }
    Invoke-Check -Name 'cpu' -Category 'system' -Body { Test-Cpu }
    Invoke-Check -Name 'uptime' -Category 'system' -Body { Test-Uptime }
    Invoke-Check -Name 'pending_reboot' -Category 'system' -Body { Test-PendingReboot }
    Invoke-Check -Name 'services' -Category 'services' -Body { Test-ServiceState -NameList $Services }
    Invoke-Check -Name 'recent_errors' -Category 'events' -Body { Test-RecentError -Hours $EventHours }
)
if (-not $SkipUpdates) {
    $results += Invoke-Check -Name 'updates' -Category 'updates' -Body { Test-PendingUpdate }
}

$overall = Get-WorstStatus ($results | ForEach-Object { $_.status })
$summary = [ordered]@{}
foreach ($status in 'OK', 'WARN', 'CRIT', 'ERROR') {
    $summary[$status] = @($results | Where-Object { $_.status -eq $status }).Count
}
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem

$report = [ordered]@{
    generated_at   = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
    host           = [ordered]@{
        hostname = $env:COMPUTERNAME
        os       = "$($osInfo.Caption) $($osInfo.Version)"
        mode     = 'powershell'
    }
    overall_status = $overall
    exit_code      = $script:ExitCodes[$overall]
    summary        = $summary
    duration_ms    = [math]::Round(((Get-Date) - $started).TotalMilliseconds, 1)
    results        = $results
}

$json = $report | ConvertTo-Json -Depth 8
if ($OutFile) {
    # UTF-8 sin BOM para que otras herramientas (jq, Python) lo lean sin problemas.
    [System.IO.File]::WriteAllText($OutFile, $json, (New-Object System.Text.UTF8Encoding($false)))
    Write-Verbose "Reporte guardado en $OutFile"
}
else {
    Write-Output $json
}
exit $script:ExitCodes[$overall]
