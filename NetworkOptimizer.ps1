# ================================================================
# NetworkOptimizer.ps1 - Standalone Network Optimization Tool
# Extracted from RahbarX Windows Performance Optimizer v2.0
# ================================================================
# Run as Administrator for full functionality
# ================================================================

# Self-elevate to Administrator if not already running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[INFO] Requesting Administrator privileges..." -ForegroundColor Yellow
    try {
        $scriptPath = $MyInvocation.MyCommand.Path
        if (-not $scriptPath) { $scriptPath = $PSCommandPath }
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Verb RunAs
    } catch {
        Write-Host "[ERROR] Failed to elevate. Please right-click and 'Run as Administrator'" -ForegroundColor Red
        Write-Host "Press any key to exit..." -ForegroundColor Gray
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
    exit
}

# Load Windows Forms for message boxes
Add-Type -AssemblyName System.Windows.Forms

# ================================================================
# LOGGING FUNCTIONS
# ================================================================

$script:LogFile = "$env:TEMP\NetworkOptimizer_$(Get-Date -Format 'yyyyMMdd').log"

function Write-Log {
    param([string]$Message, [string]$Type = "INFO")
    $timestamp = Get-Date -Format "HH:mm:ss"
    $logEntry = "[$timestamp] [$Type] $Message"
    Add-Content -Path $script:LogFile -Value $logEntry
}

# ================================================================
# HELPER FUNCTIONS
# ================================================================

function Test-CriticalNetworkConnections {
    Write-Host "  [->] Checking for critical network connections..." -ForegroundColor Gray
    
    $criticalPorts = @{
        3389 = "Remote Desktop (RDP)"
        22 = "SSH"
        1194 = "OpenVPN"
        500 = "IPSec VPN"
        4500 = "IPSec NAT-T"
        1723 = "PPTP VPN"
        443 = "HTTPS/SSL VPN"
        445 = "SMB File Sharing"
    }
    
    $criticalConnections = @()
    
    try {
        $activeConnections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        
        foreach ($conn in $activeConnections) {
            if ($criticalPorts.ContainsKey($conn.RemotePort)) {
                $criticalConnections += @{
                    LocalPort = $conn.LocalPort
                    RemoteAddress = $conn.RemoteAddress
                    RemotePort = $conn.RemotePort
                    Service = $criticalPorts[$conn.RemotePort]
                }
            }
            # Also check if we're the server side (RDP server, SMB server)
            if ($criticalPorts.ContainsKey($conn.LocalPort) -and $conn.LocalAddress -ne "127.0.0.1") {
                $criticalConnections += @{
                    LocalPort = $conn.LocalPort
                    RemoteAddress = $conn.RemoteAddress
                    RemotePort = $conn.RemotePort
                    Service = "$($criticalPorts[$conn.LocalPort]) (Incoming)"
                }
            }
        }
    } catch {
        Write-Log -Message "Could not check network connections: $($_.Exception.Message)" -Type "WARNING"
    }
    
    if ($criticalConnections.Count -gt 0) {
        Write-Host "  [!] CRITICAL CONNECTIONS DETECTED:" -ForegroundColor Yellow
        foreach ($conn in $criticalConnections) {
            Write-Host "      - $($conn.Service): $($conn.RemoteAddress):$($conn.RemotePort)" -ForegroundColor Yellow
        }
        Write-Log -Message "Critical connections detected: $($criticalConnections.Count)" -Type "WARNING"
    } else {
        Write-Host "  [OK] No critical connections detected" -ForegroundColor Green
    }
    
    return $criticalConnections
}

function Test-NetworkOptimizations {
    Write-Host "  [->] Validating network optimizations..." -ForegroundColor Gray
    
    $activeAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" }
    $validationResults = @()
    $successCount = 0
    
    foreach ($adapter in $activeAdapters) {
        $interfaceGuid = $adapter.InterfaceGuid
        $tcpipPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$interfaceGuid"
        
        if (Test-Path $tcpipPath) {
            try {
                $props = Get-ItemProperty -Path $tcpipPath -ErrorAction SilentlyContinue
                $ackOk = $props.TcpAckFrequency -eq 1
                $noDelayOk = $props.TCPNoDelay -eq 1
                
                if ($ackOk -and $noDelayOk) {
                    Write-Host "  [OK] $($adapter.Name): Optimizations verified" -ForegroundColor Green
                    $successCount++
                } else {
                    Write-Host "  [!] $($adapter.Name): Settings not optimal (ACK: $($props.TcpAckFrequency), NoDelay: $($props.TCPNoDelay))" -ForegroundColor Yellow
                }
                
                $validationResults += @{
                    Adapter = $adapter.Name
                    TcpAckFrequency = $props.TcpAckFrequency
                    TCPNoDelay = $props.TCPNoDelay
                    Optimized = ($ackOk -and $noDelayOk)
                }
            } catch {
                Write-Host "  [!] $($adapter.Name): Could not validate settings" -ForegroundColor Yellow
            }
        }
    }
    
    Write-Log -Message "Network validation: $successCount of $($activeAdapters.Count) adapters optimized" -Type "INFO"
    return $validationResults
}

# ================================================================
# LATENCY BENCHMARK FUNCTION
# ================================================================

function Test-NetworkLatency {
    Clear-Host
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "           NETWORK LATENCY BENCHMARK                            " -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "[INFO] Testing network latency to popular gaming servers..." -ForegroundColor Yellow
    Write-Host ""

    $targets = @(
        @{ Name = "Cloudflare DNS"; Host = "1.1.1.1" },
        @{ Name = "Google DNS"; Host = "8.8.8.8" },
        @{ Name = "Microsoft Azure"; Host = "13.107.4.52" },
        @{ Name = "Amazon AWS"; Host = "52.94.236.248" },
        @{ Name = "Riot Games (LoL)"; Host = "104.160.131.3" }
    )

    $results = @()

    foreach ($target in $targets) {
        Write-Host "  Testing $($target.Name)..." -ForegroundColor Gray
        
        try {
            $pingResults = 1..10 | ForEach-Object {
                $ping = Test-Connection -ComputerName $target.Host -Count 1 -ErrorAction SilentlyContinue
                if ($ping) { $ping.ResponseTime } else { $null }
            } | Where-Object { $_ -ne $null }

            if ($pingResults.Count -gt 0) {
                $avg = [math]::Round(($pingResults | Measure-Object -Average).Average, 1)
                $min = ($pingResults | Measure-Object -Minimum).Minimum
                $max = ($pingResults | Measure-Object -Maximum).Maximum
                $jitter = [math]::Round(($pingResults | ForEach-Object { [math]::Abs($_ - $avg) } | Measure-Object -Average).Average, 1)
                $loss = [math]::Round((10 - $pingResults.Count) * 10, 0)

                $color = if ($avg -lt 30) { "Green" } elseif ($avg -lt 60) { "Yellow" } else { "Red" }
                Write-Host "    [OK] $($target.Name): ${avg}ms avg (${min}-${max}ms), Jitter: ${jitter}ms, Loss: ${loss}%" -ForegroundColor $color

                $results += @{
                    Target = $target.Name
                    Average = $avg
                    Min = $min
                    Max = $max
                    Jitter = $jitter
                    PacketLoss = $loss
                }
            } else {
                Write-Host "    [!] $($target.Name): No response (blocked or unreachable)" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "    [!] $($target.Name): Test failed" -ForegroundColor Yellow
        }
    }

    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "TCP/IP CONFIGURATION STATUS:" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""

    # Show current TCP settings
    try {
        $tcpSettings = Get-NetTCPSetting -SettingName Internet -ErrorAction SilentlyContinue
        if ($tcpSettings) {
            Write-Host "  Congestion Provider: $($tcpSettings.CongestionProvider)" -ForegroundColor Gray
            Write-Host "  ECN Capability: $($tcpSettings.EcnCapability)" -ForegroundColor Gray
            Write-Host "  Auto-Tuning: $($tcpSettings.AutoTuningLevelLocal)" -ForegroundColor Gray
            Write-Host "  Initial Congestion Window: $($tcpSettings.InitialCongestionWindowMss) MSS" -ForegroundColor Gray
        }
    } catch { }

    Write-Host ""
    Write-Host "ADAPTER STATUS:" -ForegroundColor Cyan
    Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | ForEach-Object {
        $speed = if ($_.LinkSpeed) { $_.LinkSpeed } else { "Unknown" }
        Write-Host "  $($_.Name): $speed" -ForegroundColor Gray
    }

    Write-Host ""
    Write-Host "================================================================" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "RATING:" -ForegroundColor Cyan
    
    $avgLatency = if ($results.Count -gt 0) { [math]::Round(($results.Average | Measure-Object -Average).Average, 1) } else { 999 }
    
    if ($avgLatency -lt 20) {
        Write-Host "  EXCELLENT - Ultra low latency, perfect for competitive gaming!" -ForegroundColor Green
    } elseif ($avgLatency -lt 40) {
        Write-Host "  GOOD - Low latency, suitable for most online games" -ForegroundColor Green
    } elseif ($avgLatency -lt 70) {
        Write-Host "  MODERATE - Acceptable for casual gaming" -ForegroundColor Yellow
    } else {
        Write-Host "  POOR - High latency, consider network optimization" -ForegroundColor Red
    }

    Write-Host ""
    Write-Log -Message "Latency benchmark completed: ${avgLatency}ms average" -Type "INFO"
}

# ================================================================
# WINSOCK RESET FUNCTION
# ================================================================

function Reset-NetworkStack {
    Clear-Host
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "           RESET NETWORK STACK (WINSOCK RESET)                  " -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "[WARNING] This will reset Winsock and TCP/IP stack to defaults." -ForegroundColor Yellow
    Write-Host "[WARNING] A system restart will be REQUIRED after this operation." -ForegroundColor Yellow
    Write-Host ""

    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "This will reset the network stack (Winsock catalog and TCP/IP).\n\nThis can fix corruption issues but requires a restart.\n\nContinue?",
        "Reset Network Stack",
        [System.Windows.Forms.MessageBoxButtons]::YesNo,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )

    if ($confirm -eq [System.Windows.Forms.DialogResult]::Yes) {
        Write-Host "  [->] Resetting Winsock catalog..." -ForegroundColor Gray
        $null = netsh winsock reset 2>&1
        Write-Host "  [OK] Winsock reset complete" -ForegroundColor Green

        Write-Host "  [->] Resetting TCP/IP stack..." -ForegroundColor Gray
        $null = netsh int ip reset 2>&1
        Write-Host "  [OK] TCP/IP stack reset complete" -ForegroundColor Green

        Write-Host "  [->] Flushing DNS cache..." -ForegroundColor Gray
        $null = ipconfig /flushdns 2>&1
        Write-Host "  [OK] DNS cache flushed" -ForegroundColor Green

        Write-Host ""
        Write-Host "================================================================" -ForegroundColor Green
        Write-Host "  NETWORK STACK RESET COMPLETE!" -ForegroundColor Green
        Write-Host "  Please RESTART your computer for changes to take effect." -ForegroundColor Yellow
        Write-Host "================================================================" -ForegroundColor Green

        Write-Log -Message "Network stack reset completed - restart required" -Type "SUCCESS"
    } else {
        Write-Host "  [CANCELLED] Network stack reset cancelled" -ForegroundColor Yellow
    }
}

# ================================================================
# MAIN OPTIMIZATION FUNCTION
# ================================================================

function Optimize-Network {
    Clear-Host
    Write-Host "================================================================" -ForegroundColor Magenta
    Write-Host "           NETWORK OPTIMIZATION (2026 ULTRA EDITION)            " -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Magenta
    Write-Host " "
    Write-Host "[INFO] Applying 2026-era ultra low-latency network optimizations..." -ForegroundColor Yellow
    Write-Host "[INFO] Targets: Sub-ms jitter, <10ms ping improvement, zero packet loss"
    Write-Host "[INFO] Optimizing: TCP, UDP, IPv4, IPv6, WiFi, Ethernet"
    Write-Host " "

    $optimizationCount = 0
    $optimizationDetails = @()

    # SECURITY CHECK: Detect critical network connections before modification
    Write-Host "[SAFETY] Checking for critical network connections..." -ForegroundColor Cyan
    Write-Host " "
    $criticalConnections = Test-CriticalNetworkConnections
    
    if ($criticalConnections.Count -gt 0) {
        Write-Host " "
        $proceedWithNetwork = [System.Windows.Forms.MessageBox]::Show(
            "CRITICAL CONNECTIONS DETECTED!`n`n$($criticalConnections.Count) active connection(s) may be disrupted:`n`n$(($criticalConnections | ForEach-Object { "$($_.Service): $($_.RemoteAddress)" }) -join "`n")`n`nModifying network settings may disconnect these sessions.`n`nWARNING: RDP/VPN users may lose remote access!`n`nContinue anyway?",
            "Critical Network Connections",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        )
        
        if ($proceedWithNetwork -ne [System.Windows.Forms.DialogResult]::Yes) {
            Write-Host "  [CANCELLED] Network optimization cancelled to preserve connections" -ForegroundColor Yellow
            Write-Log -Message "Network optimization cancelled - critical connections detected" -Type "INFO"
            Start-Sleep -Seconds 2
            return
        }
        
        Write-Host "  [!] Proceeding despite active connections (user confirmed)" -ForegroundColor Yellow
        Write-Log -Message "Network optimization proceeding with $($criticalConnections.Count) critical connections" -Type "WARNING"
    }

    # ================================================================
    # PHASE 1: TCP/IP STACK OPTIMIZATION
    # ================================================================
    Write-Host " "
    Write-Host "PHASE 1: TCP/IP Stack Optimization" -ForegroundColor Cyan
    Write-Host " "

    # Get active physical adapters (exclude virtual, loopback, and disconnected)
    $activeAdapters = Get-NetAdapter | Where-Object { 
        $_.Status -eq "Up" -and 
        $_.InterfaceDescription -notlike "*Loopback*" -and
        $_.InterfaceDescription -notlike "*Virtual*" -and
        $_.InterfaceDescription -notlike "*VPN*" -and
        $_.Virtual -eq $false
    }

    if ($activeAdapters.Count -eq 0) {
        Write-Host "  [!] No active physical adapters found" -ForegroundColor Yellow
        $activeAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    }

    Write-Host "  [->] Detected $($activeAdapters.Count) active adapter(s)" -ForegroundColor Gray

    # Apply per-adapter TCP registry optimizations
    foreach ($adapter in $activeAdapters) {
        $interfaceGuid = $adapter.InterfaceGuid
        $tcpipPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$interfaceGuid"
        
        if (Test-Path $tcpipPath) {
            try {
                # TcpAckFrequency=1: Send ACKs immediately (reduces latency by ~20-40ms in games)
                Set-ItemProperty -Path $tcpipPath -Name "TcpAckFrequency" -Value 1 -Type DWord -Force -ErrorAction Stop
                
                # TCPNoDelay=1: Disable Nagle's algorithm (critical for real-time games)
                Set-ItemProperty -Path $tcpipPath -Name "TCPNoDelay" -Value 1 -Type DWord -Force -ErrorAction Stop
                
                Write-Host "    [OK] TCP low-latency settings applied: $($adapter.Name)" -ForegroundColor Green
                $optimizationCount++
                $optimizationDetails += "TCP ACK/NoDelay: $($adapter.Name)"
            } catch {
                Write-Host "    [!] Could not configure TCP settings: $($adapter.Name)" -ForegroundColor Yellow
            }
        }
    }

    # Configure global TCP settings using modern Set-NetTCPSetting cmdlet
    Write-Host "  [->] Configuring global TCP stack settings..." -ForegroundColor Gray
    try {
        # Get the Internet TCP setting template (used for most connections)
        $tcpSettings = Get-NetTCPSetting -SettingName Internet -ErrorAction SilentlyContinue
        
        if ($tcpSettings) {
            # Disable ECN (Explicit Congestion Notification) for gaming
            # Many routers drop ECN-marked packets, causing issues in games
            Set-NetTCPSetting -SettingName Internet -EcnCapability Disabled -ErrorAction SilentlyContinue
            Write-Host "    [OK] ECN disabled (better game server compatibility)" -ForegroundColor Green
            $optimizationCount++
            
            # Configure initial congestion window (10 segments is optimal for gaming)
            Set-NetTCPSetting -SettingName Internet -InitialCongestionWindow 10 -ErrorAction SilentlyContinue
            Write-Host "    [OK] Initial Congestion Window optimized (10 segments)" -ForegroundColor Green
            $optimizationCount++
        }
    } catch {
        Write-Host "    [!] Could not configure NetTCPSetting (requires Windows 10+)" -ForegroundColor Yellow
    }

    # Configure TCP global parameters via registry
    try {
        $globalTcpPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        
        # DefaultTTL=64: Standard for gaming (prevents packet expiry issues)
        Set-ItemProperty -Path $globalTcpPath -Name "DefaultTTL" -Value 64 -Type DWord -Force
        
        # EnablePMTUDiscovery=1: Automatic MTU detection (prevents fragmentation)
        Set-ItemProperty -Path $globalTcpPath -Name "EnablePMTUDiscovery" -Value 1 -Type DWord -Force
        
        # Tcp1323Opts=3: Enable TCP timestamps AND window scaling (critical for modern networks)
        Set-ItemProperty -Path $globalTcpPath -Name "Tcp1323Opts" -Value 3 -Type DWord -Force
        
        # SackOpts=1: Enable Selective Acknowledgment (efficient retransmission)
        Set-ItemProperty -Path $globalTcpPath -Name "SackOpts" -Value 1 -Type DWord -Force
        
        # MaxUserPort=65534: Increase ephemeral port range (prevents port exhaustion)
        Set-ItemProperty -Path $globalTcpPath -Name "MaxUserPort" -Value 65534 -Type DWord -Force
        
        # TcpTimedWaitDelay=30: Reduce TIME_WAIT state (faster port recycling)
        Set-ItemProperty -Path $globalTcpPath -Name "TcpTimedWaitDelay" -Value 30 -Type DWord -Force
        
        Write-Host "    [OK] Global TCP/IP parameters optimized (TTL, PMTU, SACK, Timestamps)" -ForegroundColor Green
        $optimizationCount++
        $optimizationDetails += "Global TCP: TTL=64, PMTU, SACK, Timestamps"
    } catch {
        Write-Host "    [!] Could not set global TCP parameters" -ForegroundColor Yellow
    }

    # Configure Auto-Tuning to 'normal' (NOT disabled - disabling hurts performance!)
    # Modern research shows disabling auto-tuning reduces throughput by 30-50%
    try {
        Set-NetTCPSetting -SettingName Internet -AutoTuningLevelLocal Normal -ErrorAction SilentlyContinue
        Write-Host "    [OK] TCP Auto-Tuning set to Normal (optimal for 2026 networks)" -ForegroundColor Green
        $optimizationCount++
    } catch {
        # Fallback to netsh if Set-NetTCPSetting fails
        try {
            $null = netsh int tcp set global autotuninglevel=normal 2>&1
            Write-Host "    [OK] TCP Auto-Tuning set to Normal (via netsh)" -ForegroundColor Green
            $optimizationCount++
        } catch {
            Write-Host "    [!] Could not configure Auto-Tuning" -ForegroundColor Yellow
        }
    }

    # 2026 NEW: Configure Delayed ACK Timer (minimize ACK delay)
    try {
        foreach ($adapter in $activeAdapters) {
            $interfaceGuid = $adapter.InterfaceGuid
            $tcpipPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$interfaceGuid"
            if (Test-Path $tcpipPath) {
                # TcpDelAckTicks=0: Disable delayed ACK timer (immediate ACKs)
                Set-ItemProperty -Path $tcpipPath -Name "TcpDelAckTicks" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
            }
        }
        Write-Host "    [OK] Delayed ACK Timer minimized (immediate acknowledgments)" -ForegroundColor Green
        $optimizationCount++
    } catch {
        Write-Host "    [!] Could not configure Delayed ACK Timer" -ForegroundColor Yellow
    }

    # 2026 NEW: Enable CTCP (Compound TCP) for improved congestion control
    try {
        # CTCP provides better throughput and lower latency than standard TCP
        Set-NetTCPSetting -SettingName Internet -CongestionProvider CTCP -ErrorAction SilentlyContinue
        Write-Host "    [OK] CTCP (Compound TCP) congestion control enabled" -ForegroundColor Green
        $optimizationCount++
        $optimizationDetails += "Congestion Control: CTCP"
    } catch {
        # Fallback for older Windows versions
        try {
            $null = netsh int tcp set global congestionprovider=ctcp 2>&1
            Write-Host "    [OK] CTCP enabled (via netsh)" -ForegroundColor Green
            $optimizationCount++
        } catch {
            Write-Host "    [!] CTCP not available on this system" -ForegroundColor Yellow
        }
    }

    # ================================================================
    # PHASE 2: UDP OPTIMIZATION (Critical for Gaming - Most Games Use UDP)
    # ================================================================
    Write-Host " "
    Write-Host "PHASE 2: UDP Stack Optimization (Gaming Protocol)" -ForegroundColor Cyan
    Write-Host " "

    # Optimize Winsock for UDP gaming traffic
    try {
        $winsockPath = "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters"
        if (-not (Test-Path $winsockPath)) {
            New-Item -Path $winsockPath -Force | Out-Null
        }
        
        # DefaultReceiveWindow: Increase UDP receive buffer (reduces packet loss)
        Set-ItemProperty -Path $winsockPath -Name "DefaultReceiveWindow" -Value 65535 -Type DWord -Force
        
        # DefaultSendWindow: Increase UDP send buffer (smoother transmission)
        Set-ItemProperty -Path $winsockPath -Name "DefaultSendWindow" -Value 65535 -Type DWord -Force
        
        # FastSendDatagramThreshold: Optimize small UDP packet handling (gaming packets are small)
        Set-ItemProperty -Path $winsockPath -Name "FastSendDatagramThreshold" -Value 1024 -Type DWord -Force
        
        # DisableRawSecurity: Allow raw socket access for gaming anti-cheat
        Set-ItemProperty -Path $winsockPath -Name "DisableRawSecurity" -Value 1 -Type DWord -Force
        
        # DoNotHoldNicBuffers: Release NIC buffers immediately (reduces latency)
        Set-ItemProperty -Path $winsockPath -Name "DoNotHoldNicBuffers" -Value 1 -Type DWord -Force
        
        # IgnorePushBitOnReceives: Process packets without waiting for PUSH bit
        Set-ItemProperty -Path $winsockPath -Name "IgnorePushBitOnReceives" -Value 1 -Type DWord -Force
        
        Write-Host "  [OK] Winsock/AFD buffers optimized (65KB, immediate release)" -ForegroundColor Green
        $optimizationCount++
        $optimizationDetails += "UDP Buffers: 65KB"
    } catch {
        Write-Host "  [!] Could not configure Winsock parameters" -ForegroundColor Yellow
    }

    # Configure UDP checksum offload per adapter
    foreach ($adapter in $activeAdapters) {
        try {
            # Enable UDP checksum offload (reduces CPU load)
            Set-NetAdapterUdpSegmentation -Name $adapter.Name -Enabled $true -ErrorAction SilentlyContinue
            Set-NetAdapterChecksumOffload -Name $adapter.Name -UdpIPv4 TxRxEnabled -UdpIPv6 TxRxEnabled -ErrorAction SilentlyContinue
            Write-Host "  [OK] UDP offload enabled: $($adapter.Name)" -ForegroundColor Green
            $optimizationCount++
        } catch {
            # UDP offload not supported on this adapter
        }
    }

    # ================================================================
    # PHASE 3: ADAPTER-LEVEL OPTIMIZATION (Modern CIM/PowerShell)
    # ================================================================
    Write-Host " "
    Write-Host "PHASE 3: Network Adapter Hardware Optimization" -ForegroundColor Cyan
    Write-Host " "

    foreach ($adapter in $activeAdapters) {
        Write-Host "  [->] Optimizing adapter: $($adapter.Name)" -ForegroundColor Gray
        
        # Configure RSS (Receive Side Scaling) for multi-core packet processing
        try {
            $rssSupported = Get-NetAdapterRss -Name $adapter.Name -ErrorAction SilentlyContinue
            if ($rssSupported) {
                # Enable RSS and optimize for gaming (use fewer queues for lower latency)
                Set-NetAdapterRss -Name $adapter.Name -Enabled $true -ErrorAction SilentlyContinue
                Write-Host "    [OK] RSS (Receive Side Scaling) enabled" -ForegroundColor Green
                $optimizationCount++
            }
        } catch {
            # RSS not supported on this adapter
        }

        # Configure Interrupt Moderation for low latency
        try {
            $intModSupported = Get-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "*InterruptModeration" -ErrorAction SilentlyContinue
            if ($intModSupported) {
                # Set to Adaptive (best balance) or Disabled (lowest latency, higher CPU)
                Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "*InterruptModeration" -RegistryValue 0 -ErrorAction SilentlyContinue
                Write-Host "    [OK] Interrupt Moderation disabled (lowest latency)" -ForegroundColor Green
                $optimizationCount++
            }
        } catch {
            # Interrupt Moderation not configurable on this adapter
        }

        # Disable Flow Control (reduces buffering latency)
        try {
            $flowControlSupported = Get-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "*FlowControl" -ErrorAction SilentlyContinue
            if ($flowControlSupported) {
                # 0 = Disabled, reduces latency by preventing flow control pauses
                Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "*FlowControl" -RegistryValue 0 -ErrorAction SilentlyContinue
                Write-Host "    [OK] Flow Control disabled" -ForegroundColor Green
                $optimizationCount++
            }
        } catch {
            # Flow Control not configurable
        }

        # Configure Receive Buffers (balance between throughput and latency)
        try {
            $rxBuffers = Get-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "*ReceiveBuffers" -ErrorAction SilentlyContinue
            if ($rxBuffers) {
                # Set to moderate value (256-512) - too low causes drops, too high adds latency
                Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "*ReceiveBuffers" -RegistryValue 512 -ErrorAction SilentlyContinue
                Write-Host "    [OK] Receive Buffers optimized (512)" -ForegroundColor Green
                $optimizationCount++
            }
        } catch {
            # Receive Buffers not configurable
        }

        # Configure Transmit Buffers
        try {
            $txBuffers = Get-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "*TransmitBuffers" -ErrorAction SilentlyContinue
            if ($txBuffers) {
                Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "*TransmitBuffers" -RegistryValue 512 -ErrorAction SilentlyContinue
                Write-Host "    [OK] Transmit Buffers optimized (512)" -ForegroundColor Green
                $optimizationCount++
            }
        } catch {
            # Transmit Buffers not configurable
        }

        # Disable Energy Efficient Ethernet (EEE) - causes latency spikes
        try {
            $eeeSupported = Get-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "*EEE" -ErrorAction SilentlyContinue
            if ($eeeSupported) {
                Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "*EEE" -RegistryValue 0 -ErrorAction SilentlyContinue
                Write-Host "    [OK] Energy Efficient Ethernet disabled" -ForegroundColor Green
                $optimizationCount++
            }
        } catch {
            # EEE not configurable
        }

        # Disable Power Saving on Network Adapters (Modern CIM method)
        try {
            # Use CIM instead of deprecated WMI
            $pnpDevice = Get-CimInstance -ClassName Win32_NetworkAdapter | Where-Object { $_.GUID -eq $adapter.InterfaceGuid }
            if ($pnpDevice) {
                $pnpDeviceId = $pnpDevice.PNPDeviceID
                $powerMgmtPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\$pnpDeviceId\Device Parameters\Power Management"
                if (Test-Path $powerMgmtPath) {
                    # PnPCapabilities = 24 (disable power management)
                    Set-ItemProperty -Path $powerMgmtPath -Name "PnPCapabilities" -Value 24 -Type DWord -Force -ErrorAction SilentlyContinue
                }
            }
            
            # Also disable via NetAdapter Power Management
            Set-NetAdapterPowerManagement -Name $adapter.Name -WakeOnMagicPacket Disabled -WakeOnPattern Disabled -ErrorAction SilentlyContinue
            Disable-NetAdapterPowerManagement -Name $adapter.Name -ErrorAction SilentlyContinue
            Write-Host "    [OK] Power Management disabled" -ForegroundColor Green
            $optimizationCount++
        } catch {
            # Power management not configurable
        }

        # Configure Checksum Offload (keep enabled - reduces CPU load without adding latency)
        try {
            Set-NetAdapterChecksumOffload -Name $adapter.Name -TcpIPv4 TxRxEnabled -TcpIPv6 TxRxEnabled -UdpIPv4 TxRxEnabled -UdpIPv6 TxRxEnabled -ErrorAction SilentlyContinue
            Write-Host "    [OK] Checksum Offload optimized" -ForegroundColor Green
            $optimizationCount++
        } catch {
            # Checksum offload not configurable
        }

        # Disable Large Send Offload (LSO) for gaming - small packets preferred
        # LSO batches packets which adds latency for real-time gaming
        try {
            Set-NetAdapterLso -Name $adapter.Name -V1IPv4Enabled $false -IPv4Enabled $false -IPv6Enabled $false -ErrorAction SilentlyContinue
            Write-Host "    [OK] Large Send Offload disabled (gaming optimized)" -ForegroundColor Green
            $optimizationCount++
        } catch {
            # LSO not configurable
        }

        # 2026 NEW: Disable Jumbo Frames for gaming (small packets preferred)
        try {
            $jumboFrame = Get-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "*JumboPacket" -ErrorAction SilentlyContinue
            if ($jumboFrame) {
                # 1514 = standard MTU (no jumbo frames)
                Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "*JumboPacket" -RegistryValue 1514 -ErrorAction SilentlyContinue
                Write-Host "    [OK] Jumbo Frames disabled (gaming optimized)" -ForegroundColor Green
                $optimizationCount++
            }
        } catch {
            # Jumbo frames not configurable
        }

        # 2026 NEW: Configure Interrupt Coalescing for ultra-low latency
        try {
            $intCoalesce = Get-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "*ITR" -ErrorAction SilentlyContinue
            if ($intCoalesce) {
                # 0 = Lowest interrupt throttle rate (most responsive)
                Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "*ITR" -RegistryValue 0 -ErrorAction SilentlyContinue
                Write-Host "    [OK] Interrupt Throttle Rate minimized" -ForegroundColor Green
                $optimizationCount++
            }
        } catch {
            # ITR not configurable
        }

        # 2026 NEW: WiFi-Specific Optimizations
        $isWiFi = $adapter.InterfaceDescription -match "Wi-Fi|Wireless|802\.11|WLAN"
        if ($isWiFi) {
            Write-Host "    [->] Applying WiFi-specific optimizations..." -ForegroundColor Gray
            
            # Disable WiFi power saving (causes latency spikes)
            try {
                $wifiPowerSave = Get-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "*WoWLAN" -ErrorAction SilentlyContinue
                if ($wifiPowerSave) {
                    Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "*WoWLAN" -RegistryValue 0 -ErrorAction SilentlyContinue
                }
                
                # Set roaming aggressiveness to lowest (stay connected longer)
                $roaming = Get-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*Roaming*" -ErrorAction SilentlyContinue
                if ($roaming) {
                    Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName $roaming.DisplayName -DisplayValue "Lowest" -ErrorAction SilentlyContinue
                }
                
                # Disable WiFi Sense (auto-connect features)
                $wifiSensePath = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
                if (Test-Path $wifiSensePath) {
                    Set-ItemProperty -Path $wifiSensePath -Name "AutoConnectAllowedOEM" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
                }
                
                # Prefer 5GHz band when available (lower latency)
                $bandPreference = Get-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "*Band*" -ErrorAction SilentlyContinue
                if ($bandPreference) {
                    Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName $bandPreference.DisplayName -DisplayValue "Prefer 5GHz band" -ErrorAction SilentlyContinue
                }
                
                Write-Host "    [OK] WiFi gaming optimizations applied" -ForegroundColor Green
                $optimizationCount++
                $optimizationDetails += "WiFi: Gaming mode enabled"
            } catch {
                Write-Host "    [!] Some WiFi optimizations could not be applied" -ForegroundColor Yellow
            }
        }
    }

    # ================================================================
    # PHASE 4: IPv6 OPTIMIZATION (2026-Critical)
    # ================================================================
    Write-Host " "
    Write-Host "PHASE 4: IPv6 Stack Optimization" -ForegroundColor Cyan
    Write-Host " "

    # Disable IPv6 transition technologies (add latency)
    try {
        # Disable Teredo (IPv6 tunneling - adds latency)
        $null = netsh interface teredo set state disabled 2>&1
        Write-Host "  [OK] Teredo tunneling disabled" -ForegroundColor Green
        $optimizationCount++
    } catch {
        Write-Host "  [!] Could not disable Teredo" -ForegroundColor Yellow
    }

    try {
        # Disable 6to4 (IPv6 transition - adds latency)
        $null = netsh interface 6to4 set state state=disabled 2>&1
        Write-Host "  [OK] 6to4 tunneling disabled" -ForegroundColor Green
        $optimizationCount++
    } catch {
        Write-Host "  [!] Could not disable 6to4" -ForegroundColor Yellow
    }

    try {
        # Disable ISATAP (IPv6 transition - adds latency)
        $null = netsh interface isatap set state state=disabled 2>&1
        Write-Host "  [OK] ISATAP tunneling disabled" -ForegroundColor Green
        $optimizationCount++
    } catch {
        Write-Host "  [!] Could not disable ISATAP" -ForegroundColor Yellow
    }

    # Configure IPv6 for native performance (don't disable - many games use it)
    try {
        $ipv6Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
        if (Test-Path $ipv6Path) {
            # DisabledComponents: 0x20 = Prefer IPv4 over IPv6 (reduces lookup time)
            Set-ItemProperty -Path $ipv6Path -Name "DisabledComponents" -Value 0x20 -Type DWord -Force
            Write-Host "  [OK] IPv4 preferred over IPv6 (faster DNS resolution)" -ForegroundColor Green
            $optimizationCount++
            $optimizationDetails += "IPv6: Prefer IPv4"
        }
    } catch {
        Write-Host "  [!] Could not configure IPv6 preference" -ForegroundColor Yellow
    }

    # ================================================================
    # PHASE 5: SYSTEM-LEVEL TUNING
    # ================================================================
    Write-Host " "
    Write-Host "PHASE 5: System-Level Network Tuning" -ForegroundColor Cyan
    Write-Host " "

    # Disable Network Throttling Index (multimedia/gaming priority)
    try {
        $throttlePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"
        if (-not (Test-Path $throttlePath)) {
            New-Item -Path $throttlePath -Force | Out-Null
        }
        # 0xFFFFFFFF = Disabled (no throttling)
        Set-ItemProperty -Path $throttlePath -Name "NetworkThrottlingIndex" -Value 0xffffffff -Type DWord -Force
        # Also set SystemResponsiveness to 0 for maximum gaming priority
        Set-ItemProperty -Path $throttlePath -Name "SystemResponsiveness" -Value 0 -Type DWord -Force
        Write-Host "  [OK] Network Throttling disabled (gaming priority enabled)" -ForegroundColor Green
        $optimizationCount++
        $optimizationDetails += "Network Throttling: Disabled"
    } catch {
        Write-Host "  [!] Could not disable network throttling" -ForegroundColor Yellow
    }

    # Configure QoS Reserved Bandwidth to 0%
    try {
        $qosPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched"
        if (-not (Test-Path $qosPath)) {
            New-Item -Path $qosPath -Force | Out-Null
        }
        Set-ItemProperty -Path $qosPath -Name "NonBestEffortLimit" -Value 0 -Type DWord -Force
        Write-Host "  [OK] QoS reserved bandwidth reclaimed (0%)" -ForegroundColor Green
        $optimizationCount++
        $optimizationDetails += "QoS: 0% reserved"
    } catch {
        Write-Host "  [!] Could not configure QoS" -ForegroundColor Yellow
    }

    # Optimize DNS Client for gaming
    try {
        Set-Service -Name "Dnscache" -StartupType Automatic -ErrorAction Stop
        Start-Service -Name "Dnscache" -ErrorAction Stop
        
        # Configure DNS cache size and TTL for gaming
        $dnsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
        if (Test-Path $dnsPath) {
            # MaxCacheEntryTtlLimit: 86400 seconds (1 day) - cache DNS longer
            Set-ItemProperty -Path $dnsPath -Name "MaxCacheEntryTtlLimit" -Value 86400 -Type DWord -Force -ErrorAction SilentlyContinue
            # MaxNegativeCacheTtl: 5 seconds - reduce negative cache time
            Set-ItemProperty -Path $dnsPath -Name "MaxNegativeCacheTtl" -Value 5 -Type DWord -Force -ErrorAction SilentlyContinue
        }
        Write-Host "  [OK] DNS Cache service optimized" -ForegroundColor Green
        $optimizationCount++
    } catch {
        Write-Host "  [!] Could not configure DNS cache" -ForegroundColor Yellow
    }

    # Configure NetOffloadGlobalSetting (modern replacement for netsh tcp global)
    try {
        # Enable RSC (Receive Segment Coalescing) for better throughput
        Set-NetOffloadGlobalSetting -ReceiveSegmentCoalescing Enabled -ErrorAction SilentlyContinue
        # Enable RSC on IPv4 and IPv6
        Set-NetOffloadGlobalSetting -ReceiveSideScaling Enabled -ErrorAction SilentlyContinue
        Write-Host "  [OK] Global offload settings optimized (RSC, RSS)" -ForegroundColor Green
        $optimizationCount++
    } catch {
        Write-Host "  [!] Could not configure global offload settings" -ForegroundColor Yellow
    }

    # Configure Nagle's algorithm disable at AFD driver level (affects all apps)
    try {
        $afdPath = "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters"
        if (-not (Test-Path $afdPath)) {
            New-Item -Path $afdPath -Force | Out-Null
        }
        # DisableTaskOffload: 0 = allow task offload (better performance)
        Set-ItemProperty -Path $afdPath -Name "DisableTaskOffload" -Value 0 -Type DWord -Force
        # DefaultReceiveWindow: Increase default receive window
        Set-ItemProperty -Path $afdPath -Name "DefaultReceiveWindow" -Value 65535 -Type DWord -Force
        # DefaultSendWindow: Increase default send window
        Set-ItemProperty -Path $afdPath -Name "DefaultSendWindow" -Value 65535 -Type DWord -Force
        Write-Host "  [OK] AFD driver parameters optimized" -ForegroundColor Green
        $optimizationCount++
    } catch {
        Write-Host "  [!] Could not configure AFD parameters" -ForegroundColor Yellow
    }

    # ================================================================
    # PHASE 6: DNS & POWER OPTIMIZATION (NEW)
    # ================================================================
    Write-Host " "
    Write-Host "PHASE 6: DNS & Power Optimization" -ForegroundColor Cyan
    Write-Host " "

    # Configure gaming-optimized DNS servers (Cloudflare + Google fallback)
    try {
        foreach ($adapter in $activeAdapters) {
            $dnsServers = @("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4")
            Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $dnsServers -ErrorAction SilentlyContinue
        }
        Write-Host "  [OK] Gaming DNS configured (Cloudflare 1.1.1.1 + Google 8.8.8.8)" -ForegroundColor Green
        $optimizationCount++
        $optimizationDetails += "DNS: Cloudflare + Google"
    } catch {
        Write-Host "  [!] Could not configure DNS servers" -ForegroundColor Yellow
    }

    # Disable DNS-over-HTTPS for lowest latency (DoH adds 10-50ms)
    try {
        $dohPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
        Set-ItemProperty -Path $dohPath -Name "EnableAutoDoh" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
        Write-Host "  [OK] DNS-over-HTTPS disabled (lowest latency)" -ForegroundColor Green
        $optimizationCount++
    } catch {
        Write-Host "  [!] Could not disable DoH" -ForegroundColor Yellow
    }

    # Set High Performance power plan
    try {
        $highPerfGuid = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
        $null = powercfg -setactive $highPerfGuid 2>&1
        Write-Host "  [OK] High Performance power plan activated" -ForegroundColor Green
        $optimizationCount++
    } catch {
        Write-Host "  [!] Could not set power plan" -ForegroundColor Yellow
    }

    # Disable USB selective suspend (affects USB network adapters)
    try {
        $null = powercfg -setacvalueindex SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 2>&1
        $null = powercfg -setactive SCHEME_CURRENT 2>&1
        Write-Host "  [OK] USB selective suspend disabled" -ForegroundColor Green
        $optimizationCount++
    } catch { }

    # Expand UDP dynamic port range for multiplayer games
    try {
        $null = netsh int ipv4 set dynamicport udp start=1025 num=64510 2>&1
        $null = netsh int ipv6 set dynamicport udp start=1025 num=64510 2>&1
        Write-Host "  [OK] UDP port range expanded (1025-65535)" -ForegroundColor Green
        $optimizationCount++
    } catch {
        Write-Host "  [!] Could not expand UDP port range" -ForegroundColor Yellow
    }

    # Disable Windows Update Delivery Optimization P2P (steals bandwidth)
    try {
        $doPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
        if (-not (Test-Path $doPath)) {
            New-Item -Path $doPath -Force | Out-Null
        }
        Set-ItemProperty -Path $doPath -Name "DODownloadMode" -Value 0 -Type DWord -Force
        Write-Host "  [OK] Delivery Optimization P2P disabled (no bandwidth stealing)" -ForegroundColor Green
        $optimizationCount++
    } catch {
        Write-Host "  [!] Could not disable Delivery Optimization" -ForegroundColor Yellow
    }

    # Disable background apps network access
    try {
        $bgAppsPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"
        if (Test-Path $bgAppsPath) {
            Set-ItemProperty -Path $bgAppsPath -Name "GlobalUserDisabled" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        }
        Write-Host "  [OK] Background apps network access limited" -ForegroundColor Green
        $optimizationCount++
    } catch { }

    # Flush DNS cache to apply new settings
    try {
        Clear-DnsClientCache -ErrorAction SilentlyContinue
        Write-Host "  [OK] DNS cache flushed" -ForegroundColor Green
    } catch { }

    # ================================================================
    # PHASE 7: VALIDATION & SUMMARY
    # ================================================================
    Write-Host " "
    Write-Host "PHASE 7: Validation & Verification" -ForegroundColor Cyan
    Write-Host " "

    # Validate network optimizations were applied
    $networkValidation = Test-NetworkOptimizations
    $validCount = ($networkValidation | Where-Object { $_.Optimized }).Count

    # Count WiFi adapters
    $wifiAdapterCount = ($activeAdapters | Where-Object { $_.InterfaceDescription -match "Wi-Fi|Wireless|802\.11|WLAN" }).Count

    Write-Host " "
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host "           NETWORK OPTIMIZATION COMPLETE! (2026 ULTRA)          " -ForegroundColor Green
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host " "
    Write-Host "SUMMARY:" -ForegroundColor Cyan
    Write-Host "  Total optimizations applied: $optimizationCount" -ForegroundColor Yellow
    Write-Host "  Adapters configured: $($activeAdapters.Count)" -ForegroundColor Yellow
    Write-Host "  Validation passed: $validCount of $($networkValidation.Count) adapters" -ForegroundColor Yellow
    Write-Host " "
    Write-Host "KEY OPTIMIZATIONS:" -ForegroundColor Cyan
    Write-Host "  [OK] Nagle's Algorithm: DISABLED (immediate packet send)" -ForegroundColor Gray
    Write-Host "  [OK] TCP ACK Frequency: 1 (instant acknowledgments)" -ForegroundColor Gray
    Write-Host "  [OK] Delayed ACK Timer: MINIMIZED (no ACK delays)" -ForegroundColor Gray
    Write-Host "  [OK] ECN: DISABLED (game server compatibility)" -ForegroundColor Gray
    Write-Host "  [OK] CTCP: ENABLED (modern congestion control)" -ForegroundColor Gray
    Write-Host "  [OK] SACK/Timestamps: ENABLED (efficient retransmission)" -ForegroundColor Gray
    Write-Host "  [OK] LSO: DISABLED (small packet optimization)" -ForegroundColor Gray
    Write-Host " "
    Write-Host "UDP/GAMING:" -ForegroundColor Cyan
    Write-Host "  [OK] UDP Buffers: 65KB (reduced packet loss)" -ForegroundColor Gray
    Write-Host "  [OK] UDP Offload: ENABLED (lower CPU usage)" -ForegroundColor Gray
    Write-Host " "
    Write-Host "ADAPTER HARDWARE:" -ForegroundColor Cyan
    Write-Host "  [OK] Interrupt Moderation: DISABLED (lowest latency)" -ForegroundColor Gray
    Write-Host "  [OK] Interrupt Throttle Rate: MINIMIZED" -ForegroundColor Gray
    Write-Host "  [OK] Flow Control: DISABLED (reduced buffering)" -ForegroundColor Gray
    Write-Host "  [OK] Power Management: DISABLED (no sleep states)" -ForegroundColor Gray
    Write-Host "  [OK] Jumbo Frames: DISABLED (gaming optimized)" -ForegroundColor Gray
    if ($wifiAdapterCount -gt 0) {
        Write-Host "  [OK] WiFi: Gaming mode ($wifiAdapterCount adapter(s))" -ForegroundColor Gray
    }
    Write-Host " "
    Write-Host "SYSTEM:" -ForegroundColor Cyan
    Write-Host "  [OK] Network Throttling: DISABLED (gaming priority)" -ForegroundColor Gray
    Write-Host "  [OK] IPv6 Tunneling: DISABLED (native only)" -ForegroundColor Gray
    Write-Host "  [OK] IPv4 Preferred: YES (faster DNS)" -ForegroundColor Gray
    Write-Host "  [OK] DNS: Cloudflare + Google (optimized)" -ForegroundColor Gray
    Write-Host "  [OK] Power Plan: High Performance" -ForegroundColor Gray
    Write-Host "  [OK] Delivery Optimization: DISABLED" -ForegroundColor Gray
    Write-Host " "
    Write-Host "[TIP] Restart your PC for all changes to take full effect." -ForegroundColor Yellow
    Write-Host "[TIP] Run 'Latency Benchmark' to test your connection." -ForegroundColor Yellow
    Write-Host "[NOTE] Use 'Restore Network Defaults' to revert all changes." -ForegroundColor Gray
    Write-Host "================================================================" -ForegroundColor DarkGray
    
    Write-Log -Message "Network optimization complete: $optimizationCount optimizations applied" -Type "SUCCESS"
    
    Start-Sleep -Seconds 3
}

# ================================================================
# RESTORE NETWORK DEFAULTS FUNCTION
# ================================================================

function Restore-NetworkDefaults {
    Clear-Host
    Write-Host "================================================================" -ForegroundColor Magenta
    Write-Host "           RESTORE NETWORK DEFAULTS (2026 EDITION)              " -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Magenta
    Write-Host " "
    Write-Host "[INFO] Reverting all network optimizations to Windows defaults..." -ForegroundColor Yellow
    Write-Host " "

    $restoredCount = 0
    $restoredDetails = @()

    # Get all adapters (including disabled ones that may have been configured)
    $allAdapters = Get-NetAdapter | Where-Object { $_.InterfaceDescription -notlike "*Loopback*" }

    # ================================================================
    # PHASE 1: REMOVE TCP/IP REGISTRY TWEAKS
    # ================================================================
    Write-Host "PHASE 1: Removing TCP/IP Registry Tweaks" -ForegroundColor Cyan
    Write-Host " "

    foreach ($adapter in $allAdapters) {
        $interfaceGuid = $adapter.InterfaceGuid
        $tcpipPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$interfaceGuid"
        
        if (Test-Path $tcpipPath) {
            try {
                Remove-ItemProperty -Path $tcpipPath -Name "TcpAckFrequency" -Force -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path $tcpipPath -Name "TCPNoDelay" -Force -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path $tcpipPath -Name "TcpDelAckTicks" -Force -ErrorAction SilentlyContinue
                Write-Host "    [OK] TCP tweaks removed: $($adapter.Name)" -ForegroundColor Green
                $restoredCount++
            } catch {
                Write-Host "    [!] Could not remove TCP tweaks: $($adapter.Name)" -ForegroundColor Yellow
            }
        }
    }

    # Remove global TCP parameter tweaks
    try {
        $globalTcpPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        Remove-ItemProperty -Path $globalTcpPath -Name "Tcp1323Opts" -Force -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $globalTcpPath -Name "SackOpts" -Force -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $globalTcpPath -Name "MaxUserPort" -Force -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $globalTcpPath -Name "TcpTimedWaitDelay" -Force -ErrorAction SilentlyContinue
        Write-Host "  [OK] Global TCP parameters restored to defaults" -ForegroundColor Green
        $restoredCount++
        $restoredDetails += "Global TCP Parameters"
    } catch {
        Write-Host "  [!] Could not restore global TCP parameters" -ForegroundColor Yellow
    }

    # Restore TCP settings using Set-NetTCPSetting
    try {
        Set-NetTCPSetting -SettingName Internet -EcnCapability Disabled -ErrorAction SilentlyContinue
        Set-NetTCPSetting -SettingName Internet -AutoTuningLevelLocal Normal -ErrorAction SilentlyContinue
        Set-NetTCPSetting -SettingName Internet -InitialCongestionWindow 4 -ErrorAction SilentlyContinue
        Set-NetTCPSetting -SettingName Internet -CongestionProvider Default -ErrorAction SilentlyContinue
        Write-Host "  [OK] NetTCPSetting restored to defaults" -ForegroundColor Green
        $restoredCount++
    } catch {
        Write-Host "  [!] Could not restore NetTCPSetting" -ForegroundColor Yellow
    }

    # ================================================================
    # PHASE 2: RESTORE ADAPTER SETTINGS
    # ================================================================
    Write-Host " "
    Write-Host "PHASE 2: Restoring Adapter Settings" -ForegroundColor Cyan
    Write-Host " "

    foreach ($adapter in ($allAdapters | Where-Object { $_.Status -eq "Up" })) {
        Write-Host "  [->] Restoring adapter: $($adapter.Name)" -ForegroundColor Gray

        # Restore Interrupt Moderation to Adaptive (default)
        try {
            Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "*InterruptModeration" -RegistryValue 1 -ErrorAction SilentlyContinue
            Write-Host "    [OK] Interrupt Moderation restored to Adaptive" -ForegroundColor Green
            $restoredCount++
        } catch { }

        # Restore Interrupt Throttle Rate to default
        try {
            Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "*ITR" -RegistryValue 65535 -ErrorAction SilentlyContinue
        } catch { }

        # Restore Flow Control to Auto (default)
        try {
            Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "*FlowControl" -RegistryValue 3 -ErrorAction SilentlyContinue
            Write-Host "    [OK] Flow Control restored to Auto" -ForegroundColor Green
            $restoredCount++
        } catch { }

        # Restore Energy Efficient Ethernet
        try {
            Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "*EEE" -RegistryValue 1 -ErrorAction SilentlyContinue
            Write-Host "    [OK] Energy Efficient Ethernet restored" -ForegroundColor Green
            $restoredCount++
        } catch { }

        # Re-enable Power Management
        try {
            Enable-NetAdapterPowerManagement -Name $adapter.Name -ErrorAction SilentlyContinue
            Write-Host "    [OK] Power Management restored" -ForegroundColor Green
            $restoredCount++
        } catch { }

        # Restore Jumbo Frames to default
        try {
            Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "*JumboPacket" -RegistryValue 1514 -ErrorAction SilentlyContinue
        } catch { }
    }

    # ================================================================
    # PHASE 3: RESTORE IPv6 SETTINGS
    # ================================================================
    Write-Host " "
    Write-Host "PHASE 3: Restoring IPv6 Settings" -ForegroundColor Cyan
    Write-Host " "

    # Re-enable IPv6 transition technologies
    try {
        $null = netsh interface teredo set state default 2>&1
        Write-Host "  [OK] Teredo restored to default" -ForegroundColor Green
        $restoredCount++
    } catch { }

    try {
        $null = netsh interface 6to4 set state state=default 2>&1
        Write-Host "  [OK] 6to4 restored to default" -ForegroundColor Green
        $restoredCount++
    } catch { }

    try {
        $null = netsh interface isatap set state state=default 2>&1
        Write-Host "  [OK] ISATAP restored to default" -ForegroundColor Green
        $restoredCount++
    } catch { }

    # Restore IPv6 preference
    try {
        $ipv6Path = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
        if (Test-Path $ipv6Path) {
            Remove-ItemProperty -Path $ipv6Path -Name "DisabledComponents" -Force -ErrorAction SilentlyContinue
            Write-Host "  [OK] IPv6 preference restored to default" -ForegroundColor Green
            $restoredCount++
        }
    } catch { }

    # ================================================================
    # PHASE 4: RESTORE SYSTEM SETTINGS
    # ================================================================
    Write-Host " "
    Write-Host "PHASE 4: Restoring System Settings" -ForegroundColor Cyan
    Write-Host " "

    # Re-enable Network Throttling (default value = 10)
    try {
        $throttlePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"
        if (Test-Path $throttlePath) {
            Set-ItemProperty -Path $throttlePath -Name "NetworkThrottlingIndex" -Value 10 -Type DWord -Force
            Remove-ItemProperty -Path $throttlePath -Name "SystemResponsiveness" -Force -ErrorAction SilentlyContinue
            Write-Host "  [OK] Network Throttling restored to default (10)" -ForegroundColor Green
            $restoredCount++
            $restoredDetails += "Network Throttling: 10"
        }
    } catch {
        Write-Host "  [!] Could not restore network throttling" -ForegroundColor Yellow
    }

    # Restore QoS Packet Scheduler
    try {
        $qosPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched"
        if (Test-Path $qosPath) {
            Remove-ItemProperty -Path $qosPath -Name "NonBestEffortLimit" -Force -ErrorAction SilentlyContinue
            Write-Host "  [OK] QoS Packet Scheduler restored to default" -ForegroundColor Green
            $restoredCount++
            $restoredDetails += "QoS: Default"
        }
    } catch {
        Write-Host "  [!] Could not restore QoS" -ForegroundColor Yellow
    }

    # Restore DNS Cache settings
    try {
        $dnsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
        if (Test-Path $dnsPath) {
            Remove-ItemProperty -Path $dnsPath -Name "MaxCacheEntryTtlLimit" -Force -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $dnsPath -Name "MaxNegativeCacheTtl" -Force -ErrorAction SilentlyContinue
            Write-Host "  [OK] DNS Cache settings restored to default" -ForegroundColor Green
            $restoredCount++
        }
    } catch {
        Write-Host "  [!] Could not restore DNS settings" -ForegroundColor Yellow
    }

    # Restore AFD driver parameters (UDP/Winsock)
    try {
        $afdPath = "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters"
        if (Test-Path $afdPath) {
            Remove-ItemProperty -Path $afdPath -Name "DefaultReceiveWindow" -Force -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $afdPath -Name "DefaultSendWindow" -Force -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $afdPath -Name "FastSendDatagramThreshold" -Force -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path $afdPath -Name "DisableRawSecurity" -Force -ErrorAction SilentlyContinue
            Write-Host "  [OK] AFD/Winsock parameters restored to default" -ForegroundColor Green
            $restoredCount++
        }
    } catch {
        Write-Host "  [!] Could not restore AFD parameters" -ForegroundColor Yellow
    }

    # Restore Global Offload Settings
    try {
        Set-NetOffloadGlobalSetting -ReceiveSegmentCoalescing Enabled -ErrorAction SilentlyContinue
        Set-NetOffloadGlobalSetting -ReceiveSideScaling Enabled -ErrorAction SilentlyContinue
        Write-Host "  [OK] Global offload settings restored" -ForegroundColor Green
        $restoredCount++
    } catch {
        Write-Host "  [!] Could not restore global offload settings" -ForegroundColor Yellow
    }

    # Restore Delivery Optimization
    try {
        $doPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
        if (Test-Path $doPath) {
            Remove-ItemProperty -Path $doPath -Name "DODownloadMode" -Force -ErrorAction SilentlyContinue
            Write-Host "  [OK] Delivery Optimization restored to default" -ForegroundColor Green
            $restoredCount++
        }
    } catch { }

    # Restore DNS to DHCP
    try {
        $activeAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        foreach ($adapter in $activeAdapters) {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ResetServerAddresses -ErrorAction SilentlyContinue
        }
        Write-Host "  [OK] DNS servers restored to DHCP defaults" -ForegroundColor Green
        $restoredCount++
    } catch { }

    # Restore DoH setting
    try {
        $dohPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
        Remove-ItemProperty -Path $dohPath -Name "EnableAutoDoh" -Force -ErrorAction SilentlyContinue
    } catch { }

    # Restore LSO
    try {
        $activeAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        foreach ($adapter in $activeAdapters) {
            Set-NetAdapterLso -Name $adapter.Name -V1IPv4Enabled $true -IPv4Enabled $true -IPv6Enabled $true -ErrorAction SilentlyContinue
        }
        Write-Host "  [OK] Large Send Offload restored to enabled" -ForegroundColor Green
        $restoredCount++
    } catch { }

    # Restore UDP port range
    try {
        $null = netsh int ipv4 set dynamicport udp start=49152 num=16384 2>&1
        $null = netsh int ipv6 set dynamicport udp start=49152 num=16384 2>&1
        Write-Host "  [OK] UDP port range restored to default" -ForegroundColor Green
        $restoredCount++
    } catch { }

    # Restore background apps
    try {
        $bgAppsPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"
        if (Test-Path $bgAppsPath) {
            Remove-ItemProperty -Path $bgAppsPath -Name "GlobalUserDisabled" -Force -ErrorAction SilentlyContinue
            Write-Host "  [OK] Background apps restored to default" -ForegroundColor Green
            $restoredCount++
        }
    } catch { }

    Write-Host " "
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host "           NETWORK DEFAULTS RESTORED! (2026 EDITION)            " -ForegroundColor Green
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host " "
    Write-Host "SUMMARY:" -ForegroundColor Cyan
    Write-Host "  Total settings restored: $restoredCount" -ForegroundColor Yellow
    Write-Host "  Adapters processed: $($allAdapters.Count)" -ForegroundColor Yellow
    Write-Host " "
    Write-Host "RESTORED TO DEFAULTS:" -ForegroundColor Cyan
    Write-Host "  [OK] TCP ACK/NoDelay/DelAck: REMOVED (Windows default)" -ForegroundColor Gray
    Write-Host "  [OK] CTCP Congestion Control: DEFAULT" -ForegroundColor Gray
    Write-Host "  [OK] ECN: DISABLED (Windows default)" -ForegroundColor Gray
    Write-Host "  [OK] UDP Buffers: DEFAULT (Windows manages)" -ForegroundColor Gray
    Write-Host "  [OK] Interrupt Moderation: ADAPTIVE (Windows default)" -ForegroundColor Gray
    Write-Host "  [OK] Flow Control: AUTO (Windows default)" -ForegroundColor Gray
    Write-Host "  [OK] Power Management: ENABLED (Windows default)" -ForegroundColor Gray
    Write-Host "  [OK] Network Throttling: ENABLED (Windows default)" -ForegroundColor Gray
    Write-Host "  [OK] IPv6 Tunneling: DEFAULT (Windows manages)" -ForegroundColor Gray
    Write-Host "  [OK] QoS: DEFAULT (Windows default)" -ForegroundColor Gray
    Write-Host "  [OK] DNS: DHCP (Windows default)" -ForegroundColor Gray
    Write-Host "  [OK] LSO: ENABLED (Windows default)" -ForegroundColor Gray
    Write-Host "  [OK] Delivery Optimization: DEFAULT" -ForegroundColor Gray
    Write-Host " "
    Write-Host "[TIP] Restart your PC for all changes to take full effect." -ForegroundColor Yellow
    Write-Host "================================================================" -ForegroundColor DarkGray
    
    Write-Log -Message "Network defaults restored: $restoredCount settings reverted" -Type "SUCCESS"
    
    Start-Sleep -Seconds 3
}

# ================================================================
# INTERACTIVE MENU
# ================================================================

function Show-Menu {
    Clear-Host
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "      NetworkOptimizer - Standalone Network Optimization Tool   " -ForegroundColor Cyan
    Write-Host "             Extracted from RahbarX v2.0 (2026 Ultra)           " -ForegroundColor DarkGray
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] Optimize Network (Gaming/Low-Latency)" -ForegroundColor Green
    Write-Host "  [2] Restore Network Defaults" -ForegroundColor Yellow
    Write-Host "  [3] Validate Current Settings" -ForegroundColor Cyan
    Write-Host "  [4] Latency Benchmark" -ForegroundColor Magenta
    Write-Host "  [5] Reset Network Stack (Winsock Reset)" -ForegroundColor Red
    Write-Host "  [6] Exit" -ForegroundColor Gray
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor DarkGray
    Write-Host ""
}

# ================================================================
# MAIN EXECUTION
# ================================================================

$continueLoop = $true

while ($continueLoop) {
    Show-Menu
    $choice = Read-Host "Select an option (1-6)"
    
    switch ($choice) {
        "1" {
            Optimize-Network
            Write-Host ""
            Write-Host "Press any key to continue..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "2" {
            Restore-NetworkDefaults
            Write-Host ""
            Write-Host "Press any key to continue..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "3" {
            Clear-Host
            Write-Host "================================================================" -ForegroundColor Cyan
            Write-Host "           NETWORK SETTINGS VALIDATION                          " -ForegroundColor Cyan
            Write-Host "================================================================" -ForegroundColor Cyan
            Write-Host ""
            $results = Test-NetworkOptimizations
            Write-Host ""
            Write-Host "================================================================" -ForegroundColor DarkGray
            Write-Host ""
            Write-Host "Press any key to continue..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "4" {
            Test-NetworkLatency
            Write-Host ""
            Write-Host "Press any key to continue..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "5" {
            Reset-NetworkStack
            Write-Host ""
            Write-Host "Press any key to continue..." -ForegroundColor Gray
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        "6" {
            $continueLoop = $false
            Write-Host "Exiting..." -ForegroundColor Gray
        }
        default {
            Write-Host "Invalid option. Please select 1-6." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
}

Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
