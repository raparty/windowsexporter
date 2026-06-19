# windows_exporter (raparty fork)

> A customized fork of [prometheus-community/windows_exporter](https://github.com/prometheus-community/windows_exporter), based on branch `0.30`.

A Prometheus exporter for Windows machines. This fork adds a custom **`eventlog` collector** on top of the upstream project, plus a default port change. See the [Customizations](#customizations) section for details.

---

## Table of Contents

- [Customizations](#customizations)
- [eventlog Collector](#eventlog-collector)
- [Collectors](#collectors)
- [Flags](#flags)
- [Installation](#installation)
- [Configuration File](#configuration-file)
- [Usage](#usage)
- [HTTP Endpoints](#http-endpoints)
- [Examples](#examples)
- [Docker](#docker)
- [Kubernetes](#kubernetes)
- [Supported Versions](#supported-versions)
- [License](#license)

---

## Customizations

The following changes have been made on top of the upstream `0.30` branch:

| Change | Details |
|--------|---------|
| **Custom `eventlog` collector** | New collector exposing Windows Event Log event counts, stability counters, and boot performance metrics. Not present in upstream. |
| **Custom listen port** | Default listen address changed from `:9182` to `:9183` via `config.yaml` |

---

## eventlog Collector

> **This is the primary custom addition in this fork.**

The `eventlog` collector reads from the Windows Event Log API (`advapi32.dll`) and the modern Event Log API (`wevtapi.dll`) to expose:

- **Filtered event counts** per channel, level, event ID, and source
- **Derived stability counters** for high-signal failure events (always collected, not subject to the event-ID filter)
- **Boot performance metrics** from `Microsoft-Windows-Diagnostics-Performance/Operational`

The collector is **not enabled by default** — it must be explicitly added to `--collectors.enabled`.

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--collector.eventlog.log-names` | Comma-separated list of Windows Event Log channels to monitor | `Application,System` |
| `--collector.eventlog.event-ids` | Comma-separated list of event IDs or inclusive ranges to include in `windows_eventlog_event_total`. Empty string = all event IDs | `15,55,41,1000,100,400-499` |

### Metrics

#### General event counter

| Name | Description | Type | Labels |
|------|-------------|------|--------|
| `windows_eventlog_event_total` | Total Windows Event Log events matching the configured filter, since the exporter started | counter | `channel`, `level`, `event_id`, `source`, `faulting_application` |

**Label values:**

- `channel` — Windows Event Log channel name, e.g. `Application`, `System`
- `level` — one of `success`, `error`, `warning`, `information`, `audit_success`, `audit_failure`
- `event_id` — numeric event ID as a string
- `source` — event source / provider name
- `faulting_application` — for Event ID 1000, the base filename of the crashing process (e.g. `Explorer.EXE`); empty for all other event IDs

#### Derived stability counters

These counters track specific high-signal event IDs and are **always collected**, independent of `--collector.eventlog.event-ids`.

| Name | Description | Type | Source |
|------|-------------|------|--------|
| `windows_explorer_crash_count` | Total `explorer.exe` crash events since the exporter started | counter | Application log, Event 1000 (`faulting_application = Explorer.EXE`) |
| `windows_application_hang_count` | Total application-hang events since the exporter started | counter | Application log, Event 1002 |
| `windows_display_reset_count` | Total display driver TDR recovery events since the exporter started | counter | System log, Event 4101 |
| `windows_unexpected_shutdown_count` | Total unexpected-shutdown events since the exporter started | counter | System log, Event 6008 |
| `windows_kernel_power_crash_count` | Total kernel-power crash events (BSOD / hard power loss) since the exporter started | counter | System log, Event 41 |
| `windows_app_crash_total` | Total application crashes grouped by faulting application name since the exporter started | counter | Application log, Event 1000 — label: `application` |

#### Boot performance metrics

These gauges reflect the most recent boot and remain constant until the next reboot. Values are omitted if the `Diagnostics-Performance` channel contains no events (e.g. freshly installed or stripped Windows SKUs).

| Name | Description | Type | Source field |
|------|-------------|------|------|
| `windows_boot_time_ms` | Total boot duration in milliseconds | gauge | `BootTime` |
| `windows_mainpath_boot_time_ms` | Main boot path duration in milliseconds | gauge | `MainPathBootTime` |
| `windows_post_boot_time_ms` | Post-boot duration in milliseconds | gauge | `BootPostBootTime` |
| `windows_boot_startup_apps` | Number of startup applications that ran during the last boot | gauge | `BootNumStartupApps` |
| `windows_boot_driver_init_time_ms` | Driver initialization duration in milliseconds | gauge | `BootDriverInitTime` |
| `windows_boot_user_profile_time_ms` | User profile processing duration in milliseconds | gauge | `BootUserProfileProcessingTime` |

All boot metrics are sourced from `Microsoft-Windows-Diagnostics-Performance/Operational`, Event ID 100 (most recent event).

### Example output

```
# General event counter
windows_eventlog_event_total{channel="Application",event_id="1000",faulting_application="Explorer.EXE",level="error",source="Application Error"} 3
windows_eventlog_event_total{channel="Application",event_id="1000",faulting_application="SearchApp.exe",level="error",source="Application Error"} 1
windows_eventlog_event_total{channel="System",event_id="41",faulting_application="",level="error",source="Microsoft-Windows-Kernel-Power"} 1

# Derived stability counters
windows_explorer_crash_count 3
windows_application_hang_count 2
windows_display_reset_count 1
windows_unexpected_shutdown_count 1
windows_kernel_power_crash_count 1

# Per-application crash breakdown
windows_app_crash_total{application="Explorer.EXE"} 3
windows_app_crash_total{application="SearchApp.exe"} 1

# Boot performance metrics
windows_boot_time_ms 133626
windows_mainpath_boot_time_ms 54726
windows_post_boot_time_ms 78900
windows_boot_startup_apps 13
windows_boot_driver_init_time_ms 4200
windows_boot_user_profile_time_ms 3100
```

### Useful PromQL queries

```promql
# Rate of new error events over 5 minutes
rate(windows_eventlog_event_total{level="error"}[5m])

# Explorer crash rate per hour
increase(windows_explorer_crash_count[1h])

# Top crashing applications over the last 24 hours
topk(10, increase(windows_app_crash_total[24h]))

# Any unexpected shutdowns in the last 7 days
increase(windows_unexpected_shutdown_count[7d]) > 0

# Last boot duration in seconds
windows_boot_time_ms / 1000

# Alert when boot takes longer than 60 seconds
windows_boot_time_ms > 60000
```

### Alerting examples

```yaml
# prometheus.rules
groups:
  - name: windows_stability
    rules:
      - alert: WindowsExplorerCrash
        expr: increase(windows_explorer_crash_count[15m]) > 0
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "Explorer crashed on {{ $labels.instance }}"
          description: "explorer.exe has crashed at least once in the last 15 minutes."

      - alert: WindowsKernelPowerCrash
        expr: increase(windows_kernel_power_crash_count[1h]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Kernel power crash on {{ $labels.instance }}"
          description: "A BSOD or hard power-loss event was recorded in the last hour."

      - alert: WindowsUnexpectedShutdown
        expr: increase(windows_unexpected_shutdown_count[1h]) > 0
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "Unexpected shutdown on {{ $labels.instance }}"
          description: "The previous system shutdown was not clean."

      - alert: WindowsEventLogErrors
        expr: rate(windows_eventlog_event_total{level="error"}[5m]) > 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Windows Event Log errors on {{ $labels.instance }}"
          description: "Event log channel '{{ $labels.channel }}' is recording errors."

      - alert: WindowsSlowBoot
        expr: windows_boot_time_ms > 60000
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "Slow Windows boot on {{ $labels.instance }}"
          description: "Last boot took {{ $value | humanizeDuration }} (threshold: 60s)."

      - alert: WindowsManyStartupApps
        expr: windows_boot_startup_apps > 20
        for: 0m
        labels:
          severity: info
        annotations:
          summary: "High startup-app count on {{ $labels.instance }}"
          description: "{{ $value }} startup applications ran during the last boot."
```

### Enable the eventlog collector

```powershell
# Enable alongside defaults
.\windows_exporter.exe --collectors.enabled "[defaults],eventlog"

# Enable with custom channels and event IDs
.\windows_exporter.exe --collectors.enabled "[defaults],eventlog" `
  --collector.eventlog.log-names="Application,System,Security" `
  --collector.eventlog.event-ids="1000,1002,4101,6008"

# Enable all event IDs (no filter)
.\windows_exporter.exe --collectors.enabled "[defaults],eventlog" `
  --collector.eventlog.event-ids=""
```

Or via `config.yaml`:

```yaml
collectors:
  enabled: "[defaults],eventlog"
collector:
  eventlog:
    log-names: Application,System
    event-ids: 15,55,41,1000,100,400-499
web:
  listen-address: ":9183"
```

---

## Collectors

| Name | Description | Enabled by default |
|------|-------------|-------------------|
| `ad` | Active Directory Domain Services | |
| `adcs` | Active Directory Certificate Services | |
| `adfs` | Active Directory Federation Services | |
| `cache` | Cache metrics | |
| `cpu` | CPU usage | ✓ |
| `cpu_info` | CPU Information | |
| `cs` | Computer System metrics (num CPUs, total memory) | |
| `container` | Container metrics | |
| `diskdrive` | Disk drive metrics | |
| `dfsr` | DFSR metrics | |
| `dhcp` | DHCP Server | |
| `dns` | DNS Server | |
| `eventlog` | **Windows Event Log counts, stability counters, boot metrics (custom — this fork)** | |
| `exchange` | Exchange metrics | |
| `filetime` | FileTime metrics | |
| `fsrmquota` | Microsoft FSRM Quotas | |
| `hyperv` | Hyper-V hosts | |
| `iis` | IIS sites and applications | |
| `license` | Windows license status | |
| `logical_disk` | Logical disks, disk I/O | ✓ |
| `memory` | Memory usage metrics | ✓ |
| `mscluster` | MSCluster metrics | |
| `msmq` | MSMQ queues | |
| `mssql` | SQL Server Performance Objects metrics | |
| `netframework` | .NET Framework metrics | |
| `net` | Network interface I/O | ✓ |
| `os` | OS metrics (memory, processes, users) | ✓ |
| `pagefile` | Pagefile metrics | |
| `performancecounter` | Custom performance counter metrics | |
| `physical_disk` | Physical disk metrics | ✓ |
| `printer` | Printer metrics | |
| `process` | Per-process metrics | |
| `remote_fx` | RemoteFX protocol (RDP) metrics | |
| `scheduled_task` | Scheduled Tasks metrics | |
| `service` | Service state metrics | ✓ |
| `smb` | SMB Server | |
| `smbclient` | SMB Client | |
| `smtp` | IIS SMTP Server | |
| `system` | System calls | ✓ |
| `tcp` | TCP connections | |
| `terminal_services` | Terminal services (RDS) | |
| `textfile` | Read Prometheus metrics from a text file | |
| `thermalzone` | Thermal information | |
| `time` | Windows Time Service | |
| `udp` | UDP connections | |
| `update` | Windows Update Service | |
| `vmware` | VMware Guest agent performance counters | |

---

## Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--web.listen-address` | host:port for exporter | `:9182` (overridden to `:9183` via `config.yaml`) |
| `--telemetry.path` | URL path for metrics | `/metrics` |
| `--telemetry.max-requests` | Maximum concurrent requests. 0 to disable | `5` |
| `--collectors.enabled` | Comma-separated list of collectors. Use `[defaults]` for all defaults | `[defaults]` |
| `--collectors.print` | Print available collectors and exit | |
| `--scrape.timeout-margin` | Seconds to subtract from client-allowed timeout | `0.5` |
| `--web.config.file` | TLS/Auth web config file | None |
| `--config.file` | Path or URL to YAML config file | None |
| `--config.file.insecure-skip-verify` | Skip TLS when loading config from URL | `false` |
| `--log.file` | Log output: `stdout`, `stderr`, `eventlog`, or a file path | `stderr` |

> **Note:** When installed via the MSI installer, the log target defaults to `eventlog`.

---

## Installation

### From source (this fork)

```powershell
git clone https://github.com/raparty/windowsexporter
cd windowsexporter
go get -u github.com/prometheus/promu
promu build -v
.\windows_exporter.exe --config.file=config.yaml
```

### MSI installer (upstream)

Download the latest release from the [upstream releases page](https://github.com/prometheus-community/windows_exporter/releases). The MSI installer registers `windows_exporter` as a Windows service and creates a Windows Firewall exception.

#### MSI parameters

| Parameter | Description |
|-----------|-------------|
| `ENABLED_COLLECTORS` | Comma-separated list of collectors to enable |
| `CONFIG_FILE` | Path to config file |
| `LISTEN_ADDR` | IP to bind to (empty = any local address) |
| `LISTEN_PORT` | Port to bind to. Default: `9182` |
| `METRICS_PATH` | Path to serve metrics. Default: `/metrics` |
| `TEXTFILE_DIRS` | Comma-separated directories for textfile collector |
| `REMOTE_ADDR` | Comma-separated remote IPs for firewall allowlist |
| `EXTRA_FLAGS` | Full CLI flags as a string |
| `ADDLOCAL` | Enable installer features: `FirewallException` |
| `REMOVE` | Disable installer features: `FirewallException` |
| `APPLICATIONFOLDER` | Install directory. Default: `C:\Program Files\windows_exporter` |

```powershell
# Example: specific collectors and port
msiexec /i <path-to-msi> --% ENABLED_COLLECTORS=os,iis LISTEN_PORT=5000

# Example: custom config file
msiexec /i <path-to-msi> --% CONFIG_FILE="D:\config.yaml"

# Example: firewall exception
msiexec /i <path-to-msi> --% ADDLOCAL=FirewallException
```

> **PowerShell 7.3+:** Set `$PSNativeCommandArgumentPassing = 'Legacy'` when using `--% EXTRA_FLAGS`.

---

## Configuration File

A YAML config file is passed with `--config.file`. This fork ships a `config.yaml` at the repo root:

```yaml
# config.yaml (this fork's customized defaults)
web:
  listen-address: ":9183"
```

A more complete example enabling the custom eventlog collector:

```yaml
collectors:
  enabled: "[defaults],eventlog"
collector:
  eventlog:
    log-names: Application,System
    event-ids: 15,55,41,1000,100,400-499
  service:
    include: windows_exporter
log:
  level: warn
web:
  listen-address: ":9183"
```

CLI flags take priority over config file values. Config files can also be loaded from a URL:

```powershell
.\windows_exporter.exe --config.file="https://example.com/config.yaml"
```

---

## Usage

```powershell
# Run with this fork's config (port 9183, no eventlog)
.\windows_exporter.exe --config.file=config.yaml

# Run with eventlog collector enabled
.\windows_exporter.exe --config.file=config.yaml --collectors.enabled "[defaults],eventlog"

# Run with specific collectors only
.\windows_exporter.exe --collectors.enabled "cpu,memory,net,logical_disk,eventlog"

# Run with all default collectors
.\windows_exporter.exe
```

Metrics are exposed at [http://localhost:9183/metrics](http://localhost:9183/metrics) (with `config.yaml`) or [http://localhost:9182/metrics](http://localhost:9182/metrics) (upstream default).

---

## HTTP Endpoints

| Endpoint | Description |
|----------|-------------|
| `/metrics` | Prometheus metrics in text format |
| `/health` | Returns `200 OK` when the exporter is running |
| `/debug/pprof/` | pprof profiling endpoints (requires `--debug.enabled`) |

---

## Examples

### Enable defaults + eventlog collector

```powershell
.\windows_exporter.exe --collectors.enabled "[defaults],eventlog"
```

### Enable only service collector with a filter

```powershell
.\windows_exporter.exe --collectors.enabled "service" --collector.service.include="windows_exporter"
```

### Enable only process collector with a regex filter

```powershell
.\windows_exporter.exe --collectors.enabled "process" --collector.process.include="firefox.+"
```

> When multiple processes share the same name, WMI appends `#index`. Use `.+` in your regex to capture all instances.

---

## Docker

The upstream Docker image is available on:

- Docker Hub: `docker.io/prometheuscommunity/windows-exporter`
- GitHub Container Registry: `ghcr.io/prometheus-community/windows-exporter`

A `-hostprocess` flavor is available for Windows Kubernetes deployments with a smaller image footprint.

---

## Kubernetes

See [kubernetes/kubernetes.md](kubernetes/kubernetes.md) for detailed instructions on deploying on Windows Kubernetes nodes.

---

## Supported Versions

| Platform | Supported |
|----------|-----------|
| Windows Server 2016+ | ✓ Full support |
| Windows 10 / 11 (21H2+) | ✓ Full support |
| Windows Server 2012 / 2012 R2 | Best-effort only |

---

## License

[MIT](LICENSE)

---

## Upstream

This project is a fork of [prometheus-community/windows_exporter](https://github.com/prometheus-community/windows_exporter). Upstream documentation, releases, and community support can be found there.
