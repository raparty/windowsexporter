# eventlog collector

The eventlog collector exposes counts of Windows Event Log entries per channel and event level,
plus a set of focused stability counters for common failure events. It also collects boot 
performance metrics from the `Microsoft-Windows-Diagnostics-Performance/Operational` event log.

|||
-|-
Metric name prefix  | `eventlog` (general) / none (derived counters and boot metrics)
Data source         | Windows Event Log API (`advapi32.dll`) and Event Log API (`wevtapi.dll`)
Enabled by default? | No

## Flags

### `--collector.eventlog.log-names`

A comma-separated list of Windows Event Log channel names to monitor.

Default: `Application,System`

Example: `--collector.eventlog.log-names="Application,System,Security"`

### `--collector.eventlog.event-ids`

A comma-separated list of event IDs (or inclusive ranges) to include in `windows_eventlog_event_total`.
An empty value collects all event IDs.

Default: `15,55,41,1000,100,400-499`

Example: `--collector.eventlog.event-ids="1000,1002,4101"`

> **Note:** The derived stability counters (`windows_explorer_crash_count`, etc.) are always
> collected regardless of this filter.

## Metrics

### General event counter

Name | Description | Type | Labels
-----|-------------|------|-------
`windows_eventlog_event_total` | Total Windows Event Log events matching the configured filter, since the exporter started | counter | `channel`, `level`, `event_id`, `source`, `faulting_application`

### Derived stability counters

These counters track specific high-signal event IDs and are **always collected**, independent
of `--collector.eventlog.event-ids`.

Name | Description | Type | Source
-----|-------------|------|-------
`windows_explorer_crash_count` | Total `explorer.exe` crash events (Application log Event 1000) since the exporter started | counter | Application log, Event 1000 (`faulting_application = Explorer.EXE`)
`windows_application_hang_count` | Total application-hang events since the exporter started | counter | Application log, Event 1002
`windows_display_reset_count` | Total display driver TDR recovery events since the exporter started | counter | System log, Event 4101
`windows_unexpected_shutdown_count` | Total unexpected-shutdown events since the exporter started | counter | System log, Event 6008
`windows_kernel_power_crash_count` | Total kernel-power crash events (BSOD / hard power loss) since the exporter started | counter | System log, Event 41
`windows_app_crash_total` | Total application crashes grouped by faulting application name since the exporter started | counter | Application log, Event 1000 — label: `application`

### Boot Performance Metrics

These gauges reflect the most recent boot and remain constant until the next reboot. Values are 
omitted entirely if the `Diagnostics-Performance` channel contains no events (e.g. on freshly 
installed or stripped Windows SKUs).

Name | Description | Type | Source
-----|-------------|------|-------
`windows_boot_time_ms` | Total boot duration in milliseconds | gauge | Microsoft-Windows-Diagnostics-Performance/Operational Event 100, field `BootTime`
`windows_mainpath_boot_time_ms` | Main boot path duration in milliseconds | gauge | Microsoft-Windows-Diagnostics-Performance/Operational Event 100, field `MainPathBootTime`
`windows_post_boot_time_ms` | Post-boot duration in milliseconds | gauge | Microsoft-Windows-Diagnostics-Performance/Operational Event 100, field `BootPostBootTime`
`windows_boot_startup_apps` | Number of startup applications that ran during the last boot | gauge | Microsoft-Windows-Diagnostics-Performance/Operational Event 100, field `BootNumStartupApps`

### Label values

**`channel`** (`windows_eventlog_event_total`): The Windows Event Log channel name, e.g. `Application`, `System`.

**`level`** (`windows_eventlog_event_total`): One of `success`, `error`, `warning`, `information`, `audit_success`, `audit_failure`.

**`event_id`** (`windows_eventlog_event_total`): Numeric event ID as a string.

**`source`** (`windows_eventlog_event_total`): The event source / provider name.

**`faulting_application`** (`windows_eventlog_event_total`): For Event ID 1000, the base filename of the
crashing process (e.g. `Explorer.EXE`). Empty for all other event IDs.

**`application`** (`windows_app_crash_total`): Base filename of the crashing process, e.g. `Explorer.EXE`,
`SearchApp.exe`.

## Example metrics

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
windows_app_crash_total{application="ScreenSketch.exe"} 1

# Boot performance metrics (collected shortly after a reboot)
windows_boot_time_ms 133626
windows_mainpath_boot_time_ms 54726
windows_post_boot_time_ms 78900
windows_boot_startup_apps 13
```

## Useful queries

### Rate of new error events over 5 minutes

```promql
rate(windows_eventlog_event_total{level="error"}[5m])
```

### Explorer crash rate per hour

```promql
increase(windows_explorer_crash_count[1h])
```

### Top crashing applications over the last 24 hours

```promql
topk(10, increase(windows_app_crash_total[24h]))
```

### Any unexpected shutdowns in the last 7 days

```promql
increase(windows_unexpected_shutdown_count[7d]) > 0
```

### Last boot duration in seconds

```promql
windows_boot_time_ms / 1000
```

### Alert when boot takes longer than 60 seconds

```promql
windows_boot_time_ms > 60000
```

## Alerting examples

**prometheus.rules**
```yaml
  - alert: "WindowsExplorerCrash"
    expr: "increase(windows_explorer_crash_count[15m]) > 0"
    for: "0m"
    labels:
      severity: "warning"
    annotations:
      summary: "Explorer crashed on {{ $labels.instance }}"
      description: "explorer.exe has crashed at least once in the last 15 minutes."

  - alert: "WindowsKernelPowerCrash"
    expr: "increase(windows_kernel_power_crash_count[1h]) > 0"
    for: "0m"
    labels:
      severity: "critical"
    annotations:
      summary: "Kernel power crash on {{ $labels.instance }}"
      description: "A BSOD or hard power-loss event was recorded in the last hour."

  - alert: "WindowsUnexpectedShutdown"
    expr: "increase(windows_unexpected_shutdown_count[1h]) > 0"
    for: "0m"
    labels:
      severity: "warning"
    annotations:
      summary: "Unexpected shutdown on {{ $labels.instance }}"
      description: "The previous system shutdown was not clean."

  - alert: "WindowsEventLogErrors"
    expr: "rate(windows_eventlog_event_total{level='error'}[5m]) > 0"
    for: "5m"
    labels:
      severity: "warning"
    annotations:
      summary: "Windows Event Log errors detected on {{ $labels.instance }}"
      description: "Event log channel '{{ $labels.channel }}' is recording errors."

  - alert: "WindowsSlowBoot"
    expr: "windows_boot_time_ms > 60000"
    for: "0m"
    labels:
      severity: "warning"
    annotations:
      summary: "Slow Windows boot on {{ $labels.instance }}"
      description: "Last boot took {{ $value | humanizeDuration }} (threshold: 60 s)."

  - alert: "WindowsManyStartupApps"
    expr: "windows_boot_startup_apps > 20"
    for: "0m"
    labels:
      severity: "info"
    annotations:
      summary: "High startup-app count on {{ $labels.instance }}"
      description: "{{ $value }} startup applications ran during the last boot."
```

## Data source details

### Classic Event Logs (Application, System)

The eventlog collector uses the classic Windows Event Log API (`advapi32.dll`) to read from 
`Application` and `System` logs as specified by `--collector.eventlog.log-names`.

### Boot Performance Metrics

Boot performance metrics are sourced from the `Microsoft-Windows-Diagnostics-Performance/Operational` 
channel, which is written by the `Microsoft-Windows-Diagnostics-Performance` ETW provider. This 
channel is **not** accessible via the classic `advapi32` API; it requires the modern Event Log API 
(`wevtapi.dll`) introduced in Windows Vista.

Event 100 (Boot Performance Measurement) is written once per boot and contains:

| XML field | Description |
|---|---|
| `BootTime` | Total time from firmware hand-off to OS ready, in milliseconds |
| `MainPathBootTime` | Main boot path duration, in milliseconds |
| `BootPostBootTime` | Duration of post-boot startup activities, in milliseconds |
| `BootNumStartupApps` | Number of startup programs that ran during this boot |
