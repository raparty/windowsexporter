# bootperformance collector

The bootperformance collector exposes Windows boot-performance timing metrics derived from the
`Microsoft-Windows-Diagnostics-Performance/Operational` event log channel.

On every scrape the most recent **Boot Performance Measurement** event (Event ID 100) is read
via the modern Windows Event Log API (`EvtQuery` / `EvtNext` / `EvtRender` from `wevtapi.dll`)
and four fields are extracted from the XML payload and emitted as gauges.

|||
-|-
Metric name prefix  | _(none — metrics use the top-level `windows_` namespace)_
Data source         | `Microsoft-Windows-Diagnostics-Performance/Operational` (Event ID 100)
Windows API         | `wevtapi.dll` — `EvtQuery`, `EvtNext`, `EvtRender`
Enabled by default? | No

## Flags

No collector-specific flags. Enable with `--collectors.enabled=bootperformance`.

## Metrics

Name | Description | Type | Labels
-----|-------------|------|-------
`windows_boot_time_ms` | Total boot duration in milliseconds (`BootTime` field in Event 100) | gauge | —
`windows_mainpath_boot_time_ms` | Main boot path duration in milliseconds (`MainPathBootTime` field in Event 100) | gauge | —
`windows_post_boot_time_ms` | Post-boot phase duration in milliseconds (`BootPostBootTime` field in Event 100) | gauge | —
`windows_boot_startup_apps` | Number of startup applications that ran during the last boot (`BootNumStartupApps` field in Event 100) | gauge | —

> **Note:** These are **gauges** — they reflect the most recent boot and remain constant until
> the next reboot. Values are omitted entirely if the `Diagnostics-Performance` channel contains
> no events (e.g. on freshly installed or stripped Windows SKUs).

## Data source details

The `Microsoft-Windows-Diagnostics-Performance/Operational` channel is a channel-based (EVTX)
event log written by the `Microsoft-Windows-Diagnostics-Performance` ETW provider. It is **not**
accessible via the classic `advapi32` `OpenEventLog` / `ReadEventLog` API used by the `eventlog`
collector; it requires the modern `wevtapi.dll` API introduced in Windows Vista.

Event 100 is written once per boot and contains (among others):

| XML field | Description |
|---|---|
| `BootTime` | Total time from firmware hand-off to OS ready, in milliseconds |
| `MainPathBootTime` | Time spent on the critical boot path (kernel + session init), in milliseconds |
| `BootPostBootTime` | Duration of post-boot startup activities, in milliseconds |
| `BootNumStartupApps` | Number of startup programs that ran during this boot |

## Example metrics

```
# Collected shortly after a reboot
windows_boot_time_ms 133626
windows_mainpath_boot_time_ms 54726
windows_post_boot_time_ms 78900
windows_boot_startup_apps 13
```

## Useful queries

### Last boot duration in seconds

```promql
windows_boot_time_ms / 1000
```

### Main path vs post-boot breakdown

```promql
windows_mainpath_boot_time_ms / windows_boot_time_ms
```

### Alert when boot takes longer than 60 seconds

```promql
windows_boot_time_ms > 60000
```

### Startup application count trend

```promql
windows_boot_startup_apps
```

## Alerting examples

**prometheus.rules**
```yaml
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

## Build / test instructions

```bash
# Cross-compile (from Linux or macOS)
GOOS=windows GOARCH=amd64 go build ./internal/collector/bootperformance/...

# Run XML parsing unit tests (cross-platform, no Windows required)
go test -v -run TestParseBootEvent100 ./internal/collector/bootperformance/...

# Run integration tests on a Windows host
go test -v ./internal/collector/bootperformance/...

# Benchmark
go test -bench=. ./internal/collector/bootperformance/...

# Enable in the exporter
windows_exporter.exe --collectors.enabled=bootperformance
```
