# eventlog collector

The eventlog collector exposes counts of Windows Event Log entries per channel and event level.

|||
-|-
Metric name prefix  | `eventlog`
Data source         | Windows Event Log API (`advapi32.dll`)
Enabled by default? | No

## Flags

### `--collector.eventlog.log-names`

A comma-separated list of Windows Event Log channel names to monitor.

Default: `Application,System`

Example: `--collector.eventlog.log-names="Application,System,Security"`

## Metrics

Name | Description | Type | Labels
-----|-------------|------|-------
`windows_eventlog_event_total` | Total number of Windows Event Log events since the exporter started | counter | channel, level

### Label values

**`channel`**: The Windows Event Log channel name (e.g. `Application`, `System`, `Security`).

**`level`**: The event level. One of:
- `success`
- `error`
- `warning`
- `information`
- `audit_success`
- `audit_failure`

### Example metric

```
windows_eventlog_event_total{channel="Application",level="error"} 5
windows_eventlog_event_total{channel="Application",level="information"} 112
windows_eventlog_event_total{channel="Application",level="warning"} 3
windows_eventlog_event_total{channel="System",level="error"} 2
windows_eventlog_event_total{channel="System",level="information"} 87
windows_eventlog_event_total{channel="System",level="warning"} 14
```

## Useful queries

### Rate of new error events over 5 minutes

```promql
rate(windows_eventlog_event_total{level="error"}[5m])
```

### Total error and warning events across all monitored channels

```promql
sum by (channel) (windows_eventlog_event_total{level=~"error|warning"})
```

## Alerting examples

**prometheus.rules**
```yaml
  - alert: "WindowsEventLogErrors"
    expr: "rate(windows_eventlog_event_total{level='error'}[5m]) > 0"
    for: "5m"
    labels:
      severity: "warning"
    annotations:
      summary: "Windows Event Log errors detected"
      description: "Event log channel '{{ $labels.channel }}' is recording errors."
```
