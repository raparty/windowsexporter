# windows_exporter (raparty fork)

A customized fork of [prometheus-community/windows_exporter](https://github.com/prometheus-community/windows_exporter) (branch `0.30`) with a custom `eventlog` collector and a default port change.

## Customizations

| Change | Details |
|--------|---------|
| **`eventlog` collector** | New collector for Windows Event Log counts, stability counters, and boot metrics. Not in upstream. |
| **Listen port** | Changed from `:9182` to `:9183` via `config.yaml` |

---

## eventlog Collector

Not enabled by default. Reads from `advapi32.dll` and `wevtapi.dll` to expose event counts, stability counters, and boot performance metrics.

**Flags**

| Flag | Description | Default |
|------|-------------|---------|
| `--collector.eventlog.log-names` | Comma-separated Event Log channels to monitor | `Application,System` |
| `--collector.eventlog.event-ids` | Event IDs or ranges to include. Empty = all | `15,55,41,1000,100,400-499` |

**Metrics**

| Name | Type | Description |
|------|------|-------------|
| `windows_eventlog_event_total` | counter | Events matching the filter. Labels: `channel`, `level`, `event_id`, `source`, `faulting_application` |
| `windows_explorer_crash_count` | counter | `explorer.exe` crashes (Event 1000) |
| `windows_application_hang_count` | counter | App hangs (Event 1002) |
| `windows_display_reset_count` | counter | Display driver TDR resets (Event 4101) |
| `windows_unexpected_shutdown_count` | counter | Unexpected shutdowns (Event 6008) |
| `windows_kernel_power_crash_count` | counter | Kernel power crashes / BSODs (Event 41) |
| `windows_app_crash_total` | counter | Crashes by app name. Label: `application` |
| `windows_boot_time_ms` | gauge | Total boot duration (ms) |
| `windows_mainpath_boot_time_ms` | gauge | Main boot path duration (ms) |
| `windows_post_boot_time_ms` | gauge | Post-boot duration (ms) |
| `windows_boot_startup_apps` | gauge | Startup apps count at last boot |
| `windows_boot_driver_init_time_ms` | gauge | Driver init duration (ms) |
| `windows_boot_user_profile_time_ms` | gauge | User profile load duration (ms) |

> Stability counters (explorer crash, hangs, etc.) are always collected regardless of the event-ID filter. Boot metrics are sourced from `Microsoft-Windows-Diagnostics-Performance/Operational` Event 100.

**Enable it**

```powershell
.\windows_exporter.exe --collectors.enabled "[defaults],eventlog"
```

Or in `config.yaml`:

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

Default collectors: `cpu`, `logical_disk`, `memory`, `net`, `os`, `physical_disk`, `service`, `system`. See [upstream docs](https://github.com/prometheus-community/windows_exporter/tree/master/docs) for the full list and per-collector flags.

## Flags

See [upstream README](https://github.com/prometheus-community/windows_exporter) for the full flag reference. Key flags:

| Flag | Default |
|------|---------|
| `--web.listen-address` | `:9182` (`:9183` in this fork) |
| `--collectors.enabled` | `[defaults]` |
| `--config.file` | None |
| `--log.file` | `stderr` |

## Building from source

```powershell
git clone https://github.com/raparty/windowsexporter
cd windowsexporter
go get -u github.com/prometheus/promu
promu build -v
.\windows_exporter.exe --config.file=config.yaml
```

## Supported versions

Windows Server 2016+, Windows 10/11 (21H2+). Server 2012/2012R2 best-effort only.

## License

[MIT](LICENSE) — upstream: [prometheus-community/windows_exporter](https://github.com/prometheus-community/windows_exporter)
